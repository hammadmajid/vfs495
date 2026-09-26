//! In-session image capture over the established secure channel.
//!
//! Once the handshake completes, the sensor speaks plain SSLv3 AppData records
//! (`17 03 00 <len> <ct>`) directly on EP1 — no tunnel — and streams the
//! plaintext image on EP2. Capture is armed by replaying the exact in-session
//! command sequence observed from HP's binary (`captures/capture_seq.json`, a
//! list of plaintext-command hex strings; device-specific, gitignored — extract
//! it from an HP trace as documented in the README). Each command is re-encrypted
//! with *our* session keys, so no HP-generated ciphertext is reused.

use crate::crypto::Record;
use crate::usb::Sensor;
use anyhow::{Context, Result};
use std::path::Path;
use std::time::{Duration, Instant};

const APPDATA: u8 = 0x17;

/// Load the in-session command sequence (list of plaintext hex strings).
fn load_sequence(base: &Path) -> Result<Vec<Vec<u8>>> {
    let path = base.join("captures/capture_seq.json");
    let raw = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {} — extract the in-session capture sequence from an HP trace (see README)",
            path.display()
        )
    })?;
    let hexes: Vec<String> = serde_json::from_str(&raw)?;
    hexes
        .iter()
        .map(|h| hex::decode(h.trim()).context("bad hex in capture_seq.json"))
        .collect()
}

/// Drain all currently-available image bytes from EP2 into `img`.
fn drain_image_into(dev: &Sensor, img: &mut Vec<u8>, quiet_reads: usize) {
    let mut empties = 0;
    for _ in 0..256 {
        let chunk = dev.read_image(16384, 60);
        if chunk.is_empty() {
            empties += 1;
            if empties >= quiet_reads {
                break;
            }
        } else {
            empties = 0;
            img.extend_from_slice(&chunk);
        }
    }
}

/// Decode the sensor status word from a decrypted in-session reply.
///
/// Ground truth from live decryption: a reply plaintext is `[0..2]=u16 status
/// (little-endian)` followed by an optional payload (`[2..]`). A bare ack is
/// exactly 2 bytes (`00 00` = status 0x0000 = OK); a data reply (e.g. a poll's
/// ~2437-byte record) carries a payload after the status word. `0x0000`/`0x0412`
/// mean OK; any value with bit `0x0400` set is an error (per
/// `scsSensorParseReply_V4`). Returns `(status, payload_len)`.
fn parse_reply(plain: &[u8]) -> (u16, usize) {
    if plain.len() < 2 {
        return (0xffff, 0);
    }
    let status = u16::from_le_bytes([plain[0], plain[1]]);
    (status, plain.len() - 2)
}

fn status_is_ok(status: u16) -> bool {
    status == 0x0000 || status == 0x0412 || (status & 0x0400) == 0
}

/// Encrypt and send one plaintext in-session command, transparently re-acquiring
/// the USB handle if the sensor re-enumerates mid-flow (keeping the SSL session),
/// then decrypt and concatenate every reply record for it. Returns the joined
/// reply payloads (each reply's 2-byte status word stripped) and the status of
/// the last reply, or `None` if the write ultimately failed.
fn send_cmd(dev: &mut Sensor, rec: &mut Record, plain: &[u8]) -> Option<(Vec<u8>, u16)> {
    let record = rec.encrypt(APPDATA, plain);
    let mut wrote = false;
    for _ in 0..6 {
        match dev.write(&record, 4000) {
            Ok(_) => {
                wrote = true;
                break;
            }
            Err(e) => {
                let es = e.to_string();
                if es.contains("No such device") || es.contains("NoDevice") {
                    log::info!("sensor re-enumerated on cmd 0x{:02x}; reopening handle", plain[0]);
                    if let Err(re) = dev.reopen() {
                        log::warn!("reopen failed: {re}");
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
    if !wrote {
        return None;
    }
    let mut payload = Vec::new();
    let mut last_status = 0xffffu16;
    for attempt in 0..4 {
        let timeout = if attempt == 0 { 3000 } else { 200 };
        match dev.read_record(timeout) {
            Ok(wire) => match rec.decrypt(&wire) {
                Ok((_t, plain_reply)) => {
                    let (status, _plen) = parse_reply(&plain_reply);
                    last_status = status;
                    if plain_reply.len() > 2 {
                        payload.extend_from_slice(&plain_reply[2..]);
                    }
                }
                Err(e) => log::warn!("reply decrypt failed: {e}"),
            },
            Err(_) => break,
        }
    }
    Some((payload, last_status))
}

/// Poll probe: bring the sensor to poll-ready state (replay the setup+calibration
/// prefix of the sequence), then repeatedly re-send the poll command and dump each
/// reply payload so a finger touching the sensor reveals the finger-contact signal.
/// Never sends the imaging trigger, so the sensor does not reset. `prefix` is how
/// many leading sequence commands to replay first; `poll_idx` is the poll command
/// to loop; `iters` is how many polls to send.
pub fn poll_probe(
    dev: &mut Sensor,
    rec: &mut Record,
    base: &Path,
    prefix: usize,
    poll_idx: usize,
    iters: usize,
) -> Result<()> {
    let seq = load_sequence(base)?;
    anyhow::ensure!(poll_idx < seq.len(), "poll_idx out of range");
    log::info!("poll-probe: replaying {prefix} setup commands to reach poll-ready state");
    for plain in seq.iter().take(prefix) {
        let mut junk = Vec::new();
        let _ = send_cmd(dev, rec, plain);
        drain_image_into(dev, &mut junk, 1);
    }
    let poll = seq[poll_idx].clone();
    log::info!(
        "poll-probe: looping poll seq[{poll_idx}] (0x{:02x}, {}B) x{iters} — touch/lift the sensor now",
        poll[0],
        poll.len()
    );
    let mut prev: Option<Vec<u8>> = None;
    for n in 0..iters {
        match send_cmd(dev, rec, &poll) {
            Some((payload, status)) => {
                let head: String = payload.iter().take(40).map(|b| format!("{b:02x}")).collect();
                let changed = prev.as_ref().map(|p| p != &payload).unwrap_or(false);
                log::info!(
                    "poll {n:3}: status=0x{status:04x} payload={}B {head}{}",
                    payload.len(),
                    if changed { "  <-- CHANGED" } else { "" }
                );
                prev = Some(payload);
            }
            None => log::warn!("poll {n:3}: write failed"),
        }
        let mut junk = Vec::new();
        drain_image_into(dev, &mut junk, 1);
        std::thread::sleep(Duration::from_millis(150));
    }
    Ok(())
}

/// Replay the in-session capture command sequence as AppData records (all
/// in-session commands are `0x17` records on EP1 regardless of their inner
/// command byte), decrypting every reply in order so the CBC IV chain and
/// receive sequence stay aligned. Logs the decoded status word of each reply and
/// flags the first `0x02` (capture/poll) reply the sensor rejects — the datum
/// that tells us which in-session device state is missing. Drains the plaintext
/// image from EP2 throughout. A finger must be swiping for real frames to appear.
pub fn arm_capture(dev: &mut Sensor, rec: &mut Record, base: &Path) -> Result<Vec<u8>> {
    let seq = load_sequence(base)?;
    let mut img = Vec::new();
    let mut first_reject: Option<(usize, u8, u16)> = None;
    for (i, plain) in seq.iter().enumerate() {
        let cmd_op = plain[0];
        let record = rec.encrypt(APPDATA, plain);
        // AppData records go directly on EP1 (no 0x11 tunnel) once the session is up.
        // Retry the write a few times without reopening — a NAK just means the
        // device is still finishing the previous (poll) command.
        let mut wrote = false;
        let mut last_err = String::new();
        for _ in 0..6 {
            match dev.write(&record, 4000) {
                Ok(_) => {
                    wrote = true;
                    break;
                }
                Err(e) => {
                    last_err = e.to_string();
                    // The imaging-trigger commands make the sensor re-enumerate on
                    // the bus (USB disconnect + fresh device number, same 138a:003f).
                    // HP does not re-handshake across this, so the firmware keeps the
                    // SSL session — we only re-acquire the USB handle and keep our
                    // Record (sseq/rseq/IV chain) intact, then resend this command.
                    if last_err.contains("No such device") || last_err.contains("NoDevice") {
                        log::info!("[{i:3}] sensor re-enumerated on cmd 0x{cmd_op:02x}; reopening handle");
                        match dev.reopen() {
                            Ok(()) => log::info!("[{i:3}] handle reopened, session kept; resending"),
                            Err(re) => log::warn!("[{i:3}] reopen failed: {re}"),
                        }
                    } else {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
        }
        if !wrote {
            log::warn!("[{i:3}] cmd 0x{cmd_op:02x} write FAILED after reopen attempts: {last_err}");
            break;
        }
        // Consume every reply record for this command, decrypting in order. The
        // first reply may be slow (the sensor is imaging); extras arrive quickly.
        let mut got_reply = false;
        for attempt in 0..4 {
            let timeout = if attempt == 0 { 3000 } else { 200 };
            match dev.read_record(timeout) {
                Ok(wire) => {
                    let whead: String = wire.iter().take(8).map(|b| format!("{b:02x}")).collect();
                    log::info!("[{i:3}]   raw reply {}B: {whead} ...", wire.len());
                    match rec.decrypt(&wire) {
                    Ok((_rtype, plain_reply)) => {
                        got_reply = true;
                        let phead: String =
                            plain_reply.iter().take(16).map(|b| format!("{b:02x}")).collect();
                        log::info!("[{i:3}]   plaintext {}B: {phead}", plain_reply.len());
                        let (status, plen) = parse_reply(&plain_reply);
                        let ok = status_is_ok(status);
                        log::info!(
                            "[{i:3}] cmd=0x{cmd_op:02x} -> status=0x{status:04x} payload={plen}B {}",
                            if ok { "OK" } else { "**REJECT**" }
                        );
                        if !ok && first_reject.is_none() {
                            first_reject = Some((i, cmd_op, status));
                        }
                    }
                    Err(e) => log::warn!("[{i:3}] reply decrypt failed: {e}"),
                    }
                }
                Err(_) => break, // no more records for this command
            }
        }
        if !got_reply {
            log::info!("[{i:3}] cmd=0x{cmd_op:02x} -> (no reply)");
        }
        drain_image_into(dev, &mut img, 2);
        // Stop on a genuine reject (its status is the datum we need), or once we've
        // covered the calibration block + first poll cluster — enough to see how the
        // poll 0x02 commands answer without grinding through all 186 commands.
        if first_reject.is_some() {
            log::info!("stopping after first reject (diagnostic)");
            break;
        }
    }
    match first_reject {
        Some((i, op, status)) => log::warn!(
            "first capture reject at seq[{i}] cmd 0x{op:02x}: sensor status 0x{status:04x} \
             (see scsSensorParseReply_V4 code map)"
        ),
        None => log::info!("no capture command was rejected"),
    }
    log::info!("capture replayed ({} commands, {} image bytes)", seq.len(), img.len());
    Ok(img)
}

/// Read the plaintext image stream from EP2 until it stays quiet for `quiet_ms`
/// (after some data has arrived) or `max_ms` elapses. Returns the raw bytes.
pub fn read_ep2_stream(dev: &Sensor, quiet_ms: u64, max_ms: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let start = Instant::now();
    let mut last = Instant::now();
    loop {
        let chunk = dev.read_image(16384, 300);
        if !chunk.is_empty() {
            out.extend_from_slice(&chunk);
            last = Instant::now();
        } else if !out.is_empty() && last.elapsed() > Duration::from_millis(quiet_ms) {
            break;
        }
        if start.elapsed() > Duration::from_millis(max_ms) {
            break;
        }
    }
    out
}
