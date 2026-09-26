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
    // scsSensorParseReply_V4 does exact-match dispatch: only 0x0000 and 0x0412 map
    // to the OK path; every other code (incl. others with bit 0x0400 set, e.g.
    // 0x0401/0x0407/0x0431) is an error. Do NOT treat "bit 0x0400 clear" as OK.
    status == 0x0000 || status == 0x0412
}

/// Mean and standard deviation of a byte slice (pixel spread). A flat no-finger
/// baseline has near-zero sd; finger ridges raise it sharply.
fn mean_sd(data: &[u8]) -> (f64, f64) {
    if data.is_empty() {
        return (0.0, 0.0);
    }
    let n = data.len() as f64;
    let mean = data.iter().map(|&b| b as f64).sum::<f64>() / n;
    let var = data.iter().map(|&b| (b as f64 - mean).powi(2)).sum::<f64>() / n;
    (mean, var.sqrt())
}

/// Encrypt and send one plaintext in-session command, transparently re-acquiring
/// the USB handle if the sensor re-enumerates mid-flow (keeping the SSL session),
/// then decrypt and concatenate every reply record for it. Returns the joined
/// reply payloads (each reply's 2-byte status word stripped) and the status of
/// the last reply, or `None` if the write ultimately failed.
fn send_cmd(
    dev: &mut Sensor,
    rec: &mut Record,
    plain: &[u8],
    recover: Option<&crate::session::Config>,
) -> Option<(Vec<u8>, u16)> {
    let mut record = rec.encrypt(APPDATA, plain);
    let mut wrote = false;
    for _ in 0..4 {
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
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    // The re-enumeration drops the SSL session (post-reset reads are
                    // zeros). HP re-establishes it via a path not captured in the
                    // scsSend-only sequence dump, so re-run the handshake to get a
                    // fresh session, then re-encrypt this command under it.
                    if let Some(cfg) = recover {
                        match crate::session::handshake(dev, cfg) {
                            Ok(newrec) => {
                                *rec = newrec;
                                log::info!("re-handshaked a fresh session after reset");
                                record = rec.encrypt(APPDATA, plain);
                            }
                            Err(he) => log::warn!("re-handshake failed: {he}"),
                        }
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
        let _ = send_cmd(dev, rec, plain, None);
        drain_image_into(dev, &mut junk, 1);
    }
    let poll = seq[poll_idx].clone();
    log::info!(
        "poll-probe: looping poll seq[{poll_idx}] (0x{:02x}, {}B) x{iters}",
        poll[0],
        poll.len()
    );
    log::info!("KEEP FINGER OFF for polls 0-7 (baseline); then PRESS/HOLD ~8-19, LIFT ~20-27, PRESS ~28-39");
    // Deviation of each poll payload from a no-finger baseline (mean of the first
    // few polls). A finger changes the frame region, spiking sum/max delta.
    let mut baseline: Option<Vec<u8>> = None;
    let mut baseline_acc: Vec<Vec<u8>> = Vec::new();
    for n in 0..iters {
        match send_cmd(dev, rec, &poll, None) {
            Some((payload, status)) => {
                // Build the baseline from polls 2..=5 (finger expected off).
                if (2..=5).contains(&n) {
                    baseline_acc.push(payload.clone());
                    if n == 5 && !baseline_acc.is_empty() {
                        let len = baseline_acc[0].len();
                        let mut avg = vec![0u32; len];
                        for b in &baseline_acc {
                            for (i, &x) in b.iter().enumerate() {
                                avg[i] += x as u32;
                            }
                        }
                        baseline = Some(
                            avg.iter().map(|&s| (s / baseline_acc.len() as u32) as u8).collect(),
                        );
                    }
                }
                let (ndiff, maxd, sumd) = match &baseline {
                    Some(base) if base.len() == payload.len() => {
                        let mut nd = 0usize;
                        let mut mx = 0u32;
                        let mut sm = 0u64;
                        for (i, &x) in payload.iter().enumerate() {
                            let d = (x as i32 - base[i] as i32).unsigned_abs();
                            if d > 4 {
                                nd += 1;
                            }
                            if d > mx {
                                mx = d;
                            }
                            sm += d as u64;
                        }
                        (nd, mx, sm)
                    }
                    _ => (0, 0, 0),
                };
                // Also measure the EP2 image stream this iteration: finger ridges
                // raise the pixel spread far above a flat no-finger baseline.
                let mut ep2 = Vec::new();
                drain_image_into(dev, &mut ep2, 1);
                let (mean, sd) = mean_sd(&ep2);
                let _ = (ndiff, maxd, sumd);
                log::info!(
                    "poll {n:3}: status=0x{status:04x} pollΔ(nd={ndiff},max={maxd})  \
                     EP2 {}B mean={mean:.1} sd={sd:.1}",
                    ep2.len()
                );
            }
            None => log::warn!("poll {n:3}: write failed"),
        }
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
pub fn arm_capture(
    dev: &mut Sensor,
    rec: &mut Record,
    base: &Path,
    cfg: &crate::session::Config,
) -> Result<Vec<u8>> {
    let seq = load_sequence(base)?;
    let mut img = Vec::new();
    // Calibration (seq 0..~15) must run with NO finger. Cue a finger at the
    // poll/imaging boundary (override with VFS_SWIPE_AT; set huge to disable).
    let swipe_at: usize =
        std::env::var("VFS_SWIPE_AT").ok().and_then(|v| v.parse().ok()).unwrap_or(16);
    // Experiment: the 1-byte 0x17 entries may be a trace artifact (the SSL AppData
    // record-type byte leaking into the command dump); each precedes a reset. Skip
    // them to test whether they are what triggers the imaging-latch re-enumeration.
    let skip_17 = std::env::var("VFS_SKIP_17").is_ok();
    for (i, plain) in seq.iter().enumerate() {
        if skip_17 && plain.as_slice() == [0x17] {
            log::info!("[{i:3}] skipping 1-byte 0x17 (artifact test)");
            continue;
        }
        if i == swipe_at {
            eprintln!("\n>>> PRESS AND HOLD your finger on the sensor NOW (firm, steady) <<<\n");
            std::thread::sleep(std::time::Duration::from_millis(1200));
        }
        let cmd_op = plain[0];
        // send_cmd handles the imaging-latch re-enumeration: reopen the handle and
        // re-handshake a fresh session (the reset drops the old one), then resend.
        // Experiment: VFS_NO_REHANDSHAKE reopens but does NOT re-handshake, to test
        // whether the sensor enters an imaging mode that streams EP2 frames without
        // a fresh session (i.e. whether the re-handshake is what causes the reset loop).
        let recover = if std::env::var("VFS_NO_REHANDSHAKE").is_ok() { None } else { Some(cfg) };
        match send_cmd(dev, rec, plain, recover) {
            Some((payload, status)) => {
                let ok = status_is_ok(status);
                log::info!(
                    "[{i:3}] cmd=0x{cmd_op:02x} -> status=0x{status:04x} payload={}B {}",
                    payload.len(),
                    if ok { "OK" } else { "**REJECT**" }
                );
            }
            None => {
                log::warn!("[{i:3}] cmd 0x{cmd_op:02x} write failed after recovery; stopping");
                break;
            }
        }
        let before = img.len();
        drain_image_into(dev, &mut img, 2);
        let (mean, sd) = mean_sd(&img[before..]);
        if img.len() > before {
            log::info!("[{i:3}]   EP2 +{}B mean={mean:.1} sd={sd:.1}", img.len() - before);
        }
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
