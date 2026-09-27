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

/// Sentinel status returned by `send_cmd` when VFS_HP_RESUME handled a
/// re-enumeration by skipping the (undelivered) reset-triggering command and
/// keeping the SSL Record continuous, so the caller should proceed to the next
/// command rather than treat this as a reject. Not a real device status.
const RESET_SKIPPED: u16 = 0xfffe;

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

/// Size of one EP2 bulk read. HP's driver reads the image stream in 16 KiB
/// chunks back to back; matching that keeps the sensor's FIFO from filling.
const EP2_CHUNK: usize = 16384;
/// Per-read EP2 timeout while a burst is flowing (a 16 KiB chunk lands in ~20 ms).
const EP2_READ_MS: u64 = 60;
/// Post-command EP2 drain budget. HP's imaging bursts run ~2.1 s per latch cycle.
const EP2_BURST_MS: u64 = 2500;

/// Drain all currently-available image bytes from EP2 into `img`.
///
/// Reads `EP2_CHUNK`-sized transfers until EP2 has been silent for `quiet_reads`
/// consecutive reads, or `max_ms` elapses. An imaging burst is ~1.7 MB, so the
/// bound is by time rather than by read count.
fn drain_image_into(dev: &Sensor, img: &mut Vec<u8>, quiet_reads: usize) {
    drain_image_bounded(dev, img, quiet_reads, 6000);
}

fn drain_image_bounded(dev: &Sensor, img: &mut Vec<u8>, quiet_reads: usize, max_ms: u64) {
    let start = Instant::now();
    let mut empties = 0;
    while start.elapsed() < Duration::from_millis(max_ms) {
        let chunk = dev.read_image(EP2_CHUNK, EP2_READ_MS);
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

/// Extract the AES-256 image key and IV from a GetFingerprint command's
/// SecurityParams TLV, if present.
///
/// HP builds the params in `scsGetSecurityParams`: a TLV with tag `0x0006` and
/// length `0x6a`, whose value holds the 32-byte AES-256 key at offset 0, the IV
/// at offset 0x20 (16 bytes used), a sign key at 0x40, and the cipher selector
/// `0x04` (AES-256) at 0x68 — all in the clear. The sensor encrypts the EP2
/// imaging burst under this key/IV; because we replay HP's exact command bytes,
/// the sensor uses HP's key, which we read straight back out here.
fn parse_security_params(plain: &[u8]) -> Option<([u8; 32], [u8; 16])> {
    // TLV header: tag 0x0006 (LE) + length 0x006a (LE) = 06 00 6a 00.
    let hdr = [0x06u8, 0x00, 0x6a, 0x00];
    let pos = plain.windows(4).position(|w| w == hdr)?;
    let v = plain.get(pos + 4..pos + 4 + 0x6a)?;
    // Only AES-256 (cipher byte 0x04) is handled; the key must be 32 bytes.
    if v.get(0x68) != Some(&0x04) {
        return None;
    }
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&v[0..32]);
    iv.copy_from_slice(&v[0x20..0x30]);
    Some((key, iv))
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
    send_cmd_draining(dev, rec, plain, recover, None)
}

/// `send_cmd` with an optional EP2 sink. When `img` is `Some`, the wait for each
/// EP1 reply is interleaved with EP2 reads: the sensor streams image data on EP2
/// as a side effect of the imaging-latch commands and stalls (then resets with
/// `-108`) if that stream is left undrained while we block on EP1. HP's driver
/// never gaps EP2; this keeps it flowing while still collecting the reply.
fn send_cmd_draining(
    dev: &mut Sensor,
    rec: &mut Record,
    plain: &[u8],
    recover: Option<&crate::session::Config>,
    mut img: Option<&mut Vec<u8>>,
) -> Option<(Vec<u8>, u16)> {
    // Experiment (VFS_HP_RESUME): snapshot the send-side Record state before this
    // command's encrypt, so if the write hits a re-enumeration we can UNDO its seq/IV
    // advance and continue the session exactly as HP does (HP never resends the
    // reset-triggering command; it just sends the next poll with continuing seq).
    let hp_resume = std::env::var("VFS_HP_RESUME").is_ok();
    let pre_encrypt = rec.clone();
    let mut record = rec.encrypt(APPDATA, plain);
    let mut wrote = false;
    let mut reopened = false;
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
                    reopened = true;
                    if hp_resume {
                        // HP-faithful: the undelivered command never reached the sensor,
                        // so roll the Record back and DON'T resend it. Continue to the
                        // next poll with an unbroken SSL sequence.
                        *rec = pre_encrypt;
                        log::info!(
                            "[DEBUG-rss] HP-resume: reopened, rolled back cmd 0x{:02x} (seq continuous), \
                             continuing WITHOUT resend/re-handshake",
                            plain[0]
                        );
                        return Some((Vec::new(), RESET_SKIPPED));
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
        match read_reply_interleaved(dev, timeout, img.as_deref_mut()) {
            Ok(wire) => {
            if reopened && attempt == 0 {
                // Raw record type of the first reply: 0x17=appdata (real reply),
                // 0x15=alert (session ALIVE but our seq/MAC desynced), all-zero
                // header => session DEAD (device not speaking SSL on EP1).
                let hdr: Vec<u8> = wire.iter().take(5).copied().collect();
                let kind = match wire.first() {
                    Some(0x17) => "appdata",
                    Some(0x15) => "ALERT(session-alive!)",
                    Some(0x16) => "handshake",
                    _ if wire.iter().take(3).all(|&b| b == 0) => "ZEROS(session-dead)",
                    _ => "other",
                };
                log::info!("[DEBUG-rss] first-reply raw hdr={hdr:02x?} => {kind}");
            }
            match rec.decrypt(&wire) {
                Ok((_t, plain_reply)) => {
                    let (status, _plen) = parse_reply(&plain_reply);
                    if reopened && attempt == 0 {
                        log::info!(
                            "[DEBUG-rss] post-reopen first reply DECRYPTED status=0x{status:04x} \
                             payload={}B => SESSION {}",
                            plain_reply.len().saturating_sub(2),
                            if status_is_ok(status) { "SURVIVED" } else { "?(status not OK)" }
                        );
                    }
                    last_status = status;
                    if plain_reply.len() > 2 {
                        payload.extend_from_slice(&plain_reply[2..]);
                    }
                }
                Err(e) => {
                    if reopened && attempt == 0 {
                        log::info!(
                            "[DEBUG-rss] post-reopen first reply DECRYPT FAILED ({e}) \
                             => SESSION DEAD (wire {} bytes: {:02x?})",
                            wire.len(),
                            &wire[..wire.len().min(8)]
                        );
                    }
                    log::warn!("reply decrypt failed: {e}");
                }
            }
            }
            Err(_) => break,
        }
    }
    Some((payload, last_status))
}

/// Wait up to `timeout_ms` for one EP1 record. With an EP2 sink, poll EP1 in
/// short slices and pull any pending image chunk between slices so the stream
/// never backs up; without one, this is a plain `read_record`.
fn read_reply_interleaved(
    dev: &Sensor,
    timeout_ms: u64,
    img: Option<&mut Vec<u8>>,
) -> Result<Vec<u8>> {
    let Some(img) = img else {
        return dev.read_record(timeout_ms);
    };
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        // Short first-byte wait; once a record starts, allow it to complete.
        match dev.read_record_split(20, 2000) {
            Ok(wire) => return Ok(wire),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => {}
        }
        let chunk = dev.read_image(EP2_CHUNK, 20);
        if !chunk.is_empty() {
            img.extend_from_slice(&chunk);
        }
    }
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
    let mut img = Vec::new();       // raw EP2 bytes (encrypted; kept for stats/logging)
    let mut out = Vec::new();       // decrypted image line stream (01fe frames)
    // The EP2 imaging burst is AES-256-CBC encrypted; the key/IV travel in each
    // GetFingerprint command's SecurityParams TLV (see `parse_security_params`).
    // Each such command resets the key and initial IV; the IV then chains across
    // EP2 reads (last ciphertext block -> next IV), exactly as HP's
    // `scsSensorDecryptFingerprint` does. EP2 reads are 16-byte aligned, so a
    // per-command slice is always a whole number of AES blocks.
    let mut cur_key: Option<[u8; 32]> = None;
    let mut cur_iv = [0u8; 16];
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
            // In daemon/quiet mode the host UI (GNOME/fprintd) shows its own prompt,
            // so suppress ours; still pause so a finger already on the sensor lands
            // within the imaging window.
            if std::env::var("VFS_NO_PROMPT").is_err() {
                eprintln!("\n>>> PRESS AND HOLD your finger on the sensor NOW (firm, steady) <<<\n");
            }
            std::thread::sleep(std::time::Duration::from_millis(1200));
        }
        let cmd_op = plain[0];
        if let Some((k, iv)) = parse_security_params(plain) {
            cur_key = Some(k);
            cur_iv = iv;
            log::info!("[{i:3}] cmd=0x{cmd_op:02x} carries SecurityParams (AES-256 image key/IV)");
        }
        // send_cmd handles the imaging-latch re-enumeration: reopen the handle and
        // re-handshake a fresh session (the reset drops the old one), then resend.
        // Experiment: VFS_NO_REHANDSHAKE reopens but does NOT re-handshake, to test
        // whether the sensor enters an imaging mode that streams EP2 frames without
        // a fresh session (i.e. whether the re-handshake is what causes the reset loop).
        let recover = if std::env::var("VFS_NO_REHANDSHAKE").is_ok() { None } else { Some(cfg) };
        let before = img.len();
        match send_cmd_draining(dev, rec, plain, recover, Some(&mut img)) {
            Some((_, RESET_SKIPPED)) => {
                log::info!(
                    "[{i:3}] cmd=0x{cmd_op:02x} -> RE-ENUM, skipped (HP-resume); next cmd tests session survival"
                );
            }
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
        // Keep draining until EP2 has been quiet for a few reads, or the burst
        // budget elapses. HP reads ~1.7 MB (~2.1 s at wire rate) after each
        // imaging latch before sending the next command; with no finger the sensor
        // streams baseline frames indefinitely, so the time bound is what ends it.
        drain_image_bounded(dev, &mut img, 3, EP2_BURST_MS);
        let slice = &img[before..];
        let (mean, sd) = mean_sd(slice);
        if !slice.is_empty() {
            log::info!("[{i:3}]   EP2 +{}B mean={mean:.1} sd={sd:.1}", slice.len());
            // Decrypt this command's EP2 slice under the active image key, chaining
            // the CBC IV forward for the next slice (matches HP's per-read decrypt).
            if let Some(k) = cur_key {
                let pt = crate::crypto::decrypt_image_stream(&k, &cur_iv, slice);
                if slice.len() >= 16 {
                    cur_iv.copy_from_slice(&slice[slice.len() - 16..]);
                }
                out.extend_from_slice(&pt);
            }
        }
    }
    log::info!(
        "capture replayed ({} commands, {} raw EP2 bytes, {} decrypted image bytes)",
        seq.len(),
        img.len(),
        out.len()
    );
    Ok(out)
}

/// Number of leading poll replies used to build the no-finger baseline.
const BASELINE_POLLS: usize = 3;
/// Sequence index of the setup-safe poll command (0x02, ~2.4 KB reply, does NOT
/// fire the big imaging burst) used for WOE-style finger detection.
const POLL_IDX: usize = 17;

/// Count payload bytes that differ from the baseline by more than a small margin.
/// A no-finger poll reply is near-constant (this count stays in the low single
/// digits); a finger shifts many AFE registers at once, so the count jumps.
fn payload_delta(cur: &[u8], base: &[u8]) -> usize {
    let n = cur.len().min(base.len());
    (0..n).filter(|&i| (cur[i] as i32 - base[i] as i32).abs() > 4).count()
}

/// Process one command's EP2 slice: track the active image key, decrypt the slice
/// with the chained CBC IV, and append plaintext to `out`. Shared by the imaging
/// tail of `capture_on_finger`.
fn process_image_command(
    dev: &mut Sensor,
    rec: &mut Record,
    plain: &[u8],
    cfg: &crate::session::Config,
    cur_key: &mut Option<[u8; 32]>,
    cur_iv: &mut [u8; 16],
    img: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> bool {
    if let Some((k, iv)) = parse_security_params(plain) {
        *cur_key = Some(k);
        *cur_iv = iv;
    }
    let before = img.len();
    if send_cmd_draining(dev, rec, plain, Some(cfg), Some(img)).is_none() {
        return false;
    }
    drain_image_bounded(dev, img, 3, EP2_BURST_MS);
    let slice = &img[before..];
    if !slice.is_empty() {
        if let Some(k) = *cur_key {
            let pt = crate::crypto::decrypt_image_stream(&k, cur_iv, slice);
            if slice.len() >= 16 {
                cur_iv.copy_from_slice(&slice[slice.len() - 16..]);
            }
            out.extend_from_slice(&pt);
        }
    }
    true
}

/// WOE-style capture: reach poll-ready, then poll the sensor until a finger is
/// detected (the poll reply diverges from a no-finger baseline by more than
/// `contact_nd` bytes), and only then fire the imaging tail. Returns the decrypted
/// image stream on a touch, or `Ok(None)` if no finger arrives within
/// `max_wait_polls` polls (the imaging latch is never fired in that case, so the
/// sensor is not stressed on empty cycles). This mirrors HP's
/// `idsSensorWOEFingerprintPoll`: poll, watch for the contact event, then image.
pub fn capture_on_finger(
    dev: &mut Sensor,
    rec: &mut Record,
    base: &Path,
    cfg: &crate::session::Config,
    contact_nd: usize,
    max_wait_polls: usize,
) -> Result<Option<Vec<u8>>> {
    let seq = load_sequence(base)?;
    anyhow::ensure!(seq.len() > POLL_IDX + 1, "capture sequence too short");
    let mut junk = Vec::new();

    // 1. Reach poll-ready: replay setup/calibration up to (not including) the poll.
    for plain in seq.iter().take(POLL_IDX) {
        if send_cmd(dev, rec, plain, Some(cfg)).is_none() {
            anyhow::bail!("setup command 0x{:02x} failed", plain[0]);
        }
        drain_image_bounded(dev, &mut junk, 2, 1500);
        junk.clear();
    }

    // 2. Poll for a finger: send the poll repeatedly, build a no-finger baseline
    //    from the first few replies, then watch for a large payload divergence.
    let poll = seq[POLL_IDX].clone();
    let mut baseline: Vec<u8> = Vec::new();
    let mut detected = false;
    for n in 0..max_wait_polls {
        let Some((payload, status)) = send_cmd(dev, rec, &poll, Some(cfg)) else {
            log::warn!("poll {n} write failed");
            continue;
        };
        drain_image_bounded(dev, &mut junk, 2, 800);
        junk.clear();
        if !status_is_ok(status) || payload.is_empty() {
            continue;
        }
        if n < BASELINE_POLLS {
            if payload.len() > baseline.len() {
                baseline = payload.clone();
            }
            continue;
        }
        let nd = payload_delta(&payload, &baseline);
        log::debug!("poll {n}: payload {}B delta {nd} (contact if > {contact_nd})", payload.len());
        if nd > contact_nd {
            log::info!("finger detected on poll {n} (payload delta {nd} > {contact_nd})");
            detected = true;
            break;
        }
    }
    if !detected {
        return Ok(None);
    }

    // 3. Finger present: fire the imaging tail and decrypt the EP2 burst.
    let mut img = Vec::new();
    let mut out = Vec::new();
    let mut cur_key: Option<[u8; 32]> = None;
    let mut cur_iv = [0u8; 16];
    for plain in seq.iter().skip(POLL_IDX + 1) {
        if !process_image_command(dev, rec, plain, cfg, &mut cur_key, &mut cur_iv, &mut img, &mut out)
        {
            log::warn!("imaging command 0x{:02x} failed; stopping", plain[0]);
            break;
        }
    }
    log::info!("imaging tail: {} raw EP2 bytes, {} decrypted image bytes", img.len(), out.len());
    Ok(Some(out))
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
