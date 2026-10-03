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

/// `capture_seq` indices of the two imaging commands (0x02 with a populated sign
/// key). Each opens a ~2.5 s window in which the sensor streams image lines; a
/// swipe must happen inside it (live-measured: the old cue, printed at idx 16,
/// came ~4 s before the first window and made users miss it).
const SWIPE_WINDOWS: [usize; 2] = [23, 27];

/// A user cue, one short colored line: red = don't touch, green = swipe,
/// yellow = wait. Kept to one or two words so it can be acted on at a glance.
enum Cue {
    DontTouch,
    Swipe,
    Wait,
}

/// `VFS_CUE_LED=<name>` (e.g. `capslock`): light `/sys/class/leds/*<name>` while
/// a swipe window is open. The only cue available where no terminal is — at the
/// login screen or under `sudo`, with the daemon running as a service.
fn cue_led(on: bool) {
    let Ok(name) = std::env::var("VFS_CUE_LED") else { return };
    let Ok(dir) = std::fs::read_dir("/sys/class/leds") else { return };
    for entry in dir.flatten() {
        if entry.file_name().to_string_lossy().ends_with(&name) {
            let _ = std::fs::write(entry.path().join("brightness"), if on { "1" } else { "0" });
        }
    }
}

fn cue(c: Cue, print: bool) {
    cue_led(matches!(c, Cue::Swipe));
    if !print {
        return;
    }
    use std::io::IsTerminal;
    let (bg, text) = match c {
        Cue::DontTouch => ("41", "  DON'T TOUCH  "),
        Cue::Swipe => ("42", "  SWIPE  \u{2193}  "),
        Cue::Wait => ("43", "  WAIT  "),
    };
    if std::io::stderr().is_terminal() {
        eprintln!("\x1b[1;30;{bg}m{text}\x1b[0m");
    } else {
        eprintln!("{}", text.trim());
    }
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

/// Wait up to `timeout_ms` for one EP1 record. With an EP2 sink, a scoped thread
/// reads EP2 continuously for the whole wait (as HP's driver does). Alternating
/// EP1/EP2 waits on one thread is NOT enough: the sensor's EP2 FIFO holds only
/// ~14 lines, so each 20 ms spent waiting on EP1 overflowed it and the sensor
/// dropped ~27 lines, corrupting every calibration sweep frame (NOTES.md
/// 2026-10-01). Without a sink, this is a plain `read_record`.
fn read_reply_interleaved(
    dev: &Sensor,
    timeout_ms: u64,
    img: Option<&mut Vec<u8>>,
) -> Result<Vec<u8>> {
    let Some(img) = img else {
        return dev.read_record(timeout_ms);
    };
    let done = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|s| {
        let reader = s.spawn(|| {
            let mut got = Vec::new();
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                got.extend_from_slice(&dev.read_image(EP2_CHUNK, 20));
            }
            got
        });
        let reply = dev.read_record(timeout_ms);
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        img.extend_from_slice(&reader.join().expect("EP2 reader panicked"));
        reply
    })
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

/// The commands of one imaging window, replayable any number of times after
/// [`Capture::prepare`]: the poll that precedes the imaging command, the imaging
/// command itself (`SWIPE_WINDOWS[1]`), and the two that close it. Live-checked
/// 2026-10-04: repeating this unit keeps returning full image bursts with no
/// recalibration.
const WINDOW_UNIT: std::ops::RangeInclusive<usize> = 26..=29;
/// Everything before the first window: setup, calibration (no finger!), arming.
const PREPARE: std::ops::Range<usize> = 0..22;
/// The recorded sequence's closing commands, sent when a request is over.
const FINISH: std::ops::Range<usize> = 30..42;

/// One in-session capture: replays the command sequence as AppData records (all
/// in-session commands are `0x17` records on EP1 regardless of their inner
/// command byte), decrypting every reply in order so the CBC IV chain and
/// receive sequence stay aligned, and draining + decrypting the EP2 image
/// stream throughout. Calibration results computed from this session's sweep
/// frames are patched into the later commands (see `calib.rs`).
pub struct Capture<'a> {
    dev: &'a mut Sensor,
    rec: &'a mut Record,
    cfg: &'a crate::session::Config,
    seq: Vec<Vec<u8>>,
    // The EP2 imaging burst is AES-256-CBC encrypted; the key/IV travel in each
    // GetFingerprint command's SecurityParams TLV (see `parse_security_params`).
    // Each such command resets the key and initial IV; the IV then chains across
    // EP2 reads (last ciphertext block -> next IV), exactly as HP's
    // `scsSensorDecryptFingerprint` does. EP2 reads are 16-byte aligned, so a
    // per-command slice is always a whole number of AES blocks.
    cur_key: Option<[u8; 32]>,
    cur_iv: [u8; 16],
    // Terminal cues (suppressed with VFS_NO_PROMPT, e.g. in the daemon).
    prompt: bool,
}

impl<'a> Capture<'a> {
    pub fn new(
        dev: &'a mut Sensor,
        rec: &'a mut Record,
        base: &Path,
        cfg: &'a crate::session::Config,
    ) -> Result<Self> {
        Ok(Capture {
            dev,
            rec,
            cfg,
            seq: load_sequence(base)?,
            cur_key: None,
            cur_iv: [0u8; 16],
            prompt: std::env::var("VFS_NO_PROMPT").is_err(),
        })
    }

    /// Setup + calibration, up to the first imaging window (~9 s). The sensor
    /// must not be touched while this runs.
    pub fn prepare(&mut self) -> Result<()> {
        cue(Cue::DontTouch, self.prompt);
        self.run(PREPARE).map(|_| ())
    }

    /// Open one imaging window (~3 s; the swipe cue is on while it records) and
    /// return its decrypted line stream.
    pub fn window(&mut self) -> Result<Vec<u8>> {
        let out = self.run(WINDOW_UNIT);
        cue(Cue::Wait, self.prompt);
        out
    }

    /// Close the capture (the recorded sequence's trailing commands).
    pub fn finish(&mut self) -> Result<()> {
        cue(Cue::DontTouch, self.prompt);
        self.run(FINISH).map(|_| ())
    }

    /// Send commands `idxs` of the sequence; returns the decrypted image bytes
    /// they produced.
    fn run(&mut self, idxs: impl IntoIterator<Item = usize>) -> Result<Vec<u8>> {
        let mut out = Vec::new(); // decrypted image line stream (01fe frames)
        // Experiment: the 1-byte 0x17 entries may be a trace artifact (the SSL AppData
        // record-type byte leaking into the command dump); each precedes a reset. Skip
        // them to test whether they are what triggers the imaging-latch re-enumeration.
        let skip_17 = std::env::var("VFS_SKIP_17").is_ok();
        for i in idxs {
            let plain = self.seq[i].clone();
            if skip_17 && plain.as_slice() == [0x17] {
                log::info!("[{i:3}] skipping 1-byte 0x17 (artifact test)");
                continue;
            }
            // The swipe cue goes on exactly when an imaging command is sent.
            if SWIPE_WINDOWS.contains(&i) {
                cue(Cue::Swipe, self.prompt);
            } else if i.checked_sub(1).is_some_and(|p| SWIPE_WINDOWS.contains(&p)) {
                cue(Cue::Wait, self.prompt);
            }
            let cmd_op = plain[0];
            if let Some((k, iv)) = parse_security_params(&plain) {
                self.cur_key = Some(k);
                self.cur_iv = iv;
                log::info!("[{i:3}] cmd=0x{cmd_op:02x} carries SecurityParams (AES-256 image key/IV)");
            }
            // send_cmd handles the imaging-latch re-enumeration: reopen the handle and
            // re-handshake a fresh session (the reset drops the old one), then resend.
            // Experiment: VFS_NO_REHANDSHAKE reopens but does NOT re-handshake, to test
            // whether the sensor enters an imaging mode that streams EP2 frames without
            // a fresh session (i.e. whether the re-handshake is what causes the reset loop).
            let recover = if std::env::var("VFS_NO_REHANDSHAKE").is_ok() { None } else { Some(self.cfg) };
            let mut img = Vec::new(); // this command's raw (encrypted) EP2 bytes
            match send_cmd_draining(self.dev, self.rec, &plain, recover, Some(&mut img)) {
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
                    cue_led(false);
                    anyhow::bail!("[{i}] cmd 0x{cmd_op:02x} write failed after recovery");
                }
            }
            // Keep draining until EP2 has been quiet for a few reads, or the burst
            // budget elapses. HP reads ~1.7 MB (~2.1 s at wire rate) after each
            // imaging latch before sending the next command; with no finger the sensor
            // streams baseline frames indefinitely, so the time bound is what ends it.
            drain_image_bounded(self.dev, &mut img, 3, EP2_BURST_MS);
            let slice = &img[..];
            if slice.is_empty() {
                continue;
            }
            let (mean, sd) = mean_sd(slice);
            log::info!("[{i:3}]   EP2 +{}B mean={mean:.1} sd={sd:.1}", slice.len());
            // Diagnostic: dump each command's raw EP2 slice (calibration RE).
            if let Ok(dir) = std::env::var("VFS_DUMP_SLICES") {
                let _ = std::fs::write(format!("{dir}/{i:02}_raw.bin"), slice);
            }
            // Calibration sweep frames arrive in the clear: compute this step's
            // result and carry it into the remaining commands (see calib.rs).
            // VFS_NO_CALIB replays the recorded values instead (A/B diagnostic).
            let calib = std::env::var("VFS_NO_CALIB").is_err();
            if let Some(applied) =
                calib.then(|| crate::calib::carry_forward(i, slice, &mut self.seq[i + 1..])).flatten()
            {
                log::info!("[{i:3}]   calibration: {applied}");
            }
            // Decrypt this command's EP2 slice under the active image key, chaining
            // the CBC IV forward for the next slice (matches HP's per-read decrypt).
            if let Some(k) = self.cur_key {
                let pt = crate::crypto::decrypt_image_stream(&k, &self.cur_iv, slice);
                if slice.len() >= 16 {
                    self.cur_iv.copy_from_slice(&slice[slice.len() - 16..]);
                }
                out.extend_from_slice(&pt);
            }
        }
        Ok(out)
    }
}

/// One whole recorded capture: calibration, the two imaging windows, closing
/// commands. Returns the decrypted image line stream of both windows. A finger
/// must be swiping during a window for real frames to appear.
pub fn arm_capture(
    dev: &mut Sensor,
    rec: &mut Record,
    base: &Path,
    cfg: &crate::session::Config,
) -> Result<Vec<u8>> {
    let mut cap = Capture::new(dev, rec, base, cfg)?;
    cue(Cue::DontTouch, cap.prompt);
    let n = cap.seq.len();
    let out = cap.run(0..n)?;
    cue(Cue::DontTouch, cap.prompt);
    log::info!("capture replayed ({n} commands, {} decrypted image bytes)", out.len());
    Ok(out)
}

// NOTE: The WOE-style poll-based finger detector (`capture_on_finger`, which
// polled seq[17] and watched the reply for divergence from a no-finger baseline)
// was removed after being falsified on hardware 2026-09-28: that poll is
// finger-blind (reply and pre-latch EP2 do not change on contact), so there is no
// pre-imaging signal to gate on. Finger presence is now decided from the decoded
// image via the ridge spectral peak (see `capture_frame` in main.rs and
// docs/STATUS.md §7). If a low-power gate is wanted later, investigate the unused
// EP3 interrupt endpoint or a dedicated WOE command rather than replaying a poll.

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
