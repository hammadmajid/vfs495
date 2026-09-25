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

/// Replay the in-session capture command sequence as AppData records (all
/// in-session commands are `0x17` records on EP1 regardless of their inner
/// command byte). The `0x04` poll command latches a frame and can be slow to
/// answer, so we wait on its reply rather than racing the next write (which the
/// busy device would NAK). Drains the plaintext image from EP2 throughout.
/// A finger must be swiping during the poll loop for real frames to appear.
pub fn arm_capture(dev: &mut Sensor, rec: &mut Record, base: &Path) -> Result<Vec<u8>> {
    let seq = load_sequence(base)?;
    let mut img = Vec::new();
    for plain in seq.iter() {
        let record = rec.encrypt(APPDATA, plain);
        // AppData records go directly on EP1 (no 0x11 tunnel) once the session is up.
        // Retry the write a few times without reopening — a NAK just means the
        // device is still finishing the previous (poll) command.
        let mut wrote = false;
        for _ in 0..3 {
            if dev.write(&record, 4000).is_ok() {
                wrote = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !wrote {
            log::warn!("cmd 0x{:02x} did not write after retries; continuing", plain[0]);
        }
        // Wait for the reply — poll/latch commands answer slowly.
        let _ = dev.read(0x1000, 4000);
        drain_image_into(dev, &mut img, 2);
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
