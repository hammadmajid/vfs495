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

/// The `0x04` command soft-resets the sensor (it re-enumerates on USB).
const RESET_CMD: u8 = 0x04;

/// Arm capture by replaying the in-session command sequence as AppData records,
/// handling the `0x04` soft resets (re-acquire the USB handle, keep the SSL
/// session), and draining image bytes that arrive between commands. Returns the
/// image bytes seen during arming. `dev` may point at a new USB handle on return.
pub fn arm_capture(dev: &mut Sensor, rec: &mut Record, base: &Path) -> Result<Vec<u8>> {
    let seq = load_sequence(base)?;
    let mut img = Vec::new();
    for (i, plain) in seq.iter().enumerate() {
        let record = rec.encrypt(APPDATA, plain);
        // AppData records go directly on EP1 (no 0x11 tunnel) once the session is up.
        match dev.write(&record, 3000) {
            Ok(_) => {
                let _ = dev.read(0x1000, 800); // discard encrypted reply
                let chunk = dev.read_image(16384, 50);
                if !chunk.is_empty() {
                    img.extend_from_slice(&chunk);
                }
            }
            Err(e) => {
                // a stale handle after an earlier reset shows up as "No such device"
                log::warn!("cmd {i} (0x{:02x}) write failed ({e}); re-acquiring device", plain[0]);
                dev.reopen()?;
                let _ = dev.write(&record, 3000); // retry once on the fresh handle
                let _ = dev.read(0x1000, 800);
            }
        }
        // after a soft-reset command, the device re-enumerates: swap the handle,
        // keep the Record (firmware preserves the session across the reset).
        if plain[0] == RESET_CMD {
            log::info!("cmd {i}: 0x04 reset — re-acquiring device");
            dev.reopen()?;
        }
    }
    log::info!("capture armed ({} commands, {} early image bytes)", seq.len(), img.len());
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
