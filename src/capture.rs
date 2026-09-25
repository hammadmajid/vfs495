//! In-session image capture over the established secure channel.
//!
//! Capture is driven by in-session AppData commands (the `0x02` family) sent
//! through the [`Record`] layer; the sensor then streams the plaintext image on
//! EP2. The exact command/config blob is device-specific and derived from an HP
//! trace, so it is not committed — supply it as a JSON array of hex strings via
//! `captures/capture_cmd.json` (see README). Without that file this reads the
//! raw EP2 stream only (useful when HP's tooling has already armed capture).

use crate::crypto::Record;
use crate::usb::Sensor;
use anyhow::{Context, Result};
use std::path::Path;
use std::time::{Duration, Instant};

const APPDATA: u8 = 0x17;

/// Send the observed capture command(s), if `captures/capture_cmd.json` exists.
pub fn arm_capture(dev: &Sensor, rec: &mut Record, base: &Path) -> Result<bool> {
    let path = base.join("captures/capture_cmd.json");
    if !path.exists() {
        log::warn!(
            "no {} — skipping arm step (streaming EP2 only)",
            path.display()
        );
        return Ok(false);
    }
    let raw = std::fs::read_to_string(&path)?;
    let cmds: Vec<String> = serde_json::from_str(&raw)?;
    for c in &cmds {
        let plain = hex::decode(c.trim()).context("bad hex in capture_cmd.json")?;
        let record = rec.encrypt(APPDATA, &plain);
        dev.write(&crate::session::tunnel(&record), 3000)?;
        let _ = dev.read(0x400, 1500);
    }
    log::info!("capture armed ({} commands)", cmds.len());
    Ok(true)
}

/// Read the plaintext image stream from EP2 until it stays quiet for `quiet_ms`
/// or `max_ms` elapses. Returns the concatenated raw bytes.
pub fn read_ep2_stream(dev: &Sensor, quiet_ms: u64, max_ms: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let start = Instant::now();
    let mut last = Instant::now();
    loop {
        let chunk = dev.read_image(16384, 300);
        if !chunk.is_empty() {
            out.extend_from_slice(&chunk);
            last = Instant::now();
        } else if last.elapsed() > Duration::from_millis(quiet_ms) && !out.is_empty() {
            break;
        }
        if start.elapsed() > Duration::from_millis(max_ms) {
            break;
        }
    }
    out
}
