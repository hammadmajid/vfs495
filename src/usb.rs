//! USB transport for the VFS495 over libusb (`rusb`).
//!
//! Interface 0, vendor-specific. Endpoints (confirmed by descriptor dump):
//!   * EP1 OUT  (0x01) bulk 64  — command channel
//!   * EP1 IN   (0x81) bulk 64  — command replies
//!   * EP2 IN   (0x82) bulk 64  — plaintext image stream
//!
//! Only reads and replays of byte sequences already observed from HP's binary
//! are performed here. No command is synthesised or fuzzed.

use anyhow::{anyhow, Context, Result};
use rusb::{Device, DeviceHandle, GlobalContext};
use std::time::Duration;

pub const VID: u16 = 0x138a;
pub const PID: u16 = 0x003f;
pub const EP_OUT: u8 = 0x01;
pub const EP_IN: u8 = 0x81;
pub const EP_IMG: u8 = 0x82;

/// An open, claimed handle to the sensor.
pub struct Sensor {
    handle: DeviceHandle<GlobalContext>,
    reattach: bool,
}

impl Sensor {
    /// Find, open and claim interface 0 of the first VFS495 on the bus.
    pub fn open() -> Result<Self> {
        let dev = find_device().context("VFS495 (138a:003f) not found on USB")?;
        let handle = dev.open().context("failed to open device (permissions? try sudo / udev rule)")?;

        let mut reattach = false;
        if handle.kernel_driver_active(0).unwrap_or(false) {
            handle
                .detach_kernel_driver(0)
                .context("failed to detach kernel driver")?;
            reattach = true;
        }
        handle.set_active_configuration(1).ok();
        handle.claim_interface(0).context("failed to claim interface 0")?;
        Ok(Sensor { handle, reattach })
    }

    /// Write a command to EP1 OUT.
    pub fn write(&self, data: &[u8], timeout_ms: u64) -> Result<usize> {
        self.handle
            .write_bulk(EP_OUT, data, Duration::from_millis(timeout_ms))
            .map_err(|e| anyhow!("EP_OUT write failed: {e}"))
    }

    /// Read a reply from EP1 IN.
    pub fn read(&self, max: usize, timeout_ms: u64) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; max];
        let n = self
            .handle
            .read_bulk(EP_IN, &mut buf, Duration::from_millis(timeout_ms))
            .map_err(|e| anyhow!("EP_IN read failed: {e}"))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Read a chunk of the image stream from EP2 IN. Returns an empty Vec on timeout.
    pub fn read_image(&self, max: usize, timeout_ms: u64) -> Vec<u8> {
        let mut buf = vec![0u8; max];
        match self
            .handle
            .read_bulk(EP_IMG, &mut buf, Duration::from_millis(timeout_ms))
        {
            Ok(n) => {
                buf.truncate(n);
                buf
            }
            Err(_) => Vec::new(),
        }
    }

    /// Drain any queued image data (used after the reset-image init command).
    pub fn drain_image(&self) {
        loop {
            let chunk = self.read_image(16384, 400);
            if chunk.len() < 16384 {
                break;
            }
        }
    }

    /// Convenience: write then read one reply.
    pub fn cmd(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.write(data, 3000)?;
        self.read(0x400, 3000)
    }

    /// Re-acquire the device after it re-enumerates (the capture flow issues
    /// `0x04` soft resets). The firmware keeps the SSL session across the reset,
    /// so callers keep their existing `Record`; only the USB handle changes.
    /// Retries for up to ~3s while the device comes back on the bus.
    pub fn reopen(&mut self) -> Result<()> {
        // drop the stale handle first
        let _ = self.handle.release_interface(0);
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(100));
            if let Some(dev) = find_device() {
                if let Ok(handle) = dev.open() {
                    self.reattach = false;
                    if handle.kernel_driver_active(0).unwrap_or(false) {
                        let _ = handle.detach_kernel_driver(0);
                        self.reattach = true;
                    }
                    handle.set_active_configuration(1).ok();
                    if handle.claim_interface(0).is_ok() {
                        self.handle = handle;
                        return Ok(());
                    }
                }
            }
        }
        anyhow::bail!("device did not re-enumerate within timeout after reset")
    }
}

impl Drop for Sensor {
    fn drop(&mut self) {
        let _ = self.handle.release_interface(0);
        if self.reattach {
            let _ = self.handle.attach_kernel_driver(0);
        }
    }
}

fn find_device() -> Option<Device<GlobalContext>> {
    rusb::devices().ok()?.iter().find(|d| {
        d.device_descriptor()
            .map(|desc| desc.vendor_id() == VID && desc.product_id() == PID)
            .unwrap_or(false)
    })
}
