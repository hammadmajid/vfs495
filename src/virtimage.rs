//! libfprint `virtual_image` feeder.
//!
//! libfprint's `virtual_image` driver is the *listener* on the UNIX socket named
//! by `$FP_VIRTUAL_IMAGE`; a client connects and sends one image per scan as
//! `<i32 width LE><i32 height LE><width*height grayscale bytes>`. This is the
//! exact link proven end-to-end by `scripts/vimage_proof.py`: image → minutiae →
//! enroll / verify. Feeding decoded VFS495 images here makes the sensor usable
//! through stock fprintd / PAM / GDM with no custom C driver.

use anyhow::{Context, Result};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// Send one grayscale image to the virtual_image socket.
pub fn send_image(sock_path: &str, pixels: &[u8], width: u32, height: u32) -> Result<()> {
    let mut stream = UnixStream::connect(sock_path)
        .with_context(|| format!("connecting to FP_VIRTUAL_IMAGE socket {sock_path}"))?;
    send_on(&mut stream, pixels, width, height)
}

/// Whether fprintd is waiting for a finger right now (an enroll or verify is in
/// progress), from its `finger-needed` D-Bus property. An open device alone does
/// not mean that: GNOME Settings keeps the device claimed for as long as its
/// fingerprint dialog is open. Never starts fprintd.
fn finger_needed() -> bool {
    let device = std::env::var("VFS_FPRINTD_DEVICE").unwrap_or_else(|_| "/net/reactivated/Fprint/Device/0".into());
    std::process::Command::new("busctl")
        .args(["--system", "--auto-start=no", "get-property", "net.reactivated.Fprint"])
        .args([device.as_str(), "net.reactivated.Fprint.Device", "finger-needed"])
        .output()
        .map(|o| o.status.success() && o.stdout.starts_with(b"b true"))
        .unwrap_or(false)
}

/// Wait until a fingerprint is actually being asked for and return a connection
/// to libfprint's listener, or `None` after `timeout` (`None` = wait forever).
/// `via_fprintd`: also require fprintd's `finger-needed`; otherwise an open
/// device (listening socket) is enough, which is right when a program drives
/// libfprint directly.
pub fn wait_for_request(sock_path: &str, via_fprintd: bool, timeout: Option<Duration>) -> Option<UnixStream> {
    let start = Instant::now();
    loop {
        if std::path::Path::new(sock_path).exists() && (!via_fprintd || finger_needed()) {
            if let Ok(stream) = UnixStream::connect(sock_path) {
                return Some(stream);
            }
        }
        if timeout.is_some_and(|t| start.elapsed() >= t) {
            return None;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Whether the request this connection was opened for is still waiting for a
/// finger: libfprint has not closed the device, and (via fprintd) a scan is
/// still in progress.
pub fn still_wanted(stream: &UnixStream, via_fprintd: bool) -> bool {
    use std::io::Read;
    let mut probe = [0u8; 1];
    let open = stream.set_nonblocking(true).is_ok()
        && matches!((&*stream).read(&mut probe), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock);
    let _ = stream.set_nonblocking(false);
    open && (!via_fprintd || finger_needed())
}

/// Send one grayscale image on an established connection.
pub fn send_on(stream: &mut UnixStream, pixels: &[u8], width: u32, height: u32) -> Result<()> {
    anyhow::ensure!(
        pixels.len() == (width as usize) * (height as usize),
        "pixel buffer {} != {}x{}",
        pixels.len(),
        width,
        height
    );
    let mut msg = Vec::with_capacity(8 + pixels.len());
    msg.extend_from_slice(&(width as i32).to_le_bytes());
    msg.extend_from_slice(&(height as i32).to_le_bytes());
    msg.extend_from_slice(pixels);
    stream.write_all(&msg).context("writing image to socket")?;
    Ok(())
}
