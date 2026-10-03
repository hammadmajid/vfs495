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

/// Send one grayscale image to the virtual_image socket.
pub fn send_image(sock_path: &str, pixels: &[u8], width: u32, height: u32) -> Result<()> {
    let mut stream = UnixStream::connect(sock_path)
        .with_context(|| format!("connecting to FP_VIRTUAL_IMAGE socket {sock_path}"))?;
    send_on(&mut stream, pixels, width, height)
}

/// Block until libfprint is listening on the socket, i.e. until something has
/// opened the fingerprint device to enroll or verify, and return the connection.
/// The listener exists only while the device is open, so this is the daemon's
/// "someone is asking for a fingerprint" signal.
pub fn wait_for_listener(sock_path: &str) -> UnixStream {
    loop {
        if let Ok(stream) = UnixStream::connect(sock_path) {
            return stream;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
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
