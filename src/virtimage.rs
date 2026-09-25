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
    anyhow::ensure!(
        pixels.len() == (width as usize) * (height as usize),
        "pixel buffer {} != {}x{}",
        pixels.len(),
        width,
        height
    );
    let mut stream = UnixStream::connect(sock_path)
        .with_context(|| format!("connecting to FP_VIRTUAL_IMAGE socket {sock_path}"))?;
    let mut msg = Vec::with_capacity(8 + pixels.len());
    msg.extend_from_slice(&(width as i32).to_le_bytes());
    msg.extend_from_slice(&(height as i32).to_le_bytes());
    msg.extend_from_slice(pixels);
    stream.write_all(&msg).context("writing image to socket")?;
    Ok(())
}
