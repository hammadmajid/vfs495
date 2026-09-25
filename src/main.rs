//! `vfs495` — command-line driver for the Validity VFS495 fingerprint sensor.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vfs495::{capture, image, session, usb, virtimage};

#[derive(Parser)]
#[command(name = "vfs495", version, about = "Open userspace driver for the Validity VFS495 (138a:003f)")]
struct Cli {
    /// Base directory holding captures/ and vendor/ (defaults to the current dir).
    #[arg(long, global = true, default_value = ".")]
    base: PathBuf,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Offline crypto self-test (no hardware). Validates the SSLv3 KDF byte-exact.
    Selftest,
    /// Live: replay init and run the open SSLv3 handshake, then exit.
    Handshake,
    /// Live: handshake, capture one swipe, and write a raw EP2 dump.
    Capture {
        /// Where to write the raw EP2 byte stream.
        #[arg(long, default_value = "captures/ep2_stream.bin")]
        out: PathBuf,
    },
    /// Decode a raw EP2 dump into a PGM (unpack + descramble + reconstruct).
    Decode {
        /// Raw EP2 byte-stream input.
        #[arg(long)]
        input: PathBuf,
        /// Output PGM path.
        #[arg(long, default_value = "captures/decoded.pgm")]
        out: PathBuf,
        /// Frame stride in bytes.
        #[arg(long, default_value_t = 272)]
        stride: usize,
        /// Keep the full frame instead of cropping to the finger band.
        #[arg(long)]
        no_crop: bool,
    },
    /// Decode already-descrambled scan lines (`<u16 w><w bytes>` records) to PGM.
    /// Fully-open path from UnpackLineRT output to a fingerprint image.
    DecodeLines {
        /// lines.raw-format input.
        #[arg(long)]
        input: PathBuf,
        /// Output PGM path.
        #[arg(long, default_value = "captures/decoded.pgm")]
        out: PathBuf,
        /// Crop to the finger-present band (off by default; lines.raw is already finger data).
        #[arg(long)]
        crop: bool,
    },
    /// Send a PGM image to the libfprint virtual_image socket ($FP_VIRTUAL_IMAGE).
    Feed {
        /// PGM image to send.
        #[arg(long)]
        image: PathBuf,
        /// Socket path (defaults to $FP_VIRTUAL_IMAGE).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Live end-to-end: handshake → capture → decode → feed virtual_image.
    Run {
        /// Socket path (defaults to $FP_VIRTUAL_IMAGE).
        #[arg(long)]
        socket: Option<String>,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let cfg = session::Config::from_base(&cli.base);

    match cli.cmd {
        Command::Selftest => {
            let ok = vfs495::selftest(&cli.base)?;
            println!("\n=== SELFTEST: {} ===", if ok { "PASS" } else { "FAIL" });
            std::process::exit(if ok { 0 } else { 1 });
        }
        Command::Handshake => {
            let dev = usb::Sensor::open()?;
            let _rec = session::handshake(&dev, &cfg)?;
            println!("[+] handshake OK — secure session established");
        }
        Command::Capture { out } => {
            let mut dev = usb::Sensor::open()?;
            let mut rec = session::handshake(&dev, &cfg)?;
            let mut stream = capture::arm_capture(&mut dev, &mut rec, &cli.base)?;
            eprintln!(">> swipe your finger now");
            stream.extend(capture::read_ep2_stream(&dev, 1200, 15000));
            std::fs::write(&out, &stream)?;
            println!("[+] wrote {} ({} bytes)", out.display(), stream.len());
        }
        Command::Decode { input, out, stride, no_crop } => {
            let raw = std::fs::read(&input)?;
            let cfg = image::DliConfig::load_main(&cli.base)?;
            let lines = image::decode_ep2(&raw, stride, &cfg);
            println!("[i] unpacked {} lines x {} cols", lines.rows, lines.cols);
            if lines.rows < 20 {
                bail!("too few lines ({}) — not a usable swipe", lines.rows);
            }
            let (px, w, h) = image::reconstruct(&lines, !no_crop);
            image::write_pgm(out.to_str().unwrap(), &px, w, h)?;
            println!("[+] wrote {} ({}x{})", out.display(), w, h);
        }
        Command::DecodeLines { input, out, crop } => {
            let raw = std::fs::read(&input)?;
            let lines = image::load_lines_raw(&raw);
            println!("[i] loaded {} lines x {} cols", lines.rows, lines.cols);
            if lines.rows < 20 {
                bail!("too few lines ({})", lines.rows);
            }
            let (px, w, h) = image::reconstruct(&lines, crop);
            image::write_pgm(out.to_str().unwrap(), &px, w, h)?;
            println!("[+] wrote {} ({}x{})", out.display(), w, h);
        }
        Command::Feed { image: img, socket } => {
            let sock = resolve_socket(socket)?;
            let (px, w, h) = read_pgm(&img)?;
            virtimage::send_image(&sock, &px, w, h)?;
            println!("[+] fed {}x{} image to {sock}", w, h);
        }
        Command::Run { socket } => {
            let sock = resolve_socket(socket)?;
            let mut dev = usb::Sensor::open()?;
            let mut rec = session::handshake(&dev, &cfg)?;
            let mut stream = capture::arm_capture(&mut dev, &mut rec, &cli.base)?;
            eprintln!(">> swipe your finger now");
            stream.extend(capture::read_ep2_stream(&dev, 1200, 15000));
            let cfg = image::DliConfig::load_main(&cli.base)?;
            let lines = image::decode_ep2(&stream, 272, &cfg);
            if lines.rows < 20 {
                bail!("capture produced too few lines ({})", lines.rows);
            }
            let (px, w, h) = image::reconstruct(&lines, true);
            virtimage::send_image(&sock, &px, w as u32, h as u32)?;
            println!("[+] captured {}x{} and fed virtual_image", w, h);
        }
    }
    Ok(())
}

fn resolve_socket(opt: Option<String>) -> Result<String> {
    match opt.or_else(|| std::env::var("FP_VIRTUAL_IMAGE").ok()) {
        Some(s) => Ok(s),
        None => bail!("no socket: pass --socket or set FP_VIRTUAL_IMAGE"),
    }
}

fn read_pgm(path: &PathBuf) -> Result<(Vec<u8>, u32, u32)> {
    let raw = std::fs::read(path)?;
    // parse a minimal P5 header
    let mut pos = 0usize;
    let mut tokens = Vec::new();
    while tokens.len() < 4 && pos < raw.len() {
        while pos < raw.len() && (raw[pos] as char).is_whitespace() {
            pos += 1;
        }
        let start = pos;
        while pos < raw.len() && !(raw[pos] as char).is_whitespace() {
            pos += 1;
        }
        tokens.push(String::from_utf8_lossy(&raw[start..pos]).to_string());
    }
    if tokens.len() < 4 || tokens[0] != "P5" {
        bail!("not a P5 PGM");
    }
    let w: u32 = tokens[1].parse()?;
    let h: u32 = tokens[2].parse()?;
    pos += 1; // single whitespace after maxval
    let need = (w * h) as usize;
    if pos + need > raw.len() {
        bail!("PGM truncated");
    }
    Ok((raw[pos..pos + need].to_vec(), w, h))
}
