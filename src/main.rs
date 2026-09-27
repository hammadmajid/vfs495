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
    /// Live diagnostic: reach poll-ready state, then loop the poll command and dump
    /// each reply payload so a finger touch reveals the finger-contact signal.
    /// Never fires the imaging trigger, so the sensor does not reset.
    PollProbe {
        /// How many leading sequence commands to replay to reach poll-ready state.
        #[arg(long, default_value_t = 16)]
        prefix: usize,
        /// Which sequence index (a 0x02 poll command) to loop.
        #[arg(long, default_value_t = 16)]
        poll_idx: usize,
        /// How many poll iterations to send.
        #[arg(long, default_value_t = 40)]
        iters: usize,
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
    /// Run continuously as a feeder: capture on each finger touch, decode, and
    /// push the image to libfprint's virtual_image socket so fprintd/PAM/GDM can
    /// enroll and verify. Idle cycles (no finger) are skipped quietly.
    Daemon {
        /// Socket path (defaults to $FP_VIRTUAL_IMAGE).
        #[arg(long)]
        socket: Option<String>,
        /// Minimum ridge spectral peak-to-mean to accept a capture as a finger
        /// (finger ~1.8, blank noise ~1.1); paired with the crop-ratio test.
        #[arg(long, default_value_t = 1.4)]
        min_ridge: f32,
        /// Poll-reply byte-delta above the no-finger baseline that signals a
        /// finger touch (baseline jitter is ~4; a touch shifts many registers).
        #[arg(long, default_value_t = 30)]
        contact_nd: usize,
        /// Max polls to wait for a finger each cycle before giving up (no imaging).
        #[arg(long, default_value_t = 20)]
        max_wait_polls: usize,
        /// Capture a single frame and feed it, then exit (for testing).
        #[arg(long)]
        once: bool,
        /// Seconds to wait between capture cycles.
        #[arg(long, default_value_t = 1)]
        gap: u64,
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
            let stream = capture::arm_capture(&mut dev, &mut rec, &cli.base, &cfg)?;
            std::fs::write(&out, &stream)?;
            println!("[+] wrote {} decrypted image bytes to {}", stream.len(), out.display());
        }
        Command::PollProbe { prefix, poll_idx, iters } => {
            let mut dev = usb::Sensor::open()?;
            let mut rec = session::handshake(&dev, &cfg)?;
            capture::poll_probe(&mut dev, &mut rec, &cli.base, prefix, poll_idx, iters)?;
            println!("[+] poll-probe done");
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
            let stream = capture::arm_capture(&mut dev, &mut rec, &cli.base, &cfg)?;
            let cfg = image::DliConfig::load_main(&cli.base)?;
            let lines = image::decode_ep2(&stream, 272, &cfg);
            if lines.rows < 20 {
                bail!("capture produced too few lines ({})", lines.rows);
            }
            let (px, w, h) = image::reconstruct(&lines, true);
            virtimage::send_image(&sock, &px, w as u32, h as u32)?;
            println!("[+] captured {}x{} and fed virtual_image", w, h);
        }
        Command::Daemon { socket, min_ridge, contact_nd, max_wait_polls, once, gap } => {
            let sock = resolve_socket(socket)?;
            run_daemon(
                &cli.base, &cfg, &sock, min_ridge, contact_nd, max_wait_polls, once, gap,
            )?;
        }
    }
    Ok(())
}

/// Capture one frame from the sensor and decode it to a reconstructed image.
/// Returns `Ok(None)` when the capture holds no finger (too few decoded lines),
/// so the daemon can skip idle cycles without treating them as errors. Each call
/// opens a fresh session, which is the proven single-shot path; re-using a
/// session across captures is not yet validated.
fn capture_frame(
    base: &std::path::Path,
    cfg: &session::Config,
    dli: &image::DliConfig,
    min_ridge: f32,
    contact_nd: usize,
    max_wait_polls: usize,
) -> Result<Option<(Vec<u8>, u32, u32)>> {
    let mut dev = usb::Sensor::open()?;
    let mut rec = session::handshake(&dev, cfg)?;
    // Stage 1: poll the sensor and only fire the imaging latch once a finger is
    // actually present (WOE-style). Empty cycles return here without imaging.
    let Some(stream) =
        capture::capture_on_finger(&mut dev, &mut rec, base, cfg, contact_nd, max_wait_polls)?
    else {
        return Ok(None);
    };
    // Stage 2: confirm the decoded image really holds ridges before feeding.
    let lines = image::decode_ep2(&stream, 272, dli);
    if lines.rows < 60 {
        return Ok(None);
    }
    let (px, w, h) = image::reconstruct(&lines, true);
    // The sensor streams high-variance noise even with no finger, so contrast
    // alone can't gate. A real finger shows up two ways at once: the reconstruct
    // finger-segmentation crops to a distinct band (output height much smaller
    // than the decoded line count), and the image has a ridge spectral peak. A
    // blank capture stays near full height and is spectrally flat.
    let crop_ratio = h as f32 / lines.rows as f32;
    let pk = image::ridge_peak(&px, w, h);
    if crop_ratio > 0.6 || pk < min_ridge {
        log::debug!(
            "skip: no finger (crop_ratio {:.2}, ridge_peak {:.2} < {:.2})",
            crop_ratio,
            pk,
            min_ridge
        );
        return Ok(None);
    }
    log::info!("finger captured: {w}x{h} (crop_ratio {crop_ratio:.2}, ridge_peak {pk:.2})");
    Ok(Some((px, w as u32, h as u32)))
}

/// Feeder loop: capture on each finger touch and push the image to libfprint's
/// virtual_image socket. Errors on one cycle (a transient USB or socket failure)
/// are logged and the loop continues, so the daemon survives fprintd restarts.
fn run_daemon(
    base: &std::path::Path,
    cfg: &session::Config,
    sock: &str,
    min_ridge: f32,
    contact_nd: usize,
    max_wait_polls: usize,
    once: bool,
    gap: u64,
) -> Result<()> {
    // Suppress the interactive capture prompt; the host UI drives the user.
    std::env::set_var("VFS_NO_PROMPT", "1");
    let dli = image::DliConfig::load_main(base)?;
    log::info!("vfs495 feeder daemon: socket {sock}, min_ridge {min_ridge}, contact_nd {contact_nd}");
    log::info!("waiting for finger touches (press and hold when your desktop asks to scan)");
    loop {
        match capture_frame(base, cfg, &dli, min_ridge, contact_nd, max_wait_polls) {
            Ok(Some((px, w, h))) => match virtimage::send_image(sock, &px, w, h) {
                Ok(()) => log::info!("fed {w}x{h} image to virtual_image"),
                Err(e) => log::warn!(
                    "captured {w}x{h} but socket feed failed: {e}                      (is fprintd running with FP_VIRTUAL_IMAGE set to {sock}?)"
                ),
            },
            Ok(None) => log::debug!("no finger this cycle; skipping"),
            Err(e) => log::warn!("capture cycle failed: {e}"),
        }
        if once {
            break;
        }
        if gap > 0 {
            std::thread::sleep(std::time::Duration::from_secs(gap));
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
