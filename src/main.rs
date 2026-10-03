//! `vfs495` — command-line driver for the Validity VFS495 fingerprint sensor.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vfs495::{capture, crypto, image, session, swipe, usb, virtimage};

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
        /// Must match the poll: replay 0..poll_idx, then loop seq[poll_idx].
        #[arg(long, default_value_t = 17)]
        prefix: usize,
        /// Which sequence index to loop. Defaults to 17, the 0x02 GetFingerprint
        /// poll the daemon watches (capture::POLL_IDX). Index 16 is a 0x06
        /// calibration command with a constant reply — do not probe that.
        #[arg(long, default_value_t = 17)]
        poll_idx: usize,
        /// How many poll iterations to send.
        #[arg(long, default_value_t = 40)]
        iters: usize,
    },
    /// Live diagnostic: fire a full imaging capture, decode it, and print the
    /// finger-gate metric (contact rows) plus diagnostics and the daemon's
    /// accept/reject verdict — WITHOUT gating, so both a finger and a no-finger
    /// capture produce output. SWIPE a finger when prompted (this is a swipe
    /// sensor; a finger held still does not image).
    RidgeProbe {
        /// Contact-row threshold to report a verdict against (matches the
        /// daemon's --min-contact).
        #[arg(long, default_value_t = DEFAULT_MIN_CONTACT)]
        min_contact: usize,
        /// Also write the reconstructed image here for visual inspection.
        #[arg(long, default_value = "captures/ridge_probe.pgm")]
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
        /// Write the image exactly as `run`/`daemon` would feed it to libfprint.
        #[arg(long)]
        feed: bool,
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
        /// Minimum number of finger-contact rows (row sd >= 25 after removing the
        /// fixed column pattern) to accept a capture as a finger. Measured live:
        /// no finger 0, a swipe ~6000 (HP's recorded swipes ~3900).
        #[arg(long, default_value_t = DEFAULT_MIN_CONTACT)]
        min_contact: usize,
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
        Command::RidgeProbe { min_contact, out } => {
            let mut dev = usb::Sensor::open()?;
            let mut rec = session::handshake(&dev, &cfg)?;
            // Fire the full imaging sequence (same path the daemon arms on a
            // detected finger) and decode it, exactly as the daemon's gate does.
            let stream = capture::arm_capture(&mut dev, &mut rec, &cli.base, &cfg)?;
            let dli = image::DliConfig::load_main(&cli.base)?;
            let lines = image::decode_ep2(&stream, 272, &dli);
            println!(
                "[i] decrypted {} EP2 bytes -> {} decoded lines x {} cols",
                stream.len(),
                lines.rows,
                lines.cols
            );
            if lines.rows == 0 {
                bail!("no lines decoded — capture produced no frames");
            }
            let (gate, contact) = finger_gate(&lines, min_contact);
            let swipe = swipe::reconstruct_swipe(&lines);
            let verdict = gate && swipe.is_some();
            let (px, w, h) = swipe.unwrap_or_else(|| image::reconstruct(&lines, true));
            let ridge = image::ridge_peak(&px, w, h);
            println!("[i] reconstructed image: {w}x{h} ({})", if verdict { "swipe" } else { "no usable swipe" });
            println!("[i]   contact rows = {contact}   (THE gate — no finger 0, swipe thousands; gate >= {min_contact})");
            println!("[i]   ridge_peak   = {ridge:.2}   (diagnostic only — NOT a finger signal)");
            println!(
                "[{}] daemon verdict: {}",
                if verdict { "+" } else { "-" },
                if verdict { "FINGER (would feed)" } else { "no finger (would skip)" }
            );
            image::write_pgm(out.to_str().unwrap(), &px, w, h)?;
            println!("[+] wrote {} for visual inspection", out.display());
        }
        Command::Decode { input, out, stride, no_crop, feed } => {
            let raw = std::fs::read(&input)?;
            let cfg = image::DliConfig::load_main(&cli.base)?;
            let lines = image::decode_ep2(&raw, stride, &cfg);
            println!("[i] unpacked {} lines x {} cols", lines.rows, lines.cols);
            if lines.rows < 20 {
                bail!("too few lines ({}) — not a usable swipe", lines.rows);
            }
            let mut sd = lines.contact_sd();
            sd.sort_by(|a, b| a.partial_cmp(b).unwrap());
            if let (Some(lo), Some(hi)) = (sd.get(sd.len() / 10), sd.get(sd.len() * 9 / 10)) {
                println!(
                    "[i] contact sd p10={lo:.1} p90={hi:.1}; rows with contact (sd>=25): {}",
                    lines.contact_rows(25.0)
                );
            }
            let (px, w, h) = match (no_crop, swipe::reconstruct_swipe(&lines)) {
                (false, Some(img)) => img,
                (false, None) => {
                    println!("[!] no usable swipe (finger moving across the sensor); writing the raw band");
                    image::reconstruct(&lines, true)
                }
                (true, _) => image::reconstruct(&lines, false),
            };
            let (px, w, h) = if feed { image::window_for_feed(&px, w, h) } else { (px, w, h) };
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
            // Never feed a blank capture (a missed swipe) into an enrollment.
            let (accept, contact) = finger_gate(&lines, DEFAULT_MIN_CONTACT);
            if !accept {
                bail!("no finger detected ({contact} contact rows < {DEFAULT_MIN_CONTACT}) — nothing fed");
            }
            let Some((px, w, h)) = swipe::reconstruct_swipe(&lines) else {
                bail!("finger touched but did not swipe ({contact} contact rows, no motion) — nothing fed");
            };
            let (fpx, fw, fh) = image::window_for_feed(&px, w, h);
            // VFS_SAVE_FED=<dir>: keep every fed image + its decrypted stream (offline analysis).
            if let Ok(dir) = std::env::var("VFS_SAVE_FED") {
                let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis();
                image::write_pgm(&format!("{dir}/fed_{ts}.pgm"), &fpx, fw, fh)?;
                std::fs::write(format!("{dir}/fed_{ts}.stream"), &stream)?;
            }
            virtimage::send_image(&sock, &fpx, fw as u32, fh as u32)?;
            println!("[+] captured a {w}x{h} swipe ({contact} contact rows) and fed {fw}x{fh} to virtual_image");
        }
        Command::Daemon { socket, min_contact, once, gap } => {
            let sock = resolve_socket(socket)?;
            run_daemon(&cli.base, &cfg, &sock, min_contact, once, gap)?;
        }
    }
    Ok(())
}

/// Default `--min-contact`: well above a blank sensor (0) and far below a swipe
/// (~4000-6000 rows), so partial swipes still pass.
const DEFAULT_MIN_CONTACT: usize = 300;

/// The finger gate: enough decoded lines and at least `min_contact` rows with
/// real finger contact (see `Lines::contact_sd`). Returns (accept, contact rows).
fn finger_gate(lines: &image::Lines, min_contact: usize) -> (bool, usize) {
    let contact = lines.contact_rows(image::CONTACT_SD);
    (lines.rows >= 60 && contact >= min_contact, contact)
}

/// Capture one frame from the sensor and decode it to a reconstructed image,
/// reusing an already-open device and SSL session. Returns `Ok(None)` when the
/// capture holds no finger (too few decoded lines / low ridge), so the daemon can
/// skip idle cycles without treating them as errors. A USB/session error is
/// returned as `Err` for the caller to recover from (re-open + re-handshake) —
/// reusing one session across captures avoids the per-capture open/handshake churn
/// that was re-enumerating the sensor.
fn capture_frame(
    dev: &mut usb::Sensor,
    rec: &mut crypto::Record,
    base: &std::path::Path,
    cfg: &session::Config,
    dli: &image::DliConfig,
    min_contact: usize,
) -> Result<Option<(Vec<u8>, u32, u32)>> {
    // Fire the full imaging capture. The WOE poll gate (poll seq[17] and watch for
    // reply divergence) was falsified on hardware — that poll is finger-blind, so
    // there is no pre-latch signal to gate on (see docs/STATUS.md §7). We instead
    // image every cycle and decide from the picture; firing the latch per cycle is
    // safe (the "latch stresses the sensor" premise was falsified in session 4).
    let stream = capture::arm_capture(dev, rec, base, cfg)?;
    let lines = image::decode_ep2(&stream, 272, dli);
    if lines.rows < 60 {
        log::debug!("skip: no finger (only {} decoded lines)", lines.rows);
        return Ok(None);
    }
    // Gate on finger contact rows: with the fixed column pattern removed, a blank
    // sensor is quiet (row sd ~4) and a swiped finger's rows are ~25-60. (The old
    // ridge_peak gate measured noise statistics, not ridges — NOTES 2026-10-01.)
    let (accept, contact) = finger_gate(&lines, min_contact);
    if !accept {
        log::debug!("skip: no finger ({contact} contact rows < {min_contact})");
        return Ok(None);
    }
    let Some((px, w, h)) = swipe::reconstruct_swipe(&lines) else {
        log::info!("skip: finger touched but did not swipe ({contact} contact rows, no motion)");
        return Ok(None);
    };
    // Clamp the pixels we actually feed to a libfprint-acceptable height.
    let (fpx, fw, fh) = image::window_for_feed(&px, w, h);
    log::info!("finger captured: {w}x{h} ({contact} contact rows); feeding {fw}x{fh}");
    Ok(Some((fpx, fw as u32, fh as u32)))
}

/// (Re)establish a live session: recover the device (waiting out any USB
/// re-enumeration, falling back to a fresh open) and run the SSL handshake.
fn reestablish(dev: &mut usb::Sensor, cfg: &session::Config) -> Result<crypto::Record> {
    if dev.reopen().is_err() {
        // The handle could not be recovered in place (e.g. the device fully went
        // away); open the current device from scratch.
        *dev = usb::Sensor::open()?;
    }
    session::handshake(dev, cfg)
}

/// Feeder loop: capture on each finger touch and push the image to libfprint's
/// virtual_image socket. The device is opened and the SSL session established
/// ONCE and reused across captures (per-capture open/handshake churn was
/// re-enumerating the sensor). A capture error rebuilds the session and continues,
/// so the daemon survives a re-enumeration or an fprintd restart.
fn run_daemon(
    base: &std::path::Path,
    cfg: &session::Config,
    sock: &str,
    min_contact: usize,
    once: bool,
    gap: u64,
) -> Result<()> {
    // Suppress the interactive capture prompt; the host UI drives the user.
    std::env::set_var("VFS_NO_PROMPT", "1");
    let dli = image::DliConfig::load_main(base)?;
    log::info!("vfs495 feeder daemon: socket {sock}, min_contact {min_contact}");
    log::info!("idle until libfprint opens the device (enroll/verify), then capturing");

    let mut dev = usb::Sensor::open()?;
    let mut rec = session::handshake(&dev, cfg)?;
    loop {
        // Capture only while something is waiting for a fingerprint: the sensor
        // stays idle otherwise, and no stale image is ever queued.
        let mut listener = virtimage::wait_for_listener(sock);
        log::info!("fingerprint requested; capturing");
        match capture_frame(&mut dev, &mut rec, base, cfg, &dli, min_contact) {
            Ok(Some((px, w, h))) => match virtimage::send_on(&mut listener, &px, w, h) {
                Ok(()) => log::info!("fed {w}x{h} image to virtual_image"),
                Err(e) => log::warn!("captured {w}x{h} but the request was gone: {e}"),
            },
            Ok(None) => log::info!("no usable swipe this cycle"),
            Err(e) => {
                // The session/device faulted (e.g. the sensor dropped off the bus).
                // Rebuild it rather than tight-looping: back off (also lets a USB
                // re-enumeration settle), then re-open + re-handshake. On persistent
                // failure keep retrying at a readable rate instead of spinning.
                log::warn!("capture cycle failed: {e}; rebuilding session");
                std::thread::sleep(std::time::Duration::from_secs(gap.max(3)));
                match reestablish(&mut dev, cfg) {
                    Ok(new_rec) => {
                        rec = new_rec;
                        log::info!("session re-established");
                    }
                    Err(e2) => log::warn!("session rebuild failed: {e2}; will retry"),
                }
                continue;
            }
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
