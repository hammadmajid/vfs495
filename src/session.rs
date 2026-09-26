//! Open SSLv3 secure-session setup for the (unowned) VFS495.
//!
//! On an UNOWNED sensor the ClientKeyExchange is plain `RSA(premaster)` — no
//! `s_key` AES wrap — so a standard proprietary-SSLv3 handshake establishes the
//! session with no pairing. This module replays the observed static init (the
//! HP firmware "patch" uploads, kept out of the repo — see README), then runs
//! the handshake in open Rust and hands back an active [`Record`] layer.

use crate::crypto::{random_bytes, rsa_encrypt, ssl3_finished, ssl3_prf, Record};
use crate::usb::Sensor;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// "client finished" label = struct.pack("<I", 0x434C4E54).
const FINISHED_LABEL: [u8; 4] = [0x54, 0x4e, 0x4c, 0x43];

#[derive(Deserialize)]
struct InitStep {
    #[serde(default)]
    hex: Option<String>,
    #[serde(default)]
    blob: Option<String>,
}

#[derive(Deserialize)]
struct ModulusFile {
    exp: u64,
    modulus: String,
}

/// Filesystem locations of the runtime data the driver needs.
///
/// `init_seq` and `modulus` are non-secret and ship with the repo. `patch_dir`
/// holds HP firmware blobs that must NOT be redistributed; the user extracts
/// them from HP's package into `vendor/patches/` (see README).
pub struct Config {
    pub init_seq: PathBuf,
    pub modulus: PathBuf,
    pub patch_dir: PathBuf,
}

impl Config {
    /// Default layout, resolved against `base` (usually the repo / cwd).
    pub fn from_base(base: &Path) -> Self {
        Config {
            init_seq: base.join("captures/init_seq.json"),
            modulus: base.join("captures/modulus.json"),
            patch_dir: base.join("vendor/patches"),
        }
    }
}

/// The sensor's RSA public key.
pub struct PubKey {
    pub modulus_be: Vec<u8>,
    pub exp: u64,
}

pub fn load_pubkey(cfg: &Config) -> Result<PubKey> {
    let raw = std::fs::read_to_string(&cfg.modulus)
        .with_context(|| format!("reading {}", cfg.modulus.display()))?;
    let m: ModulusFile = serde_json::from_str(&raw)?;
    let modulus_be = hex::decode(m.modulus.trim())?;
    Ok(PubKey { modulus_be, exp: m.exp })
}

/// Wrap a secure record in the 0x11 "tunnel" command: `11 <u16 LE len> <record>`.
pub fn tunnel(record: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + record.len());
    out.push(0x11);
    out.extend_from_slice(&(record.len() as u16).to_le_bytes());
    out.extend_from_slice(record);
    out
}

/// Build the ClientHello record. Returns (wire_record, handshake_message).
fn client_hello(client_random: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sid = [0u8; 7];
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x00]); // client version SSLv3
    body.extend_from_slice(client_random);
    body.push(sid.len() as u8);
    body.extend_from_slice(&sid);
    body.extend_from_slice(&[0x00, 0x06]); // cipher-suites length
    body.extend_from_slice(&[0x00, 0x44, 0x00, 0x43, 0x00, 0x42]); // AES-256/192/128-CBC-SHA1
    body.push(0x00); // one compression method: null

    let mut hs = Vec::new();
    hs.push(0x01); // handshake type: ClientHello
    let l = (body.len() as u32).to_be_bytes();
    hs.extend_from_slice(&l[1..]); // u24 length
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.extend_from_slice(&[0x16, 0x03, 0x00]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    (rec, hs)
}

/// Replay the observed static init sequence (patch uploads + small commands).
pub fn replay_init(dev: &Sensor, cfg: &Config) -> Result<()> {
    let raw = std::fs::read_to_string(&cfg.init_seq)
        .with_context(|| format!("reading {}", cfg.init_seq.display()))?;
    let steps: Vec<InitStep> = serde_json::from_str(&raw)?;
    for step in &steps {
        let payload = if let Some(h) = &step.hex {
            hex::decode(h.trim())?
        } else if let Some(b) = &step.blob {
            let path = cfg.patch_dir.join(b);
            std::fs::read(&path).with_context(|| {
                format!(
                    "reading firmware patch {} — extract HP's package into vendor/patches/ (see README)",
                    path.display()
                )
            })?
        } else {
            bail!("init step has neither hex nor blob");
        };
        dev.write(&payload, 3000)?;
        dev.read(0x400, 3000)?;
        if payload.first() == Some(&0x1f) {
            dev.drain_image();
        }
    }
    log::info!("init replayed ({} steps)", steps.len());
    Ok(())
}

/// Run the full open handshake. On success returns the active record layer.
pub fn handshake(dev: &Sensor, cfg: &Config) -> Result<Record> {
    let key = load_pubkey(cfg)?;
    replay_init(dev, cfg)?;

    // ClientHello
    let client_random = random_bytes(32);
    let (ch_rec, ch_hs) = client_hello(&client_random);

    // Pre-compute the ClientKeyExchange (plain RSA on an unowned sensor).
    let mut premaster = vec![0x03u8, 0x00];
    premaster.extend_from_slice(&random_bytes(46));
    let enc = rsa_encrypt(&key.modulus_be, key.exp, &premaster);
    let mut cke_hs = vec![0x10, 0x00, 0x01, 0x00];
    cke_hs.extend_from_slice(&enc);
    let mut cke_rec = vec![0x16, 0x03, 0x00];
    cke_rec.extend_from_slice(&(cke_hs.len() as u16).to_be_bytes());
    cke_rec.extend_from_slice(&cke_hs);

    dev.write(&tunnel(&ch_rec), 3000)?;
    let sh = dev.read(0x400, 3000)?;
    if sh.len() < 43 {
        bail!("short ServerHello ({} bytes): {}", sh.len(), hex::encode(&sh));
    }
    log::info!("ServerHello {}B: {}", sh.len(), hex::encode(&sh[..16.min(sh.len())]));
    let shln = u16::from_be_bytes([sh[3], sh[4]]) as usize;
    let sh_hs = &sh[5..5 + shln.min(sh.len() - 5)];
    let server_random = sh[11..43].to_vec();

    // Derive keys and the Finished message over CH+SH+CKE.
    let master = ssl3_prf(&premaster, &client_random, &server_random, 48);
    let kb = ssl3_prf(&master, &server_random, &client_random, 136);
    let mut rec = Record::new(&kb);

    let mut transcript = Vec::new();
    transcript.extend_from_slice(&ch_hs);
    transcript.extend_from_slice(sh_hs);
    transcript.extend_from_slice(&cke_hs);
    let fin_body = ssl3_finished(&master, &transcript, &FINISHED_LABEL);
    let mut fin_hs = vec![0x14, 0x00, 0x00, 0x24];
    fin_hs.extend_from_slice(&fin_body);
    let ccs = [0x14u8, 0x03, 0x00, 0x00, 0x01, 0x01];
    let fin_rec = rec.encrypt(0x16, &fin_hs);

    let mut flight = Vec::new();
    flight.extend_from_slice(&cke_rec);
    flight.extend_from_slice(&ccs);
    flight.extend_from_slice(&fin_rec);
    dev.write(&tunnel(&flight), 3000)?;

    let resp = dev.read(0x400, 3000)?;
    if resp.is_empty() {
        bail!("no server response after Finished");
    }
    log::info!("server flight {}B: {}", resp.len(), hex::encode(&resp[..16.min(resp.len())]));
    match resp[0] {
        0x15 => Err(anyhow!(
            "ALERT level={} desc=0x{:02x} — handshake REJECTED",
            resp[resp.len() - 2],
            resp[resp.len() - 1]
        )),
        0x14 | 0x16 => {
            log::info!("HANDSHAKE OK — secure session established");
            // Consume the server's post-CCS records (the encrypted Finished) through
            // the Record layer so the receive sequence number and CBC IV chain (rseq,
            // siv) advance to their post-handshake state. Without this, decrypting the
            // first in-session reply would use a stale IV. The CCS record (type 0x14)
            // is plaintext and not sequence-numbered, so it is skipped, not decrypted.
            let mut off = 0usize;
            while off + 5 <= resp.len() {
                let rtype = resp[off];
                let ln = u16::from_be_bytes([resp[off + 3], resp[off + 4]]) as usize;
                let end = off + 5 + ln;
                if end > resp.len() {
                    break;
                }
                if rtype != 0x14 {
                    // 0x16 Finished (or any AppData) — advance rseq/siv.
                    if let Err(e) = rec.decrypt(&resp[off..end]) {
                        log::warn!("could not sync receive state on server record 0x{rtype:02x}: {e}");
                    }
                }
                off = end;
            }
            Ok(rec)
        }
        t => Err(anyhow!("unexpected server record type 0x{t:02x}")),
    }
}
