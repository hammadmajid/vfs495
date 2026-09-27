# VFS495 open driver — project status & reverse-engineering reference

A distilled, organized digest of the project's established facts, the reverse
engineering of HP's binary, and the current state of the open driver. For the
chronological, dated reasoning and evidence behind every claim here, see
[`../NOTES.md`](../NOTES.md). For build and usage, see [`../README.md`](../README.md).

Status as of 2026-09-28: **the full open capture path — secure session, transport,
image decryption, decode, and reconstruction — runs in open Rust with no HP code
and is live-confirmed on hardware.** A feeder daemon bridges it to libfprint for
GNOME/fprintd. Finger detection uses a **ridge-peak gate** on each decoded capture
(live-confirmed 2026-09-28: finger 2.10 vs no-finger 1.21); the earlier WOE
poll-divergence gate was falsified as finger-blind and removed (see §7). Remaining
work is the end-to-end daemon → fprintd enroll/verify run and integration polish —
no protocol unknowns.

---

## 1. Target and constraints

- **Sensor:** Validity VFS495 ("Falcon"), USB `138a:003f`, HP EliteBook 820 G3
  and other 2015-era HP laptops. `bcdDevice 1.04`. Endpoints: EP1 IN/OUT bulk 64,
  EP2 IN bulk 64 (image), EP3 IN interrupt 8.
- **Repo:** local-only git at `~/Developer/lab/vfs495`, no remote, never
  published. HP's package and all extractions live in `vendor/` (gitignored,
  never committed). Biometric captures, raw USB traces, and HP patch blobs are
  also gitignored.
- **Do not**, without explicit user OK: send `TakeOwnership` / `setowner` /
  `resetowner` (persistent, cycle-limited sensor writes), or change system
  fprintd / PAM / authselect / GDM config.

---

## 2. Key established facts

### Secure session (SSLv3-RSA)
- The sensor wraps every command in a **proprietary variant of SSLv3-RSA**
  (cipher suite `0x0044` = AES-256-CBC + SHA-1).
- Prior art (saifulmd0/vfs495-linux) hit fatal alert **`0x2f`** because on an
  **owned** sensor the `ClientKeyExchange` wraps the premaster secret in
  `AES-256-CBC(s_key)` before RSA, where `s_key` is a 32-byte DH-derived shared
  secret set at pairing.
- **This sensor is UNOWNED** (`get_ownership_info` → 65535/65535 cycles left). On
  an unowned sensor the `s_key` wrap is skipped, so a **standard open SSLv3
  client establishes the session with no pairing at all** — the wall every prior
  VFS495 project hit. Proven live in Rust (`vfs495 handshake` → CCS + Finished,
  no alert).
- The sensor's RSA pubkey (2048-bit, `e=65537`) modulus is in
  `captures/modulus.json`. The sensor ships the pubkey in an opaque signed key
  blob on EP2 during init (no clean TLV/length anchor → kept file-based per
  device; dump with `scripts/dump_modulus.gdb.py`).

### Pairing (not needed here, fully mapped)
- **Pairing = "TakeOwnership"**: cmd `0x0f` (DH → `s_key`) + cmd `0x2c` (host RSA
  keypair). Reversible via `ResetOwnership`; 65535 ownership cycles. Credentials
  are stored host-side in `/etc/ValidityPersistentData` (GSKGlobal-wrapped),
  keyed by sensor serial. Not implemented — this sensor is unowned.

### Reply format
- In-session replies are plain SSLv3 AppData records (`17 03 00 <len> <ct>`) on
  EP1 — no tunnel (the `0x11` tunnel is handshake-only). Decrypted reply
  plaintext = **`u16 LE status` + optional payload**. `0x0000` / `0x0412` = OK;
  any status with bit `0x0400` set = error. A bare ack is 2 bytes (`00 00`).
- The earlier "capture is a blocked, un-replayable interactive protocol"
  conclusion was an artifact of misparsing the 2-byte status ack. The polls work.

### Capture command stream
- Capture is driven by replaying HP's in-session command sequence
  (`captures/capture_seq.json`, gitignored device data; a list of plaintext
  command-hex strings extracted from an HP `scsSend` trace). Each command is
  re-encrypted with **our** session keys — no HP ciphertext is reused.
- 42-command sequence: `1f` setup; calibration block (`1a`/`06`/`02` sweep
  frames, ~idx 0–15, term `0x12`); then the poll/imaging loop (`0x02` polls,
  then `0x17`/`0x04` imaging latch, then `0x02` imaging bursts).
- Commands `0..23` all return status `0x0000` OK on a clean session.

---

## 3. The EP2 image transform (the final unlock)

The raw EP2 imaging stream is **AES-256-CBC encrypted** (entropy ~8, no SSL
framing). The frames that decode to a fingerprint (`01fe`-framed, 272-byte
stride) only appear *after* decryption. This is what made a raw live capture
show "too few lines" until session 5.

- **Cipher:** `scsSensorDecryptFingerprint@0x4fd640` → `palCryptoAesCbc`. IV
  chains across EP2 reads (last 16 ciphertext bytes → next IV); decrypt is
  in-place. Key length comes from the SSL suite (=32).
- **Key source:** NOT the SSL session key. HP generates a **fresh random 32-byte
  key and IV per capture** in `_scsSensorFpEncInit@0x4eb7f0` (`palCryptoRng`).
- **Key delivery:** `scsGetSecurityParams@0x4fd740` packs them **in the clear**
  (no RSA wrap) into a SecurityParams TLV embedded in the `0x02` GetFingerprint
  command, sent inside the already-SSL-encrypted channel:

  | field | offset in TLV value | size |
  |-------|--------------------|------|
  | AES-256 key | `0x00` | 32 |
  | IV (16 used) | `0x20` | 32 |
  | sign/HMAC key | `0x40` | 32 |
  | cipher selector (`0x04` = AES-256) | `0x68` | 1 |

  TLV header = tag `0x0006` (LE) + length `0x6a` (LE), i.e. `06 00 6a 00`.

- **Why replay works:** we replay HP's exact command bytes, so the sensor
  encrypts EP2 with HP's key — which is sitting in plaintext in those same bytes.
  We read it back and decrypt. In `capture_seq.json`, commands `3/17/22/23/26/27/41`
  carry the TLV; imaging commands `23` and `27` also carry a populated sign key.
- **Proven:** decrypting the imaging burst with the command's key yields clean
  `01fe` frames at 272 stride (frame-type `07 07`; the `06`/`07` byte is a mode
  marker the open unpack ignores) → a real fingerprint. Wrong key → noise.
- The image **signature** (sign key + `_scsSensorFpSignUpdate`) is an integrity
  HMAC over the image; not needed to obtain pixels, currently ignored.

---

## 4. Image decode (open, byte-exact)

`src/image.rs` is a clean-room reimplementation of HP's `UnpackLineRT`
(`0x46f510`) plus line assembly and reconstruction:

- **Modes:** mode 8 = `dst[perm[i]] = src[i]` (8-bit direct + descramble scatter);
  mode 4 = nibble expand; general = variable-bit per-column (bits at `cfg+8`,
  left-justify `<< (8-w)`, perm scatter at `cfg+0x57c`).
- **This device:** main image frames are **mode 8, width 264**, on-wire `01fe` +
  8-byte header + 264 payload = **stride 272**. Descramble table
  `captures/perm_264.bin` = `reverse(0..199) ++ reverse(200..263)`.
- **Config** (`captures/dli_config.json`) confirmed on-device with
  `scripts/dump_dli_config.gdb.py` (mode 8, width 264, max_bits 8; perm is a
  valid permutation of 0..263).
- **Verified byte-exact:** `scripts/dump_unpack_pairs.gdb.py` — the open
  `dst[perm[i]] = src[i]` unpack reproduces HP's `UnpackLineRT` output on 95/95
  real image lines, 0 mismatches.
- Reconstruction: fixed-pattern removal + ridge bandpass + finger-segment crop +
  motion-resample + local-contrast normalize → PGM.

---

## 5. Reverse-engineered HP functions (binary has debug symbols)

`vendor/runtime/bin/validity-sensor-unlocked` (built by
`scripts/build_harness.sh` with OpenSSL-0.9.8 stubs; not stripped).

| function | addr | role |
|----------|------|------|
| `scsSend` | `0x4f7bd0` | VCSFW wire framing `[cmd byte][payload]` |
| `scsSensorSendGetFingerprint_V4` | `0x5065f0` | builds the `0x02` poll/capture command |
| `scsSensorParseReply_V4` | `0x506340` | reply status decode (LE) |
| `idsSensorWOEFingerprintPoll` | `0x456320` | WOE finger-poll loop (poll-then-watch) |
| `scsSensorFalconCalibrate` | `0x4fcb20` | closed-loop calibration (data-dependent) |
| `scsSensorDecryptFingerprint` | `0x4fd640` | AES-256-CBC EP2 image decrypt |
| `_scsSensorFpEncInit` | `0x4eb7f0` | RNG-generate per-capture image key + IV |
| `scsGetSecurityParams` | `0x4fd740` | pack key/IV into the SecurityParams TLV |
| `irDliRTFalconData` | `0x462350` | frame demux/assembly (scans `01fe`) |
| `UnpackLineRT` | `0x46f510` | line unpack/descramble |

HP tracing harness verbs: `getver`, `get_ownership_info`, `getprintwait`,
`setowner` (writes!). Always `-doinit`.

---

## 6. Rust driver (crate `vfs495`, MIT, at repo root)

| module | responsibility |
|--------|----------------|
| `src/crypto.rs` | SSLv3 KDF, RSA (LE modulus, PKCS#1 v1.5), length-less MAC, AES-256-CBC record layer, `decrypt_image_stream` (EP2). Byte-exact vs `captures/skey_dump.json` (`vfs495 selftest`). |
| `src/usb.rs` | libusb transport (rusb): EP1 OUT/IN, EP2 image; `read_record` / `read_record_split`; kernel-driver detach/reattach. |
| `src/session.rs` | init replay + open SSLv3 handshake → active record layer. |
| `src/capture.rs` | in-session command replay, EP2 decrypt, `arm_capture` (full imaging capture → decrypted stream), `poll_probe` diagnostic. |
| `src/image.rs` | `UnpackLineRT` port, descramble, assembly, reconstruction → PGM; `ridge_peak`, `median_line_std`. |
| `src/virtimage.rs` | feed a decoded image to `$FP_VIRTUAL_IMAGE`. |
| `src/main.rs` | CLI: `selftest`, `handshake`, `capture`, `poll-probe`, `ridge-probe`, `decode`, `decode-lines`, `feed`, `run`, `daemon`. |

Toolchain: `libusb1-devel`; non-root USB via `packaging/70-vfs495.rules`.
6 unit tests pass; clippy-clean.

### Transport fix (session 4)
The `0x17`/`0x04` imaging latch made EP2 stream data; blocking on an EP1 reply
while EP2 was undrained starved the FIFO and reset the sensor (`-108`), which
looked like a USB re-enumeration. The fix interleaves EP2 draining with the EP1
reply wait (`read_record_split`, `drain_image_bounded`, `read_reply_interleaved`,
`send_cmd_draining`). Live result: all 42 commands OK, no reset, stable USB
address. (The old "the imaging latch re-enumerates the sensor" premise was false
— HP images a full swipe on one stable address; the old usblog "R(err)" were EP2
read cancels, not USB resets.)

### Falsified hypotheses (with evidence, so we don't revisit)
- `set_active_configuration` on reopen — the kernel sets config anyway.
- HP vendor control-plane resume on reopen — none; all standard kernel/hub
  enumeration.
- resend-`0x04` / SSL seq-continuity across a reset — the session was genuinely
  gone (zeros, not an alert). Moot once the re-enum was shown to be our bug.

---

## 7. Feeder daemon and GNOME integration

`vfs495 daemon` bridges the open capture path to libfprint's `virtual_image`
driver, so the sensor works through stock **fprintd / PAM / GDM / sudo** with no
custom C driver. The enroll → match → reject round-trip through libfprint is
proven in `scripts/vimage_proof.py`.

**Finger detection — ridge gate (the sensor streams high-variance imaging noise
even with no finger, so contrast, line count, and the segmentation crop all fail
to gate; only the ridge spectral peak works).** Each cycle the daemon fires a full
imaging capture (`arm_capture`), decodes it, and accepts it as a finger iff the
reconstructed image's **ridge spectral peak-to-mean** clears `--min-ridge`. That
is the sole gate. Measured live 2026-09-28 with the `ridge-probe` diagnostic:

| capture | ridge_peak | crop_ratio | verdict @1.4 |
|---------|-----------|-----------|--------------|
| no finger | **1.21** | 0.857 | reject ✓ |
| finger (held) | **2.10** | 0.995 | accept ✓ |

- `ridge_peak` separates cleanly (noise ~1.1–1.2, finger ~1.8–2.1); the default
  `--min-ridge 1.4` sits between them.
- `crop_ratio` is **not** a finger signal and was removed from the gate: a held
  finger covers nearly every line, so segmentation crops nothing (0.995 > the
  no-finger 0.857 — the wrong direction). It is logged for diagnostics only.
- Firing the imaging latch every cycle is safe (the "latch stresses the sensor"
  premise was falsified in §6, and HP images full swipes on one stable address).

Diagnostic: `vfs495 ridge-probe [--min-ridge N]` — captures, decodes, prints
`ridge_peak`/`crop_ratio`/line count and the daemon verdict without gating, and
writes a PGM. Run once with a finger and once without to compare / retune.

**Falsified and removed (2026-09-28): the WOE poll-divergence gate.** The former
`capture::capture_on_finger` polled `seq[17]` (0x02 GetFingerprint) and watched for
reply divergence from a no-finger baseline. Live test with a finger held firmly the
entire run showed that poll is **finger-blind**: reply byte-divergence stayed flat
at `nd = 2–4` and the pre-latch EP2 stayed a constant 5712 B at mean ≈127 / sd ≈74,
identical with and without contact. Replaying a captured poll returns a canned
reply plus free-running AFE noise; without the `0x17`/`0x04` imaging latch there is
no finger signal. The old "~10 byte baseline jitter" was measuring that noise. The
poll path, `--contact-nd`, and `--max-wait-polls` were deleted. If a low-power gate
is wanted later (to avoid imaging on empty cycles), investigate the **unused EP3
interrupt endpoint** or a dedicated WOE command — not a replayed swipe poll.
(`vfs495 poll-probe` remains as a diagnostic; its defaults were corrected to
`--prefix 17 --poll-idx 17` — index 16 is a `0x06` calibration command with a
constant reply and no EP2, the earlier off-by-one that read all zeros.)

Tunables: `--min-ridge` (1.4), `--gap`, `--once`. `VFS_NO_PROMPT=1` suppresses the
interactive capture prompt.

**To route the system fprintd through the bridge** (a system-config change the
user must opt into), add a systemd drop-in setting `FP_VIRTUAL_IMAGE` and run the
daemon — see the README "GNOME / fprintd integration" section.

---

## 8. Current status and remaining work

**Done and live-confirmed:**
- Open SSLv3 session and transport (no HP code in the session path).
- Full command replay with continuous EP2 draining, no sensor reset.
- AES-256-CBC EP2 image decryption (key recovered from the replayed command).
- Open decode + reconstruction → real fingerprint (264×623, ridge ~10.6 px).
- libfprint enroll/verify through `virtual_image` proven (`vimage_proof.py`).
- **Finger detection: ridge-peak gate, live-confirmed** (finger 2.10 vs no-finger
  1.21, threshold 1.4). Daemon rebuilt on it; the finger-blind WOE poll gate and
  the misleading crop-ratio condition were removed. See §7.

**Remaining:**
- End-to-end daemon run: `vfs495 daemon --once` (or with a socket) driving a real
  `fprintd-enroll`/`fprintd-verify` — the gate is validated in isolation via
  `ridge-probe`, but the full daemon → socket → fprintd loop with a live finger has
  not been exercised yet.
- Repeated-capture reliability: each capture opens a fresh session (the proven
  single-shot path); re-using a session across captures is not yet validated.
- Enroll may need several good frames; a held-finger capture is a tall full-height
  image (crop does not isolate a band). Feed quality across enroll stages unproven.
- fprintd systemd drop-in for `FP_VIRTUAL_IMAGE` — a user-opt-in system change.
- Verify the open unpack is byte-exact for frame-type `07` (payload decodes to
  ridges, so almost certainly yes).
- Optional: a low-power gate via the unused **EP3 interrupt endpoint** to avoid
  imaging on empty cycles (currently every cycle images then gates on the picture).
- Owned-sensor pairing is mapped but unimplemented (not needed here).
- Per-device RSA modulus auto-extraction is not wired (dump per unit).

---

## 9. Diagnostic env gates (in the driver)

`VFS_NO_PROMPT` (suppress capture prompt), `VFS_SWIPE_AT` (finger-cue index),
`VFS_SKIP_17`, `VFS_NO_REHANDSHAKE`, `VFS_REOPEN_SETCONFIG`, `VFS_HP_RESUME`.
Most are leftovers from the re-enumeration investigation and are inert on the
happy path; kept for regression probing.
