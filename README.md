# vfs495

An open-source userspace driver for the **Validity VFS495** ("Falcon") swipe
fingerprint sensor — USB `138a:003f`, as shipped in the HP EliteBook 820 G3 and
several other 2015-era HP laptops.

The whole secure session, image capture and decode run in open Rust. There is
**no proprietary HP code in the session or login path**. Decoded images are fed
to libfprint's `virtual_image` driver, which makes the sensor usable through
stock **fprintd / PAM / GDM / `sudo`** with no custom C kernel or libfprint
driver.

> Status: research driver. The open secure session, transport, AES-256-CBC image
> decryption, decode and reconstruction all run in open Rust and are
> **live-confirmed on hardware**; a feeder daemon bridges it to libfprint for
> GNOME/fprintd. Remaining work is integration polish (see [Limitations](#limitations)).
> Contributions welcome. **A distilled project status & reverse-engineering
> reference is in [`docs/STATUS.md`](docs/STATUS.md)**; the full dated log is
> [`NOTES.md`](NOTES.md).

---

## Why this sensor was hard

The VFS495 wraps every command in a **proprietary variant of SSLv3-RSA**. Earlier
open efforts could build the session crypto but still had to run HP's closed
binary to establish each session, because owned sensors reject the handshake with
fatal alert `0x2f`.

The root cause, found here: on an **owned** sensor the `ClientKeyExchange` wraps
the premaster secret in `AES-256-CBC(s_key)` before RSA, where `s_key` is a
32-byte shared secret established at *pairing* ("TakeOwnership"). On an
**unowned** sensor that wrap is skipped, so a plain `RSA(premaster)` handshake
works with no pairing at all. This driver targets the unowned case and completes
the handshake entirely in open code — the wall every prior VFS495 project hit.

See [`NOTES.md`](NOTES.md) for the full reverse-engineering log and evidence.

---

## How it works

```
 USB (rusb)                                    libfprint
 138a:003f                                     virtual_image
    │                                              ▲
    ▼                                              │  <i32 w><i32 h><pixels>
 init replay ─► open SSLv3 handshake ─► capture ─► DLI decode ─► feed socket
 (src/usb)      (src/session, src/crypto) (src/capture) (src/image) (src/virtimage)
```

| Module            | Responsibility                                                        |
|-------------------|-----------------------------------------------------------------------|
| `src/crypto.rs`   | Validity SSLv3 KDF, RSA (LE modulus, PKCS#1 v1.5), length-less MAC, AES-256-CBC record layer |
| `src/usb.rs`      | libusb transport (EP1 OUT/IN, EP2 image)                              |
| `src/session.rs`  | init replay + open handshake → active record layer                    |
| `src/capture.rs`  | in-session capture command + EP2 stream read                          |
| `src/image.rs`    | `UnpackLineRT` port (mode 4/8/general), descramble, assembly, reconstruction → PGM |
| `src/virtimage.rs`| feed a decoded image to `$FP_VIRTUAL_IMAGE`                           |

The crypto is validated **byte-exact** against a live trace of HP's binary — run
`vfs495 selftest` (see below).

---

## Build

Requires a Rust toolchain and libusb 1.0.

```sh
# Fedora:        sudo dnf install libusb1-devel
# Debian/Ubuntu: sudo apt install libusb-1.0-0-dev
cargo build --release
```

## Runtime data you must supply

Two things are intentionally **not** distributed with this repo:

1. **Firmware patch blobs** (`vendor/patches/*.bin`). The sensor needs a set of
   firmware "patches" uploaded to its RAM during init. These are HP's
   intellectual property and are extracted from HP's own Linux driver package
   (`rpm2cpio`/`cpio`). This is the same accepted compromise every open Validity
   driver makes. The file names expected are listed in
   [`captures/init_seq.json`](captures/init_seq.json).

2. **Your sensor's RSA public key** (`captures/modulus.json`). A per-device
   value; the one committed here is for the author's unit. (Parsing it from the
   sensor's `Certificate` message at handshake time is a planned enhancement so
   the driver is device-portable out of the box.)

## Usage

```sh
# 1. Offline crypto self-test — no hardware needed (needs captures/skey_dump.json locally)
vfs495 selftest

# 2. Non-root USB access (recommended)
sudo cp packaging/70-vfs495.rules /etc/udev/rules.d/
sudo udevadm control --reload && sudo udevadm trigger

# 3. Prove the open secure session against the real sensor
vfs495 handshake

# 4. Capture a swipe and decode it to a PGM
vfs495 capture --out capture.bin
vfs495 decode --input capture.bin --out fingerprint.pgm    # unpack + descramble + reconstruct

# ...or reconstruct from already-descrambled scan lines (fully-open, verifiable offline):
vfs495 decode-lines --input captures/lines.raw --out fingerprint.pgm

# 5. End-to-end: hand a live swipe to libfprint's virtual_image
FP_VIRTUAL_IMAGE=/run/user/$(id -u)/vfs495.sock
#   (start fprintd/libfprint with the virtual_image driver pointed at that socket)
vfs495 run --socket "$FP_VIRTUAL_IMAGE"

# 6. Run continuously as a feeder daemon (for enroll/verify through fprintd):
#    captures on each finger touch, skips empty cycles, pushes images to the socket.
sudo -E FP_VIRTUAL_IMAGE="$FP_VIRTUAL_IMAGE" vfs495 daemon
#    --once     capture one frame and exit (testing)
#    --min-ridge 1.4   finger-detection threshold (ridge spectral peak/mean)
```

### GNOME / fprintd integration (feeder daemon)

GDM's fingerprint login is entirely fprintd/PAM-mediated — GDM never talks to the
driver. Once decoded images reach libfprint via `virtual_image`, `fprintd-enroll`
/ `fprintd-verify`, the GNOME Settings fingerprint UI, and PAM-based `sudo`/GDM
all work through the stock stack. The enroll → match → reject round-trip through
libfprint is proven in [`scripts/vimage_proof.py`](scripts/vimage_proof.py).

The **`vfs495 daemon`** command bridges the two: it captures on each finger
touch, decodes, and pushes the image to the `virtual_image` socket. To route the
system `fprintd` through it, point fprintd at the same socket with a systemd
drop-in (**a system-config change you must opt into**):

```sh
# /etc/systemd/system/fprintd.service.d/virtual-image.conf
[Service]
Environment=FP_VIRTUAL_IMAGE=/run/vfs495.sock
```

```sh
sudo systemctl daemon-reload && sudo systemctl restart fprintd
sudo -E FP_VIRTUAL_IMAGE=/run/vfs495.sock vfs495 daemon      # leave running
fprintd-enroll        # then press & hold when prompted (five stages)
fprintd-verify
```

Finger presence is detected in two stages. First, WOE-style: the daemon reaches
poll-ready, then polls the `0x02` command and watches the reply for a large
divergence from a no-finger baseline (the reply is near-constant with no finger —
~10 bytes of jitter — and a touch shifts many AFE registers at once). Only when a
finger is detected does it fire the imaging latch, so empty cycles never stress
the sensor. Second, the decoded image must clear a ridge spectral-peak gate before
it is fed. Tunables: `--contact-nd` (poll divergence threshold, default 30),
`--max-wait-polls`, and `--min-ridge`. The poll threshold's no-finger margin is
verified on hardware; confirm/tune the finger side with a live touch.

---

## Limitations

- **Image decode is ported and verified byte-exact against HP on live sensor
  data.** `src/image.rs` is a clean-room reimplementation of `UnpackLineRT` (all
  three modes) plus line assembly and reconstruction. On this hardware the main
  image frames are mode 8 (width 264): the open `dst[perm[i]] = src[i]` unpack
  reproduces HP's `UnpackLineRT` output **byte-exact on every real image line**
  (verified via `scripts/dump_unpack_pairs.gdb.py` — 95/95 lines, 0 mismatches),
  and the descrambled-lines path reconstructs a real fingerprint (`decode-lines`,
  ridge period ~14 px). The DLI config is confirmed on-device with
  `scripts/dump_dli_config.gdb.py` (→ `captures/dli_config.json`, auto-loaded).
  A firm, slow swipe is needed for a full-height image; light swipes yield mostly
  baseline lines (which the finger-segment crop drops).
- **Unowned sensors only.** Owned sensors need the pairing (`TakeOwnership`) flow
  — fully mapped in `NOTES.md` but not implemented, since it is a persistent,
  cycle-limited sensor write.
- **Finger detection is two-stage**: a WOE-style poll-divergence gate decides
  when to image (no-finger baseline verified stable at ~10; contact threshold 30),
  then a ridge spectral-peak gate validates the decoded image before feeding. Both
  thresholds are tunable; the finger-side poll magnitude should be confirmed live.
- **RSA modulus is per-device** and read from `captures/modulus.json`. The sensor
  delivers it in an opaque signed key blob during init (not a plain SSL
  certificate), so generic auto-extraction isn't wired up; on a different unit,
  dump your modulus with `scripts/dump_modulus.gdb.py`.

---

## Credits & prior art

This work stands on a large body of Validity reverse engineering:

- **[saifulmd0/vfs495-linux](https://github.com/saifulmd0/vfs495-linux)** —
  documented the VFS495 SSLv3 protocol (`docs/SSL_PROTOCOL.md`), the column
  descramble, and the image reconstruction approach. The crypto here is an
  independent re-implementation of that spec, validated against a live trace.
- **The [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint)
  project** — the `virtual_image` driver and the whole fprintd/PAM stack that
  make this usable for real logins.
- **The broader Validity/Synaptics RE community**, whose work on sibling sensors
  (VFS0050/0090/7552, `python-validity`, `vfs-tools`) mapped the device family's
  behaviour.

Reverse engineering here was done for interoperability, on hardware owned by the
author, to enable an open Linux driver.

## License

[MIT](LICENSE) © 2026 Hammad Majid.

No proprietary HP code is included in this repository.
