# vfs495

An open-source userspace driver for the **Validity VFS495** ("Falcon") swipe
fingerprint sensor — USB `138a:003f`, as shipped in the HP EliteBook 820 G3 and
several other 2015-era HP laptops.

The whole secure session, image capture and decode run in open Rust. There is
**no proprietary HP code in the session or login path**. Decoded images are fed
to libfprint's `virtual_image` driver, which makes the sensor usable through
stock **fprintd / PAM / GDM / `sudo`** with no custom C kernel or libfprint
driver.

> Status: research driver. The crypto and open SSLv3 handshake are proven; the
> capture path works end-to-end; final open image assembly is still being
> polished (see [Limitations](#limitations)). Contributions welcome.

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
```

### Native GDM / sudo login

GDM's fingerprint login is entirely fprintd/PAM-mediated — GDM never talks to the
driver. Once images reach libfprint via `virtual_image`, `fprintd-enroll` /
`fprintd-verify`, the GNOME Settings fingerprint UI, and PAM-based `sudo`/GDM all
work through the stock stack. The enroll → match → reject round-trip through
libfprint is proven in [`scripts/vimage_proof.py`](scripts/vimage_proof.py).

---

## Limitations

- **Image assembly is ported and verified on real data; the raw-EP2 unpack needs a
  one-time config dump.** `src/image.rs` is a clean-room reimplementation of
  `UnpackLineRT` (all three modes) plus line assembly and reconstruction. The
  descrambled-lines path (`decode-lines`) is proven offline: it reconstructs the
  real 264-wide capture into a fingerprint with clear ridge periodicity (~14 px).
  Unpacking *raw* EP2 frames additionally needs the per-column bit-width table
  (HP's `cfg+8`), which is capture-specific; dump it once with
  `scripts/dump_dli_config.gdb.py` (writes `captures/dli_config.json`, which the
  decoder then uses with no HP binary at capture time).
- **Unowned sensors only.** Owned sensors need the pairing (`TakeOwnership`) flow
  — fully mapped in `NOTES.md` but not implemented, since it is a persistent,
  cycle-limited sensor write.
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
