# VFS495 pairing RE — running log

Device: Validity VFS495, USB **138a:003f**, HP EliteBook 820 G3.
Host: Fedora 44, libfprint 1.94.100, fprintd 1.94.5 (sensor "known unsupported").
Goal: open pairing + capture path, no HP code in the login path.

USB descriptors (given): vendor-specific interface; EP1 OUT bulk 64,
EP1 IN bulk 64, EP2 IN bulk 64, EP3 IN interrupt 8. bcdDevice 1.04.
Sensor serial (given): 00a0ee0e4080.

Rules honored: HP package only under vendor/ (gitignored); extract, never
install; run their binary only from repo dir under gdb/strace when tracing;
never send a command not seen from HP's code; no fuzzing; no flash/firmware/OTP
writes without explicit OK; stop and ask for a finger swipe when needed
(swipe ~2s after prompt); do not touch PAM/authselect/fprintd config.

---

## 2026-09-25 — Session start

### Environment verified
- Sensor present: `lsusb` -> `Bus 001 Device 029: ID 138a:003f Validity
  Sensors, Inc. VFS495 Fingerprint Reader`. Evidence: `lsusb -d 138a:003f`.
- Tools present: objdump, gdb, python3, rpm2cpio, cpio, ar, wireshark, tshark,
  lsusb, usbhid-dump.
- Tools MISSING (to install): strace, rizin. (r2/ghidra not required if rizin
  works; Ghidra available only via flatpak per rules.)
- usbmon: kernel module not loaded; debugfs `/sys/kernel/debug/usb/usbmon/`
  not readable without root. Will load `usbmon` + capture via
  wireshark/tshark on the `usbmon1` interface (bus 1) when tracing HP's binary.

### Repo skeleton
- Created vendor/ (gitignored), scripts/, captures/, notes/.
- .gitignore excludes vendor/, venvs, large raw captures.

### Next
1. Verify commit signing (1Password op-ssh-sign) with initial commit.
2. Install strace + rizin (record for user).
3. Read prior art: saifulmd0/vfs495-linux and rindeal driver; summarize
   protocol/SSLv3/where pairing blocks.
4. Fetch HP package into vendor/, extract, locate pairing/session code.
