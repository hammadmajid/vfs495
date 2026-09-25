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

---

## 2026-09-25 — Prior art fully read (saifulmd0/vfs495-linux + rindeal)

### What saifulmd0/vfs495-linux already established (their evidence, summarized)
- **Transport/protocol (VCSFW):** cmd/reply framing `scsSend @0x4f7bd0` = `[cmd byte][payload]`,
  reply starts with u16 status. Command IDs known: 01 GetVersion, 02 GetFingerprint(capture),
  04 Abort, 05 Reset, 06 DownloadPatch, 07 Peek, 08 Poke, 0x11 TLS-tunnel, 0x13 SetCPUClock,
  0x15 GetConfig/GetFingerprint, 0x17 GetFingerState, 0x19 GetStartInfo, 0x1a UnloadPatch,
  0x1b Lock, 0x1c MatchVerify, 0x1d SignEnc, 0x1e DecVerify, 0x1f SPIBulkRead, 0x24/0x2a LED,
  **0x26 GetOwnershipInfo, 0x27 GetUID, 0x29 Cert**.
- **Pre-SSL init that WORKS via HP binary** (`getprintwait -doinit`, from harvest_cmds_full.py @0x4f7bd0):
  `01 19 06 01 1f 1f 06 01` (GetVer, GetStartInfo, DownloadPatch~693B, GetVer, SPIBulkRead x2,
  DownloadPatch~1301B security-mgmt, GetVer) → then cmd 0x11 SSLv3 handshake. **No explicit
  ownership/pairing command appears in this pre-SSL sequence.**
- **Secure session = proprietary SSLv3**, cipher suites custom 0x0042/43/44 (AES-128/192/256-CBC-SHA1),
  chosen 0x0044. ALSO defines 0x0030/31/32 = "pre-shared-AES key-exchange variant (NOT used here)".
  Key exchange = RSA: 48B premaster (`03 00` + 46 random) RSA-encrypted with the SENSOR's RSA-2048
  pubkey (exp 65537, modulus from `scsGetDataFromStorage(id=10) @0x511c30`, stored little-endian).
  No host/client certificate sent on the wire. `id=11` storage = a cert the HOST uses locally to
  validate the id-10 modulus (`scsSensorValidateCertificate`); NOT sent on wire.
- **Every SSL crypto primitive validated byte-exact** vs gdb dumps of HP's live session: master-secret
  KDF, key-block KDF, SSLv3 Finished (LE label), AES-256-CBC record + length-less SSLv3 MAC, RSA
  (LE modulus, PKCS#1 v1.5, big-endian wire). Their standalone PoC (`tools/ssl_session.py`) reproduces
  all of these.
- **THE BLOCKER:** their from-scratch PoC handshake is rejected by the sensor with fatal alert
  `15 03 00 00 02 02 2f` (level 2, desc 0x2f=47 illegal_parameter), right after the CKE+CCS+Finished
  flight. Their ClientHello is ACCEPTED (ServerHello parses, contains "FALCSSL"). usbmon wire-diff of
  their PoC vs HP's session = byte-identical framing; only randoms/ciphertext differ. They ruled out:
  premaster version bytes, CKE corruption (same 0x2f → rejection is content-independent), MAC±length,
  ServerHelloDone in/out of hash, random-role swap, dev.reset()/boot-state, priming with HP first.
  They concluded 0x2f is sensor-firmware-generated (not in host decompile) and is a **sensor-side
  provisioning/pairing gate they could not cross from the host**, and PIVOTED to wrapping HP's binary.
- They note their PoC used a **baked RSA modulus constant** and their own TODO is "issue the
  storage-read (scsGetDataFromStorage id 10) instead of the constant" — i.e. the PoC may skip a
  wire command HP issues. (Lead to check.)

### HP function addresses already located by prior author (image base 0x400000, validity-sensor)
- `scsSend` 0x4f7bd0 (wire framing) · `scsGetDataFromStorage` 0x511c30
- SSL: `scsSSLMasterSecretGenerate` 0x5139c0 · `scsSSLRsaPublicEncrypt` 0x5161c0 ·
  hs-hash-update 0x5132b0 · `scsSSLFinishedWrite` 0x513920 · `scsSSLRecordPack` 0x514580 ·
  RSA-key-build 0x51fac0 · `palRsaPublicKeyOperation` 0x52b770
- ctx offsets: client_random ptr @ctx+0x38, server_random ptr @ctx+0x40, master @ctx+8,
  keyblock @ctx+0x48, record seq @ctx+0x100, cipher-active flag @ctx+0x13c (bit1).
- Image path: `UnpackLineRT` 0x46f510, `irDliRTFalconData` 0x462350, main() gate jmp @0x44122d,
  Execute() dispatcher @0x4403b0, FunctionList @0x8705e0.
- **NOT yet analyzed by anyone:** the ownership/pairing surface — `scsGetOwnershipInfo`,
  setowner/resetowner handlers, cmd 0x26/0x27/0x29, `scsSensorValidateCertificate`, and the full
  body of `scsSSLEstablishSession` (where id-10/id-11 are read and the RSA key struct is built).

### rindeal driver
- Pure wrapper: a `capture-helper` process dlopen's HP's `libvfsFprintWrapper.so` and pipes images to
  a libfprint driver. No raw command flow / no crypto — not useful for pairing. Confirms the whole
  community delegates the secure session to HP's closed stack.

### The paradox to resolve (my actual task)
HP's binary and the PoC send **byte-identical wire** with **byte-exact crypto**, yet HP is accepted and
the PoC gets 0x2f. Since nothing host-observable differs, the accept/reject must hinge on something
NOT on the wire. Working hypotheses, in priority order:
1. **A host-held secret/credential mixed into the handshake** that HP has and the PoC doesn't — but
   note their KDF validation fed HP's own dumped premaster, so it would NOT detect a secret that enters
   *before* the dumped premaster. Need to trace where the premaster is generated (backward from
   0x5139c0 / 0x5161c0) and whether any byte comes from storage/host state rather than RNG.
2. **A missing wire command** HP issues that the PoC skips (e.g. the id-10/id-11 storage read as a
   state gate) — check scsSSLEstablishSession's command emissions vs the PoC's init.
3. **An ownership/pairing gate** (cmd 0x26/0x27/0x29 or setowner) that sets sensor state HP relies on.
   Check whether getprintwait's success depends on ownership state already present on THIS laptop.
4. **Session/handshake-hash nuance** not visible on the wire (what exactly is fed to the hs hash).

### Plan
A. Download HP sp84530 into vendor/, extract (rpm2cpio/cpio), inventory binaries.
B. Static-analyze `scsSSLEstablishSession` end-to-end in `validity-sensor` (not stripped, 2686 funcs):
   premaster generation source, storage reads, ownership checks. Focus on hypotheses 1–3.
C. Analyze the ownership/pairing functions (0x26/0x27/0x29, setowner, scsSensorValidateCertificate).
D. Decide: is the pairing secret recoverable/derivable (→ open impl possible) or sensor-locked?
E. Only if a secret/step is found: build a standalone pyusb pairing+session, validate byte-for-byte
   vs a fresh gdb/usbmon trace of HP's binary.
