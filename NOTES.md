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

---

## 2026-09-25 — HP package analyzed: pairing IS "TakeOwnership" (major findings)

### Package (in vendor/, gitignored)
- `sp84530.tar` md5 9877c69c… (matches prior art). RPM payload extracted to vendor/rpm/.
- Target binary: `usr/sbin/validity-sensor` — **NOT stripped, has DWARF debug_info**, 4148 symbols.
  Image base 0x400000. `vcsFPService` is the stripped daemon (same codebase).

### Sensor state on THIS laptop (read-only, cmd 0x01 GetVersion — scripts/getver.py)
- Reply 38B: v4.60 build 104, target ROM, product 3 (Falconusb), **serial 00a0ee0e4080**
  (matches the user-provided serial), **security[2] = 01 7d**, no patch loaded (patchsig 0).
- IDENTICAL to prior author's sensor (they recorded v4.60.0104, security 01 7d). security 017d is the
  default ROM security config, NOT an ownership flag.
- `/etc/ValidityPersistentData` does **NOT exist** here; no Validity service installed; HP binaries only
  in vendor/. => no host-side owner credential present on this machine.

### The storage model (scsGetDataFromStorage @0x511c30 and scsSSLEstablishSession)
- Session establishment (`scsSSLEstablishSession` @0x515870) reads 5 storage slots by data-ID:
  - **id 10**: sensor RSA public key (256B modulus, exp 65537) -> ctx+0x11c  [used to encrypt premaster]
  - **id 11**: certificate (256B) -> `scsSensorValidateCertificate` validates the id-10 modulus
  - **id 1** : a 32-byte secret ("s_key") -> ctx+0x148 (memset+freed after handshake use)
  - **id 12**: a SECOND RSA public key (256B, exp 65537) -> ctx+0x124  [HOST owner public key]
  - **id 13**: an RSA **PRIVATE** key (1184B) -> `palCryptoRsaCreatePrivateKeyHandle` -> ctx+0x530
               [HOST owner private key; consumed by scsSSLRsaPrivateEncrypt @0x516290]
- Storage backend = **host file `/etc/ValidityPersistentData`** (palReadAll/WriteAllPersistentData,
  palGet/SetPersistentDataBinaryValue). Keyed by the 6-byte sensor serial under a registry-style path
  `SOFTWARE\Validity\vfs301`, value names **`HAPrivKey`** (Host App priv key = id 13), `s_key`,
  `SPrivMod`, plus an `AfterTakeOwner` marker.
- Each slot is wrapped by a "Secure Storage Protector": `scsEncrypt/DecryptWithGSKGlobal` (real, 32-byte
  key via palCryptoDecrypt+checksum), `…WithGSKMCFACT` (stub), or `…Void` (plaintext). The meaningful one
  is **GSKGlobal** — "Global" => a key that is not per-device (recoverable from the binary if ever needed;
  irrelevant to an open impl, which stores its own keys).

### Pairing = TakeOwnership (the step prior art never implemented)
- `scsSensorTakeOwnership`/`…WithKeys` are called ONLY from the explicit **setowner** command handlers
  (`vcsWITSetOwnership`, `vcsSensorSetOwner*`) and test paths (`vcsTestSimulateTakeOwnership`,
  `vcsTestGenFakeSharedSecret`). **NOT** from getprint/getprintwait/-doinit. => running the capture path
  never auto-pairs; prior art's SSL success means THEIR machine already had owner creds from a prior
  setowner. Their pyusb PoC got alert 0x2f because it used ONLY the sensor pubkey (standard CKE) and never
  presented/used the host owner key -> **0x2f (illegal_parameter) = "not the owner"**, a pairing gate,
  exactly as they suspected but never located.
- `scsSensorSendTakeOwnership_V4` @0x508760 sends VCSFW **cmd 0x0f** (66-byte payload) via scsSend, then
  0x13 (9B) and 0x17 (1B). Whole TakeOwnership path calls **only scsSend/scsSensorSendCommand — NO OTP,
  flash, erase, or Poke.** `ResetOwnership` exists (reversible). => pairing is a **reversible secure-storage
  write, not a one-time OTP burn.**
- BUT `GetOwnershipInfo` help = "Get Ownership total cycles and available cycles number" => ownership
  changes are a **finite, counted resource** (limited cycles). So each TakeOwnership consumes a cycle.
- Pairing crypto uses **Diffie-Hellman**: `scsDHEstablishSessionKey` @0x516700 is called from the
  TakeOwnership-reply store path (0x4ebb65/…/0x4ebe66) — i.e. host+sensor agree the 32-byte shared secret
  (`s_key`, id 1) via DH during pairing; the host also registers an RSA keypair (id 12 pub / id 13 priv).

### Verdict on the pairing secret (answers the step-3 question)
- It is **NOT a universal key baked into the binary**, and **NOT derived from the serial**. It is a
  **per-pairing host-side credential set** (RSA owner keypair `HAPrivKey`/id-12 + a DH-derived 32-byte
  shared secret `s_key`) created at first `setowner`, stored host-side in `/etc/ValidityPersistentData`
  (GSKGlobal-wrapped), and MATCHED by an **owner record the sensor stores internally** (written by cmd
  0x0f, cycle-limited, reversible via ResetOwnership).
- => An open, HP-free login path **is feasible**: pair ONCE with our own keypair using an open
  reimplementation of TakeOwnership (cmd 0x0f), store the keypair in our own format, and run an open
  session that authenticates as owner. No HP code in the login path, no proprietary secret required.
- COST/RISK of proceeding: pairing (a) consumes one of a limited number of ownership cycles, and (b) may
  overwrite/disrupt any EXISTING owner (e.g. a Windows fingerprint pairing) on this sensor. This is a
  persistent, cycle-limited sensor write => requires explicit user authorization before sending cmd 0x0f.

### Still to reverse (static, safe) before any pairing attempt
1. The exact **cmd 0x0f (TakeOwnership) payload/DH exchange** and its reply (so an open pairing is exact).
2. The exact **owner-key usage in the SSLv3 handshake** (how ctx+0x530 priv / ctx+0x124 pub / ctx+0x148
   s_key authenticate the client) — resolves the last gap in prior art's reversed session.
3. Whether reading ownership state (cmd 0x26) needs the security-mgmt patch/session first (got 0x0401 raw).

### Tools installed this session (for the user's record)
- `sudo dnf install strace rizin` (+deps: rizin-common, libtree-sitter0.25).
- Python venv at .venv with `pyusb` (1.3.1).

---

## 2026-09-25 — SOLVED: why prior art hit alert 0x2f (the ownership proof in the handshake)

Read `scsSSLClientKeyExchangeWrite` @0x513f30. The ClientKeyExchange is NOT a standard
RSA-wrapped premaster. The exact construction:
1. premaster = `03 00` + 46 random bytes (48B)   [scsSSLGetRandom(0x2e), palCryptoRng]
2. **premaster is AES-256-CBC-encrypted with `s_key`** (the 32-byte shared secret, id-1, ctx+0x148)
   via `scsSSLAesEncDec` @0x516340 (edx=0x30=48B; key=ctx+0x148; palCryptoAesCbc; 16B IV handling).
3. CKE plaintext = that 48B blob; PKCS#1 v1.5 padded to 256B; RSA-encrypted with the sensor pubkey
   (`scsSSLRsaPublicEncrypt`, premaster at EM offset 208 — matches prior art's byte layout).

Sensor side: RSA-decrypt -> AES-decrypt with ITS stored `s_key` -> premaster -> derive master.
A host lacking the correct `s_key` produces a garbage premaster -> master mismatch -> client Finished
never verifies -> **fatal alert 0x2f**. This matches EVERY prior-art observation exactly:
- "corrupting CKE ciphertext -> same 0x2f" (any wrong premaster' fails identically),
- "premaster version bytes all -> same 0x2f",
- their KDF/Finished "byte-exact" (they fed HP's already-AES-decrypted premaster; the KDF fn IS standard),
- wire "byte-structurally identical" (the AES layer is invisible inside the 256B RSA blob).

=> **THE missing piece in prior art's open SSL client is a single step: AES-256-CBC(premaster, s_key)
   before the RSA in ClientKeyExchange.** Everything else in tools/ssl_session.py is correct.

Also present but gated OFF in this RSA-KX flow (only used if the sensor sends a CertificateRequest):
- `scsSSLCertificateWrite` @0x5134a0 — client Certificate carrying id-12 host pubkey (ctx+0x124).
- `scsSSLCertificateVerifyWrite` @0x513890 — signs the handshake hash with id-13 host priv key
  (scsSSLRsaPrivateEncrypt, ctx+0x530). Consistent with prior art's 340B flight = CKE+CCS+Finished only.

### What this means end-to-end
- The one secret that unlocks the session is **`s_key`** (32B). It is DH-derived and shared between host
  and sensor at pairing (TakeOwnership), then persisted on both sides. Not in the binary, not from serial.
- An open session = prior-art SSLv3 client + the AES(s_key) CKE wrap. An open login path additionally
  needs an open pairing to establish a matching `s_key` on both sides.
- Pairing is UNAVOIDABLE for capture: an unowned sensor has no `s_key` (session can't work at all); an
  owner from a different host (e.g. Windows) holds a `s_key` we cannot read. So we must run our own
  TakeOwnership to get a matching pair. That is a persistent, cycle-limited sensor write => needs user OK.

---

## 2026-09-25 — Pairing protocol mapped; sensor-state probe; Windows now gone

### User update
- Windows no longer on this machine (Fedora-only now); Windows Hello fingerprint WAS used in the past.
  => the sensor is most likely still OWNED by that old Windows install (owner record persists in sensor
  secure storage), but re-pairing has NO functional downside now (no Windows to break). Only cost = one
  ownership cycle. User directive stands: pause before any write.

### Read-only state probe (scripts/probe_state.py — all reads HP sends, no writes/patches)
- GetVersion(0x01): OK, v4.60.0104, serial 00a0ee0e4080, security 017d.
- GetStartInfo(0x19): 68B status 0; carries a 40-byte high-entropy sensor blob (a boot/session nonce).
- GetOwnershipInfo(0x26): still status 0x0401 after 0x01+0x19 => reading current owner + remaining
  ownership-cycle count needs the security-management patch loaded to sensor RAM first (non-persistent,
  unloadable). Held off per "pause before write".

### Pairing routine fully mapped (vcsWITSetOwnership @0x447410)
Flow (open-reimplementable): 
1. `palCryptoRsaGenerateKeypair` -> `palCryptoRsaExportPublicKey` / `…ExportPrivateKeyBlobData`
   = host generates its OWN owner RSA-2048 keypair.
2. `scsSensorTakeOwnershipWithKeys` -> cmd **0x2c** (845B payload = 32 + 32 + 256 + 256 + 256):
   registers the host public key (+ secrets) with the sensor.
3. `scsSensorTakeOwnership` -> cmd **0x0f** (66B) + 0x13 + 0x17: DH exchange establishing the 32-byte
   shared secret `s_key` (scsDHEstablishSessionKey @0x516700 uses palCryptoRng + loads a patch;
   sensor side computes its half).
4. `scsStoreDataInStorage` + `palSetPersistentDataBinaryValue` + `scsSerializeRawPartition`:
   persist HAPrivKey(id13)+s_key(id1)+host pub(id12)+sensor pub(id10)+cert(id11) to
   /etc/ValidityPersistentData (GSKGlobal-wrapped).
5. `GetOwnershipInfo` to verify.
- Related opcodes: ResetOwnership = cmd **0x10** (98B) + 0x0b(34B) + 0x05(Reset). LoadSecurityManagement
  patch is required in RAM for the ownership commands.

### Where this leaves feasibility
- Open LOGIN path (session+capture): SOLVED on paper — prior-art SSLv3 client + AES-256-CBC(premaster,
  s_key) in CKE + plaintext ep2 image. Needs a known s_key (from pairing).
- Open PAIRING: fully mapped in shape; exact byte-level DH (cmd 0x0f) and the 0x2c payload encryption
  still need byte-exact pinning, best done by tracing HP's own setowner run (which is itself the write).
- Ownership cycles are LIMITED and their remaining count is currently unknown (needs the RAM patch to
  read). This matters: developing/testing an OPEN pairing could burn several cycles, whereas HP's binary
  pairs correctly in one. Pairing is one-time SETUP, not the login path, so using HP's binary for the
  single pairing write would still leave a 100%-HP-free login path.

---

## 2026-09-26 — BREAKTHROUGH: our sensor is UNOWNED → open session needs NO pairing

Built a live-trace harness (scripts/build_harness.sh -> vendor/runtime/, gitignored): HP binary +
5-byte HOST-side unlock patch + OpenSSL-0.9.8 stub libs + distro libusb-0.1 + our LD_PRELOAD USB logger
(scripts/usblog.c). Ran HP's `get_ownership_info -doinit` (authorized RAM-patch read).

### Ownership state (captures/getownership.usblog)
- `get_ownership_info -doinit` => **SUCCESS. Total cycles 65535, Available 65535.**
  available==total==0xffff => **the sensor is UNOWNED (factory); no ownership ever taken**, and cycles are
  effectively unlimited. (Old Windows Hello evidently never took ownership via this counter, or was reset.)
- The command ran INSIDE a full SSL session that **completed successfully** with NO
  /etc/ValidityPersistentData present: init `01 19 06(patch693) 01 1f 1f(cfg) 06(patch1301) 01` then
  `11` ClientHello -> ServerHello("FALCSSL",0044) -> `11 54 01` CKE+CCS+Finished flight -> server
  `14 03 00`CCS + `16 03 00 00 40`Finished. Session up; app-data (`17 03 00`) + ep2 image (0xff empty).

### Why prior art hit 0x2f and we do not (gdb dump: captures/skey_dump.json)
- Dumped the live handshake secrets. **`cke_input_after_aeswrap` == raw `premaster` byte-for-byte** =>
  on an UNOWNED sensor the AES-256-CBC(premaster, s_key) step is SKIPPED (s_key pointer is NULL because
  id-1 isn't in storage). So our CKE = **plain RSA(premaster) — standard SSLv3.**
- => The prior author's byte-exact open SSLv3 client would have WORKED on an unowned sensor. Their
  alert 0x2f happened only because THEIR sensor was OWNED (required the real s_key AES-wrap). This fully
  reconciles their "crypto byte-exact yet rejected" paradox.
- Master secret = standard SSLv3 KDF(premaster, cR, sR); confirmed live (captures/skey_dump.json).

### Our sensor's RSA public key (captures/modulus.json — per-device, from live handshake)
- 2048-bit, exp 65537, modulus (big-endian as HP lays it out at keyptr+8):
  `bd5c2253ed964b9b417b690c35d4a8de…04abea`. (Prior art's sensor started bd2f0c74; ours bd5c2253.)

### Revised verdict & plan (no sensor write needed!)
- **Open, HP-free CAPTURE on THIS sensor is achievable with NO pairing:** replay the static init
  (patch uploads — HP firmware blobs to RAM, the accepted community compromise; extractable/replayable)
  + an OPEN standard SSLv3-RSA handshake (our modulus) + capture cmd in-session + plaintext ep2 image.
- Pairing/TakeOwnership + the s_key AES-wrap remain fully documented for the general (owned-sensor) case,
  but are NOT required here. No ownership write will be attempted (sensor left unowned/factory).
- NEXT: build scripts/vfs495_open.py (pyusb): (1) replay init, (2) open SSLv3 session, (3) capture.
