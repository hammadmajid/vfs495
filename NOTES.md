# VFS495 pairing RE — running log

> This is the chronological, dated log with full reasoning and evidence. For the
> distilled, organized current-state and reverse-engineering reference, see
> [`docs/STATUS.md`](docs/STATUS.md).

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
1. Install strace + rizin (record for user).
2. Read prior art: saifulmd0/vfs495-linux and rindeal driver; summarize
   protocol/SSLv3/where pairing blocks.
3. Fetch HP package into vendor/, extract, locate pairing/session code.

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

---

## 2026-09-26 — *** OPEN SECURE SESSION ESTABLISHED (no HP code in session path) ***

Built scripts/vfs495_open.py: pure-Python (pyusb + cryptography) VFS495 SSLv3 client.
- Crypto (ssl3_prf KDF, RSA PKCS#1 LE-modulus, SSLv3 Finished LE-label, AES-256-CBC length-less-MAC
  record layer) re-implemented from the RE'd spec and **validated byte-exact offline** against the live
  gdb dump: `--selftest` => master match TRUE, keyblock match TRUE (captures/skey_dump.json).
- Init = replay of the exact observed command sequence (captures/init_seq.json); the two DownloadPatch
  blobs are HP firmware loaded to sensor RAM (vendor/patches/, gitignored — not committed).
- ClientKeyExchange = plain RSA(premaster) (correct for our UNOWNED sensor; no s_key wrap).

LIVE RESULT (`sudo .venv/bin/python scripts/vfs495_open.py --handshake`):
```
[i] init replayed
[i] ServerHello 58B: 16030000350200002d0300000003a910...
[i] server flight 144B: 14030000010116030000406a9d632160...
[+] HANDSHAKE OK — sensor sent CCS/Finished. Secure session established.
```
=> The sensor ACCEPTS our open handshake (server CCS+Finished, 144B, same shape as HP's). The prior
project's alert-0x2f wall is CROSSED — with zero HP code in the session. Root cause of their block
confirmed: their sensor was owned (needed s_key); ours is unowned (standard SSLv3).

### Remaining to a full open capture
- Send the in-session capture command (getprint/GetFingerprint) as AppData and read the plaintext image
  from ep2, then decode/descramble/assemble (prior art's UnpackLineRT/reconstruct is the spec).
- Needs a finger swipe (~2s after prompt). Will trace HP's getprintwait once to pin the exact in-session
  command + ep2 framing, then reproduce it open. (Requires user at the sensor.)

---

## 2026-09-26 — Capture command identified + real swipe image captured (traced)

Traced HP `getprintwait -doinit` under gdb (scsSend plaintext dump) + usblog (ep2), one user swipe.
- **Capture command = cmd 0x02** (scsSensorSendGetFingerprint_V4), sent as SSL AppData, with a large
  (~2.3–3.0 KB) config blob. Image returns PLAINTEXT on ep2.
- Post-handshake capture sequence (plaintext, from captures/plaintext_cmds.txt):
  `1f 1a 06(getprint-patch 405B) 02(config ~2331B)` then repeated `02` frame reads; calibration uses
  `06(2581B)`; `12`, `17`, `04(Abort)` also appear. getprintwait re-arms via `1a`(unload)+`06`(reload).
- Real swipe captured: **4.10 MB ep2, 297 reads (263 varied), 546 `01 fe` frame markers** (captures/
  capture_swipe.usblog, gitignored). Confirms the finger scan came through.

### Status vs. goals
- Open PAIRING analysis: COMPLETE (TakeOwnership = cmd 0x0f DH s_key + cmd 0x2c host RSA keypair;
  reversible, 65535 cycles). Not needed for THIS sensor (unowned).
- Open SECURE SESSION: **DONE and proven live** (scripts/vfs495_open.py --handshake). This is the wall
  every prior VFS495 project hit; crossed with zero HP code in the session.
- Open CAPTURE: capture command + framing known; image data captured. Remaining: reproduce the
  post-handshake capture sequence as AppData in the open client + decode (prior art's descramble/assembly
  is the decode spec).

---

## 2026-09-26 — Open image decode built; traced swipe was too light (needs a cleaner capture)

- Built scripts/decode_image.py: OPEN raw-ep2 DLI decoder. Confirmed frame format on our data:
  fixed **208-byte frames** = `01 fe <seq:u16> <f4> <f5> <width> 00` + **200 pixel bytes** (8-bit direct);
  the header width byte is NOT the length (prior art's drift trap — solved by fixed 208 stride).
  Main-image descramble = reverse each 200-byte line (perm[0:200]=199..0, from vfs495-linux table).
  Parsed 6 frame-runs (up to 255 lines) cleanly -> proves the open framing/descramble works.
- BUT the captured swipe has **no ridge signal**: per-line std ~6.7 (a real print is much higher), no
  ~10–12px horizontal ridge frequency. => the finger swipe in that trace was too light/mistimed
  (getprintwait retried 17x, consistent with a poor finger). captures/open_fingerprint.png = mostly noise.
- Not a decode bug: the pipeline extracts and orders frames correctly; there simply were no ridges to show.
  A firmer, well-timed swipe (~3s after capture arms, slow ~1.5s full-fingertip drag) should yield ridges.

### Honest status of the CAPTURE path
- Transport: open session works; capture cmd 0x02 identified; ep2 image framing decoded openly.
- Missing: a cleanly-captured swipe to validate the open decode end-to-end (image quality is a swipe-
  timing issue, not a protocol gap). Prior art's fallback for descrambled lines is a gdb RAM dump of
  UnpackLineRT — proven but uses HP's decode; our decode_image.py is a fully-open alternative pending a
  good swipe.

---

## 2026-09-26 — *** REAL FINGERPRINT captured; end-to-end capture path proven ***

- Frame types clarified: raw ep2 interleaves MAIN image lines (width 264) and NAVIGATION lines
  (width 200); separating them from the raw stream = irDliRTFalconData's assembly (prior art's known-
  hard unsolved open problem). Dumped the true perm table (captures/perm_264.bin, width 264, valid
  permutation) — first 200 are 199..0, but the raw stream also needs the correct frame demux.
- To prove the capture works end-to-end, harvested HP's UnpackLineRT OUTPUT (already descrambled 264-wide
  lines) via gdb (scripts/harvest_lines.gdb.py) during a firm swipe: **6572 lines, per-line std ~71**
  (strong finger contact). Reconstructed (fixed-pattern removal + ridge bandpass + finger-segment +
  novelty motion-resample + local-contrast normalize): **captures/fingerprint_open.png = a clean,
  recognizable fingerprint (loop core, coherent ridge flow).** (Biometric images gitignored.)

### END-TO-END STATUS
- Open PAIRING/OWNERSHIP: fully reverse-engineered + verdict (cmd 0x0f DH s_key + cmd 0x2c host RSA
  keypair; reversible; 65535 cycles). NOT needed for our sensor (unowned).
- Open SECURE SESSION: **DONE, proven live** with zero HP code (scripts/vfs495_open.py --handshake).
  This is the wall every prior VFS495 project hit (alert 0x2f) — now crossed.
- CAPTURE: command 0x02 identified; a real fingerprint captured end-to-end. The image descramble/assembly
  (irDliRTFalconData/UnpackLineRT) is currently done by HP's code (RAM-harvested); porting THAT to open
  code (using the dumped perm + frame demux) is the one remaining step to a 100%-open capture. The SSLv3
  session — the actual security gate and prior blocker — is already fully open.

---

## 2026-09-26 — virtual_image integration PROVEN (isolated, no login config touched)

Question: will the libfprint `virtual_image` bridge actually carry enroll/verify (so GDM/sudo work)?
Verified the driver-specific link directly, without touching fprintd/PAM/GDM config.

Machine facts (read-only): libfprint 1.94.100 ships `virtual_image` (FpDeviceVirtualImage in
/usr/lib64/libfprint-2.so.2); fprintd 1.94.5 + pam_fprintd installed; **GDM already has
/etc/pam.d/gdm-fingerprint** (fingerprint login is 100% fprintd/PAM-mediated; GDM never touches the driver).

scripts/vimage_proof.py drives libfprint via GObject-introspection against `virtual_image`
(FP_VIRTUAL_IMAGE socket; protocol `<i32 w><i32 h><w*h gray>`, libfprint listens). Result:
- device driver=virtual_image, 5 enroll stages;
- ENROLL 5/5 -> template from our real captured print;
- VERIFY(same) -> **match=True**; VERIFY(different) -> non-match. **RESULT: PASS.**
Caveat: the non-match image was synthetic (no minutiae -> rejected), so it proves "won't falsely accept";
real impostor discrimination (genuine 79 vs impostor 5, threshold 40) was already shown by prior art via
fprintd. Cannot test through the *system* fprintd without a fprintd systemd drop-in (= config change,
disallowed) — but that layer (fprintd/pam_fprintd/gdm-fingerprint) is stock/unmodified.

Conclusion: the virtual_image path is real and works; a Rust helper feeding it is a sound architecture
for native GDM+sudo. Language choice is decoupled from this integration choice.

---

## 2026-09-26 — Rust driver: crypto + session + capture + decode + virtual_image feeder

Built the open driver in idiomatic Rust (crate `vfs495`, MIT, GitHub-ready). Ported the proven Python
reference (`scripts/vfs495_open.py`, `scripts/decode_image.py`, `scripts/vimage_proof.py`) to a typed,
modular crate:

- `src/crypto.rs` — SSLv3 KDF, RSA (LE modulus / PKCS#1 v1.5, big-endian wire), length-less SSLv3 MAC,
  AES-256-CBC record layer. **`vfs495 selftest` -> PASS** (master + key block byte-exact vs
  captures/skey_dump.json — same vectors as the Python selftest). Committed unit test for the
  Finished label. No hardware needed.
- `src/usb.rs` — rusb transport (EP1 OUT/IN, EP2 image; kernel-driver detach/reattach on Drop).
- `src/session.rs` — init replay (reads captures/init_seq.json + vendor/patches blobs) + open handshake
  (ClientHello suites 0044/0043/0042, plain RSA CKE, CCS+Finished). Faithful port of the live-proven flow.
- `src/capture.rs` — in-session capture command (optional captures/capture_cmd.json) + EP2 stream read.
- `src/image.rs` — DLI fixed-frame demux (8-byte header + payload, stride 208), column reverse-descramble,
  local-contrast normalization, PGM out. Validated offline: decoded the existing capture_swipe EP2 stream
  -> 255x200 image, mean 128 / stdev 56 / full range (real variance, pipeline runs end-to-end).
- `src/virtimage.rs` — feed `<i32 w><i32 h><pixels>` to $FP_VIRTUAL_IMAGE (the proven libfprint bridge).
- `src/main.rs` — CLI: selftest / handshake / capture / decode / feed / run.

Packaging: `packaging/70-vfs495.rules` (uaccess udev rule, user installs it — NOT installed by us),
`README.md` rewritten for the driver (credits saifulmd0/vfs495-linux, libfprint, the Validity RE
community), `LICENSE` (MIT). `.gitignore` adds /target + Cargo.lock. No HP code committed;
vendor/patches + modulus stay runtime-supplied per README.

Toolchain installed this session: libusb1-devel (for rusb linkage). Rust crates pulled: rusb, aes, cbc,
sha1, md-5, num-bigint, num-traits, rand, serde/serde_json, anyhow, clap, hex, log, env_logger.

Remaining open work (documented in README Limitations): width-264 main-frame assembly
(irDliRTFalconData/UnpackLineRT) in open code; parse RSA modulus from the sensor certificate for
device portability; pairing/TakeOwnership for owned sensors (persistent write, needs explicit OK).

---

## 2026-09-26 — Open image assembly: UnpackLineRT ported + verified on real data

Closed the "image assembly done via gdb RAM harvest" gap. Disassembled HP's UnpackLineRT (0x46f510)
and reimplemented it clean-room in `src/image.rs`. Three modes:
- mode 8  (cfg[0]==8): dst[perm[i]] = src[i]  (8-bit direct + descramble scatter).
- mode 4  (cfg[0]==4): each byte -> two pixels: (b&0x0f)<<4 at perm[i], (b&0xf0) at perm[i+1].
- general (else): per-column bit widths at cfg+8 (clamped to max_bits = src[6]&0xf), samples read
  little-endian from the packed stream, left-justified `<< (8-w)`, scattered via perm at cfg+0x57c.
Descramble table = captures/perm_264.bin (u16 perm of 0..263 = reverse(0..199) ++ reverse(200..263)).
Unit tests cover mode8/mode4/general + general==mode8 when 8-bit. All pass (5 tests).

Assembly + reconstruction (`load_lines_raw`, `finger_segment`, `normalize`, `reconstruct`) verified
OFFLINE on the real harvested lines.raw (6572x264): `vfs495 decode-lines` -> 264x6572 PGM, std ~54,
and an FFT ridge check shows a clear ridge band (period ~14 px, peak/mean 3.2x). So the open
descrambled-lines -> fingerprint path is proven on real data with zero HP code at decode time.

Raw-EP2 unpack: `decode_ep2` + `DliConfig` implement it, but need the per-column bit table for our
capture (frames are ~200 packed bytes -> 264 samples => variable <8-bit). Added
`scripts/dump_dli_config.gdb.py` to dump {mode,width,max_bits,bits,perm} in one gdb run on the next
swipe -> captures/dli_config.json (gitignored; decoder auto-loads it). That removes the last HP
dependency at capture time; only verification of the live raw path is pending a swipe.

Modulus-from-certificate: investigated. The sensor ships its RSA pubkey inside an opaque signed key
blob on ep2 during init (found at a device-specific offset; no clean TLV/length anchor, exponent not
adjacent). No verifiable generic parser without full cert-format RE, so kept modulus-from-file
(reliable) + documented dump path for other devices. Not shipping an unverifiable wire parser.

New CLI: `decode-lines` (open lines->PGM), `decode` now does full unpack+descramble+reconstruct.

---

## 2026-09-26 — LIVE verification on the sensor: handshake OK + open unpack byte-exact

Ran the Rust driver and gdb dumps against the real VFS495 (138a:003f).

1) `vfs495 handshake` (release, sudo): init replayed (8 steps) -> ServerHello 58B ->
   server flight 144B = `14 03 00 0001 01` (CCS) + `16 03 00 0040 ...` (encrypted Finished)
   -> **HANDSHAKE OK**. The open SSLv3 session is now proven LIVE in Rust (crypto.rs + usb.rs +
   session.rs), not just Python. No writes (standard ClientHello/CKE/Finished only).

2) `scripts/dump_dli_config.gdb.py` (one swipe): **mode=8, width=264, max_bits=8**; dumped perm
   matches perm_264.bin exactly and is a valid permutation of 0..263. So main frames are plain
   8-bit + descramble (no variable-bit packing) on this device. On the wire: 01fe frames,
   8-byte header + 264 payload = stride 272 (set as the `decode` default).

3) `scripts/dump_unpack_pairs.gdb.py` (one swipe): dumped 18704 real UnpackLineRT input->output
   pairs. Our open unpack `dst[perm[i]] = src[i]` reproduces HP's output **BYTE-EXACT on all 95
   real image lines (0 mismatches)**. The swipe was light so only 95 lines had finger contact;
   the rest were baseline (dominant value 128/112) — real imaging comes in period-20 bursts
   (19 image lines + 1 sync). A firm/slow swipe yields thousands (cf. lines.raw = 6572).

Net: the fully-open capture->image path is verified end-to-end on real hardware — open unpack
matches HP byte-exact, and descrambled lines reconstruct to a fingerprint. No HP code in the
session or decode path. Only a firmer swipe (pressure/speed) is needed for a full-height image.

New/updated: src/main.rs (decode/run stride 272), scripts/dump_dli_config.gdb.py,
scripts/dump_unpack_pairs.gdb.py. Dumps (dli_config.json, unpack_pairs.bin) gitignored.

---

## 2026-09-26 — FULLY-OPEN decode of a real swipe, from raw frames, through the Rust driver

Slow firm swipe under gdb (dump_unpack_pairs -> raw input frames). Rebuilt the on-wire ep2 stream
from the dumped inputs (272-stride 01fe frames) and ran `vfs495 decode --stride 272`: open mode-8
unpack + perm_264 descramble + reconstruct -> **264x270 fingerprint, ridges present (FFT peak/mean
2.29, period ~12px)**. So the complete capture->image path runs in open Rust with no HP code in the
decode; HP only drove the sensor. Image lines are ~95% mode 8 (perm-scatter, byte-exact); the rest
of the stream is baseline (no-finger) lines, dropped by the finger-segment crop.

Fix: reconstruct() crop guard was rows/8 (too big for a short finger band in a long baseline stream);
now keeps any detected band >=20 lines. captures/*.bin and *.png (biometric) gitignored.

Swipe technique that works: one finger, slow (~1.5-2s), firm continuous top->bottom, don't lift
mid-swipe. ~270-300 finger lines per good swipe. Fully-open CAPTURE (Rust arming cmd 0x02 itself,
no HP at all) is the next milestone: ~40 in-session commands (02 + per-capture 06 patch uploads +
1a/12/04/17) traced in order in captures/plaintext_cmds.txt (gitignored) — a deliberate replay to build.

---

## 2026-09-26 — Fully-open capture: handshake+resets work, imaging NOT yet triggered (WIP)

Built the fully-open capture (Rust arms the sensor, no HP): handshake -> replay the 42 in-session
commands (captures/capture_seq.json, extracted from HP trace) as AppData records (17 03 00...), read EP2.

Wire format nailed: post-handshake, every command is a plain SSLv3 AppData record `17 03 00 <len> <ct>`
sent DIRECTLY on EP1 (no 0x11 tunnel; tunnel is handshake-only). EP2 image is plaintext. Confirmed by
matching plaintext lengths to encrypted wire lengths in init_full.usblog.

Capture is a MULTI-PHASE STATE MACHINE with soft resets: cmd 0x04 (trace idx 35 & 39) soft-resets the
sensor -> it re-enumerates on USB (dmesg: disconnect + new full-speed device, same 138a:003f). Added
Sensor::reopen() (re-acquire handle over ~3s) and reset-aware arm_capture that keeps the Record across
the reset. Runs now complete all 42 commands and survive both resets.

BUT no image: EP2 yields only 16384 bytes of 0xFF (empty/uninitialized) — imaging never triggers.
Likely cause: the SSL session does NOT survive the 0x04 reset the way assumed (needs a re-handshake
after each reset), so post-reset AppData commands are rejected and the sensor never arms; and/or the
finger-wait/imaging trigger + swipe timing isn't reproduced. An early cmd-2 disconnect also seen
(device still settling from prior run's reset).

DECISIVE NEXT EXPERIMENT (one instrumented swipe): capture HP getprintwait's RAW EP1 writes with
usblog.so preloaded, across the 0x04 resets, to see if HP re-handshakes (sends 0x11 tunnels) after each
reset and what triggers imaging. init_full.usblog only covers a simpler single-session flow (no 04/no
re-handshake), so it can't answer this. Then match HP's post-reset behavior.

State: fully-open SESSION + DECODE are proven; fully-open CAPTURE needs this deeper reset/imaging RE
(iterative, several swipes). Device confirmed healthy after all attempts.

---

## 2026-09-26 — Fully-open capture is BLOCKED: capture is an interactive protocol, not a replay

Self-trace wire-diff (added VFS_WIRE logging in src/usb.rs; compared my EP1/EP2 traffic to HP's
getprint_trace.usblog). Findings:

- Post-handshake wire format is correct: my setup commands are ACCEPTED (device streams real baseline
  image on EP2 — hundreds of non-0xFF 16384-byte reads). Handshake + config replay work.
- The stall is at the poll loop. HP's poll commands (02/2691 enc 2725, 02/3033 enc 3061) return a
  **2437-byte** response on EP1 IN. My byte-identical commands return only **37 bytes** (short reject).
- HP's live command sequence also DIFFERS from my recorded one (e.g. HP sends two 02/2666 where the
  recorded trace has one). => the sequence is DYNAMIC.

Conclusion: capture is an **interactive, adaptive protocol** — HP reads the large (2437-byte) poll
responses (calibration/frame state) and BUILDS subsequent commands from them. A static replay sends
stale, session-mismatched parameters, so the sensor short-rejects each poll command and then NAKs all
further EP_OUT writes (the "Operation timed out" at the first 0x04). Finger presence is irrelevant —
rejection happens before imaging. Root cause is NOT a USB/flow bug; it's protocol semantics.

What fully-open capture now requires (substantial, separate effort): reverse the capture state machine
in HP's binary — decode the 2437-byte poll responses, and reimplement how the poll commands
(02/2691, 02/3033, their embedded parameters) are constructed from session/calibration state. This is
real decompilation of HP's imaging logic, not a replay.

Infra added this session (committed): src/usb.rs VFS_WIRE wire logger + Sensor::reopen(); capture.rs
replays in-session AppData with retries + heavy EP2 drain (proven correct for setup; insufficient for
the adaptive poll loop). Device confirmed healthy after all attempts (re-enumerates cleanly).

STATE: open SESSION + open DECODE remain proven end-to-end. Fully-open CAPTURE is blocked on the
interactive-protocol RE above. For a usable driver sooner, the alternative is to drive HP's capture
(getprintwait) and decode its output with our open code — but that keeps a proprietary component in the
capture path, which is out of scope for a fully-open login path.

---

## 2026-09-26 — Capture state-machine RE: interactive protocol DECODED (fully-open path now concrete)

Reversed HP's capture state machine (binary vendor/runtime/bin/validity-sensor-unlocked, not
stripped) to turn the "interactive protocol, blocked" conclusion into a concrete open reimplementation
plan. Four focused disassembly passes; full internal listings kept in scratch (uncommitted), only the
wire protocol + plan recorded here.

### The reframe (why byte-identical replay was short-rejected)
NOT cryptographic and NOT a USB/flow bug. The 0x02 poll command carries NO session MAC of its own; the
rejection is a DEVICE-STATE dependency. The poll references DSP/AFE/calibration state that must be
(re)established in the current session by the preceding calibration commands. Replaying poll bytes onto
a sensor whose volatile state isn't set up -> short (~37B) error reply.

Also corrected: SecurityParams is a RED HERRING here. scsGetSecurityParams builds a tag-6 block of
FRESH RANDOM key/IV (palCryptoRng), gated by the persistent `encryptFPData` flag; it is NOT derived
from the SSL session keys. On this unowned sensor images stream PLAINTEXT (flag off) -> the block is
empty/absent. The open driver simply omits it.

### Poll command (scsSensorSendGetFingerprint_V4 @0x5065f0) — on-wire opcode 0x02
Layout: 02 | BE16(printcfg key8) | BE16(reqfield) | PrintParamBlob | [ConfigReplyParams] |
[CalibBlob] | [FalconCfgBlob] | [WOE-setup TLV] | [SecurityParams] | [FpBufferingParams].
Segment inclusion selected by flags/mode; the two observed wire sizes (2691/3033) are just which
optional blobs are present, NOT two opcodes. CalibBlob = calResultsGetCalibrationDataBlob, serialized
from a per-session tagval bag (device+0x408). This is the session-specific segment that matters.

### Poll reply + status (scsSensorParseReply_V4 @0x506340) — VCSFW is LITTLE-endian
Reply plaintext: [0]=0x02 opcode echo, [1..3]=u16 sensor status (LE), [3..]=register TLVs
("04 03 00 09 00 <reg16> 20 04 30 <val32>"). Status 0x0000/0x0412 = OK; any code with bit 0x0400 set
= error. The short 37B reject is an ordinary error reply (no payload): its 2 bytes at [1..3] ARE the
reject reason. NB: esi=0xD1 seen earlier is NOT a reply byte — it's idsSubsystemService's "keep
polling" service tick; 0xD0/0xD2 are OUTBOUND finger-event codes. Poll loop (idsSensorWOEFingerprintPoll
@0x456320): status 0 -> phase done, start imaging; nonzero -> error/stop.
Two error namespaces: transport codes (parseReply, 0x4xx) on a short reject vs BVS-layer codes
(0x213 section-missing, 0xda/db wrong-mode) emitted while decoding the body of a GOOD 2437B reply.

### Calibration (scsSensorFalconCalibrate @0x4fcb20) — CLOSED-LOOP
Steps CommDet/PgaOffset/Adc/PgaGain/AspLna1/AspPga1/Woe. Primitives: scsSensorLoadPatch (the 0x06
uploads), scsSensorGetCountedLinesSynch (the 0x02 counted-line reads). Each step measures the captured
frame and picks the next trial register value -> command bytes are DATA-DEPENDENT, so you cannot pure-
replay calibration bytes + parse responses. Converged AFE values are static per sensor and are
persisted, but program VOLATILE registers that reset each power cycle. Minimum viable open path: run
the closed loop once, cache tags 1..7, then re-upload fixed patches + re-write cached values each
session. (Risk, unverified: whether re-writing cached values without a fresh sweep images well across
temperature drift.)

In-session command stream (captures/capture_seq.json, 186 cmds): 1f setup; calibration block
(1a+06+02 sweep frames, ~idx 1-13, term 0x12); then the poll loop repeating [17] 04 02(2691) 02(3029).

### Driver changes this session (committed pending live result)
- crypto: session now decrypts the server post-CCS Finished so rseq/siv advance to post-handshake state
  (src/session.rs) — required before any in-session reply can be decrypted (send side was already fine,
  which is why our commands were accepted).
- usb::read_record(): reads one complete SSLv3 record (accumulates across 64B bulk packets).
- capture::arm_capture(): now decrypts EVERY reply in order, logs decoded [op,status] per command, and
  flags/stops at the first 0x02 reject — the decisive diagnostic (no swipe needed; reject precedes
  imaging). parse_reply()/status_is_ok() implement the parseReply status decode above.

### Next
Run `sudo RUST_LOG=info ./target/release/vfs495 capture --out /tmp/probe.bin` (no swipe). The first
0x02 reject's status + index decides: reject at an early (calibration) 0x02 -> implement closed-loop
calibration; calibration 0x02s OK but poll 0x02 rejects -> calibration state is fine, poll param
(CalibBlob) is the issue. Result to be folded into this entry before commit.

### LIVE RESULTS (2026-09-26, same day) — "blocked" conclusion OVERTURNED
Ran the open driver with in-session reply decryption (session.rs now consumes the server Finished so
rseq/siv advance; usb::read_record frames whole records; capture::arm_capture decrypts every reply).
Ground-truth reply format from live decryption: **reply plaintext = u16 LE status [+ payload]** (NOT
"[0]=opcode echo, [1..3]=status" — that earlier read came from agent samples that were actually HP
OUTBOUND commands). A bare ack is 2 bytes `00 00` = status 0x0000 = OK.

- Commands 0..22 ALL return status 0x0000 OK. The **poll 0x02 commands (seq 16,21,22) return the full
  2437-byte reply** (plaintext 2404B = status + register TLVs `00 00 00 00 ff f9 87 20 e1 f8 87 00 ...`),
  status 0x0000, in our FULLY-OPEN session. => The prior "short-reject / capture is an un-replayable
  interactive protocol" conclusion was an ARTIFACT of misparsing the 2-byte status ack. The polls work.
- The wall is the **imaging trigger** (seq 23 `0x17`, seq 24 `0x04`): ~6s after the last poll the sensor
  **re-enumerates** (dmesg: `usb 1-8: USB disconnect` + `new full-speed USB device`, same 138a:003f,
  new device number). Our write then fails `No such device`.
- reopen() re-acquires the handle but every subsequent read returns 5 zero bytes — the **SSL session does
  NOT survive the reset**. A FRESH `vfs495 handshake` right after DOES succeed => device is alive, only
  the session is lost.
- Strong hypothesis: the reset is a **watchdog timeout** — we fire the imaging trigger with NO finger
  present (HP's recorded seq had a finger swiping), the sensor waits ~6s for frames, gets none, resets.
  I.e. capture IS interactive in the sense that the imaging phase needs a live finger + a finger-aware
  poll loop; it is NOT that our commands are wrong (they're accepted, status OK).

### Revised remaining work for fully-open capture
1. Decode the 2437-byte poll reply payload (register TLVs after the status word) to find the
   finger-contact / frame-ready signal (compare baseline vs finger-present poll reply).
2. Real poll loop: repeat 0x02 poll until contact detected, THEN run the 17/04/02 frame-read loop while
   the finger moves, draining EP2. (Fixed-sequence replay without a finger always hits the reset.)
3. Immediate test: replay the existing sequence WHILE swiping continuously from launch, to see if a
   present finger avoids the reset and yields a real (non-baseline) image on EP2.
Driver: session.rs (Finished consumed), usb.rs (read_record), capture.rs (reply decrypt + status decode
+ reopen-on-disconnect). All committed pending a green capture.

### Imaging-latch reset characterized (2026-09-26, same day)
Wired reply-decryption + reopen + re-handshake recovery into the capture loop and ran the full
sequence on hardware (no finger; the reset is finger-INDEPENDENT — a firm held finger did NOT prevent
it). Findings:
- The **0x04 imaging-latch intrinsically re-enumerates the sensor** (USB disconnect + fresh device
  number, same 138a:003f). Not a watchdog-for-finger, not the 1-byte 0x17 (skipping 0x17 just moved the
  reset to 0x04). Every imaging iteration triggers it.
- The re-enumeration **drops the SSL session** (post-reopen EP1 reads are 5-byte zeros). Re-acquiring the
  handle is not enough.
- **Recovery works:** on the reset, reopen() + a fresh `handshake()` re-establishes a session, and the
  imaging commands then all return OK (0x04 -> status 0x0412 OK; poll 0x02 -> 2402B, status 0x0000).
  So the whole 186-command sequence completes with valid statuses.
- BUT re-handshake per iteration (~2s each x ~40 iters) is far too slow to capture a ~2s swipe, and it
  is almost certainly NOT what HP does. Leading hypothesis: HP re-enumerates ONCE into an imaging mode
  and stays there reading EP2 frames; OUR re-handshake kicks the device back to session mode, so the
  next 0x04 re-enters imaging (reset) -> the per-frame reset loop is self-inflicted by re-handshaking.

### Decisive next experiment (needs a finger swipe)
Trace HP's own getprintwait across the 0x04 reset with usblog preloaded (scripts/trace_capture.gdb.py):
does HP (a) re-handshake (send 0x11 tunnels) after each 0x04, or (b) re-enumerate ONCE then read EP2
frames without re-handshaking? That decides whether the open driver should re-handshake per frame
(slow, current) or switch to an imaging-mode EP2 read after a single reset (fast, swipe-capable).
Also confirm whether image frames arrive on EP2 (plaintext) during imaging, and how many 0x04s HP sends
per swipe. Driver now has: poll-probe diagnostic, EP2 spread metric, reopen+re-handshake recovery,
VFS_SWIPE_AT / VFS_SKIP_17 experiment gates.

### HP getprintwait wire trace — the RESET is survivable WITHOUT re-handshake (2026-09-26)
Traced HP's own getprintwait across the resets (usblog.so raw EP1/EP2 + scsSend gdb hook; one swipe).
/tmp/hp_getprint.usblog: 110 W ep=0x01, 110 R ep=0x01, 1046 R ep=0x02 (image), 11 R(err) ep=0x02 (the
re-enumerations). DECISIVE:
- Only **2** `0x11` tunnels in the whole trace (lines 19,21) = the INITIAL handshake only (same two our
  session.rs sends). **HP never re-handshakes.** 99 in-session `17 03 00` records, 75 of them AFTER the
  first reset.
- At each re-enumeration HP just CONTINUES the same session: right after `R(err) ep=0x02` it sends the
  `17 03 00` poll (len 2725) and gets the `len 2437` reply — session fully intact, seq continues.
=> The sensor's SSL session SURVIVES the USB re-enumeration. Our session dies only because of OUR
   reopen() procedure. Prime suspect: `set_active_configuration(1)` (SET_CONFIGURATION resets device/
   endpoint state and likely the firmware session); HP does not re-issue it. Also our re-handshake
   (added as a workaround) is unnecessary and is what made the loop slow.

FIX DIRECTION for next session:
1. Make Sensor::reopen() re-acquire the handle WITHOUT set_active_configuration(1) (just open + claim_
   interface(0)); keep the same Record (keys, sseq/rseq, civ/siv) — do NOT re-handshake.
2. Handle the seq of the reset-triggering command: the 0x04/command that triggers the re-enumeration —
   determine whether the sensor counted it (rseq/sseq) before dropping USB, so the resend uses the right
   sseq (HP continues seamlessly, so likely the command is re-sent/continued without a seq gap). Verify
   by decrypting replies after reopen: if they parse to sane statuses (0x0000/0x0412), the session held.
3. Then the imaging loop runs at full speed (no ~2s re-handshake per frame) and a real swipe can be
   captured. HP sends ~99 in-session cmds / ~1046 EP2 reads per swipe.
BONUS: /tmp/hp_getprint.usblog EP2 (R ep=0x02) reads contain a REAL fingerprint swipe (plaintext) to
validate the open decode against. (Both /tmp logs are chmod 644; they are biometric+trace data — do NOT
commit; treat as gitignored scratch.)

### Adversarial review corrections (2026-09-26) — before handoff
An adversarial subagent re-checked this session's claims against the logs, code and binary. Confirmed:
numbers (110/110/1046 W/R/img, 11 R(err), 2 tunnels @lines 19,21 pre-first-reset, 99 in-session records),
the reply=u16-LE-status reading, and that HP sends NO re-handshake after any reset. Corrections applied:
- **status decode:** the "bit 0x0400 set = error" rule of thumb is WRONG (0x0412 has that bit but is OK).
  scsSensorParseReply_V4 does exact-match: OK = {0x0000, 0x0412}, everything else = error. status_is_ok
  fixed accordingly.
- **"session survives re-enumeration with nothing needed" OVERREACHES.** usblog.so hooks only bulk
  read/write; a full re-enumeration (new device number) forces HP to re-open + re-claim via control
  transfers that the log CANNOT show. Proven: HP does not re-handshake (SSL layer). Unproven: what
  control-plane recovery HP does. So "just resend on the new handle" is not established as sufficient.
- **set_active_configuration(1) is CANDIDATE #1, not THE fix (untested).** Co-equal alternative: Record
  seq/IV continuity — every prior death occurred WITH both set_active_configuration AND re-handshake in
  the loop, so the exact target config (reopen w/o set_config AND keep the same Record w/o re-handshake,
  with correct seq accounting for the reset-triggering command) has NEVER been run. Next session must
  test that combination and isolate the cause; don't assume removing set_active_configuration alone fixes it.
- **"each 0x04 -> one reset" is inference:** hp_cmds.txt has 9x 0x04 but the wire shows 11 R(err); not 1:1.
- **SecurityParams:** conclusion (empty on this plaintext sensor -> omit) holds, but the earlier mechanism
  claim ("fresh random via palCryptoRng, not SSL-derived") is NOT supported by scsGetSecurityParams
  disassembly (it calls scsSSLGetSessionKeyLength/_scsSensorFpEncInit/_scsSensorFpSignInit); retract that
  mechanism unless re-verified.
- Nit: 74 (not 75) in-session records after the first reset.
- Final wire record is an encrypted 15 03 alert (line 1277) — likely close_notify/teardown; uncharacterized.

## 2026-09-26 (session 3) — *** THE "RE-ENUMERATION" WAS OUR BUG, NOT THE SENSOR ***

The entire prior premise ("the 0x04 imaging-latch intrinsically re-enumerates the sensor ~11x/swipe,
so make the SSL session survive the reset") is **FALSE**. Captured HP's own getprintwait across a real
finger swipe under **usbmon** (control + bulk, not just usblog's bulk): `usbmon_swipe.txt`, 4254 lines.

### Ground truth from the HP swipe (usbmon)
- HP ran the **entire swipe on ONE stable USB address** (dev 116, line 42→4252). **ONE** GET_DESCRIPTOR,
  **ONE** SET_CONFIGURATION, **ZERO** port resets, **ZERO** disconnects. **HP never re-enumerates.**
- EP2: **23 MB** of image data over 1656 clean reads (status 0); only 14 `-2` (ENOENT cancels). EP1: 17
  clean 2437B poll replies + 159 37-byte records, no zeros, no errors. Session never dropped.
- => The old usblog "11x R(err) ep=0x02" were just EP2 read cancels (status -2), **NOT** USB
  re-enumerations. The handoff's whole "session survival across reset" task was chasing a self-inflicted
  wound.

### Two co-located root causes of OUR re-enumeration
1. **Corrupted replay sequence.** `captures/capture_seq.json` was built from `clean_cmds.txt`, which was
   parsed from the **WIRE/bulk stream** where SSL record-type bytes leak in as fake commands: histogram
   61x`0x17`(AppData type), 34x`0x04`, and even `0x11`(handshake tunnel) + `0x15`(alert). The
   authoritative HP command layer is `plaintext_cmds.txt` (gdb `scsSend` hook): only 2x`0x17`, 2x`0x04`,
   17x`0x02`. REBUILT capture_seq.json from plaintext_cmds.txt in-session slice (lines 11..52; 1-8 =
   pre-handshake init done by session.rs init_seq, 9-10 = 0x11 handshake tunnels done by session.rs,
   53 = 0x15 close alert). New seq = 42 entries (17x02, 9x1a, 9x06, 2x12, 2x17, 2x04, 1x1f).
   Regenerate: `python3` filter plaintext_cmds.txt lines 11..52 -> JSON list of the hex payloads.
   (Both files gitignored — device/trace data.)
   RESULT: with the clean seq, commands **0..23 ALL return status 0x0000 OK** (setup + calibration + 14
   polls) vs the old pollution that rejected almost everything.
2. **EP2 starvation at the imaging trigger (remaining blocker).** With the clean seq the ONLY re-enum is
   at the first 1-byte `0x17` imaging-latch (idx 24). usbmon of our run: we write 0x17 (37B, completes
   OK), then BLOCK ~600ms on an EP1 read that never returns, get `-108` (ESHUTDOWN) = device dropped —
   all while NOT servicing EP2. HP, after arming imaging, drains EP2 **continuously** (23MB) and never
   gaps it; our synchronous "send EP1 cmd -> block on EP1 reply" loop starves EP2 -> firmware resets.
   FIX DIRECTION: after the imaging latch, stop blocking on EP1 replies; continuously drain EP2 (HP-style
   async/interleaved reads). This is an `arm_capture` architecture change, not a sequence fix.

### Hypotheses FALSIFIED this session (with evidence)
- `set_active_configuration(1)` in reopen(): irrelevant — usbmon shows the **kernel** auto-issues
  SET_CONFIGURATION(1) on every re-enumeration regardless. (Ran with/without: byte-identical dead result.)
- HP does a vendor control-plane resume on reopen: NO — HP's control transfers are 100% standard
  kernel/hub enumeration (GET_DESCRIPTOR/SET_CONFIGURATION/SET_INTERFACE/hub PORT_RESET).
- Resending 0x04 / SSL seq-continuity across reopen (VFS_HP_RESUME experiment): NO — skipping the
  undelivered 0x04 and continuing seq-continuous still returned literal ZERO bytes (not an SSL alert),
  i.e. the session was genuinely gone. Moot anyway now that the re-enum itself is our bug.

### Driver changes (committed)
- crypto.rs: `#[derive(Clone)]` on Record (snapshot/rollback for the seq experiment).
- usb.rs: reopen() no longer forces set_active_configuration by default (VFS_REOPEN_SETCONFIG restores
  it); [DEBUG-rss] logs. HP-faithful and proven inert.
- capture.rs: VFS_HP_RESUME (skip+rollback the reset-triggering cmd) + RESET_SKIPPED sentinel +
  [DEBUG-rss] first-reply-kind logging (fires only after a reopen).
- Diagnostic env gates remain: VFS_SWIPE_AT / VFS_SKIP_17 / VFS_NO_REHANDSHAKE / VFS_REOPEN_SETCONFIG /
  VFS_HP_RESUME. selftest still PASS.

### NEXT (next session)
Rework `arm_capture` imaging phase to continuously drain EP2 (don't block on EP1 after the 0x17/0x04
latch); confirm no `-108`/re-enum on hardware (no finger). Then a real firm/slow swipe -> EP2 stream ->
`decode`/`decode-lines` (already proven). Validation asset: `/tmp/usbmon_swipe.txt`
(scratchpad) is HP's real 23MB swipe on a stable session; the EP2 R:116:2 reads are plaintext frames.

---

## 2026-09-26 (session 4) — *** EP2-STARVATION BLOCKER FIXED: full 42-cmd sequence, ZERO re-enum ***

Implemented the architecture change the last session flagged as NEXT: `arm_capture` no longer blocks
on an EP1 reply while EP2 sits undrained. The imaging-latch (0x17/0x04) makes the sensor stream image
data on EP2 as a side effect; leaving that stream ungated caused the ~600ms EP1 stall -> firmware reset
(-108) -> self-inflicted re-enumeration. HP never gaps EP2.

### Driver changes (committed)
- usb.rs: added `read_record_split(first_ms, rest_ms)` — a short budget for the *first* byte of an EP1
  record, a longer one for the remainder once any byte arrives. A first-byte timeout returns Err with
  nothing consumed, so EP1 can be polled in slices while EP2 is drained between slices without ever
  losing a partial record. `read_record` now delegates to it (same behavior as before).
- capture.rs:
  - `drain_image_bounded(dev, img, quiet_reads, max_ms)` — time-bounded EP2 drain in 16 KiB reads
    (EP2_CHUNK), replacing the old fixed 256-iteration cap. `drain_image_into` delegates to it.
  - `read_reply_interleaved(dev, timeout, img)` — waits for one EP1 record while pulling any pending
    EP2 chunk between short EP1 slices. With no sink it is a plain `read_record`.
  - `send_cmd_draining(dev, rec, plain, recover, img)` — `send_cmd` plus an optional EP2 sink; the reply
    wait uses `read_reply_interleaved`. `send_cmd` delegates with `None`.
  - `arm_capture` now calls `send_cmd_draining(.., Some(&mut img))` and drains with a 2.5s burst budget
    (EP2_BURST_MS) after each command.

### LIVE RESULT (2026-09-26, no finger, VFS_SWIPE_AT=999 VFS_NO_REHANDSHAKE=1)
- **All 42 commands returned status OK** (0x0000 / 0x0412). No REJECT, no `-108`, no re-enum, no reopen.
- Device stayed on **USB address 117 across the entire run** (`lsusb` before == after), TWICE.
- The imaging-latch bursts drain cleanly: cmd[23]/[27] each streamed ~2.1 MB on EP2 (mean 127.5, sd 73.9)
  and the sequence continued straight through — matching HP's ~1.7 MB-per-latch-cycle drain in
  `usbmon_swipe.txt`. Total ~5 MB EP2 with the 2.5s budget (13.9 MB with an 8s budget on the first run).
- So the EP2-starvation root cause is FIXED. There is no longer any re-enumeration to recover from; the
  VFS_HP_RESUME / re-handshake recovery paths are now dead weight for the happy path (kept behind gates).

### Note on decode of a no-finger stream (expected, not a regression)
`decode` on the no-finger dump found only ~11 stride-272 (main-image, width 264) lines. Expected: with no
finger there is almost no main-image content; the raw stream is mostly baseline + navigation lines
(stride 208, width 200), exactly as the frame-demux notes describe. `decode` extracts the longest
fixed-272 run, so it correctly reports "too few lines". Not a decode bug.

### NEXT (needs a physical finger — cannot be done autonomously)
One firm, slow swipe under `sudo RUST_LOG=info ./target/release/vfs495 capture --out /tmp/swipe.bin`
(default VFS_SWIPE_AT=16 cues the finger at the poll/imaging boundary), then
`./target/release/vfs495 decode --input /tmp/swipe.bin --out /tmp/swipe.pgm`. The open decode is already
proven byte-exact on real lines; this is the end-to-end validation on a live-captured (not gdb-rebuilt)
swipe. Open question to watch on that run: whether the raw *live* EP2 stream demuxes to the same
stride-272 01fe frames the gdb-rebuilt stream did (the live no-finger stream mixes 208/272 gaps).

---

## 2026-09-26 (session 4b) — "too few lines" DIAGNOSED: raw live EP2 ≠ decodable frames (transform is UNSOLVED)

A live firm swipe now runs the full 42-cmd sequence cleanly (session-4 fix holds: no re-enum), but
`decode /tmp/swipe.bin` still reports "too few lines (11)". Root cause is NOT swipe quality and NOT the
transport fix — it is a decode-layer gap that prior "proofs" masked.

Evidence (all from /tmp/swipe.bin + captures/ep2_stream.bin + usbmon_swipe.txt):
- **The frames that decode to a fingerprint are type `b4=06 b5=06`.** captures/ep2_stream.bin (the
  "proven" stream) is **100% `06 06`** frames (24921/24921), payload entropy ~6, real ridge structure.
- **The raw LIVE EP2 stream contains ZERO `06 06` frames.** Its 01fe frames are a scatter of other types
  (08 01 nav, 00 00 blank, 05 05, 04 04, 01 01, 0f 08 …) with payloads that are near-zero (blank main,
  entropy ~1) or low-sd (nav, entropy ~5) — no ridge image.
- **The bulk of live EP2 (the two ~2.1 MB imaging bursts after the 0x17/0x04 latch) is entropy 7.999
  bits/byte — effectively random**, flat byte histogram, no line-period autocorrelation, no `17 03 00`
  (so NOT SSL-record-wrapped), only 79 stray 01fe in 4.3 MB.
- **HP's RAW EP2 is the same:** the usbmon reconstruction (52 KB sample, data-length-limited) is
  entropy 7.97 with the same junk frame-types (00 00 / 01 01 / 08 01 / 05 05 / 04 04) and NO `06 06`;
  mid-burst bytes are pure random (`d5e07684 eb18e667 …`).

Conclusion: **`captures/ep2_stream.bin` was rebuilt from gdb-dumped UnpackLineRT *inputs* — i.e. HP's
POST-transform data harvested from RAM inside the driver — not raw EP2.** The raw EP2 wire stream (entropy
~8) is transformed by HP's code (irDliRTFalconData assembly, and very likely a decrypt/depacketize step)
into the `06 06` frames that UnpackLineRT then descrambles. That raw-EP2 → `06 06`-frame transform was
NEVER reverse-engineered; the "byte-exact decode" only ever validated UnpackLineRT (the descramble),
running on HP-harvested intermediate data. So the open path has always been missing this step — it was
just hidden because every decode ran on the post-transform stream. NOTES already called irDliRTFalconData
"the known-hard unsolved open problem"; this session proves it is the exact wall for a live open capture.

### Leading hypothesis for the transform
EP2 imaging data is encrypted (entropy ~8, no SSL framing) — plausibly under the SAME session keys the
driver already has (crypto.rs AES-256-CBC), as a raw keystream/block stream with no record headers.
Testable next: RE HP's EP2 read path (near the poll loop @0x456320 / irDliRTFalconData) to find whether
EP2 bytes are fed through a cipher before framing, and with what key/IV/chunking. If it is the session
key, the open driver can decrypt EP2 with machinery it already has, then the existing 272/`06 06` decode
should light up. If instead it is bit-unpacking (variable-bit mode, not this device's mode-8), the entropy
argues against it, but confirm from the config.

### Correction to the record
Prior top-line "open session + DECODE proven" / "real fingerprint captured end-to-end" overstated the
decode: the SECURE SESSION and TRANSPORT are proven open and live; the DECODE of a raw live EP2 capture
is NOT — it depends on an unsolved raw-EP2 transform. The fingerprint image was produced from HP-RAM-
harvested intermediate data, not from a fully-open capture.

---

## 2026-09-27 (session 5) — *** EP2 TRANSFORM SOLVED: image is AES-256-CBC, key travels in the command. FULLY-OPEN CAPTURE NOW COMPLETE ***

The raw-EP2 → decodable-frames transform (session-4b's blocker) is reverse-engineered and implemented.
The open driver now captures and decodes a real fingerprint from a LIVE raw EP2 stream with zero HP code.

### The mechanism (from the HP binary, debug symbols intact)
- `scsSensorDecryptFingerprint@0x4fd640`: EP2 imaging data is **AES-256-CBC** (`palCryptoDecrypt`->
  `palCryptoAesCbc`, cipher selector 5/6). Key length taken from the SSL suite via
  `scsSSLGetSessionKeyLength` (=32). IV **chains across reads** (last 16 ciphertext bytes of each read
  become the next IV); decrypt is in-place.
- `_scsSensorFpEncInit@0x4eb7f0`: HP generates a **fresh random 32-byte key AND IV per capture**
  (`palCryptoRng`), stored at ctx+0x4b8 (key) and ctx+0x4d8 (IV). NOT the SSL session key.
- `scsGetSecurityParams@0x4fd740`: packs those into a SecurityParams TLV **in the clear** (no RSA wrap):
  **tag `0x0006`, length `0x6a`; value[0..32]=AES key, value[0x20..0x30]=IV, value[0x40..0x60]=sign key,
  byte[0x68]=cipher (0x04=AES-256)**. This TLV is embedded in the `0x02` GetFingerprint command, sent
  over the already-SSL-encrypted channel. The sensor encrypts the image with the host-supplied key.

### Why this unblocks us
Our capture REPLAYS HP's exact command bytes, so the sensor encrypts EP2 with **HP's** key — which is
sitting in plaintext inside those same replayed bytes. We recover it and decrypt. No new key exchange
needed. capture_seq.json commands 3/17/22/23/26/27/41 each carry the TLV; the two imaging commands
(23, 27) additionally carry a populated sign key.

### Proven OFFLINE on the user's live /tmp/swipe.bin (the "too few lines" capture)
- Decrypting the cmd-23 burst (AES-256-CBC, key/IV from seq[23]'s TLV) yields **7845 clean `01fe` frames
  at a perfect 272-byte stride, all frame-type `07 07`** — identical structure to the gdb-rebuilt
  ep2_stream.bin (which was `06 06`; 06 vs 07 is just a mode/version byte the open unpack ignores).
- `vfs495 decode` on the decrypted burst -> **264 x 7845 image**; per-line sd median 57, every line >30,
  dominant ridge column-period ~11.5 px, spectral peak/mean 5.15 = a real, firm-contact fingerprint.
- Wrong key (a non-imaging command) -> ~90 stray `01fe`, no frames. Confirms the key is correct.

### Driver changes (committed)
- crypto.rs: `decrypt_image_stream(key,iv,ct)` = AES-256-CBC, no padding, drops a trailing <16 remainder;
  reuses the record layer's `Aes256CbcDec`. Unit test `image_stream_decrypt_roundtrips` (6 tests pass).
- capture.rs: `parse_security_params(plain)` extracts the `06 00 6a 00` TLV's key/IV (AES-256 only).
  `arm_capture` now tracks the active key/IV, resets them on each SecurityParams command, decrypts each
  command's EP2 slice with the running IV (chained across slices; EP2 reads are 16-aligned so slices are
  whole blocks), and RETURNS the decrypted `01fe` stream instead of raw EP2.
- main.rs: `capture` writes the decrypted stream (no more stale trailing raw read); `run` decodes it.

### Status: FULLY OPEN, end to end
Secure session, transport, capture, EP2 decrypt, frame demux, and unpack/reconstruct all run in open Rust
with no HP code and no gdb RAM harvest. Only a fresh hardware run remains to confirm the wired-in path
live: `sudo ./target/release/vfs495 capture --out /tmp/swipe.bin` then `vfs495 decode --input
/tmp/swipe.bin` (capture now emits the DECRYPTED stream, so decode should light up directly).

### Open follow-ups (minor)
- Frame type `07 07` vs `06 06`: confirm the open unpack (mode 8 / perm_264) is byte-correct for `07`
  frames too (payload decodes to ridges, so likely yes; verify against a fresh gdb pair if paranoid).
- Sign key (value[0x40..0x60]) + `_scsSensorFpSignUpdate` = an HMAC/signature over the image for
  integrity; not needed to obtain pixels, ignored for now.

---

## 2026-09-27 (session 5b) — LIVE-CONFIRMED on hardware: fully-open capture->image works end to end

Ran the wired path on the real sensor (press-and-hold):
`sudo ./target/release/vfs495 capture --out /tmp/swipe.bin` then
`./target/release/vfs495 decode --input /tmp/swipe.bin --out /tmp/swipe.pgm`.

Result: capture emitted the DECRYPTED stream, decode unpacked **7906 lines x 264 cols** and reconstructed
a **264 x 623** finger band — a real fingerprint (per-line/global sd ~57, dominant ridge column-period
~10.6 px). No "too few lines", no HP code, no gdb harvest. This confirms the AES-256-CBC EP2 decrypt
(key/IV recovered from the replayed command's SecurityParams TLV) works live, closing the session-4b
blocker. The open driver is now complete end to end: session -> transport -> capture -> EP2 decrypt ->
demux -> unpack/reconstruct, all in open Rust.

---

## 2026-09-28 (session 6) — feeder daemon: continuous capture -> virtual_image, with finger-presence gate

Built `vfs495 daemon`: the persistent feeder that makes the sensor usable through stock fprintd/PAM/GDM
via libfprint's `virtual_image` bridge. Loop = open+handshake -> arm_capture (decrypts EP2) -> decode ->
finger gate -> `send_image` to $FP_VIRTUAL_IMAGE. Fresh session per capture (proven single-shot path
repeated; re-using a session across captures still unvalidated). `VFS_NO_PROMPT=1` suppresses the
interactive press prompt (the desktop UI drives the user). Flags: `--socket`, `--min-ridge` (default 1.4),
`--once`, `--gap`.

### Key finding: finger presence is NOT separable by contrast
The imaging burst is high-variance sensor NOISE even with no finger (confirmed live, no-finger runs):
decoded no-finger stream = 15892 lines, median per-line sd ~48 — indistinguishable from a finger by
contrast/line-count. So line-count and contrast gates both FAIL (my first two attempts fed no-finger
noise). The real discriminators, measured live (finger = user's /tmp/swipe.bin, no-finger = fresh
capture):
- reconstruct finger-segmentation **crop ratio** (out_h / decoded_rows): finger ~0.08-0.30, but NOISY
  (a no-finger run also hit 0.30) -> not reliable alone.
- **ridge spectral peak/mean** (column-mean profile, ridge band period ~8-16px): finger **1.81**,
  no-finger **1.10-1.14**. This is the robust signal.
Gate = accept only if crop_ratio < 0.6 AND ridge_peak >= min_ridge(1.4). Verified live: no-finger
--once -> "skip: no finger (crop_ratio 0.30, ridge_peak 1.14 < 1.40)", no feed. Finger path proven by
the offline 264x623 print (ridge_peak 1.81).

### Caveat / next
Finger detection is heuristic and tuned on n=1 finger + n=1 no-finger; margin is modest (1.81 vs 1.14).
A weak swipe can false-reject, noise can false-accept. DURABLE FIX: use the `0x02` poll contact signal
(`poll_probe` already reaches poll-ready and reads the contact delta without firing the imaging latch) to
detect a finger BEFORE arming a full capture — not yet wired into the daemon. Also: to route the SYSTEM
fprintd through the bridge needs a systemd drop-in setting FP_VIRTUAL_IMAGE (a system-config change; the
project has not applied it — documented in README for the user to opt into).

### Changes (committed)
- image.rs: `Lines::median_line_std()` (contrast metric, kept for diagnostics) and `ridge_peak(px,w,h)`
  (direct windowed DFT peak/mean over the ridge band).
- capture.rs: swipe prompt gated on `VFS_NO_PROMPT`.
- main.rs: `Command::Daemon` + `capture_frame` (crop-ratio + ridge_peak gate) + `run_daemon` loop.
- README: daemon usage + GNOME/fprintd systemd drop-in wiring + finger-detection caveat.
- 6 unit tests pass; clippy clean.

---

## 2026-09-28 (session 6b) — poll-based finger detection wired into the daemon (WOE-style)

Added `capture::capture_on_finger` and switched the daemon's `capture_frame` to a two-stage gate, so
empty cycles no longer fire the imaging latch.

### Mechanism
Reverse-engineered `idsSensorWOEFingerprintPoll@0x456320`: it repeatedly sends the poll via
`scsSensorSendCommand` and dispatches a finger event (`idsSensorEventPerformCallback`) — the detection is
a poll-then-watch loop, not a single reply field. So `capture_on_finger` mirrors that:
1. Replay setup seq[0..17] to reach poll-ready.
2. Poll seq[17] (0x02, ~2.4 KB reply, does NOT fire the big burst); build a no-finger baseline from the
   first 3 replies; then flag a finger when `payload_delta` (# bytes differing >4 from baseline) exceeds
   `contact_nd`. Give up after `max_wait_polls` (returns None, imaging never fired).
3. On a touch, replay the imaging tail seq[18..] with the AES-256-CBC EP2 decrypt.

### Verified on hardware (no finger)
Poll-ready reached, 12 polls, payload delta steady at **9-10** (< threshold 30) -> "no finger this
cycle; skipping", NO imaging tail, clean exit. Confirms the empty-cycle path is now cheap and never
stresses the imaging latch. (Earlier `poll-probe` also showed the no-finger reply is near-constant:
nd 0-4 at delta>4.) The finger-side magnitude (delta with a real touch) should be confirmed live to tune
`--contact-nd`; a touch shifts many AFE registers so it is expected well above 30.

### Changes (committed)
- capture.rs: `capture_on_finger` (WOE poll-wait -> imaging), `payload_delta`, `process_image_command`
  (shared key-tracking + EP2 decrypt helper), consts POLL_IDX=17 / BASELINE_POLLS=3.
- main.rs: `capture_frame` now calls `capture_on_finger` first (stage 1), then the ridge gate (stage 2);
  daemon flags `--contact-nd` (30), `--max-wait-polls` (20).
- README: two-stage detection documented. 6 unit tests pass; clippy clean.

### Follow-ups
- Confirm finger-side poll delta live and tune `--contact-nd`.
- fprintd systemd drop-in (FP_VIRTUAL_IMAGE) still a user-opt-in system-config change (README).

## 2026-09-28 (session 7) — *** WOE POLL GATE FALSIFIED LIVE: seq[17] 0x02 poll is finger-blind ***

Goal for the session: step 1 of system integration — get the daemon polling so we
could touch the sensor, measure the finger-side poll divergence, and finally tune
`--contact-nd` (the long-standing open item). Result: the poll-based detection
does not work at all, and we now know why.

### Setup
- Installed the udev rule (`/etc/udev/rules.d/70-vfs495.rules`); `udevadm trigger`
  applied the `uaccess` ACL to the live device with no replug (`user:bine:rw-`).
  This is USB access only — no PAM/GDM/fprintd change.
- Sensor present at 138a:003f, session/handshake healthy every run.

### Bug found first: poll-probe was probing the wrong command
- `poll-probe` defaults were `--prefix 16 --poll-idx 16`. Index 16 is a `0x06`
  calibration command that returns a constant 405 B reply and **no EP2 data**, so
  the first run read `nd=0, EP2 0B` on all 40 polls — pure off-by-one, not a sensor
  fact. The `0x02` GetFingerprint poll the daemon actually watches is `seq[17]`
  (`capture::POLL_IDX = 17`, 2691 B, carries the SecurityParams TLV).
- Fixed the `poll-probe` defaults to `17/17` and documented the trap in the CLI
  help. `capture_on_finger` was already correct (`POLL_IDX = 17`).

### The finding (two live runs)
Looping `seq[17]` with EP2 draining, 40 polls @ 150 ms:
- **Run A** (press mid-run per the cue): `nd` flat at 3–4 the whole time, no jump in
  the press window; EP2 constant 5712 B, mean ≈128, sd ≈74 every poll.
- **Run B** (finger pressed FIRMLY for the entire run, before launch to after
  "done"): identical — `nd` flat 2–4, EP2 constant 5712 B mean ≈127 sd ≈74.

Conclusion: **`seq[17]` is finger-blind.** Replaying a captured `0x02` poll returns
a canned reply plus free-running AFE noise; without the `0x17`/`0x04` imaging latch
the sensor produces no finger-dependent signal in either the reply or the pre-latch
EP2 stream. The WOE poll-divergence gate cannot work at this index, and
`--contact-nd` has no usable threshold. The earlier "no-finger baseline ~10 bytes
jitter" was measuring this noise; the finger side had never been confirmed — this
is the first time it was, and it is negative.

### Consequence and plan
- Daemon stage-1 detection is dead as designed. Rebuild on the **ridge gate**
  (stage 2), which is the proven finger signal (crop_ratio < 0.6 and ridge_peak
  above ~1.4; finger ~1.8 vs noise ~1.1): fire the imaging latch on a timer,
  decode, gate on the reconstructed image, drop the poll stage. Firing the latch
  per cycle is acceptable — the "imaging latch stresses/re-enumerates the sensor"
  premise was already falsified in session 4.
- Before rewiring: confirm live that the ridge gate separates finger from
  no-finger (a `capture` with a finger vs. without, compare `ridge_peak`).
- Worth a look first: HP may deliver finger-present events out of band on the
  **unused EP3 interrupt endpoint** or via a dedicated WOE command (not the
  replayed swipe poll). If so, that would restore a low-power gate.

### Changed
- `src/main.rs`: `poll-probe` defaults 16/16 → 17/17 + help note.
- `docs/STATUS.md`: §7 rewritten (poll gate falsified, ridge gate is the detector),
  §8 blocker recorded, header status corrected.

### Follow-ups
- Confirm ridge gate finger/no-finger discrimination live.
- Rebuild daemon finger detection on the ridge gate (or EP3-interrupt WOE).
- Only then: fprintd systemd drop-in + enroll/verify.

### Ridge-gate discrimination CONFIRMED; daemon rebuilt on ridge-only gate
Added `vfs495 ridge-probe` (fires a full `arm_capture`, decodes, prints
rows/crop_ratio/ridge_peak + the daemon verdict without gating, writes a PGM).
Live results:
- No finger: ridge_peak **1.21**, crop_ratio 0.857 -> verdict reject.
- Finger held: ridge_peak **2.10**, crop_ratio 0.995 -> ridge passes, but the old
  gate's crop_ratio<=0.6 condition FAILED (a held finger covers ~all lines so
  segmentation crops nothing -> crop_ratio ~1.0, actually HIGHER than no-finger).

Conclusions:
- `ridge_peak` is a clean discriminator (noise ~1.2, finger ~2.1); default
  `--min-ridge 1.4` separates them.
- `crop_ratio` is NOT a finger signal (wrong direction on a static press) and was
  the reason a real finger was being rejected. Removed from the gate.

Changes:
- `capture_frame` (main.rs) now: `arm_capture` -> decode -> gate on `ridge_peak >=
  min_ridge` ALONE (rows>=60 sanity floor; crop_ratio logged for diagnostics only).
  Dropped the dead poll-detection stage.
- Removed `capture::capture_on_finger`, `process_image_command`, `payload_delta`,
  `BASELINE_POLLS`, `POLL_IDX` (all only served the falsified poll gate). Left a
  note pointing future low-power-gate work at EP3.
- Daemon CLI/`run_daemon`/`capture_frame` lost `--contact-nd`/`--max-wait-polls`.
  Remaining daemon flags: `--socket --min-ridge(1.4) --once --gap`.
- Build clean, clippy clean (only pre-existing warnings), 6 unit tests pass.

Not yet done: run the daemon end-to-end into fprintd (enroll/verify) with a live
finger; validate feed quality across enroll stages; session reuse across captures.
Everything above (poll-probe default fix + ridge-probe + daemon rebuild) NOT yet
committed.

## 2026-09-28 (session 8) — libfprint enroll/verify with LIVE sensor image; image-size fix

Step 1 of system integration: run the daemon path end-to-end into libfprint
enroll/verify. Drove libfprint directly via GObject introspection (no fprintd/PAM/
system change), feeding images over the virtual_image socket exactly as the daemon
does. Parametrized `vimage_proof.py` into a scratchpad probe that enrolls a given
PGM, verifies it against itself (expect match) and against a synthetic different
print (expect reject).

Findings:
- Baseline `captures/fingerprint_open.pgm` (200x400, an earlier swipe): PASS
  (enroll 5 stages, match self, reject different). libfprint stack works here.
- Our fresh LIVE held-finger capture `captures/ridge_finger.pgm` (264x7867):
  REJECTED by libfprint before any minutiae read — "Image header suggests an
  unrealistically large image, disconnecting client." A held finger stacks the same
  region into ~7867 near-identical lines (the finger-segment crop keeps them all,
  crop_ratio ~1.0), producing an over-tall strip libfprint won't accept.
- A normal finger-sized WINDOW of that same real capture PASSES: central 264x400
  AND central 264x500 both enroll all 5 stages, match self, reject different. So the
  live image contains genuine usable minutiae; the only problem was geometry/size.

Fix: `image::reconstruct` now clamps the finger band to a central `MAX_FEED_ROWS`
(=500) window when it is taller. A swipe (few-hundred-line band) is unaffected; the
clamp only bites the held-finger redundant-stack case. Re-tested: the 264x500 clamp
window enrolls/verifies (PASS). Build + 6 unit tests pass.

Net: image path is PROVEN end-to-end for a real sensor capture (enroll+match+reject
through real libfprint). Still to do live: run the actual `vfs495 daemon` feeding a
live enroll with finger touches (5 for enroll + 1 verify); then the fprintd systemd
drop-in. Committed this session.

### Live daemon enroll attempt — BLOCKED by repeated-capture USB re-enumeration
Wrote an interactive harness (scratchpad/live_enroll.py) that opens libfprint
virtual_image directly (no fprintd/PAM change), spawns one `vfs495 run` capture per
enroll stage with loud PRESS/HOLD/LIFT cues, and feeds each decoded image to the
socket. Findings from live attempts:
- Single capture / handshake: RELIABLE (confirmed again this session).
- Repeated back-to-back full captures: the sensor DROPS OFF USB and re-enumerates
  (address walked 005 -> 011 across one failed run); once it is mid-re-enumeration,
  every `vfs495 run` fails instantly with `EP_OUT write failed: No such device`,
  producing a cascade. The daemon's old tight retry loop turned this into thousands
  of lines/sec (fixed: back off gap.max(3)s on error, commit 41e05fa).
- A transient `open_sync` "Address already in use" also appeared: a race with a
  just-Ctrl-C'd prior harness still releasing its virtual_image socket. Mitigated
  by a unique per-PID socket + atexit unlink; in isolation open_sync works fine.

Root cause: we open a FRESH session + full 42-cmd imaging sequence per capture.
Doing that repeatedly (enroll = 5, plus every verify) churns USB re-init and
re-enumerates the sensor. HP images continuously in ONE session. So the fix is
repeated-capture resilience — most likely SESSION REUSE (open once, capture many),
the previously-deferred item, and/or capture-level recovery that waits out a
re-enumeration and re-opens on the new address instead of failing the cycle.

Status: the SUBSTANCE of step 1 is proven (a real live capture enrolls all 5
stages + verifies through libfprint, session 8). The fully-live 5-touch enroll is
gated on repeated-capture stability, not on the protocol.

## 2026-09-28 (session 9) — session reuse FIXES re-enumeration; two detector bugs found

### Session reuse (fix for repeated-capture re-enumeration) — WORKS
Refactored the daemon to open the device + SSL-handshake ONCE and reuse that
session across captures (capture_frame now takes &mut Sensor + &mut Record); a
capture fault rebuilds the session (reopen waits out a re-enumeration, else fresh
open). Validated no-finger: 6 back-to-back capture cycles on one reused session,
0 errors, 0 rebuilds, USB address stable (no re-enumeration). Committed 9699192.
(Note: `ridge-probe` still opens a fresh session per run, so repeated ridge-probes
still re-enumerate — that path is diagnostic-only; the daemon is the stable one.)

### Bug 1: MAX_FEED_ROWS clamp broke the ridge gate (FIXED)
The 264x7867->500 clamp I added (session 8, inside reconstruct) was computing
`ridge_peak` on the clamped 500-row window. ridge_peak is WINDOW-SIZE DEPENDENT:
averaging over 500 rows instead of ~7900 suppresses noise far less, inflating the
no-finger ridge from ~1.2 to ~2.4-2.6 -> the gate reported FINGER with nothing on
the sensor (confirmed on a fresh session AND after a full laptop power-off, so it
was never sensor drift from that). Fix: reconstruct returns the full band again;
`image::window_for_feed()` clamps to central MAX_FEED_ROWS ONLY for the pixels fed
to libfprint, AFTER the gate is decided on the full image. RidgeProbe verdict also
corrected to ridge-only (was still ANDing crop_ratio<=0.6, which the daemon dropped).

### Bug 2 / open problem: no-finger ridge_peak DRIFTS -> fixed threshold is fragile
Even on the full image (same code as session 7 morning), no-finger ridge_peak is
now 1.60-1.82, vs 1.21 at session start; a held finger is ~2.1. So the no-finger
baseline drifts upward with use/temperature and the finger margin can shrink to
~0.3, which a fixed --min-ridge cannot separate reliably. This is consistent with
our calibration being a FIXED REPLAY while HP's is closed-loop/adaptive
(scsSensorFalconCalibrate is data-dependent) -> stale background, residual ridge-
like structure in no-finger noise. NOT yet solved. Options to evaluate:
  (a) adaptive/relative baseline: measure current no-finger ridge at daemon start
      and gate on a delta above it (needs a guaranteed-no-finger moment);
  (b) a better discriminator (tighter ridge frequency band / orientation coherence
      / finger-region contrast) that separates real ridges from drifted noise;
  (c) implement real closed-loop calibration (deep RE) so no-finger stays low;
  (d) require a SWIPE (not a hold): a swipe yields a segmentable band (crop_ratio
      low ~0.06-0.3) that no-finger (crop ~1.0) never does, restoring crop_ratio as
      a discriminator alongside ridge — matches this being a swipe sensor.

### PAUSED here 2026-09-28 (resume pointer)
Work paused for a few days. Exact resume state is in docs/STATUS.md §0 ("Resume
here"). Summary: detection blocker = no-finger ridge_peak drifts (~1.2 fresh ->
~1.6-1.8 used) into finger range (~2.1) because our AFE calibration is a fixed
replay vs HP's closed-loop scsSensorFalconCalibrate. Decision: implement C-full
(port the closed-loop calibration). NEXT ACTION = run scripts/trace_calibration.gdb.py
(sudo, get_ownership_info -doinit, no finger) -> captures/calib_trace.txt, then map
the 7 calibration steps and port them.

Tooling added this session (persistent, in scripts/):
- scripts/trace_calibration.gdb.py — gdb trace of scsSensorFalconCalibrate's
  LoadPatch/GetCountedLines calls (the pending NEXT ACTION runs this).
- scripts/enroll_verify_probe.py — enroll+verify any PGM through libfprint direct
  (no fprintd). Proves the image path; PASS on real captures 2026-09-28.
- scripts/live_enroll.py — live daemon enroll+verify harness with press/hold/lift
  cues; ready for when detection is fixed.
Nothing uncommitted after this entry.
