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
