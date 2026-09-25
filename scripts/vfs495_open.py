#!/usr/bin/env python3
"""Open VFS495 (138a:003f) secure-session client — no HP code in the session path.

On an UNOWNED sensor (ours: get_ownership_info -> 65535/65535) the ClientKeyExchange
is plain RSA(premaster) (no s_key AES-wrap), so a standard proprietary-SSLv3 handshake
establishes the session. This module: replays the static init (patch uploads = HP
firmware blobs loaded to sensor RAM, kept in vendor/patches/, the accepted community
compromise), then performs the SSLv3 handshake in open Python, then can send in-session
commands and read the plaintext image on ep2.

Crypto follows the spec reverse-engineered by saifulmd0/vfs495-linux (docs/SSL_PROTOCOL.md),
independently re-implemented here and validated byte-exact against a live gdb dump
(captures/skey_dump.json) via `--selftest`.

Usage:
  python3 scripts/vfs495_open.py --selftest        # offline crypto check (no hardware)
  sudo .venv/bin/python scripts/vfs495_open.py --handshake   # live: init + SSL handshake
"""
import argparse, json, os, struct, sys, hashlib, secrets

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CAP  = os.path.join(ROOT, "captures")
VEND = os.path.join(ROOT, "vendor", "patches")
VID, PID = 0x138A, 0x003F
EP_OUT, EP_IN, EP_IMG = 0x01, 0x81, 0x82

# Our sensor's RSA public key (from captures/modulus.json; per-device, big-endian as HP lays it out)
MODULUS_BE = bytes.fromhex(json.load(open(os.path.join(CAP, "modulus.json")))["modulus"])
RSA_EXP = 0x10001

# ---- SSLv3 crypto (Validity variant) --------------------------------------
def ssl3_prf(secret, seed_a, seed_b, nbytes):
    """SSLv3 KDF: for i=0.., salt=('A'+i) repeated (i+1); MD5(secret + SHA1(salt+secret+a+b))."""
    out, i = b"", 0
    while len(out) < nbytes:
        salt = bytes([0x41 + i]) * (i + 1)
        out += hashlib.md5(secret + hashlib.sha1(salt + secret + seed_a + seed_b).digest()).digest()
        i += 1
    return out[:nbytes]

def rsa_encrypt(msg):
    """PKCS#1 v1.5 type-2; modulus interpreted LITTLE-endian; wire = big-endian C."""
    n = int.from_bytes(MODULUS_BE, "little")
    k = len(MODULUS_BE)
    ps = b""
    while len(ps) < k - 3 - len(msg):
        b = secrets.token_bytes(1)
        if b != b"\x00":
            ps += b
    em = b"\x00\x02" + ps + b"\x00" + msg
    return pow(int.from_bytes(em, "big"), RSA_EXP, n).to_bytes(k, "big")

def ssl3_finished(master, hs_msgs, label):
    def h(algo, pad):
        inner = algo(hs_msgs + label + master + b"\x36" * pad).digest()
        return algo(master + b"\x5c" * pad + inner).digest()
    return h(hashlib.md5, 48) + h(hashlib.sha1, 40)

class Rec:
    """SSLv3 record layer once the cipher is active (AES-256-CBC + length-less SSLv3 MAC)."""
    def __init__(self, kb):
        (self.cmac, self.smac, self.ckey, self.skey, self.civ, self.siv) = (
            kb[0:20], kb[20:40], kb[40:72], kb[72:104], kb[104:120], kb[120:136])
        self.sseq = self.rseq = 0
    def _mac(self, key, seq, rtype, data):
        hdr = struct.pack(">Q", seq) + bytes([rtype])          # NOTE: length omitted (Validity variant)
        inner = hashlib.sha1(key + b"\x36" * 40 + hdr + data).digest()
        return hashlib.sha1(key + b"\x5c" * 40 + inner).digest()
    def encrypt(self, rtype, data):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        m = self._mac(self.cmac, self.sseq, rtype, data); self.sseq += 1
        body = data + m
        pad = 16 - (len(body) % 16)
        body += bytes([pad - 1]) * pad
        enc = Cipher(algorithms.AES(self.ckey), modes.CBC(self.civ)).encryptor()
        ct = enc.update(body) + enc.finalize()
        self.civ = ct[-16:]
        return bytes([rtype, 3, 0]) + struct.pack(">H", len(ct)) + ct
    def decrypt(self, rec):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        assert rec[1:3] == b"\x03\x00", rec[:3].hex()
        ln = int.from_bytes(rec[3:5], "big"); ct = rec[5:5 + ln]
        dec = Cipher(algorithms.AES(self.skey), modes.CBC(self.siv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        self.siv = ct[-16:]
        padlen = pt[-1] + 1
        body = pt[:-padlen]
        data, mac = body[:-20], body[-20:]
        self.rseq += 1
        return rec[0], data

def client_hello(client_random, sid=b"\x00" * 7):
    body = b"\x03\x00" + client_random + bytes([len(sid)]) + sid + b"\x00\x06" + \
           b"\x00\x44\x00\x43\x00\x42" + b"\x00"
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body     # 01 + u24 len + body
    return b"\x16\x03\x00" + struct.pack(">H", len(hs)) + hs, hs

def tunnel(record):
    return bytes([0x11]) + struct.pack("<H", len(record)) + record

# ---- offline self-test ----------------------------------------------------
def selftest():
    d = json.load(open(os.path.join(CAP, "skey_dump.json")))
    pre = bytes.fromhex(d["premaster"]); cR = bytes.fromhex(d["client_random"]); sR = bytes.fromhex(d["server_random"])
    master = ssl3_prf(pre, cR, sR, 48)
    kb = ssl3_prf(master, sR, cR, 136)
    ok_m = master.hex() == d["master"]
    ok_k = kb.hex() == d["keyblock"]
    print("master  match:", ok_m, "" if ok_m else f"\n  got {master.hex()}\n  exp {d['master']}")
    print("keyblock match:", ok_k, "" if ok_k else f"\n  got {kb.hex()}\n  exp {d['keyblock']}")
    return 0 if (ok_m and ok_k) else 1

# ---- live handshake -------------------------------------------------------
def live_handshake(do_capture=False):
    import usb.core, usb.util
    seq = json.load(open(os.path.join(CAP, "init_seq.json")))
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None: sys.exit("VFS495 not found")
    try:
        if dev.is_kernel_driver_active(0): dev.detach_kernel_driver(0)
    except Exception: pass
    dev.set_configuration(1); usb.util.claim_interface(dev, 0)
    def w(b, to=3000): dev.write(EP_OUT, bytes(b), to)
    def r(n=0x400, to=3000): return bytes(dev.read(EP_IN, n, to))
    def drain_img():
        try:
            while True:
                if len(bytes(dev.read(EP_IMG, 16384, 400))) < 16384: break
        except usb.core.USBError: pass
    try:
        # 1. init: replay exact observed commands (small ones inline, patches from vendor/)
        for e in seq:
            payload = bytes.fromhex(e["hex"]) if "hex" in e else open(os.path.join(VEND, e["blob"]), "rb").read()
            w(payload); r()
            if payload[0] == 0x1F: drain_img()
        print("[i] init replayed")
        # 2. ClientHello
        cR = secrets.token_bytes(32)
        ch_rec, ch_hs = client_hello(cR)
        # precompute RSA CKE before sending CH (minimize latency)
        premaster = b"\x03\x00" + secrets.token_bytes(46)
        cke_hs = b"\x10\x00\x01\x00" + rsa_encrypt(premaster)
        cke_rec = b"\x16\x03\x00" + struct.pack(">H", len(cke_hs)) + cke_hs
        w(tunnel(ch_rec))
        sh = r()
        print(f"[i] ServerHello {len(sh)}B: {sh[:16].hex()}")
        shln = int.from_bytes(sh[3:5], "big"); sh_hs = sh[5:5 + shln]; sR = sh[11:43]
        # 3. keys + Finished (hash over CH + SH + CKE handshake messages)
        master = ssl3_prf(premaster, cR, sR, 48)
        kb = ssl3_prf(master, sR, cR, 136)
        st = Rec(kb)
        fin_body = ssl3_finished(master, ch_hs + sh_hs + cke_hs, struct.pack("<I", 0x434C4E54))
        fin_hs = b"\x14\x00\x00\x24" + fin_body
        ccs = b"\x14\x03\x00\x00\x01\x01"
        fin_rec = st.encrypt(0x16, fin_hs)
        w(tunnel(cke_rec + ccs + fin_rec))
        resp = r()
        print(f"[i] server flight {len(resp)}B: {resp[:16].hex()}")
        if resp[0] == 0x15:
            print(f"[!] ALERT level={resp[-2]} desc=0x{resp[-1]:02x} -> handshake REJECTED")
            return 1
        if resp[0] in (0x14, 0x16):
            print("[+] HANDSHAKE OK — sensor sent CCS/Finished. Secure session established.")
            return 0
        print("[?] unexpected response")
        return 2
    finally:
        usb.util.release_interface(dev, 0); usb.util.dispose_resources(dev)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--handshake", action="store_true")
    a = ap.parse_args()
    if a.selftest: sys.exit(selftest())
    if a.handshake: sys.exit(live_handshake())
    ap.print_help()
