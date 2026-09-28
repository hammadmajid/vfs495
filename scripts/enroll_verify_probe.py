#!/usr/bin/env python3
"""Enroll + verify a given PGM through libfprint's virtual_image, directly (no
fprintd/PAM/system change). Proves whether an image produces a usable minutiae
template: enroll -> verify-same (expect match) -> verify-different (expect reject).

Usage:  python3 scripts/enroll_verify_probe.py <print.pgm>

Requires python3-gobject + libfprint with the virtual_image driver (Fedora ships
it) and numpy. Creates its own temp socket; nothing persistent is touched.
Validated 2026-09-28: captures/fingerprint_open.pgm (200x400) and a central
264x400/500 window of a real live capture all PASS.
"""
import os, sys, socket, struct, threading, time, tempfile

SOCK = os.path.join(tempfile.mkdtemp(prefix="vfs_evp_"), "vimg.sock")
os.environ["FP_VIRTUAL_IMAGE"] = SOCK

import numpy as np

def load_pgm(path):
    with open(path, "rb") as f:
        assert f.readline().strip() == b"P5", "not a P5 PGM"
        w, h = map(int, f.readline().split())
        f.readline()
        return np.frombuffer(f.read(w * h), np.uint8).reshape(h, w)

def synth_print(h, w, seed=7):
    rng = np.random.default_rng(seed)
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    r = np.hypot(xx - w * 0.5, yy - h * 0.45)
    theta = np.arctan2(yy - h * 0.45, xx - w * 0.5)
    ridges = np.sin(0.11 * r * 2 * np.pi / 6 + 3 * np.cos(theta + 0.6)) * 60 + 128
    ridges += rng.normal(0, 8, ridges.shape)
    return np.clip(ridges, 0, 255).astype(np.uint8)

class Feeder(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.img = None; self.stop = False; self.sent = 0
    def set(self, img): self.img = img
    def run(self):
        while not self.stop:
            img = self.img
            if img is None:
                time.sleep(0.05); continue
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(1.0); s.connect(SOCK)
                h, w = img.shape
                s.sendall(struct.pack("<ii", w, h) + img.tobytes()); s.close()
                self.sent += 1; time.sleep(0.4)
            except (socket.timeout, OSError):
                time.sleep(0.15)

import gi
gi.require_version("FPrint", "2.0")
from gi.repository import FPrint, GLib

def main():
    if len(sys.argv) < 2:
        print("usage: enroll_verify_probe.py <print.pgm>"); return 1
    A = load_pgm(sys.argv[1]).astype(np.uint8)
    B = synth_print(A.shape[0], A.shape[1])
    print(f"[i] enroll image A = {sys.argv[1]} {A.shape}  (B = synthetic-different)")

    feeder = Feeder(); feeder.start()
    ctx = FPrint.Context.new(); ctx.enumerate()
    devs = ctx.get_devices()
    dev = next((d for d in devs if (d.get_driver() or "") == "virtual_image"), None)
    if dev is None:
        print("[!] no virtual_image device (FP_VIRTUAL_IMAGE set? driver present?)"); return 1
    dev.open_sync()
    stages = dev.get_nr_enroll_stages()
    print(f"[i] device driver={dev.get_driver()} enroll_stages={stages}")

    def progress(d, done, pr, err, ud=None):
        print(f"    enroll stage {done}/{stages}")

    feeder.set(A); time.sleep(0.5)
    tmpl = FPrint.Print.new(dev); tmpl.set_finger(FPrint.Finger.RIGHT_INDEX)
    try:
        enrolled = dev.enroll_sync(tmpl, None, progress, None)
        print("[+] ENROLL ok")
    except GLib.Error as e:
        print(f"[!] ENROLL FAILED: {e.message}"); dev.close_sync(); return 2

    feeder.set(A); time.sleep(0.6)
    try:
        r = dev.verify_sync(enrolled)
        same_ok = bool(r[0] if isinstance(r, tuple) else r)
        print(f"[{'+' if same_ok else '!'}] VERIFY(same): match={same_ok} (expect True)")
    except GLib.Error as e:
        print(f"[!] verify(same) error: {e.message}"); same_ok = False

    feeder.set(B); time.sleep(0.8)
    try:
        r = dev.verify_sync(enrolled)
        diff_ok = not bool(r[0] if isinstance(r, tuple) else r)
        print(f"[{'+' if diff_ok else '!'}] VERIFY(diff): match={not diff_ok} (expect False)")
    except GLib.Error as e:
        print(f"[i] verify(diff) raised {e.message} -> non-match"); diff_ok = True

    dev.close_sync(); feeder.stop = True
    ok = same_ok and diff_ok
    print("\n=== RESULT:", "PASS" if ok else "FAIL", "===")
    return 0 if ok else 3

if __name__ == "__main__":
    sys.exit(main())
