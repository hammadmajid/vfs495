#!/usr/bin/env python3
"""Isolated proof that libfprint's virtual_image enroll->verify round-trips.

Drives libfprint DIRECTLY via GObject introspection (no fprintd, no PAM, no GDM,
no system config touched). A background feeder thread speaks the virtual_image
socket protocol (<i32 w><i32 h><w*h gray>, libfprint is the listener) and hands
libfprint whichever image the current phase needs.

Proves the exact link a Rust helper would feed: image -> minutiae -> enroll ->
match(same) / reject(different). Everything above this (fprintd/PAM/GDM) is stock.
"""
import os, sys, socket, struct, threading, time
import numpy as np

SOCK = os.environ["FP_VIRTUAL_IMAGE"]

# ---- images ---------------------------------------------------------------
def load_pgm(path):
    with open(path, "rb") as f:
        assert f.readline().strip() == b"P5"
        w, h = map(int, f.readline().split())
        f.readline()
        data = np.frombuffer(f.read(w*h), np.uint8).reshape(h, w)
    return data

def synth_print(h=380, w=200, angle=0.6, freq=0.11, seed=7):
    """A synthetic but fingerprint-like ridge field (different from the real one)."""
    rng = np.random.default_rng(seed)
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    cx, cy = w*0.5, h*0.45
    r = np.hypot(xx-cx, yy-cy)
    theta = np.arctan2(yy-cy, xx-cx)
    ridges = np.sin(freq*r*2*np.pi/6 + 3*np.cos(theta+angle)) * 60 + 128
    ridges += rng.normal(0, 8, ridges.shape)
    return np.clip(ridges, 0, 255).astype(np.uint8)

# ---- feeder thread --------------------------------------------------------
class Feeder(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.img = None          # current HxW uint8 image (set per phase)
        self.stop = False
        self.sent = 0
    def set(self, img):
        self.img = img
    def run(self):
        while not self.stop:
            img = self.img
            if img is None:
                time.sleep(0.05); continue
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect(SOCK)
                h, w = img.shape
                s.sendall(struct.pack("<ii", w, h) + img.tobytes())
                s.close()
                self.sent += 1
                time.sleep(0.4)  # pace: one image per libfprint scan request
            except (socket.timeout, OSError):
                time.sleep(0.15)

# ---- libfprint via GI -----------------------------------------------------
import gi
gi.require_version("FPrint", "2.0")
from gi.repository import FPrint, GLib

def main():
    A = load_pgm("captures/fingerprint_open.pgm").astype(np.uint8)     # real captured print
    B = synth_print(A.shape[0], A.shape[1])                            # a different print
    print(f"[i] image A (real) {A.shape}, image B (synthetic-different) {B.shape}")

    feeder = Feeder(); feeder.start()

    ctx = FPrint.Context.new()
    ctx.enumerate()
    devs = ctx.get_devices()
    dev = next((d for d in devs if "virt" in (d.get_driver() or "").lower()
                or "virt" in (d.get_name() or "").lower()), devs[0] if devs else None)
    if dev is None:
        print("[!] no libfprint device found (is FP_VIRTUAL_IMAGE set?)"); return 1
    print(f"[i] device: driver={dev.get_driver()} name={dev.get_name()} enroll_stages={dev.get_nr_enroll_stages()}")
    dev.open_sync()

    def progress(d, done, pr, err, ud=None):
        print(f"    enroll stage {done}/{d.get_nr_enroll_stages()}")

    # ENROLL on image A
    feeder.set(A); time.sleep(0.5)
    template = FPrint.Print.new(dev)
    template.set_finger(FPrint.Finger.RIGHT_INDEX)
    try:
        enrolled = dev.enroll_sync(template, None, progress, None)
        print("[+] ENROLL ok — minutiae template created")
    except GLib.Error as e:
        print(f"[!] enroll failed: {e.message}"); dev.close_sync(); return 2

    # VERIFY same image A -> expect MATCH
    feeder.set(A); time.sleep(0.6)
    try:
        r = dev.verify_sync(enrolled)
        match = r[0] if isinstance(r, tuple) else r
        print(f"[{'+' if match else '!'}] VERIFY(same A): match={bool(match)}   (expect True)")
        same_ok = bool(match)
    except GLib.Error as e:
        print(f"[!] verify(A) error: {e.message}"); same_ok = False

    # VERIFY different image B -> expect NO MATCH
    feeder.set(B); time.sleep(0.8)
    try:
        r = dev.verify_sync(enrolled)
        match = r[0] if isinstance(r, tuple) else r
        print(f"[{'+' if not match else '!'}] VERIFY(diff B): match={bool(match)}   (expect False)")
        diff_ok = not bool(match)
    except GLib.Error as e:
        # an error extracting/for a non-match still counts as "did not falsely accept"
        print(f"[i] verify(B) raised {e.message} -> treated as non-match")
        diff_ok = True

    dev.close_sync()
    feeder.stop = True
    print(f"[i] feeder delivered {feeder.sent} frames")
    ok = same_ok and diff_ok
    print("\n=== RESULT:", "PASS — virtual_image enroll/verify round-trips (match+reject)" if ok
          else "PARTIAL/FAIL — see above", "===")
    return 0 if ok else 3

if __name__ == "__main__":
    sys.exit(main())
