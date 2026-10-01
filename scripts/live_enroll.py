#!/usr/bin/env python3
"""LIVE end-to-end: real `vfs495` capture -> virtual_image socket -> libfprint
enroll + verify, driven by real finger touches, ONE capture per stage with loud
on-screen cues. Drives libfprint directly via GI (the layer fprintd sits on); no
fprintd/PAM/system change.

Run from the repo root (the sensor must be accessible, e.g. udev uaccess rule
installed):  python3 scripts/live_enroll.py

Status 2026-09-28: BLOCKED upstream by finger detection, not by this harness. The
ridge gate's no-finger baseline drifts (~1.2 fresh -> ~1.8 used) into the finger
range (~2.1), so captures may mis-gate until closed-loop calibration (C-full) is
implemented. See docs/STATUS.md. This harness is ready for when detection is fixed.
Each stage: press+hold ~25s on the PRESS banner; lift on the LIFT banner; 5 stages
+ 1 verify, same finger.
"""
import os, sys, subprocess, threading, time, tempfile

SOCK = os.path.join(tempfile.mkdtemp(prefix="vfs_live_"), f"vimg_{os.getpid()}.sock")
os.environ["FP_VIRTUAL_IMAGE"] = SOCK
os.environ.setdefault("VFS_NO_PROMPT", "1")

def banner(lines):
    w = 60
    print("\n" + "#" * w)
    for ln in lines:
        print("#" + ln.center(w - 2) + "#")
    print("#" * w + "\n", flush=True)

def wait_for_device(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(["lsusb", "-d", "138a:003f"], capture_output=True)
        if r.returncode == 0 and r.stdout.strip():
            return True
        print("    ...waiting for sensor on USB...", flush=True); time.sleep(1.5)
    return False

def one_capture():
    if not wait_for_device():
        print("    [sensor not on bus]", flush=True); return False
    env = {**os.environ, "RUST_LOG": "info", "VFS_NO_PROMPT": "1"}
    try:
        p = subprocess.run(["./target/release/vfs495", "run", "--socket", SOCK],
                           env=env, timeout=90, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        print("    [capture timed out]", flush=True); return False
    out = (p.stdout or "") + (p.stderr or "")
    for ln in out.splitlines():
        if any(k in ln for k in ("finger captured", "ridge_peak", "fed ", "WARN",
                                 "Error", "not found", "too few")):
            print("    " + ln.strip(), flush=True)
    return "fed " in out and "image" in out

import gi
gi.require_version("FPrint", "2.0")
from gi.repository import FPrint, GLib

def main():
    ctx = FPrint.Context.new(); ctx.enumerate()
    dev = next((d for d in ctx.get_devices() if (d.get_driver() or "") == "virtual_image"), None)
    if dev is None:
        print("[!] no libfprint virtual_image device"); return 1
    dev.open_sync()
    stages = dev.get_nr_enroll_stages()
    print(f"[i] libfprint open: driver={dev.get_driver()} enroll_stages={stages}")

    stage_event = threading.Event()
    state = {"done": 0, "enroll_finished": False}

    def progress(d, done, pr, err, ud=None):
        state["done"] = done
        print(f"\n    >>> ENROLL STAGE {done}/{stages} ACCEPTED <<<\n", flush=True)
        stage_event.set()

    def feeder():
        attempts = 0
        while not state["enroll_finished"] and attempts < stages * 3:
            target = state["done"] + 1
            if target > stages:
                break
            banner([f"SWIPE YOUR FINGER NOW (slowly, downward, 1-2 s)", f"STAGE {target} OF {stages}",
                    "SWIPE AGAIN ~3 s LATER; DO NOT HOLD STILL"])
            if not one_capture():
                banner(["CAPTURE MISSED — wait for the next SWIPE prompt"])
                attempts += 1; time.sleep(6); continue
            if stage_event.wait(timeout=20):
                stage_event.clear(); banner(["DONE — wait for the next SWIPE prompt"]); time.sleep(5.0)
            attempts += 1

    banner(["LIVE ENROLL — follow the big prompts, same finger"])
    time.sleep(1.0)
    ft = threading.Thread(target=feeder, daemon=True); ft.start()
    try:
        tmpl = FPrint.Print.new(dev); tmpl.set_finger(FPrint.Finger.RIGHT_INDEX)
        enrolled = dev.enroll_sync(tmpl, None, progress, None)
        state["enroll_finished"] = True
        print("\n[+] ENROLL ok — template from LIVE captures", flush=True)
    except GLib.Error as e:
        state["enroll_finished"] = True
        print(f"\n[!] ENROLL FAILED: {e.message}"); dev.close_sync(); return 2
    ft.join(timeout=5)

    banner(["ENROLL DONE! NOW VERIFY", "SWIPE THE SAME FINGER (slowly, downward)"])
    vdone = {"v": False}
    def vfeeder():
        for _ in range(3):
            if vdone["v"]:
                return
            if one_capture():
                return
            banner(["VERIFY CAPTURE MISSED — swipe again, slowly"]); time.sleep(2)
    threading.Thread(target=vfeeder, daemon=True).start()
    ok = False
    try:
        r = dev.verify_sync(enrolled); vdone["v"] = True
        ok = bool(r[0] if isinstance(r, tuple) else r)
        print(f"\n[{'+' if ok else '!'}] VERIFY: match={ok} (expect True)")
    except GLib.Error as e:
        vdone["v"] = True; print(f"\n[!] verify error: {e.message}")
    dev.close_sync()
    banner(["RESULT: PASS — LIVE ENROLL+VERIFY WORKS" if ok else "RESULT: FAIL/INCOMPLETE"])
    return 0 if ok else 3

if __name__ == "__main__":
    sys.exit(main())
