#!/usr/bin/env python3
"""LIVE end-to-end: real `vfs495` captures -> virtual_image socket -> libfprint
enroll (5 stages) + verify, with real swipes. Drives libfprint directly via GI
(the layer fprintd sits on); no fprintd/PAM/system change, nothing persisted.

Run from the repo root in a normal terminal:  python3 scripts/live_enroll.py

The screen shows only colored cues, timed by the driver to the sensor's imaging
windows:  RED = don't touch,  GREEN = swipe (slowly, downward, 1-2 s),
YELLOW = wait.  After each round a short check/cross. Ctrl+C stops everything.
"""
import os, signal, subprocess, sys, tempfile, threading, time

# libfprint's *_sync calls block in C, where Python never runs its KeyboardInterrupt
# handler; the default action makes Ctrl+C kill this process (and the capture child,
# which shares the terminal's process group) immediately.
signal.signal(signal.SIGINT, signal.SIG_DFL)

RUN_DIR = tempfile.mkdtemp(prefix="vfs_live_")
SOCK = os.path.join(RUN_DIR, f"vimg_{os.getpid()}.sock")
os.environ["FP_VIRTUAL_IMAGE"] = SOCK
os.environ["VFS_SAVE_FED"] = RUN_DIR   # every fed image is kept here (biometric; local only)

RED, GREEN, YELLOW, DIM, RESET = "\x1b[1;30;41m", "\x1b[1;30;42m", "\x1b[1;30;43m", "\x1b[2m", "\x1b[0m"
CUES = {"DON'T TOUCH": (RED, "  DON'T TOUCH  "), "SWIPE": (GREEN, "  SWIPE  ↓  "),
        "WAIT": (YELLOW, "  WAIT  ")}

def say(color, text):
    print(f"{color}{text}{RESET}", flush=True)

def note(text):
    print(f"{DIM}{text}{RESET}", flush=True)

def wait_device(timeout=30):
    """Wait until the sensor has been on the bus for ~1 s. Starting a session
    right after the previous one ends makes it re-enumerate (drop off USB)."""
    seen, deadline = 0, time.time() + timeout
    while time.time() < deadline and seen < 3:
        on = subprocess.run(["lsusb", "-d", "138a:003f"], capture_output=True).stdout.strip()
        seen = seen + 1 if on else 0
        time.sleep(0.5)

def run_once():
    """One `vfs495 run`: relay its cues in color, hide everything else.
    Returns "ok" (swipe fed), "miss" (no finger / no swipe motion) or "device"."""
    time.sleep(3)
    wait_device()
    env = {**os.environ, "RUST_LOG": "error"}
    env.pop("VFS_NO_PROMPT", None)
    p = subprocess.Popen(["./target/release/vfs495", "run", "--socket", SOCK], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    err = ""
    for line in p.stderr:
        for key, (color, text) in CUES.items():
            if line.strip().startswith(key):
                say(color, text)
        if line.startswith("Error"):
            err = line
    p.wait()
    if p.returncode == 0:
        return "ok"
    return "miss" if ("no finger" in err or "did not swipe" in err) else "device"

def one_capture():
    """A capture the user can see: USB hiccups are retried silently."""
    for _ in range(5):
        r = run_once()
        if r != "device":
            return r == "ok"
    return False

import gi
gi.require_version("FPrint", "2.0")
from gi.repository import FPrint, GLib
# virtual_image logs a harmless warning each time our sender closes the socket.
GLib.log_set_handler("libfprint-virtual_image", GLib.LogLevelFlags.LEVEL_WARNING, lambda *a: None, None)

def main():
    ctx = FPrint.Context.new(); ctx.enumerate()
    dev = next((d for d in ctx.get_devices() if (d.get_driver() or "") == "virtual_image"), None)
    if dev is None:
        print("no libfprint virtual_image device"); return 1
    dev.open_sync()
    stages = dev.get_nr_enroll_stages()
    state = {"done": 0, "finished": False}
    accepted = threading.Event()

    def progress(d, done, pr, ud=None, err=None):
        state["done"] = done
        accepted.set()

    def feeder():
        tries = 0
        while not state["finished"] and state["done"] < stages and tries < stages * 3:
            note(f"\nround {state['done'] + 1}/{stages}")
            before = state["done"]
            if one_capture() and accepted.wait(timeout=20):
                accepted.clear()
            ok = state["done"] > before
            print(f"\x1b[32m✓ {state['done']}/{stages}\x1b[0m" if ok else "\x1b[31m✗ again\x1b[0m",
                  flush=True)
            tries += 1

    ft = threading.Thread(target=feeder, daemon=True); ft.start()
    try:
        tmpl = FPrint.Print.new(dev); tmpl.set_finger(FPrint.Finger.RIGHT_INDEX)
        enrolled = dev.enroll_sync(tmpl, None, progress, None)
    except GLib.Error as e:
        state["finished"] = True
        say(RED, f"  ENROLL FAILED: {e.message}  "); dev.close_sync(); return 2
    state["finished"] = True
    ft.join()   # never overlap a leftover enroll capture with the verify capture

    note("\nverify: same finger")
    done = {"v": False}
    def vfeeder():
        for _ in range(3):
            if done["v"] or one_capture():
                return
            print("\x1b[31m✗ again\x1b[0m", flush=True)
    threading.Thread(target=vfeeder, daemon=True).start()
    try:
        r = dev.verify_sync(enrolled)
        ok = bool(r[0] if isinstance(r, tuple) else r)
    except GLib.Error as e:
        ok = False; note(f"verify error: {e.message}")
    done["v"] = True
    dev.close_sync()
    say(GREEN if ok else RED, "  RESULT: PASS (match)  " if ok else "  RESULT: FAIL (no match)  ")
    note(f"images: {RUN_DIR}")
    return 0 if ok else 3

if __name__ == "__main__":
    sys.exit(main())
