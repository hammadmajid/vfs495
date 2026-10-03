#!/usr/bin/env python3
"""Offline leave-one-out genuine-match test through libfprint's virtual_image
(no sensor, no fprintd/PAM/system change).

Usage:  python3 scripts/loo_match.py <same-finger.pgm>... [-- <other-finger.pgm>...]

For each same-finger image: enroll the others (repeated to fill the 5 stages),
then verify the held-out one (genuine), every other-finger image (impostor) and
one enrolled image (control), printing libfprint's bozorth3 scores (match >= 40).
Feed it images as the driver would send them:
    vfs495 decode --feed --input swipe.stream --out swipe.pgm

Requires python3-gobject, numpy and libfprint with the virtual_image driver.
"""
import os, re, subprocess, sys

if os.environ.get("VFS_LOO_CHILD") != "1":
    env = dict(os.environ, VFS_LOO_CHILD="1", G_MESSAGES_DEBUG="all")
    child = subprocess.Popen([sys.executable, __file__] + sys.argv[1:], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    scores = []
    for line in child.stdout:
        m = re.search(r"score (\d+)/\d+", line)
        if m:
            scores.append(int(m.group(1)))
        elif line.startswith("@verify "):
            print(f"  {line[8:].strip():<40} scores {scores}", flush=True)
            scores = []
        elif line.startswith("@"):
            print(line[1:].rstrip(), flush=True)
            scores = []
    sys.exit(child.wait())

import signal, socket, struct, tempfile, threading, time
import numpy as np

signal.signal(signal.SIGINT, signal.SIG_DFL)
SOCK = os.path.join(tempfile.mkdtemp(prefix="vfs_loo_"), "v.sock")
os.environ["FP_VIRTUAL_IMAGE"] = SOCK

def load_pgm(path):
    with open(path, "rb") as f:
        assert f.readline().strip() == b"P5", "not a P5 PGM"
        w, h = map(int, f.readline().split())
        f.readline()
        return np.frombuffer(f.read(w * h), np.uint8).reshape(h, w)

args = sys.argv[1:]
split = args.index("--") if "--" in args else len(args)
genuine = [(os.path.basename(p), load_pgm(p)) for p in args[:split]]
impostors = [(os.path.basename(p), load_pgm(p)) for p in args[split + 1:]]
if len(genuine) < 2:
    sys.exit(__doc__)

current = {"img": None}
def feeder():
    while True:
        img = current["img"]
        if img is None:
            time.sleep(0.05); continue
        try:
            s = socket.socket(socket.AF_UNIX); s.settimeout(1); s.connect(SOCK)
            h, w = img.shape
            s.sendall(struct.pack("<ii", w, h) + img.tobytes()); s.close(); time.sleep(0.4)
        except OSError:
            time.sleep(0.1)
threading.Thread(target=feeder, daemon=True).start()

import gi
gi.require_version("FPrint", "2.0")
from gi.repository import FPrint, GLib

ctx = FPrint.Context.new(); ctx.enumerate()
dev = next(d for d in ctx.get_devices() if d.get_driver() == "virtual_image")
dev.open_sync()

def verify(label, template, img):
    current["img"] = img; time.sleep(0.6)
    try:
        r = dev.verify_sync(template)
        result = bool(r[0] if isinstance(r, tuple) else r)
    except GLib.Error as e:
        result = f"error: {e.message}"
    print(f"@verify {label}: match={result}", flush=True)

for hold, (name, img) in enumerate(genuine):
    enroll = [im for i, (_, im) in enumerate(genuine) if i != hold]
    queue = [enroll[i % len(enroll)] for i in range(5)]
    current["img"] = queue.pop(0)
    def progress(d, done, pr, *rest):
        if queue:
            current["img"] = queue.pop(0)
    template = FPrint.Print.new(dev); template.set_finger(FPrint.Finger.RIGHT_INDEX)
    try:
        template = dev.enroll_sync(template, None, progress, None)
    except GLib.Error as e:
        print(f"@held-out {name}: enroll failed ({e.message})", flush=True); continue
    print(f"@held-out {name}:", flush=True)
    verify("genuine", template, img)
    for iname, iimg in impostors:
        verify(f"impostor {iname}", template, iimg)
    verify("control (enrolled image)", template, enroll[0])
dev.close_sync()
