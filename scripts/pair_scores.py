#!/usr/bin/env python3
"""Pairwise bozorth3 scores through libfprint's virtual_image (offline; no
sensor, no fprintd/PAM/system change).

Usage:  python3 scripts/pair_scores.py <same-finger.pgm>... [-- <impostor.pgm>...]

Each same-finger image is enrolled on its own; every other image is verified
against it and libfprint's score printed (match >= 40), with a summary line.
Use it to compare reconstruction changes: more signal than a match/no-match
count. Lacking a second finger, mirrored copies of the prints make usable
impostors. Feed it `vfs495 decode --feed` outputs.
"""
import os, re, subprocess, sys
if os.environ.get("VFS_CHILD") != "1":
    env = dict(os.environ, VFS_CHILD="1", G_MESSAGES_DEBUG="all")
    ch = subprocess.Popen([sys.executable, __file__] + sys.argv[1:], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    sc = []; rows = {}; cur = None
    for line in ch.stdout:
        m = re.search(r"score (\d+)/\d+", line)
        if m: sc.append(int(m.group(1)))
        elif line.startswith("@t "): cur = line[3:].strip(); rows[cur] = {}; sc = []
        elif line.startswith("@v "):
            k, n = line[3:].split(); rows[cur][(k, n)] = sc[0] if sc else -1; sc = []
    ch.wait()
    gen = []; imp = []
    for t, r in rows.items():
        g = [v for (k, n), v in r.items() if k == 'g']; i = [v for (k, n), v in r.items() if k == 'i']
        gen += g; imp += i
        print(f"{t:>14}: genuine {g}  impostor {i}")
    import statistics as st
    gs = sorted(gen)
    print(f"GENUINE n={len(gen)} >=40: {sum(v>=40 for v in gen)}  >=25: {sum(v>=25 for v in gen)}  median {st.median(gen)}  mean {st.mean(gen):.1f}  min {gs[0]} | IMPOSTOR max {max(imp) if imp else None} mean {st.mean(imp) if imp else 0:.1f}")
    sys.exit(0)
import signal, socket, struct, tempfile, threading, time
import numpy as np
signal.signal(signal.SIGINT, signal.SIG_DFL)
SOCK = os.path.join(tempfile.mkdtemp(prefix="vfs_pairs_"), "v.sock"); os.environ["FP_VIRTUAL_IMAGE"] = SOCK
def load(path):
    with open(path, "rb") as f:
        assert f.readline().strip() == b"P5"; w, h = map(int, f.readline().split()); f.readline()
        return np.frombuffer(f.read(w * h), np.uint8).reshape(h, w)
args = sys.argv[1:]; sp = args.index("--") if "--" in args else len(args)
gen = [(os.path.basename(p), load(p)) for p in args[:sp]]; imp = [(os.path.basename(p), load(p)) for p in args[sp + 1:]]
cur = {"img": None}
def feeder():
    while True:
        img = cur["img"]
        if img is None: time.sleep(0.02); continue
        try:
            s = socket.socket(socket.AF_UNIX); s.settimeout(1); s.connect(SOCK)
            h, w = img.shape; s.sendall(struct.pack("<ii", w, h) + img.tobytes()); s.close(); time.sleep(0.15)
        except OSError: time.sleep(0.05)
threading.Thread(target=feeder, daemon=True).start()
import gi; gi.require_version("FPrint", "2.0"); from gi.repository import FPrint, GLib
ctx = FPrint.Context.new(); ctx.enumerate()
dev = next(d for d in ctx.get_devices() if d.get_driver() == "virtual_image"); dev.open_sync()
for ti, (tn, timg) in enumerate(gen):
    cur["img"] = timg; time.sleep(0.3)
    t = FPrint.Print.new(dev); t.set_finger(FPrint.Finger.RIGHT_INDEX)
    try: t = dev.enroll_sync(t, None, None, None)
    except GLib.Error as e: print(f"@t {tn}", flush=True); continue
    print(f"@t {tn}", flush=True)
    for kind, lst in (('g', [g for j, g in enumerate(gen) if j != ti]), ('i', imp)):
        for n, img in lst:
            cur["img"] = None; time.sleep(0.25); cur["img"] = img; time.sleep(0.3)
            try: dev.verify_sync(t)
            except GLib.Error as e: pass
            print(f"@v {kind} {n}", flush=True)
dev.close_sync()
