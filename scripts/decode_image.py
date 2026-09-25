#!/usr/bin/env python3
"""Open decode of a VFS495 raw ep2 DLI stream -> fingerprint PGM.

No HP code. Frame format (RE'd, confirmed on our capture):
  01 fe <seq:u16 LE> <f4> <f5> <width:u8> 00  then <width> pixel bytes (8-bit direct).
Main image = width 0xc8 (200). Column descramble for the main image is perm[0:200] = 199..0,
i.e. reverse each line (from vfs495-linux driver/vfs495_descramble.inc). Reconstruction
(fixed-pattern removal + ridge bandpass + motion segmentation) follows vfs495-linux/reconstruct.py.

Usage: .venv/bin/python scripts/decode_image.py captures/capture_swipe.usblog out.pgm
"""
import sys, re
import numpy as np
from scipy.ndimage import gaussian_filter, gaussian_filter1d

def load_ep2(path):
    reads = []
    for ln in open(path, errors="ignore"):
        p = ln.split()
        if len(p) >= 4 and p[0] == "R" and p[1] == "ep=0x02":
            try: reads.append(bytes.fromhex(p[3]))
            except ValueError: pass
    return b"".join(reads)

def parse_frames(buf, payload=200, stride=208):
    """Frames are FIXED size (8-byte header + 200 pixels = 208), delimited by 01fe.
    The width byte in the header is NOT the frame length (prior art's drift trap).
    Find the longest run of 01fe markers spaced `stride` apart; extract & descramble
    (main-image descramble = reverse each line)."""
    n = len(buf)
    marks = [m.start() for m in re.finditer(b"\x01\xfe", buf)]
    # longest contiguous run with gap==stride
    best_run, cur = [], []
    for k in range(len(marks)):
        if cur and marks[k] - cur[-1] == stride:
            cur.append(marks[k])
        else:
            if len(cur) > len(best_run): best_run = cur
            cur = [marks[k]]
    if len(cur) > len(best_run): best_run = cur
    lines = []
    for p in best_run:
        body = p + 8
        if body + payload <= n:
            lines.append(np.frombuffer(buf[body:body+payload], np.uint8)[::-1].astype(np.float32))
    return np.array(lines) if lines else np.zeros((0, payload), np.float32)

def preprocess(img):
    res = img - img.mean(0, keepdims=True)
    res = res - gaussian_filter(res, sigma=(0, 4))
    return res

def finger_energy(res):
    return gaussian_filter1d(np.abs(res).mean(1), 8)

def best_segment(energy, bridge=100):
    if len(energy) == 0: return 0, 0
    thr = np.median(energy) + 0.35 * (energy.max() - np.median(energy))
    on = energy > thr
    best = (0, 0); i = 0; N = len(on)
    while i < N:
        if not on[i]: i += 1; continue
        j = i
        while j < N:
            if on[j]: j += 1
            else:
                k = j
                while k < N and not on[k] and k - j < bridge: k += 1
                if k < N and on[k]: j = k
                else: break
        if j - i > best[1] - best[0]: best = (i, j)
        i = j + 1
    return best

def normalize(res):
    m = res - gaussian_filter(res, sigma=(8, 8))
    s = gaussian_filter(np.abs(m), sigma=(8, 8)) + 1e-3
    out = np.clip(m / s * 48 + 128, 0, 255)
    return out.astype(np.uint8)

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "captures/capture_swipe.usblog"
    out = sys.argv[2] if len(sys.argv) > 2 else "captures/open_fingerprint.pgm"
    buf = load_ep2(src)
    print(f"ep2 bytes: {len(buf)}")
    img = parse_frames(buf)
    print(f"main-image lines parsed: {img.shape}")
    if img.shape[0] < 20:
        print("too few lines; not a usable swipe"); return 1
    res = preprocess(img)
    energy = finger_energy(res)
    a, b = best_segment(energy)
    print(f"finger-present segment: rows {a}..{b} ({b-a} lines)")
    seg = res[a:b] if b > a else res
    pgm = normalize(seg)
    # write PGM
    h, w = pgm.shape
    with open(out, "wb") as f:
        f.write(f"P5\n{w} {h}\n255\n".encode())
        f.write(pgm.tobytes())
    print(f"wrote {out} ({w}x{h})")
    # ridge sanity: horizontal autocorrelation peak in ridge band
    row = seg.mean(0)
    ac = np.correlate(row - row.mean(), row - row.mean(), "full")[len(row)-1:]
    band = ac[6:16]
    print(f"ridge-band autocorr peak (cols 6..15): {band.max():.1f} vs col1 {ac[1]:.1f}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
