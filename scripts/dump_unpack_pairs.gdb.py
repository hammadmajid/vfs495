# Dump real UnpackLineRT input->output pairs to prove the open unpack byte-exact.
#
# For each call: record <u16 width><input: 8-byte hdr + width bytes><output: width bytes>.
# input  = raw packed line from ep2 (rdi, +8 = pixel payload)
# output = HP's descrambled line (rdx, +8 = pixels)  [dumped one call behind, so it's fully written]
# We then verify in open code that unpack(input) == output.
#
# Usage: cd vfs495 && sudo env LD_LIBRARY_PATH="$PWD/vendor/runtime/lib" \
#   gdb -q -batch -x scripts/dump_unpack_pairs.gdb.py \
#   --args vendor/runtime/bin/validity-sensor-unlocked getprintwait -doinit
import gdb, os, struct

OUT = os.environ.get("VFS_PAIRS", "/home/bine/Developer/lab/vfs495/captures/unpack_pairs.bin")
open(OUT, "wb").close()
state = {"prev": None}

class Unpack(gdb.Breakpoint):
    def stop(self):
        f = gdb.selected_frame()
        src = int(f.read_register("rdi")) & (2**64 - 1)
        dst = int(f.read_register("rdx")) & (2**64 - 1)
        cfg = int(f.read_register("rcx")) & (2**64 - 1)
        if not (src and dst and cfg):
            return False
        inf = gdb.selected_inferior()
        try:
            width = struct.unpack("<I", bytes(inf.read_memory(cfg + 4, 4)))[0]
        except Exception:
            return False
        if not (0 < width <= 4096):
            return False
        # dump PREVIOUS call's fully-written output alongside its input
        p = state["prev"]
        if p is not None:
            ps, pd, pw = p
            try:
                inp = bytes(inf.read_memory(ps, 8 + pw))   # header + payload
                out = bytes(inf.read_memory(pd + 8, pw))   # descrambled pixels
                with open(OUT, "ab") as fh:
                    fh.write(struct.pack("<H", pw) + inp + out)
            except Exception:
                pass
        state["prev"] = (src, dst, width)
        return False

Unpack("*0x46f510")
gdb.execute("run")
gdb.execute("quit")
