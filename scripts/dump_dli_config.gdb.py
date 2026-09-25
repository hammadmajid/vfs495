# Dump the full DLI unpack config for the open decoder, from HP's UnpackLineRT.
#
# UnpackLineRT(src=rdi, esi, dst=rdx, cfg=rcx, r8d) — see src/image.rs for the
# reversed semantics. The config layout we need:
#   cfg[0]      u32   mode (4, 8, or general)
#   cfg[4]      u32   width (output pixels per line)
#   cfg[8..]    u8[width]   per-column bit widths (general path)
#   cfg[0x57c]  i16[width]  column descramble permutation
#   max_bits  = (src[6] & 0x0f)   (clamp for the general path)
#
# Writes captures/dli_config.json so `vfs495 decode` can unpack raw EP2 lines in
# open code with no HP binary at capture time. Run one finger swipe when prompted.
#
# Usage:  cd vfs495 && ./scripts/build_harness.sh   # builds vendor/runtime
#         gdb -x scripts/dump_dli_config.gdb.py --args vendor/runtime/bin/validity-sensor-unlocked getprintwait -doinit
import gdb, os, json, struct

OUT = os.environ.get("VFS_DLI", "/home/bine/Developer/lab/vfs495/captures/dli_config.json")
state = {"done": False}

class Unpack(gdb.Breakpoint):
    def stop(self):
        if state["done"]:
            return False
        f = gdb.selected_frame()
        src = int(f.read_register("rdi")) & (2**64 - 1)
        cfg = int(f.read_register("rcx")) & (2**64 - 1)
        if not src or not cfg:
            return False
        inf = gdb.selected_inferior()
        mode = struct.unpack("<I", bytes(inf.read_memory(cfg + 0, 4)))[0]
        width = struct.unpack("<I", bytes(inf.read_memory(cfg + 4, 4)))[0]
        if not (0 < width <= 4096):
            return False
        max_bits = bytes(inf.read_memory(src + 6, 1))[0] & 0x0F
        bits = list(bytes(inf.read_memory(cfg + 8, width)))
        perm_raw = bytes(inf.read_memory(cfg + 0x57C, width * 2))
        perm = list(struct.unpack("<%dh" % width, perm_raw))
        json.dump(
            {"mode": mode, "width": width, "max_bits": max_bits, "bits": bits, "perm": perm},
            open(OUT, "w"),
        )
        print("[dump_dli_config] mode=%d width=%d max_bits=%d -> %s" % (mode, width, max_bits, OUT))
        state["done"] = True
        return False

Unpack("*0x46f510")
gdb.execute("run")
gdb.execute("quit")
