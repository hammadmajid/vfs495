# Trace HP's closed-loop AFE calibration (scsSensorFalconCalibrate @0x4fcb20) to
# map the sweep: every scsSensorLoadPatch (register/patch write) and
# scsSensorGetCountedLinesSynch (frame read) call is logged with args, in order,
# so the measure->adjust loop per step (CommDet/PgaOffset/Adc/PgaGain/AspLna1/
# AspPga1/Woe) can be reconstructed and ported to open code.
#
# Run (needs root for libusb-0.1; no finger, no ownership write):
#   cd vfs495 && sudo env LD_LIBRARY_PATH="$PWD/vendor/runtime/lib" \
#     gdb -batch -x scripts/trace_calibration.gdb.py \
#     --args vendor/runtime/bin/validity-sensor-unlocked get_ownership_info -doinit
import gdb, os

OUT = os.environ.get("VFS_CALIB", "/home/bine/Developer/lab/vfs495/captures/calib_trace.txt")
open(OUT, "w").close()
log = open(OUT, "a")

CALIB = 0x4fcb20          # scsSensorFalconCalibrate
LOADPATCH = 0x4ea540      # scsSensorLoadPatch(dev, patch, len)
LOADPATCHEX = 0x4ea1e0    # scsSensorLoadPatchEx
COUNTED = 0x4ece20        # scsSensorGetCountedLinesSynch

state = {"in_calib": False, "patch": 0, "counted": 0}

def rd(f, reg):
    return int(f.read_register(reg)) & (2**64 - 1)

def mem(addr, n):
    try:
        return bytes(gdb.selected_inferior().read_memory(addr, n))
    except gdb.MemoryError:
        return b""

class Calib(gdb.Breakpoint):
    def stop(self):
        state["in_calib"] = True
        log.write("\n=== scsSensorFalconCalibrate ENTER ===\n"); log.flush()
        return False

class Ret(gdb.FinishBreakpoint):
    pass

class LoadPatch(gdb.Breakpoint):
    def stop(self):
        if not state["in_calib"]:
            return False
        f = gdb.selected_frame()
        dev, patch, ln = rd(f, "rdi"), rd(f, "rsi"), rd(f, "rdx") & 0xffffffff
        head = mem(patch, min(ln, 48)) if 0 < ln <= 4096 else b""
        state["patch"] += 1
        log.write(f"[LoadPatch #{state['patch']:03d}] len={ln} data={head.hex()}\n"); log.flush()
        return False

class Counted(gdb.Breakpoint):
    def stop(self):
        if not state["in_calib"]:
            return False
        f = gdb.selected_frame()
        a1, a2, a3 = rd(f, "rdi"), rd(f, "rsi") & 0xffffffff, rd(f, "rdx") & 0xffffffff
        state["counted"] += 1
        log.write(f"[Counted   #{state['counted']:03d}] rsi={a2} rdx={a3}\n"); log.flush()
        return False

Calib(f"*{CALIB}")
LoadPatch(f"*{LOADPATCH}")
LoadPatch(f"*{LOADPATCHEX}")
Counted(f"*{COUNTED}")

gdb.execute("run get_ownership_info -doinit")
log.write(f"\n=== DONE: {state['patch']} LoadPatch, {state['counted']} Counted calls in calibration ===\n")
log.flush(); log.close()
gdb.execute("quit")
