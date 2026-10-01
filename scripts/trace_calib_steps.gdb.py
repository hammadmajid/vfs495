# Map HP's closed-loop AFE calibration step -> result, with ground-truth frames.
# Logs, in order: each scsSensorGetCountedLinesSynch (buffer, length), each step
# function entry (CommDet/PgaOffset/Adc/PgaGain/AspLna1/AspPga1/Woe) — at which
# point the just-read sweep frame is dumped to captures/calib_frames/NN_<step>.bin —
# and every calResultsSetByte/SetWord (tag, idx, value) the step writes.
#
# Run (root for libusb-0.1; no finger; safe verb, no ownership write):
#   cd vfs495 && sudo env LD_LIBRARY_PATH="$PWD/vendor/runtime/lib" \
#     gdb -batch -x scripts/trace_calib_steps.gdb.py \
#     --args vendor/runtime/bin/validity-sensor-unlocked get_ownership_info -doinit
import gdb, os

BASE = os.environ.get("VFS_BASE", "/home/bine/Developer/lab/vfs495")
RUN = os.environ.get("VFS_RUN", "")  # optional run tag -> separate output set
OUT = os.path.join(BASE, f"captures/calib_trace_steps{RUN}.txt")
FR = os.path.join(BASE, "captures/calib_frames" + (f"/run{RUN}" if RUN else ""))
os.makedirs(FR, exist_ok=True)
log = open(OUT, "w")

STEPS = {
    0x50e610: "CommDet", 0x50e010: "PgaOffset", 0x50d9e0: "Adc",
    0x50d110: "PgaGain", 0x50f970: "AspLna1", 0x510030: "AspPga1",
    0x510610: "Woe",
}
COUNTED = 0x4ece20
SETBYTE, SETWORD, SETFLAG = 0x5029b0, 0x502a00, 0x502860
state = {"buf": 0, "len": 0, "n": 0}

def reg(r):
    return int(gdb.selected_frame().read_register(r)) & (2**64 - 1)

def w(s):
    log.write(s + "\n"); log.flush()

class Counted(gdb.Breakpoint):
    def stop(self):
        state["buf"], state["len"] = reg("rsi"), reg("rdx") & 0xffffffff
        w(f"[read] buf={state['buf']:#x} len={state['len']}")
        return False

class Step(gdb.Breakpoint):
    def __init__(self, addr, name):
        super().__init__(f"*{addr}")
        self.name = name
    def stop(self):
        state["n"] += 1
        fn = os.path.join(FR, f"{state['n']:02d}_{self.name}.bin")
        try:
            data = bytes(gdb.selected_inferior().read_memory(state["buf"], state["len"]))
            open(fn, "wb").write(data)
        except Exception as e:
            fn = f"(dump failed: {e})"
        w(f"[step {state['n']:02d}] {self.name} frame={fn}")
        return False

class Set(gdb.Breakpoint):
    def __init__(self, addr, kind):
        super().__init__(f"*{addr}")
        self.kind = kind
    def stop(self):
        tag, idx = reg("rsi") & 0xffffffff, reg("rdx") & 0xffffffff
        val = reg("rcx") & (0xff if self.kind == "byte" else 0xffff if self.kind == "word" else 0xffffffff)
        w(f"    set{self.kind} tag={tag:#x} idx={idx} val={val} ({val:#x})")
        return False

Counted(f"*{COUNTED}")
for a, n in STEPS.items():
    Step(a, n)
Set(SETBYTE, "byte"); Set(SETWORD, "word"); Set(SETFLAG, "flag")
gdb.execute("run")
w("=== DONE ===")
log.close()
gdb.execute("quit")
