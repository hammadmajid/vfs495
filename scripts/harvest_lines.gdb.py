# Harvest the DESCRAMBLED 264-wide scan lines from HP's UnpackLineRT output (RDX),
# to prove end-to-end capture produces a real fingerprint. (HP does the assembly here;
# porting irDliRTFalconData/UnpackLineRT to open code is the remaining decode work.)
import gdb, os, struct
OUT = os.environ.get("VFS_LINES", "/home/bine/Developer/lab/vfs495/captures/lines.raw")
open(OUT, "wb").close()
state = {"prev": None}

class Unpack(gdb.Breakpoint):
    # UnpackLineRT(line=rdi, ?, out=rdx, cfg=rcx); width = *(int*)(cfg+4)
    def stop(self):
        f = gdb.selected_frame()
        out = int(f.read_register("rdx")) & (2**64-1)
        cfg = int(f.read_register("rcx")) & (2**64-1)
        try:
            width = int.from_bytes(bytes(gdb.selected_inferior().read_memory(cfg + 4, 4)), "little")
        except Exception:
            return False
        # one-behind: dump the PREVIOUS call's output (fully written by now)
        p = state["prev"]
        if p is not None:
            po, pw = p
            try:
                data = bytes(gdb.selected_inferior().read_memory(po, pw))
                with open(OUT, "ab") as fh:
                    fh.write(struct.pack("<H", pw) + data)
            except Exception:
                pass
        state["prev"] = (out, width)
        return False

Unpack("*0x46f510")
gdb.execute("run getprintwait -doinit")
gdb.execute("quit")
