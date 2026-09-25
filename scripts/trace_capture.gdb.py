# Trace HP getprintwait: dump every PLAINTEXT command sent via scsSend (0x4f7bd0)
# so we learn the exact capture command 0x02 + its config blob to replay in open code.
# ep2 image is captured separately by the LD_PRELOAD usblog. One finger swipe needed.
import gdb, os
OUT = os.environ.get("VFS_CMDS", "/home/bine/Developer/lab/vfs495/captures/plaintext_cmds.txt")
open(OUT, "w").close()

class Send(gdb.Breakpoint):
    # scsSend(dev, data=rsi, len=rdx, ...)
    def stop(self):
        f = gdb.selected_frame()
        data = int(f.read_register("rsi")) & (2**64-1)
        n = int(f.read_register("rdx")) & 0xffffffff
        if 0 < n <= 8192:
            b = bytes(gdb.selected_inferior().read_memory(data, n))
            with open(OUT, "a") as fh:
                fh.write(f"{b[0]:02x} len={n} {b.hex()}\n")
        return False

Send("*0x4f7bd0")
gdb.execute("run getprintwait -doinit")
gdb.execute("quit")
