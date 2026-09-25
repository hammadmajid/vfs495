# Dump the sensor RSA public key used in the live handshake (unowned sensor).
import gdb, json, os
OUT = os.environ.get("VFS_OUT", "/home/bine/Developer/lab/vfs495/captures/modulus.json")
d = {}
def rd(a, n): return bytes(gdb.selected_inferior().read_memory(a, n))
def ptr(a): return int.from_bytes(rd(a, 8), "little")

class KEY(gdb.Breakpoint):
    # palCryptoRsaCreatePrivateKeyHandle won't fire (no priv on unowned).
    # Hook scsSSLRsaPublicEncrypt(ctx=rdi): key struct ptr at ctx+0x11c -> {size,exp,mod[256]}
    def stop(self):
        f = gdb.selected_frame()
        ctx = int(f.read_register("rdi")) & (2**64-1)
        try:
            kp = ptr(ctx + 0x11c)
            if kp:
                size = int.from_bytes(rd(kp, 4), "little")
                exp = int.from_bytes(rd(kp + 4, 4), "little")
                d["key_size_bits"] = size
                d["exp"] = exp
                d["modulus"] = rd(kp + 8, 256).hex()
            else:
                d["note"] = "ctx+0x11c is NULL"
                # fall back: scan nothing
        except Exception as e:
            d["err"] = str(e)
        json.dump(d, open(OUT, "w"), indent=1)
        print("MODULUS:", d.get("key_size_bits"), hex(d.get("exp",0)), (d.get("modulus","")[:32]+"..."))
        return True

KEY("*0x5161c0")
gdb.execute("run get_ownership_info -doinit")
gdb.execute("quit")
