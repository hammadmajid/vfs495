# gdb -x this against the unlocked HP binary running get_ownership_info -doinit.
# Dumps the SSL secrets incl. s_key (ctx+0x148) to see what the UNOWNED sensor
# session uses. Read-only w.r.t. the sensor (dumps host memory only).
import gdb, json, os
OUT = os.environ.get("VFS_OUT", "/home/bine/Developer/lab/vfs495/captures/skey_dump.json")
d = {}
def rd(a, n):
    return bytes(gdb.selected_inferior().read_memory(a, n))
def ptr(a):
    return int.from_bytes(rd(a, 8), "little")

class MSG(gdb.Breakpoint):
    # scsSSLMasterSecretGenerate(ctx=rdi, premaster=rsi)
    def stop(self):
        f = gdb.selected_frame()
        ctx = int(f.read_register("rdi")) & (2**64-1)
        pre = int(f.read_register("rsi")) & (2**64-1)
        try:
            d["premaster"] = rd(pre, 48).hex()
            d["s_key_ctx148"] = rd(ctx + 0x148, 32).hex()
            d["client_random"] = rd(ptr(ctx + 0x38), 32).hex()
            d["server_random"] = rd(ptr(ctx + 0x40), 32).hex()
            d["ctx"] = hex(ctx)
        except Exception as e:
            d["err_msg"] = str(e)
        return False

class CKE(gdb.Breakpoint):
    # scsSSLClientKeyExchangeWrite: at entry dump s_key via r12 later; grab at 0x513fa7 instead
    def stop(self):
        f = gdb.selected_frame()
        r12 = int(f.read_register("r12")) & (2**64-1)
        try:
            d["s_key_r12_148"] = rd(r12 + 0x148, 32).hex()
        except Exception as e:
            d["err_cke"] = str(e)
        return False

class RSAENC(gdb.Breakpoint):
    # scsSSLRsaPublicEncrypt(ctx=rdi, premaster_in=rsi): master/keyblock now filled
    def stop(self):
        f = gdb.selected_frame()
        ctx = int(f.read_register("rdi")) & (2**64-1)
        rsi = int(f.read_register("rsi")) & (2**64-1)
        try:
            d["master"] = rd(ctx + 8, 48).hex()
            d["keyblock"] = rd(ctx + 0x48, 136).hex()
            d["cke_input_after_aeswrap"] = rd(rsi, 48).hex()
        except Exception as e:
            d["err_rsa"] = str(e)
        json.dump(d, open(OUT, "w"), indent=1)
        print("SKEY DUMP:", {k: (v[:24]+"..." if isinstance(v,str) and len(v)>24 else v) for k,v in d.items()})
        return True

MSG("*0x5139c0")
CKE("*0x513fa7")   # right at `mov 0x148(%r12),%r8`
RSAENC("*0x5161c0")
gdb.execute("run get_ownership_info -doinit")
gdb.execute("quit")
