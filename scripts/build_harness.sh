#!/usr/bin/env bash
# Build a runnable harness around HP's validity-sensor for LIVE TRACING ONLY.
# Applies the prior-art 5-byte HOST-SIDE unlock patch (re-enables diagnostic CLI
# verbs in HP's binary; does NOT change sensor behaviour) and builds empty
# OpenSSL-0.9.8 stub libs (the binary does its crypto statically). Everything is
# written under vendor/ (gitignored). libusb-0.1.so.4 comes from the distro.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/vendor/rpm/usr/sbin/validity-sensor"
RT="$ROOT/vendor/runtime"
mkdir -p "$RT/bin" "$RT/lib"
python3 - "$SRC" "$RT/bin/validity-sensor-unlocked" <<'PY'
import sys,subprocess,re
src,dst=sys.argv[1],sys.argv[2]
d=bytearray(open(src,"rb").read())
secs=subprocess.check_output(["readelf","-S","-W",src]).decode()
def v2o(v):
    for line in secs.splitlines():
        m=re.search(r'\]\s+\S+\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)',line)
        if m:
            a=int(m.group(1),16);o=int(m.group(2),16);s=int(m.group(3),16)
            if a and a<=v<a+s: return o+(v-a)
off=v2o(0x44122d)
assert d[off:off+4]==bytes.fromhex("488b7b08"), d[off:off+4].hex()
# unconditional jmp 0x4412b4 (re-enable all diagnostic commands)
rel=(0x4412b4-(0x44122d+5))
d[off:off+5]=b"\xe9"+rel.to_bytes(4,"little",signed=True)
open(dst,"wb").write(d)
import os; os.chmod(dst,0o755)
print("patched ->",dst)
PY
printf 'void __vfs_stub(void){}\n' > "$RT/stub.c"
gcc -shared -fPIC -Wl,-soname,libssl.so.0.9.8    -o "$RT/lib/libssl.so.0.9.8"    "$RT/stub.c"
gcc -shared -fPIC -Wl,-soname,libcrypto.so.0.9.8 -o "$RT/lib/libcrypto.so.0.9.8" "$RT/stub.c"
# symlink distro libusb-0.1 into lib dir so LD_LIBRARY_PATH is self-contained
ln -sf /lib64/libusb-0.1.so.4 "$RT/lib/libusb-0.1.so.4"
echo "harness ready in $RT"
