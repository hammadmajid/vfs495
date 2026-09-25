#!/usr/bin/env python3
"""Read-only probe: GetVersion(0x01) -> GetStartInfo(0x19) -> GetOwnershipInfo(0x26).
All three are read commands HP's validity-sensor issues in this order during init.
No writes, no patches. Shows boot state and whether ownership can be read pre-patch."""
import sys, usb.core, usb.util
dev = usb.core.find(idVendor=0x138a, idProduct=0x003f)
if dev is None: sys.exit("no device")
try:
    if dev.is_kernel_driver_active(0): dev.detach_kernel_driver(0)
except Exception: pass
dev.set_configuration(1); usb.util.claim_interface(dev, 0)
def cmd(b, n=256, t=3000):
    dev.write(0x01, bytes(b), timeout=2000)
    return bytes(dev.read(0x81, n, timeout=t))
try:
    for name, c in [("GetVersion",b"\x01"), ("GetStartInfo",b"\x19"), ("GetOwnershipInfo",b"\x26")]:
        try:
            r = cmd(c)
            st = int.from_bytes(r[0:2],"little") if len(r)>=2 else -1
            print(f"{name:16} ({c.hex()}): {len(r)}B status={st:#06x}  {r.hex()}")
        except Exception as e:
            print(f"{name:16} ({c.hex()}): ERR {e}")
finally:
    usb.util.release_interface(dev, 0)
