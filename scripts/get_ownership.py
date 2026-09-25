#!/usr/bin/env python3
"""Read-only: send VCSFW cmd 0x26 (GetOwnershipInfo) and dump the reply.
0x26 is a single-byte read command HP's validity-sensor issues
(scsSensorSendGetOwnershipInfo_V4). No sensor state is changed."""
import sys, usb.core, usb.util
dev = usb.core.find(idVendor=0x138a, idProduct=0x003f)
if dev is None: sys.exit("no device")
try:
    if dev.is_kernel_driver_active(0): dev.detach_kernel_driver(0)
except Exception: pass
dev.set_configuration(1); usb.util.claim_interface(dev, 0)
try:
    dev.write(0x01, b"\x26", timeout=2000)
    rep = bytes(dev.read(0x81, 256, timeout=3000))
finally:
    usb.util.release_interface(dev, 0)
status = int.from_bytes(rep[0:2], "little") if len(rep) >= 2 else None
print(f"reply {len(rep)} bytes: {rep.hex()}")
print(f"status = {status:#06x}" if status is not None else "no status")
