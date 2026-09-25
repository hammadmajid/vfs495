#!/usr/bin/env python3
"""VFS495 (138a:003f) GET_VERSION reader — READ ONLY.

Sends only VCSFW command 0x01 (GetVersion), the exact first command HP's
validity-sensor binary issues (and which prior art already replays). No state
is changed on the sensor. Parses the reply per the field layout documented in
vfs495-linux/docs/FINDINGS.md to show version + security/provisioning bits.

Run: sudo /home/bine/Developer/lab/vfs495/.venv/bin/python scripts/getver.py
"""
import sys, struct
import usb.core, usb.util

VID, PID = 0x138a, 0x003f
EP_OUT, EP_IN = 0x01, 0x81

def main():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("device 138a:003f not found", file=sys.stderr); return 2
    # Detach any kernel driver on interface 0 (there shouldn't be one).
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
            print("[i] detached kernel driver on if0")
    except (NotImplementedError, usb.core.USBError):
        pass
    dev.set_configuration(1)
    usb.util.claim_interface(dev, 0)
    try:
        dev.write(EP_OUT, b"\x01", timeout=2000)          # GET_VERSION
        rep = bytes(dev.read(EP_IN, 64, timeout=2000))
    finally:
        usb.util.release_interface(dev, 0)
    print(f"[i] reply {len(rep)} bytes: {rep.hex()}")
    if len(rep) < 38:
        print("[!] short reply; not parsing"); return 0
    status  = struct.unpack_from("<H", rep, 0)[0]
    build_t = struct.unpack_from("<I", rep, 2)[0]
    build_n = struct.unpack_from("<I", rep, 6)[0]
    vmajor, vminor, target, product, siliconrev, formalrel, platform, patch = rep[10:18]
    serial  = rep[18:24]
    security = rep[24:26]
    patchsig = struct.unpack_from("<I", rep, 26)[0]
    iface    = rep[30]
    prod = {1:"Falcon",3:"Falconusb",4:"Falconspi"}.get(product, str(product))
    print(f"    status        = 0x{status:04x}")
    print(f"    build         = v{vmajor}.{vminor:02d} build {build_n} (buildtime 0x{build_t:08x})")
    print(f"    target/product= {target} / {product} ({prod})  siliconrev {siliconrev}")
    print(f"    formalrel     = {formalrel}  platform 0x{platform:02x}  patch {patch}")
    print(f"    serial        = {serial.hex()}")
    print(f"    security[2]   = {security.hex()}   (bit fields: sensor secured/provisioned state)")
    print(f"    patchsig      = 0x{patchsig:08x}   iface {iface}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
