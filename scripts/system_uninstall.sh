#!/bin/bash
# Undo scripts/system_install.sh completely. Pass --keep-prints to leave the
# fingerprints enrolled through fprintd in place (they are unusable without the
# daemon, and PAM falls back to the password).
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
systemctl disable --now vfs495.service 2>/dev/null
if [ "${1:-}" != "--keep-prints" ]; then
    for d in /var/lib/fprint/*/; do [ -d "$d" ] && fprintd-delete "$(basename "$d")" 2>/dev/null; done
fi
systemctl stop fprintd.service 2>/dev/null
rm -f /etc/systemd/system/vfs495.service /etc/systemd/system/fprintd.service.d/vfs495.conf
rmdir /etc/systemd/system/fprintd.service.d 2>/dev/null
rm -f /var/lib/fprint/vfs495.sock
rm -rf /usr/local/share/vfs495
rm -f /usr/local/bin/vfs495
semodule -l 2>/dev/null | grep -qx vfs495_fprintd && semodule -r vfs495_fprintd
systemctl daemon-reload
echo "vfs495 system integration removed."
