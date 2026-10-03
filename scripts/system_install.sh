#!/bin/bash
# Route the system fprintd through the vfs495 feeder daemon.
# Every file this creates is listed in docs/SYSTEM_CHANGES.md and removed by
# scripts/system_uninstall.sh. It changes no PAM/authselect/GDM configuration.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -x target/release/vfs495 ] || { echo "build first: cargo build --release"; exit 1; }

install -D -m 0755 target/release/vfs495 /usr/local/bin/vfs495
install -d -m 0700 /usr/local/share/vfs495/captures /usr/local/share/vfs495/vendor/patches
for f in capture_seq.json init_seq.json modulus.json perm_264.bin dli_config.json; do
    install -m 0600 "captures/$f" "/usr/local/share/vfs495/captures/$f"
done
install -m 0600 vendor/patches/* /usr/local/share/vfs495/vendor/patches/
chmod 0700 /usr/local/share/vfs495
install -D -m 0644 packaging/vfs495.service /etc/systemd/system/vfs495.service
install -D -m 0644 packaging/fprintd-vfs495.conf /etc/systemd/system/fprintd.service.d/vfs495.conf
restorecon -R /usr/local/bin/vfs495 /usr/local/share/vfs495 /etc/systemd/system/vfs495.service \
    /etc/systemd/system/fprintd.service.d 2>/dev/null || true
systemctl daemon-reload
systemctl try-restart fprintd.service || true
systemctl enable --now vfs495.service
echo "installed. Enroll with: fprintd-enroll   (swipe while the Caps Lock LED is lit)"
