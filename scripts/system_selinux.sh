#!/bin/bash
# Build and load packaging/vfs495_fprintd.te (see that file for what it allows).
# Separate from system_install.sh on purpose: it changes SELinux policy, so run
# it only if you accept that. Undone by scripts/system_uninstall.sh
# (or: sudo semodule -r vfs495_fprintd).
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
tmp=$(mktemp -d)
checkmodule -M -m -o "$tmp/vfs495_fprintd.mod" packaging/vfs495_fprintd.te
semodule_package -o "$tmp/vfs495_fprintd.pp" -m "$tmp/vfs495_fprintd.mod"
semodule -i "$tmp/vfs495_fprintd.pp"
rm -rf "$tmp"
systemctl try-restart fprintd.service || true
echo "SELinux module vfs495_fprintd loaded."
