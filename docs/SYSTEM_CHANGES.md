# System changes made for fprintd integration

Everything the project has changed outside the repo, so it can be reversed.
**To reverse all of it:** `sudo ./scripts/system_uninstall.sh`
(add `--keep-prints` to leave fprintd's enrolled fingerprints in place).

No PAM, authselect or GDM configuration was changed. `authselect` already had
`with-fingerprint` enabled before this work (profile `local`), so once a finger is
enrolled in fprintd, `sudo` and the login screen ask for a fingerprint first and fall
back to the password.

## Applied 2026-10-04 by `sudo ./scripts/system_install.sh`

| Path | What | Reverse |
|---|---|---|
| `/usr/local/bin/vfs495` | the driver binary (copy of `target/release/vfs495`) | delete |
| `/usr/local/share/vfs495/captures/` (root, 0700) | `capture_seq.json`, `init_seq.json`, `modulus.json`, `perm_264.bin`, `dli_config.json` copied from `captures/` | delete dir |
| `/usr/local/share/vfs495/vendor/patches/` | the 5 patch blobs copied from `vendor/patches/` | delete dir |
| `/etc/systemd/system/vfs495.service` | feeder daemon unit (`packaging/vfs495.service`), enabled + started | `systemctl disable --now vfs495`, delete |
| `/etc/systemd/system/multi-user.target.wants/vfs495.service` | symlink made by `systemctl enable` | removed by `disable` |
| `/etc/systemd/system/fprintd.service.d/vfs495.conf` | sets `FP_VIRTUAL_IMAGE=/var/lib/fprint/vfs495.sock` for fprintd (`packaging/fprintd-vfs495.conf`) | delete file + dir, `systemctl daemon-reload` |

Pre-existing, not part of this change: `/etc/udev/rules.d/70-vfs495.rules` (installed
in an earlier session; lets the user open the sensor without sudo).
`/var/lib/fprint` was empty before (no enrolled prints).

## NOT applied — needs the user's decision

| Change | Why it is needed | How | Reverse |
|---|---|---|---|
| SELinux module `vfs495_fprintd` (`packaging/vfs495_fprintd.te`) | SELinux (enforcing) denies fprintd creating the `virtual_image` socket: `avc: denied { create } ... scontext=fprintd_t tcontext=fprintd_var_lib_t tclass=sock_file` (and `{ write }` on a `/run` directory). Without it the device fails to open: "Error binding to address: Permission denied". The module allows fprintd to create/unlink a socket file in its own `/var/lib/fprint` and nothing else. | `sudo ./scripts/system_selinux.sh` | `sudo semodule -r vfs495_fprintd` (also done by the uninstall script) |

## Created later by use (not by the scripts)

| Path | What | Reverse |
|---|---|---|
| `/var/lib/fprint/<user>/...` | fingerprints enrolled with `fprintd-enroll` | `fprintd-delete <user>` |
| `/var/lib/fprint/vfs495.sock` | socket fprintd creates while the device is open | removed by the uninstall script |
