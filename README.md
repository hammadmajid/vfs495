# vfs495 — open pairing/capture for the Validity VFS495 (USB 138a:003f)

Reverse-engineering the **pairing** step of the Validity VFS495 fingerprint
sensor (HP EliteBook 820 G3) toward a fully open-source Linux driver with no
proprietary code in the login path.

Prior art builds the SSLv3 secure session and image capture
(saifulmd0/vfs495-linux) but still runs HP's closed binary to establish each
session. This project's scope starts at **pairing** — the step before that
session.

- `NOTES.md` — running log: what was tried, what happened, blocker + next step.
- `notes/`   — deeper writeups (protocol, binary map, secret analysis).
- `scripts/` — our own tooling (pyusb pairing/session, trace parsers).
- `captures/`— usbmon/gdb traces (large raw files gitignored).
- `vendor/`  — HP package + extractions. **Gitignored. Never published.**

No proprietary HP code is committed. Nothing here goes into the login path.
