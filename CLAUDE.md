# CLAUDE.md — working rules for this repo

## Commits
- **Always commit your changes. Do NOT ask for permission to commit — just commit.**
- Commit at the end of a piece of work (a fix, a finding, a doc update), with a
  clear message describing what changed and why.
- This repo is local-only (no remote); do not push.

## Docs
- **Always keep docs in sync with new findings and progress.** When project state,
  behavior, or a conclusion changes, update in the same change:
  - `docs/STATUS.md` — the distilled, organized project digest (keep authoritative).
  - `NOTES.md` — append a dated entry with the reasoning and evidence.
  - `README.md` — when build/usage/behavior changes.
- Record falsified hypotheses too, with the evidence, so they are not revisited.

## Project context
- Open-driver reverse engineering of the Validity VFS495 fingerprint sensor
  (`138a:003f`). Full status in `docs/STATUS.md`; full log in `NOTES.md`.
- `vendor/` (HP's package + extractions), biometric captures, raw USB traces, and
  HP patch blobs are gitignored and must never be committed.
- Do **not**, without explicit user OK, send `TakeOwnership`/`setowner`/
  `resetowner` (persistent, cycle-limited sensor writes) or change system
  fprintd / PAM / authselect / GDM config.

## Verify before committing
- `cargo build --release`, `cargo clippy --release`, and `cargo test --release`
  should be clean (only pre-existing warnings) before committing code changes.
