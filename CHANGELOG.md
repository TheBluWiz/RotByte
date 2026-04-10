# Changelog

## 0.1.0 — 2026-04-08

Initial release.

**Core**
- BLAKE2b-512 checksums stored in a per-directory SQLite database
- Quick scans re-hash only files whose size or mtime changed; `--check` forces a full re-verify to catch silent bit rot
- Edit-aware: changed hash + changed metadata = intentional edit, not corruption
- Parallel hashing via `--workers` (defaults to CPU count)
- Interrupt-safe: Ctrl-C finishes the current batch, commits progress, and resumes on next run
- File lock prevents concurrent runs against the same database

**Verification**
- `--budget` caps wall-clock time on full scans, verifying stalest files first
- `--due` targets only files not checked within N days; combines with `--budget`
- Move detection: flags new files whose checksum matches a missing file

**Recovery**
- `--accept` re-baselines a single file after restoring from backup
- `--accept-all` clears all MISSING and FAILED records at once
- `--import` ingests existing `.b2sum`/`.b2` sidecar files, verifies them, and removes the originals

**Scheduling**
- `--track` installs native launchd (macOS) or systemd (Linux) timers with configurable `--every` and `--full-at` schedules
- `--status` shows all scheduled scans, last activity, and file health

**Notifications**
- `--notify-setup email` interactive SMTP configuration with test message
- `--notify email` sends alerts when bit rot or missing files are detected

**Output**
- `--report` prints a human-readable integrity summary
- `--json` produces machine-readable results for scripts and monitoring
- `--export` writes a b2sum-compatible plain-text manifest
- `--quiet` suppresses everything except problems (cron-friendly)
- Live progress bar with throughput stats; degrades gracefully when piped

**Other**
- `--exclude` skips directories; `--include-hidden` opts in to dotfiles
- `--db` allows a custom database location
- Shell completions for Bash, Zsh, and Fish
- Man page (`rotbyte.1`)
- Exit codes: 0 (OK), 1 (missing), 2 (bit rot), 3 (interrupted)
- Requires Python 3.9+ on macOS or Linux