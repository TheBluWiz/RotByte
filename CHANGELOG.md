# Changelog

## 1.0.0 — 2026-04-12

**Notifications**
- `--notify email` now sends a health report after every full re-verify (`--check`), not only when problems are found
- Four distinct email states with matching subject lines: pass (✓ all files OK), warning (⚠ N read errors), fail (✗ N failed, N missing), interrupted (⚠ scan interrupted)
- Quick scans still only notify when problems are detected
- `--notify-setup` now collects a "Send alerts from" address for custom sender and alias support; credentials include a `from` key alongside `username`, `to`, `smtp_host`, and `smtp_port`

**Documentation**
- Comprehensive documentation audit and polish pass for v1.0.0
- Consistent use of "full re-verify" throughout all docs
- Added "What to expect" section to `docs/Email Notification Setup.md` with the four notification states
- Updated `docs/macOS Permissions.md` version references to v1.0.0

---

## 0.1.1 — 2026-04-10

**Notifications**
- `--notify email` sends an alert when bit rot or missing files are detected
- `--notify-setup email` interactive SMTP configuration with test email
- Credentials stored in `~/.config/rotbyte/notify.conf` (Linux) or `~/Library/Application Support/rotbyte/notify.conf` (macOS) with 0600 permissions
- Notification is best-effort: send failures print a warning but never change the scan exit code
- `--notify` carries through `--track` into generated launchd/systemd commands
- `--status` displays notify configuration for tracked directories

**macOS Full Disk Access fix**
- `--track` now generates launchd plists that invoke Python directly instead of going through the Homebrew bash wrapper
- This fixes "authorization denied" errors on TCC-protected directories (`~/Desktop`, `~/Documents`, `~/Downloads`, `/Volumes/...`) when Full Disk Access is granted to the Python binary
- Linux (systemd) is unaffected

**Plist generation fix**
- Fixed malformed XML in generated launchd plists caused by `textwrap.dedent` with interpolated variables
- Plists now pass `plistlib` validation, fixing `--status` showing "no scheduled scans found"

**Shell completions**
- Added `--notify` and `--notify-setup` to Bash, Zsh, and Fish completions

**Documentation**
- Added macOS permissions guide (`docs/macOS Permissions.md`)
- Added email notification setup guide with Gmail, iCloud, and Outlook instructions (`docs/Email Notification Setup.md`)
- Added Notifications section to README
- Updated man page with `--notify` and `--notify-setup` entries

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