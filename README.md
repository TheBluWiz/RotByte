# rotbyte

Guard your files against silent data corruption.

Bit rot flips bits without touching timestamps or file sizes. By the time you notice, your backups may have already rotated out the good copy. **rotbyte** keeps a database of checksums and tells you the moment something doesn't match.

## Install

```
brew install rotbyte
```

## Quick start

```bash
# Index every file in the current directory
rotbyte

# Scan a specific drive
rotbyte /Volumes/Media

# Full re-verify — the only way to catch true silent corruption
rotbyte --check

# See what's healthy and what isn't
rotbyte --report
```

## How to Use

### Your first run

On the first run, rotbyte hashes every file in the target directory and stores the results in a `.dirname_checksums.db` SQLite database inside that directory. Subsequent runs only re-hash files whose size or modification time changed, so they're fast.

```bash
# Index all files in the current directory
rotbyte

# Index a specific drive or folder
rotbyte /Volumes/Media
```

### Checking for corruption

Default scans detect changed files but won't catch bit rot — silent corruption where the data changes without touching the modification time. `--check` re-hashes every file regardless of metadata. A hash change accompanied by a metadata change is treated as an intentional edit; only a hash change with no metadata change triggers a FAILED record.

```bash
# Full re-verify — the only way to catch true silent corruption
rotbyte --check /Volumes/Media

# See a full status report: counts, failed files, stale files
rotbyte --report /Volumes/Media
```

### Scheduling quick scans

`--track` installs a native platform timer (launchd on macOS, systemd on Linux) so rotbyte runs automatically. Without `--full-at`, only a quick scan is installed at the default 60-minute interval.

```bash
# Quick scan every hour (default interval), fire and forget
rotbyte --track /Volumes/Media

# Check that the timer is active and review the last result
rotbyte --status
```

### Scheduling with full re-verifies

Combine `--track` with `--full-at` (daily full re-verify time), `--budget` (cap how long the full re-verify runs), and `--notify email` (email health reports and problem alerts):

```bash
# Quick scan every 30 min, full re-verify nightly at 2 AM,
# 2-hour budget, email health report after each full re-verify
rotbyte --track \
  --every 30m \
  --full-at 2h \
  --budget 2h \
  --notify email \
  /Volumes/Media
```

`--budget 2h` processes the stalest files first so successive runs gradually cover the entire archive. `--notify email` requires one-time setup via `--notify-setup email`.

## Features

- **Fast** — parallel hashing across all cores with a live progress bar and throughput stats.
- **Interrupt-safe** — hit Ctrl-C and it finishes the current batch, saves progress, and picks up where it left off next time. Hit Ctrl-C a second time to abort immediately.
- **Edit-aware** — a changed hash with changed metadata is an edit, not an alarm. Only silent mismatches trigger a failure.
- **Move detection** — when new files match the checksum of missing files, rotbyte tells you they were probably renamed rather than deleted and re-added.
- **Import-friendly** — already have `.b2sum` sidecar files? `rotbyte --import` pulls them in and cleans up the originals.
- **Cron-ready** — `--quiet` suppresses everything except problems, so you get clean logs.
- **Time-budgeted scans** — `--budget` caps wall-clock time on full re-verifies. Stalest files are checked first, so successive runs cover the entire database.
- **Scheduled scanning** — `--track` installs native launchd (macOS) or systemd (Linux) timers with configurable quick and full scan schedules.
- **Due-based verification** — `--due 30d` targets only files not checked recently, combining naturally with `--budget`.
- **Email notifications** — `--notify email` sends a health report after every full re-verify and an alert when problems are found on quick scans. Works standalone or with `--track`.
- **JSON output** — `--json` produces machine-readable results for scripts and monitoring pipelines.
- **Export** — `--export` writes a b2sum-compatible manifest as an independent backup of your checksums outside the database.
- **Directory exclusion** — `--exclude` skips directories you don't want tracked.

## Scheduling

Instead of writing cron rules by hand, use `--track` to install platform-native scheduled scans:

```bash
# Quick scan every hour, full re-verify daily at 2 AM with a 2-hour budget
rotbyte --track --every 1h --full-at 2h --budget 2h /Volumes/Media

# Quick scan every 30 minutes, full verify twice daily
rotbyte --track --every 30m --full-at 2h 14h /Volumes/Media

# Check what's scheduled and how your files are doing
rotbyte --status
```

On macOS this writes launchd plists to `~/Library/LaunchAgents/`. On Linux it writes systemd user timers to `~/.config/systemd/user/`. Running `--track` without `--full-at` installs only the quick scan; add `--full-at` to also schedule a nightly full re-verify.

> **macOS users:** Scanning TCC-protected directories (Desktop, Documents, Downloads, external drives) with `--track` requires a one-time Full Disk Access grant for Python. See [docs/macOS Permissions.md](docs/macOS%20Permissions.md).

You can still use cron if you prefer:

```bash
# Sunday 2 AM full verify, only log problems
0 2 * * 0  rotbyte --check -q /Volumes/Media >> /var/log/rotbyte.log 2>&1
```

## Notifications

Get email health reports after full re-verifies and alerts when problems are found. One-time setup:

```bash
rotbyte --notify-setup email
```

This prompts for your SMTP credentials (e.g. Gmail + app password), sends a test email, and saves the config. Then use `--notify email` on any scan:

```bash
# One-off scan with email alert
rotbyte --check --notify email /Volumes/Media

# Bake it into scheduled scans
rotbyte --track --every 1h --full-at 2h --notify email /Volumes/Media
```

Full scans (`--check`) always send a health report — whether everything checks out or something needs attention. Quick scans only notify when there's a problem, so your inbox stays clean.

For provider-specific setup (Gmail, iCloud, Outlook) see [docs/Email Notification Setup.md](docs/Email%20Notification%20Setup.md).

## Incremental verification

Large archives can't always be fully re-verified in one sitting. Combine `--check` with `--budget` and `--due` to spread the work across multiple runs:

```bash
# Full verify with a 2-hour time limit (stalest files first)
rotbyte --check --budget 2h /Volumes/Media

# Only re-verify files not checked in 30 days, with a 1-hour budget
rotbyte --due 30d --budget 1h /Volumes/Media
```

## Recovering from problems

```bash
# Accept a single restored file as correct
rotbyte --accept restored_file.mkv

# Accept everything — clears all MISSING and FAILED records
rotbyte --accept-all

# Export checksums as a portable plain-text manifest (MISSING files are excluded)
rotbyte --export checksums.txt
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All files OK |
| `1` | Missing files detected |
| `2` | Bit rot detected |
| `3` | Interrupted (safe to re-run) |

## All options

Run `rotbyte --help` for the full reference, or `man rotbyte` after installing via Homebrew.

Additional tuning flags available via `--help`: `--workers` (parallel hashing workers), `--db` (custom database path), `--skip-missing` (skip missing-file detection), `--include-hidden` (include dotfiles and hidden directories).

Shell completions for bash, zsh, and fish are in the `completions/` directory.

## Requirements

Python 3.9+ on macOS or Linux.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

MIT