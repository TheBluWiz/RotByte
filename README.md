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

On the first run, rotbyte hashes every file and stores the results. On later runs it only re-hashes files whose size or modification time changed — and it knows the difference between an intentional edit and corruption. Use `--check` to force a full re-verify, which is where actual bit rot gets caught.

## Features

- **Fast** — parallel hashing across all cores with a live progress bar and throughput stats.
- **Interrupt-safe** — hit Ctrl-C and it finishes the current batch, saves progress, and picks up where it left off next time.
- **Edit-aware** — a changed hash with changed metadata is an edit, not an alarm. Only silent mismatches trigger a failure.
- **Move detection** — when new files match the checksum of missing files, rotbyte tells you they were probably renamed rather than deleted and re-added.
- **Import-friendly** — already have `.b2sum` sidecar files? `rotbyte --import` pulls them in and cleans up the originals.
- **Cron-ready** — `--quiet` suppresses everything except problems, so you get clean logs.
- **Time-budgeted scans** — `--budget` caps wall-clock time on full verifies. Stalest files are checked first, so successive runs cover the entire database.
- **Scheduled scanning** — `--track` installs native launchd (macOS) or systemd (Linux) timers with configurable quick and full scan schedules.
- **Due-based verification** — `--due 30d` targets only files not checked recently, combining naturally with `--budget`.
- **JSON output** — `--json` produces machine-readable results for scripts and monitoring pipelines.
- **Export** — `--export` writes a b2sum-compatible manifest as an independent backup of your checksums outside the database.
- **Directory exclusion** — `--exclude` skips directories you don't want tracked.

## Scheduling

Instead of writing cron rules by hand, use `--track` to install platform-native scheduled scans:

```bash
# Quick scan every hour, full verify daily at 2 AM with a 2-hour budget
rotbyte --track --every 1h --full-at 2h --budget 2h /Volumes/Media

# Quick scan every 30 minutes, full verify twice daily
rotbyte --track --every 30m --full-at 2h 14h /Volumes/Media

# Check what's scheduled and how your files are doing
rotbyte --status
```

On macOS this writes launchd plists to `~/Library/LaunchAgents/`. On Linux it writes systemd user timers to `~/.config/systemd/user/`.

You can still use cron if you prefer:

```bash
# Sunday 2 AM full verify, only log problems
0 2 * * 0  rotbyte --check -q /Volumes/Media >> /var/log/rotbyte.log 2>&1
```

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

# Export checksums as a portable plain-text manifest
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

## Requirements

Python 3.9+ on macOS or Linux.

## License

MIT