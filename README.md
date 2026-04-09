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

```bash
# Sunday 2 AM full verify, only log problems
0 2 * * 0  rotbyte --check -q /Volumes/Media >> /var/log/rotbyte.log 2>&1
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