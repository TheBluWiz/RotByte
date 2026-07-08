#!/usr/bin/env python3
"""
rotbyte — File Integrity Checker
=================================
Detects bit rot by computing and verifying BLAKE2b checksums for every
file in a directory tree, stored in a local SQLite database.

Usage:
    rotbyte                              # scan current directory
    rotbyte /Volumes/Media               # scan a specific directory
    rotbyte --check                      # force full re-verify of all files
    rotbyte --check /Volumes/Media
    rotbyte --report                     # print status summary
    rotbyte --workers 8                  # parallel hashing (default: CPU count)

Default behavior (no flags):
    - New files are hashed and added to the database.
    - Existing files are re-hashed only if their size or modification
      time has changed since the last check. A changed hash with changed
      metadata is treated as an intentional edit, not corruption.

With --check:
    - Every file is re-hashed regardless of size/mtime, which catches
      silent bit rot where the file corrupts without the metadata changing.
      This is the only mode that can detect true bit rot.

The database (.{dirname}_rotbyte.db) is created automatically inside
the target directory on first run. Databases from rotbyte 1.0 and earlier
(.{dirname}_rotbyte.db) are auto-migrated on the first run of any newer
version — the DB plus its .lock / WAL / SHM / .manifest sidecars are
atomically renamed, with history preserved.

Requires Python 3.9+ on macOS, Linux, or Windows.

This module is a thin entry point. The actual pipeline lives in the
:mod:`_rotbyte` internal package (database, hashing, scheduler, notify,
progress, platform). Symbols are re-exported here so the historical
``rotbyte.X`` API used by the test suite continues to work.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import sys
import time
from datetime import datetime
from typing import List, Optional, Set

# ── Re-exports from the _rotbyte package ──────────────────────────────────────
# Keep the `rotbyte.X` surface that tests and users depend on. Anything
# that should be callable via ``rotbyte.X`` lives here.

from _rotbyte.database import (
    ChecksumDB,
    DB_FILENAME_SUFFIX,
    LEGACY_DB_FILENAME_SUFFIX,
    SCHEMA_SQL,
    SCHEMA_VERSION,
    _migrate_legacy_db_name,
)
from _rotbyte.hashing import (
    BATCH_SIZE,
    FileEntry,
    HASH_BUFFER_SIZE,
    HashResult,
    _is_windows_hidden,
    detect_missing,
    hash_file,
    prescan_files,
    run_hashing,
    scan_files,
)
from _rotbyte.helpers import (
    _format_clock_time,
    _format_duration,
    _format_size,
    _is_tty,
    _mtime_iso,
    _next_calendar_run,
    _now,
    _resolve,
    _term_width,
    _utc_to_local,
    parse_clock_time,
    parse_days,
    parse_duration,
)
from _rotbyte.notify import (
    _keychain_account,
    _keychain_get,
    _keychain_set,
    _load_notify_config,
    _notify_config_path,
    _run_notify_setup,
    _send_email_notification,
    _windows_credential_get,
)
from _rotbyte.platform import (
    _IS_LINUX,
    _IS_MACOS,
    _IS_WINDOWS,
    FileLock,
    _try_lock,
    _unlock,
)
from _rotbyte.power import PreventSleep
from _rotbyte.progress import ProgressBar, Spinner
from _rotbyte.scheduler import (
    _dir_hash,
    _discover_tracked,
    _find_rotbyte_executable,
    _missing_command_path,
    _parse_cmd_flags,
    _run_repair,
    _run_track,
    _run_untrack,
    _run_untrack_all,
    _stable_homebrew_path,
)
from _rotbyte.scheduler.launchd import (
    _discover_launchd,
    _generate_launchd_plist,
    _install_launchd,
    _launchd_log_path,
    _rotate_launchd_log,
    _uninstall_all_launchd,
    _uninstall_launchd,
)
from _rotbyte.scheduler.schtasks import (
    _discover_schtasks,
    _generate_task_xml,
    _install_schtasks,
    _iso_duration,
    _parse_iso_duration,
    _parse_schtasks_xml,
    _quote_windows_args,
    _split_windows_args,
    _uninstall_all_schtasks,
    _uninstall_schtasks,
    _xml_escape,
)
from _rotbyte.scheduler.systemd import (
    _discover_systemd,
    _generate_systemd_timer,
    _generate_systemd_unit,
    _install_systemd,
    _split_exec_start,
    _systemd_escape_arg,
    _systemd_escape_description,
    _uninstall_all_systemd,
    _uninstall_systemd,
)

# Kept available for tests that poke at it via ``rotbyte.smtplib``.
import smtplib  # noqa: F401

# ── Version and process exit codes ────────────────────────────────────────────

VERSION = "1.2.0"

# Documented process exit codes. Callers (cron, monitoring, CI) rely on
# these — keep them stable and add new codes rather than reusing existing
# ones. The 0–4 range is the public surface from rotbyte 1.0; 5–7 were
# added to disambiguate "couldn't start cleanly" from "scan completed
# and found problems."
EXIT_OK = 0
EXIT_MISSING = 1            # MISSING files detected
EXIT_BIT_ROT = 2            # FAILED files detected (silent corruption)
EXIT_INTERRUPTED = 3        # Ctrl-C or SIGTERM during scan
EXIT_DB_CORRUPT = 4         # PRAGMA quick_check failed; restore from backup
EXIT_DB_LOCKED = 5          # Another rotbyte process holds the lock
EXIT_IO = 6                 # Target dir unreachable / permission denied / I/O failure
EXIT_INTERNAL = 7           # Worker pool died, unexpected exception


def _conflicting_mode_flags(args: argparse.Namespace) -> List[str]:
    """Return mode-flag names that would conflict with --untrack[-all].

    Used to refuse combinations like ``--untrack --check`` or
    ``--untrack-all --track`` that don't have a coherent meaning.
    Listed in --help order for predictable error messages.
    """
    flags: List[str] = []
    if args.track:               flags.append("--track")
    if args.track_setup:         flags.append("--track-setup")
    if args.status:              flags.append("--status")
    if args.repair:              flags.append("--repair")
    if args.report:              flags.append("--report")
    if args.check:               flags.append("--check")
    if args.accept:              flags.append("--accept")
    if args.accept_all:          flags.append("--accept-all")
    if args.import_hashes:       flags.append("--import")
    if args.verify_file:         flags.append("--verify-file")
    if args.export:              flags.append("--export")
    if args.notify_setup:        flags.append("--notify-setup")
    return flags


# ── Reporting ──────────────────────────────────────────────────────────────────

def _budget_cutoff_note(budget_exceeded: bool) -> List[str]:
    """Terminal lines warning that a --budget scan didn't verify everything.

    Returns an empty list when the budget wasn't hit, so the caller can
    splice it into the summary unconditionally. Extracted from _run_phases
    so the message is unit-testable without a real timed-out scan.
    """
    if not budget_exceeded:
        return []
    return [
        "",
        "  Note: time budget reached — not every file was verified this run.",
        "        Stalest files were checked first; re-run to continue,",
        "        or raise --budget to cover more per run.",
    ]


def print_report(db: ChecksumDB, stale_days: int = 90):
    """Print a human-readable status report from the database.

    ``stale_days`` bounds the "not verified recently" section. It defaults
    to 90 but the caller passes the schedule's ``--due`` window when one is
    configured, so the report's notion of "stale" matches the freshness
    target rather than an unrelated constant.
    """
    def _fmt_ts(value):
        # Localize like --status; fall back to the raw stored string on any
        # unexpected format so the report never crashes on a stray row (the
        # pre-localization code printed the raw value and couldn't fail).
        if not value:
            return "—"
        try:
            return _utc_to_local(value)
        except (ValueError, TypeError):
            return value

    print()
    print("═" * 60)
    print("  rotbyte — Integrity Report")
    print("═" * 60)

    summary = db.status_summary()
    if not summary:
        print("  Database is empty — no files have been verified yet.")
        return

    total = sum(r["count"] for r in summary)
    print(f"  Total tracked files: {total:,}")
    print()
    for row in summary:
        bar = "█" * min(40, int(40 * row["count"] / total))
        print(f"  {row['status']:>8s}  {row['count']:>8,}  {bar}")
    print()

    failed = db.failed_files()
    if failed:
        print(f"  ✗ Failed files ({len(failed)}):")
        print(f"  {'─' * 56}")
        for f in failed:
            # Localize the timestamp so --report and --status agree instead
            # of showing the same instant in two different timezones.
            print(f"    {f['file_path']}")
            print(f"      Size: {_format_size(f['file_size'])}  |  "
                  f"Tracked since: {_fmt_ts(f.get('first_seen'))}  |  "
                  f"Last verified: {_fmt_ts(f['last_verified'])}")
            print(f"      Expected: {f['baseline_checksum'][:32]}...")
            print(f"      Got:      {f['checksum'][:32]}...")
        print()

    stale = db.stale_files(stale_days)
    if stale:
        # Cap the listing but be honest about it — the previous code
        # announced the full count then silently printed only the first 10.
        stale_cap = 20
        print(f"  ⏰ Files not verified in {stale_days}+ days: {len(stale):,}")
        shown = stale if len(stale) <= stale_cap else stale[:stale_cap]
        if len(stale) > stale_cap:
            print(f"    (showing first {stale_cap} of {len(stale):,})")
        for s in shown:
            print(f"    {s['file_path']}  (last: {_fmt_ts(s['last_verified'])})")
        print()


# ── Main orchestration ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="rotbyte",
        description="Detect bit rot by tracking BLAKE2b checksums in a SQLite database.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  rotbyte                                Scan current directory
  rotbyte /Volumes/Media                 Scan a specific directory
  rotbyte --check                        Full re-verify (catches silent bit rot)
  rotbyte --check /Volumes/Media         Full re-verify on a specific directory
  rotbyte --report                       Show integrity status summary
  rotbyte --accept movie.mkv             Accept a single file as correct
  rotbyte --accept-all                   Accept all current state as new baseline
  rotbyte --import                       Import existing .b2sum/.b2 hash files
  rotbyte --exclude tmp                  Skip the 'tmp' directory
  rotbyte --exclude tmp cache            Skip multiple directories
  rotbyte --include-hidden               Include hidden files and directories
  rotbyte --case-insensitive             Normalise paths to lowercase (APFS/NTFS)
  rotbyte --check --budget 2h            Full verify with a 2-hour time limit
  rotbyte --due 30d                       Re-verify files not checked in 30 days
  rotbyte --due 7d --budget 1h           Re-verify week-old files, 1hr budget
  rotbyte --track /Volumes/Media         Quick scan every hour (launchd/systemd)
  rotbyte --track --every 30m --full-at 2h 14h --budget 2h /Volumes/Media
  rotbyte --untrack /Volumes/Media       Remove scheduled scans for one directory
  rotbyte --untrack-all                  Remove every scheduled rotbyte run
  rotbyte --status                       Show all scheduled scans and health
  rotbyte --repair                       Fix scheduled scans after an upgrade

Exit codes:
  0  All files verified OK
  1  Missing files detected
  2  Bit rot detected (checksum mismatch)
  3  Run was interrupted (safe to re-run)
  4  Database integrity check failed (restore from backup)
  5  Database locked by another rotbyte process (retry later)
  6  I/O error (target directory unreachable, permission denied)
  7  Internal error (worker pool died, unexpected exception)
""",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("path", nargs="?", default=".",
                        help="Directory to scan (default: current directory)")
    parser.add_argument("--check", action="store_true",
                        help="Force re-hash of every file regardless of modification time")
    parser.add_argument("--accept", metavar="FILE",
                        help="Accept a single file's current state (clears MISSING or re-hashes FAILED)")
    parser.add_argument("--verify-file", metavar="FILE", dest="verify_file",
                        help="Verify a single file's integrity against the database")
    parser.add_argument("--accept-all", action="store_true",
                        help="Accept all current state as new baseline (clears all MISSING and FAILED)")
    parser.add_argument("--import", dest="import_hashes", action="store_true",
                        help="Import .b2sum/.b2 hash files into the database and delete them after")
    parser.add_argument("--report", action="store_true",
                        help="Print status report and exit")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Only output problems (for cron jobs and automation)")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4,
                        help=f"Parallel hashing workers (default: {os.cpu_count() or 4})")
    parser.add_argument("--skip-missing", action="store_true",
                        help="Don't check for files that have been removed")
    parser.add_argument("--include-hidden", action="store_true",
                        help="Include hidden files and directories (excluded by default)")
    parser.add_argument("--case-insensitive", dest="case_insensitive",
                        action="store_true",
                        help="Treat file paths as case-insensitive. Useful on "
                             "macOS APFS (default) and Windows NTFS where a "
                             "rename-by-case would otherwise produce phantom "
                             "MISSING records. Off by default; changing it on "
                             "an existing database will rewrite paths to lower "
                             "case on the next scan.")
    parser.add_argument("--exclude", nargs="+", default=[], metavar="PATH",
                        help="Exclude one or more directories (relative to target dir or absolute)")
    parser.add_argument("--db", help="Database path (default: .{dirname}_rotbyte.db inside target dir)")
    parser.add_argument("--export", metavar="FILE",
                        help="Export a plain-text manifest of all tracked file checksums")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Output results as JSON (for scripts and monitoring)")
    parser.add_argument("--budget", metavar="DURATION",
                        help="Time budget for --check scans (e.g. 2h, 30m, 1h30m). "
                             "Stalest files are verified first.")
    parser.add_argument("--due", metavar="DAYS",
                        help="Only re-verify files not checked within N days (e.g. 30d, 7d, 90d). "
                             "Implies --check.")
    parser.add_argument("--track", action="store_true",
                        help="Install scheduled scans using launchd (macOS), systemd (Linux), "
                             "or Task Scheduler (Windows)")
    parser.add_argument("--auto-export", dest="auto_export", action="store_true",
                        help="After a successful --check, write a b2sum-compatible manifest "
                             "to <db_path>.manifest as an independent backup of checksums. "
                             "Off by default. Persists across scheduled runs when combined "
                             "with --track.")
    parser.add_argument("--run-on-battery", dest="run_on_battery", action="store_true",
                        help="Windows --track only: allow scheduled scans to run while on "
                             "battery power. Default is to skip runs on battery to preserve "
                             "battery life (matches typical Task Scheduler defaults).")
    parser.add_argument("--track-setup", dest="track_setup", action="store_true",
                        help="Interactive setup wizard for --track (prompts for schedule, budget, etc.)")
    parser.add_argument("--untrack", action="store_true",
                        help="Remove scheduled scans for the given directory "
                             "(or the current directory if PATH is omitted). "
                             "Stops the launchd / systemd / Task Scheduler "
                             "unit and deletes its config file.")
    parser.add_argument("--untrack-all", dest="untrack_all", action="store_true",
                        help="Remove every scheduled scan installed by rotbyte "
                             "on this machine across every tracked directory.")
    parser.add_argument("--status", action="store_true",
                        help="Show status of all scheduled scans and file health")
    parser.add_argument("--repair", action="store_true",
                        help="Re-point every installed scheduled scan at the current "
                             "rotbyte/Python path and reload it. Fixes schedules broken "
                             "by a Homebrew upgrade (interpreter/script path deleted). "
                             "Safe to run anytime; schedules already current are left as-is.")
    parser.add_argument("--every", metavar="INTERVAL", default="60m",
                        help="Quick scan frequency for --track (e.g. 30m, 2h). Default: 60m")
    parser.add_argument("--full-at", nargs="+", metavar="TIME", dest="full_at",
                        help="Daily clock times for full --check scans (e.g. 2h 2h30m 14h)")
    parser.add_argument("--notify", metavar="BACKEND",
                        help="Send a notification when problems are detected (e.g. email)")
    parser.add_argument("--notify-setup", metavar="BACKEND", dest="notify_setup",
                        help="Interactive setup for notifications (e.g. email)")
    parser.add_argument("--scheduled", action="store_true",
                        help="Internal: set by --track to identify scheduled runs")

    args = parser.parse_args()

    # Validate --untrack / --untrack-all up front so a conflicting
    # combination can't be silently won by another mode flag's earlier
    # dispatch branch (e.g. --status). The actual untrack work happens
    # further down, after notify-config and other input validation has
    # had a chance to short-circuit.
    if args.untrack and args.untrack_all:
        print("Error: --untrack and --untrack-all are mutually exclusive.",
              file=sys.stderr)
        sys.exit(1)
    if args.untrack or args.untrack_all:
        conflicts = _conflicting_mode_flags(args)
        if conflicts:
            flag = "--untrack-all" if args.untrack_all else "--untrack"
            print(f"Error: {flag} cannot be combined with {', '.join(conflicts)}.",
                  file=sys.stderr)
            sys.exit(1)

    # --notify-setup is a standalone command
    if args.notify_setup:
        if args.notify_setup != "email":
            print(f"Error: Unknown notification backend '{args.notify_setup}'. "
                  "Supported: email", file=sys.stderr)
            sys.exit(1)
        _run_notify_setup()
        return

    # --track-setup is a standalone command — runs the interactive wizard
    # and dispatches to the normal --track install path with the collected args.
    if args.track_setup:
        _run_track_setup(args.path)
        return

    # Validate --notify
    if args.notify:
        if args.notify != "email":
            print(f"Error: Unknown notification backend '{args.notify}'. "
                  "Supported: email", file=sys.stderr)
            sys.exit(1)
        # Verify config exists early so the user doesn't wait through a full
        # scan only to discover notifications aren't configured. On scheduled
        # runs, degrade to a warning: a broken email config must never
        # disable the integrity scanning itself (the send path already
        # warns-and-continues on failure, this check would otherwise abort
        # the whole run before a single file is hashed).
        if getattr(args, "scheduled", False):
            try:
                _load_notify_config()
            except SystemExit:
                print("Warning: email notification config is unavailable — "
                      "the scheduled scan will run, but no email will be sent.",
                      file=sys.stderr)
                print("  Run `rotbyte --notify-setup email` to fix notifications.",
                      file=sys.stderr)
        else:
            _load_notify_config()

    # --status doesn't need a target directory or any other validation
    if args.status:
        _run_status()
        return

    # --repair rewrites installed scheduler configs in place; like --status
    # it needs no target directory, database, or lock.
    if args.repair:
        sys.exit(_run_repair())

    # --untrack / --untrack-all: tear down installed scheduler units.
    # Mutually-exclusive validation already happened up front, so by the
    # time we get here at most one of these is set. They don't open the
    # database, take the lock, or require the target path to still exist
    # on disk (a removed directory should still be untrackable so its
    # schedule isn't orphaned).
    if args.untrack_all:
        sys.exit(_run_untrack_all())
    if args.untrack:
        # Single-target untrack: realpath the path argument so the dhash
        # we compute matches what --track installed. os.path.realpath()
        # tolerates non-existent paths (returns the input absolutised),
        # which is the right behaviour here.
        target_dir = _resolve(args.path)
        sys.exit(_run_untrack(target_dir))

    # --verify-file has its own database discovery and bypasses the normal
    # target_dir / db_path resolution
    if args.verify_file:
        db_path = _discover_db_for_file(args.verify_file)
        target_dir = os.path.dirname(db_path)
        lock_path = db_path + ".lock"
        lock = FileLock(lock_path)
        if not lock.acquire():
            print("Error: Another instance is already running against this database.",
                  file=sys.stderr)
            print(f"  If this is a mistake, remove: {lock_path}", file=sys.stderr)
            sys.exit(EXIT_DB_LOCKED)
        try:
            _run(args, target_dir, db_path)
        finally:
            lock.release()
        return

    # Validate --workers
    if args.workers < 1:
        print("Error: --workers must be at least 1.", file=sys.stderr)
        sys.exit(1)

    # Parse --budget duration
    args.budget_seconds = None
    if args.budget:
        try:
            args.budget_seconds = parse_duration(args.budget)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        if not args.check and not args.due and not args.track:
            print("Error: --budget requires --check, --due, or --track with --full-at.", file=sys.stderr)
            sys.exit(1)

    # Parse --due and imply --check
    args.due_days = None
    if args.due:
        try:
            args.due_days = parse_days(args.due)
        except ValueError as e:
            print(f"Error: --due: {e}", file=sys.stderr)
            sys.exit(1)
        args.check = True

    # Validate --track related args
    if args.full_at and not args.track:
        print("Error: --full-at requires --track.", file=sys.stderr)
        sys.exit(1)
    if args.every != "60m" and not args.track:
        print("Error: --every requires --track.", file=sys.stderr)
        sys.exit(1)
    if args.budget and args.track and not args.full_at:
        print("Error: --budget with --track requires --full-at.", file=sys.stderr)
        sys.exit(1)

    target_dir = _resolve(args.path)
    if not os.path.isdir(target_dir):
        print(f"Error: '{target_dir}' is not a directory.", file=sys.stderr)
        sys.exit(EXIT_IO)

    # Resolve --exclude paths relative to the target directory
    exclude_dirs: Set[str] = set()
    for exc in args.exclude:
        if os.path.isabs(exc):
            exclude_dirs.add(_resolve(exc))
        else:
            exclude_dirs.add(_resolve(os.path.join(target_dir, exc)))
    args.exclude_dirs = exclude_dirs

    db_name = "." + os.path.basename(target_dir) + DB_FILENAME_SUFFIX
    db_path = args.db or os.path.join(target_dir, db_name)
    # Auto-migrate a pre-1.1 .{dirname}_checksums.db if the user hasn't
    # overridden --db. No-op when nothing to migrate; emits a one-line
    # notice when it acts. Runs before any lock or DB open.
    if not args.db:
        _migrate_legacy_db_name(db_path)
    lock_path = db_path + ".lock"

    # --track doesn't need the database or lock — it just generates config
    if args.track:
        try:
            every_seconds = parse_duration(args.every)
        except ValueError as e:
            print(f"Error: --every: {e}", file=sys.stderr)
            sys.exit(1)

        full_at_times = None
        if args.full_at:
            full_at_times = []
            for t in args.full_at:
                try:
                    full_at_times.append(parse_clock_time(t))
                except ValueError as e:
                    print(f"Error: --full-at: {e}", file=sys.stderr)
                    sys.exit(1)

        rotbyte_exe = _find_rotbyte_executable()
        # Only pass --workers through if explicitly set (not the default)
        track_workers = args.workers if args.workers != (os.cpu_count() or 4) else None
        _run_track(target_dir, every_seconds, full_at_times,
                   args.budget_seconds, rotbyte_exe, workers=track_workers,
                   due_days=args.due_days, notify=args.notify,
                   auto_export=args.auto_export,
                   run_on_battery=args.run_on_battery)
        return

    # Acquire file lock to prevent concurrent runs
    lock = FileLock(lock_path)
    if not lock.acquire():
        print("Error: Another instance is already running against this database.", file=sys.stderr)
        print(f"  If this is a mistake, remove: {lock_path}", file=sys.stderr)
        sys.exit(EXIT_DB_LOCKED)

    try:
        _run(args, target_dir, db_path)
    finally:
        lock.release()


def _run(args: argparse.Namespace, target_dir: str, db_path: str):
    """Core logic, called with the file lock held."""

    # Open or create the database, catching corruption at connect time.
    # Integrity failures at open or via PRAGMA exit with code 4 so that
    # automation can distinguish a corrupted tripwire from normal findings.
    try:
        db = ChecksumDB(db_path)
    except sqlite3.DatabaseError as e:
        print(f"Error: Could not open database — {e}", file=sys.stderr)
        print(f"  Path: {db_path}", file=sys.stderr)
        print("  The database file appears corrupt.", file=sys.stderr)
        print("  Recovery options:", file=sys.stderr)
        print(f"    1. Restore {os.path.basename(db_path)} from your backup", file=sys.stderr)
        print("    2. Re-run rotbyte --import against an exported manifest", file=sys.stderr)
        print("    3. Delete the database file to start fresh (loses history)", file=sys.stderr)
        sys.exit(EXIT_DB_CORRUPT)

    # Catch subtler corruption that doesn't prevent opening. Runs on every
    # invocation — PRAGMA quick_check is milliseconds even on large DBs.
    if not db.verify_integrity():
        print("Error: Database failed integrity check.", file=sys.stderr)
        print(f"  Path: {db_path}", file=sys.stderr)
        print("  The database is internally inconsistent.", file=sys.stderr)
        print("  Recovery options:", file=sys.stderr)
        print(f"    1. Restore {os.path.basename(db_path)} from your backup", file=sys.stderr)
        print("    2. Re-run rotbyte --import against an exported manifest", file=sys.stderr)
        print("    3. Delete the database file to start fresh (loses history)", file=sys.stderr)
        db.close()
        sys.exit(EXIT_DB_CORRUPT)

    # Informational one-liner when the DB lives on a different volume than
    # the data it tracks — the recommended durability pattern. Silent when
    # they share a volume (no nagging users on default layouts). Suppressed
    # in quiet and JSON modes.
    if not getattr(args, "quiet", False) and not getattr(args, "json_output", False):
        try:
            if os.stat(target_dir).st_dev != os.stat(db_path).st_dev:
                print("  DB on separate volume: ✓")
        except OSError:
            pass

    # ── Dispatch to the requested mode ─────────────────────────────────
    if args.report:
        print_report(db, stale_days=getattr(args, "due_days", None) or 90)
        db.close()
        return

    if args.export:
        _run_export(db, args.export)
        db.close()
        return

    if args.accept_all:
        _run_accept_all(db, target_dir)
        db.close()
        return

    if args.accept:
        _run_accept_one(db, target_dir, args.accept)
        db.close()
        return

    if args.verify_file:
        _run_verify_file(db, args.verify_file)
        db.close()
        return

    if args.import_hashes:
        _run_import(db, target_dir, args.include_hidden, args.exclude_dirs)
        db.close()
        return

    # ── Normal scan mode ───────────────────────────────────────────────
    db.check_interrupted_run()

    # Set up clean shutdown on Ctrl+C / SIGTERM. Uses a mutable list
    # because signal handlers can't rebind a closure variable.
    interrupted: List[bool] = [False]

    def handle_signal(signum, frame):
        if interrupted[0]:
            # Second interrupt — abort immediately
            print("\n  Aborting immediately.\n", file=sys.stderr)
            sys.exit(EXIT_INTERRUPTED)
        interrupted[0] = True
        print("\n\n  Interrupt received — finishing current batch and saving progress...")
        print("  Press Ctrl-C again to abort immediately.\n")

    # SIGTERM is POSIX-only; Windows delivers CTRL_BREAK_EVENT etc. instead.
    # We register SIGINT everywhere and SIGTERM only where it exists.
    prev_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, handle_signal)
    prev_sigterm = None
    if not _IS_WINDOWS:
        prev_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, handle_signal)

    try:
        with PreventSleep():
            _run_phases(db, target_dir, args, interrupted)
    finally:
        signal.signal(signal.SIGINT, prev_sigint)
        if not _IS_WINDOWS and prev_sigterm is not None:
            signal.signal(signal.SIGTERM, prev_sigterm)
        db.close()


def _auto_export_manifest(db: ChecksumDB, manifest_path: str,
                          args: argparse.Namespace) -> None:
    """Write a b2sum-compatible manifest of all non-MISSING tracked files.

    Same format as --export but written automatically next to the DB.
    Uses atomic write (tmp file + rename) so a crash mid-export doesn't
    leave a truncated manifest in place of a valid one.
    """
    records = db.all_records()
    tmp_path = manifest_path + ".tmp"
    count = 0
    with open(tmp_path, "w") as f:
        for r in records:
            if r["status"] == "MISSING":
                continue
            f.write(f"{r['baseline_checksum']}  {r['file_path']}\n")
            count += 1
    os.replace(tmp_path, manifest_path)
    if not getattr(args, "quiet", False) and not getattr(args, "json_output", False):
        print(f"  ✓ Auto-exported {count:,} checksums to {manifest_path}")


# ── Export mode ─────────────────────────────────────────────────────────────────

def _run_export(db: ChecksumDB, export_path: str):
    """Export a plain-text manifest of all tracked file checksums.

    Format is b2sum-compatible: one line per file with
    "<baseline_checksum>  <file_path>". This provides an independent
    copy of the trust anchor outside the SQLite database.
    """
    records = db.all_records()
    if not records:
        print("  Database is empty — nothing to export.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(export_path, "w") as f:
            for r in records:
                if r["status"] == "MISSING":
                    continue
                f.write(f"{r['baseline_checksum']}  {r['file_path']}\n")
    except OSError as e:
        print(f"Error: Could not write to {export_path} — {e}", file=sys.stderr)
        sys.exit(EXIT_IO)

    exported = sum(1 for r in records if r["status"] != "MISSING")
    print(f"  ✓ Exported {exported:,} checksums to {export_path}")


# ── Import mode ────────────────────────────────────────────────────────────────

def _run_import(db: ChecksumDB, target_dir: str, include_hidden: bool = False,
                exclude_dirs: Optional[Set[str]] = None):
    """Import existing .b2sum and .b2 hash files into the database.

    For each hash file, derives the media filename by stripping the
    extension (e.g. movie.mkv.b2sum → movie.mkv, movie.mkv.b2 → movie.mkv).
    Only imports if the media file exists in the same directory and our
    computed hash matches the stored hash. Deletes the hash file after
    successful import.
    """
    HASH_EXTENSIONS = (".b2sum", ".b2")

    exclude = exclude_dirs or set()
    now = _now()

    print("═" * 60)
    print("  rotbyte — Importing hash files")
    print("═" * 60)
    print()

    # Find all hash files, respecting hidden/exclude settings
    hash_files: List[str] = []
    for root, dirs, filenames in os.walk(target_dir, followlinks=False):
        if not include_hidden:
            dirs[:] = [d for d in dirs if not d.startswith(".")]
        dirs[:] = [d for d in dirs if _resolve(os.path.join(root, d)) not in exclude]
        for name in filenames:
            if name.endswith(HASH_EXTENSIONS) and (include_hidden or not name.startswith(".")):
                hash_files.append(os.path.join(root, name))
    hash_files.sort()

    if not hash_files:
        print("  No .b2sum or .b2 files found.")
        print()
        print("═" * 60)
        return

    print(f"  Found {len(hash_files):,} hash file{'s' if len(hash_files) != 1 else ''}.")
    print()

    imported = 0
    skipped = 0
    mismatched = 0
    errors = 0

    for hash_path in hash_files:
        hash_dir = os.path.dirname(hash_path)
        hash_name = os.path.basename(hash_path)

        # Strip the hash extension to get the media filename
        for ext in HASH_EXTENSIONS:
            if hash_name.endswith(ext):
                media_name = hash_name[:-len(ext)]
                break
        media_path = os.path.join(hash_dir, media_name)

        if not os.path.isfile(media_path):
            print(f"  ✗ No matching file: {media_name} (from {hash_name})")
            skipped += 1
            continue

        # Don't re-import files already tracked (unless MISSING/FAILED)
        existing_status = db.get_file_status(_resolve(media_path))
        if existing_status is not None and existing_status not in ("MISSING", "FAILED"):
            print(f"  – Already tracked: {media_path}")
            skipped += 1
            continue

        # Parse the hash (format: "<128 hex chars>  <filename>")
        try:
            with open(hash_path, "r") as f:
                content = f.read().strip()
        except OSError as e:
            print(f"  ✗ Cannot read {hash_path}: {e}")
            errors += 1
            continue

        if not content:
            print(f"  ✗ Empty file: {hash_path}")
            errors += 1
            continue

        first_line = content.splitlines()[0].strip()
        stored_hash = first_line.split()[0].lower()

        # BLAKE2b-512 produces a 128-character hex digest
        if len(stored_hash) != 128 or not all(c in "0123456789abcdef" for c in stored_hash):
            print(f"  ✗ Invalid hash in {hash_name} (expected 128 hex chars)")
            errors += 1
            continue

        # Hash the actual file and compare
        _, our_hash, h_size, h_mtime, hash_err = hash_file(media_path)
        if our_hash is None:
            if hash_err:
                print(f"  ✗ Could not read {media_name}: {hash_err}")
            errors += 1
            continue

        if our_hash != stored_hash:
            print(f"  ✗ MISMATCH: {media_name}")
            print(f"      expected: {stored_hash[:32]}...")
            print(f"      computed: {our_hash[:32]}...")
            mismatched += 1
            continue

        # Hashes match — import into the database
        media_real = _resolve(media_path)

        if existing_status in ("MISSING", "FAILED"):
            db.accept_file(media_real, our_hash, h_size, h_mtime, now)
        else:
            db.upsert_file(
                media_real, os.path.basename(media_real), h_size,
                h_mtime, our_hash, None, "OK", now,
            )

        # Delete the hash file now that the checksum is in the database
        try:
            os.unlink(hash_path)
        except OSError as e:
            print(f"  ✓ Imported but could not delete {hash_name}: {e}")
            imported += 1
            continue

        print(f"  ✓ Imported: {media_name}")
        imported += 1

    print()
    print("═" * 60)
    print(f"  Imported   : {imported:,}")
    if skipped:
        print(f"  Skipped    : {skipped:,}")
    if mismatched:
        print(f"  Mismatched : {mismatched:,}  (hash did not match file)")
    if errors:
        print(f"  Errors     : {errors:,}")
    print("═" * 60)


# ── Accept modes ───────────────────────────────────────────────────────────────

def _run_accept_one(db: ChecksumDB, target_dir: str, file_arg: str):
    """Accept a single file's current state as correct.

    MISSING → removes the record (you intentionally deleted it).
    FAILED  → re-hashes and stores the new checksum as known-good.
    """
    file_path = _resolve(file_arg)
    now = _now()

    status = db.get_file_status(file_path)
    if status is None:
        print(f"  '{file_arg}' is not tracked in the database.", file=sys.stderr)
        sys.exit(1)

    if status == "MISSING":
        db.purge_file(file_path)
        print(f"  ✓ Removed missing record: {file_path}")

    elif status == "FAILED":
        if not os.path.isfile(file_path):
            print(f"  File not found on disk: {file_path}", file=sys.stderr)
            sys.exit(EXIT_IO)

        _, digest, h_size, h_mtime, hash_err = hash_file(file_path)
        if digest is None:
            print(f"  Error reading file: {hash_err or 'unknown error'}",
                  file=sys.stderr)
            sys.exit(EXIT_IO)

        db.accept_file(file_path, digest, h_size, h_mtime, now)
        print(f"  ✓ Accepted: {file_path}")

    else:
        print(f"  '{file_arg}' has status '{status}' — nothing to accept.")


def _discover_db_for_file(file_arg: str) -> str:
    """Discover the rotbyte database for a given file path.

    Search order:
    1. Current working directory for .{dirname}_rotbyte.db
    2. Each ancestor directory of the file, checking for .{dirname}_rotbyte.db
    3. As a fallback, the legacy .{dirname}_checksums.db name is also checked
       at each step. When a legacy file is found, it is auto-migrated in
       place before being returned.

    Returns the database path, or exits with an error if none is found.
    """
    def _check_dir(d: str) -> Optional[str]:
        base = os.path.basename(d)
        new_path = os.path.join(d, "." + base + DB_FILENAME_SUFFIX)
        if os.path.isfile(new_path):
            return new_path
        legacy_path = os.path.join(d, "." + base + LEGACY_DB_FILENAME_SUFFIX)
        if os.path.isfile(legacy_path):
            _migrate_legacy_db_name(new_path)
            if os.path.isfile(new_path):
                return new_path
        return None

    # 1. Check current working directory
    found = _check_dir(os.getcwd())
    if found:
        return found

    # 2. Walk up from the file's resolved location
    search_dir = os.path.dirname(_resolve(file_arg))
    while True:
        found = _check_dir(search_dir)
        if found:
            return found
        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break  # reached filesystem root
        search_dir = parent

    print(f"Error: No rotbyte database found for '{file_arg}'.", file=sys.stderr)
    print("  Run 'rotbyte <directory>' first to create a database.", file=sys.stderr)
    sys.exit(1)


def _run_verify_file(db: ChecksumDB, file_arg: str):
    """Verify a single file's integrity against the database.

    Looks up the file by its absolute path, hashes it, and compares against
    the stored baseline_checksum (the known-good hash).

    Exit codes: 0 = OK, 2 = checksum mismatch, 1 = error (not tracked, not found, read error).
    """
    file_path = _resolve(file_arg)
    now = _now()

    record = db.get_file_record(file_path)
    if record is None:
        print(f"  '{file_arg}' is not tracked in the database.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(file_path):
        # Semantically this is "file that was tracked is gone" — code 1
        # (MISSING), not 6 (I/O). Keep the legacy mapping.
        print(f"  File not found on disk: {file_path}", file=sys.stderr)
        sys.exit(EXIT_MISSING)

    _, digest, _h_size, _h_mtime, hash_err = hash_file(file_path)
    if digest is None:
        print(f"  Error reading file: {hash_err or 'unknown error'}",
              file=sys.stderr)
        sys.exit(EXIT_IO)

    baseline = record["baseline_checksum"]
    if digest == baseline:
        db.update_last_verified(file_path, now)
        print(f"  ✓ OK: {file_path}")
    else:
        print(f"  ✗ FAILED: {file_path}", file=sys.stderr)
        print(f"    Expected : {baseline}", file=sys.stderr)
        print(f"    Got      : {digest}", file=sys.stderr)
        sys.exit(EXIT_BIT_ROT)


def _run_accept_all(db: ChecksumDB, target_dir: str):
    """Accept the entire current filesystem state as the new baseline.

    Removes all MISSING records and re-hashes all FAILED files to store
    their current content as the new known-good checksum.
    """
    now = _now()
    print("═" * 60)
    print("  rotbyte — Accepting all current state as baseline")
    print("═" * 60)
    print()

    purged = db.purge_missing(target_dir)
    if purged:
        print(f"  Cleared {purged:,} missing file record{'s' if purged != 1 else ''}.")

    failed_paths = db.get_failed_paths(target_dir)
    accepted = 0
    errors = 0

    if failed_paths:
        with db.transaction():
            for fpath in failed_paths:
                _, digest, h_size, h_mtime, hash_err = hash_file(fpath)
                if digest is None:
                    suffix = f": {hash_err}" if hash_err else ""
                    print(f"  ! Cannot read {fpath}{suffix} — skipping.")
                    errors += 1
                    continue

                db.accept_file(fpath, digest, h_size, h_mtime, now)
                accepted += 1
                print(f"  ✓ Accepted: {fpath}")

    if not purged and not accepted and not errors:
        print("  Nothing to reconcile — no MISSING or FAILED files.")

    print()
    print("═" * 60)
    print(f"  Missing cleared : {purged:,}")
    print(f"  Failed accepted : {accepted:,}")
    if errors:
        print(f"  Errors          : {errors:,}")
    print("═" * 60)


# ── Interactive --track wizard ─────────────────────────────────────────────────

def _run_track_setup(path_arg: str):
    """Interactive setup wizard for --track.

    Collects the same inputs --track accepts as flags, validating each with
    the existing parsers, then calls _run_track() to perform the actual
    platform install. No install logic is duplicated here.
    """
    from typing import Tuple

    print("═" * 60)
    print("  rotbyte — Scheduled scan setup")
    print("═" * 60)
    print()
    print("  This wizard installs scheduled scans via launchd (macOS)")
    print("  or systemd (Linux). Press Ctrl-C at any prompt to abort.")
    print()

    # 1. Target directory
    default_dir = _resolve(path_arg)
    raw = input(f"  Directory to scan [{default_dir}]: ").strip()
    target_dir = _resolve(raw) if raw else default_dir
    if not os.path.isdir(target_dir):
        print(f"Error: '{target_dir}' is not a directory.", file=sys.stderr)
        sys.exit(EXIT_IO)

    # 2. Quick scan frequency
    while True:
        raw = input("  Quick scan frequency [60m]: ").strip() or "60m"
        try:
            every_seconds = parse_duration(raw)
            every_display = raw
            break
        except ValueError as e:
            print(f"  Invalid duration: {e}")

    # 3. Full scan clock times (optional)
    full_at_times: Optional[List[Tuple[int, int]]] = None
    full_at_display: List[str] = []
    while True:
        raw = input("  Full scan clock times, space-separated (e.g. 2h 14h) [none]: ").strip()
        if not raw:
            break
        try:
            full_at_times = [parse_clock_time(t) for t in raw.split()]
            full_at_display = raw.split()
            break
        except ValueError as e:
            print(f"  Invalid clock time: {e}")

    # 4. Budget (only meaningful with full scans)
    budget_seconds: Optional[int] = None
    budget_display: Optional[str] = None
    if full_at_times:
        while True:
            raw = input("  Time budget per full scan (e.g. 2h) [none]: ").strip()
            if not raw:
                break
            try:
                budget_seconds = parse_duration(raw)
                budget_display = raw
                break
            except ValueError as e:
                print(f"  Invalid duration: {e}")

    # 5. Due threshold
    due_days: Optional[int] = None
    due_display: Optional[str] = None
    while True:
        raw = input("  Re-verify files not checked within (e.g. 30d) [none]: ").strip()
        if not raw:
            break
        try:
            due_days = parse_days(raw)
            due_display = raw
            break
        except ValueError as e:
            print(f"  Invalid --due value: {e}")

    # 6. Email notifications (optional)
    notify: Optional[str] = None
    raw = input("  Send email on problems? [y/N]: ").strip().lower()
    if raw in ("y", "yes"):
        cfg_path = _notify_config_path()
        if not os.path.exists(cfg_path):
            print(f"  Email isn't configured yet ({cfg_path} not found).")
            print("  Run 'rotbyte --notify-setup email' first, then re-run --track-setup.")
            print("  Continuing without email notifications.")
        else:
            notify = "email"

    # 7. Confirmation summary
    rotbyte_exe = _find_rotbyte_executable()
    # _find_rotbyte_executable returns an argument list; a plain string is
    # tolerated (tests stub it that way) for the echoed command below.
    exe_display = (rotbyte_exe if isinstance(rotbyte_exe, str)
                   else " ".join(rotbyte_exe))
    cli_parts = [exe_display, "--track", "--every", every_display]
    if full_at_display:
        cli_parts.extend(["--full-at", *full_at_display])
    if budget_display:
        cli_parts.extend(["--budget", budget_display])
    if due_display:
        cli_parts.extend(["--due", due_display])
    if notify:
        cli_parts.extend(["--notify", notify])
    cli_parts.append(target_dir)

    print()
    print("  Equivalent command:")
    print(f"    {' '.join(cli_parts)}")
    print()
    raw = input("  Install? [Y/n]: ").strip().lower()
    if raw in ("n", "no"):
        print("  Aborted.")
        return

    # 8. Install via the existing code path
    _run_track(target_dir, every_seconds, full_at_times, budget_seconds,
               rotbyte_exe, workers=None, due_days=due_days, notify=notify)


# ── --status dispatch ──────────────────────────────────────────────────────────

def _schedule_health_label(entry: dict) -> str:
    """One-word-ish health label for a discovered schedule entry.

    "active ✓" previously meant only "the unit is loaded" — a job whose
    every run dies at exec (e.g. a Homebrew upgrade deleted the pinned
    Cellar path) still read as healthy. Distinguish:

      - BROKEN ✗   — the scheduled command's executable no longer exists
      - active ⚠   — loaded, but the last run exited non-zero
      - active ✓   — loaded and last run (if any) succeeded
      - inactive ✗ — not loaded
    """
    if entry.get("missing_exe"):
        return "BROKEN ✗"
    if not entry.get("active"):
        return "inactive ✗"
    last_exit = entry.get("last_exit")
    if last_exit not in (None, 0):
        return f"active ⚠ (last run exited {last_exit})"
    return "active ✓"


def _run_status():
    """Display status of all tracked directories with schedule and health info.

    Discovers installed scheduler configs, opens each target's database,
    and reports schedule, last activity, and file health.
    """
    if not (_IS_MACOS or _IS_LINUX or _IS_WINDOWS):
        print(f"Error: --status is not supported on {sys.platform}.", file=sys.stderr)
        sys.exit(EXIT_IO)

    # Discover all tracked directories grouped by hash
    if _IS_WINDOWS:
        tracked = _discover_schtasks()
    else:
        tracked = _discover_tracked(_IS_MACOS)

    if not tracked:
        print("  No scheduled scans found.")
        print()
        print("  Use --track to set up scheduled scanning:")
        print("    rotbyte --track /path/to/directory")
        return

    print()
    print("═" * 60)
    print("  rotbyte — Status")
    print("═" * 60)

    for target_dir, info in sorted(tracked.items()):
        print()
        print(f"  {target_dir}")

        # Quick scan info
        if info.get("quick"):
            q = info["quick"]
            print(f"    Quick : every {_format_duration(q['interval'])}".ljust(40)
                  + _schedule_health_label(q))
        else:
            print(f"    Quick : (not configured)")

        # Full scan info
        if info.get("full"):
            f = info["full"]
            times_str = ", ".join(
                _format_clock_time(h, m) for h, m in f["times"]
            ) if f.get("times") else "scheduled"
            print(f"    Full  : daily at {times_str}".ljust(40)
                  + _schedule_health_label(f))
            # Show extra flags
            extras = []
            if f.get("due"):
                extras.append(f"--due {f['due']}")
            if f.get("budget"):
                extras.append(f"--budget {f['budget']}")
            if f.get("workers"):
                extras.append(f"--workers {f['workers']}")
            if extras:
                print(f"            {' '.join(extras)}")
            # Next fire time — only meaningful for a loaded, non-broken
            # calendar schedule (interval timers fire relative to an opaque
            # load time the scheduler doesn't expose, so quick scans can't
            # show this reliably).
            if f.get("times") and f.get("active") and not f.get("missing_exe"):
                nxt = _next_calendar_run(f["times"], datetime.now().astimezone())
                if nxt:
                    ndt, secs = nxt
                    print(f"            next {_format_clock_time(ndt.hour, ndt.minute)}"
                          f" (in {_format_duration(secs)})")
        else:
            print(f"    Full  : (not configured)")

        # Notification state — shown for every tracked dir so a schedule
        # installed without --notify is visible rather than silently mute.
        notify_val = ((info.get("full") or {}).get("notify")
                      or (info.get("quick") or {}).get("notify"))
        if notify_val:
            print(f"    Notify: {notify_val}")
        else:
            print("    Notify: (off — re-run --track with --notify email to enable)")

        # A schedule whose command no longer exists fails at exec on every
        # run — say so loudly, with the remedy.
        missing = ((info.get("quick") or {}).get("missing_exe")
                   or (info.get("full") or {}).get("missing_exe"))
        if missing:
            print(f"    ⚠ Scheduled command is broken: {missing} no longer exists.")
            print(f"      Every scheduled run is failing. Re-run --track for this")
            print(f"      directory to regenerate the schedule.")

        # Database health
        db_name = "." + os.path.basename(target_dir) + DB_FILENAME_SUFFIX
        db_path = os.path.join(target_dir, db_name)

        if not os.path.isfile(db_path):
            print(f"    Last  : no database yet (first scan has not run)")
            continue

        try:
            db = ChecksumDB(db_path)
        except sqlite3.DatabaseError:
            print(f"    Last  : database error (may be corrupt)")
            continue

        try:
            # Prefer the actual last-run time (when a scan process finished)
            # over max(last_verified): a run that verified nothing new still
            # updates finished_at, and it distinguishes "finished" from
            # "started but never completed" (in progress or hard-killed).
            run = db.last_run_info()
            if run and run.get("finished_at"):
                print(f"    Last  : {_utc_to_local(run['finished_at'])}")
            elif run and run.get("status") == "RUNNING" and run.get("started_at"):
                print(f"    Last  : started {_utc_to_local(run['started_at'])}"
                      f" — in progress or interrupted")
            else:
                # Legacy DB with no last_run row: fall back to newest file
                # verification time.
                last = db.last_activity()
                if last:
                    print(f"    Last  : {_utc_to_local(last)}")
                else:
                    print(f"    Last  : no scans completed yet")

            counts = db.status_counts()
            if counts:
                parts = []
                ok = counts.get("OK", 0)
                if ok:
                    parts.append(f"{ok:,} OK")
                new = counts.get("NEW", 0)
                if new:
                    # NEW = indexed but not yet re-verified against a baseline.
                    # Folding it into OK (as before) hid files that have never
                    # actually been checked for rot; show it distinctly.
                    parts.append(f"{new:,} NEW")
                failed = counts.get("FAILED", 0)
                if failed:
                    parts.append(f"{failed:,} FAILED")
                missing = counts.get("MISSING", 0)
                if missing:
                    parts.append(f"{missing:,} MISSING")
                print(f"    Files : {' · '.join(parts)}")

                # Show failed file paths
                if failed:
                    failed_list = db.failed_files()
                    for ff in failed_list[:5]:
                        print(f"      ⚠ {ff['file_path']}")
                    if len(failed_list) > 5:
                        print(f"      ... and {len(failed_list) - 5} more")

            # Show verification freshness when --due is configured
            due_str = info.get("full", {}).get("due")
            if due_str:
                try:
                    due_days = parse_days(due_str)
                    total, verified, due_count = db.freshness_stats(target_dir, due_days)
                    pct = (verified / total * 100) if total else 0.0
                    print(f"    Fresh : {verified:,} / {total:,} files verified within {due_str} window ({pct:.1f}%)")
                    print(f"            {due_count:,} files due for re-verification")
                except ValueError:
                    pass
        finally:
            db.close()

    print()
    print("═" * 60)


# ── Scan pipeline ──────────────────────────────────────────────────────────────

def _run_phases(db: ChecksumDB, target_dir: str, args: argparse.Namespace,
                interrupted: List[bool]):
    """Execute the three verification phases: scan, hash, detect missing."""

    quiet = args.quiet or args.json_output
    budget_seconds = getattr(args, "budget_seconds", None)
    due_days = getattr(args, "due_days", None)
    case_insensitive = getattr(args, "case_insensitive", False)

    if not quiet:
        print("═" * 60)
        print("  rotbyte")
        print("═" * 60)
        print(f"  Directory  : {target_dir}")
        print(f"  Database   : {db.db_path}")
        print(f"  Workers    : {args.workers}")
        mode = "full re-verify (--check)" if args.check else "quick (changed files only)"
        if due_days:
            mode = f"due files only (not verified in {due_days}d)"
        if budget_seconds:
            mode += f"  ·  budget {_format_duration(budget_seconds)}"
        print(f"  Mode       : {mode}")
        print("═" * 60)
        print()

    # ── Phase 1: Scan filesystem and compare against database ──────────
    with Spinner("Scanning filesystem", quiet=quiet) as sp:
        all_files = scan_files(target_dir, db.db_path, args.include_hidden,
                               args.exclude_dirs,
                               case_insensitive=case_insensitive)
        sp.set_suffix(f"  {len(all_files):,} files")

    with Spinner("Loading database", quiet=quiet) as sp:
        existing = db.load_all_records(target_dir)
        sp.set_suffix(f"  {len(existing):,} tracked")

    with Spinner("Comparing", quiet=quiet) as sp:
        to_hash, skip_count = prescan_files(all_files, existing, args.check)
        sp.set_suffix(f"  {len(to_hash):,} to hash, {skip_count:,} unchanged")

    # When --due is set, filter to only files that haven't been verified
    # within the threshold. New files (not yet in DB) are always included.
    due_start_count = 0
    if due_days:
        with Spinner(f"Filtering to files due for re-verify ({due_days}d)", quiet=quiet) as sp:
            due_paths = db.due_file_paths(target_dir, due_days)
            # Snapshot the "overdue at scan start" count so the email layer
            # can later report done/start progress even if budget or errors
            # leave some files still due.
            due_start_count = len(due_paths)
            before = len(to_hash)
            to_hash = [e for e in to_hash if e.old_checksum is None or e.path in due_paths]
            filtered = before - len(to_hash)
            skip_count += filtered
            sp.set_suffix(f"  {len(to_hash):,} due, {filtered:,} recently verified")

    # When using a time budget with --check, prioritize the stalest files
    # so each run covers the files that haven't been verified in the longest
    # time. Over successive runs, the entire database gets covered.
    if budget_seconds and args.check and len(to_hash) > 1:
        with Spinner("Sorting by stalest first", quiet=quiet):
            stalest_order = db.stalest_file_paths(target_dir)
            stalest_rank = {p: i for i, p in enumerate(stalest_order)}
            # New files (not in DB yet) go last — they have no staleness
            max_rank = len(stalest_order)
            to_hash.sort(key=lambda e: stalest_rank.get(e.path, max_rank))

    if not quiet:
        print()

    # ── Phase 2: Hash files and record results ─────────────────────────
    db.start_run(target_dir)
    now = _now()
    start_time = time.monotonic()
    try:
        result = run_hashing(db, to_hash, args.workers, now, interrupted, quiet,
                             budget_seconds=budget_seconds)
    except Exception as e:
        # Unexpected worker-pool or orchestration failure — exit with the
        # dedicated internal-error code so automation can distinguish it
        # from normal scan findings.
        print(f"\nError: hashing phase failed unexpectedly: {e}", file=sys.stderr)
        db.close()
        sys.exit(EXIT_INTERNAL)

    # ── Phase 3: Detect missing files ──────────────────────────────────
    count_missing = 0
    if not interrupted[0] and not args.skip_missing:
        with Spinner("Checking for missing files", quiet=quiet):
            count_missing = detect_missing(db, target_dir, set(all_files), existing, now)

    # Capture the previous run's problem counts before finish_run overwrites
    # them, so the notification can report the change ("bit rot 1 → 3").
    previous_counts = db.previous_run_counts()
    db.finish_run(failed=result.failed, missing=count_missing)

    # ── Summary ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start_time
    has_problems = result.failed > 0 or count_missing > 0 or interrupted[0]

    # ── Email notification (if configured) ─────────────────────────────
    if args.notify == "email":
        # Full re-verifies always notify; scheduled quick scans only notify
        # when problems are found. --full-at is an install-time flag and is
        # not passed to scheduled commands, so check args.check instead.
        suppress = (
            getattr(args, "scheduled", False)
            and not args.check
            and not has_problems
        )
        if suppress:
            if not quiet:
                print("  Skipping email notification (scheduled quick scan, no problems)")
        else:
            failed_details = db.failed_files() if result.failed > 0 else []
            freshness = db.freshness_stats(target_dir, due_days) if due_days else None
            due_progress = None
            if due_days and due_start_count > 0:
                due_end_count = len(db.due_file_paths(target_dir, due_days))
                due_done = max(due_start_count - due_end_count, 0)
                due_progress = (due_done, due_start_count)
            scan_stats = {
                "ok": result.ok,
                "new": result.new,
                "updated": result.updated,
                "skipped": skip_count,
                "bytes_hashed": result.bytes_hashed,
            }
            _send_email_notification(
                target_dir, result.failed, count_missing,
                failed_details,
                freshness=freshness,
                elapsed_seconds=elapsed,
                due_progress=due_progress,
                interrupted=interrupted[0],
                budget_exceeded=result.budget_exceeded,
                errors=result.errors,
                stats=scan_stats,
                scan_time=time.strftime("%Y-%m-%d %H:%M %Z", time.localtime()),
                previous_counts=previous_counts,
            )

    if args.json_output:
        likely_moves = 0
        if result.new > 0 and count_missing > 0:
            likely_moves = db.detect_likely_moves(target_dir)
        summary = {
            "status": "interrupted" if interrupted[0] else "complete",
            "directory": target_dir,
            "duration_seconds": round(elapsed, 2),
            "bytes_hashed": result.bytes_hashed,
            "new": result.new,
            "updated": result.updated,
            "verified_ok": result.ok,
            "failed": result.failed,
            "missing": count_missing,
            "skipped": skip_count,
            "errors": result.errors,
            "likely_moves": likely_moves,
        }
        if result.failed > 0:
            summary["failed_files"] = [
                f["file_path"] for f in db.failed_files()
            ]
        print(json.dumps(summary, indent=2))
    elif not quiet or has_problems:
        if not quiet:
            print()
        print("═" * 60)
        print(f"  {'Interrupted' if interrupted[0] else 'Complete'}")
        print("═" * 60)
        if not quiet:
            print(f"  Duration     : {_format_duration(elapsed)}")
            print(f"  Data hashed  : {_format_size(result.bytes_hashed)}")
            if elapsed > 0 and result.bytes_hashed > 0:
                print(f"  Throughput   : {_format_size(result.bytes_hashed / elapsed)}/s")
            print("  ──────────────────────────────────────────────────────")
            print(f"  New files    : {result.new:,}")
            print(f"  Updated      : {result.updated:,}  (edits detected and accepted)")
            print(f"  Verified OK  : {result.ok:,}")
        print(f"  FAILED       : {result.failed:,}")
        if not quiet:
            print(f"  Skipped      : {skip_count:,}  (unchanged since last run)")
        print(f"  Missing      : {count_missing:,}")
        if not quiet:
            print(f"  Errors       : {result.errors:,}  (could not read/hash)")
        print("═" * 60)

        # A --budget scan that ran out of time verified only the stalest
        # files. That was previously visible only in the email; say so at
        # the terminal too so a truncated run isn't mistaken for a full one.
        if not quiet:
            for line in _budget_cutoff_note(getattr(result, "budget_exceeded", False)):
                print(line)

        # Hint about likely renames when new files match missing checksums
        if result.new > 0 and count_missing > 0:
            likely_moves = db.detect_likely_moves(target_dir)
            if likely_moves > 0:
                print()
                s = "s" if likely_moves != 1 else ""
                verb = "match" if likely_moves != 1 else "matches"
                print(f"  Note: {likely_moves:,} new file{s} {verb}"
                      f" the checksum of missing files.")
                print("  This usually means files were renamed or moved.")
                print("  Run --accept-all to clear, or --report for details.")

    # --auto-export: write the b2sum-compatible manifest before exit so
    # the independent backup stays fresh after every full --check. Skip
    # on interrupt (partial manifests would be misleading) and skip on
    # quick scans (the checksum set hasn't meaningfully changed).
    if (getattr(args, "auto_export", False) and args.check
            and not interrupted[0]):
        manifest_path = db.db_path + ".manifest"
        try:
            _auto_export_manifest(db, manifest_path, args)
        except OSError as e:
            print(f"  ! auto-export failed: {e}", file=sys.stderr)

    if result.failed > 0:
        print()
        print("⚠  BIT ROT DETECTED — run with --report for details.")
        sys.exit(EXIT_BIT_ROT)
    if interrupted[0]:
        print()
        print("  Run again to resume where you left off.")
        sys.exit(EXIT_INTERRUPTED)
    if count_missing > 0:
        sys.exit(EXIT_MISSING)
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
