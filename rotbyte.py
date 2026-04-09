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

The database (.{dirname}_checksums.db) is created automatically inside
the target directory on first run.

Requires Python 3.9+ and a POSIX system (macOS or Linux).
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import sqlite3
import sys
import threading
import time
import fcntl
from concurrent.futures import ProcessPoolExecutor, as_completed, BrokenExecutor
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

# ── Constants ──────────────────────────────────────────────────────────────────

# Database schema: two tables.
#   checksums  — one row per tracked file with its hash, metadata, and status.
#   last_run   — single row tracking whether the previous run completed,
#                so we can warn if it was interrupted.
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS checksums (
    file_path       TEXT    PRIMARY KEY,
    file_name       TEXT    NOT NULL,
    file_size       INTEGER NOT NULL,
    file_mtime      TEXT    NOT NULL,
    checksum        TEXT    NOT NULL,
    baseline_checksum TEXT,
    algorithm       TEXT    NOT NULL DEFAULT 'BLAKE2b',
    status          TEXT    NOT NULL DEFAULT 'NEW',
    first_seen      TEXT    NOT NULL,
    last_verified   TEXT    NOT NULL,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_status        ON checksums(status);
CREATE INDEX IF NOT EXISTS idx_last_verified ON checksums(last_verified);
CREATE INDEX IF NOT EXISTS idx_file_name     ON checksums(file_name);
CREATE INDEX IF NOT EXISTS idx_file_size     ON checksums(file_size);

CREATE TABLE IF NOT EXISTS last_run (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    started_at  TEXT    NOT NULL,
    finished_at TEXT,
    target_dir  TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'RUNNING'
);

CREATE TABLE IF NOT EXISTS schema_version (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL DEFAULT 1
);
"""

SCHEMA_VERSION = 2

VERSION = "1.0.0"
DB_FILENAME_SUFFIX = "_checksums.db"
HASH_BUFFER_SIZE = 1024 * 1024  # 1 MiB — balances syscall overhead vs memory
BATCH_SIZE = 200                # DB writes per transaction before committing


# ── Hashing (runs in worker processes) ─────────────────────────────────────────

def hash_file(file_path: str) -> Tuple[str, Optional[str], Optional[int], Optional[str]]:
    """Compute BLAKE2b-512 hash of a file.

    Returns (path, hex_digest, size, mtime_iso) on success or
    (path, None, None, None) on read error.

    Metadata is captured via fstat() on the open file descriptor so that
    the recorded size and mtime correspond to the exact bytes that were
    hashed — no TOCTOU gap between stat() and read().

    This function runs in a worker process via ProcessPoolExecutor and
    must not access the database or any shared mutable state.
    """
    try:
        h = hashlib.blake2b()
        with open(file_path, "rb") as f:
            st = os.fstat(f.fileno())
            while True:
                chunk = f.read(HASH_BUFFER_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return file_path, h.hexdigest(), st.st_size, _mtime_iso(st)
    except OSError as e:
        print(f"\n  ! Error reading {file_path}: {e}", file=sys.stderr)
        return file_path, None, None, None


# ── Database ───────────────────────────────────────────────────────────────────

class ChecksumDB:
    """SQLite database wrapper.

    All queries use parameterized placeholders (?) to prevent SQL injection
    from filenames. WAL journal mode allows concurrent reads during writes.
    Manual transaction control (begin/commit/rollback) enables batching
    many writes into a single transaction for performance.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-64000")   # 64 MB cache
        self.conn.execute("PRAGMA busy_timeout=5000")    # wait up to 5s on lock
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA_SQL)
        self._migrate()

    def _migrate(self):
        """Run any pending schema migrations.

        Existing databases without a schema_version table are treated as
        version 1. Migrations are applied sequentially up to SCHEMA_VERSION.
        """
        row = self.conn.execute(
            "SELECT version FROM schema_version WHERE id = 1"
        ).fetchone()

        if row is None:
            # New database or pre-versioning database. Check whether the
            # checksums table has data to distinguish the two cases.
            has_data = self.conn.execute(
                "SELECT 1 FROM checksums LIMIT 1"
            ).fetchone()
            current = 1 if has_data else SCHEMA_VERSION
            self.conn.execute(
                "INSERT INTO schema_version (id, version) VALUES (1, ?)",
                (current,),
            )
            if not has_data:
                return  # Fresh database, schema is already current
        else:
            current = row["version"]

        if current >= SCHEMA_VERSION:
            return

        # ── Migration 1 → 2: add baseline_checksum column ────────────
        if current < 2:
            # Check if column already exists (defensive)
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(checksums)")}
            if "baseline_checksum" not in cols:
                self.conn.execute(
                    "ALTER TABLE checksums ADD COLUMN baseline_checksum TEXT"
                )
            # For FAILED rows, the current checksum column holds the
            # known-good hash (old behavior). Move it to baseline_checksum.
            # For all other rows, baseline = checksum (they're the same).
            self.conn.execute(
                "UPDATE checksums SET baseline_checksum = checksum"
            )
            current = 2

        self.conn.execute(
            "UPDATE schema_version SET version = ? WHERE id = 1",
            (current,),
        )

    def verify_integrity(self) -> bool:
        """Quick integrity check on the database file itself."""
        result = self.conn.execute("PRAGMA quick_check").fetchone()
        return result is not None and result[0] == "ok"

    def close(self):
        self.conn.close()

    @staticmethod
    def _escape_like(prefix: str) -> str:
        """Escape SQL LIKE wildcards (%, _, \\) in a directory prefix.

        Ensures the prefix ends with os.sep so that '/Volumes/Media'
        does not match '/Volumes/Media2'.
        """
        if not prefix.endswith(os.sep):
            prefix += os.sep
        return prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    # ── Run tracking (single row, updated in place) ───────────────────────

    def check_interrupted_run(self):
        """Warn if the previous run was interrupted (status still RUNNING)."""
        row = self.conn.execute(
            "SELECT started_at FROM last_run WHERE id = 1 AND status = 'RUNNING'"
        ).fetchone()
        if row:
            print(f"  Note: A previous run from {row['started_at']} was interrupted.")
            print("  This run will re-check any files that were skipped.")
            print()

    def start_run(self, target_dir: str):
        """Mark a run as in progress. Overwrites any previous record."""
        self.conn.execute(
            "INSERT OR REPLACE INTO last_run (id, started_at, finished_at, target_dir, status) "
            "VALUES (1, ?, NULL, ?, 'RUNNING')",
            (_now(), target_dir),
        )

    def finish_run(self):
        """Mark the current run as complete."""
        self.conn.execute(
            "UPDATE last_run SET finished_at = ?, status = 'COMPLETE' WHERE id = 1",
            (_now(),),
        )

    # ── Bulk lookups ──────────────────────────────────────────────────────

    def load_all_records(self, prefix: str) -> Dict[str, Tuple[str, int, str, str]]:
        """Load all tracked records under a directory prefix.

        Returns {file_path: (baseline_checksum, file_size, file_mtime, status)}.
        Uses baseline_checksum for comparisons since it holds the known-good
        hash. Includes MISSING records so re-added files are verified against
        their baseline. Escapes SQL LIKE wildcards.
        """
        escaped = self._escape_like(prefix)
        rows = self.conn.execute(
            "SELECT file_path, baseline_checksum, file_size, file_mtime, status FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\'",
            (escaped + "%",),
        ).fetchall()
        return {r["file_path"]: (r["baseline_checksum"], r["file_size"], r["file_mtime"], r["status"]) for r in rows}

    def get_missing_paths(self, prefix: str) -> Set[str]:
        """Return all file paths currently marked MISSING under a prefix."""
        escaped = self._escape_like(prefix)
        rows = self.conn.execute(
            "SELECT file_path FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\' AND status = 'MISSING'",
            (escaped + "%",),
        ).fetchall()
        return {r["file_path"] for r in rows}

    # ── Transaction helpers ───────────────────────────────────────────────

    def begin(self):
        self.conn.execute("BEGIN")

    def commit(self):
        self.conn.execute("COMMIT")

    def rollback(self):
        try:
            self.conn.execute("ROLLBACK")
        except sqlite3.OperationalError:
            pass  # No active transaction

    # ── Writes ────────────────────────────────────────────────────────────

    def upsert_file(self, file_path: str, file_name: str, file_size: int,
                    file_mtime: str, checksum: str, old_checksum: Optional[str],
                    status: str, now: str):
        """Insert a new file or update an existing one.

        If old_checksum is provided, the file is already tracked — update it.
        Otherwise insert a new record.

        On FAILED, checksum stores the bad hash and baseline_checksum is
        left unchanged (preserving the known-good hash for restore
        verification). On all other statuses, both columns are updated
        to the current hash.
        """
        if old_checksum is not None:
            if status == "FAILED":
                self.conn.execute(
                    """UPDATE checksums
                       SET checksum = ?, file_size = ?, file_mtime = ?,
                           status = ?, last_verified = ?
                     WHERE file_path = ?""",
                    (checksum, file_size, file_mtime, status, now, file_path),
                )
            else:
                self.conn.execute(
                    """UPDATE checksums
                       SET checksum = ?, baseline_checksum = ?,
                           file_size = ?, file_mtime = ?,
                           status = ?, last_verified = ?
                     WHERE file_path = ?""",
                    (checksum, checksum, file_size, file_mtime, status, now, file_path),
                )
        else:
            self.conn.execute(
                """INSERT INTO checksums
                   (file_path, file_name, file_size, file_mtime, checksum,
                    baseline_checksum, algorithm, status, first_seen, last_verified)
                   VALUES (?, ?, ?, ?, ?, ?, 'BLAKE2b', ?, ?, ?)""",
                (file_path, file_name, file_size, file_mtime, checksum,
                 checksum, status, now, now),
            )

    def mark_missing(self, file_path: str, now: str):
        """Mark a tracked file as MISSING (only if not already MISSING)."""
        self.conn.execute(
            "UPDATE checksums SET status = 'MISSING', last_verified = ? "
            "WHERE file_path = ? AND status != 'MISSING'",
            (now, file_path),
        )

    def purge_missing(self, prefix: str) -> int:
        """Delete all MISSING records under a prefix. Returns count removed."""
        escaped = self._escape_like(prefix)
        cur = self.conn.execute(
            "DELETE FROM checksums WHERE file_path LIKE ? ESCAPE '\\' AND status = 'MISSING'",
            (escaped + "%",),
        )
        return cur.rowcount

    def accept_file(self, file_path: str, checksum: str, file_size: int,
                    file_mtime: str, now: str):
        """Accept a file's current content as the new known-good baseline."""
        self.conn.execute(
            """UPDATE checksums
               SET checksum = ?, baseline_checksum = ?,
                   file_size = ?, file_mtime = ?,
                   status = 'OK', last_verified = ?
             WHERE file_path = ?""",
            (checksum, checksum, file_size, file_mtime, now, file_path),
        )

    def get_failed_paths(self, prefix: str) -> List[str]:
        """Return all FAILED file paths under a prefix."""
        escaped = self._escape_like(prefix)
        rows = self.conn.execute(
            "SELECT file_path FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\' AND status = 'FAILED'",
            (escaped + "%",),
        ).fetchall()
        return [r["file_path"] for r in rows]

    def get_file_status(self, file_path: str) -> Optional[str]:
        """Return the status of a single file, or None if not tracked."""
        row = self.conn.execute(
            "SELECT status FROM checksums WHERE file_path = ?",
            (file_path,),
        ).fetchone()
        return row["status"] if row else None

    def purge_file(self, file_path: str):
        """Remove a single file's record from the database entirely."""
        self.conn.execute("DELETE FROM checksums WHERE file_path = ?", (file_path,))

    # ── Reporting queries ─────────────────────────────────────────────────

    def status_summary(self) -> List[Dict]:
        """Count of files grouped by status (OK, NEW, FAILED, MISSING)."""
        rows = self.conn.execute(
            "SELECT status, count(*) as count FROM checksums GROUP BY status ORDER BY count DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def failed_files(self) -> List[Dict]:
        """Return details for all FAILED files."""
        rows = self.conn.execute(
            "SELECT file_path, file_size, checksum, baseline_checksum, last_verified "
            "FROM checksums WHERE status = 'FAILED'"
        ).fetchall()
        return [dict(r) for r in rows]

    def stale_files(self, days: int) -> List[Dict]:
        """Return files not verified in the given number of days."""
        rows = self.conn.execute(
            "SELECT file_path, last_verified FROM checksums "
            "WHERE last_verified < datetime('now', ?)",
            (f"-{days} days",),
        ).fetchall()
        return [dict(r) for r in rows]

    def stalest_file_paths(self, prefix: str, limit: Optional[int] = None) -> List[str]:
        """Return file paths ordered by oldest last_verified first.

        Used by --budget mode to prioritize re-verifying the files that
        haven't been checked in the longest time. Only returns non-MISSING
        files under the given prefix.
        """
        escaped = self._escape_like(prefix)
        query = (
            "SELECT file_path FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\' AND status != 'MISSING' "
            "ORDER BY last_verified ASC"
        )
        params: list = [escaped + "%"]
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        rows = self.conn.execute(query, params).fetchall()
        return [r["file_path"] for r in rows]

    def due_file_paths(self, prefix: str, days: int) -> Set[str]:
        """Return paths not verified within the given number of days.

        Used by --due to select only files that are overdue for a full
        re-verify, avoiding redundant work on recently checked files.
        """
        escaped = self._escape_like(prefix)
        rows = self.conn.execute(
            "SELECT file_path FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\' AND status != 'MISSING' "
            "AND last_verified < datetime('now', ?)",
            (escaped + "%", f"-{days} days"),
        ).fetchall()
        return {r["file_path"] for r in rows}

    def detect_likely_moves(self, prefix: str) -> int:
        """Count NEW files whose checksum matches a MISSING file.

        A match strongly suggests a rename/move rather than a deletion
        and a new unrelated file. Returns the count of matches.
        """
        escaped = self._escape_like(prefix)
        row = self.conn.execute(
            "SELECT count(*) as count FROM checksums c1 "
            "WHERE c1.file_path LIKE ? ESCAPE '\\' AND c1.status = 'NEW' "
            "AND EXISTS ("
            "  SELECT 1 FROM checksums c2 "
            "  WHERE c2.file_path LIKE ? ESCAPE '\\' AND c2.status = 'MISSING' "
            "  AND c2.baseline_checksum = c1.baseline_checksum"
            ")",
            (escaped + "%", escaped + "%"),
        ).fetchone()
        return row["count"] if row else 0

    def all_records(self) -> List[Dict]:
        """Return all tracked records for manifest export."""
        rows = self.conn.execute(
            "SELECT file_path, baseline_checksum, checksum, file_size, "
            "file_mtime, status, first_seen, last_verified "
            "FROM checksums ORDER BY file_path"
        ).fetchall()
        return [dict(r) for r in rows]


# ── File lock ──────────────────────────────────────────────────────────────────

class FileLock:
    """Prevents concurrent runs against the same database.

    Uses flock() for atomic locking. If a second instance tries to run
    against the same database, it will fail immediately rather than
    corrupt data with concurrent writes.
    """

    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.lock_file = None

    def acquire(self) -> bool:
        try:
            self.lock_file = open(self.lock_path, "w")
            fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock_file.write(str(os.getpid()))
            self.lock_file.flush()
            return True
        except (OSError, IOError):
            return False

    def release(self):
        if self.lock_file:
            try:
                fcntl.flock(self.lock_file, fcntl.LOCK_UN)
                self.lock_file.close()
                os.unlink(self.lock_path)
            except OSError:
                pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _now() -> str:
    """Current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mtime_iso(stat_result: os.stat_result) -> str:
    """Convert a stat result's mtime to ISO 8601 UTC string.

    Uses st_mtime_ns for nanosecond precision when the sub-second part
    is non-zero. Files with exact-second timestamps keep the old format
    so upgrading doesn't trigger unnecessary re-hashing of every file.
    """
    ns = stat_result.st_mtime_ns
    secs, frac_ns = divmod(ns, 1_000_000_000)
    dt = datetime.fromtimestamp(secs, tz=timezone.utc)
    if frac_ns:
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{frac_ns:09d}Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_size(size_bytes: float) -> str:
    """Human-readable file size (e.g. 1.5 GB)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def _format_duration(seconds: float) -> str:
    """Human-readable duration (e.g. 2h 15m 30s)."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    return f"{minutes}m {secs}s"


def _is_tty() -> bool:
    """True when stderr is an interactive terminal (not a pipe or file)."""
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


import re as _re

def parse_duration(s: str) -> int:
    """Parse a human duration string like '2h30m', '45m', '3h' into seconds.

    Accepted formats: Nh, Nm, NhMm (e.g. '2h', '30m', '2h30m', '90m').
    Returns total seconds. Raises ValueError on bad input.
    """
    m = _re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?", s)
    if not m or (m.group(1) is None and m.group(2) is None):
        raise ValueError(
            f"Invalid duration '{s}'. Use formats like '2h', '30m', or '2h30m'."
        )
    hours = int(m.group(1) or 0)
    minutes = int(m.group(2) or 0)
    total = hours * 3600 + minutes * 60
    if total <= 0:
        raise ValueError(f"Duration must be positive: '{s}'")
    return total


def parse_clock_time(s: str) -> Tuple[int, int]:
    """Parse a clock time like '2h30m', '14h', '2h00m' into (hour, minute).

    Accepted formats: Nh, NhMm (e.g. '2h' = 02:00, '14h30m' = 14:30).
    Returns (hour, minute). Raises ValueError on bad input.
    """
    m = _re.fullmatch(r"(\d+)h(?:(\d+)m)?", s)
    if not m:
        raise ValueError(
            f"Invalid clock time '{s}'. Use formats like '2h', '14h30m'."
        )
    hour = int(m.group(1))
    minute = int(m.group(2) or 0)
    if hour > 23 or minute > 59:
        raise ValueError(f"Invalid clock time '{s}': hour 0-23, minute 0-59.")
    return hour, minute


def parse_days(s: str) -> int:
    """Parse a day count like '30d', '7d', '90d' into an integer.

    Raises ValueError on bad input.
    """
    m = _re.fullmatch(r"(\d+)d", s)
    if not m:
        raise ValueError(
            f"Invalid day count '{s}'. Use format like '30d', '7d', '90d'."
        )
    days = int(m.group(1))
    if days <= 0:
        raise ValueError(f"Day count must be positive: '{s}'")
    return days


def _format_clock_time(hour: int, minute: int) -> str:
    """Format (hour, minute) as a human-readable string like '2:30 AM'."""
    ampm = "AM" if hour < 12 else "PM"
    display_hour = hour % 12 or 12
    if minute:
        return f"{display_hour}:{minute:02d} {ampm}"
    return f"{display_hour} {ampm}"


def _term_width() -> int:
    """Return usable terminal width, clamped to a sane range."""
    return max(40, min(shutil.get_terminal_size((80, 24)).columns, 200))


# ── Spinner & progress bar ─────────────────────────────────────────────────────

class Spinner:
    """Animated spinner for indeterminate-length blocking operations.

    Usage:
        with Spinner("Scanning"):
            do_work()          # spinner animates on a background thread
        # prints "Scanning  [ done ]" on exit

    Falls back to a static message when stderr is not a tty (pipes, cron).
    """

    _FRAMES = ("|", "/", "—", "\\")
    _INTERVAL = 0.12  # seconds between frames

    def __init__(self, message: str, quiet: bool = False):
        self.message = message
        self.quiet = quiet
        self._tty = _is_tty()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._suffix = ""

    def __enter__(self):
        if self.quiet:
            return self
        if self._tty:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print(f"  {self.message}...", end="", file=sys.stderr, flush=True)
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join()
        if not self.quiet:
            if self._tty:
                self._clear_line()
                print(
                    f"  {self.message}  [ done ]{self._suffix}",
                    file=sys.stderr,
                    flush=True,
                )
            else:
                print(f" done.{self._suffix}", file=sys.stderr, flush=True)

    def set_suffix(self, text: str):
        """Append text after '[ done ]' when the spinner finishes."""
        self._suffix = text

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            self._clear_line()
            print(
                f"  {self.message}  [ {frame} ]",
                end="",
                file=sys.stderr,
                flush=True,
            )
            i += 1
            self._stop.wait(self._INTERVAL)

    @staticmethod
    def _clear_line():
        print(f"\r\033[2K", end="", file=sys.stderr, flush=True)


class ProgressBar:
    """Compact progress bar for the hashing phase.

    Renders a single self-updating line like:
        [████████████░░░░░░░░░░░░]  1,204 / 3,891  ·  2.4 GB  @ 312.5 MB/s

    Degrades to periodic line-based updates when not on a tty.
    """

    _FILL = "█"
    _EMPTY = "░"
    _BAR_MIN_WIDTH = 10
    _NON_TTY_INTERVAL = 5.0  # seconds between updates when piped

    def __init__(self, total: int, quiet: bool = False):
        self.total = total
        self.quiet = quiet
        self._tty = _is_tty()
        self._processed = 0
        self._bytes_hashed = 0
        self._start = time.monotonic()
        self._last_non_tty = 0.0
        self._lock = threading.Lock()  # guards counter updates from futures

    def update(self, file_bytes: int):
        """Advance counters by one file and render."""
        with self._lock:
            self._processed += 1
            self._bytes_hashed += file_bytes
            self._render()

    def finish(self):
        """Render the final state and move to the next line."""
        if self.quiet:
            return
        if self._tty:
            self._render(force=True)
            print(file=sys.stderr)
        else:
            self._render_non_tty(force=True)

    def _render(self, force: bool = False):
        if self.quiet:
            return
        if not self._tty:
            self._render_non_tty(force=force)
            return

        cols = _term_width()
        elapsed = time.monotonic() - self._start
        rate = self._bytes_hashed / elapsed if elapsed > 0 else 0

        # Build the right-side stats string first to calculate remaining space
        stats = (
            f"  {self._processed:,}/{self.total:,}"
            f"  ·  {_format_size(self._bytes_hashed)}"
            f"  @ {_format_size(rate)}/s"
        )

        # Allocate remaining space to the bar (with brackets and padding)
        #   "  [████░░░░]  stats"
        bar_overhead = 5  # "  [" + "]"
        bar_width = cols - len(stats) - bar_overhead
        bar_width = max(self._BAR_MIN_WIDTH, bar_width)

        if self.total > 0:
            frac = self._processed / self.total
        else:
            frac = 1.0
        filled = int(bar_width * frac)
        bar = self._FILL * filled + self._EMPTY * (bar_width - filled)

        line = f"  [{bar}]{stats}"
        print(f"\r\033[2K{line}", end="", file=sys.stderr, flush=True)

    def _render_non_tty(self, force: bool = False):
        now = time.monotonic()
        if not force and (now - self._last_non_tty) < self._NON_TTY_INTERVAL:
            return
        self._last_non_tty = now
        elapsed = now - self._start
        rate = self._bytes_hashed / elapsed if elapsed > 0 else 0
        pct = (self._processed / self.total * 100) if self.total > 0 else 100
        print(
            f"  {pct:5.1f}%  {self._processed:,}/{self.total:,}"
            f"  ·  {_format_size(self._bytes_hashed)} @ {_format_size(rate)}/s",
            file=sys.stderr,
            flush=True,
        )


# ── Filesystem scanning ───────────────────────────────────────────────────────

def scan_files(target_dir: str, db_path: str, include_hidden: bool = False,
               exclude_dirs: Optional[Set[str]] = None) -> List[str]:
    """Walk the directory tree and return a sorted list of file paths.

    Skips by default:
      - Hidden files and directories (names starting with '.')
      - .b2sum and .b2 hash files (handled separately by --import)
      - The database file and its SQLite companion files (-wal, -shm, .lock)
      - Any directories in exclude_dirs
    Does not follow symlinks to prevent infinite loops.
    """
    skip_files = {
        os.path.realpath(db_path),
        os.path.realpath(db_path + ".lock"),
        os.path.realpath(db_path + "-wal"),
        os.path.realpath(db_path + "-shm"),
    }
    exclude = exclude_dirs or set()
    files = []
    for root, dirs, filenames in os.walk(target_dir, followlinks=False):
        if not include_hidden:
            dirs[:] = [d for d in dirs if not d.startswith(".")]
        dirs[:] = [d for d in dirs if os.path.realpath(os.path.join(root, d)) not in exclude]

        for name in filenames:
            if not include_hidden and name.startswith("."):
                continue
            if name.endswith(".b2sum") or name.endswith(".b2"):
                continue
            full = os.path.join(root, name)
            if os.path.realpath(full) in skip_files:
                continue
            files.append(full)
    files.sort()
    return files


# ── Pre-scan: decide what needs hashing ────────────────────────────────────────

class FileEntry:
    """Snapshot of a file's metadata at prescan time.

    Used to decide whether a file needs re-hashing (based on size/mtime
    changes). The actual metadata stored in the database comes from
    fstat() during hashing to avoid TOCTOU gaps.

    The 'modified' flag records whether size or mtime changed since the
    last check. This is how rotbyte distinguishes intentional edits
    (modified=True, hash change is expected) from silent bit rot
    (modified=False, hash should not have changed).
    """
    __slots__ = ("path", "name", "size", "mtime", "old_checksum", "modified")

    def __init__(self, path: str, name: str, size: int, mtime: str,
                 old_checksum: Optional[str], modified: bool):
        self.path = path
        self.name = name
        self.size = size
        self.mtime = mtime
        self.old_checksum = old_checksum
        self.modified = modified


def prescan_files(
    all_files: List[str],
    existing: Dict[str, Tuple[str, int, str, str]],
    force: bool,
) -> Tuple[List[FileEntry], int]:
    """Compare files on disk against the database to decide what to hash.

    Returns (files_to_hash, skip_count). Files are skipped (not hashed)
    only when all of these are true:
      - Not running with --check (force=False)
      - File is not marked MISSING or FAILED in the database
      - File's size and mtime match the stored values
    """
    to_hash: List[FileEntry] = []
    skip_count = 0

    for fpath in all_files:
        try:
            st = os.stat(fpath)
        except OSError:
            continue

        name = os.path.basename(fpath)
        size = st.st_size
        mtime = _mtime_iso(st)

        record = existing.get(fpath)
        if record:
            old_checksum, old_size, old_mtime, old_status = record
            metadata_changed = (old_size != size or old_mtime != mtime)

            # Always re-hash MISSING files (they reappeared — verify against
            # old checksum) and FAILED files (may have been restored from
            # backup). Also re-hash if metadata changed or --check is set.
            if not force and old_status not in ("MISSING", "FAILED") and not metadata_changed:
                skip_count += 1
                continue
            to_hash.append(FileEntry(fpath, name, size, mtime, old_checksum, metadata_changed))
        else:
            to_hash.append(FileEntry(fpath, name, size, mtime, None, True))

    return to_hash, skip_count


# ── Hashing phase ─────────────────────────────────────────────────────────────

class HashResult:
    """Counters accumulated during the hashing phase."""
    __slots__ = ("new", "ok", "updated", "failed", "errors", "bytes_hashed")

    def __init__(self):
        self.new = 0
        self.ok = 0
        self.updated = 0
        self.failed = 0
        self.errors = 0
        self.bytes_hashed = 0


def run_hashing(
    db: ChecksumDB,
    entries: List[FileEntry],
    workers: int,
    now: str,
    interrupted: List[bool],
    quiet: bool = False,
    budget_seconds: Optional[int] = None,
) -> HashResult:
    """Hash files in parallel and write results to the database.

    Files are submitted in batches of BATCH_SIZE. Each batch is wrapped
    in a database transaction with try/finally to guarantee every opened
    transaction is either committed or rolled back — even on interrupt
    or worker crash.

    If budget_seconds is set, hashing stops after the wall-clock budget
    is exceeded (finishing the current batch first).
    """
    result = HashResult()
    total = len(entries)
    if total == 0:
        return result

    processed = 0
    entry_map = {e.path: e for e in entries}
    bar = ProgressBar(total, quiet=quiet)
    budget_start = time.monotonic()

    with ProcessPoolExecutor(max_workers=workers) as executor:
        for batch_start in range(0, total, BATCH_SIZE):
            if interrupted[0]:
                break

            # Check time budget between batches
            if budget_seconds is not None:
                elapsed = time.monotonic() - budget_start
                if elapsed >= budget_seconds:
                    if not quiet:
                        print(f"\n  Time budget reached ({_format_duration(elapsed)})."
                              f" Stopping with {total - batch_start:,} files remaining.")
                    break

            batch = entries[batch_start : batch_start + BATCH_SIZE]
            futures = {executor.submit(hash_file, e.path): e.path for e in batch}

            db.begin()
            try:
                for future in as_completed(futures):
                    if interrupted[0]:
                        break

                    # Catch worker crashes (OOM, segfault) so one bad file
                    # doesn't abort the entire run.
                    try:
                        fpath, digest, hash_size, hash_mtime = future.result()
                    except (BrokenExecutor, Exception) as e:
                        fpath = futures[future]
                        print(f"\n  ! Worker error for {fpath}: {e}", file=sys.stderr)
                        result.errors += 1
                        processed += 1
                        bar.update(0)
                        continue

                    processed += 1

                    if digest is None:
                        result.errors += 1
                        bar.update(0)
                        continue

                    entry = entry_map[fpath]

                    # Determine file status based on hash comparison and
                    # whether the file's metadata changed.
                    if entry.old_checksum is None:
                        status = "NEW"
                        result.new += 1
                    elif digest == entry.old_checksum:
                        status = "OK"
                        result.ok += 1
                    elif entry.modified:
                        # Hash changed but so did mtime/size — this is an
                        # intentional edit, not corruption. Accept it.
                        status = "OK"
                        result.updated += 1
                    else:
                        # Hash changed with no metadata change — bit rot.
                        status = "FAILED"
                        result.failed += 1
                        print(f"\n  ✗ FAILED: {fpath}")

                    result.bytes_hashed += hash_size

                    db.upsert_file(
                        fpath, entry.name, hash_size, hash_mtime,
                        digest, entry.old_checksum, status, now,
                    )

                    bar.update(hash_size)

                db.commit()
            except BaseException:
                db.rollback()
                raise

    bar.finish()
    return result


# ── Missing file detection ─────────────────────────────────────────────────────

def detect_missing(
    db: ChecksumDB,
    target_dir: str,
    on_disk: Set[str],
    existing: Dict[str, Tuple[str, int, str, str]],
    now: str,
) -> int:
    """Detect and report all files missing from disk.

    Uses the already-loaded records dict from the prescan phase to avoid
    a redundant database query. Newly missing files are marked MISSING
    in the database. Previously known missing files are also reported so
    every run shows the full picture. Returns total count of all currently
    missing files.
    """
    missing_paths = set(existing.keys()) - on_disk
    already_missing = db.get_missing_paths(target_dir) - on_disk
    newly_missing = missing_paths - already_missing

    if newly_missing:
        db.begin()
        try:
            for mpath in sorted(newly_missing):
                db.mark_missing(mpath, now)
            db.commit()
        except BaseException:
            db.rollback()
            raise

    all_missing = newly_missing | already_missing
    for mpath in sorted(all_missing):
        print(f"  ? MISSING: {mpath}")

    return len(all_missing)


# ── Reporting ──────────────────────────────────────────────────────────────────

def print_report(db: ChecksumDB):
    """Print a human-readable status report from the database."""
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
            print(f"    {f['file_path']}")
            print(f"      Size: {_format_size(f['file_size'])}  |  Last verified: {f['last_verified']}")
            print(f"      Expected: {f['baseline_checksum'][:32]}...")
            print(f"      Got:      {f['checksum'][:32]}...")
        print()

    stale = db.stale_files(90)
    if stale:
        print(f"  ⏰ Files not verified in 90+ days: {len(stale):,}")
        if len(stale) <= 20:
            for s in stale:
                print(f"    {s['file_path']}  (last: {s['last_verified']})")
        else:
            print("    (showing first 10)")
            for s in stale[:10]:
                print(f"    {s['file_path']}  (last: {s['last_verified']})")
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
  rotbyte --check --budget 2h            Full verify with a 2-hour time limit
  rotbyte --due 30d                       Re-verify files not checked in 30 days
  rotbyte --due 7d --budget 1h           Re-verify week-old files, 1hr budget
  rotbyte --track /Volumes/Media         Quick scan every hour (launchd/systemd)
  rotbyte --track --every 30m --full-at 2h 14h --budget 2h /Volumes/Media

Exit codes:
  0  All files verified OK
  1  Missing files detected
  2  Bit rot detected (checksum mismatch)
  3  Run was interrupted (safe to re-run)
""",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("path", nargs="?", default=".",
                        help="Directory to scan (default: current directory)")
    parser.add_argument("--check", action="store_true",
                        help="Force re-hash of every file regardless of modification time")
    parser.add_argument("--accept", metavar="FILE",
                        help="Accept a single file's current state (clears MISSING or re-hashes FAILED)")
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
    parser.add_argument("--exclude", nargs="+", default=[], metavar="PATH",
                        help="Exclude one or more directories (relative to target dir or absolute)")
    parser.add_argument("--db", help="Database path (default: .{dirname}_checksums.db inside target dir)")
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
                        help="Install scheduled scans using launchd (macOS) or systemd (Linux)")
    parser.add_argument("--every", metavar="INTERVAL", default="60m",
                        help="Quick scan frequency for --track (e.g. 30m, 2h). Default: 60m")
    parser.add_argument("--full-at", nargs="+", metavar="TIME", dest="full_at",
                        help="Daily clock times for full --check scans (e.g. 2h 2h30m 14h)")

    args = parser.parse_args()

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

    target_dir = os.path.realpath(args.path)
    if not os.path.isdir(target_dir):
        print(f"Error: '{target_dir}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    # Resolve --exclude paths relative to the target directory
    exclude_dirs: Set[str] = set()
    for exc in args.exclude:
        if os.path.isabs(exc):
            exclude_dirs.add(os.path.realpath(exc))
        else:
            exclude_dirs.add(os.path.realpath(os.path.join(target_dir, exc)))
    args.exclude_dirs = exclude_dirs

    db_name = "." + os.path.basename(target_dir) + DB_FILENAME_SUFFIX
    db_path = args.db or os.path.join(target_dir, db_name)
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
                   due_days=args.due_days)
        return

    # Acquire file lock to prevent concurrent runs
    lock = FileLock(lock_path)
    if not lock.acquire():
        print("Error: Another instance is already running against this database.", file=sys.stderr)
        print(f"  If this is a mistake, remove: {lock_path}", file=sys.stderr)
        sys.exit(1)

    try:
        _run(args, target_dir, db_path)
    finally:
        lock.release()


def _run(args: argparse.Namespace, target_dir: str, db_path: str):
    """Core logic, called with the file lock held."""

    # Open or create the database, catching corruption at connect time
    try:
        db = ChecksumDB(db_path)
    except sqlite3.DatabaseError as e:
        print(f"Error: Could not open database — {e}", file=sys.stderr)
        print(f"  Path: {db_path}", file=sys.stderr)
        print("  It may be corrupt. Restore from backup or delete to start fresh.", file=sys.stderr)
        sys.exit(1)

    # Catch subtler corruption that doesn't prevent opening
    if not db.verify_integrity():
        print("Error: Database failed integrity check.", file=sys.stderr)
        print(f"  Path: {db_path}", file=sys.stderr)
        print("  Restore from backup or delete to start fresh.", file=sys.stderr)
        db.close()
        sys.exit(1)

    # ── Dispatch to the requested mode ─────────────────────────────────
    if args.report:
        print_report(db)
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
            sys.exit(3)
        interrupted[0] = True
        print("\n\n  Interrupt received — finishing current batch and saving progress...")
        print("  Press Ctrl-C again to abort immediately.\n")

    prev_sigint = signal.getsignal(signal.SIGINT)
    prev_sigterm = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        _run_phases(db, target_dir, args, interrupted)
    finally:
        signal.signal(signal.SIGINT, prev_sigint)
        signal.signal(signal.SIGTERM, prev_sigterm)
        db.close()


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
        sys.exit(1)

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
        dirs[:] = [d for d in dirs if os.path.realpath(os.path.join(root, d)) not in exclude]
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
        existing_status = db.get_file_status(os.path.realpath(media_path))
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
        _, our_hash, h_size, h_mtime = hash_file(media_path)
        if our_hash is None:
            errors += 1
            continue

        if our_hash != stored_hash:
            print(f"  ✗ MISMATCH: {media_name}")
            print(f"      expected: {stored_hash[:32]}...")
            print(f"      computed: {our_hash[:32]}...")
            mismatched += 1
            continue

        # Hashes match — import into the database
        media_real = os.path.realpath(media_path)

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
    file_path = os.path.realpath(file_arg)
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
            sys.exit(1)

        _, digest, h_size, h_mtime = hash_file(file_path)
        if digest is None:
            print("  Error reading file.", file=sys.stderr)
            sys.exit(1)

        db.accept_file(file_path, digest, h_size, h_mtime, now)
        print(f"  ✓ Accepted: {file_path}")

    else:
        print(f"  '{file_arg}' has status '{status}' — nothing to accept.")


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
        db.begin()
        try:
            for fpath in failed_paths:
                _, digest, h_size, h_mtime = hash_file(fpath)
                if digest is None:
                    print(f"  ! Cannot read {fpath} — skipping.")
                    errors += 1
                    continue

                db.accept_file(fpath, digest, h_size, h_mtime, now)
                accepted += 1
                print(f"  ✓ Accepted: {fpath}")
            db.commit()
        except BaseException:
            db.rollback()
            raise

    if not purged and not accepted and not errors:
        print("  Nothing to reconcile — no MISSING or FAILED files.")

    print()
    print("═" * 60)
    print(f"  Missing cleared : {purged:,}")
    print(f"  Failed accepted : {accepted:,}")
    if errors:
        print(f"  Errors          : {errors:,}")
    print("═" * 60)


# ── Track mode (scheduler installation) ────────────────────────────────────────

import hashlib as _hashlib
import platform as _platform
import subprocess as _subprocess
import textwrap as _textwrap

def _dir_hash(target_dir: str) -> str:
    """Short hash of the target directory path for unique config naming."""
    return _hashlib.md5(target_dir.encode()).hexdigest()[:8]


def _find_rotbyte_executable() -> str:
    """Find the full path to the rotbyte executable.

    Checks, in order: the script that's currently running (if it looks
    like an installed entry point), then $PATH via `which`.
    """
    # If we were invoked as an installed script (not 'python rotbyte.py')
    if not sys.argv[0].endswith(".py"):
        candidate = shutil.which(os.path.basename(sys.argv[0]))
        if candidate:
            return os.path.realpath(candidate)

    # Try finding 'rotbyte' on PATH
    candidate = shutil.which("rotbyte")
    if candidate:
        return os.path.realpath(candidate)

    # Fallback: use current Python + current script
    return f"{sys.executable} {os.path.realpath(sys.argv[0])}"


def _generate_launchd_plist(label: str, command: List[str],
                            interval_seconds: Optional[int] = None,
                            calendar_times: Optional[List[Tuple[int, int]]] = None) -> str:
    """Generate a macOS launchd plist XML string.

    Either interval_seconds (for StartInterval) or calendar_times
    (for StartCalendarInterval) must be provided.
    """
    cmd_xml = "\n".join(f"        <string>{c}</string>" for c in command)

    if interval_seconds is not None:
        trigger = f"    <key>StartInterval</key>\n    <integer>{interval_seconds}</integer>"
    elif calendar_times is not None:
        entries = []
        for hour, minute in calendar_times:
            entries.append(
                "        <dict>\n"
                f"            <key>Hour</key>\n"
                f"            <integer>{hour}</integer>\n"
                f"            <key>Minute</key>\n"
                f"            <integer>{minute}</integer>\n"
                "        </dict>"
            )
        trigger = (
            "    <key>StartCalendarInterval</key>\n"
            "    <array>\n" + "\n".join(entries) + "\n"
            "    </array>"
        )
    else:
        raise ValueError("Must provide interval_seconds or calendar_times")

    return _textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>{label}</string>
            <key>ProgramArguments</key>
            <array>
        {cmd_xml}
            </array>
        {trigger}
            <key>StandardOutPath</key>
            <string>/tmp/{label}.log</string>
            <key>StandardErrorPath</key>
            <string>/tmp/{label}.log</string>
            <key>Nice</key>
            <integer>10</integer>
        </dict>
        </plist>
    """)


def _generate_systemd_unit(description: str, command: List[str]) -> str:
    """Generate a systemd .service unit file."""
    exec_start = " ".join(command)
    return _textwrap.dedent(f"""\
        [Unit]
        Description={description}

        [Service]
        Type=oneshot
        ExecStart={exec_start}
        Nice=10

        [Install]
        WantedBy=default.target
    """)


def _generate_systemd_timer(description: str,
                            interval_seconds: Optional[int] = None,
                            calendar_times: Optional[List[Tuple[int, int]]] = None) -> str:
    """Generate a systemd .timer unit file."""
    if interval_seconds is not None:
        minutes = max(1, interval_seconds // 60)
        schedule = f"    OnBootSec=5min\n    OnUnitActiveSec={minutes}min"
    elif calendar_times is not None:
        entries = []
        for hour, minute in calendar_times:
            entries.append(f"    OnCalendar=*-*-* {hour:02d}:{minute:02d}:00")
        schedule = "\n".join(entries) + "\n    Persistent=true"
    else:
        raise ValueError("Must provide interval_seconds or calendar_times")

    return _textwrap.dedent(f"""\
        [Unit]
        Description={description}

        [Timer]
        {schedule}

        [Install]
        WantedBy=timers.target
    """)


def _run_track(target_dir: str, every_seconds: int,
               full_at: Optional[List[Tuple[int, int]]],
               budget_seconds: Optional[int],
               rotbyte_exe: str,
               workers: Optional[int] = None,
               due_days: Optional[int] = None):
    """Install platform-native scheduled tasks for rotbyte.

    On macOS: launchd plists in ~/Library/LaunchAgents/
    On Linux: systemd user timer/service pairs in ~/.config/systemd/user/
    """
    is_mac = _platform.system() == "Darwin"
    is_linux = _platform.system() == "Linux"

    if not is_mac and not is_linux:
        print(f"Error: --track is not supported on {_platform.system()}.", file=sys.stderr)
        print("  Supported platforms: macOS (launchd) and Linux (systemd).", file=sys.stderr)
        sys.exit(1)

    dhash = _dir_hash(target_dir)

    # Split rotbyte_exe into command parts (handles "python /path/to/rotbyte.py")
    exe_parts = rotbyte_exe.split()

    # --workers passthrough (only when explicitly set)
    workers_args = ["--workers", str(workers)] if workers is not None else []

    # Build the commands that will be scheduled
    quick_cmd = exe_parts + workers_args + ["--quiet", target_dir]
    full_cmd = None
    if full_at:
        full_cmd = exe_parts + ["--check", "--quiet"] + workers_args
        if due_days:
            full_cmd += ["--due", f"{due_days}d"]
        if budget_seconds:
            # Store as the original duration format for the scheduled command
            budget_h = budget_seconds // 3600
            budget_m = (budget_seconds % 3600) // 60
            budget_str = ""
            if budget_h:
                budget_str += f"{budget_h}h"
            if budget_m:
                budget_str += f"{budget_m}m"
            if not budget_str:
                budget_str = "1m"
            full_cmd += ["--budget", budget_str]
        full_cmd.append(target_dir)

    print("═" * 60)
    print("  rotbyte — Installing scheduled scans")
    print("═" * 60)
    print(f"  Directory  : {target_dir}")
    print(f"  Quick scan : every {_format_duration(every_seconds)}")
    if full_at:
        times_str = ", ".join(_format_clock_time(h, m) for h, m in full_at)
        print(f"  Full scan  : daily at {times_str}")
        if budget_seconds:
            print(f"  Budget     : {_format_duration(budget_seconds)} per full scan")
        if due_days:
            print(f"  Due window : files not verified in {due_days} days")
    if workers is not None:
        print(f"  Workers    : {workers}")
    print(f"  Platform   : {'macOS (launchd)' if is_mac else 'Linux (systemd)'}")
    print("═" * 60)
    print()

    if is_mac:
        _install_launchd(target_dir, dhash, quick_cmd, every_seconds,
                         full_cmd, full_at)
    else:
        _install_systemd(target_dir, dhash, quick_cmd, every_seconds,
                         full_cmd, full_at)

    print()
    print("═" * 60)
    print("  ✓ Scheduled scans installed successfully.")
    print()
    print("  Logs:")
    if is_mac:
        print(f"    /tmp/com.rotbyte.quick.{dhash}.log")
        if full_at:
            print(f"    /tmp/com.rotbyte.full.{dhash}.log")
    else:
        print(f"    journalctl --user -u rotbyte-quick-{dhash}")
        if full_at:
            print(f"    journalctl --user -u rotbyte-full-{dhash}")
    print("═" * 60)


def _install_launchd(target_dir: str, dhash: str, quick_cmd: List[str],
                     every_seconds: int, full_cmd: Optional[List[str]],
                     full_at: Optional[List[Tuple[int, int]]]):
    """Write and load macOS launchd plist files."""
    agents_dir = os.path.expanduser("~/Library/LaunchAgents")
    os.makedirs(agents_dir, exist_ok=True)

    quick_label = f"com.rotbyte.quick.{dhash}"
    quick_plist = os.path.join(agents_dir, f"{quick_label}.plist")

    # Unload existing agents first (ignore errors if not loaded)
    _subprocess.run(["launchctl", "unload", quick_plist],
                    capture_output=True)

    plist_content = _generate_launchd_plist(
        quick_label, quick_cmd, interval_seconds=every_seconds,
    )
    with open(quick_plist, "w") as f:
        f.write(plist_content)
    _subprocess.run(["launchctl", "load", quick_plist], check=True)
    print(f"  ✓ Installed: {quick_plist}")

    if full_cmd and full_at:
        full_label = f"com.rotbyte.full.{dhash}"
        full_plist = os.path.join(agents_dir, f"{full_label}.plist")

        _subprocess.run(["launchctl", "unload", full_plist],
                        capture_output=True)

        plist_content = _generate_launchd_plist(
            full_label, full_cmd, calendar_times=full_at,
        )
        with open(full_plist, "w") as f:
            f.write(plist_content)
        _subprocess.run(["launchctl", "load", full_plist], check=True)
        print(f"  ✓ Installed: {full_plist}")


def _install_systemd(target_dir: str, dhash: str, quick_cmd: List[str],
                     every_seconds: int, full_cmd: Optional[List[str]],
                     full_at: Optional[List[Tuple[int, int]]]):
    """Write and enable systemd user timer/service pairs."""
    unit_dir = os.path.expanduser("~/.config/systemd/user")
    os.makedirs(unit_dir, exist_ok=True)

    quick_name = f"rotbyte-quick-{dhash}"

    # Quick scan service + timer
    service_content = _generate_systemd_unit(
        f"rotbyte quick scan ({target_dir})", quick_cmd,
    )
    timer_content = _generate_systemd_timer(
        f"rotbyte quick scan timer ({target_dir})",
        interval_seconds=every_seconds,
    )

    with open(os.path.join(unit_dir, f"{quick_name}.service"), "w") as f:
        f.write(service_content)
    with open(os.path.join(unit_dir, f"{quick_name}.timer"), "w") as f:
        f.write(timer_content)

    _subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    _subprocess.run(["systemctl", "--user", "enable", "--now", f"{quick_name}.timer"],
                    check=True)
    print(f"  ✓ Installed: {quick_name}.timer + .service")

    if full_cmd and full_at:
        full_name = f"rotbyte-full-{dhash}"

        service_content = _generate_systemd_unit(
            f"rotbyte full scan ({target_dir})", full_cmd,
        )
        timer_content = _generate_systemd_timer(
            f"rotbyte full scan timer ({target_dir})",
            calendar_times=full_at,
        )

        with open(os.path.join(unit_dir, f"{full_name}.service"), "w") as f:
            f.write(service_content)
        with open(os.path.join(unit_dir, f"{full_name}.timer"), "w") as f:
            f.write(timer_content)

        _subprocess.run(["systemctl", "--user", "enable", "--now", f"{full_name}.timer"],
                        check=True)
        print(f"  ✓ Installed: {full_name}.timer + .service")


# ── Normal scan mode ───────────────────────────────────────────────────────────

def _run_phases(db: ChecksumDB, target_dir: str, args: argparse.Namespace,
                interrupted: List[bool]):
    """Execute the three verification phases: scan, hash, detect missing."""

    quiet = args.quiet or args.json_output
    budget_seconds = getattr(args, "budget_seconds", None)
    due_days = getattr(args, "due_days", None)

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
        all_files = scan_files(target_dir, db.db_path, args.include_hidden, args.exclude_dirs)
        sp.set_suffix(f"  {len(all_files):,} files")

    with Spinner("Loading database", quiet=quiet) as sp:
        existing = db.load_all_records(target_dir)
        sp.set_suffix(f"  {len(existing):,} tracked")

    with Spinner("Comparing", quiet=quiet) as sp:
        to_hash, skip_count = prescan_files(all_files, existing, args.check)
        sp.set_suffix(f"  {len(to_hash):,} to hash, {skip_count:,} unchanged")

    # When --due is set, filter to only files that haven't been verified
    # within the threshold. New files (not yet in DB) are always included.
    if due_days:
        with Spinner(f"Filtering to files due for re-verify ({due_days}d)", quiet=quiet) as sp:
            due_paths = db.due_file_paths(target_dir, due_days)
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
    result = run_hashing(db, to_hash, args.workers, now, interrupted, quiet,
                         budget_seconds=budget_seconds)

    # ── Phase 3: Detect missing files ──────────────────────────────────
    count_missing = 0
    if not interrupted[0] and not args.skip_missing:
        with Spinner("Checking for missing files", quiet=quiet):
            count_missing = detect_missing(db, target_dir, set(all_files), existing, now)

    db.finish_run()

    # ── Summary ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start_time
    has_problems = result.failed > 0 or count_missing > 0 or interrupted[0]

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

    if result.failed > 0:
        print()
        print("⚠  BIT ROT DETECTED — run with --report for details.")
        sys.exit(2)
    if interrupted[0]:
        print()
        print("  Run again to resume where you left off.")
        sys.exit(3)
    if count_missing > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()