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
"""

VERSION = "1.0.0"
DB_FILENAME_SUFFIX = "_checksums.db"
HASH_BUFFER_SIZE = 1024 * 1024  # 1 MiB — balances syscall overhead vs memory
BATCH_SIZE = 200                # DB writes per transaction before committing


# ── Hashing (runs in worker processes) ─────────────────────────────────────────

def hash_file(file_path: str) -> Tuple[str, Optional[str]]:
    """Compute BLAKE2b-512 hash of a file.

    Returns (path, hex_digest) on success or (path, None) on read error.
    This function runs in a worker process via ProcessPoolExecutor and
    must not access the database or any shared mutable state.
    """
    try:
        h = hashlib.blake2b()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(HASH_BUFFER_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return file_path, h.hexdigest()
    except OSError as e:
        print(f"\n  ! Error reading {file_path}: {e}", file=sys.stderr)
        return file_path, None


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

    def verify_integrity(self) -> bool:
        """Quick integrity check on the database file itself."""
        result = self.conn.execute("PRAGMA quick_check").fetchone()
        return result is not None and result[0] == "ok"

    def close(self):
        self.conn.close()

    @staticmethod
    def _escape_like(prefix: str) -> str:
        """Escape SQL LIKE wildcards (%, _, \\) in a path prefix."""
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

        Returns {file_path: (checksum, file_size, file_mtime, status)}.
        Includes MISSING records so re-added files are verified against
        their last known-good checksum. Escapes SQL LIKE wildcards.
        """
        escaped = self._escape_like(prefix)
        rows = self.conn.execute(
            "SELECT file_path, checksum, file_size, file_mtime, status FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\'",
            (escaped + "%",),
        ).fetchall()
        return {r["file_path"]: (r["checksum"], r["file_size"], r["file_mtime"], r["status"]) for r in rows}

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
        """
        if old_checksum is not None:
            self.conn.execute(
                """UPDATE checksums
                   SET checksum = ?, file_size = ?, file_mtime = ?,
                       status = ?, last_verified = ?
                 WHERE file_path = ?""",
                (checksum, file_size, file_mtime, status, now, file_path),
            )
        else:
            self.conn.execute(
                """INSERT INTO checksums
                   (file_path, file_name, file_size, file_mtime, checksum,
                    algorithm, status, first_seen, last_verified)
                   VALUES (?, ?, ?, ?, ?, 'BLAKE2b', ?, ?, ?)""",
                (file_path, file_name, file_size, file_mtime, checksum, status, now, now),
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
               SET checksum = ?, file_size = ?, file_mtime = ?,
                   status = 'OK', last_verified = ?
             WHERE file_path = ?""",
            (checksum, file_size, file_mtime, now, file_path),
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
            "SELECT file_path, file_size, checksum, last_verified "
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
            "  AND c2.checksum = c1.checksum"
            ")",
            (escaped + "%", escaped + "%"),
        ).fetchone()
        return row["count"] if row else 0


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
    """Convert a stat result's mtime to ISO 8601 UTC string."""
    return datetime.fromtimestamp(
        stat_result.st_mtime, tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    """Snapshot of a file's metadata at scan time.

    Capturing size and mtime here (rather than after hashing) ensures the
    metadata stored in the database matches the exact bytes that were
    hashed — no TOCTOU gap.

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
) -> HashResult:
    """Hash files in parallel and write results to the database.

    Files are submitted in batches of BATCH_SIZE. Each batch is wrapped
    in a database transaction with try/finally to guarantee every opened
    transaction is either committed or rolled back — even on interrupt
    or worker crash.
    """
    result = HashResult()
    total = len(entries)
    if total == 0:
        return result

    processed = 0
    entry_map = {e.path: e for e in entries}
    bar = ProgressBar(total, quiet=quiet)

    with ProcessPoolExecutor(max_workers=workers) as executor:
        for batch_start in range(0, total, BATCH_SIZE):
            if interrupted[0]:
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
                        fpath, digest = future.result()
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

                    result.bytes_hashed += entry.size

                    # On failure, keep the original known-good checksum so
                    # a backup restore can be verified against it later.
                    stored_checksum = entry.old_checksum if status == "FAILED" else digest
                    db.upsert_file(
                        fpath, entry.name, entry.size, entry.mtime,
                        stored_checksum, entry.old_checksum, status, now,
                    )

                    bar.update(entry.size)

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

    args = parser.parse_args()

    # Validate --workers
    if args.workers < 1:
        print("Error: --workers must be at least 1.", file=sys.stderr)
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
        _, our_hash = hash_file(media_path)
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
        st = os.stat(media_path)

        if existing_status in ("MISSING", "FAILED"):
            db.accept_file(media_real, our_hash, st.st_size, _mtime_iso(st), now)
        else:
            db.upsert_file(
                media_real, os.path.basename(media_real), st.st_size,
                _mtime_iso(st), our_hash, None, "OK", now,
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

        st = os.stat(file_path)
        _, digest = hash_file(file_path)
        if digest is None:
            print("  Error reading file.", file=sys.stderr)
            sys.exit(1)

        db.accept_file(file_path, digest, st.st_size, _mtime_iso(st), now)
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
                try:
                    st = os.stat(fpath)
                except OSError:
                    print(f"  ! Cannot read {fpath} — skipping.")
                    errors += 1
                    continue

                _, digest = hash_file(fpath)
                if digest is None:
                    errors += 1
                    continue

                db.accept_file(fpath, digest, st.st_size, _mtime_iso(st), now)
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


# ── Normal scan mode ───────────────────────────────────────────────────────────

def _run_phases(db: ChecksumDB, target_dir: str, args: argparse.Namespace,
                interrupted: List[bool]):
    """Execute the three verification phases: scan, hash, detect missing."""

    quiet = args.quiet

    if not quiet:
        print("═" * 60)
        print("  rotbyte")
        print("═" * 60)
        print(f"  Directory  : {target_dir}")
        print(f"  Database   : {db.db_path}")
        print(f"  Workers    : {args.workers}")
        print(f"  Mode       : {'full re-verify (--check)' if args.check else 'quick (changed files only)'}")
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

    if not quiet:
        print()

    # ── Phase 2: Hash files and record results ─────────────────────────
    db.start_run(target_dir)
    now = _now()
    start_time = time.monotonic()
    result = run_hashing(db, to_hash, args.workers, now, interrupted, quiet)

    # ── Phase 3: Detect missing files ──────────────────────────────────
    count_missing = 0
    if not interrupted[0] and not args.skip_missing:
        with Spinner("Checking for missing files", quiet=quiet):
            count_missing = detect_missing(db, target_dir, set(all_files), existing, now)

    db.finish_run()

    # ── Summary ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start_time
    has_problems = result.failed > 0 or count_missing > 0 or interrupted[0]

    if not quiet or has_problems:
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