"""SQLite-backed checksum database for rotbyte.

Holds every tracked file's known-good hash, metadata, and lifecycle
status (NEW / OK / FAILED / MISSING). All writes batched through an
explicit transaction; see :func:`transaction` for the context-manager
form that run_hashing/detect_missing/accept_all use.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import sys
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .helpers import _now

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
-- idx_baseline_checksum is created in _ensure_indexes() rather than here
-- because legacy v1 databases don't have the baseline_checksum column
-- until _migrate() adds it. Running CREATE INDEX here would fail on
-- pre-migration open.

CREATE TABLE IF NOT EXISTS last_run (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    started_at  TEXT    NOT NULL,
    finished_at TEXT,
    target_dir  TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'RUNNING',
    -- Problem counts from the last completed run, so the next notification
    -- can report the change ("bit rot 1 → 3"). NULL until a run records them.
    failed      INTEGER,
    missing     INTEGER
);

CREATE TABLE IF NOT EXISTS schema_version (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL DEFAULT 1
);
"""

SCHEMA_VERSION = 4


class SchemaTooNewError(sqlite3.DatabaseError):
    """The database was written by a newer rotbyte than we understand.

    Subclasses ``sqlite3.DatabaseError`` so callers that only catch the
    generic open-time error still handle it, while a caller that wants to
    tell the user "upgrade rotbyte" (rather than "your DB is corrupt") can
    catch this more specific type first.
    """


# Current DB filename shape: ".{dirname}_rotbyte.db". The leading dot keeps
# the file hidden on POSIX; the {dirname} prefix keeps DBs distinguishable
# when users copy them side-by-side onto a backup target.
DB_FILENAME_SUFFIX = "_rotbyte.db"
# Prior name, retained so existing users are auto-migrated on first run of
# a version that ships the rename. See _migrate_legacy_db_name().
LEGACY_DB_FILENAME_SUFFIX = "_checksums.db"


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

        # Record whether the `checksums` table pre-dates this open, BEFORE
        # executescript recreates it. _migrate() uses this to tell a truly
        # fresh database (stamp current schema) from a legacy pre-versioning
        # one (run the migration chain) without relying on a row-count
        # heuristic that mis-flags an empty legacy DB as fresh.
        self._checksums_preexisted = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='checksums'"
        ).fetchone() is not None

        # WAL silently degrades to a rollback journal on network filesystems
        # (NFS/SMB) that lack the shared-memory mmap WAL needs — and rotbyte
        # targets NAS/backup storage. synchronous=NORMAL is only crash-durable
        # under WAL; when WAL did NOT engage we must use FULL to stay durable.
        mode = self.conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if mode and mode.lower() == "wal":
            self.conn.execute("PRAGMA synchronous=NORMAL")
        else:
            self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA cache_size=-64000")   # 64 MB cache
        self.conn.execute("PRAGMA busy_timeout=5000")    # wait up to 5s on lock
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA_SQL)
        self._migrate()
        self._ensure_indexes()

        # The DB (and its -wal/-shm sidecars) is created under the process
        # umask, typically 0644 — world-readable. It holds the full tracked
        # path/size/checksum inventory, so restrict to owner-only like
        # notify.conf and the .lock file. chmod is a no-op/raises on some
        # Windows setups, hence the guard.
        self._restrict_permissions()

    def _restrict_permissions(self):
        """Restrict the DB file and its WAL/SHM sidecars to owner-only (0600)."""
        for path in (self.db_path, self.db_path + "-wal", self.db_path + "-shm"):
            try:
                if os.path.exists(path):
                    os.chmod(path, 0o600)
            except OSError:
                pass

    def _ensure_indexes(self):
        """Create indexes that depend on columns added by migrations.

        Runs after _migrate() so legacy v1 databases (which lack
        baseline_checksum until the 1→2 migration adds it) can open
        cleanly before the index exists. Idempotent.
        """
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_baseline_checksum "
            "ON checksums(baseline_checksum)"
        )

    def _migrate(self):
        """Run any pending schema migrations.

        Existing databases without a schema_version table are treated as
        version 1. Migrations are applied sequentially up to SCHEMA_VERSION.
        """
        row = self.conn.execute(
            "SELECT version FROM schema_version WHERE id = 1"
        ).fetchone()

        if row is None:
            # No schema_version row. Distinguish a truly fresh database from
            # a legacy pre-versioning one STRUCTURALLY, not by row count: an
            # EMPTY legacy DB was previously misread as fresh, stamped at the
            # current version, and thereby skipped the migration that adds the
            # baseline_checksum column — bricking it permanently.
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(checksums)")}
            has_baseline = "baseline_checksum" in cols
            if not self._checksums_preexisted:
                # Brand-new DB: executescript just created the full current
                # schema. Stamp it and skip migrations.
                current = SCHEMA_VERSION
            elif not has_baseline:
                # Legacy pre-versioning DB missing baseline_checksum. Treat as
                # v1 and run the migration chain regardless of row count.
                current = 1
            else:
                # Pre-existing DB that already has baseline_checksum but no
                # schema_version row (v2-shaped). Start at 2 so we skip the
                # destructive 1→2 backfill (which would clobber the preserved
                # known-good hash on FAILED rows); later migrations are
                # idempotent.
                current = 2
            self.conn.execute(
                "INSERT INTO schema_version (id, version) VALUES (1, ?)",
                (current,),
            )
        else:
            current = row["version"]

        if current > SCHEMA_VERSION:
            # Database written by a newer rotbyte. Refuse rather than silently
            # operating on a schema we don't understand. SchemaTooNewError
            # subclasses DatabaseError, so it still flows through the caller's
            # generic open-time handler if not caught more specifically.
            raise SchemaTooNewError(
                "database was created by a newer version of rotbyte; "
                "please upgrade rotbyte"
            )
        if current == SCHEMA_VERSION:
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

        # ── Migration 2 → 3: index baseline_checksum for move detection ──
        # Without this index, looking up MISSING rows by checksum when new
        # files arrive is O(n) per lookup and O(n²) for large reshuffles
        # (e.g. a media-library reorganization). The index is ~64 bytes per
        # row and pays for itself the first time a user reorganizes.
        if current < 3:
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_baseline_checksum "
                "ON checksums(baseline_checksum)"
            )
            current = 3

        # ── Migration 3 → 4: last_run gains failed/missing counts ────────
        # Lets a notification report the change since the previous run
        # ("bit rot 1 → 3"). Nullable — existing rows report "no prior
        # counts" until the next run records them.
        if current < 4:
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(last_run)")}
            if "failed" not in cols:
                self.conn.execute("ALTER TABLE last_run ADD COLUMN failed INTEGER")
            if "missing" not in cols:
                self.conn.execute("ALTER TABLE last_run ADD COLUMN missing INTEGER")
            current = 4

        self.conn.execute(
            "UPDATE schema_version SET version = ? WHERE id = 1",
            (current,),
        )

    def verify_integrity(self) -> bool:
        """Quick integrity check on the database file itself.

        Called by the caller's open path immediately after construction as
        the integrity gate that catches corruption which doesn't prevent the
        file from opening (exit code EXIT_DB_CORRUPT on failure).
        """
        result = self.conn.execute("PRAGMA quick_check").fetchone()
        return result is not None and result[0] == "ok"

    def close(self):
        # PRAGMA optimize refreshes query-planner statistics on indexes
        # touched during this session. Cheap (milliseconds) and keeps
        # plans accurate as the database grows. SQLite's recommended
        # close-time hygiene as of 3.18.
        try:
            self.conn.execute("PRAGMA optimize")
        except sqlite3.Error:
            pass
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

    def _like_prefix(self, prefix: str) -> Tuple[str]:
        """Return the single-element parameter tuple for LIKE-prefix queries.

        Consolidates the ``(_escape_like(prefix) + "%",)`` boilerplate
        used by every prefix-scoped SELECT/DELETE in this class. Query
        strings still use ``file_path LIKE ? ESCAPE '\\'`` verbatim.
        """
        return (self._escape_like(prefix) + "%",)

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
        """Mark a run as in progress.

        Resets only the run-state fields (started_at, finished_at, status,
        target_dir) and deliberately preserves the prior run's ``failed`` /
        ``missing`` counts so :meth:`previous_run_counts` can report the
        change after this run finishes. On the very first run the row is
        created with NULL counts (no prior run to compare against).
        """
        updated = self.conn.execute(
            "UPDATE last_run SET started_at = ?, finished_at = NULL, "
            "target_dir = ?, status = 'RUNNING' WHERE id = 1",
            (_now(), target_dir),
        ).rowcount
        if not updated:
            self.conn.execute(
                "INSERT INTO last_run "
                "(id, started_at, finished_at, target_dir, status, failed, missing) "
                "VALUES (1, ?, NULL, ?, 'RUNNING', NULL, NULL)",
                (_now(), target_dir),
            )

    def previous_run_counts(self) -> Optional[Tuple[int, int]]:
        """Return ``(failed, missing)`` from the last recorded run, or None.

        Returns None when no run has recorded counts yet (fresh database or
        a row migrated from before schema v4), so the first notification
        doesn't invent a bogus "was 0 last run" comparison. Must be read
        *before* :meth:`finish_run` overwrites the counts for this run.
        """
        row = self.conn.execute(
            "SELECT failed, missing FROM last_run WHERE id = 1"
        ).fetchone()
        if row is None or row["failed"] is None or row["missing"] is None:
            return None
        return (row["failed"], row["missing"])

    def last_run_info(self) -> Optional[Dict]:
        """Return the last run's timing/state, or None if none recorded.

        ``{"started_at", "finished_at", "status"}``. ``finished_at`` is None
        when the last run is still in progress or was hard-killed before it
        could mark itself COMPLETE (the same signal
        :meth:`check_interrupted_run` uses).
        """
        row = self.conn.execute(
            "SELECT started_at, finished_at, status FROM last_run WHERE id = 1"
        ).fetchone()
        if row is None:
            return None
        return {"started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "status": row["status"]}

    def finish_run(self, failed: int = 0, missing: int = 0):
        """Mark the current run as complete and record its problem counts."""
        self.conn.execute(
            "UPDATE last_run SET finished_at = ?, status = 'COMPLETE', "
            "failed = ?, missing = ? WHERE id = 1",
            (_now(), int(failed), int(missing)),
        )

    # ── Bulk lookups ──────────────────────────────────────────────────────

    def load_all_records(self, prefix: str) -> Dict[str, Tuple[str, int, str, str]]:
        """Load all tracked records under a directory prefix.

        Returns {file_path: (baseline_checksum, file_size, file_mtime, status)}.
        Uses baseline_checksum for comparisons since it holds the known-good
        hash. Includes MISSING records so re-added files are verified against
        their baseline. Escapes SQL LIKE wildcards.
        """
        rows = self.conn.execute(
            "SELECT file_path, baseline_checksum, file_size, file_mtime, status FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\'",
            self._like_prefix(prefix),
        ).fetchall()
        return {r["file_path"]: (r["baseline_checksum"], r["file_size"], r["file_mtime"], r["status"]) for r in rows}

    def get_missing_paths(self, prefix: str) -> Set[str]:
        """Return all file paths currently marked MISSING under a prefix."""
        rows = self.conn.execute(
            "SELECT file_path FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\' AND status = 'MISSING'",
            self._like_prefix(prefix),
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

    @contextlib.contextmanager
    def transaction(self) -> Iterator["ChecksumDB"]:
        """Context manager: begin, yield, commit — rollback on any exception.

        Catches BaseException (not just Exception) so KeyboardInterrupt
        or SystemExit raised mid-transaction rolls back the open write
        before the signal propagates. Without this, SQLite's write lock
        would be held until the connection is closed.
        """
        self.begin()
        try:
            yield self
            self.commit()
        except BaseException:
            self.rollback()
            raise

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
        cur = self.conn.execute(
            "DELETE FROM checksums WHERE file_path LIKE ? ESCAPE '\\' AND status = 'MISSING'",
            self._like_prefix(prefix),
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
        rows = self.conn.execute(
            "SELECT file_path FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\' AND status = 'FAILED'",
            self._like_prefix(prefix),
        ).fetchall()
        return [r["file_path"] for r in rows]

    def get_file_status(self, file_path: str) -> Optional[str]:
        """Return the status of a single file, or None if not tracked."""
        row = self.conn.execute(
            "SELECT status FROM checksums WHERE file_path = ?",
            (file_path,),
        ).fetchone()
        return row["status"] if row else None

    def get_file_record(self, file_path: str) -> Optional[Dict]:
        """Return the full database record for a file, or None if not tracked."""
        row = self.conn.execute(
            "SELECT file_path, baseline_checksum, checksum, file_size, "
            "file_mtime, status, first_seen, last_verified "
            "FROM checksums WHERE file_path = ?",
            (file_path,),
        ).fetchone()
        return dict(row) if row else None

    def update_last_verified(self, file_path: str, now: str):
        """Update last_verified timestamp for a file without changing any other field."""
        self.conn.execute(
            "UPDATE checksums SET last_verified = ? WHERE file_path = ?",
            (now, file_path),
        )

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
            "SELECT file_path, file_size, checksum, baseline_checksum, "
            "first_seen, last_verified "
            "FROM checksums WHERE status = 'FAILED'"
        ).fetchall()
        return [dict(r) for r in rows]

    def missing_files(self) -> List[Dict]:
        """Return details for all MISSING files (tracked, now gone from disk).

        Ordered by path for a stable, browsable listing. Mirrors
        :meth:`failed_files` so a report can enumerate every "not good" file,
        not just the corrupted ones.
        """
        rows = self.conn.execute(
            "SELECT file_path, file_size, first_seen, last_verified "
            "FROM checksums WHERE status = 'MISSING' ORDER BY file_path"
        ).fetchall()
        return [dict(r) for r in rows]

    def stale_files(self, days: int) -> List[Dict]:
        """Return files not verified in the given number of days."""
        rows = self.conn.execute(
            "SELECT file_path, first_seen, last_verified FROM checksums "
            # Stored last_verified is ISO 'YYYY-MM-DDTHH:MM:SSZ'; datetime('now')
            # yields 'YYYY-MM-DD HH:MM:SS'. Parse both sides so the T/Z don't
            # break the comparison on the boundary day. rtrim the trailing Z
            # for portability with SQLite < 3.42, which returns NULL for a
            # Z-suffixed string.
            "WHERE datetime(rtrim(last_verified, 'Z')) < datetime('now', ?)",
            (f"-{days} days",),
        ).fetchall()
        return [dict(r) for r in rows]

    def stalest_file_paths(self, prefix: str, limit: Optional[int] = None) -> List[str]:
        """Return file paths ordered by oldest last_verified first.

        Used by --budget mode to prioritize re-verifying the files that
        haven't been checked in the longest time. Only returns non-MISSING
        files under the given prefix.
        """
        query = (
            "SELECT file_path FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\' AND status != 'MISSING' "
            "ORDER BY last_verified ASC"
        )
        params: list = list(self._like_prefix(prefix))
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
        escaped_prefix = self._like_prefix(prefix)[0]
        rows = self.conn.execute(
            "SELECT file_path FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\' AND status != 'MISSING' "
            # Parse both sides so the stored 'T'/'Z' ISO form compares
            # correctly against datetime('now', ?); see stale_files().
            "AND datetime(rtrim(last_verified, 'Z')) < datetime('now', ?)",
            (escaped_prefix, f"-{days} days"),
        ).fetchall()
        return {r["file_path"] for r in rows}

    def detect_likely_moves(self, prefix: str) -> int:
        """Count NEW files whose checksum matches a MISSING file.

        A match strongly suggests a rename/move rather than a deletion
        and a new unrelated file. Returns the count of matches.
        """
        escaped_prefix = self._like_prefix(prefix)[0]
        row = self.conn.execute(
            "SELECT count(*) as count FROM checksums c1 "
            "WHERE c1.file_path LIKE ? ESCAPE '\\' AND c1.status = 'NEW' "
            "AND EXISTS ("
            "  SELECT 1 FROM checksums c2 "
            "  WHERE c2.file_path LIKE ? ESCAPE '\\' AND c2.status = 'MISSING' "
            "  AND c2.baseline_checksum = c1.baseline_checksum"
            ")",
            (escaped_prefix, escaped_prefix),
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

    def last_activity(self) -> Optional[str]:
        """Return the most recent last_verified timestamp, or None if empty."""
        row = self.conn.execute(
            "SELECT max(last_verified) as latest FROM checksums"
        ).fetchone()
        return row["latest"] if row and row["latest"] else None

    def status_counts(self) -> Dict[str, int]:
        """Return {status: count} dict for all tracked files."""
        rows = self.conn.execute(
            "SELECT status, count(*) as count FROM checksums GROUP BY status"
        ).fetchall()
        return {r["status"]: r["count"] for r in rows}

    def freshness_stats(self, prefix: str, days: int) -> tuple:
        """Return (total, verified_within, due) counts for non-MISSING files.

        Used to summarize verification coverage when --due is active.
        'verified_within' counts files whose last_verified is within the
        given day window; 'due' is the remainder (verified outside the
        window). last_verified is NOT NULL, so every non-MISSING file falls
        into exactly one of the two buckets.
        """
        escaped_prefix = self._like_prefix(prefix)[0]
        row = self.conn.execute(
            "SELECT "
            "  count(*) as total, "
            # Parse the stored 'T'/'Z' ISO timestamp so the window comparison
            # is correct on the boundary day; see stale_files().
            "  sum(CASE WHEN datetime(rtrim(last_verified, 'Z')) >= datetime('now', ?) "
            "           THEN 1 ELSE 0 END) as verified "
            "FROM checksums "
            "WHERE file_path LIKE ? ESCAPE '\\' AND status != 'MISSING'",
            (f"-{days} days", escaped_prefix),
        ).fetchone()
        total = row["total"] or 0
        verified = row["verified"] or 0
        due = total - verified
        return total, verified, due


# ── Legacy database auto-migration ─────────────────────────────────────────────

def _migrate_legacy_db_name(new_db_path: str) -> None:
    """Rename a pre-1.1 .{dirname}_checksums.db to .{dirname}_rotbyte.db.

    Runs before the lock is taken and before the DB is opened. Scope:

      - Only acts if `new_db_path` ends with the current suffix
        (.{dirname}_rotbyte.db) AND the new-name file does not yet exist.
      - Derives the legacy path by swapping the suffix and checks whether
        that file exists. If both exist, leaves both alone and prints a
        loud warning — that is an ambiguous state the user must resolve.
      - Atomically renames the DB and its .lock, -wal, -shm, and
        .manifest sidecars using os.replace() (atomic on POSIX and
        Windows when source and target are on the same volume).
      - Quiet when nothing to do. One informational line when it migrates.

    Users who passed a custom --db path are responsible for their own
    renames; this helper only handles the default-path layout.
    """
    if not new_db_path.endswith(DB_FILENAME_SUFFIX):
        return  # Custom --db path; out of scope
    if os.path.exists(new_db_path):
        return  # Already on the new name
    legacy_path = new_db_path[:-len(DB_FILENAME_SUFFIX)] + LEGACY_DB_FILENAME_SUFFIX
    if not os.path.exists(legacy_path):
        return  # Nothing to migrate

    # Ambiguous state: the legacy file exists but so does something else
    # at the new path. Covered by the os.path.exists check above, but
    # guard the sidecars too — if any new-name sidecar exists while the
    # legacy DB is present, refuse rather than clobber.
    sidecar_suffixes = (".lock", "-wal", "-shm", ".manifest")
    for sfx in sidecar_suffixes:
        if os.path.exists(new_db_path + sfx) and os.path.exists(legacy_path + sfx):
            print("Warning: both legacy and current rotbyte database files present:",
                  file=sys.stderr)
            print(f"  legacy : {legacy_path}{sfx}", file=sys.stderr)
            print(f"  current: {new_db_path}{sfx}", file=sys.stderr)
            print("  Resolve manually before running rotbyte.", file=sys.stderr)
            sys.exit(1)

    try:
        os.replace(legacy_path, new_db_path)
    except OSError as e:
        print(f"Warning: could not rename legacy database {legacy_path}: {e}",
              file=sys.stderr)
        return

    migrated = [os.path.basename(new_db_path)]
    for sfx in sidecar_suffixes:
        src = legacy_path + sfx
        dst = new_db_path + sfx
        if os.path.exists(src) and not os.path.exists(dst):
            try:
                os.replace(src, dst)
                migrated.append(os.path.basename(dst))
            except OSError as e:
                print(f"Warning: could not rename {src}: {e}", file=sys.stderr)

    print(f"  Renamed legacy database to {os.path.basename(new_db_path)} "
          f"({len(migrated)} file{'s' if len(migrated) != 1 else ''})",
          file=sys.stderr)
