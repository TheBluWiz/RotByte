"""
rotbyte — Comprehensive Test Harness
=====================================
Tests every automatable feature of rotbyte:

  - Database creation, schema, migrations
  - First-run indexing (NEW files)
  - Quick scan (skip unchanged, detect edits)
  - Full re-verify (--check catches bit rot)
  - Missing file detection
  - Move detection (new file matches missing checksum)
  - --accept single file (MISSING and FAILED)
  - --accept-all (bulk clear)
  - --import .b2sum/.b2 sidecar files
  - --export manifest
  - --report output
  - --json output
  - --budget time-limited scans
  - --due day-based filtering
  - --exclude directory exclusion
  - --include-hidden
  - --quiet mode
  - --db custom database location
  - --skip-missing
  - File locking (FileLock)
  - Exit codes (0, 1, 2, 3)
  - Prescan logic (modified vs unmodified)
  - Helpers: parse_duration, parse_clock_time, parse_days, _format_size, etc.
  - Schema migration (v1 → v2 baseline_checksum)
  - Edge cases: empty dirs, unreadable files, TOCTOU via fstat
  - Interrupt handling (simulated)
  - Database integrity check
  - b2sum import validation (bad hashes, missing media, mismatches)

Excludes (not automatable without mocking or real services):
  - --notify / --notify-setup (SMTP)
  - --track / --status (launchd/systemd)
  - TTY-specific spinner/progress rendering
"""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

# ── Import rotbyte module directly ─────────────────────────────────────────────

sys.path.insert(0, os.path.dirname(__file__))
import rotbyte


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def tmp(tmp_path):
    """Create a temp directory with a few test files."""
    (tmp_path / "a.txt").write_text("alpha")
    (tmp_path / "b.txt").write_text("bravo")
    (tmp_path / "c.txt").write_text("charlie")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "d.txt").write_text("delta")
    return tmp_path


@pytest.fixture
def db_path(tmp):
    """Return the default database path for the tmp directory."""
    name = "." + tmp.name + rotbyte.DB_FILENAME_SUFFIX
    return str(tmp / name)


@pytest.fixture
def db(db_path):
    """Open a fresh ChecksumDB and close it after the test."""
    d = rotbyte.ChecksumDB(db_path)
    yield d
    d.close()


def _run_cli(*args, cwd=None):
    """Run rotbyte as a subprocess and return (returncode, stdout, stderr)."""
    cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "rotbyte.py")] + list(args)
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=60)
    return r.returncode, r.stdout, r.stderr


def _extract_json(text: str) -> dict:
    """Extract the JSON object from output that may contain non-JSON lines.

    Use this instead of json.loads() whenever rotbyte's exit code is non-zero,
    because warning lines (MISSING, FAILED) are printed to stdout before the
    JSON blob.  For exit-code-0 cases, json.loads(out) is fine but this
    function also works — so it's safe to use unconditionally.
    """
    try:
        start = text.index("{")
    except ValueError:
        raise ValueError(
            f"No JSON object found in rotbyte output.\n"
            f"--- stdout was ---\n{text}\n--- end ---"
        )
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError(
        f"Unterminated JSON object in rotbyte output.\n"
        f"--- stdout was ---\n{text}\n--- end ---"
    )


def _hash_bytes(data: bytes) -> str:
    """Compute the BLAKE2b-512 hex digest of raw bytes."""
    return hashlib.blake2b(data).hexdigest()


def _corrupt_file(path: Path):
    """Overwrite file content while preserving exact mtime and size.

    This simulates silent bit rot: content changes but metadata stays
    the same, which is the exact scenario --check is designed to catch.
    """
    original = path.read_bytes()
    assert len(original) > 0, f"Cannot corrupt an empty file: {path}"
    st = path.stat()
    atime_ns = st.st_atime_ns
    mtime_ns = st.st_mtime_ns
    # Write different bytes of the same length
    corrupted = bytes((b ^ 0xFF) for b in original)
    path.write_bytes(corrupted)
    os.utime(str(path), ns=(atime_ns, mtime_ns))


def _insert_old_record(db, file_path, file_name="old.txt", file_size=10,
                       date="2020-01-01T00:00:00Z", checksum="x", status="OK"):
    """Insert a database record with a backdated last_verified timestamp.

    Useful for testing --due, stale file detection, and stalest-first ordering
    without waiting for real time to pass.
    """
    db.conn.execute(
        "INSERT INTO checksums (file_path, file_name, file_size, file_mtime, "
        "checksum, baseline_checksum, algorithm, status, first_seen, last_verified) "
        "VALUES (?, ?, ?, ?, ?, ?, 'BLAKE2b', ?, ?, ?)",
        (file_path, file_name, file_size, date, checksum, checksum, status, date, date),
    )


def _prescan_existing(tmp, filename, checksum="somehash", status="OK",
                      size_offset=0, mtime_override=None):
    """Build the existing-records dict entry for a single file.

    Returns (path, existing_dict) matching the format prescan_files expects.
    Saves repeating the os.stat / _mtime_iso boilerplate in every prescan test.
    """
    path = str(tmp / filename)
    st = os.stat(path)
    mtime = mtime_override or rotbyte._mtime_iso(st)
    existing = {path: (checksum, st.st_size + size_offset, mtime, status)}
    return path, existing


# ══════════════════════════════════════════════════════════════════════════════
# 1. Helpers & Parsers
# ══════════════════════════════════════════════════════════════════════════════

class TestParseDuration:
    def test_hours(self):
        assert rotbyte.parse_duration("2h") == 7200

    def test_minutes(self):
        assert rotbyte.parse_duration("30m") == 1800

    def test_combined(self):
        assert rotbyte.parse_duration("1h30m") == 5400

    def test_invalid_empty(self):
        with pytest.raises(ValueError):
            rotbyte.parse_duration("")

    def test_invalid_text(self):
        with pytest.raises(ValueError):
            rotbyte.parse_duration("abc")

    def test_zero(self):
        with pytest.raises(ValueError):
            rotbyte.parse_duration("0h")

    def test_zero_minutes(self):
        with pytest.raises(ValueError):
            rotbyte.parse_duration("0m")


class TestParseClockTime:
    def test_hour_only(self):
        assert rotbyte.parse_clock_time("2h") == (2, 0)

    def test_hour_minute(self):
        assert rotbyte.parse_clock_time("14h30m") == (14, 30)

    def test_midnight(self):
        assert rotbyte.parse_clock_time("0h") == (0, 0)

    def test_invalid_hour(self):
        with pytest.raises(ValueError):
            rotbyte.parse_clock_time("25h")

    def test_invalid_minute(self):
        with pytest.raises(ValueError):
            rotbyte.parse_clock_time("2h60m")

    def test_invalid_format(self):
        with pytest.raises(ValueError):
            rotbyte.parse_clock_time("2:30")


class TestParseDays:
    def test_normal(self):
        assert rotbyte.parse_days("30d") == 30

    def test_one(self):
        assert rotbyte.parse_days("1d") == 1

    def test_invalid(self):
        with pytest.raises(ValueError):
            rotbyte.parse_days("30")

    def test_zero(self):
        with pytest.raises(ValueError):
            rotbyte.parse_days("0d")


class TestFormatSize:
    def test_bytes(self):
        assert "B" in rotbyte._format_size(500)

    def test_kb(self):
        assert "KB" in rotbyte._format_size(2048)

    def test_gb(self):
        assert "GB" in rotbyte._format_size(2 * 1024**3)


class TestFormatDuration:
    def test_seconds(self):
        assert "s" in rotbyte._format_duration(5.3)

    def test_minutes(self):
        assert "m" in rotbyte._format_duration(90)

    def test_hours(self):
        result = rotbyte._format_duration(3661)
        assert "1h" in result
        assert "1m" in result


class TestFormatClockTime:
    def test_am(self):
        assert rotbyte._format_clock_time(2, 0) == "2 AM"

    def test_pm(self):
        assert rotbyte._format_clock_time(14, 30) == "2:30 PM"

    def test_noon(self):
        assert rotbyte._format_clock_time(12, 0) == "12 PM"

    def test_midnight(self):
        assert rotbyte._format_clock_time(0, 0) == "12 AM"


class TestUtcToLocal:
    def test_basic(self):
        result = rotbyte._utc_to_local("2026-04-09T14:30:00Z")
        assert "2026-04-09" in result

    def test_nanosecond(self):
        result = rotbyte._utc_to_local("2026-04-09T14:30:00.123456789Z")
        assert "2026-04-09" in result


# ══════════════════════════════════════════════════════════════════════════════
# 2. Hashing
# ══════════════════════════════════════════════════════════════════════════════

class TestHashFile:
    def test_normal(self, tmp):
        path = str(tmp / "a.txt")
        fpath, digest, size, mtime = rotbyte.hash_file(path)
        assert fpath == path
        assert digest == _hash_bytes(b"alpha")
        assert size == 5
        assert mtime is not None

    def test_nonexistent(self):
        fpath, digest, size, mtime = rotbyte.hash_file("/nonexistent/file")
        assert digest is None
        assert size is None

    def test_empty_file(self, tmp):
        p = tmp / "empty.txt"
        p.write_bytes(b"")
        fpath, digest, size, mtime = rotbyte.hash_file(str(p))
        assert digest == _hash_bytes(b"")
        assert size == 0


# ══════════════════════════════════════════════════════════════════════════════
# 3. Database
# ══════════════════════════════════════════════════════════════════════════════

class TestChecksumDB:
    def test_create(self, db):
        assert os.path.isfile(db.db_path)

    def test_integrity(self, db):
        assert db.verify_integrity()

    def test_upsert_new(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/f.txt", "f.txt", 100, now, "abc123", None, "NEW", now)
        row = db.conn.execute("SELECT * FROM checksums WHERE file_path = '/tmp/f.txt'").fetchone()
        assert row["status"] == "NEW"
        assert row["checksum"] == "abc123"
        assert row["baseline_checksum"] == "abc123"

    def test_upsert_update_ok(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/f.txt", "f.txt", 100, now, "aaa", None, "NEW", now)
        db.upsert_file("/tmp/f.txt", "f.txt", 100, now, "bbb", "aaa", "OK", now)
        row = db.conn.execute("SELECT * FROM checksums WHERE file_path = '/tmp/f.txt'").fetchone()
        assert row["status"] == "OK"
        assert row["checksum"] == "bbb"
        assert row["baseline_checksum"] == "bbb"

    def test_upsert_failed_preserves_baseline(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/f.txt", "f.txt", 100, now, "good", None, "OK", now)
        db.upsert_file("/tmp/f.txt", "f.txt", 100, now, "bad", "good", "FAILED", now)
        row = db.conn.execute("SELECT * FROM checksums WHERE file_path = '/tmp/f.txt'").fetchone()
        assert row["status"] == "FAILED"
        assert row["checksum"] == "bad"
        assert row["baseline_checksum"] == "good"  # preserved

    def test_mark_missing(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/f.txt", "f.txt", 100, now, "abc", None, "OK", now)
        db.mark_missing("/tmp/f.txt", now)
        assert db.get_file_status("/tmp/f.txt") == "MISSING"

    def test_mark_missing_idempotent(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/f.txt", "f.txt", 100, now, "abc", None, "OK", now)
        db.mark_missing("/tmp/f.txt", now)
        db.mark_missing("/tmp/f.txt", now)  # should not error
        assert db.get_file_status("/tmp/f.txt") == "MISSING"

    def test_purge_missing(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/dir/f.txt", "f.txt", 100, now, "abc", None, "OK", now)
        db.mark_missing("/tmp/dir/f.txt", now)
        count = db.purge_missing("/tmp/dir")
        assert count == 1
        assert db.get_file_status("/tmp/dir/f.txt") is None

    def test_purge_file(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/f.txt", "f.txt", 100, now, "abc", None, "OK", now)
        db.purge_file("/tmp/f.txt")
        assert db.get_file_status("/tmp/f.txt") is None

    def test_accept_file(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/f.txt", "f.txt", 100, now, "bad", None, "FAILED", now)
        db.accept_file("/tmp/f.txt", "new_good", 101, now, now)
        row = db.conn.execute("SELECT * FROM checksums WHERE file_path = '/tmp/f.txt'").fetchone()
        assert row["status"] == "OK"
        assert row["checksum"] == "new_good"
        assert row["baseline_checksum"] == "new_good"

    def test_status_summary(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/a", "a", 1, now, "x", None, "OK", now)
        db.upsert_file("/tmp/b", "b", 1, now, "y", None, "FAILED", now)
        summary = db.status_summary()
        statuses = {r["status"]: r["count"] for r in summary}
        assert statuses["OK"] == 1
        assert statuses["FAILED"] == 1

    def test_failed_files(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/f.txt", "f.txt", 100, now, "bad", None, "FAILED", now)
        failed = db.failed_files()
        assert len(failed) == 1
        assert failed[0]["file_path"] == "/tmp/f.txt"

    def test_stale_files(self, db):
        _insert_old_record(db, "/tmp/old.txt")
        stale = db.stale_files(90)
        assert len(stale) == 1

    def test_stalest_file_paths(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/new.txt", "new.txt", 1, now, "a", None, "OK", now)
        _insert_old_record(db, "/tmp/old.txt")
        order = db.stalest_file_paths("/tmp")
        assert order[0] == "/tmp/old.txt"  # oldest first

    def test_stalest_with_limit(self, db):
        now = rotbyte._now()
        for i in range(5):
            db.upsert_file(f"/tmp/f{i}", f"f{i}", 1, now, str(i), None, "OK", now)
        result = db.stalest_file_paths("/tmp", limit=2)
        assert len(result) == 2

    def test_due_file_paths(self, db):
        _insert_old_record(db, "/tmp/old.txt")
        due = db.due_file_paths("/tmp", 30)
        assert "/tmp/old.txt" in due

    def test_detect_likely_moves(self, db):
        now = rotbyte._now()
        db.upsert_file("/d/old.txt", "old.txt", 1, now, "same_hash", None, "OK", now)
        db.mark_missing("/d/old.txt", now)
        db.upsert_file("/d/new.txt", "new.txt", 1, now, "same_hash", None, "NEW", now)
        assert db.detect_likely_moves("/d") == 1

    def test_all_records(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/f.txt", "f.txt", 1, now, "x", None, "OK", now)
        recs = db.all_records()
        assert len(recs) == 1

    def test_last_activity(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/f.txt", "f.txt", 1, now, "x", None, "OK", now)
        assert db.last_activity() is not None

    def test_last_activity_empty(self, db):
        assert db.last_activity() is None

    def test_status_counts(self, db):
        now = rotbyte._now()
        db.upsert_file("/tmp/a", "a", 1, now, "x", None, "OK", now)
        db.upsert_file("/tmp/b", "b", 1, now, "y", None, "OK", now)
        counts = db.status_counts()
        assert counts["OK"] == 2

    def test_run_tracking(self, db):
        db.start_run("/tmp")
        row = db.conn.execute("SELECT status FROM last_run WHERE id = 1").fetchone()
        assert row["status"] == "RUNNING"
        db.finish_run()
        row = db.conn.execute("SELECT status FROM last_run WHERE id = 1").fetchone()
        assert row["status"] == "COMPLETE"

    def test_transaction_commit(self, db):
        now = rotbyte._now()
        db.begin()
        db.upsert_file("/tmp/f.txt", "f.txt", 1, now, "x", None, "OK", now)
        db.commit()
        assert db.get_file_status("/tmp/f.txt") == "OK"

    def test_transaction_rollback(self, db):
        now = rotbyte._now()
        db.begin()
        db.upsert_file("/tmp/f.txt", "f.txt", 1, now, "x", None, "OK", now)
        db.rollback()
        assert db.get_file_status("/tmp/f.txt") is None

    def test_escape_like_wildcards(self, db):
        now = rotbyte._now()
        # File path with SQL LIKE wildcards
        db.upsert_file("/tmp/100%_done/f.txt", "f.txt", 1, now, "x", None, "OK", now)
        records = db.load_all_records("/tmp/100%_done")
        assert len(records) == 1

    def test_load_all_records(self, db):
        now = rotbyte._now()
        db.upsert_file("/d/a.txt", "a.txt", 5, now, "aaa", None, "OK", now)
        db.upsert_file("/d/b.txt", "b.txt", 5, now, "bbb", None, "NEW", now)
        db.upsert_file("/other/c.txt", "c.txt", 5, now, "ccc", None, "OK", now)
        records = db.load_all_records("/d")
        assert len(records) == 2
        assert "/d/a.txt" in records
        assert "/other/c.txt" not in records

    def test_get_missing_paths(self, db):
        now = rotbyte._now()
        db.upsert_file("/d/a.txt", "a.txt", 5, now, "x", None, "OK", now)
        db.mark_missing("/d/a.txt", now)
        missing = db.get_missing_paths("/d")
        assert "/d/a.txt" in missing

    def test_get_failed_paths(self, db):
        now = rotbyte._now()
        db.upsert_file("/d/a.txt", "a.txt", 5, now, "bad", None, "FAILED", now)
        failed = db.get_failed_paths("/d")
        assert "/d/a.txt" in failed


# ══════════════════════════════════════════════════════════════════════════════
# 4. Schema Migration
# ══════════════════════════════════════════════════════════════════════════════

class TestSchemaMigration:
    def test_v1_to_v2_adds_baseline(self, tmp):
        """Simulate a v1 database and verify migration adds baseline_checksum."""
        db_path = str(tmp / ".test_checksums.db")
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE checksums (
                file_path TEXT PRIMARY KEY, file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL, file_mtime TEXT NOT NULL,
                checksum TEXT NOT NULL, algorithm TEXT NOT NULL DEFAULT 'BLAKE2b',
                status TEXT NOT NULL DEFAULT 'NEW', first_seen TEXT NOT NULL,
                last_verified TEXT NOT NULL, notes TEXT
            );
            CREATE TABLE last_run (
                id INTEGER PRIMARY KEY CHECK (id = 1), started_at TEXT NOT NULL,
                finished_at TEXT, target_dir TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'RUNNING'
            );
            CREATE TABLE schema_version (
                id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL DEFAULT 1
            );
            INSERT INTO schema_version (id, version) VALUES (1, 1);
            INSERT INTO checksums (file_path, file_name, file_size, file_mtime,
                checksum, algorithm, status, first_seen, last_verified)
            VALUES ('/tmp/f.txt', 'f.txt', 10, '2020-01-01T00:00:00Z',
                'oldhash', 'BLAKE2b', 'OK', '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z');
        """)
        conn.close()

        db = rotbyte.ChecksumDB(db_path)
        row = db.conn.execute("SELECT baseline_checksum FROM checksums WHERE file_path = '/tmp/f.txt'").fetchone()
        assert row["baseline_checksum"] == "oldhash"

        version = db.conn.execute("SELECT version FROM schema_version WHERE id = 1").fetchone()
        assert version["version"] == 2
        db.close()

    def test_fresh_db_is_current_version(self, tmp):
        db_path = str(tmp / ".fresh_checksums.db")
        db = rotbyte.ChecksumDB(db_path)
        version = db.conn.execute("SELECT version FROM schema_version WHERE id = 1").fetchone()
        assert version["version"] == rotbyte.SCHEMA_VERSION
        db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 5. File Scanning
# ══════════════════════════════════════════════════════════════════════════════

class TestScanFiles:
    def test_finds_all_files(self, tmp, db_path):
        files = rotbyte.scan_files(str(tmp), db_path)
        names = {os.path.basename(f) for f in files}
        assert names == {"a.txt", "b.txt", "c.txt", "d.txt"}

    def test_skips_hidden_by_default(self, tmp, db_path):
        (tmp / ".hidden").write_text("secret")
        (tmp / ".hiddendir").mkdir()
        (tmp / ".hiddendir" / "inside.txt").write_text("x")
        files = rotbyte.scan_files(str(tmp), db_path)
        names = {os.path.basename(f) for f in files}
        assert ".hidden" not in names
        assert "inside.txt" not in names

    def test_include_hidden(self, tmp, db_path):
        (tmp / ".hidden").write_text("secret")
        files = rotbyte.scan_files(str(tmp), db_path, include_hidden=True)
        names = {os.path.basename(f) for f in files}
        assert ".hidden" in names

    def test_exclude_dirs(self, tmp, db_path):
        sub = str(tmp / "sub")
        files = rotbyte.scan_files(str(tmp), db_path, exclude_dirs={os.path.realpath(sub)})
        names = {os.path.basename(f) for f in files}
        assert "d.txt" not in names
        assert "a.txt" in names

    def test_skips_b2sum_files(self, tmp, db_path):
        (tmp / "movie.mkv.b2sum").write_text("hash  movie.mkv")
        (tmp / "movie.mkv.b2").write_text("hash  movie.mkv")
        files = rotbyte.scan_files(str(tmp), db_path)
        names = {os.path.basename(f) for f in files}
        assert "movie.mkv.b2sum" not in names
        assert "movie.mkv.b2" not in names

    def test_skips_db_files(self, tmp, db_path):
        # Create the DB file so scan can see it
        Path(db_path).touch()
        files = rotbyte.scan_files(str(tmp), db_path)
        basenames = {os.path.basename(f) for f in files}
        assert os.path.basename(db_path) not in basenames

    def test_sorted_output(self, tmp, db_path):
        files = rotbyte.scan_files(str(tmp), db_path)
        assert files == sorted(files)

    def test_empty_directory(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        db_p = str(empty / ".empty_checksums.db")
        files = rotbyte.scan_files(str(empty), db_p)
        assert files == []


# ══════════════════════════════════════════════════════════════════════════════
# 6. Prescan Logic
# ══════════════════════════════════════════════════════════════════════════════

class TestPrescan:
    def test_new_files(self, tmp):
        all_files = [str(tmp / "a.txt")]
        to_hash, skipped = rotbyte.prescan_files(all_files, {}, force=False)
        assert len(to_hash) == 1
        assert to_hash[0].old_checksum is None
        assert skipped == 0

    def test_unchanged_skipped(self, tmp):
        """File with matching size, mtime, and OK status is skipped."""
        path, existing = _prescan_existing(tmp, "a.txt")
        to_hash, skipped = rotbyte.prescan_files([path], existing, force=False)
        assert len(to_hash) == 0
        assert skipped == 1

    def test_changed_size_hashed(self, tmp):
        """A size change means the file was edited — must re-hash."""
        path, existing = _prescan_existing(tmp, "a.txt", size_offset=100)
        to_hash, skipped = rotbyte.prescan_files([path], existing, force=False)
        assert len(to_hash) == 1
        assert to_hash[0].modified is True

    def test_force_hashes_all(self, tmp):
        """--check (force=True) re-hashes even unchanged files."""
        path, existing = _prescan_existing(tmp, "a.txt")
        to_hash, skipped = rotbyte.prescan_files([path], existing, force=True)
        assert len(to_hash) == 1
        assert skipped == 0

    def test_missing_always_rehashed(self, tmp):
        """A file previously marked MISSING must be re-verified when it reappears."""
        path, existing = _prescan_existing(tmp, "a.txt", status="MISSING")
        to_hash, skipped = rotbyte.prescan_files([path], existing, force=False)
        assert len(to_hash) == 1

    def test_failed_always_rehashed(self, tmp):
        """A FAILED file is always re-checked to see if the corruption persists."""
        path, existing = _prescan_existing(tmp, "a.txt", status="FAILED")
        to_hash, skipped = rotbyte.prescan_files([path], existing, force=False)
        assert len(to_hash) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 7. FileLock
# ══════════════════════════════════════════════════════════════════════════════

class TestFileLock:
    def test_acquire_release(self, tmp):
        lock_path = str(tmp / "test.lock")
        lock = rotbyte.FileLock(lock_path)
        assert lock.acquire() is True
        assert os.path.isfile(lock_path)
        lock.release()

    def test_double_lock_fails(self, tmp):
        lock_path = str(tmp / "test.lock")
        lock1 = rotbyte.FileLock(lock_path)
        lock2 = rotbyte.FileLock(lock_path)
        assert lock1.acquire() is True
        assert lock2.acquire() is False
        lock1.release()
        # lock2 was never acquired, no release needed

    def test_reacquire_after_release(self, tmp):
        lock_path = str(tmp / "test.lock")
        lock = rotbyte.FileLock(lock_path)
        assert lock.acquire() is True
        lock.release()
        lock2 = rotbyte.FileLock(lock_path)
        assert lock2.acquire() is True
        lock2.release()


# ══════════════════════════════════════════════════════════════════════════════
# 8. CLI Integration — First Run (Indexing)
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIFirstRun:
    def test_index_creates_db(self, tmp):
        rc, out, err = _run_cli(str(tmp))
        assert rc == 0
        db_name = "." + tmp.name + rotbyte.DB_FILENAME_SUFFIX
        assert (tmp / db_name).is_file()

    def test_index_reports_new_files(self, tmp):
        rc, out, err = _run_cli(str(tmp))
        assert rc == 0
        assert "New files" in out or "new" in out.lower()

    def test_json_output_first_run(self, tmp):
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["new"] == 4
        assert data["failed"] == 0
        assert data["missing"] == 0
        assert data["status"] == "complete"


# ══════════════════════════════════════════════════════════════════════════════
# 9. CLI — Quick Scan (unchanged files skipped)
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIQuickScan:
    def test_second_run_skips(self, tmp):
        _run_cli(str(tmp))
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["new"] == 0
        assert data["skipped"] == 4

    def test_edit_detected(self, tmp):
        _run_cli(str(tmp))
        time.sleep(0.05)
        (tmp / "a.txt").write_text("alpha_modified")
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["updated"] >= 1
        assert data["failed"] == 0  # edit, not bit rot


# ══════════════════════════════════════════════════════════════════════════════
# 10. CLI — Full Verify (--check, bit rot detection)
# ══════════════════════════════════════════════════════════════════════════════

class TestCLICheck:
    def test_check_no_changes(self, tmp):
        _run_cli(str(tmp))
        rc, out, err = _run_cli("--check", "--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["verified_ok"] == 4
        assert data["failed"] == 0

    def test_check_detects_bit_rot(self, tmp):
        _run_cli(str(tmp))
        _corrupt_file(tmp / "a.txt")
        rc, out, err = _run_cli("--check", "--json", str(tmp))
        assert rc == 2  # exit code for bit rot
        data = _extract_json(out)
        assert data["failed"] >= 1

    def test_check_exit_code_2(self, tmp):
        _run_cli(str(tmp))
        _corrupt_file(tmp / "b.txt")
        rc, _, _ = _run_cli("--check", str(tmp))
        assert rc == 2


# ══════════════════════════════════════════════════════════════════════════════
# 11. CLI — Missing Files
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIMissing:
    def test_missing_detected(self, tmp):
        _run_cli(str(tmp))
        (tmp / "a.txt").unlink()
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 1  # exit code for missing
        data = _extract_json(out)
        assert data["missing"] >= 1

    def test_skip_missing_flag(self, tmp):
        _run_cli(str(tmp))
        (tmp / "a.txt").unlink()
        rc, out, err = _run_cli("--skip-missing", "--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["missing"] == 0

    def test_reappeared_file_verified(self, tmp):
        """A file that disappears and reappears should be re-verified."""
        _run_cli(str(tmp))
        content = (tmp / "a.txt").read_bytes()
        (tmp / "a.txt").unlink()
        _run_cli(str(tmp))  # marks MISSING
        (tmp / "a.txt").write_bytes(content)
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["verified_ok"] >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 12. CLI — Move Detection
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIMoveDetection:
    def test_rename_detected(self, tmp):
        _run_cli(str(tmp))
        content = (tmp / "a.txt").read_bytes()
        (tmp / "a.txt").unlink()
        (tmp / "a_renamed.txt").write_bytes(content)
        rc, out, err = _run_cli("--json", str(tmp))
        data = _extract_json(out)
        assert data["likely_moves"] >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 13. CLI — --accept
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIAccept:
    def test_accept_missing(self, tmp):
        _run_cli(str(tmp))
        (tmp / "a.txt").unlink()
        _run_cli(str(tmp))  # marks MISSING
        rc, out, err = _run_cli("--accept", str(tmp / "a.txt"), str(tmp))
        assert rc == 0
        assert "Removed" in out

    def test_accept_failed(self, tmp):
        _run_cli(str(tmp))
        _corrupt_file(tmp / "a.txt")
        _run_cli("--check", str(tmp))  # marks FAILED
        rc, out, err = _run_cli("--accept", str(tmp / "a.txt"), str(tmp))
        assert rc == 0
        assert "Accepted" in out

    def test_accept_unknown_file(self, tmp):
        _run_cli(str(tmp))
        rc, out, err = _run_cli("--accept", "/nonexistent/file.txt", str(tmp))
        assert rc == 1


# ══════════════════════════════════════════════════════════════════════════════
# 14. CLI — --accept-all
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIAcceptAll:
    def test_accept_all_clears_missing_and_failed(self, tmp):
        _run_cli(str(tmp))
        _corrupt_file(tmp / "a.txt")
        (tmp / "b.txt").unlink()
        _run_cli("--check", str(tmp))
        rc, out, err = _run_cli("--accept-all", str(tmp))
        assert rc == 0
        assert "Missing cleared" in out
        assert "Failed accepted" in out

    def test_accept_all_nothing_to_do(self, tmp):
        _run_cli(str(tmp))
        rc, out, err = _run_cli("--accept-all", str(tmp))
        assert rc == 0
        assert "Nothing to reconcile" in out


# ══════════════════════════════════════════════════════════════════════════════
# 15. CLI — --import
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIImport:
    def test_import_b2sum(self, tmp):
        # Write a valid .b2sum sidecar
        content = (tmp / "a.txt").read_bytes()
        expected_hash = _hash_bytes(content)
        (tmp / "a.txt.b2sum").write_text(f"{expected_hash}  a.txt\n")

        rc, out, err = _run_cli("--import", str(tmp))
        assert rc == 0
        assert "Imported: a.txt" in out
        assert not (tmp / "a.txt.b2sum").exists()  # sidecar deleted

    def test_import_b2(self, tmp):
        content = (tmp / "b.txt").read_bytes()
        expected_hash = _hash_bytes(content)
        (tmp / "b.txt.b2").write_text(f"{expected_hash}  b.txt\n")

        rc, out, err = _run_cli("--import", str(tmp))
        assert rc == 0
        assert "Imported: b.txt" in out

    def test_import_mismatch(self, tmp):
        (tmp / "a.txt.b2sum").write_text("0" * 128 + "  a.txt\n")
        rc, out, err = _run_cli("--import", str(tmp))
        assert "MISMATCH" in out

    def test_import_invalid_hash_length(self, tmp):
        (tmp / "a.txt.b2sum").write_text("abc  a.txt\n")
        rc, out, err = _run_cli("--import", str(tmp))
        assert "Invalid hash" in out

    def test_import_no_matching_file(self, tmp):
        (tmp / "nonexistent.mkv.b2sum").write_text("0" * 128 + "  nonexistent.mkv\n")
        rc, out, err = _run_cli("--import", str(tmp))
        assert "No matching file" in out

    def test_import_empty_hash_file(self, tmp):
        (tmp / "a.txt.b2sum").write_text("")
        rc, out, err = _run_cli("--import", str(tmp))
        assert "Empty file" in out

    def test_import_no_sidecars(self, tmp):
        rc, out, err = _run_cli("--import", str(tmp))
        assert "No .b2sum or .b2 files found" in out

    def test_import_already_tracked(self, tmp):
        # First index the file normally
        _run_cli(str(tmp))
        content = (tmp / "a.txt").read_bytes()
        expected_hash = _hash_bytes(content)
        (tmp / "a.txt.b2sum").write_text(f"{expected_hash}  a.txt\n")
        rc, out, err = _run_cli("--import", str(tmp))
        assert "Already tracked" in out


# ══════════════════════════════════════════════════════════════════════════════
# 16. CLI — --export
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIExport:
    def test_export(self, tmp):
        _run_cli(str(tmp))
        export_path = str(tmp / "manifest.txt")
        rc, out, err = _run_cli("--export", export_path, str(tmp))
        assert rc == 0
        assert os.path.isfile(export_path)
        content = Path(export_path).read_text()
        assert "a.txt" in content
        # Each line should be: <128-char hash>  <path>
        for line in content.strip().splitlines():
            parts = line.split("  ", 1)
            assert len(parts[0]) == 128

    def test_export_excludes_missing(self, tmp):
        _run_cli(str(tmp))
        (tmp / "a.txt").unlink()
        _run_cli(str(tmp))  # mark MISSING
        export_path = str(tmp / "manifest.txt")
        _run_cli("--export", export_path, str(tmp))
        content = Path(export_path).read_text()
        for line in content.strip().splitlines():
            assert "a.txt" not in line

    def test_export_empty_db(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        rc, out, err = _run_cli("--export", str(empty / "out.txt"), str(empty))
        assert rc == 1  # exits with error on empty DB


# ══════════════════════════════════════════════════════════════════════════════
# 17. CLI — --report
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIReport:
    def test_report_after_scan(self, tmp):
        _run_cli(str(tmp))
        rc, out, err = _run_cli("--report", str(tmp))
        assert rc == 0
        assert "Integrity Report" in out
        assert "Total tracked files" in out

    def test_report_empty_db(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        rc, out, err = _run_cli("--report", str(empty))
        assert rc == 0
        assert "empty" in out.lower()

    def test_report_shows_failed(self, tmp):
        _run_cli(str(tmp))
        _corrupt_file(tmp / "a.txt")
        _run_cli("--check", str(tmp))
        rc, out, err = _run_cli("--report", str(tmp))
        assert "Failed files" in out or "FAILED" in out


# ══════════════════════════════════════════════════════════════════════════════
# 18. CLI — --json
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIJson:
    def test_json_structure(self, tmp):
        rc, out, err = _run_cli("--json", str(tmp))
        data = _extract_json(out)
        for key in ("status", "directory", "duration_seconds", "bytes_hashed",
                     "new", "updated", "verified_ok", "failed", "missing",
                     "skipped", "errors", "likely_moves"):
            assert key in data

    def test_json_failed_files_listed(self, tmp):
        _run_cli(str(tmp))
        _corrupt_file(tmp / "a.txt")
        rc, out, err = _run_cli("--check", "--json", str(tmp))
        data = _extract_json(out)
        assert "failed_files" in data
        assert len(data["failed_files"]) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 19. CLI — --quiet
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIQuiet:
    def test_quiet_no_output_on_ok(self, tmp):
        _run_cli(str(tmp))
        rc, out, err = _run_cli("--quiet", str(tmp))
        assert rc == 0
        # Quiet mode suppresses the verbose scanning/loading progress lines
        assert "Scanning" not in out
        assert "Loading" not in out

    def test_quiet_shows_problems(self, tmp):
        _run_cli(str(tmp))
        (tmp / "a.txt").unlink()
        rc, out, err = _run_cli("--quiet", str(tmp))
        assert rc == 1
        assert "MISSING" in out


# ══════════════════════════════════════════════════════════════════════════════
# 20. CLI — --budget
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIBudget:
    def test_budget_requires_check_or_due(self, tmp):
        rc, out, err = _run_cli("--budget", "1h", str(tmp))
        assert rc != 0
        assert "requires" in err.lower() or "requires" in out.lower()

    def test_budget_with_check(self, tmp):
        _run_cli(str(tmp))
        rc, out, err = _run_cli("--check", "--budget", "2h", "--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["status"] == "complete"

    def test_budget_invalid_format(self, tmp):
        rc, out, err = _run_cli("--check", "--budget", "abc", str(tmp))
        assert rc != 0


# ══════════════════════════════════════════════════════════════════════════════
# 21. CLI — --due
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIDue:
    def test_due_implies_check(self, tmp):
        _run_cli(str(tmp))
        rc, out, err = _run_cli("--due", "30d", "--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        # Files were just indexed seconds ago, so none are due for re-check
        assert data["verified_ok"] == 0
        assert data["skipped"] == 4

    def test_due_invalid_format(self, tmp):
        rc, out, err = _run_cli("--due", "30", str(tmp))
        assert rc != 0


# ══════════════════════════════════════════════════════════════════════════════
# 22. CLI — --db custom database
# ══════════════════════════════════════════════════════════════════════════════

class TestCLICustomDB:
    def test_custom_db_path(self, tmp, tmp_path):
        custom_db = str(tmp_path / "custom.db")
        rc, out, err = _run_cli("--db", custom_db, str(tmp))
        assert rc == 0
        assert os.path.isfile(custom_db)


# ══════════════════════════════════════════════════════════════════════════════
# 23. CLI — --exclude
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIExclude:
    def test_exclude_directory(self, tmp):
        rc, out, err = _run_cli("--exclude", "sub", "--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["new"] == 3  # a, b, c — not d in sub/

    def test_exclude_absolute(self, tmp):
        rc, out, err = _run_cli("--exclude", str(tmp / "sub"), "--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["new"] == 3

    def test_exclude_multiple(self, tmp):
        sub2 = tmp / "sub2"
        sub2.mkdir()
        (sub2 / "e.txt").write_text("echo")
        rc, out, err = _run_cli("--exclude", "sub", "sub2", "--json", str(tmp))
        data = _extract_json(out)
        assert data["new"] == 3  # only a, b, c


# ══════════════════════════════════════════════════════════════════════════════
# 24. CLI — --include-hidden
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIIncludeHidden:
    def test_include_hidden(self, tmp):
        (tmp / ".secret").write_text("hidden")
        rc, out, err = _run_cli("--include-hidden", "--json", str(tmp))
        data = _extract_json(out)
        assert data["new"] == 5  # 4 + .secret


# ══════════════════════════════════════════════════════════════════════════════
# 25. CLI — Exit Codes
# ══════════════════════════════════════════════════════════════════════════════

class TestExitCodes:
    def test_exit_0_all_ok(self, tmp):
        rc, _, _ = _run_cli(str(tmp))
        assert rc == 0

    def test_exit_1_missing(self, tmp):
        _run_cli(str(tmp))
        (tmp / "a.txt").unlink()
        rc, _, _ = _run_cli(str(tmp))
        assert rc == 1

    def test_exit_2_bit_rot(self, tmp):
        _run_cli(str(tmp))
        _corrupt_file(tmp / "a.txt")
        rc, _, _ = _run_cli("--check", str(tmp))
        assert rc == 2

    def test_exit_2_trumps_exit_1(self, tmp):
        """Bit rot exit code takes priority over missing."""
        _run_cli(str(tmp))
        _corrupt_file(tmp / "a.txt")
        (tmp / "b.txt").unlink()
        rc, _, _ = _run_cli("--check", str(tmp))
        assert rc == 2  # bit rot takes priority


# ══════════════════════════════════════════════════════════════════════════════
# 26. CLI — Concurrent lock
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIConcurrentLock:
    def test_concurrent_run_blocked(self, tmp):
        """A second instance against the same DB should fail."""
        db_name = "." + tmp.name + rotbyte.DB_FILENAME_SUFFIX
        lock_path = str(tmp / db_name) + ".lock"
        lock = rotbyte.FileLock(lock_path)
        assert lock.acquire()
        try:
            rc, out, err = _run_cli(str(tmp))
            assert rc != 0
            assert "Another instance" in err or "already running" in err
        finally:
            lock.release()


# ══════════════════════════════════════════════════════════════════════════════
# 27. CLI — Invalid inputs
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIInvalidInputs:
    def test_nonexistent_dir(self):
        rc, out, err = _run_cli("/this/dir/does/not/exist")
        assert rc != 0
        assert "not a directory" in err

    def test_full_at_without_track(self, tmp):
        rc, out, err = _run_cli("--full-at", "2h", str(tmp))
        assert rc != 0

    def test_every_without_track(self, tmp):
        rc, out, err = _run_cli("--every", "30m", str(tmp))
        assert rc != 0

    def test_workers_zero(self, tmp):
        rc, out, err = _run_cli("--workers", "0", str(tmp))
        assert rc != 0


# ══════════════════════════════════════════════════════════════════════════════
# 28. Run Hashing — unit test
# ══════════════════════════════════════════════════════════════════════════════

class TestRunHashing:
    def test_basic_hashing(self, tmp, db):
        now = rotbyte._now()
        entries = [
            rotbyte.FileEntry(str(tmp / "a.txt"), "a.txt", 5,
                              now, None, True),
        ]
        result = rotbyte.run_hashing(db, entries, workers=1, now=now,
                                     interrupted=[False], quiet=True)
        assert result.new == 1
        assert result.failed == 0

    def test_hashing_detects_bit_rot(self, tmp, db):
        # Insert a known-good record with a wrong checksum
        now = rotbyte._now()
        st = os.stat(str(tmp / "a.txt"))
        mtime = rotbyte._mtime_iso(st)
        entries = [
            rotbyte.FileEntry(str(tmp / "a.txt"), "a.txt", st.st_size,
                              mtime, "wrong_checksum_on_purpose", False),
        ]
        result = rotbyte.run_hashing(db, entries, workers=1, now=now,
                                     interrupted=[False], quiet=True)
        assert result.failed == 1

    def test_hashing_edit_not_failure(self, tmp, db):
        now = rotbyte._now()
        entries = [
            rotbyte.FileEntry(str(tmp / "a.txt"), "a.txt", 5,
                              now, "old_hash", True),  # modified=True
        ]
        result = rotbyte.run_hashing(db, entries, workers=1, now=now,
                                     interrupted=[False], quiet=True)
        assert result.updated == 1
        assert result.failed == 0

    def test_empty_entries(self, db):
        now = rotbyte._now()
        result = rotbyte.run_hashing(db, [], workers=1, now=now,
                                     interrupted=[False], quiet=True)
        assert result.new == 0

    def test_interrupt_flag(self, tmp, db):
        """Hashing respects the interrupted flag."""
        now = rotbyte._now()
        # Create many files to increase chance the flag is checked
        for i in range(20):
            (tmp / f"file_{i}.txt").write_text(f"content {i}")
        entries = [
            rotbyte.FileEntry(str(tmp / f"file_{i}.txt"), f"file_{i}.txt",
                              10, now, None, True)
            for i in range(20)
        ]
        interrupted = [True]  # pre-set
        result = rotbyte.run_hashing(db, entries, workers=1, now=now,
                                     interrupted=interrupted, quiet=True)
        # Should process fewer than all 20
        assert result.new < 20


# ══════════════════════════════════════════════════════════════════════════════
# 29. Detect Missing — unit test
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectMissing:
    def test_detects_missing(self, tmp, db):
        now = rotbyte._now()
        target = str(tmp)
        # Pretend "a.txt" was tracked
        real_a = str(tmp / "a.txt")
        db.upsert_file(real_a, "a.txt", 5, now, "x", None, "OK", now)
        # But only b.txt is on disk
        on_disk = {str(tmp / "b.txt")}
        existing = db.load_all_records(target)
        count = rotbyte.detect_missing(db, target, on_disk, existing, now)
        assert count == 1
        assert db.get_file_status(real_a) == "MISSING"


# ══════════════════════════════════════════════════════════════════════════════
# 30. Launchd / Systemd generation (string output only, no install)
# ══════════════════════════════════════════════════════════════════════════════

class TestSchedulerGeneration:
    def test_launchd_plist_interval(self):
        xml = rotbyte._generate_launchd_plist(
            "com.rotbyte.test", ["python3", "rotbyte.py", "/tmp"],
            interval_seconds=3600,
        )
        assert "com.rotbyte.test" in xml
        assert "<integer>3600</integer>" in xml
        assert "rotbyte.py" in xml

    def test_launchd_plist_calendar(self):
        xml = rotbyte._generate_launchd_plist(
            "com.rotbyte.full", ["python3", "rotbyte.py", "--check", "/tmp"],
            calendar_times=[(2, 0), (14, 30)],
        )
        assert "StartCalendarInterval" in xml
        assert "<integer>2</integer>" in xml
        assert "<integer>14</integer>" in xml

    def test_launchd_plist_valid_xml(self):
        import plistlib
        xml = rotbyte._generate_launchd_plist(
            "com.rotbyte.test", ["python3", "/path/to/rotbyte.py", "/Volumes/Media"],
            interval_seconds=1800,
        )
        # Should parse without error
        plistlib.loads(xml.encode())

    def test_systemd_service(self):
        unit = rotbyte._generate_systemd_unit(
            "rotbyte quick scan", ["rotbyte", "--quiet", "/data"],
        )
        assert "ExecStart=rotbyte --quiet /data" in unit
        assert "Type=oneshot" in unit

    def test_systemd_timer_interval(self):
        timer = rotbyte._generate_systemd_timer(
            "rotbyte timer", interval_seconds=1800,
        )
        assert "OnUnitActiveSec=30min" in timer

    def test_systemd_timer_calendar(self):
        timer = rotbyte._generate_systemd_timer(
            "rotbyte timer", calendar_times=[(2, 0)],
        )
        assert "OnCalendar=*-*-* 02:00:00" in timer
        assert "Persistent=true" in timer


# ══════════════════════════════════════════════════════════════════════════════
# 31. _parse_cmd_flags
# ══════════════════════════════════════════════════════════════════════════════

class TestParseCmdFlags:
    def test_parses_all_flags(self):
        args = ["rotbyte", "--check", "--due", "30d", "--budget", "2h",
                "--workers", "4", "--notify", "email", "--quiet", "/data"]
        flags = rotbyte._parse_cmd_flags(args)
        assert flags["due"] == "30d"
        assert flags["budget"] == "2h"
        assert flags["workers"] == "4"
        assert flags["notify"] == "email"

    def test_no_flags(self):
        flags = rotbyte._parse_cmd_flags(["rotbyte", "--quiet", "/data"])
        assert "due" not in flags


# ══════════════════════════════════════════════════════════════════════════════
# 32. Notify config path
# ══════════════════════════════════════════════════════════════════════════════

class TestNotifyConfigPath:
    def test_returns_string(self):
        path = rotbyte._notify_config_path()
        assert isinstance(path, str)
        assert "rotbyte" in path
        assert "notify.conf" in path


# ══════════════════════════════════════════════════════════════════════════════
# 33. _dir_hash
# ══════════════════════════════════════════════════════════════════════════════

class TestDirHash:
    def test_deterministic(self):
        h1 = rotbyte._dir_hash("/Volumes/Media")
        h2 = rotbyte._dir_hash("/Volumes/Media")
        assert h1 == h2

    def test_different_dirs_different_hashes(self):
        h1 = rotbyte._dir_hash("/Volumes/Media")
        h2 = rotbyte._dir_hash("/Volumes/Other")
        assert h1 != h2

    def test_length(self):
        assert len(rotbyte._dir_hash("/tmp")) == 8


# ══════════════════════════════════════════════════════════════════════════════
# 34. Edge cases
# ══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_file_with_special_chars_in_name(self, tmp):
        special = tmp / "hello world (copy) [2].txt"
        special.write_text("special")
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["new"] == 5  # 4 fixture files + special

    def test_deeply_nested(self, tmp):
        deep = tmp / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        (deep / "deep.txt").write_text("deep")
        rc, out, err = _run_cli("--json", str(tmp))
        data = _extract_json(out)
        assert data["new"] == 5

    def test_large_file_count(self, tmp_path):
        """Test with many small files."""
        d = tmp_path / "many"
        d.mkdir()
        for i in range(100):
            (d / f"f{i:03d}.txt").write_text(f"content {i}")
        rc, out, err = _run_cli("--json", str(d))
        data = _extract_json(out)
        assert data["new"] == 100

    @pytest.mark.skipif(os.getuid() == 0, reason="root ignores file permissions")
    def test_unreadable_file(self, tmp):
        """Unreadable files should be counted as errors, not crash."""
        bad = tmp / "unreadable.txt"
        bad.write_text("secret")
        bad.chmod(0o000)
        try:
            rc, out, err = _run_cli("--json", str(tmp))
            data = _extract_json(out)
            assert data["new"] == 4       # the 4 readable fixture files
            assert data["errors"] == 1    # the unreadable one
        finally:
            bad.chmod(0o644)

    def test_symlink_not_followed(self, tmp):
        """Symlinks to files should be hashed, but symlink dirs not followed."""
        target = tmp / "a.txt"
        link = tmp / "link.txt"
        link.symlink_to(target)
        rc, out, err = _run_cli("--json", str(tmp))
        data = _extract_json(out)
        # 4 fixture files + 1 symlink to a.txt = 5 files scanned
        assert data["new"] == 5

    def test_empty_file_hashes(self, tmp):
        (tmp / "empty.txt").write_bytes(b"")
        _run_cli(str(tmp))
        rc, out, err = _run_cli("--check", "--json", str(tmp))
        data = _extract_json(out)
        assert data["failed"] == 0

    def test_mtime_nanosecond_precision(self, tmp):
        """Verify sub-second mtime is handled correctly."""
        path = str(tmp / "a.txt")
        st = os.stat(path)
        iso = rotbyte._mtime_iso(st)
        # Should be a valid ISO string
        assert iso.endswith("Z")
        assert "T" in iso

    def test_version_flag(self):
        rc, out, err = _run_cli("--version")
        assert rc == 0
        assert "rotbyte" in out or rotbyte.VERSION in out

    def test_help_flag(self):
        rc, out, err = _run_cli("--help")
        assert rc == 0
        assert "rotbyte" in out


# ══════════════════════════════════════════════════════════════════════════════
# 35. Database corruption detection
# ══════════════════════════════════════════════════════════════════════════════

class TestDBCorruption:
    def test_corrupt_db_exits_gracefully(self, tmp):
        db_name = "." + tmp.name + rotbyte.DB_FILENAME_SUFFIX
        db_path = tmp / db_name
        db_path.write_bytes(b"this is not a sqlite database")
        rc, out, err = _run_cli(str(tmp))
        assert rc != 0
        assert "corrupt" in err.lower() or "could not open" in err.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 36. Workers flag
# ══════════════════════════════════════════════════════════════════════════════

class TestWorkers:
    def test_custom_workers(self, tmp):
        rc, out, err = _run_cli("--workers", "2", "--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["new"] == 4

    def test_single_worker(self, tmp):
        rc, out, err = _run_cli("--workers", "1", "--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["new"] == 4


# ══════════════════════════════════════════════════════════════════════════════
# 37. Interrupted run detection
# ══════════════════════════════════════════════════════════════════════════════

class TestInterruptedRunDetection:
    def test_interrupted_warning(self, tmp, db):
        """If a previous run was interrupted, the next run should warn."""
        db.start_run(str(tmp))
        # Don't call finish_run — simulates interrupt
        db.close()
        rc, out, err = _run_cli(str(tmp))
        assert rc == 0
        combined = out + err
        assert "previous run" in combined.lower() or "interrupted" in combined.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])


# ══════════════════════════════════════════════════════════════════════════════
# 38. Accept edge cases
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIAcceptEdgeCases:
    def test_accept_ok_file_is_noop(self, tmp):
        """Accepting a file that is already OK should not error or change state."""
        _run_cli(str(tmp))
        rc, out, err = _run_cli("--accept", str(tmp / "a.txt"), str(tmp))
        # Should indicate there's nothing to accept
        assert "nothing to accept" in out.lower() or "status 'OK'" in out


# ══════════════════════════════════════════════════════════════════════════════
# 39. Unicode filenames
# ══════════════════════════════════════════════════════════════════════════════

class TestUnicodeFilenames:
    def test_emoji_filename(self, tmp):
        (tmp / "📸 photo.txt").write_text("emoji")
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["new"] == 5  # 4 fixtures + emoji file

    def test_cjk_filename(self, tmp):
        (tmp / "报告书.txt").write_text("chinese")
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["new"] == 5

    def test_accented_filename(self, tmp):
        (tmp / "café résumé.txt").write_text("accented")
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["new"] == 5


# ══════════════════════════════════════════════════════════════════════════════
# 40. Export → Import round-trip
# ══════════════════════════════════════════════════════════════════════════════

class TestExportImportRoundTrip:
    def test_round_trip(self, tmp):
        """Export a manifest, wipe the DB, re-import via b2sum sidecars,
        then verify all checksums still match."""
        # Step 1: index all files
        _run_cli(str(tmp))

        # Step 2: export manifest
        manifest = tmp / "manifest.txt"
        rc, _, _ = _run_cli("--export", str(manifest), str(tmp))
        assert rc == 0

        # Step 3: convert manifest lines to .b2sum sidecar files,
        # placing each sidecar next to its source file
        for line in manifest.read_text().strip().splitlines():
            checksum, filepath = line.split("  ", 1)
            name = os.path.basename(filepath)
            sidecar_dir = os.path.dirname(filepath)
            sidecar = Path(sidecar_dir) / (name + ".b2sum")
            sidecar.write_text(f"{checksum}  {name}\n")

        # Step 4: delete the DB
        db_name = "." + tmp.name + rotbyte.DB_FILENAME_SUFFIX
        (tmp / db_name).unlink()
        manifest.unlink()

        # Step 5: import from sidecars
        rc, out, _ = _run_cli("--import", str(tmp))
        assert rc == 0
        assert "MISMATCH" not in out  # all checksums should match

        # Step 6: verify imported data with --check
        rc, out, _ = _run_cli("--check", "--json", str(tmp))
        data = _extract_json(out)
        assert data["failed"] == 0
        assert data["verified_ok"] == 4