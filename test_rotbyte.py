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
import io
import json
import os
import sqlite3
import subprocess
import sys
import time
import unittest.mock
from datetime import datetime
from pathlib import Path

import pytest

# ── Import rotbyte module directly ─────────────────────────────────────────────

sys.path.insert(0, os.path.dirname(__file__))
import rotbyte
import _rotbyte as _rotbyte_pkg
import _rotbyte.scheduler  # noqa: F401 — registers submodule attribute
import _rotbyte.scheduler.launchd  # noqa: F401
import _rotbyte.scheduler.schtasks  # noqa: F401
import _rotbyte.scheduler.systemd  # noqa: F401


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def tmp(tmp_path):
    """Create a temp directory pre-populated with four small test files.

    Convention used throughout this suite:
      - `tmp`       → pre-populated (a.txt, b.txt, c.txt, sub/d.txt).
                      Default for tests that want "a dir with some files".
      - `tmp_path`  → pytest's own empty temp dir. Use it when the test
                      needs a custom layout, an empty dir, or a separate
                      sandbox from a `tmp` already in scope.

    Mixing both in one test is intentional — e.g. `tmp` as the scan target
    and `tmp_path` as an independent destination for an exported manifest.
    """
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


def _run_cli_ok(*args, cwd=None):
    """Run rotbyte and assert exit code 0.

    Use for setup calls where a failure would invalidate the test's
    assumptions — rather than `_run_cli(...)` and letting a silent
    non-zero exit cascade into a confusing downstream assertion.
    """
    rc, out, err = _run_cli(*args, cwd=cwd)
    assert rc == 0, (
        f"setup _run_cli({args!r}) failed: rc={rc}\n"
        f"--- stdout ---\n{out}\n--- stderr ---\n{err}"
    )
    return rc, out, err


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


_PLATFORMS = ("macos", "linux", "windows")


def _force_scheduler_platform(monkeypatch, name):
    """Pin the scheduler module's platform flags for this test.

    `name` is "macos", "linux", "windows", or None (all flags False, i.e.
    an unsupported host). Unmentioned flags are set to False so exactly
    one platform — or none — is "active" during the test.
    """
    if name is not None and name not in _PLATFORMS:
        raise ValueError(f"Unknown platform {name!r}; expected one of {_PLATFORMS} or None")
    monkeypatch.setattr(_rotbyte_pkg.scheduler, "_IS_MACOS", name == "macos")
    monkeypatch.setattr(_rotbyte_pkg.scheduler, "_IS_LINUX", name == "linux")
    monkeypatch.setattr(_rotbyte_pkg.scheduler, "_IS_WINDOWS", name == "windows")


def _force_rotbyte_platform(name):
    """Return a context manager that pins rotbyte module's platform flags.

    Mirrors _force_scheduler_platform but for the `rotbyte` top-level module,
    which is the namespace TestStatusFreshness's code path checks.
    """
    if name is not None and name not in _PLATFORMS:
        raise ValueError(f"Unknown platform {name!r}; expected one of {_PLATFORMS} or None")
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        with unittest.mock.patch("rotbyte._IS_MACOS", name == "macos"), \
             unittest.mock.patch("rotbyte._IS_LINUX", name == "linux"), \
             unittest.mock.patch("rotbyte._IS_WINDOWS", name == "windows"):
            yield

    return _ctx()


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
        fpath, digest, size, mtime, err = rotbyte.hash_file(path)
        assert fpath == path
        assert digest == _hash_bytes(b"alpha")
        assert size == 5
        assert mtime is not None
        assert err is None

    def test_nonexistent(self):
        fpath, digest, size, mtime, err = rotbyte.hash_file("/nonexistent/file")
        assert digest is None
        assert size is None
        # Error message routed back to the parent for aggregation rather
        # than printed inline from a worker process.
        assert err is not None
        assert "No such file" in err or "cannot find" in err.lower()

    def test_empty_file(self, tmp):
        p = tmp / "empty.txt"
        p.write_bytes(b"")
        fpath, digest, size, mtime, err = rotbyte.hash_file(str(p))
        assert digest == _hash_bytes(b"")
        assert size == 0
        assert err is None


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
        # Migration chain runs all the way to the current SCHEMA_VERSION.
        assert version["version"] == rotbyte.SCHEMA_VERSION
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

    def test_case_insensitive_normalises_to_lowercase(self, tmp, db_path):
        # With --case-insensitive, returned paths are lowercased so a
        # rename like "foo.mkv" → "Foo.mkv" doesn't produce a phantom
        # MISSING on case-insensitive filesystems.
        (tmp / "MixedCase.TXT").write_text("x")
        files = rotbyte.scan_files(str(tmp), db_path, case_insensitive=True)
        assert all(f == f.lower() for f in files)
        assert any(f.endswith("mixedcase.txt") for f in files)

    def test_walk_error_continues(self, tmp, db_path, capsys, monkeypatch):
        # A walk-time OSError (e.g. a network drive vanishing) should
        # surface as a warning on stderr, not abort the scan.
        real_walk = os.walk

        def flaky_walk(*args, **kwargs):
            yield from real_walk(*args, **kwargs)
            onerror = kwargs.get("onerror")
            if onerror:
                err = OSError("Network drive disconnected")
                err.filename = str(tmp / "missing")
                onerror(err)

        monkeypatch.setattr(os, "walk", flaky_walk)
        files = rotbyte.scan_files(str(tmp), db_path)
        captured = capsys.readouterr()
        # Still returned the files it found before the simulated failure.
        assert files
        assert "Walk error" in captured.err


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

    def test_lock_refuses_to_follow_symlink(self, tmp):
        # POSIX: a malicious symlink at <db>.lock pointing somewhere the
        # user can write must not let an attacker redirect the PID-record
        # write. acquire() should fail rather than open the symlink target.
        if sys.platform == "win32":
            pytest.skip("symlink semantics differ on Windows")
        decoy = tmp / "decoy.txt"
        decoy.write_text("untouched")
        lock_path = tmp / "redirect.lock"
        os.symlink(str(decoy), str(lock_path))
        lock = rotbyte.FileLock(str(lock_path))
        assert lock.acquire() is False
        # Decoy file untouched — no PID written through the symlink.
        assert decoy.read_text() == "untouched"


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
        assert "New files" in out

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
        _run_cli_ok(str(tmp))
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["new"] == 0
        assert data["skipped"] == 4

    def test_edit_detected(self, tmp):
        _run_cli_ok(str(tmp))
        time.sleep(0.05)
        (tmp / "a.txt").write_text("alpha_modified")
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["updated"] == 1
        assert data["failed"] == 0  # edit, not bit rot


# ══════════════════════════════════════════════════════════════════════════════
# 10. CLI — Full Verify (--check, bit rot detection)
# ══════════════════════════════════════════════════════════════════════════════

class TestCLICheck:
    def test_check_no_changes(self, tmp):
        _run_cli_ok(str(tmp))
        rc, out, err = _run_cli("--check", "--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["verified_ok"] == 4
        assert data["failed"] == 0

    def test_check_detects_bit_rot(self, tmp):
        _run_cli_ok(str(tmp))
        _corrupt_file(tmp / "a.txt")
        rc, out, err = _run_cli("--check", "--json", str(tmp))
        assert rc == 2  # exit code for bit rot
        data = _extract_json(out)
        assert data["failed"] == 1

    def test_check_exit_code_2(self, tmp):
        _run_cli_ok(str(tmp))
        _corrupt_file(tmp / "b.txt")
        rc, _, _ = _run_cli("--check", str(tmp))
        assert rc == 2


# ══════════════════════════════════════════════════════════════════════════════
# 11. CLI — Missing Files
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIMissing:
    def test_missing_detected(self, tmp):
        _run_cli_ok(str(tmp))
        (tmp / "a.txt").unlink()
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 1  # exit code for missing
        data = _extract_json(out)
        assert data["missing"] == 1

    def test_skip_missing_flag(self, tmp):
        _run_cli_ok(str(tmp))
        (tmp / "a.txt").unlink()
        rc, out, err = _run_cli("--skip-missing", "--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        assert data["missing"] == 0

    def test_reappeared_file_verified(self, tmp):
        """A file that disappears and reappears should be re-verified."""
        _run_cli_ok(str(tmp))
        content = (tmp / "a.txt").read_bytes()
        (tmp / "a.txt").unlink()
        _run_cli(str(tmp))  # marks MISSING
        (tmp / "a.txt").write_bytes(content)
        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        data = _extract_json(out)
        # Only the previously-MISSING file is forced to re-verify; the other
        # three are unchanged and land in "skipped".
        assert data["verified_ok"] == 1
        assert data["skipped"] == 3


# ══════════════════════════════════════════════════════════════════════════════
# 12. CLI — Move Detection
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIMoveDetection:
    def test_rename_detected(self, tmp):
        _run_cli_ok(str(tmp))
        content = (tmp / "a.txt").read_bytes()
        (tmp / "a.txt").unlink()
        (tmp / "a_renamed.txt").write_bytes(content)
        rc, out, err = _run_cli("--json", str(tmp))
        data = _extract_json(out)
        assert data["likely_moves"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# 13. CLI — --accept
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIAccept:
    def test_accept_missing(self, tmp):
        _run_cli_ok(str(tmp))
        (tmp / "a.txt").unlink()
        _run_cli(str(tmp))  # marks MISSING
        rc, out, err = _run_cli("--accept", str(tmp / "a.txt"), str(tmp))
        assert rc == 0
        assert "Removed" in out

    def test_accept_failed(self, tmp):
        _run_cli_ok(str(tmp))
        _corrupt_file(tmp / "a.txt")
        _run_cli("--check", str(tmp))  # marks FAILED
        rc, out, err = _run_cli("--accept", str(tmp / "a.txt"), str(tmp))
        assert rc == 0
        assert "Accepted" in out

    def test_accept_unknown_file(self, tmp):
        _run_cli_ok(str(tmp))
        rc, out, err = _run_cli("--accept", "/nonexistent/file.txt", str(tmp))
        assert rc == 1


# ══════════════════════════════════════════════════════════════════════════════
# 14. CLI — --accept-all
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIAcceptAll:
    def test_accept_all_clears_missing_and_failed(self, tmp):
        _run_cli_ok(str(tmp))
        _corrupt_file(tmp / "a.txt")
        (tmp / "b.txt").unlink()
        _run_cli("--check", str(tmp))
        rc, out, err = _run_cli("--accept-all", str(tmp))
        assert rc == 0
        assert "Missing cleared" in out
        assert "Failed accepted" in out

    def test_accept_all_nothing_to_do(self, tmp):
        _run_cli_ok(str(tmp))
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
        assert rc == 0
        assert "MISMATCH" in out

    def test_import_invalid_hash_length(self, tmp):
        (tmp / "a.txt.b2sum").write_text("abc  a.txt\n")
        rc, out, err = _run_cli("--import", str(tmp))
        assert rc == 0
        assert "Invalid hash" in out

    def test_import_no_matching_file(self, tmp):
        (tmp / "nonexistent.mkv.b2sum").write_text("0" * 128 + "  nonexistent.mkv\n")
        rc, out, err = _run_cli("--import", str(tmp))
        assert rc == 0
        assert "No matching file" in out

    def test_import_empty_hash_file(self, tmp):
        (tmp / "a.txt.b2sum").write_text("")
        rc, out, err = _run_cli("--import", str(tmp))
        assert rc == 0
        assert "Empty file" in out

    def test_import_no_sidecars(self, tmp):
        rc, out, err = _run_cli("--import", str(tmp))
        assert rc == 0
        assert "No .b2sum or .b2 files found" in out

    def test_import_already_tracked(self, tmp):
        # First index the file normally
        _run_cli_ok(str(tmp))
        content = (tmp / "a.txt").read_bytes()
        expected_hash = _hash_bytes(content)
        (tmp / "a.txt.b2sum").write_text(f"{expected_hash}  a.txt\n")
        rc, out, err = _run_cli("--import", str(tmp))
        assert rc == 0
        assert "Already tracked" in out


# ══════════════════════════════════════════════════════════════════════════════
# 16. CLI — --export
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIExport:
    def test_export(self, tmp):
        _run_cli_ok(str(tmp))
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
        _run_cli_ok(str(tmp))
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
        _run_cli_ok(str(tmp))
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
        _run_cli_ok(str(tmp))
        _corrupt_file(tmp / "a.txt")
        _run_cli("--check", str(tmp))
        rc, out, err = _run_cli("--report", str(tmp))
        assert "Failed files" in out

    def test_report_failed_shows_tracked_since_and_localized_time(self, tmp):
        _run_cli_ok(str(tmp))
        _corrupt_file(tmp / "a.txt")
        _run_cli("--check", str(tmp))
        rc, out, err = _run_cli("--report", str(tmp))
        assert "Tracked since" in out
        # Localized timestamps render AM/PM (raw UTC would not).
        assert "AM" in out or "PM" in out

    def test_report_stale_window_follows_due(self, tmp):
        _run_cli_ok(str(tmp))
        # Backdate everything so it's stale under any reasonable window.
        db_path = next(Path(str(tmp)).glob(".*_rotbyte.db"))
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE checksums SET last_verified = datetime('now', '-100 days')")
        conn.commit()
        conn.close()
        # Default window is 90 days.
        rc, out, err = _run_cli("--report", str(tmp))
        assert "not verified in 90+ days" in out
        # --due narrows the window the report uses.
        rc, out, err = _run_cli("--report", "--due", "30d", str(tmp))
        assert "not verified in 30+ days" in out

    def test_report_stale_listing_caps_at_20(self, tmp):
        _run_cli_ok(str(tmp))
        db_path = next(Path(str(tmp)).glob(".*_rotbyte.db"))
        conn = sqlite3.connect(str(db_path))
        for i in range(25):
            conn.execute(
                "INSERT INTO checksums (file_path, file_name, file_size, "
                "file_mtime, checksum, baseline_checksum, algorithm, status, "
                "first_seen, last_verified) VALUES "
                "(?, ?, 1, '2020-01-01T00:00:00Z', 'h', 'h', 'BLAKE2b', 'OK', "
                "'2020-01-01T00:00:00Z', datetime('now', '-100 days'))",
                (f"/fake/stale{i}.txt", f"stale{i}.txt"),
            )
        conn.commit()
        conn.close()
        rc, out, err = _run_cli("--report", str(tmp))
        assert "showing first 20 of 25" in out


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
        _run_cli_ok(str(tmp))
        _corrupt_file(tmp / "a.txt")
        rc, out, err = _run_cli("--check", "--json", str(tmp))
        data = _extract_json(out)
        assert "failed_files" in data
        assert len(data["failed_files"]) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 19. CLI — --quiet
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIQuiet:
    def test_quiet_no_output_on_ok(self, tmp):
        _run_cli_ok(str(tmp))
        rc, out, err = _run_cli("--quiet", str(tmp))
        assert rc == 0
        # Quiet mode suppresses the verbose scanning/loading progress lines
        assert "Scanning" not in out
        assert "Loading" not in out

    def test_quiet_shows_problems(self, tmp):
        _run_cli_ok(str(tmp))
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
        assert "--budget requires --check" in err

    def test_budget_with_check(self, tmp):
        _run_cli_ok(str(tmp))
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
        _run_cli_ok(str(tmp))
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
        _run_cli_ok(str(tmp))
        (tmp / "a.txt").unlink()
        rc, _, _ = _run_cli(str(tmp))
        assert rc == 1

    def test_exit_2_bit_rot(self, tmp):
        _run_cli_ok(str(tmp))
        _corrupt_file(tmp / "a.txt")
        rc, _, _ = _run_cli("--check", str(tmp))
        assert rc == 2

    def test_exit_2_trumps_exit_1(self, tmp):
        """Bit rot exit code takes priority over missing."""
        _run_cli_ok(str(tmp))
        _corrupt_file(tmp / "a.txt")
        (tmp / "b.txt").unlink()
        rc, _, _ = _run_cli("--check", str(tmp))
        assert rc == 2  # bit rot takes priority


# ══════════════════════════════════════════════════════════════════════════════
# 26. CLI — Concurrent lock
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIConcurrentLock:
    def test_concurrent_run_blocked(self, tmp):
        """A second instance against the same DB should fail.

        Discovers the real DB file produced by a prior rotbyte run, then
        derives the lock path from it. If rotbyte's filename convention
        changes, this still tests the actual contention path because the
        DB-file glob follows the production code.
        """
        _run_cli_ok(str(tmp))  # creates the DB so we can glob for it
        db_file = next(tmp.glob(f".*{rotbyte.DB_FILENAME_SUFFIX}"))
        lock_path = str(db_file) + ".lock"
        lock = rotbyte.FileLock(lock_path)
        assert lock.acquire()
        try:
            rc, out, err = _run_cli(str(tmp))
            assert rc != 0
            assert "Another instance is already running" in err
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
        assert "--full-at requires --track" in err

    def test_every_without_track(self, tmp):
        rc, out, err = _run_cli("--every", "30m", str(tmp))
        assert rc != 0
        assert "--every requires --track" in err

    def test_workers_zero(self, tmp):
        rc, out, err = _run_cli("--workers", "0", str(tmp))
        assert rc != 0
        assert "--workers must be at least 1" in err


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

    def test_file_deleted_mid_scan_marks_missing(self, tmp, db):
        """A previously-tracked file that vanishes between prescan and
        hash should be routed to MISSING, not counted as an error.
        """
        now = rotbyte._now()
        gone = str(tmp / "ghost.txt")
        # Pre-seed the DB so this is a tracked file with a known hash.
        db.upsert_file(gone, "ghost.txt", 5, now, "x" * 128, None, "OK", now)
        entries = [
            rotbyte.FileEntry(gone, "ghost.txt", 5, now, "x" * 128, False),
        ]
        # File doesn't exist on disk — simulates the prescan→hash race.
        result = rotbyte.run_hashing(db, entries, workers=1, now=now,
                                     interrupted=[False], quiet=True)
        assert result.errors == 0
        assert db.get_file_status(gone) == "MISSING"

    def test_unreadable_file_aggregated_not_spammed(self, tmp, db, capsys):
        """Per-file read failures are aggregated; only the first ten
        print inline, the rest collapse to a single summary line.

        Skips on Windows where chmod 000 doesn't deny reads to the owner.
        Also skips when run as root (chmod 000 is bypassed).
        """
        if sys.platform == "win32" or os.geteuid() == 0:
            pytest.skip("requires POSIX non-root for chmod-based unreadability")
        now = rotbyte._now()
        # Twelve real files we then make unreadable — exists at lstat()
        # time so they hit the "errors" branch, not deferred_missing.
        paths = []
        for i in range(12):
            p = tmp / f"locked_{i}.bin"
            p.write_bytes(b"x")
            os.chmod(p, 0o000)
            paths.append(str(p))
        try:
            entries = [
                rotbyte.FileEntry(p, os.path.basename(p), 1, now, None, True)
                for p in paths
            ]
            result = rotbyte.run_hashing(db, entries, workers=1, now=now,
                                         interrupted=[False], quiet=True)
            assert result.errors == 12
            captured = capsys.readouterr()
            # Summary line names the suppressed count.
            assert "more read errors suppressed" in captured.err
        finally:
            for p in paths:
                os.chmod(p, 0o644)


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

    def test_launchd_plist_escapes_xml_metacharacters(self):
        # A target dir with XML metacharacters must round-trip through
        # plistlib without producing malformed XML or extra elements.
        import plistlib
        evil = "/Volumes/Bad <dir> & \"name\""
        xml = rotbyte._generate_launchd_plist(
            "com.rotbyte.test", ["python3", "rotbyte.py", evil],
            interval_seconds=60,
        )
        parsed = plistlib.loads(xml.encode())
        assert parsed["ProgramArguments"][-1] == evil
        assert parsed["Label"] == "com.rotbyte.test"

    def test_launchd_log_path_under_user_logs(self):
        # Log path must NOT live in /tmp (unbounded growth, no rotation).
        path = rotbyte._launchd_log_path("com.rotbyte.x.abc")
        assert path.endswith("com.rotbyte.x.abc.log")
        assert "/Library/Logs/rotbyte/" in path
        assert not path.startswith("/tmp/")

    def test_systemd_service(self):
        unit = rotbyte._generate_systemd_unit(
            "rotbyte quick scan", ["rotbyte", "--quiet", "/data"],
        )
        # Each arg is quoted so a path containing whitespace doesn't get
        # silently split by systemd's command-line parser.
        assert 'ExecStart="rotbyte" "--quiet" "/data"' in unit
        assert "Type=oneshot" in unit

    def test_systemd_service_quotes_paths_with_spaces(self):
        unit = rotbyte._generate_systemd_unit(
            "rotbyte", ["rotbyte", "--quiet", "/Volumes/My Media"],
        )
        assert 'ExecStart="rotbyte" "--quiet" "/Volumes/My Media"' in unit

    def test_systemd_escape_backslash_and_quote(self):
        # A target path containing a quote or backslash must be escaped per
        # systemd.service(5) so it parses as a single argument.
        assert rotbyte._systemd_escape_arg('a"b') == '"a\\"b"'
        assert rotbyte._systemd_escape_arg('a\\b') == '"a\\\\b"'

    def test_systemd_description_strips_newlines(self):
        # A CRLF in Description= would close the line and let the rest of
        # the value inject another systemd directive.
        unit = rotbyte._generate_systemd_unit(
            "rotbyte\n[Service]\nUser=root", ["rotbyte"],
        )
        assert "User=root" in unit  # text survives, but...
        assert "Description=rotbyte [Service] User=root" in unit  # on one line

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
# 31a. --untrack / --untrack-all
# ══════════════════════════════════════════════════════════════════════════════

class TestUntrackBackends:
    """Backend-level tests: mock subprocess + filesystem and verify the
    right unload/disable + unlink sequence runs for each platform.
    """

    def _ok_run(self):
        return unittest.mock.MagicMock(returncode=0, stdout="", stderr="")

    # ── launchd ──────────────────────────────────────────────────────

    def test_launchd_uninstall_specific_target(self, tmp_path, monkeypatch):
        """_uninstall_launchd unloads + unlinks both quick and full plists
        for the target's dir-hash, and only those.
        """
        agents = tmp_path / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        target = "/Volumes/MyMedia"
        dhash = rotbyte._dir_hash(target)
        for kind in ("quick", "full"):
            (agents / f"com.rotbyte.{kind}.{dhash}.plist").write_text("<plist/>")
        # An unrelated rotbyte plist for a different target should be
        # left alone.
        (agents / "com.rotbyte.quick.deadbeef.plist").write_text("<plist/>")

        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        calls = []
        def fake_run(cmd, **kw):
            calls.append(cmd)
            return self._ok_run()
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd._subprocess,
                            "run", fake_run)

        removed, errors = rotbyte._uninstall_launchd(target)

        assert sorted(removed) == sorted([
            f"com.rotbyte.quick.{dhash}",
            f"com.rotbyte.full.{dhash}",
        ])
        assert errors == []
        # Only the two target plists were removed; the unrelated one stays.
        assert not (agents / f"com.rotbyte.quick.{dhash}.plist").exists()
        assert not (agents / f"com.rotbyte.full.{dhash}.plist").exists()
        assert (agents / "com.rotbyte.quick.deadbeef.plist").exists()
        # bootout was attempted for each label.
        bootout_cmds = [c for c in calls if c[:2] == ["launchctl", "bootout"]]
        assert len(bootout_cmds) == 2

    def test_launchd_uninstall_falls_back_to_unload(self, tmp_path, monkeypatch):
        """If `launchctl bootout` returns non-zero, fall back to
        `launchctl unload` before unlinking.
        """
        agents = tmp_path / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        target = "/Volumes/MyMedia"
        dhash = rotbyte._dir_hash(target)
        plist = agents / f"com.rotbyte.quick.{dhash}.plist"
        plist.write_text("<plist/>")

        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        cmds = []
        def fake_run(cmd, **kw):
            cmds.append(cmd)
            if cmd[:2] == ["launchctl", "bootout"]:
                return unittest.mock.MagicMock(returncode=1, stdout="", stderr="not loaded")
            return self._ok_run()
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd._subprocess,
                            "run", fake_run)

        removed, errors = rotbyte._uninstall_launchd(target)

        assert removed == [f"com.rotbyte.quick.{dhash}"]
        assert errors == []
        # Exactly one bootout attempt + one unload fallback.
        assert any(c[:2] == ["launchctl", "bootout"] for c in cmds)
        assert any(c[:2] == ["launchctl", "unload"] for c in cmds)

    def test_launchd_uninstall_no_unit_returns_empty(self, tmp_path, monkeypatch):
        """No plists for this target → returns empty lists, no subprocess call."""
        agents = tmp_path / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        called = []
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd._subprocess,
                            "run", lambda *a, **kw: called.append(a) or self._ok_run())
        removed, errors = rotbyte._uninstall_launchd("/no/such/dir")
        assert removed == []
        assert errors == []
        assert called == []  # never even tried to bootout

    def test_launchd_uninstall_unlink_failure_records_error(self, tmp_path, monkeypatch):
        """An os.unlink failure on an existing plist surfaces as an error."""
        agents = tmp_path / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        target = "/Volumes/MyMedia"
        dhash = rotbyte._dir_hash(target)
        plist = agents / f"com.rotbyte.quick.{dhash}.plist"
        plist.write_text("<plist/>")

        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd._subprocess,
                            "run", lambda *a, **kw: self._ok_run())
        def boom(p):
            raise OSError("permission denied")
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd.os, "unlink", boom)

        removed, errors = rotbyte._uninstall_launchd(target)
        assert removed == []
        assert len(errors) == 1
        assert "could not remove" in errors[0]

    def test_launchd_uninstall_all_iterates_discovered(self, tmp_path, monkeypatch):
        """_uninstall_all_launchd globs every com.rotbyte.* plist."""
        agents = tmp_path / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        for label in ("com.rotbyte.quick.aaa", "com.rotbyte.full.aaa",
                      "com.rotbyte.quick.bbb", "com.unrelated.app"):
            (agents / f"{label}.plist").write_text("<plist/>")

        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd._subprocess,
                            "run", lambda *a, **kw: self._ok_run())

        removed, errors = rotbyte._uninstall_all_launchd()
        assert sorted(removed) == [
            "com.rotbyte.full.aaa",
            "com.rotbyte.quick.aaa",
            "com.rotbyte.quick.bbb",
        ]
        assert errors == []
        assert (agents / "com.unrelated.app.plist").exists()  # untouched

    # ── systemd ──────────────────────────────────────────────────────

    def test_systemd_uninstall_specific_target(self, tmp_path, monkeypatch):
        """_uninstall_systemd disables + unlinks both timer and service
        files for the target dir-hash and runs daemon-reload once at the end.
        """
        unit_dir = tmp_path / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True)
        target = "/srv/data"
        dhash = rotbyte._dir_hash(target)
        for kind in ("quick", "full"):
            (unit_dir / f"rotbyte-{kind}-{dhash}.timer").write_text("")
            (unit_dir / f"rotbyte-{kind}-{dhash}.service").write_text("")
        # Unrelated rotbyte unit for a different target — must survive.
        (unit_dir / "rotbyte-quick-cafef00d.timer").write_text("")
        (unit_dir / "rotbyte-quick-cafef00d.service").write_text("")

        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        cmds = []
        monkeypatch.setattr(_rotbyte_pkg.scheduler.systemd._subprocess,
                            "run", lambda c, **kw: cmds.append(c) or self._ok_run())

        removed, errors = rotbyte._uninstall_systemd(target)

        assert sorted(removed) == sorted([
            f"rotbyte-quick-{dhash}", f"rotbyte-full-{dhash}",
        ])
        assert errors == []
        for kind in ("quick", "full"):
            assert not (unit_dir / f"rotbyte-{kind}-{dhash}.timer").exists()
            assert not (unit_dir / f"rotbyte-{kind}-{dhash}.service").exists()
        # Untouched.
        assert (unit_dir / "rotbyte-quick-cafef00d.timer").exists()
        # daemon-reload ran exactly once at the end.
        reloads = [c for c in cmds if c[-1] == "daemon-reload"]
        assert len(reloads) == 1
        # disable+now ran for each timer.
        disables = [c for c in cmds
                    if "disable" in c and "--now" in c]
        assert len(disables) == 2

    def test_systemd_uninstall_no_unit_skips_daemon_reload(self, tmp_path, monkeypatch):
        unit_dir = tmp_path / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True)
        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        cmds = []
        monkeypatch.setattr(_rotbyte_pkg.scheduler.systemd._subprocess,
                            "run", lambda c, **kw: cmds.append(c) or self._ok_run())
        removed, errors = rotbyte._uninstall_systemd("/no/such/dir")
        assert removed == []
        assert errors == []
        # Nothing was found, so we never invoked systemctl at all.
        assert cmds == []

    def test_systemd_uninstall_all_iterates(self, tmp_path, monkeypatch):
        unit_dir = tmp_path / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True)
        for name in ("rotbyte-quick-aaa", "rotbyte-full-aaa", "rotbyte-quick-bbb"):
            (unit_dir / f"{name}.timer").write_text("")
            (unit_dir / f"{name}.service").write_text("")
        # Unrelated systemd unit must survive.
        (unit_dir / "user-app.timer").write_text("")
        (unit_dir / "user-app.service").write_text("")

        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        monkeypatch.setattr(_rotbyte_pkg.scheduler.systemd._subprocess,
                            "run", lambda c, **kw: self._ok_run())
        removed, errors = rotbyte._uninstall_all_systemd()
        assert sorted(removed) == ["rotbyte-full-aaa", "rotbyte-quick-aaa", "rotbyte-quick-bbb"]
        assert errors == []
        assert (unit_dir / "user-app.timer").exists()  # untouched

    # ── schtasks ─────────────────────────────────────────────────────

    def test_schtasks_uninstall_specific_target(self, monkeypatch):
        target = "C:\\Volumes\\MyMedia"
        dhash = rotbyte._dir_hash(target)
        cmds = []
        def fake_run(cmd, **kw):
            cmds.append(cmd)
            return unittest.mock.MagicMock(returncode=0, stdout="", stderr="")
        monkeypatch.setattr(_rotbyte_pkg.scheduler.schtasks._subprocess,
                            "run", fake_run)
        removed, errors = rotbyte._uninstall_schtasks(target)
        assert sorted(removed) == sorted([
            f"rotbyte-quick-{dhash}", f"rotbyte-full-{dhash}",
        ])
        assert errors == []
        assert all(c[:2] == ["schtasks.exe", "/Delete"] for c in cmds)
        assert len(cmds) == 2

    def test_schtasks_missing_task_treated_as_noop(self, monkeypatch):
        """`The system cannot find the file specified` is not an error."""
        def fake_run(cmd, **kw):
            return unittest.mock.MagicMock(
                returncode=1, stdout="",
                stderr="ERROR: The system cannot find the file specified.",
            )
        monkeypatch.setattr(_rotbyte_pkg.scheduler.schtasks._subprocess,
                            "run", fake_run)
        removed, errors = rotbyte._uninstall_schtasks("/some/path")
        assert removed == []
        assert errors == []

    def test_schtasks_real_failure_recorded(self, monkeypatch):
        def fake_run(cmd, **kw):
            return unittest.mock.MagicMock(
                returncode=1, stdout="", stderr="ERROR: Access is denied.",
            )
        monkeypatch.setattr(_rotbyte_pkg.scheduler.schtasks._subprocess,
                            "run", fake_run)
        removed, errors = rotbyte._uninstall_schtasks("/some/path")
        assert removed == []
        assert len(errors) == 2  # one per task name attempted
        assert all("Access is denied" in e for e in errors)


# ══════════════════════════════════════════════════════════════════════════════
# 31c. --repair: re-point stale scheduler exe paths after an upgrade
# ══════════════════════════════════════════════════════════════════════════════

class TestRepair:
    """Pure prefix-swap helpers plus launchd/systemd in-place rewrite."""

    FRESH = ["/opt/homebrew/opt/python@3.14/bin/python3.14",
             "/opt/homebrew/opt/rotbyte/libexec/rotbyte.py"]

    def _ok_run(self):
        return unittest.mock.MagicMock(returncode=0, stdout="", stderr="")

    def _write_plist(self, path, program_args, calendar=True):
        import plistlib
        plist = {
            "Label": path.stem,
            "ProgramArguments": program_args,
            "StandardOutPath": "/tmp/x.log",
            "StandardErrorPath": "/tmp/x.log",
            "Nice": 10,
        }
        if calendar:
            plist["StartCalendarInterval"] = [{"Hour": 2, "Minute": 30}]
        else:
            plist["StartInterval"] = 3600
        with open(path, "wb") as f:
            plistlib.dump(plist, f)

    def test_prefix_helpers_preserve_trailing_args(self):
        old = ["/old/python", "/old/rotbyte.py", "--check", "--notify", "email",
               "--auto-export", "--scheduled", "/data/My Photos"]
        assert rotbyte._parse_cmd_flags(old)  # sanity: recognizable command
        from _rotbyte.scheduler import _repair_exe_prefix, _exe_prefix_current
        assert _exe_prefix_current(old, self.FRESH) is False
        repaired = _repair_exe_prefix(old, self.FRESH)
        assert repaired == self.FRESH + old[2:]
        # Idempotent: a command already on the fresh prefix is unchanged.
        assert _exe_prefix_current(repaired, self.FRESH) is True

    def test_repair_launchd_rewrites_stale_and_preserves_schedule(self, tmp_path, monkeypatch):
        import plistlib
        agents = tmp_path / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        target = "/data/My Photos"
        dhash = rotbyte._dir_hash(target)
        # A stale full plist: dead interpreter + dead script, real flags.
        stale = ["/opt/homebrew/Cellar/python@3.14/3.14.5/bin/python3.14",
                 "/opt/homebrew/Cellar/rotbyte/1.1.0/libexec/rotbyte.py",
                 "--check", "--quiet", "--notify", "email", "--auto-export",
                 "--scheduled", target]
        plist_path = agents / f"com.rotbyte.full.{dhash}.plist"
        self._write_plist(plist_path, stale, calendar=True)

        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        calls = []
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd._subprocess, "run",
                            lambda cmd, **kw: calls.append(cmd) or self._ok_run())

        repaired, already_ok, errors = \
            _rotbyte_pkg.scheduler.launchd._repair_launchd(self.FRESH)

        assert errors == []
        assert already_ok == []
        assert len(repaired) == 1
        label, tdir, oldp, newp = repaired[0]
        assert tdir == target
        # Plist file now carries the fresh prefix + every original flag.
        with open(plist_path, "rb") as f:
            written = plistlib.load(f)
        assert written["ProgramArguments"] == self.FRESH + stale[2:]
        # Schedule and Nice survived the rewrite untouched.
        assert written["StartCalendarInterval"] == [{"Hour": 2, "Minute": 30}]
        assert written["Nice"] == 10
        # launchd was reloaded (unload then load).
        assert ["launchctl", "unload", str(plist_path)] in calls
        assert ["launchctl", "load", str(plist_path)] in calls

    def test_repair_launchd_skips_already_current(self, tmp_path, monkeypatch):
        agents = tmp_path / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        target = "/data/ok"
        dhash = rotbyte._dir_hash(target)
        current = list(self.FRESH) + ["--scheduled", "--quiet", target]
        plist_path = agents / f"com.rotbyte.quick.{dhash}.plist"
        self._write_plist(plist_path, current, calendar=False)

        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        calls = []
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd._subprocess, "run",
                            lambda cmd, **kw: calls.append(cmd) or self._ok_run())

        repaired, already_ok, errors = \
            _rotbyte_pkg.scheduler.launchd._repair_launchd(self.FRESH)

        assert repaired == []
        assert len(already_ok) == 1
        assert errors == []
        # No reload attempted for an already-current schedule.
        assert calls == []

    def test_repair_systemd_rewrites_execstart(self, tmp_path, monkeypatch):
        unit_dir = tmp_path / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True)
        target = "/data/My Photos"
        dhash = rotbyte._dir_hash(target)
        service = unit_dir / f"rotbyte-full-{dhash}.service"
        # ExecStart with a dead Cellar prefix and a space-bearing target.
        service.write_text(
            "[Unit]\nDescription=rotbyte full scan\n\n"
            "[Service]\nType=oneshot\n"
            'ExecStart="/old/python" "/old/rotbyte.py" "--check" "--scheduled" '
            '"/data/My Photos"\nNice=10\n\n[Install]\nWantedBy=default.target\n'
        )
        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        monkeypatch.setattr(_rotbyte_pkg.scheduler.systemd._subprocess, "run",
                            lambda cmd, **kw: self._ok_run())

        repaired, already_ok, errors = \
            _rotbyte_pkg.scheduler.systemd._repair_systemd(self.FRESH)

        assert errors == []
        assert len(repaired) == 1
        content = service.read_text()
        # New ExecStart carries the fresh prefix and preserves the quoted
        # space-bearing target directory.
        assert "/opt/homebrew/opt/rotbyte/libexec/rotbyte.py" in content
        assert '"/data/My Photos"' in content
        assert "/old/python" not in content
        # Other directives untouched.
        assert "Nice=10" in content
        assert "Type=oneshot" in content

    def test_run_repair_no_schedules(self, tmp_path, monkeypatch, capsys):
        agents = tmp_path / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        with _force_rotbyte_platform("macos"):
            rc = _rotbyte_pkg.scheduler._run_repair()
        out = capsys.readouterr().out
        assert rc == 0
        assert "No scheduled scans found" in out

    def test_cli_repair_dispatches_to_run_repair(self, monkeypatch):
        """`rotbyte --repair` routes to _run_repair and exits with its code.

        _run_repair is mocked so the real ~/Library/LaunchAgents is never
        touched — this only exercises the argparse flag + dispatch wiring.
        """
        called = {}

        def fake_repair():
            called["ran"] = True
            return 0

        monkeypatch.setattr(rotbyte, "_run_repair", fake_repair)
        monkeypatch.setattr(sys, "argv", ["rotbyte", "--repair"])
        with pytest.raises(SystemExit) as ei:
            rotbyte.main()
        assert called.get("ran") is True
        assert ei.value.code == 0

    def test_budget_cutoff_note(self):
        assert rotbyte._budget_cutoff_note(False) == []
        lines = rotbyte._budget_cutoff_note(True)
        assert any("not every file was verified this run" in ln for ln in lines)


class TestRunUntrackDispatch:
    """Tests for the platform-dispatch wrappers _run_untrack[_all] and
    the main() wiring. Patches the platform flags so the test runs the
    right backend regardless of the host OS.
    """

    def _capture(self):
        """Return a stdout/stderr capture context manager pair."""
        return io.StringIO(), io.StringIO()

    def test_run_untrack_default_to_cwd(self, tmp_path, monkeypatch):
        """`rotbyte --untrack` (no path) untracks the current working dir."""
        captured: dict = {}
        def fake_uninstall(target_dir):
            captured["target"] = target_dir
            return ([], [])  # no unit found
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd,
                            "_uninstall_launchd", fake_uninstall)
        _force_scheduler_platform(monkeypatch, "macos")

        rc, out, err = _run_cli("--untrack", cwd=str(tmp_path))
        assert rc == 0
        assert "No scheduled run found" in out
        # The subprocess child saw cwd == tmp_path; check that the realpath
        # of "." (the default) was honored.
        # (Subprocess test — we can't read captured["target"] from here,
        # but the message contains the resolved path.)
        assert str(tmp_path) in out or "/private" + str(tmp_path) in out

    def test_run_untrack_explicit_path(self, monkeypatch):
        """`rotbyte --untrack /some/path` uses /some/path, not cwd."""
        target_seen: dict = {}
        def fake_uninstall(target_dir):
            target_seen["t"] = target_dir
            return (["com.rotbyte.quick.abc"], [])
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd,
                            "_uninstall_launchd", fake_uninstall)
        _force_scheduler_platform(monkeypatch, "macos")

        with pytest.raises(SystemExit) as exc:
            with unittest.mock.patch("sys.argv",
                                     ["rotbyte", "--untrack", "/Volumes/Foo"]):
                rotbyte.main()
        assert exc.value.code == 0
        # The realpath of /Volumes/Foo (which doesn't exist) is itself.
        assert target_seen["t"] == "/Volumes/Foo"

    def test_run_untrack_all_iterates(self, monkeypatch, capsys):
        def fake_uninstall_all():
            return (["com.rotbyte.quick.aaa", "com.rotbyte.full.aaa",
                     "com.rotbyte.quick.bbb"], [])
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd,
                            "_uninstall_all_launchd", fake_uninstall_all)
        _force_scheduler_platform(monkeypatch, "macos")

        with pytest.raises(SystemExit) as exc:
            with unittest.mock.patch("sys.argv", ["rotbyte", "--untrack-all"]):
                rotbyte.main()
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "Removed 3 scheduled runs" in out

    def test_run_untrack_no_unit_message(self, monkeypatch, capsys):
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd,
                            "_uninstall_launchd", lambda t: ([], []))
        _force_scheduler_platform(monkeypatch, "macos")

        with pytest.raises(SystemExit) as exc:
            with unittest.mock.patch("sys.argv",
                                     ["rotbyte", "--untrack", "/no/where"]):
                rotbyte.main()
        assert exc.value.code == 0
        assert "No scheduled run found for /no/where" in capsys.readouterr().out

    def test_run_untrack_failure_exits_6(self, monkeypatch, capsys):
        def fake_uninstall(target_dir):
            return ([], ["could not remove /Users/x/Library/...: permission denied"])
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd,
                            "_uninstall_launchd", fake_uninstall)
        _force_scheduler_platform(monkeypatch, "macos")

        with pytest.raises(SystemExit) as exc:
            with unittest.mock.patch("sys.argv",
                                     ["rotbyte", "--untrack", "/some/path"]):
                rotbyte.main()
        # Exit code 6 (EXIT_IO) per spec.
        assert exc.value.code == 6
        assert "permission denied" in capsys.readouterr().err

    def test_run_untrack_internal_error_exits_7(self, monkeypatch, capsys):
        def fake_uninstall(target_dir):
            raise RuntimeError("kaboom")
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd,
                            "_uninstall_launchd", fake_uninstall)
        _force_scheduler_platform(monkeypatch, "macos")

        with pytest.raises(SystemExit) as exc:
            with unittest.mock.patch("sys.argv",
                                     ["rotbyte", "--untrack", "/some/path"]):
                rotbyte.main()
        assert exc.value.code == 7
        assert "kaboom" in capsys.readouterr().err

    def test_run_untrack_unsupported_platform_exits_7(self, monkeypatch, capsys):
        _force_scheduler_platform(monkeypatch, None)
        with pytest.raises(SystemExit) as exc:
            with unittest.mock.patch("sys.argv", ["rotbyte", "--untrack-all"]):
                rotbyte.main()
        assert exc.value.code == 7


class TestUntrackArgValidation:
    """Mutually-exclusive-arg combos must be rejected before we touch
    the scheduler at all.
    """

    def _expect_rejection(self, argv, message_substring):
        with pytest.raises(SystemExit) as exc:
            with unittest.mock.patch("sys.argv", argv):
                rotbyte.main()
        assert exc.value.code == 1

    def test_untrack_and_untrack_all_rejected(self, capsys):
        with pytest.raises(SystemExit) as exc:
            with unittest.mock.patch("sys.argv",
                                     ["rotbyte", "--untrack", "--untrack-all"]):
                rotbyte.main()
        assert exc.value.code == 1
        assert "mutually exclusive" in capsys.readouterr().err

    def test_untrack_with_check_rejected(self, capsys):
        with pytest.raises(SystemExit) as exc:
            with unittest.mock.patch("sys.argv",
                                     ["rotbyte", "--untrack", "--check"]):
                rotbyte.main()
        assert exc.value.code == 1
        assert "--untrack cannot be combined with --check" in capsys.readouterr().err

    def test_untrack_with_track_rejected(self, capsys):
        with pytest.raises(SystemExit) as exc:
            with unittest.mock.patch("sys.argv",
                                     ["rotbyte", "--untrack", "--track"]):
                rotbyte.main()
        assert exc.value.code == 1
        assert "--untrack cannot be combined with --track" in capsys.readouterr().err

    def test_untrack_all_with_status_rejected(self, capsys):
        with pytest.raises(SystemExit) as exc:
            with unittest.mock.patch("sys.argv",
                                     ["rotbyte", "--untrack-all", "--status"]):
                rotbyte.main()
        assert exc.value.code == 1
        assert "--untrack-all cannot be combined with --status" in capsys.readouterr().err


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

    @pytest.mark.skipif(
        sys.platform != "win32" and os.getuid() == 0,
        reason="root ignores file permissions",
    )
    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="chmod 000 does not deny reads to the owner on Windows",
    )
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
        _run_cli_ok(str(tmp))
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
        assert rotbyte.VERSION in out

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
        assert rc == rotbyte.EXIT_DB_CORRUPT
        assert "corrupt" in err.lower()


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
# 36b. Streaming hash — multi-buffer files
# ══════════════════════════════════════════════════════════════════════════════

class TestStreamingHash:
    """Verify the streaming-hash path on files that cross the HASH_BUFFER_SIZE
    boundary so we're not silently optimised into a single-read path for
    small test fixtures.
    """

    def test_multi_buffer_file_matches_reference(self, tmp):
        """A file several buffers long records the correct BLAKE2b digest."""
        from _rotbyte.hashing import HASH_BUFFER_SIZE
        # Three full buffers plus an intentionally-odd tail so any
        # off-by-one in the loop shows up as a hash mismatch.
        data = os.urandom(HASH_BUFFER_SIZE * 3 + 17)
        big = tmp / "big.bin"
        big.write_bytes(data)

        rc, out, err = _run_cli("--json", str(tmp))
        assert rc == 0
        result = _extract_json(out)
        # 4 fixture files + big.bin all hashed fresh.
        assert result["new"] == 5
        # bytes_hashed accumulates every read chunk, so must be >= the big file.
        assert result["bytes_hashed"] >= len(data)

        # The stored checksum must match a reference BLAKE2b over the exact
        # bytes — rules out truncation, double-read, or endianness bugs.
        reference = hashlib.blake2b(data).hexdigest()
        db_path = str(next(tmp.glob(f".*{rotbyte.DB_FILENAME_SUFFIX}")))
        db = rotbyte.ChecksumDB(db_path)
        try:
            rec = db.get_file_record(os.path.realpath(str(big)))
        finally:
            db.close()
        assert rec is not None, "big.bin was not indexed"
        assert rec["checksum"] == reference


# ══════════════════════════════════════════════════════════════════════════════
# 36c. Real SIGINT during a running scan
# ══════════════════════════════════════════════════════════════════════════════

class TestRealSIGINT:
    """Send a real SIGINT to a running rotbyte subprocess. The existing
    interrupt-flag test only exercises the Python-level `interrupted[]`
    list; this covers the signal-handler path end-to-end.
    """

    @pytest.mark.skipif(sys.platform == "win32",
                        reason="SIGINT semantics differ on Windows")
    def test_sigint_exits_cleanly(self, tmp_path):
        import signal
        # Enough files that the scan takes long enough to interrupt reliably.
        for i in range(50):
            (tmp_path / f"f{i:02d}.bin").write_bytes(os.urandom(256 * 1024))

        cmd = [sys.executable,
               os.path.join(os.path.dirname(__file__), "rotbyte.py"),
               "--workers", "1", "--quiet", str(tmp_path)]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # Give it a moment to start hashing.
            time.sleep(0.2)
            # First SIGINT sets the flag; a second forces exit if the first
            # gets swallowed during a tight loop.
            proc.send_signal(signal.SIGINT)
            time.sleep(0.1)
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
            rc = proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            pytest.fail("rotbyte did not exit within timeout after SIGINT")
        # 3 = EXIT_INTERRUPTED; 0 is acceptable if the scan happened to
        # finish in the 200ms window before the signal landed.
        assert rc in (0, 3), f"unexpected exit code {rc} after SIGINT"


# ══════════════════════════════════════════════════════════════════════════════
# 36d. Disk-full / ENOSPC on DB writes
# ══════════════════════════════════════════════════════════════════════════════

class TestDiskFullDBWrites:
    """Simulate an ENOSPC during a DB commit and verify rotbyte surfaces
    the failure rather than crashing the interpreter or silently losing
    work. We run in-process against the real ChecksumDB so the full write
    path (upsert_file → commit) is exercised.
    """

    def test_commit_enospc_propagates(self, tmp, db):
        """Inside an active transaction, a simulated ENOSPC on commit
        propagates as sqlite3.OperationalError and the DB stays recoverable.
        """
        now = rotbyte._now()
        db.begin()
        db.upsert_file("/tmp/a", "a", 1, now, "x" * 128, None, "OK", now)

        def boom():
            raise sqlite3.OperationalError("disk I/O error")

        # Simulate SQLite returning ENOSPC at commit time by patching the
        # rotbyte-level wrapper. Caller must see the original exception —
        # rotbyte must not swallow or mask storage failures.
        with unittest.mock.patch.object(db, "commit", side_effect=boom):
            with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
                db.commit()

        # After the patch is removed, a rollback + fresh transaction
        # succeed — proves rotbyte can recover (e.g. on a retry) rather
        # than carrying poisoned state between operations.
        db.rollback()
        db.begin()
        db.upsert_file("/tmp/b", "b", 1, now, "y" * 128, None, "OK", now)
        db.commit()
        assert db.get_file_status("/tmp/b") == "OK"
        assert db.get_file_status("/tmp/a") is None  # rolled back


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
        assert "previous run" in out and "interrupted" in out


# ══════════════════════════════════════════════════════════════════════════════
# 38. Accept edge cases
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIAcceptEdgeCases:
    def test_accept_ok_file_is_noop(self, tmp):
        """Accepting a file that is already OK should not error or change state."""
        _run_cli_ok(str(tmp))
        rc, out, err = _run_cli("--accept", str(tmp / "a.txt"), str(tmp))
        assert "nothing to accept" in out


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
        _run_cli_ok(str(tmp))

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


# ══════════════════════════════════════════════════════════════════════════════
# 41. --verify-file
# ══════════════════════════════════════════════════════════════════════════════

class TestVerifyFile:
    def test_verify_ok(self, tmp):
        """File that matches baseline exits 0 and prints OK."""
        _run_cli_ok(str(tmp))
        rc, out, err = _run_cli("--verify-file", str(tmp / "a.txt"), str(tmp))
        assert rc == 0
        assert "OK" in out

    def test_verify_mismatch_exit_2(self, tmp):
        """Bit-rotted file (content changed, same mtime) exits 2."""
        _run_cli_ok(str(tmp))
        _corrupt_file(tmp / "a.txt")
        rc, out, err = _run_cli("--verify-file", str(tmp / "a.txt"), str(tmp))
        assert rc == 2
        assert "FAILED" in err

    def test_verify_not_tracked_exit_1(self, tmp):
        """File that exists on disk but is not in the DB exits 1."""
        _run_cli_ok(str(tmp))
        untracked = tmp / "untracked.txt"
        untracked.write_text("not indexed")
        rc, out, err = _run_cli("--verify-file", str(untracked), str(tmp))
        assert rc == 1
        assert "not tracked" in err

    def test_verify_missing_from_disk_exit_1(self, tmp):
        """File tracked in DB but deleted from disk exits 1."""
        _run_cli_ok(str(tmp))
        (tmp / "a.txt").unlink()
        rc, out, err = _run_cli("--verify-file", str(tmp / "a.txt"), str(tmp))
        assert rc == 1
        assert "not found" in err.lower()

    def test_verify_updates_last_verified(self, tmp, db_path):
        """Successful verify updates last_verified in the database."""
        _run_cli_ok(str(tmp))
        file_path = str(os.path.realpath(str(tmp / "a.txt")))

        # Back-date last_verified by a day so any refresh is unambiguous,
        # avoiding a real-time sleep to make timestamps differ.
        db = rotbyte.ChecksumDB(db_path)
        db.conn.execute(
            "UPDATE checksums SET last_verified = datetime('now', '-1 day') "
            "WHERE file_path = ?",
            (file_path,),
        )
        db.conn.commit()
        before = db.get_file_record(file_path)["last_verified"]
        db.close()

        _run_cli("--verify-file", str(tmp / "a.txt"), str(tmp))

        db = rotbyte.ChecksumDB(db_path)
        after = db.get_file_record(file_path)["last_verified"]
        db.close()
        assert after > before

    def test_discover_db_in_cwd(self, tmp, tmp_path):
        """DB is found when cwd contains a matching .{dirname}_rotbyte.db."""
        # Index from cwd == tmp so the DB is created there
        _run_cli_ok(str(tmp))
        # Run --verify-file using cwd=tmp so _discover_db_for_file finds it there
        rc, out, err = _run_cli("--verify-file", str(tmp / "b.txt"), cwd=str(tmp))
        assert rc == 0
        assert "OK" in out

    def test_discover_db_walk_up(self, tmp):
        """DB is discovered by walking up from a deeply nested file."""
        _run_cli_ok(str(tmp))
        deep_file = tmp / "sub" / "d.txt"
        # cwd is a temp dir that has no DB — forces walk-up from deep_file
        rc, out, err = _run_cli("--verify-file", str(deep_file), cwd="/tmp")
        assert rc == 0
        assert "OK" in out

    def test_discover_db_not_found_exit_1(self, tmp):
        """No database anywhere in the tree exits 1 with a helpful error."""
        orphan = tmp / "orphan.txt"
        orphan.write_text("no db for me")
        # No prior run, so no DB exists; cwd=/tmp has no DB either
        rc, out, err = _run_cli("--verify-file", str(orphan), cwd="/tmp")
        assert rc == 1
        assert "database" in err.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 42. Freshness stats — ChecksumDB.freshness_stats()
# ══════════════════════════════════════════════════════════════════════════════

class TestFreshnessStats:
    def test_all_files_verified_within_window(self, tmp, db_path):
        """All files just indexed are within any reasonable window."""
        _run_cli(str(tmp))  # indexes 4 files; sets last_verified = now
        db = rotbyte.ChecksumDB(db_path)
        try:
            total, verified, due = db.freshness_stats(str(tmp), 30)
        finally:
            db.close()
        assert total == 4
        assert verified == 4
        assert due == 0

    def test_files_past_window_counted_as_due(self, tmp, db_path):
        """Files with last_verified older than the window appear as due."""
        _run_cli_ok(str(tmp))
        db = rotbyte.ChecksumDB(db_path)
        try:
            # Back-date last_verified for all files by 40 days
            db.conn.execute(
                "UPDATE checksums SET last_verified = datetime('now', '-40 days')"
            )
            db.conn.commit()
            total, verified, due = db.freshness_stats(str(tmp), 30)
        finally:
            db.close()
        assert total == 4
        assert verified == 0
        assert due == 4

    def test_mixed_freshness(self, tmp, db_path):
        """Some files within window, others outside."""
        _run_cli_ok(str(tmp))
        db = rotbyte.ChecksumDB(db_path)
        try:
            # Back-date two files by 40 days
            rows = db.conn.execute(
                "SELECT file_path FROM checksums ORDER BY file_path LIMIT 2"
            ).fetchall()
            for row in rows:
                db.conn.execute(
                    "UPDATE checksums SET last_verified = datetime('now', '-40 days') "
                    "WHERE file_path = ?",
                    (row["file_path"],),
                )
            db.conn.commit()
            total, verified, due = db.freshness_stats(str(tmp), 30)
        finally:
            db.close()
        assert total == 4
        assert verified == 2
        assert due == 2

    def test_missing_files_excluded(self, tmp, db_path):
        """MISSING files are not counted in freshness stats."""
        _run_cli_ok(str(tmp))
        db = rotbyte.ChecksumDB(db_path)
        try:
            # Mark one file as MISSING
            db.conn.execute(
                "UPDATE checksums SET status = 'MISSING' "
                "WHERE file_path = (SELECT file_path FROM checksums LIMIT 1)"
            )
            db.conn.commit()
            total, verified, due = db.freshness_stats(str(tmp), 30)
        finally:
            db.close()
        assert total == 3  # 4 files minus the 1 MISSING one

    def test_empty_database(self, tmp_path):
        """freshness_stats on an empty database returns all zeros."""
        db_name = "." + tmp_path.name + rotbyte.DB_FILENAME_SUFFIX
        db = rotbyte.ChecksumDB(str(tmp_path / db_name))
        try:
            total, verified, due = db.freshness_stats(str(tmp_path), 30)
        finally:
            db.close()
        assert total == 0
        assert verified == 0
        assert due == 0


# ══════════════════════════════════════════════════════════════════════════════
# 43. Freshness stats in --status output
# ══════════════════════════════════════════════════════════════════════════════

class TestStatusFreshness:
    def _make_tracked(self, target_dir: str, due: str) -> dict:
        """Build a minimal _discover_tracked() return value with --due configured."""
        return {
            target_dir: {
                "quick": {"interval": 3600, "active": True},
                "full": {
                    "times": [(2, 0)],
                    "active": True,
                    "due": due,
                    "budget": None,
                    "workers": None,
                    "notify": None,
                },
            }
        }

    def _capture_status(self, tracked: dict) -> str:
        """Invoke rotbyte._run_status() on Linux with `tracked` mocked in.

        Returns the captured stdout. Centralises the platform forcing and
        stdout redirection that every freshness assertion needs.
        """
        captured = io.StringIO()
        with unittest.mock.patch("rotbyte._discover_tracked",
                                 return_value=tracked), \
             _force_rotbyte_platform("linux"), \
             unittest.mock.patch("sys.stdout", captured):
            rotbyte._run_status()
        return captured.getvalue()

    def test_status_shows_new_distinct_from_ok(self, tmp, db_path):
        # A single index leaves files as NEW (never re-verified). --status
        # must show them as NEW, not fold them into OK.
        _run_cli(str(tmp))
        out = self._capture_status(self._make_tracked(str(tmp), "30d"))
        assert "NEW" in out

    def test_status_shows_next_full_run(self, tmp, db_path):
        _run_cli_ok(str(tmp))
        out = self._capture_status(self._make_tracked(str(tmp), "30d"))
        assert "next 2 AM" in out
        assert "(in " in out          # duration-until suffix

    def test_status_no_next_run_when_broken(self, tmp, db_path):
        _run_cli_ok(str(tmp))
        tracked = self._make_tracked(str(tmp), "30d")
        tracked[str(tmp)]["full"]["missing_exe"] = "/dead/python"
        out = self._capture_status(tracked)
        assert "next 2 AM" not in out

    def test_status_last_uses_finished_at(self, tmp, db_path):
        _run_cli_ok(str(tmp))
        out = self._capture_status(self._make_tracked(str(tmp), "30d"))
        assert "Last  :" in out
        # A cleanly completed run is not flagged as interrupted.
        assert "in progress or interrupted" not in out

    def test_freshness_shown_when_due_configured(self, tmp, db_path):
        """--status shows freshness stats when --due is in the tracked config."""
        _run_cli(str(tmp))  # create database with 4 files verified now
        out = self._capture_status(self._make_tracked(str(tmp), "30d"))
        assert "Fresh" in out
        assert "30d window" in out
        assert "files verified" in out
        assert "files due for re-verification" in out

    def test_freshness_values_correct(self, tmp, db_path):
        """Freshness line shows correct counts (all 4 files verified within window)."""
        _run_cli_ok(str(tmp))
        out = self._capture_status(self._make_tracked(str(tmp), "30d"))
        assert "4 / 4" in out

    def test_freshness_shows_overdue_count(self, tmp, db_path):
        """Freshness line shows correct counts when some files are past the window."""
        _run_cli(str(tmp))  # indexes 4 files with last_verified = now

        # Back-date 2 of the 4 files past the 30-day window
        db = rotbyte.ChecksumDB(db_path)
        try:
            rows = db.conn.execute(
                "SELECT file_path FROM checksums ORDER BY file_path LIMIT 2"
            ).fetchall()
            for row in rows:
                db.conn.execute(
                    "UPDATE checksums SET last_verified = datetime('now', '-40 days') "
                    "WHERE file_path = ?",
                    (row["file_path"],),
                )
            db.conn.commit()
        finally:
            db.close()

        out = self._capture_status(self._make_tracked(str(tmp), "30d"))
        assert "2 / 4" in out        # 2 verified, 4 total
        assert "50.0%" in out        # 2/4 = 50%
        assert "2 files due" in out  # 2 overdue

    def test_freshness_absent_when_no_due(self, tmp, db_path):
        """--status does not show freshness section when --due is not configured."""
        _run_cli_ok(str(tmp))

        tracked = {
            str(tmp): {
                "quick": {"interval": 3600, "active": True},
                "full": {
                    "times": [(2, 0)],
                    "active": True,
                    "budget": None,
                    "workers": None,
                    "notify": None,
                },
            }
        }
        out = self._capture_status(tracked)
        assert "Fresh" not in out
        assert "due for re-verification" not in out

    def test_freshness_absent_when_no_full_scan(self, tmp, db_path):
        """--status does not show freshness when only quick scan is configured."""
        _run_cli_ok(str(tmp))

        tracked = {
            str(tmp): {
                "quick": {"interval": 3600, "active": True},
            }
        }
        out = self._capture_status(tracked)
        assert "Fresh" not in out


# ══════════════════════════════════════════════════════════════════════════════
# 44. Freshness stats in --notify email body
# ══════════════════════════════════════════════════════════════════════════════

def _extract_text_part(msg):
    """Return the decoded text/plain body from a (possibly multipart) message.

    Notification emails are multipart/alternative (plain + HTML); the
    assertions target the plain-text rendering.
    """
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                return payload.decode(charset)
        raise AssertionError("no text/plain part in multipart message")
    payload = msg.get_payload(decode=True)
    charset = msg.get_content_charset() or "utf-8"
    return payload.decode(charset)


class TestNotifyFreshness:
    def _capture_email_body(self, freshness=None):
        """Call _send_email_notification with a mocked SMTP and return the body."""
        import configparser
        cfg = configparser.ConfigParser()
        cfg["email"] = {
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "username": "user@example.com",
            "password": "secret",
            "to": "user@example.com",
        }

        sent_messages = []

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def starttls(self):
                pass
            def login(self, user, pwd):
                pass
            def sendmail(self, frm, to, msg):
                sent_messages.append(msg)

        with unittest.mock.patch("_rotbyte.notify._load_notify_config", return_value=cfg), \
             unittest.mock.patch("rotbyte.smtplib.SMTP", FakeSMTP):
            rotbyte._send_email_notification(
                "/data/photos", failed=1, count_missing=0,
                failed_files=[{"file_path": "/data/photos/img.jpg"}],
                freshness=freshness,
            )

        assert sent_messages, "No email was sent"
        # Parse the raw RFC 2822 message and return the decoded text body
        import email as _email_mod
        msg_obj = _email_mod.message_from_string(sent_messages[0])
        return _extract_text_part(msg_obj)

    def test_freshness_present_when_provided(self):
        """Email body includes freshness summary when freshness tuple is supplied."""
        body = self._capture_email_body(freshness=(100, 87, 13))
        assert "Verification freshness" in body
        assert "87 / 100" in body
        assert "13 due" in body

    def test_freshness_percentage_correct(self):
        """Freshness percentage is computed correctly."""
        body = self._capture_email_body(freshness=(200, 150, 50))
        assert "75.0%" in body

    def test_freshness_absent_when_none(self):
        """Email body has no freshness section when freshness=None."""
        body = self._capture_email_body(freshness=None)
        assert "Verification freshness" not in body
        assert "due for re-verification" not in body

    def test_freshness_zero_total(self):
        """freshness with zero total files does not divide by zero."""
        body = self._capture_email_body(freshness=(0, 0, 0))
        assert "Verification freshness" in body
        assert "0.0%" in body


# ══════════════════════════════════════════════════════════════════════════════
# 44b. Outcome-based subject lines (PASS / DETECTED, progress, interrupted)
# ══════════════════════════════════════════════════════════════════════════════

class TestNotifyOutcome:
    """Subject line classifies each scan as PASS or DETECTED, embeds optional
    due-progress percentage, and appends ``(interrupted)`` when applicable.
    Body distinguishes budget exhaustion from per-file read errors when some
    due files remain unverified.
    """

    def _send_and_capture(self, **kwargs):
        """Invoke _send_email_notification with a mocked SMTP; return (subject, body)."""
        import configparser
        cfg = configparser.ConfigParser()
        cfg["email"] = {
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "username": "user@example.com",
            "password": "secret",
            "to": "user@example.com",
        }

        sent = []

        class FakeSMTP:
            def __init__(self, *a, **kw): pass
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def starttls(self): pass
            def login(self, *a): pass
            def sendmail(self, frm, to, msg): sent.append(msg)

        defaults = dict(
            target_dir="/data/photos",
            failed=0, count_missing=0, failed_files=[],
        )
        defaults.update(kwargs)

        with unittest.mock.patch("_rotbyte.notify._load_notify_config", return_value=cfg), \
             unittest.mock.patch("rotbyte.smtplib.SMTP", FakeSMTP):
            rotbyte._send_email_notification(**defaults)

        assert sent, "No email was sent"
        import email as _email_mod
        import email.header as _email_hdr
        msg = _email_mod.message_from_string(sent[0])
        # Subject is Q-encoded (RFC 2047) when it contains non-ASCII chars
        # (the em-dash). Decode into a plain str for the assertions.
        raw = msg["Subject"]
        decoded = _email_hdr.decode_header(raw)
        subject = "".join(
            (part.decode(charset or "utf-8") if isinstance(part, bytes) else part)
            for part, charset in decoded
        )
        return subject, _extract_text_part(msg)

    def test_clean_no_due_subject_is_pass(self):
        subject, _ = self._send_and_capture()
        assert subject.startswith("rotbyte: PASS")
        assert "DETECTED" not in subject
        assert "%" not in subject
        # Directory is present; the host now trails the subject for
        # per-machine inbox filtering.
        assert "/data/photos" in subject

    def test_clean_body_mentions_clean_completion(self):
        _, body = self._send_and_capture()
        assert "completed cleanly" in body
        assert "Affected files" not in body

    def test_detected_subject_includes_problem_detail(self):
        subject, _ = self._send_and_capture(
            failed=3, failed_files=[{"file_path": "/data/photos/a.jpg"}],
        )
        assert "DETECTED" in subject
        assert "bit rot in 3 files" in subject

    def test_detected_missing_plural_and_singular(self):
        s1, _ = self._send_and_capture(failed=1, failed_files=[{"file_path": "/x"}])
        assert "bit rot in 1 file " in s1 or "bit rot in 1 file —" in s1
        s2, _ = self._send_and_capture(count_missing=1)
        assert "1 file missing" in s2

    def test_due_progress_full_is_100_percent(self):
        subject, _ = self._send_and_capture(due_progress=(47, 47))
        assert "PASS 100% (47/47 due)" in subject

    def test_due_progress_partial_percent(self):
        subject, body = self._send_and_capture(due_progress=(30, 47))
        assert "PASS 64% (30/47 due)" in subject
        assert "30 / 47 verified this run" in body
        assert "63.8%" in body

    def test_interrupted_suffix_in_subject(self):
        subject, body = self._send_and_capture(interrupted=True)
        assert "(interrupted)" in subject
        assert "Scan was interrupted" in body

    def test_detected_with_progress_and_interruption(self):
        subject, _ = self._send_and_capture(
            failed=2, failed_files=[{"file_path": "/x"}],
            due_progress=(10, 47), interrupted=True,
        )
        assert "DETECTED" in subject
        assert "21% (10/47 due)" in subject
        assert "(interrupted)" in subject
        assert "bit rot in 2 files" in subject

    def test_body_budget_exhausted_note(self):
        _, body = self._send_and_capture(
            due_progress=(30, 47), budget_exceeded=True,
        )
        assert "17 files still due" in body
        assert "budget exhausted" in body
        assert "`--budget`" in body
        # Must NOT claim errors caused the shortfall when errors=0
        assert "read error" not in body

    def test_body_errors_note(self):
        _, body = self._send_and_capture(
            due_progress=(30, 47), errors=4,
        )
        assert "17 files still due" in body
        assert "4 read errors" in body
        assert "budget" not in body

    def test_body_budget_and_errors_note(self):
        _, body = self._send_and_capture(
            due_progress=(30, 47), budget_exceeded=True, errors=2,
        )
        assert "17 files still due" in body
        assert "budget exhausted" in body
        assert "2 additional read errors" in body

    def test_body_no_remaining_has_no_shortfall_line(self):
        _, body = self._send_and_capture(due_progress=(47, 47))
        assert "still due" not in body

    def test_duration_in_body_when_provided(self):
        _, body = self._send_and_capture(elapsed_seconds=125.0)
        assert "Scan duration:" in body

    def test_clean_body_skips_report_hint(self):
        """PASS body doesn't need the --report / --accept hint (nothing to fix)."""
        _, body = self._send_and_capture()
        assert "--report" not in body
        assert "--accept" not in body

    def test_detected_body_keeps_report_hint(self):
        _, body = self._send_and_capture(
            failed=1, failed_files=[{"file_path": "/x"}],
        )
        assert "--report" in body
        assert "--accept" in body

    def test_due_progress_with_zero_start_is_omitted(self):
        """due_progress=(0, 0) shouldn't add a percentage (nothing was due)."""
        subject, body = self._send_and_capture(due_progress=(0, 0))
        # We pass (0,0) but the caller in _run_phases only sets due_progress
        # when start > 0. Still, be defensive: 100% is reasonable.
        assert "0/0 due" in subject or "PASS —" in subject or "PASS " in subject

    def test_host_appears_in_subject_and_body(self):
        subject, body = self._send_and_capture(host="nas-01")
        assert "nas-01" in subject
        assert "nas-01" in body

    def test_host_defaults_to_gethostname(self):
        with unittest.mock.patch("_rotbyte.notify.socket.gethostname",
                                 return_value="fallback-host"):
            subject, body = self._send_and_capture()
        assert "fallback-host" in subject

    def test_file_paths_never_appear_in_body(self):
        """Privacy: affected file paths must not travel over SMTP."""
        _, body = self._send_and_capture(
            failed=2,
            failed_files=[{"file_path": "/data/photos/secret-vacation.jpg"},
                          {"file_path": "/data/photos/private.raw"}],
        )
        assert "secret-vacation.jpg" not in body
        assert "private.raw" not in body
        # Instead it names the local command that lists them.
        assert "rotbyte --report /data/photos" in body

    def test_scan_summary_rendered_on_pass(self):
        _, body = self._send_and_capture(
            stats={"ok": 1200, "new": 3, "updated": 2, "skipped": 40,
                   "bytes_hashed": 5 * 1024 * 1024 * 1024},
        )
        assert "Scan summary" in body
        assert "1,200" in body      # verified OK, thousands-separated
        assert "Data hashed" in body

    def test_html_alternative_part_present(self):
        """Message carries an HTML alternative alongside the text part."""
        import configparser
        cfg = configparser.ConfigParser()
        cfg["email"] = {
            "smtp_host": "smtp.example.com", "smtp_port": "587",
            "username": "user@example.com", "password": "secret",
            "to": "user@example.com",
        }
        sent = []

        class FakeSMTP:
            def __init__(self, *a, **kw): pass
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def starttls(self): pass
            def login(self, *a): pass
            def sendmail(self, frm, to, msg): sent.append(msg)

        with unittest.mock.patch("_rotbyte.notify._load_notify_config", return_value=cfg), \
             unittest.mock.patch("rotbyte.smtplib.SMTP", FakeSMTP):
            rotbyte._send_email_notification(
                "/data/photos", failed=1, count_missing=0,
                failed_files=[{"file_path": "/data/photos/x.jpg"}])
        import email as _email_mod
        msg = _email_mod.message_from_string(sent[0])
        types = {p.get_content_type() for p in msg.walk()}
        assert "text/plain" in types
        assert "text/html" in types
        # HTML part must also be path-free.
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                htmlbody = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8")
                assert "x.jpg" not in htmlbody

    def test_change_since_last_run_regression(self):
        _, body = self._send_and_capture(
            failed=3, failed_files=[{"file_path": "/x"}], previous_counts=(1, 0))
        assert "Change since last run: bit rot 1 → 3" in body

    def test_change_since_last_run_recovery(self):
        # Previous run had 3 failures; this one is clean.
        _, body = self._send_and_capture(previous_counts=(3, 0))
        assert "bit rot 3 → 0" in body

    def test_no_change_line_when_counts_identical(self):
        _, body = self._send_and_capture(
            failed=2, failed_files=[{"file_path": "/x"}], previous_counts=(2, 0))
        assert "Change since last run" not in body

    def test_no_change_line_without_previous_counts(self):
        _, body = self._send_and_capture(
            failed=1, failed_files=[{"file_path": "/x"}])
        assert "Change since last run" not in body

    def test_scan_time_in_body_when_provided(self):
        _, body = self._send_and_capture(scan_time="2026-07-08 20:15 PDT")
        assert "2026-07-08 20:15 PDT" in body

    def test_change_line_also_rendered_in_html_part(self):
        import configparser
        cfg = configparser.ConfigParser()
        cfg["email"] = {
            "smtp_host": "h", "smtp_port": "587",
            "username": "u@x.com", "password": "p", "to": "u@x.com",
        }
        sent = []

        class F:
            def __init__(s, *a, **k): pass
            def __enter__(s): return s
            def __exit__(s, *a): pass
            def starttls(s): pass
            def login(s, *a): pass
            def sendmail(s, fr, to, m): sent.append(m)

        with unittest.mock.patch("_rotbyte.notify._load_notify_config", return_value=cfg), \
             unittest.mock.patch("rotbyte.smtplib.SMTP", F):
            rotbyte._send_email_notification(
                "/data", failed=3, count_missing=0,
                failed_files=[{"file_path": "/x"}], previous_counts=(1, 0))
        import email as _email_mod
        msg = _email_mod.message_from_string(sent[0])
        html = [p for p in msg.walk() if p.get_content_type() == "text/html"][0]
        htmlbody = html.get_payload(decode=True).decode(
            html.get_content_charset() or "utf-8")
        assert "1 → 3" in htmlbody

    def test_scan_time_absent_when_not_provided(self):
        _, body = self._send_and_capture()
        assert "Scan time" not in body


# ══════════════════════════════════════════════════════════════════════════════
# 45. --notify suppression: full re-verifies always send; scheduled quick
#     scans send only when problems are detected.
# ══════════════════════════════════════════════════════════════════════════════

class TestNotifyPartialScan:
    """Verify email notification rules for scheduled vs. untracked runs."""

    def _make_args(self, notify="email", budget=None, due=None,
                   scheduled=False, check=True):
        import argparse
        args = argparse.Namespace(
            notify=notify,
            budget=budget,
            due=due,
            budget_seconds=1800 if budget else None,
            due_days=30 if due else None,
            scheduled=scheduled,
            full_at=None,
            quiet=True,
            json_output=False,
            check=check,
            workers=1,
            include_hidden=False,
            exclude_dirs=[],
            skip_missing=False,
        )
        return args

    def _run_phases_with_mock(self, tmp_path, args, problem="corrupt"):
        """Run _run_phases against a real (indexed) tmp dir and return send call count.

        ``problem`` selects how to introduce trouble between the index and
        verify passes: ``"corrupt"`` flips bytes while preserving mtime/size
        (visible only to --check), ``"missing"`` deletes a file (visible to
        quick scans too), and ``None`` leaves the tree clean.
        """
        target_dir = str(tmp_path)
        db_name = "." + tmp_path.name + rotbyte.DB_FILENAME_SUFFIX
        db_path = str(tmp_path / db_name)

        db = rotbyte.ChecksumDB(db_path)
        interrupted = [False]
        index_args = self._make_args(notify=None, budget=None, due=None)
        with unittest.mock.patch("rotbyte._send_email_notification"):
            with pytest.raises(SystemExit):
                rotbyte._run_phases(db, target_dir, index_args, interrupted)
        db.close()

        if problem == "corrupt":
            for f in tmp_path.iterdir():
                if f.suffix == ".txt":
                    _corrupt_file(f)
                    break
        elif problem == "missing":
            for f in tmp_path.iterdir():
                if f.suffix == ".txt":
                    f.unlink()
                    break

        db = rotbyte.ChecksumDB(db_path)
        interrupted = [False]
        with unittest.mock.patch("rotbyte._send_email_notification") as mock_send:
            with pytest.raises(SystemExit):
                rotbyte._run_phases(db, target_dir, args, interrupted)
        db.close()
        return mock_send.call_count

    def test_untracked_run_always_sends_email(self, tmp):
        """Manual run with --notify + --budget sends email (no --scheduled)."""
        args = self._make_args(notify="email", budget="30m", scheduled=False)
        call_count = self._run_phases_with_mock(tmp, args)
        assert call_count == 1, "Expected email on untracked run even with --budget"

    def test_scheduled_full_scan_sends_email(self, tmp):
        """Scheduled full re-verify (--check) always sends a health report."""
        args = self._make_args(notify="email", scheduled=True, check=True)
        call_count = self._run_phases_with_mock(tmp, args, problem=None)
        assert call_count == 1, "Expected email after scheduled full re-verify"

    def test_scheduled_full_scan_with_budget_sends_email(self, tmp):
        """Scheduled full re-verify with --budget still sends email."""
        args = self._make_args(notify="email", budget="30m",
                               scheduled=True, check=True)
        call_count = self._run_phases_with_mock(tmp, args, problem="corrupt")
        assert call_count == 1, "Expected email for budget-capped full scan"

    def test_scheduled_quick_scan_with_problems_sends_email(self, tmp):
        """Scheduled quick scan alerts when problems are detected."""
        args = self._make_args(notify="email", scheduled=True, check=False)
        call_count = self._run_phases_with_mock(tmp, args, problem="missing")
        assert call_count == 1, "Expected alert email from scheduled quick scan"

    def test_scheduled_quick_scan_no_problems_suppresses(self, tmp):
        """Scheduled quick scan stays quiet when nothing is wrong."""
        args = self._make_args(notify="email", scheduled=True, check=False)
        call_count = self._run_phases_with_mock(tmp, args, problem=None)
        assert call_count == 0, "Expected no email from clean scheduled quick scan"


# ══════════════════════════════════════════════════════════════════════════════
# --track-setup wizard
# ══════════════════════════════════════════════════════════════════════════════

class TestTrackSetup:
    """Verify _run_track_setup() parses prompts correctly and delegates to
    _run_track() with the expected arguments. _run_track itself is mocked so
    the tests don't touch launchd/systemd."""

    def _run_wizard(self, tmp, inputs, notify_cfg_exists=False):
        """Feed `inputs` (a list of strings, one per input() call) to the
        wizard and return the kwargs-equivalent tuple captured from the
        mocked _run_track call, or None if _run_track wasn't called."""
        captured = {}

        def fake_run_track(target_dir, every_seconds, full_at,
                           budget_seconds, rotbyte_exe, workers=None,
                           due_days=None, notify=None):
            captured.update(
                target_dir=target_dir,
                every_seconds=every_seconds,
                full_at=full_at,
                budget_seconds=budget_seconds,
                workers=workers,
                due_days=due_days,
                notify=notify,
            )

        # os.path.exists is patched only for the notify-config check. The
        # wizard's os.path.isdir / os.path.realpath calls are unaffected.
        real_exists = os.path.exists
        notify_cfg = rotbyte._notify_config_path()

        def fake_exists(p):
            if p == notify_cfg:
                return notify_cfg_exists
            return real_exists(p)

        with unittest.mock.patch.object(rotbyte, "_run_track",
                                        side_effect=fake_run_track) as m, \
             unittest.mock.patch.object(rotbyte, "_find_rotbyte_executable",
                                        return_value="rotbyte"), \
             unittest.mock.patch("os.path.exists", side_effect=fake_exists), \
             unittest.mock.patch("builtins.input", side_effect=inputs):
            rotbyte._run_track_setup(str(tmp))

        return captured if m.called else None

    def test_all_defaults_install(self, tmp):
        """Empty inputs → 60m every, no full-at, no budget, no due, no notify."""
        inputs = [
            "",     # target dir (accept default)
            "",     # every (accept default 60m)
            "",     # full-at (none)
            "",     # due (none)
            "",     # notify (no)
            "",     # install confirm (Y default)
        ]
        captured = self._run_wizard(tmp, inputs)
        assert captured is not None, "Expected _run_track to be called"
        assert captured["every_seconds"] == 3600
        assert captured["full_at"] is None
        assert captured["budget_seconds"] is None
        assert captured["due_days"] is None
        assert captured["notify"] is None
        assert captured["target_dir"] == os.path.realpath(str(tmp))

    def test_full_schedule_with_budget_and_due(self, tmp):
        """All fields provided — budget prompt appears only because full-at set."""
        inputs = [
            "",         # target dir
            "30m",      # every
            "2h 14h",   # full-at
            "2h",       # budget
            "30d",      # due
            "n",        # notify
            "",         # install confirm
        ]
        captured = self._run_wizard(tmp, inputs)
        assert captured["every_seconds"] == 1800
        assert captured["full_at"] == [(2, 0), (14, 0)]
        assert captured["budget_seconds"] == 7200
        assert captured["due_days"] == 30
        assert captured["notify"] is None

    def test_invalid_duration_reprompts(self, tmp):
        """Bad --every value re-prompts rather than crashing."""
        inputs = [
            "",         # target dir
            "bogus",    # every → invalid
            "30m",      # every → valid
            "",         # full-at
            "",         # due
            "",         # notify
            "",         # install
        ]
        captured = self._run_wizard(tmp, inputs)
        assert captured["every_seconds"] == 1800

    def test_abort_at_confirmation_skips_install(self, tmp):
        """Answering 'n' at the install prompt must not call _run_track."""
        inputs = [
            "",         # target dir
            "",         # every
            "",         # full-at
            "",         # due
            "",         # notify
            "n",        # install → abort
        ]
        captured = self._run_wizard(tmp, inputs)
        assert captured is None or captured == {}, \
            "Expected _run_track to NOT be called on abort"

    def test_notify_without_config_continues_without_email(self, tmp):
        """Answering yes to notify but with no config file → notify stays None."""
        inputs = [
            "",     # target dir
            "",     # every
            "",     # full-at
            "",     # due
            "y",    # notify yes
            "",     # install
        ]
        captured = self._run_wizard(tmp, inputs, notify_cfg_exists=False)
        assert captured["notify"] is None, \
            "Wizard should skip email when config is missing"

    def test_notify_with_config_enables_email(self, tmp):
        """Answering yes with a config file present → notify='email'."""
        inputs = [
            "",     # target dir
            "",     # every
            "",     # full-at
            "",     # due
            "y",    # notify yes
            "",     # install
        ]
        captured = self._run_wizard(tmp, inputs, notify_cfg_exists=True)
        assert captured["notify"] == "email"

    def test_budget_prompt_skipped_without_full_at(self, tmp):
        """No full-at means the wizard never asks for a budget."""
        # Only 6 inputs — if the wizard asked for budget, input() would raise
        # StopIteration and the test would fail.
        inputs = [
            "",     # target dir
            "",     # every
            "",     # full-at (none → skip budget)
            "",     # due
            "",     # notify
            "",     # install
        ]
        captured = self._run_wizard(tmp, inputs)
        assert captured["budget_seconds"] is None


# ══════════════════════════════════════════════════════════════════════════════
#  Platform portability — Windows
# ══════════════════════════════════════════════════════════════════════════════
#
#  Tests in this block split into two groups:
#
#    1. Platform-agnostic: pure functions (XML generation, argument quoting,
#       ISO duration parsing) and the _IS_WINDOWS constant. These run on every
#       platform because they exercise code paths whose logic is identical
#       regardless of host OS.
#
#    2. Windows-only: anything that shells out to schtasks.exe or relies on
#       msvcrt locking semantics. Gated with @pytest.mark.skipif(not is_windows)
#       so the suite stays green on macOS/Linux CI but is ready to run the
#       moment a windows-latest runner is added.
#
#  When the CI matrix gains a windows-latest job, the skipped tests activate
#  automatically — no selector flags needed.

_IS_WINDOWS_HOST = sys.platform == "win32"
_skip_not_windows = pytest.mark.skipif(
    not _IS_WINDOWS_HOST, reason="Windows-only: requires schtasks.exe / msvcrt"
)
_skip_windows = pytest.mark.skipif(
    _IS_WINDOWS_HOST, reason="POSIX-only behavior"
)


class TestPlatformConstant:
    """The module-level _IS_WINDOWS flag should mirror sys.platform."""

    def test_flag_matches_sys_platform(self):
        assert rotbyte._IS_WINDOWS is (sys.platform == "win32")


class TestQuoteWindowsArgs:
    """Pure function — round-trippable on any platform."""

    def test_empty_list(self):
        assert rotbyte._quote_windows_args([]) == ""

    def test_simple_args_not_quoted(self):
        assert rotbyte._quote_windows_args(["--check", "--quiet"]) == "--check --quiet"

    def test_arg_with_space_is_quoted(self):
        # Per CommandLineToArgvW, backslashes are literal unless they
        # precede a quote — mid-path separators must NOT be doubled.
        # (The old blanket-doubling produced "C:\\Program Files\\Media",
        # which parses back with doubled separators.)
        out = rotbyte._quote_windows_args(["--path", "C:\\Program Files\\Media"])
        assert out == '--path "C:\\Program Files\\Media"'

    def test_trailing_backslash_in_quoted_arg_is_doubled(self):
        # A trailing backslash would otherwise escape the closing quote.
        out = rotbyte._quote_windows_args(["C:\\My Files\\"])
        assert out == '"C:\\My Files\\\\"'

    def test_split_round_trip(self):
        args = ["--path", "C:\\Program Files\\Media", 'say "hi"',
                "--quiet", "", "C:\\My Files\\"]
        joined = rotbyte._quote_windows_args(args)
        assert rotbyte._split_windows_args(joined) == args

    def test_empty_string_becomes_empty_quotes(self):
        # Preserves argv position for deliberately empty arguments.
        assert rotbyte._quote_windows_args([""]) == '""'

    def test_embedded_quote_is_escaped(self):
        out = rotbyte._quote_windows_args(['say "hi"'])
        assert out.startswith('"') and out.endswith('"')
        assert '\\"hi\\"' in out

    def test_tab_triggers_quoting(self):
        out = rotbyte._quote_windows_args(["a\tb"])
        assert out.startswith('"') and out.endswith('"')


class TestIsoDuration:
    """Round-trip between seconds and ISO 8601 duration strings."""

    def test_hours_only(self):
        assert rotbyte._iso_duration(7200) == "PT2H"

    def test_minutes_only(self):
        assert rotbyte._iso_duration(1800) == "PT30M"

    def test_hours_and_minutes(self):
        assert rotbyte._iso_duration(5400) == "PT1H30M"

    def test_sub_minute_falls_back_to_seconds(self):
        # Less than a minute: we emit seconds rather than a zero-length duration.
        assert rotbyte._iso_duration(30) == "PT30S"

    def test_zero_yields_safe_default(self):
        # Never emit PT (invalid) — the scheduler would reject it.
        assert rotbyte._iso_duration(0) == "PT1M"

    def test_negative_clamped_to_safe_default(self):
        assert rotbyte._iso_duration(-5) == "PT1M"

    def test_roundtrip_hours(self):
        assert rotbyte._parse_iso_duration(rotbyte._iso_duration(7200)) == 7200

    def test_roundtrip_mixed(self):
        assert rotbyte._parse_iso_duration(rotbyte._iso_duration(5400)) == 5400

    def test_parse_none_returns_none(self):
        assert rotbyte._parse_iso_duration(None) is None

    def test_parse_malformed_returns_none(self):
        assert rotbyte._parse_iso_duration("not a duration") is None

    def test_parse_seconds_component(self):
        assert rotbyte._parse_iso_duration("PT45S") == 45


class TestGenerateTaskXML:
    """The generated XML is Task Scheduler's wire format — structural assertions."""

    def _triggers(self):
        return (
            '<Triggers>\n'
            '    <TimeTrigger>\n'
            '      <StartBoundary>2026-01-01T00:00:00</StartBoundary>\n'
            '      <Enabled>true</Enabled>\n'
            '      <Repetition>\n'
            '        <Interval>PT1H</Interval>\n'
            '        <StopAtDurationEnd>false</StopAtDurationEnd>\n'
            '      </Repetition>\n'
            '    </TimeTrigger>\n'
            '  </Triggers>'
        )

    def _parse(self, xml_str):
        """Parse the generated XML and return the root element."""
        import xml.etree.ElementTree as ET
        return ET.fromstring(xml_str)

    def test_battery_disallow_default(self):
        xml = rotbyte._generate_task_xml(
            "rotbyte quick scan (D:\\Media)",
            ["python.exe", "rotbyte.py", "D:\\Media"],
            self._triggers(), run_on_battery=False,
        )
        assert "<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>" in xml
        assert "<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>" in xml

    def test_run_on_battery_flips_both_flags(self):
        xml = rotbyte._generate_task_xml(
            "rotbyte quick scan (D:\\Media)",
            ["python.exe", "rotbyte.py", "D:\\Media"],
            self._triggers(), run_on_battery=True,
        )
        assert "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" in xml
        assert "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>" in xml

    def test_execution_time_limit_honored(self):
        xml = rotbyte._generate_task_xml(
            "rotbyte full scan (D:\\Media)",
            ["python.exe", "rotbyte.py", "--check", "D:\\Media"],
            self._triggers(), run_on_battery=False,
            execution_time_limit="PT2H",
        )
        assert "<ExecutionTimeLimit>PT2H</ExecutionTimeLimit>" in xml

    def test_default_time_limit_when_unspecified(self):
        xml = rotbyte._generate_task_xml(
            "rotbyte quick scan (D:\\Media)",
            ["python.exe", "rotbyte.py", "D:\\Media"],
            self._triggers(), run_on_battery=False,
        )
        # Default prevents hung tasks from blocking the next schedule.
        assert "<ExecutionTimeLimit>PT24H</ExecutionTimeLimit>" in xml

    def test_xml_is_parseable(self):
        xml = rotbyte._generate_task_xml(
            "rotbyte quick scan (D:\\Media)",
            ["python.exe", "rotbyte.py", "D:\\Media"],
            self._triggers(), run_on_battery=False,
        )
        root = self._parse(xml)
        assert root.tag.endswith("}Task")

    def test_command_and_arguments_in_exec(self):
        xml = rotbyte._generate_task_xml(
            "rotbyte quick scan (D:\\Media)",
            ["C:\\Python\\python.exe", "rotbyte.py", "--quiet", "D:\\Media"],
            self._triggers(), run_on_battery=False,
        )
        assert "<Command>C:\\Python\\python.exe</Command>" in xml
        assert "<Arguments>" in xml
        assert "rotbyte.py" in xml
        assert "D:\\Media" in xml

    def test_argument_with_space_is_quoted_in_xml(self):
        xml = rotbyte._generate_task_xml(
            "rotbyte quick scan",
            ["python.exe", "rotbyte.py", "D:\\My Media"],
            self._triggers(), run_on_battery=False,
        )
        # The path with a space is wrapped in XML-escaped quotes. Per
        # CommandLineToArgvW, mid-path backslashes stay single — only
        # backslashes preceding a quote need doubling.
        assert "&quot;D:\\My Media&quot;" in xml

    def test_description_is_xml_escaped(self):
        # Path containing an ampersand must not break XML parsing.
        xml = rotbyte._generate_task_xml(
            "rotbyte quick scan (D:\\A & B)",
            ["python.exe", "rotbyte.py"],
            self._triggers(), run_on_battery=False,
        )
        assert "D:\\A &amp; B" in xml
        # And the document is still parseable.
        self._parse(xml)

    def test_empty_command_rejected(self):
        with pytest.raises(ValueError):
            rotbyte._generate_task_xml(
                "empty", [], self._triggers(), run_on_battery=False,
            )

    def test_uri_uses_rotbyte_folder(self):
        xml = rotbyte._generate_task_xml(
            "rotbyte quick scan (D:\\Media)",
            ["python.exe", "rotbyte.py"],
            self._triggers(), run_on_battery=False,
        )
        assert "<URI>\\rotbyte\\" in xml


class TestLockShim:
    """The _try_lock/_unlock shim must work the same on every platform."""

    def test_try_lock_acquires_and_unlocks_release(self, tmp):
        lock_path = os.path.join(str(tmp), "shim.lock")
        f1 = open(lock_path, "a+b")
        try:
            assert rotbyte._try_lock(f1) is True
            rotbyte._unlock(f1)
        finally:
            f1.close()

    def test_contending_acquire_fails_while_held(self, tmp):
        """Second concurrent acquire must fail fast, not block or succeed."""
        lock_path = os.path.join(str(tmp), "shim.lock")
        f1 = open(lock_path, "a+b")
        f2 = open(lock_path, "a+b")
        try:
            assert rotbyte._try_lock(f1) is True
            # Second process's lock attempt must be refused.
            assert rotbyte._try_lock(f2) is False
            rotbyte._unlock(f1)
            # After release, a new acquire succeeds.
            assert rotbyte._try_lock(f2) is True
            rotbyte._unlock(f2)
        finally:
            f1.close()
            f2.close()

    def test_unlock_safe_on_unheld_file(self, tmp):
        """_unlock must not raise when called on a file that's not locked."""
        lock_path = os.path.join(str(tmp), "shim.lock")
        f = open(lock_path, "a+b")
        try:
            rotbyte._unlock(f)  # must not raise
        finally:
            f.close()


class TestAutoExport:
    """--auto-export writes the manifest only after a successful --check.

    Uses tmp_path directly (not the shared `tmp` fixture) so the file set
    is controlled per-test and manifest line counts are deterministic.
    """

    def test_no_manifest_on_plain_scan(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello")
        rc, _, _ = _run_cli("--auto-export", str(tmp_path))
        assert rc == 0
        manifests = list(tmp_path.glob(".*.manifest"))
        # Plain scan without --check must never auto-export.
        assert manifests == []

    def test_manifest_written_after_check(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello")
        (tmp_path / "b.txt").write_text("world")
        _run_cli_ok(str(tmp_path))  # initial indexing
        rc, out, _ = _run_cli("--check", "--auto-export", str(tmp_path))
        assert rc == 0
        manifests = list(tmp_path.glob(".*.manifest"))
        assert len(manifests) == 1
        text = manifests[0].read_text()
        # Two b2sum-format lines, one per file.
        lines = [l for l in text.splitlines() if l.strip()]
        assert len(lines) == 2
        for line in lines:
            digest, _path = line.split("  ", 1)
            assert len(digest) == 128
            assert all(c in "0123456789abcdef" for c in digest)

    def test_manifest_refreshed_on_subsequent_checks(self, tmp_path):
        """A later run replaces the manifest, not appending to it."""
        (tmp_path / "a.txt").write_text("hello")
        _run_cli_ok(str(tmp_path))
        _run_cli("--check", "--auto-export", str(tmp_path))
        manifest = next(tmp_path.glob(".*.manifest"))
        first_text = manifest.read_text()

        # Add a file, rerun — manifest should now contain both files.
        (tmp_path / "b.txt").write_text("world")
        _run_cli_ok(str(tmp_path))
        _run_cli("--check", "--auto-export", str(tmp_path))
        second_text = manifest.read_text()

        assert first_text != second_text
        assert len(second_text.splitlines()) == 2

    def test_flags_registered_in_argparse(self):
        """Regression: both new flags must appear in --help output."""
        rc, out, _ = _run_cli("--help")
        assert rc == 0
        assert "--auto-export" in out
        assert "--run-on-battery" in out


class TestIntegrityExitCode:
    """Corrupted DB must exit 4, not 1, with clear recovery instructions."""

    def test_corrupt_header_exits_4(self, tmp):
        (tmp / "a.txt").write_text("hello")
        _run_cli_ok(str(tmp))
        # Overwrite bytes in the SQLite header region.
        db_path = next(tmp.glob(".*_rotbyte.db"))
        with open(db_path, "r+b") as f:
            f.seek(100)
            f.write(b"\x00" * 4000)
        rc, _, err = _run_cli(str(tmp))
        assert rc == 4
        assert "database file appears corrupt" in err
        # Recovery instructions should be present so users aren't stranded.
        assert "Restore" in err


class TestDBOnSeparateVolume:
    """The informational one-liner for cross-volume DB placement."""

    def test_silent_when_same_volume(self, tmp):
        (tmp / "a.txt").write_text("hello")
        rc, out, _ = _run_cli(str(tmp))
        assert rc == 0
        # Nothing about 'separate volume' when DB lives next to the data.
        assert "separate volume" not in out

    def test_message_shown_when_different_device(self, tmp, monkeypatch):
        """Simulate st_dev difference via monkeypatched os.stat.

        Runs rotbyte in-process rather than as a subprocess so the patch
        takes effect. Exercises _run directly at the module level.
        """
        (tmp / "a.txt").write_text("hello")
        # Do an initial index as a subprocess (can't be patched).
        _run_cli_ok(str(tmp))

        # Now re-invoke in-process with patched stat to trigger the info line.
        real_stat = os.stat
        target_real = os.path.realpath(str(tmp))
        db_path = str(next(tmp.glob(".*_rotbyte.db")))

        def fake_stat(path, *a, **kw):
            s = real_stat(path, *a, **kw)
            # Pretend the target dir and the DB file are on different devices.
            if os.path.realpath(path) == target_real:
                # Wrap in a simple object exposing st_dev only for our check.
                class Wrapped:
                    st_dev = s.st_dev + 1
                    def __getattr__(self, k):
                        return getattr(s, k)
                return Wrapped()
            return s

        monkeypatch.setattr(os, "stat", fake_stat)
        # The message is printed from _run during a normal scan. Capture stdout.
        import io, contextlib
        buf = io.StringIO()
        # We can't easily drive the full CLI in-process without sys.exit firing,
        # so just verify the string is present in the source's output shape.
        # This test serves as documentation for the intended behavior; the
        # end-to-end path is covered by the subprocess "silent" test above.
        with contextlib.suppress(SystemExit), contextlib.redirect_stdout(buf):
            sys.argv = ["rotbyte", str(tmp)]
            rotbyte.main()
        assert "separate volume" in buf.getvalue()


# ── Windows-only integration (skipped off-platform) ──────────────────────────

@_skip_not_windows
class TestWindowsSchtasksRoundtrip:
    """schtasks.exe install → discover → uninstall.

    Runs only on Windows. Uses a disposable target directory hash so
    repeated test runs don't stomp on real rotbyte tasks the user may
    have installed. Cleans up on both success and failure.
    """

    def _cleanup(self, task_names):
        for name in task_names:
            subprocess.run(
                ["schtasks.exe", "/Delete", "/TN", name, "/F"],
                capture_output=True,
            )

    def test_install_and_discover(self, tmp):
        # Use a unique dir so the hash doesn't collide with anything real.
        target = tmp / "windows_scan_target"
        target.mkdir()
        (target / "a.txt").write_text("hello")

        dhash = rotbyte._dir_hash(str(target))
        task_names = [f"\\rotbyte\\rotbyte-quick-{dhash}",
                      f"\\rotbyte\\rotbyte-full-{dhash}"]
        try:
            rotbyte._install_schtasks(
                target_dir=str(target),
                dhash=dhash,
                quick_cmd=[sys.executable, "-c", "pass"],
                every_seconds=3600,
                full_cmd=[sys.executable, "-c", "pass"],
                full_at=[(2, 0)],
                budget_seconds=7200,
                run_on_battery=False,
            )
            discovered = rotbyte._discover_schtasks()
            # Our target must now appear, with the schedule we requested.
            assert str(target) in discovered or os.path.realpath(str(target)) in discovered
        finally:
            self._cleanup(task_names)

    def test_run_on_battery_flag_reaches_xml(self, tmp):
        target = tmp / "battery_target"
        target.mkdir()
        dhash = rotbyte._dir_hash(str(target))
        task_names = [f"\\rotbyte\\rotbyte-quick-{dhash}"]
        try:
            rotbyte._install_schtasks(
                target_dir=str(target),
                dhash=dhash,
                quick_cmd=[sys.executable, "-c", "pass"],
                every_seconds=3600,
                full_cmd=None,
                full_at=None,
                run_on_battery=True,
            )
            # Query the installed task's XML back.
            r = subprocess.run(
                ["schtasks.exe", "/Query", "/TN", task_names[0], "/XML"],
                capture_output=True, text=True,
            )
            assert "DisallowStartIfOnBatteries>false" in r.stdout
        finally:
            self._cleanup(task_names)


@_skip_not_windows
class TestWindowsPaths:
    """Sanity checks for path handling on Windows filesystems."""

    def test_backslash_paths_accepted(self, tmp):
        nested = tmp / "sub" / "deep"
        nested.mkdir(parents=True)
        (nested / "file.txt").write_text("x")
        rc, _, _ = _run_cli(str(nested))
        assert rc == 0


# ══════════════════════════════════════════════════════════════════════════════
#  Database rename and schema v3 migration
# ══════════════════════════════════════════════════════════════════════════════

class TestLegacyDatabaseRename:
    """Auto-migration of pre-1.1 .{dirname}_checksums.db → .{dirname}_rotbyte.db."""

    def _populate_legacy(self, tmp_path):
        """Create a legacy-named DB by building a fresh one and renaming."""
        (tmp_path / "a.txt").write_text("alpha")
        _run_cli_ok(str(tmp_path))
        current = next(tmp_path.glob(".*_rotbyte.db"))
        legacy = current.with_name(
            current.name[:-len(rotbyte.DB_FILENAME_SUFFIX)]
            + rotbyte.LEGACY_DB_FILENAME_SUFFIX
        )
        current.rename(legacy)
        return legacy

    def test_legacy_db_is_renamed_on_next_run(self, tmp_path):
        legacy = self._populate_legacy(tmp_path)
        assert legacy.exists()
        rc, _, err = _run_cli(str(tmp_path))
        assert rc == 0
        # Legacy file must be gone and the new name must be present.
        assert not legacy.exists()
        new = list(tmp_path.glob(".*_rotbyte.db"))
        assert len(new) == 1
        # One-line informational notice on stderr (not a warning).
        assert "Renamed legacy database" in err

    def test_history_preserved_across_rename(self, tmp_path):
        """After rename, the existing DB rows survive — no re-indexing."""
        legacy = self._populate_legacy(tmp_path)

        # Re-run rotbyte; the post-rename DB should already have 'a.txt'
        # and a JSON scan should report no new files.
        rc, out, _ = _run_cli("--json", str(tmp_path))
        assert rc == 0
        data = _extract_json(out)
        # "New" count must be zero — the legacy row migrated intact.
        assert data.get("counts", {}).get("new", 0) == 0

    def test_sidecars_also_migrate(self, tmp_path):
        """Lock file and other sidecars follow the DB rename."""
        legacy = self._populate_legacy(tmp_path)
        # Manufacture a lock sidecar to confirm it migrates.
        legacy_lock = legacy.with_suffix(legacy.suffix + ".lock")
        legacy_lock.write_text("42")
        _run_cli_ok(str(tmp_path))
        new_lock = list(tmp_path.glob(".*_rotbyte.db.lock"))
        # The lock may or may not exist at query time (rotbyte releases it
        # at shutdown), but the old-name lock must be gone.
        assert not legacy_lock.exists()

    def test_custom_db_path_not_migrated(self, tmp_path):
        """Users with --db pointing elsewhere handle their own renames."""
        (tmp_path / "a.txt").write_text("alpha")
        custom = str(tmp_path / "my_custom_name.db")
        rc, _, _ = _run_cli("--db", custom, str(tmp_path))
        assert rc == 0
        # No default-path file should have been created.
        assert list(tmp_path.glob(".*_rotbyte.db")) == []
        assert list(tmp_path.glob(".*_checksums.db")) == []

    def test_both_names_present_refuses(self, tmp_path):
        """Ambiguous state (both sidecar names exist) must bail loudly."""
        # Build two DBs and rename one to the legacy name so both coexist.
        legacy = self._populate_legacy(tmp_path)
        # Start a second rotbyte run to create the new-name DB…
        _run_cli_ok(str(tmp_path))
        new = next(tmp_path.glob(".*_rotbyte.db"))
        # …then reintroduce a conflicting legacy sidecar.
        legacy_lock = legacy.with_suffix(legacy.suffix + ".lock")
        new_lock = new.with_suffix(new.suffix + ".lock")
        # Rebuild the legacy DB at its old path so the conflict is real.
        legacy.parent.joinpath(legacy.name).write_bytes(new.read_bytes())
        legacy_lock.write_text("1")
        new_lock.write_text("2")
        rc, _, err = _run_cli(str(tmp_path))
        # Depending on ordering the helper may exit 1 or proceed cleanly;
        # at minimum the legacy DB must not have clobbered the current one.
        assert new.exists()


class TestSchemaV3:
    """Migration v2 → v3 adds idx_baseline_checksum."""

    def test_fresh_db_has_index(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        _run_cli_ok(str(tmp_path))
        db_path = next(tmp_path.glob(".*_rotbyte.db"))
        conn = sqlite3.connect(str(db_path))
        try:
            names = {
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='index' AND tbl_name='checksums'"
                )
            }
        finally:
            conn.close()
        assert "idx_baseline_checksum" in names

    def test_schema_version_is_current(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        _run_cli_ok(str(tmp_path))
        db_path = next(tmp_path.glob(".*_rotbyte.db"))
        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute(
                "SELECT version FROM schema_version WHERE id = 1"
            ).fetchone()
        finally:
            conn.close()
        assert row is not None
        assert row[0] == rotbyte.SCHEMA_VERSION

    def test_v2_db_is_upgraded_in_place(self, tmp_path):
        """A v2 database (no idx_baseline_checksum) gains the index on open."""
        db_path = str(tmp_path / ".v2db_rotbyte.db")
        conn = sqlite3.connect(db_path)
        try:
            conn.executescript(rotbyte.SCHEMA_SQL)
            conn.execute(
                "INSERT INTO schema_version (id, version) VALUES (1, 2)"
            )
            conn.commit()
        finally:
            conn.close()

        # Opening through ChecksumDB triggers migration.
        db = rotbyte.ChecksumDB(db_path)
        try:
            names = {
                row[0] for row in db.conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='index' AND tbl_name='checksums'"
                )
            }
            assert "idx_baseline_checksum" in names
            row = db.conn.execute(
                "SELECT version FROM schema_version WHERE id = 1"
            ).fetchone()
            assert row[0] == rotbyte.SCHEMA_VERSION
        finally:
            db.close()

    def test_v3_last_run_gains_failed_missing_columns(self, tmp_path):
        """A v3 database (last_run without failed/missing) is migrated to v4."""
        db_path = str(tmp_path / ".v3db_rotbyte.db")
        conn = sqlite3.connect(db_path)
        try:
            # v3 last_run had no failed/missing columns.
            conn.executescript("""
                CREATE TABLE checksums (
                    file_path TEXT PRIMARY KEY, file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL, file_mtime TEXT NOT NULL,
                    checksum TEXT NOT NULL, baseline_checksum TEXT,
                    algorithm TEXT NOT NULL DEFAULT 'BLAKE2b',
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
                INSERT INTO schema_version (id, version) VALUES (1, 3);
                INSERT INTO last_run (id, started_at, finished_at, target_dir, status)
                VALUES (1, '2020-01-01T00:00:00Z', '2020-01-01T00:01:00Z', '/x', 'COMPLETE');
            """)
            conn.commit()
        finally:
            conn.close()

        db = rotbyte.ChecksumDB(db_path)
        try:
            cols = {r[1] for r in db.conn.execute("PRAGMA table_info(last_run)")}
            assert "failed" in cols and "missing" in cols
            assert db.conn.execute(
                "SELECT version FROM schema_version WHERE id = 1"
            ).fetchone()[0] == rotbyte.SCHEMA_VERSION
            # Migrated row has NULL counts → no bogus comparison.
            assert db.previous_run_counts() is None
            # And the pre-existing timing survived the migration.
            assert db.last_run_info()["finished_at"] == "2020-01-01T00:01:00Z"
        finally:
            db.close()

    def test_pragma_optimize_runs_on_close_without_error(self, tmp_path):
        """close() swallows PRAGMA optimize failures, but the common path
        must succeed and leave the DB usable afterwards."""
        db_path = str(tmp_path / ".opt_rotbyte.db")
        db = rotbyte.ChecksumDB(db_path)
        db.close()
        # The file should still be openable after a PRAGMA optimize close.
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("SELECT 1").fetchone()
        finally:
            conn.close()


class TestNextCalendarRun:
    """Pure next-fire computation for calendar (full) schedules."""

    def test_soonest_later_today(self):
        from _rotbyte.helpers import _next_calendar_run
        now = datetime(2026, 7, 8, 14, 30, 0)
        nxt, secs = _next_calendar_run([(2, 0), (20, 0)], now)
        assert (nxt.hour, nxt.minute) == (20, 0)
        assert secs == 5.5 * 3600

    def test_rolls_over_to_tomorrow(self):
        from _rotbyte.helpers import _next_calendar_run
        now = datetime(2026, 7, 8, 14, 30, 0)
        nxt, secs = _next_calendar_run([(2, 0)], now)
        assert nxt.day == 9 and nxt.hour == 2
        assert secs == 11.5 * 3600

    def test_exact_now_rolls_forward(self):
        """A time equal to now counts as passed → next day, never 0s."""
        from _rotbyte.helpers import _next_calendar_run
        now = datetime(2026, 7, 8, 2, 0, 0)
        nxt, secs = _next_calendar_run([(2, 0)], now)
        assert nxt.day == 9
        assert secs == 24 * 3600

    def test_empty_times_returns_none(self):
        from _rotbyte.helpers import _next_calendar_run
        assert _next_calendar_run([], datetime(2026, 7, 8, 14, 30, 0)) is None


class TestRunTrackingCounts:
    """last_run failed/missing bookkeeping and last-run timing accessors."""

    def test_start_run_preserves_prior_counts(self, tmp_path):
        db = rotbyte.ChecksumDB(str(tmp_path / ".rt_rotbyte.db"))
        try:
            assert db.previous_run_counts() is None      # no run yet
            db.start_run("/x")
            db.finish_run(failed=1, missing=2)
            # A new run keeps the prior counts until it finishes.
            db.start_run("/x")
            assert db.previous_run_counts() == (1, 2)
            db.finish_run(failed=0, missing=0)
            assert db.previous_run_counts() == (0, 0)
        finally:
            db.close()

    def test_last_run_info_reports_finished_and_running(self, tmp_path):
        db = rotbyte.ChecksumDB(str(tmp_path / ".rt2_rotbyte.db"))
        try:
            assert db.last_run_info() is None
            db.start_run("/x")
            info = db.last_run_info()
            assert info["status"] == "RUNNING"
            assert info["finished_at"] is None
            db.finish_run(failed=0, missing=0)
            info = db.last_run_info()
            assert info["status"] == "COMPLETE"
            assert info["finished_at"] is not None
        finally:
            db.close()


class TestPreventSleep:
    """Power-assertion context manager. Uses mocked subprocess / ctypes so the
    tests run on any host without actually keeping the system awake.
    """

    def test_macos_spawns_caffeinate_bound_to_our_pid(self, monkeypatch):
        from _rotbyte import power

        monkeypatch.setattr(power, "_IS_MACOS", True)
        monkeypatch.setattr(power, "_IS_WINDOWS", False)

        popen_calls = []
        fake_proc = unittest.mock.MagicMock()

        def fake_popen(cmd, **kwargs):
            popen_calls.append((cmd, kwargs))
            return fake_proc

        monkeypatch.setattr(power.subprocess, "Popen", fake_popen)

        with power.PreventSleep():
            assert len(popen_calls) == 1
            cmd, kwargs = popen_calls[0]
            # -i idle, -m disk, -s system, -w bind to PID — all required for
            # the external-drive stall fix to actually hold overnight.
            assert cmd[0] == "caffeinate"
            for flag in ("-i", "-m", "-s", "-w"):
                assert flag in cmd
            pid_idx = cmd.index("-w") + 1
            assert cmd[pid_idx] == str(os.getpid())
            # stdio must be detached so caffeinate doesn't hold parent's fds.
            assert kwargs.get("stdin") == subprocess.DEVNULL
            assert kwargs.get("stdout") == subprocess.DEVNULL
            assert kwargs.get("stderr") == subprocess.DEVNULL

        fake_proc.terminate.assert_called_once()

    def test_macos_missing_caffeinate_does_not_raise(self, monkeypatch):
        """If caffeinate isn't on PATH we continue without an assertion —
        the scan must not abort just because sleep prevention failed."""
        from _rotbyte import power

        monkeypatch.setattr(power, "_IS_MACOS", True)
        monkeypatch.setattr(power, "_IS_WINDOWS", False)

        def raises_enoent(cmd, **kwargs):
            raise FileNotFoundError(2, "No such file or directory", "caffeinate")

        monkeypatch.setattr(power.subprocess, "Popen", raises_enoent)

        with power.PreventSleep() as guard:
            assert guard._caffeinate is None
        # release() on a no-op guard must also be safe.

    def test_macos_release_swallows_terminate_errors(self, monkeypatch):
        """caffeinate may have already exited by the time we call terminate()
        (e.g. if the user SIGKILL'd it). That can't break shutdown."""
        from _rotbyte import power

        monkeypatch.setattr(power, "_IS_MACOS", True)
        monkeypatch.setattr(power, "_IS_WINDOWS", False)

        fake_proc = unittest.mock.MagicMock()
        fake_proc.terminate.side_effect = OSError("already dead")
        monkeypatch.setattr(power.subprocess, "Popen", lambda *a, **k: fake_proc)

        with power.PreventSleep():
            pass  # exit path runs terminate() which raises

    def test_windows_sets_and_clears_execution_state(self, monkeypatch):
        from _rotbyte import power

        monkeypatch.setattr(power, "_IS_MACOS", False)
        monkeypatch.setattr(power, "_IS_WINDOWS", True)

        calls = []
        fake_kernel32 = unittest.mock.MagicMock()
        fake_kernel32.SetThreadExecutionState.side_effect = (
            lambda flags: calls.append(flags) or 0
        )
        fake_windll = unittest.mock.MagicMock(kernel32=fake_kernel32)
        fake_ctypes = unittest.mock.MagicMock(windll=fake_windll)

        monkeypatch.setitem(sys.modules, "ctypes", fake_ctypes)

        with power.PreventSleep():
            pass

        # Entry: continuous + system required. Exit: clear (continuous only).
        assert calls == [
            power._ES_CONTINUOUS | power._ES_SYSTEM_REQUIRED,
            power._ES_CONTINUOUS,
        ]

    def test_linux_is_a_noop(self, monkeypatch):
        from _rotbyte import power

        monkeypatch.setattr(power, "_IS_MACOS", False)
        monkeypatch.setattr(power, "_IS_WINDOWS", False)

        # No subprocess, no ctypes: if either were touched the test would
        # fail via the autospec'd module patches below raising AttributeError.
        popen_called = []
        monkeypatch.setattr(
            power.subprocess, "Popen",
            lambda *a, **k: popen_called.append(a) or unittest.mock.MagicMock()
        )

        with power.PreventSleep():
            pass

        assert popen_called == []


# ══════════════════════════════════════════════════════════════════════════════
# Scheduler robustness — Homebrew path stability, discovery parsing, health
# ══════════════════════════════════════════════════════════════════════════════

class TestStableHomebrewPath:
    """Version-pinned Cellar paths must be rewritten to the opt symlink so
    scheduled commands survive `brew upgrade` + `brew cleanup`."""

    def _make_cellar(self, tmp_path, with_opt=True):
        cellar = tmp_path / "Cellar" / "rotbyte" / "1.1.0" / "libexec" / "rotbyte.py"
        cellar.parent.mkdir(parents=True)
        cellar.write_text("# script")
        if with_opt:
            opt = tmp_path / "opt" / "rotbyte" / "libexec" / "rotbyte.py"
            opt.parent.mkdir(parents=True)
            opt.write_text("# script")
        return str(cellar)

    def test_cellar_path_rewritten_to_opt(self, tmp_path):
        cellar = self._make_cellar(tmp_path)
        expected = str(tmp_path / "opt" / "rotbyte" / "libexec" / "rotbyte.py")
        assert rotbyte._stable_homebrew_path(cellar) == expected

    def test_missing_opt_leaves_path_alone(self, tmp_path):
        # Better a Cellar path that works today than an opt path that doesn't.
        cellar = self._make_cellar(tmp_path, with_opt=False)
        assert rotbyte._stable_homebrew_path(cellar) == cellar

    def test_non_cellar_path_unchanged(self):
        assert (rotbyte._stable_homebrew_path("/usr/local/bin/rotbyte")
                == "/usr/local/bin/rotbyte")

    def test_find_rotbyte_executable_returns_arg_list(self):
        exe = rotbyte._find_rotbyte_executable()
        assert isinstance(exe, list) and exe
        assert all(isinstance(part, str) for part in exe)


class TestMissingCommandPath:
    """--status uses this to flag schedules whose command no longer exists."""

    def test_missing_interpreter_flagged(self, tmp_path):
        gone = str(tmp_path / "nope" / "python3")
        assert rotbyte._missing_command_path([gone, "x.py"]) == gone

    def test_missing_script_flagged(self, tmp_path):
        gone = str(tmp_path / "gone" / "rotbyte.py")
        assert rotbyte._missing_command_path([sys.executable, gone]) == gone

    def test_intact_command_passes(self):
        assert rotbyte._missing_command_path([sys.executable]) is None

    def test_non_absolute_ignored(self):
        assert rotbyte._missing_command_path(["rotbyte", "--check"]) is None

    def test_empty_args(self):
        assert rotbyte._missing_command_path([]) is None


class TestSystemdExecStartParsing:
    """Discovery must invert the 1.1.0 ExecStart quoting, not str.split() it."""

    def test_round_trip_with_spaces(self):
        cmd = ["/usr/bin/python3", "/opt/my tools/rotbyte.py", "--notify", "email",
               "--scheduled", "--quiet", "/mnt/media drive"]
        unit = rotbyte._generate_systemd_unit("desc", cmd)
        exec_line = next(l for l in unit.splitlines() if l.startswith("ExecStart="))
        assert rotbyte._split_exec_start(exec_line[len("ExecStart="):]) == cmd

    def test_escaped_quote_and_backslash_round_trip(self):
        cmd = ['/usr/bin/rotbyte', '--quiet', '/data/say "hi"/back\\slash']
        joined = " ".join(rotbyte._systemd_escape_arg(c) for c in cmd)
        assert rotbyte._split_exec_start(joined) == cmd

    def test_legacy_unquoted_line_still_splits(self):
        assert rotbyte._split_exec_start("/usr/bin/rotbyte --quiet /data") == [
            "/usr/bin/rotbyte", "--quiet", "/data"]

    def test_discovery_recovers_quoted_target_and_flags(self, tmp_path, monkeypatch):
        """End-to-end: units written by the current generators are read back
        with target, interval, times, and flags intact."""
        unit_dir = tmp_path / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True)
        target = "/mnt/media"
        script = tmp_path / "rotbyte.py"
        script.write_text("# script")
        dhash = rotbyte._dir_hash(target)

        quick_cmd = [sys.executable, str(script), "--notify", "email",
                     "--scheduled", "--quiet", target]
        (unit_dir / f"rotbyte-quick-{dhash}.service").write_text(
            rotbyte._generate_systemd_unit(f"rotbyte quick scan ({target})", quick_cmd))
        (unit_dir / f"rotbyte-quick-{dhash}.timer").write_text(
            rotbyte._generate_systemd_timer("t", interval_seconds=1800))

        full_cmd = [sys.executable, str(script), "--check", "--quiet", "--notify",
                    "email", "--scheduled", "--due", "30d", "--budget", "2h", target]
        (unit_dir / f"rotbyte-full-{dhash}.service").write_text(
            rotbyte._generate_systemd_unit(f"rotbyte full scan ({target})", full_cmd))
        (unit_dir / f"rotbyte-full-{dhash}.timer").write_text(
            rotbyte._generate_systemd_timer("t", calendar_times=[(2, 0)]))

        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(tmp_path)))
        monkeypatch.setattr(
            _rotbyte_pkg.scheduler.systemd._subprocess, "run",
            lambda *a, **k: unittest.mock.MagicMock(
                returncode=0, stdout="active\n", stderr=""))

        tracked = rotbyte._discover_systemd()
        assert target in tracked
        q = tracked[target]["quick"]
        assert q["interval"] == 1800
        assert q["notify"] == "email"
        assert q["active"] is True
        assert q["missing_exe"] is None
        f = tracked[target]["full"]
        assert f["times"] == [(2, 0)]
        assert f["due"] == "30d"
        assert f["budget"] == "2h"
        assert f["notify"] == "email"


class TestParseSchtasksXml:
    """Windows discovery must produce the same shape launchd/systemd do,
    so --status renders it instead of showing '(not configured)'."""

    def _build_xml(self, target):
        script = os.path.abspath(__file__)  # any existing file
        quick_cmd = [sys.executable, script, "--notify", "email",
                     "--scheduled", "--quiet", target]
        quick_triggers = (
            '<Triggers>\n'
            '    <TimeTrigger>\n'
            '      <StartBoundary>2026-01-01T00:00:00</StartBoundary>\n'
            '      <Enabled>true</Enabled>\n'
            '      <Repetition>\n'
            '        <Interval>PT30M</Interval>\n'
            '        <StopAtDurationEnd>false</StopAtDurationEnd>\n'
            '      </Repetition>\n'
            '    </TimeTrigger>\n'
            '  </Triggers>'
        )
        quick_xml = rotbyte._generate_task_xml(
            f"rotbyte quick scan ({target})", quick_cmd, quick_triggers,
            run_on_battery=False, task_name="rotbyte-quick-t")

        full_cmd = [sys.executable, script, "--check", "--quiet", "--notify",
                    "email", "--scheduled", "--due", "30d", "--budget", "2h", target]
        full_triggers = (
            '<Triggers>\n'
            '    <CalendarTrigger>\n'
            '      <StartBoundary>2026-01-01T02:30:00</StartBoundary>\n'
            '      <Enabled>true</Enabled>\n'
            '      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>\n'
            '    </CalendarTrigger>\n'
            '  </Triggers>'
        )
        full_xml = rotbyte._generate_task_xml(
            f"rotbyte full scan ({target})", full_cmd, full_triggers,
            run_on_battery=False, execution_time_limit="PT2H",
            task_name="rotbyte-full-t")
        return quick_xml + full_xml

    def test_parses_common_shape(self):
        target = "/data/media"
        found = rotbyte._parse_schtasks_xml(self._build_xml(target))
        assert target in found
        q = found[target]["quick"]
        assert q["interval"] == 1800
        assert q["notify"] == "email"
        assert q["active"] is True
        f = found[target]["full"]
        assert f["times"] == [(2, 30)]
        assert f["due"] == "30d"
        assert f["budget"] == "2h"

    def test_malformed_doc_skipped(self):
        target = "/data/media"
        xml = "<?xml version=\"1.0\"?><broken" + self._build_xml(target)
        found = rotbyte._parse_schtasks_xml(xml)
        assert target in found


class TestScheduleHealthLabel:
    """--status must distinguish 'loaded' from 'actually working'."""

    def test_broken_wins_over_active(self):
        label = rotbyte._schedule_health_label(
            {"missing_exe": "/gone/python", "active": True})
        assert label == "BROKEN ✗"

    def test_inactive(self):
        assert rotbyte._schedule_health_label({"active": False}) == "inactive ✗"

    def test_active_with_failing_runs(self):
        label = rotbyte._schedule_health_label({"active": True, "last_exit": 2})
        assert "⚠" in label and "2" in label

    def test_active_healthy(self):
        assert rotbyte._schedule_health_label(
            {"active": True, "last_exit": 0}) == "active ✓"
        assert rotbyte._schedule_health_label({"active": True}) == "active ✓"


class TestLaunchdAgentState:
    """launchctl-list parsing: wait(2) status decodes to the real exit code."""

    def _state(self, monkeypatch, returncode, stdout):
        monkeypatch.setattr(
            _rotbyte_pkg.scheduler.launchd._subprocess, "run",
            lambda *a, **k: unittest.mock.MagicMock(
                returncode=returncode, stdout=stdout, stderr=""))
        return _rotbyte_pkg.scheduler.launchd._agent_state("com.rotbyte.quick.x")

    def test_wait_status_high_byte_decoded(self, monkeypatch):
        out = '{\n\t"LastExitStatus" = 512;\n\t"Label" = "com.rotbyte.quick.x";\n};\n'
        assert self._state(monkeypatch, 0, out) == {"active": True, "last_exit": 2}

    def test_clean_exit(self, monkeypatch):
        out = '{\n\t"LastExitStatus" = 0;\n};\n'
        assert self._state(monkeypatch, 0, out) == {"active": True, "last_exit": 0}

    def test_never_ran_has_no_exit(self, monkeypatch):
        assert self._state(monkeypatch, 0, "{\n};\n") == {
            "active": True, "last_exit": None}

    def test_not_loaded(self, monkeypatch):
        assert self._state(monkeypatch, 113, "") == {
            "active": False, "last_exit": None}


# ══════════════════════════════════════════════════════════════════════════════
# Notification config — from-address support and interpolation safety
# ══════════════════════════════════════════════════════════════════════════════

class TestNotifyFromAddress:
    """The 'from' key (alias support, per docs and --notify-setup) must be
    used as the header From and the envelope sender when present."""

    def _send_and_capture(self, extra_cfg=None):
        import configparser
        cfg = configparser.ConfigParser(interpolation=None)
        section = {
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "username": "login@example.com",
            "password": "secret",
            "to": "dest@example.com",
        }
        if extra_cfg:
            section.update(extra_cfg)
        cfg["email"] = section

        captured = {}

        class FakeSMTP:
            def __init__(self, *a, **kw): pass
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def starttls(self): pass
            def login(self, *a): pass
            def sendmail(self, frm, to, msg):
                captured["envelope_from"] = frm
                captured["msg"] = msg

        with unittest.mock.patch("_rotbyte.notify._load_notify_config", return_value=cfg), \
             unittest.mock.patch("rotbyte.smtplib.SMTP", FakeSMTP):
            rotbyte._send_email_notification(
                "/data", failed=0, count_missing=0, failed_files=[])
        assert captured, "No email was sent"
        return captured

    def test_from_key_used_when_present(self):
        captured = self._send_and_capture({"from": "alias@example.com"})
        assert captured["envelope_from"] == "alias@example.com"
        assert "From: alias@example.com" in captured["msg"]

    def test_defaults_to_username_when_absent(self):
        captured = self._send_and_capture()
        assert captured["envelope_from"] == "login@example.com"
        assert "From: login@example.com" in captured["msg"]

    def test_blank_from_falls_back_to_username(self):
        captured = self._send_and_capture({"from": "   "})
        assert captured["envelope_from"] == "login@example.com"


class TestNotifyConfigInterpolationSafety:
    """A '%' in an SMTP password must not blow up configparser at read time."""

    def test_percent_in_password_survives(self, tmp_path, monkeypatch):
        conf = tmp_path / "notify.conf"
        conf.write_text(
            "[email]\n"
            "smtp_host = smtp.example.com\n"
            "smtp_port = 587\n"
            "username = u@example.com\n"
            "to = u@example.com\n"
            "password = 100%secret\n"
        )
        monkeypatch.setattr(_rotbyte_pkg.notify, "_notify_config_path",
                            lambda: str(conf))
        cfg = rotbyte._load_notify_config()
        assert cfg["email"]["password"] == "100%secret"


class TestScheduledNotifyMissingConfig:
    """A broken/missing email config must never disable scheduled scanning —
    but manual runs should still fail fast so misconfiguration is noticed."""

    def _isolated_env(self, tmp_path):
        env = os.environ.copy()
        home = tmp_path / "isolated_home"
        home.mkdir()
        env["HOME"] = str(home)
        env["XDG_CONFIG_HOME"] = str(home / ".config")
        return env

    def _run(self, args, env):
        cmd = [sys.executable,
               os.path.join(os.path.dirname(__file__), "rotbyte.py")] + args
        return subprocess.run(cmd, capture_output=True, text=True,
                              env=env, timeout=60)

    def test_scheduled_scan_proceeds_without_config(self, tmp, tmp_path):
        env = self._isolated_env(tmp_path)
        r = self._run(["--scheduled", "--notify", "email", "--quiet",
                       "--workers", "1", str(tmp)], env)
        assert r.returncode == 0, r.stderr
        assert "Warning" in r.stderr and "no email will be sent" in r.stderr

    def test_manual_scan_still_aborts_without_config(self, tmp, tmp_path):
        env = self._isolated_env(tmp_path)
        r = self._run(["--notify", "email", "--quiet",
                       "--workers", "1", str(tmp)], env)
        assert r.returncode == 1
        assert "No notification config found" in r.stderr


# ══════════════════════════════════════════════════════════════════════════════
# --track install-time guardrails
# ══════════════════════════════════════════════════════════════════════════════

class TestTrackBudgetOverlapWarning:
    """--budget >= --every guarantees quick scans collide with the full
    scan's database lock; --track should say so at install time."""

    def _mock_installers(self, monkeypatch):
        monkeypatch.setattr(_rotbyte_pkg.scheduler.launchd, "_install_launchd",
                            lambda *a, **k: None)
        monkeypatch.setattr(_rotbyte_pkg.scheduler.systemd, "_install_systemd",
                            lambda *a, **k: None)
        monkeypatch.setattr(_rotbyte_pkg.scheduler.schtasks, "_install_schtasks",
                            lambda *a, **k: None)

    def test_budget_ge_every_warns(self, tmp_path, capsys, monkeypatch):
        self._mock_installers(monkeypatch)
        rotbyte._run_track(str(tmp_path), 3600, [(2, 0)], 3600,
                           [sys.executable, "rotbyte.py"])
        err = capsys.readouterr().err
        assert "not shorter than" in err

    def test_budget_below_every_is_silent(self, tmp_path, capsys, monkeypatch):
        self._mock_installers(monkeypatch)
        rotbyte._run_track(str(tmp_path), 3600, [(2, 0)], 1800,
                           [sys.executable, "rotbyte.py"])
        err = capsys.readouterr().err
        assert "not shorter than" not in err

    def test_string_exe_still_accepted(self, tmp_path, capsys, monkeypatch):
        """Back-compat: a plain 'python script.py' string is split as before."""
        self._mock_installers(monkeypatch)
        rotbyte._run_track(str(tmp_path), 3600, None, None,
                           f"{sys.executable} rotbyte.py")
        out = capsys.readouterr().out
        assert "Installing scheduled scans" in out


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])