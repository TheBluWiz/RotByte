"""File hashing pipeline.

:func:`hash_file` runs in a worker process and does the actual I/O;
:func:`run_hashing` drives a :class:`ProcessPoolExecutor` over a prescan
list and writes results to the database in batched transactions.
:func:`detect_missing` reconciles the on-disk file set with the database
after the hash phase completes.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

from .database import ChecksumDB
from .helpers import _format_duration, _mtime_iso, _resolve
from .progress import ProgressBar

HASH_BUFFER_SIZE = 1024 * 1024  # 1 MiB — balances syscall overhead vs memory
BATCH_SIZE = 200                # DB writes per transaction before committing


def hash_file(file_path: str) -> Tuple[str, Optional[str], Optional[int], Optional[str], Optional[str]]:
    """Compute BLAKE2b-512 hash of a file.

    Returns ``(path, hex_digest, size, mtime_iso, error)``. On success the
    error slot is None and the others are populated. On read failure the
    digest/size/mtime are None and ``error`` carries the OSError message
    so the parent process can aggregate per-file failures rather than
    spamming stderr from inside each worker.

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
        return file_path, h.hexdigest(), st.st_size, _mtime_iso(st), None
    except OSError as e:
        return file_path, None, None, None, str(e)


# ── Filesystem scanning ───────────────────────────────────────────────────────

def scan_files(target_dir: str, db_path: str, include_hidden: bool = False,
               exclude_dirs: Optional[Set[str]] = None,
               case_insensitive: bool = False) -> List[str]:
    """Walk the directory tree and return a sorted list of file paths.

    Skips by default:
      - Hidden files and directories (names starting with '.'; on
        Windows, also entries with the FILE_ATTRIBUTE_HIDDEN bit set)
      - .b2sum and .b2 hash files (handled separately by --import)
      - The database file and its SQLite companion files (-wal, -shm, .lock)
      - Any directories in exclude_dirs

    If ``case_insensitive`` is true (on macOS APFS / NTFS users who pass
    ``--case-insensitive``), file paths are normalised to lowercase so a
    rename-by-case doesn't produce phantom MISSINGs.

    Does not follow symlinks to prevent infinite loops. On OSError during
    walk (e.g. a network drive that vanished mid-scan), emits a warning
    and returns what was collected so far rather than aborting the scan.
    """
    skip_files = {
        _resolve(db_path),
        _resolve(db_path + ".lock"),
        _resolve(db_path + "-wal"),
        _resolve(db_path + "-shm"),
    }
    exclude = exclude_dirs or set()
    files = []

    def _walk_err(exc: OSError) -> None:
        # A typical cause is a network drive disappearing mid-scan. Warn
        # the user and keep going with what we have.
        print(f"\n  ! Walk error at {getattr(exc, 'filename', '?')}: {exc}",
              file=sys.stderr)

    for root, dirs, filenames in os.walk(target_dir, followlinks=False,
                                         onerror=_walk_err):
        if not include_hidden:
            dirs[:] = [d for d in dirs
                       if not d.startswith(".")
                       and not _is_windows_hidden(os.path.join(root, d))]
        dirs[:] = [d for d in dirs if _resolve(os.path.join(root, d)) not in exclude]

        for name in filenames:
            if not include_hidden:
                if name.startswith("."):
                    continue
                full = os.path.join(root, name)
                if _is_windows_hidden(full):
                    continue
            if name.endswith(".b2sum") or name.endswith(".b2"):
                continue
            full = os.path.join(root, name)
            if _resolve(full) in skip_files:
                continue
            files.append(full.lower() if case_insensitive else full)
    files.sort()
    return files


def _is_windows_hidden(path: str) -> bool:
    """Return True when ``path`` has the Windows HIDDEN attribute set.

    No-op on POSIX. Windows users running without ``--include-hidden``
    expect hidden files to be skipped even when they don't have a dot
    prefix — the POSIX "dotfile" convention doesn't apply there.
    """
    if sys.platform != "win32":
        return False
    try:
        import stat
        attrs = os.stat(path, follow_symlinks=False).st_file_attributes  # type: ignore[attr-defined]
        return bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
    except (OSError, AttributeError):
        return False


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
    __slots__ = ("new", "ok", "updated", "failed", "errors", "bytes_hashed",
                 "budget_exceeded")

    def __init__(self):
        self.new = 0
        self.ok = 0
        self.updated = 0
        self.failed = 0
        self.errors = 0
        self.bytes_hashed = 0
        self.budget_exceeded = False


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

    If budget_seconds is set, the elapsed time is checked after every
    completed file. When the budget is exceeded the current batch's
    already-completed results are committed and no further batches are
    started.
    """
    result = HashResult()
    total = len(entries)
    if total == 0:
        return result

    processed = 0
    entry_map = {e.path: e for e in entries}
    bar = ProgressBar(total, quiet=quiet)
    budget_start = time.monotonic()
    budget_exceeded = False

    # Aggregate per-file read errors so a permission-denied subtree
    # doesn't spew thousands of lines to stderr. We print the first
    # ERROR_PRINT_LIMIT inline and a summary line for the rest at the
    # end of the phase. Files that vanished between prescan and hash
    # (FileNotFoundError) are routed to MISSING instead of "errors"
    # because that's what they actually are.
    ERROR_PRINT_LIMIT = 10
    deferred_missing: List[str] = []
    error_messages: List[str] = []

    with ProcessPoolExecutor(max_workers=workers) as executor:
        for batch_start in range(0, total, BATCH_SIZE):
            if interrupted[0] or budget_exceeded:
                break

            batch = entries[batch_start : batch_start + BATCH_SIZE]
            futures = {executor.submit(hash_file, e.path): e.path for e in batch}

            with db.transaction():
                for future in as_completed(futures):
                    if interrupted[0]:
                        break

                    # Check time budget after each completed file
                    if budget_seconds is not None and not budget_exceeded:
                        elapsed = time.monotonic() - budget_start
                        if elapsed >= budget_seconds:
                            budget_exceeded = True
                            result.budget_exceeded = True
                            remaining = total - processed
                            if not quiet:
                                print(f"\n  Time budget reached ({_format_duration(elapsed)})."
                                      f" Stopping with {remaining:,} files remaining.")
                            break

                    # Catch worker crashes (OOM, segfault, BrokenExecutor
                    # when the pool dies) so one bad file doesn't abort
                    # the entire run. BrokenExecutor is a subclass of
                    # Exception, so this catches both — left untyped to
                    # signal the intent to catch anything the worker
                    # subprocess layer can raise.
                    try:
                        fpath, digest, hash_size, hash_mtime, hash_err = future.result()
                    except Exception as e:  # noqa: BLE001
                        fpath = futures[future]
                        # Worker crashes are rare and indicate something
                        # serious (OOM, segfault). Print these inline.
                        print(f"\n  ! Worker error for {fpath}: {e}", file=sys.stderr)
                        result.errors += 1
                        processed += 1
                        bar.update(0)
                        continue

                    processed += 1

                    if digest is None:
                        # The worker couldn't read the file. Distinguish a
                        # file that vanished between prescan and hash (route
                        # to MISSING — that's the truth) from a real read
                        # error (permission, I/O failure). Best-effort lstat:
                        # if it raises, the file is gone.
                        try:
                            os.lstat(fpath)
                            existed = True
                        except OSError:
                            existed = False
                        if not existed:
                            deferred_missing.append(fpath)
                        else:
                            result.errors += 1
                            error_messages.append(
                                f"  ! Error reading {fpath}: {hash_err}"
                                if hash_err else
                                f"  ! Error reading {fpath}"
                            )
                            if len(error_messages) <= ERROR_PRINT_LIMIT:
                                print(f"\n{error_messages[-1]}", file=sys.stderr)
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

    bar.finish()

    # Mark files that vanished mid-scan as MISSING in their own
    # transaction. They were *known* files in the database (otherwise
    # they wouldn't have been queued for hashing) so this is the same
    # "previously tracked, no longer on disk" semantic that
    # detect_missing() handles for the prescan-discovered case.
    if deferred_missing:
        with db.transaction():
            for mpath in deferred_missing:
                # Brand-new files (no row yet) just disappear silently —
                # there's nothing to mark MISSING.
                if mpath in entry_map and entry_map[mpath].old_checksum is not None:
                    db.mark_missing(mpath, now)

    extra_errors = len(error_messages) - ERROR_PRINT_LIMIT
    if extra_errors > 0:
        print(f"\n  ... and {extra_errors:,} more read errors suppressed.",
              file=sys.stderr)

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
        with db.transaction():
            for mpath in sorted(newly_missing):
                db.mark_missing(mpath, now)

    all_missing = newly_missing | already_missing
    for mpath in sorted(all_missing):
        print(f"  ? MISSING: {mpath}")

    return len(all_missing)
