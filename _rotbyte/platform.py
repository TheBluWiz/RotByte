"""Platform constants and cross-platform advisory file locking.

Kept in its own module so the rest of the package never has to guess
whether we're on Windows or POSIX — import ``_IS_WINDOWS`` and friends
from here.
"""

from __future__ import annotations

import os
import sys

_IS_WINDOWS = sys.platform == "win32"
_IS_MACOS = sys.platform == "darwin"
_IS_LINUX = sys.platform.startswith("linux")

# Platform-specific locking primitives. rotbyte uses an advisory file lock
# to prevent two processes from writing to the same database concurrently.
# POSIX systems (macOS/Linux) use fcntl.flock; Windows uses msvcrt.locking
# on a byte-range at the start of the lock file.
if _IS_WINDOWS:
    import msvcrt  # type: ignore[import-not-found]
else:
    import fcntl


def _try_lock(fileobj) -> bool:
    """Non-blocking exclusive lock. Returns True on success, False if held."""
    try:
        if _IS_WINDOWS:
            msvcrt.locking(fileobj.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(fileobj, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (OSError, IOError):
        return False


def _unlock(fileobj) -> None:
    """Release a lock acquired via _try_lock. Safe to call if not held."""
    try:
        if _IS_WINDOWS:
            msvcrt.locking(fileobj.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(fileobj, fcntl.LOCK_UN)
    except OSError:
        pass


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
        # On POSIX, refuse to follow a symlink at the lock path: a malicious
        # symlink at <db>.lock would otherwise let an attacker redirect our
        # PID-record write to an arbitrary file. O_NOFOLLOW makes os.open
        # raise ELOOP if the path is a symlink. On Windows symlinks require
        # privilege to create and msvcrt.locking has no equivalent flag.
        try:
            if _IS_WINDOWS:
                fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            else:
                flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
                fd = os.open(self.lock_path, flags, 0o600)
            # "a+b" so Windows msvcrt.locking has a real byte to lock on.
            self.lock_file = os.fdopen(fd, "a+b")
        except OSError:
            return False
        if not _try_lock(self.lock_file):
            try:
                self.lock_file.close()
            finally:
                self.lock_file = None
            return False
        try:
            self.lock_file.seek(0)
            self.lock_file.truncate()
            self.lock_file.write(str(os.getpid()).encode("ascii"))
            self.lock_file.flush()
        except OSError:
            # A write failure doesn't invalidate the lock; the PID record
            # is informational only.
            pass
        return True

    def release(self):
        if self.lock_file:
            try:
                _unlock(self.lock_file)
                self.lock_file.close()
            except OSError:
                pass
            self.lock_file = None
            # Best-effort cleanup; on Windows the file may still be in use
            # by another process briefly, which is harmless.
            try:
                os.unlink(self.lock_path)
            except OSError:
                pass
