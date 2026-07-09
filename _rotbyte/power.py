"""Keep the OS and external disks awake for the duration of a scan.

Long rotbyte scans on external drives can stall when the OS idle-sleeps
the system or spins down the disk mid-scan. Both default to aggressive
timeouts on macOS (~10 min) and trigger even while the machine is on
AC power with the lid open. A stalled syscall inside an attached USB or
Thunderbolt volume can wedge the process indefinitely.

:class:`PreventSleep` is a context manager that takes a power assertion
for the duration of the scan so neither happens:

  macOS:   spawns ``caffeinate -i -m -s -w <pid>`` as a child process.
           -i  prevent idle system sleep
           -m  prevent disk idle sleep (fixes the external-drive stall)
           -s  prevent system sleep (effective on AC)
           -w  terminate when our PID exits — survives SIGKILL, crashes,
               and clean shutdowns without cleanup code.
  Windows: SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED).
  Linux:   no-op. Headless Linux doesn't idle-sleep; desktop Linux
           rarely affects disk I/O scans.

Best-effort on all platforms: if the assertion fails to engage the scan
still runs. The exception cases users into the same behavior as before
this module existed.
"""

from __future__ import annotations

import os
import subprocess
from typing import Optional

from .platform import _IS_MACOS, _IS_WINDOWS


# Windows SetThreadExecutionState flags
_ES_CONTINUOUS = 0x80000000
_ES_SYSTEM_REQUIRED = 0x00000001


class PreventSleep:
    """Context manager: take a power assertion for the wrapped block.

    Use around the hashing phase only. Short-lived operations like
    --status or --report don't need (and shouldn't take) an assertion.
    """

    def __init__(self):
        self._caffeinate: Optional[subprocess.Popen] = None
        self._windows_active: bool = False

    def __enter__(self) -> "PreventSleep":
        if _IS_MACOS:
            self._start_caffeinate()
        elif _IS_WINDOWS:
            self._set_execution_state()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()

    def release(self) -> None:
        if self._caffeinate is not None:
            try:
                self._caffeinate.terminate()
            except OSError:
                pass
            self._caffeinate = None
        if self._windows_active:
            self._clear_execution_state()
            self._windows_active = False

    def _start_caffeinate(self) -> None:
        try:
            self._caffeinate = subprocess.Popen(
                ["caffeinate", "-i", "-m", "-s", "-w", str(os.getpid())],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:  # FileNotFoundError is a subclass of OSError
            self._caffeinate = None

    def _set_execution_state(self) -> None:
        try:
            import ctypes  # type: ignore[import-not-found]

            ctypes.windll.kernel32.SetThreadExecutionState(
                _ES_CONTINUOUS | _ES_SYSTEM_REQUIRED
            )
            self._windows_active = True
        except (OSError, AttributeError):
            self._windows_active = False

    def _clear_execution_state(self) -> None:
        try:
            import ctypes  # type: ignore[import-not-found]

            ctypes.windll.kernel32.SetThreadExecutionState(_ES_CONTINUOUS)
        except (OSError, AttributeError):
            pass
