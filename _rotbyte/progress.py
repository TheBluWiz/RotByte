"""Spinner and progress bar rendering.

Both widgets degrade gracefully to plain text when stderr is not a tty
(pipes, cron, systemd journal), so the same instantiation works for
interactive sessions and automation.
"""

from __future__ import annotations

import sys
import threading
import time
from typing import Optional

from .helpers import _format_size, _is_tty, _term_width


def _enable_windows_vt() -> None:
    """Enable ANSI escape handling on legacy Windows consoles.

    The spinner/progress renderers emit VT sequences ('\\r\\033[2K'). On
    Windows 10+ these only render if virtual-terminal processing is turned
    on for the console; otherwise they show as literal garbage. Flip the
    ENABLE_VIRTUAL_TERMINAL_PROCESSING bit on stdout and stderr once, via
    ctypes (stdlib — no third-party dependency). A no-op everywhere but
    Windows, and best-effort: any failure (old console, redirected handle)
    is swallowed so a non-tty / automation path is unaffected.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(
                    handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                )
    except Exception:  # noqa: BLE001 — best-effort; never break rendering
        pass


_enable_windows_vt()


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
        print("\r\033[2K", end="", file=sys.stderr, flush=True)


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
