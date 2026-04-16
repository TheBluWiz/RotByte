"""Time / format / parse helpers shared across the package.

Small, pure utilities with no package-internal dependencies — every
other module is free to import from here.
"""

from __future__ import annotations

import functools
import os
import re as _re
import shutil
import sys
from datetime import datetime, timezone
from typing import Tuple


# rotbyte calls os.path.realpath() in many hot paths: skip-file dedup,
# exclude-dir normalisation, scheduler discovery, and --verify-file DB
# lookup. Each call is a syscall chain that resolves symlinks. rotbyte
# is one-shot, so a process-scoped LRU cache is safe and bounded.
@functools.lru_cache(maxsize=None)
def _resolve(path: str) -> str:
    """Cached ``os.path.realpath`` for the lifetime of this process.

    Safe because rotbyte invocations are one-shot — the process exits
    before anything on disk can be renamed out from under the cache.
    """
    return os.path.realpath(path)


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


def _utc_to_local(utc_iso: str) -> str:
    """Convert a UTC ISO 8601 timestamp to a local time display string.

    Handles both second-precision ('2026-04-09T14:30:00Z') and
    nanosecond-precision ('2026-04-09T14:30:00.123456789Z') formats.
    Returns a human-readable local time like '2026-04-09 7:30 AM PDT'.
    """
    # Strip nanosecond fractional part if present (strptime only handles up to 6 digits)
    clean = utc_iso
    if "." in clean:
        clean = clean[:clean.index(".")] + "Z"
    dt = datetime.strptime(clean, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    local = dt.astimezone()
    # Get timezone abbreviation
    tz_name = local.strftime("%Z")
    ampm = "AM" if local.hour < 12 else "PM"
    display_hour = local.hour % 12 or 12
    if local.minute:
        time_str = f"{display_hour}:{local.minute:02d} {ampm}"
    else:
        time_str = f"{display_hour} {ampm}"
    return f"{local.strftime('%Y-%m-%d')} {time_str} {tz_name}"


def _term_width() -> int:
    """Return usable terminal width, clamped to a sane range."""
    return max(40, min(shutil.get_terminal_size((80, 24)).columns, 200))
