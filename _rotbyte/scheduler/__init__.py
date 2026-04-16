"""Scheduler installation and discovery — platform dispatch layer.

Exports :func:`_run_track` (install scheduled scans on the current
platform) and :func:`_discover_tracked` (read them back for ``--status``).
Per-platform details live in ``launchd.py`` / ``systemd.py`` /
``schtasks.py``.
"""

from __future__ import annotations

import hashlib as _hashlib
import os
import re as _re
import shutil
import sys
from typing import Dict, List, Optional, Tuple

from ..helpers import _format_clock_time, _format_duration
from ..platform import _IS_MACOS, _IS_WINDOWS


def _dir_hash(target_dir: str) -> str:
    """Short hash of the target directory path for unique config naming."""
    return _hashlib.md5(target_dir.encode()).hexdigest()[:8]


def _find_rotbyte_executable() -> str:
    """Find the full path to the rotbyte executable for scheduled tasks.

    On macOS, always returns 'python script.py' format to avoid going
    through shell wrapper scripts (like Homebrew's bash wrappers). This
    is critical for Full Disk Access — TCC checks the binary that
    actually performs I/O (Python), and a bash wrapper in the chain
    breaks the attribution.

    On Linux (systemd), the shell wrapper is fine since there's no TCC.
    """
    if _IS_MACOS:
        # Always use Python directly on macOS to avoid bash wrapper
        # attribution issues with Full Disk Access
        script = os.path.realpath(sys.argv[0])
        if script.endswith(".py"):
            return f"{sys.executable} {script}"
        # If invoked via a wrapper, find the .py script it points to
        wrapper = shutil.which(os.path.basename(sys.argv[0]))
        if wrapper:
            wrapper = os.path.realpath(wrapper)
            try:
                with open(wrapper, "r") as f:
                    content = f.read()
                # Parse Homebrew-style wrapper:
                #   exec "/path/to/rotbyte.py" "$@"
                match = _re.search(r'exec\s+"([^"]+\.py)"', content)
                if match:
                    return f"{sys.executable} {match.group(1)}"
            except OSError:
                pass
        return f"{sys.executable} {script}"

    # Linux / other: shell wrappers work fine
    if not sys.argv[0].endswith(".py"):
        candidate = shutil.which(os.path.basename(sys.argv[0]))
        if candidate:
            return os.path.realpath(candidate)

    candidate = shutil.which("rotbyte")
    if candidate:
        return os.path.realpath(candidate)

    return f"{sys.executable} {os.path.realpath(sys.argv[0])}"


def _parse_cmd_flags(args: List[str]) -> Dict[str, Optional[str]]:
    """Extract --due, --budget, --workers, --notify values from a command arg list."""
    flags: Dict[str, Optional[str]] = {}
    for i, arg in enumerate(args):
        if arg == "--due" and i + 1 < len(args):
            flags["due"] = args[i + 1]
        elif arg == "--budget" and i + 1 < len(args):
            flags["budget"] = args[i + 1]
        elif arg == "--workers" and i + 1 < len(args):
            flags["workers"] = args[i + 1]
        elif arg == "--notify" and i + 1 < len(args):
            flags["notify"] = args[i + 1]
    return flags


def _run_track(target_dir: str, every_seconds: int,
               full_at: Optional[List[Tuple[int, int]]],
               budget_seconds: Optional[int],
               rotbyte_exe: str,
               workers: Optional[int] = None,
               due_days: Optional[int] = None,
               notify: Optional[str] = None,
               auto_export: bool = False,
               run_on_battery: bool = False):
    """Install platform-native scheduled tasks for rotbyte.

    On macOS:   launchd plists in ~/Library/LaunchAgents/
    On Linux:   systemd user timer/service pairs in ~/.config/systemd/user/
    On Windows: Task Scheduler tasks under \\rotbyte\\ (user-level).
    """
    # Import per-platform implementations lazily so platforms the user
    # isn't on don't pay the import cost (and so systemd-only tests
    # don't load launchd tooling on Linux CI).
    from . import launchd, schtasks, systemd

    is_mac = _IS_MACOS
    is_windows = _IS_WINDOWS
    is_linux = sys.platform.startswith("linux")

    if not is_mac and not is_linux and not is_windows:
        print(f"Error: --track is not supported on {sys.platform}.", file=sys.stderr)
        print("  Supported platforms: macOS (launchd), Linux (systemd), Windows (Task Scheduler).",
              file=sys.stderr)
        sys.exit(1)

    if run_on_battery and not is_windows:
        # Silent on non-Windows — flag is platform-specific but permissive.
        pass

    dhash = _dir_hash(target_dir)

    # Split rotbyte_exe into command parts (handles "python /path/to/rotbyte.py")
    exe_parts = rotbyte_exe.split()

    # --workers passthrough (only when explicitly set)
    workers_args = ["--workers", str(workers)] if workers is not None else []
    notify_args = ["--notify", notify] if notify else []
    # --auto-export is a bare flag that persists in the scheduled command
    # so each future run re-exports the manifest after a full --check.
    auto_export_args = ["--auto-export"] if auto_export else []

    # Build the commands that will be scheduled
    quick_cmd = (exe_parts + workers_args + notify_args + auto_export_args
                 + ["--scheduled", "--quiet", target_dir])
    full_cmd = None
    if full_at:
        full_cmd = (exe_parts + ["--check", "--quiet"] + workers_args + notify_args
                    + auto_export_args + ["--scheduled"])
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
    if notify:
        print(f"  Notify     : {notify}")
    if auto_export:
        print(f"  Manifest   : auto-exported after each full scan")
    if is_windows:
        plat_label = "Windows (Task Scheduler)"
    elif is_mac:
        plat_label = "macOS (launchd)"
    else:
        plat_label = "Linux (systemd)"
    print(f"  Platform   : {plat_label}")
    if is_windows:
        print(f"  On battery : {'allowed' if run_on_battery else 'skip (default)'}")
    print("═" * 60)
    print()

    if is_mac:
        launchd._install_launchd(target_dir, dhash, quick_cmd, every_seconds,
                                 full_cmd, full_at)
    elif is_linux:
        systemd._install_systemd(target_dir, dhash, quick_cmd, every_seconds,
                                 full_cmd, full_at)
    else:
        schtasks._install_schtasks(target_dir, dhash, quick_cmd, every_seconds,
                                   full_cmd, full_at, budget_seconds=budget_seconds,
                                   run_on_battery=run_on_battery)

    print()
    print("═" * 60)
    print("  ✓ Scheduled scans installed successfully.")
    print()
    print("  Logs:")
    if is_mac:
        print(f"    {launchd._launchd_log_path(f'com.rotbyte.quick.{dhash}')}")
        if full_at:
            print(f"    {launchd._launchd_log_path(f'com.rotbyte.full.{dhash}')}")
    elif is_linux:
        print(f"    journalctl --user -u rotbyte-quick-{dhash}")
        if full_at:
            print(f"    journalctl --user -u rotbyte-full-{dhash}")
    else:
        log_dir = os.path.join(os.environ.get("LOCALAPPDATA",
                               os.path.expanduser("~")), "rotbyte", "logs")
        print(f"    {os.path.join(log_dir, f'quick-{dhash}.log')}")
        if full_at:
            print(f"    {os.path.join(log_dir, f'full-{dhash}.log')}")
        print("    (also visible in Task Scheduler → Task History)")
    print("═" * 60)


def _discover_tracked(is_mac: bool) -> Dict[str, Dict]:
    """Discover all installed rotbyte scheduler configs.

    Returns {target_dir: {"quick": {...}, "full": {...}}} with schedule
    details and active status for each tracked directory.
    """
    from . import launchd, systemd
    if is_mac:
        return launchd._discover_launchd()
    return systemd._discover_systemd()
