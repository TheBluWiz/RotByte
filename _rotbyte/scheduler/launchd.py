"""macOS launchd plist generation, installation, and discovery."""

from __future__ import annotations

import glob as _glob
import os
import plistlib as _plistlib
import subprocess as _subprocess
from typing import Dict, List, Optional, Tuple

from . import _parse_cmd_flags


def _launchd_log_path(label: str) -> str:
    """Return the rotated log path for a launchd job label.

    Lives under ~/Library/Logs/rotbyte/ to match XDG/AppData behavior on
    Linux/Windows and to survive reboots (unlike /tmp). The directory is
    created lazily by the caller before the plist is loaded.
    """
    return os.path.expanduser(f"~/Library/Logs/rotbyte/{label}.log")


# Rotate launchd log at install time to bound on-disk growth: launchd
# holds the log FD open between runs, so rotating from inside the
# rotbyte process at install/reinstall time is the safe moment. Keeps
# ``.1``..``.MAX-1`` generations.
_LAUNCHD_LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
_LAUNCHD_LOG_KEEP = 3


def _rotate_launchd_log(log_path: str) -> None:
    """Best-effort rotation of a launchd log file.

    Renames ``log.2`` → ``log.3``, ``log.1`` → ``log.2``, ``log`` →
    ``log.1`` when the current log exceeds _LAUNCHD_LOG_MAX_BYTES.
    Silent on any failure — log rotation is a nice-to-have, not a
    correctness requirement.
    """
    try:
        size = os.path.getsize(log_path)
    except OSError:
        return
    if size < _LAUNCHD_LOG_MAX_BYTES:
        return
    for i in range(_LAUNCHD_LOG_KEEP - 1, 0, -1):
        src = f"{log_path}.{i}"
        dst = f"{log_path}.{i + 1}"
        if os.path.exists(src):
            try:
                os.replace(src, dst)
            except OSError:
                return
    try:
        os.replace(log_path, f"{log_path}.1")
    except OSError:
        pass


def _generate_launchd_plist(label: str, command: List[str],
                            interval_seconds: Optional[int] = None,
                            calendar_times: Optional[List[Tuple[int, int]]] = None) -> str:
    """Generate a macOS launchd plist XML string.

    Either interval_seconds (for StartInterval) or calendar_times
    (for StartCalendarInterval) must be provided.

    Uses ``plistlib.dumps()`` from the stdlib so every interpolated value
    (label, command args, log paths) is XML-escaped automatically. This
    closes a prior injection gap where a target directory containing
    ``<``, ``>``, ``&`` or ``"`` would produce malformed XML or worse.
    """
    log_path = _launchd_log_path(label)
    plist: Dict[str, object] = {
        "Label": label,
        "ProgramArguments": list(command),
        "StandardOutPath": log_path,
        "StandardErrorPath": log_path,
        "Nice": 10,
    }
    if interval_seconds is not None:
        plist["StartInterval"] = int(interval_seconds)
    elif calendar_times is not None:
        plist["StartCalendarInterval"] = [
            {"Hour": int(h), "Minute": int(m)} for h, m in calendar_times
        ]
    else:
        raise ValueError("Must provide interval_seconds or calendar_times")
    return _plistlib.dumps(plist).decode("utf-8")


def _install_launchd(target_dir: str, dhash: str, quick_cmd: List[str],
                     every_seconds: int, full_cmd: Optional[List[str]],
                     full_at: Optional[List[Tuple[int, int]]]):
    """Write and load macOS launchd plist files."""
    agents_dir = os.path.expanduser("~/Library/LaunchAgents")
    os.makedirs(agents_dir, exist_ok=True)
    # Logs live under ~/Library/Logs/rotbyte/ (matches XDG/AppData on
    # other platforms and survives reboots, unlike /tmp). Created up
    # front so the first launchd run can open the log file.
    os.makedirs(os.path.expanduser("~/Library/Logs/rotbyte"), exist_ok=True)

    quick_label = f"com.rotbyte.quick.{dhash}"
    quick_plist = os.path.join(agents_dir, f"{quick_label}.plist")

    # Unload existing agents first (ignore errors if not loaded). Rotate
    # the existing log file before reload so launchd opens a fresh FD on
    # the new (smaller) file. Doing it here is the only safe moment —
    # while the agent is unloaded, nobody holds the FD.
    _subprocess.run(["launchctl", "unload", quick_plist],
                    capture_output=True)
    _rotate_launchd_log(_launchd_log_path(quick_label))

    plist_content = _generate_launchd_plist(
        quick_label, quick_cmd, interval_seconds=every_seconds,
    )
    with open(quick_plist, "w") as f:
        f.write(plist_content)
    _subprocess.run(["launchctl", "load", quick_plist], check=True)
    print(f"  ✓ Installed: {quick_plist}")

    if full_cmd and full_at:
        full_label = f"com.rotbyte.full.{dhash}"
        full_plist = os.path.join(agents_dir, f"{full_label}.plist")

        _subprocess.run(["launchctl", "unload", full_plist],
                        capture_output=True)
        _rotate_launchd_log(_launchd_log_path(full_label))

        plist_content = _generate_launchd_plist(
            full_label, full_cmd, calendar_times=full_at,
        )
        with open(full_plist, "w") as f:
            f.write(plist_content)
        _subprocess.run(["launchctl", "load", full_plist], check=True)
        print(f"  ✓ Installed: {full_plist}")


def _uninstall_launchd(target_dir: str) -> Tuple[List[str], List[str]]:
    """Bootout (or unload) and delete the launchd plists for a target.

    Returns ``(removed_labels, error_messages)``. An empty
    ``(removed, errors)`` tuple means no plists existed for this target —
    the caller treats that as a friendly no-op rather than an error.
    """
    from . import _dir_hash
    dhash = _dir_hash(target_dir)
    labels = [f"com.rotbyte.quick.{dhash}", f"com.rotbyte.full.{dhash}"]
    return _bootout_and_unlink(labels)


def _uninstall_all_launchd() -> Tuple[List[str], List[str]]:
    """Bootout and delete every ``com.rotbyte.*`` launchd agent."""
    agents_dir = os.path.expanduser("~/Library/LaunchAgents")
    plists = sorted(_glob.glob(os.path.join(agents_dir, "com.rotbyte.*.plist")))
    labels = [os.path.basename(p)[: -len(".plist")] for p in plists]
    return _bootout_and_unlink(labels)


def _bootout_and_unlink(labels: List[str]) -> Tuple[List[str], List[str]]:
    """Stop and remove a list of launchd plists by label.

    Modern macOS prefers ``launchctl bootout gui/<uid>/<label>``; older
    releases (10.10 and earlier) only know ``launchctl unload <plist>``.
    Try the modern form first and fall back; either way attempt the
    ``os.unlink`` so a leftover plist doesn't haunt the next reboot.
    Bootout/unload failures are best-effort (the agent may already be
    stopped); only ``unlink`` failures count as errors.
    """
    agents_dir = os.path.expanduser("~/Library/LaunchAgents")
    removed: List[str] = []
    errors: List[str] = []
    uid = os.getuid()
    for label in labels:
        plist_path = os.path.join(agents_dir, f"{label}.plist")
        if not os.path.isfile(plist_path):
            continue  # nothing here for this label
        # Stop the agent. Modern syntax first; fall back to legacy.
        target = f"gui/{uid}/{label}"
        result = _subprocess.run(
            ["launchctl", "bootout", target],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            _subprocess.run(
                ["launchctl", "unload", plist_path],
                capture_output=True, text=True,
            )
        # Remove the plist regardless — leaving it would let launchd
        # re-load the agent on the next user login or reboot.
        try:
            os.unlink(plist_path)
            removed.append(label)
        except OSError as e:
            errors.append(f"could not remove {plist_path}: {e}")
    return removed, errors


def _discover_launchd() -> Dict[str, Dict]:
    """Parse installed launchd plists to discover tracked directories."""
    agents_dir = os.path.expanduser("~/Library/LaunchAgents")
    tracked: Dict[str, Dict] = {}

    for plist_path in sorted(_glob.glob(os.path.join(agents_dir, "com.rotbyte.*.plist"))):
        try:
            with open(plist_path, "rb") as f:
                plist = _plistlib.load(f)
        except Exception:  # noqa: BLE001 — skip malformed plists
            # plistlib raises InvalidFileException, ValueError, OSError,
            # and more depending on how the file is broken. For
            # discovery, any unreadable plist is simply skipped so one
            # stale file can't hide every other tracked directory.
            continue

        label = plist.get("Label", "")
        args = plist.get("ProgramArguments", [])
        if not args:
            continue

        # The target directory is always the last argument
        target_dir = args[-1] if args else None
        if not target_dir or not os.path.isabs(target_dir):
            continue

        if target_dir not in tracked:
            tracked[target_dir] = {}

        # Check if this agent is loaded
        result = _subprocess.run(
            ["launchctl", "list", label],
            capture_output=True, text=True,
        )
        active = result.returncode == 0

        if ".quick." in label:
            interval = plist.get("StartInterval", 3600)
            tracked[target_dir]["quick"] = {
                "interval": interval,
                "active": active,
            }
        elif ".full." in label:
            times = []
            cal = plist.get("StartCalendarInterval", [])
            if isinstance(cal, dict):
                cal = [cal]
            for entry in cal:
                times.append((entry.get("Hour", 0), entry.get("Minute", 0)))

            tracked[target_dir]["full"] = {
                "times": times,
                "active": active,
                **_parse_cmd_flags(args),
            }

    return tracked
