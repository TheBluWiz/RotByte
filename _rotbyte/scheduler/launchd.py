"""macOS launchd plist generation, installation, and discovery."""

from __future__ import annotations

import glob as _glob
import os
import plistlib as _plistlib
import re as _re
import subprocess as _subprocess
from typing import Dict, List, Optional, Tuple

from . import (_exe_prefix_current, _exe_prefix_len, _missing_command_path,
               _parse_cmd_flags, _repair_exe_prefix)


def _launch_agents_dir() -> str:
    """Return ``~/Library/LaunchAgents``, resolved fresh on each call.

    Kept as a function (rather than an import-time constant) so it honors a
    later-patched ``$HOME`` / ``os.path.expanduser`` — the test suite
    redirects HOME per-test — while still giving every function in this
    module one source of truth for the LaunchAgents directory.
    """
    return os.path.expanduser("~/Library/LaunchAgents")


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
# up to _LAUNCHD_LOG_KEEP rotated generations (``.1``..``.3``).
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


def _rotbyte_log_dir() -> str:
    """Return ``~/Library/Logs/rotbyte``, resolved fresh on each call.

    Mirrors ``_launch_agents_dir`` so it honors a later-patched ``$HOME``
    (the test suite redirects HOME per-test).
    """
    return os.path.expanduser("~/Library/Logs/rotbyte")


# Matches ``com.rotbyte.quick.<hash>.log`` and its rotated generations
# ``…​.log.1`` / ``.log.2``. Group 1 is the job label; group 2 is the
# rotation suffix (empty for the live log). ``<hash>`` never contains a
# dot, so ``[^.]+`` bounds it cleanly.
_LOG_NAME_RE = _re.compile(
    r"^(com\.rotbyte\.(?:quick|full)\.[^.]+)\.log(\.\d+)?$"
)


def _clear_launchd_logs() -> Tuple[List[str], List[str], List[str]]:
    """Clear rotbyte's launchd log files under ~/Library/Logs/rotbyte.

    The *live* ``.log`` of a still-installed job is **truncated in place**
    rather than unlinked: it's the conservative choice for a file launchd
    may have open — it can't orphan launchd's descriptor or race an
    in-flight write. (Verified empirically: launchd writes each run's
    output from offset 0, so a truncated log refills cleanly with no
    sparse-hole regrowth.) Rotated generations (``.log.1``…) and any
    orphan log whose plist is gone are **deleted**.

    A job is "installed" when a matching ``com.rotbyte.*.plist`` still
    exists in ~/Library/LaunchAgents. Returns
    ``(truncated, deleted, errors)`` — the first two are file paths, the
    last is human-readable error strings.
    """
    log_dir = _rotbyte_log_dir()
    agents_dir = _launch_agents_dir()

    installed = {
        os.path.basename(p)[: -len(".plist")]
        for p in _glob.glob(os.path.join(agents_dir, "com.rotbyte.*.plist"))
    }

    truncated: List[str] = []
    deleted: List[str] = []
    errors: List[str] = []

    for path in sorted(_glob.glob(os.path.join(log_dir, "com.rotbyte.*.log*"))):
        m = _LOG_NAME_RE.match(os.path.basename(path))
        if not m:
            continue
        label, rotated = m.group(1), m.group(2)
        if label in installed and not rotated:
            # Live log of an installed job → truncate, preserve the inode.
            try:
                with open(path, "w"):
                    pass
                truncated.append(path)
            except OSError as e:
                errors.append(f"could not truncate {path}: {e}")
        else:
            # Rotated generation, or orphan whose plist is gone → delete.
            try:
                os.unlink(path)
                deleted.append(path)
            except OSError as e:
                errors.append(f"could not delete {path}: {e}")

    return truncated, deleted, errors


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
    agents_dir = _launch_agents_dir()
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
    _load_or_cleanup(quick_plist)
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
        _load_or_cleanup(full_plist)
        print(f"  ✓ Installed: {full_plist}")


def _load_or_cleanup(plist_path: str) -> None:
    """``launchctl load`` a plist; on failure unlink it and raise.

    Replaces a bare ``check=True`` so a rejected load doesn't dump a
    traceback and leave an orphaned, never-loaded plist behind that a
    future login/reboot might partially adopt. The caller (_run_track)
    turns the RuntimeError into a friendly message.
    """
    result = _subprocess.run(["launchctl", "load", plist_path],
                             capture_output=True, text=True)
    if result.returncode != 0:
        try:
            os.unlink(plist_path)
        except OSError:
            pass
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(
            f"launchctl load {plist_path} failed (exit {result.returncode})"
            + (f": {detail}" if detail else "")
        )


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
    agents_dir = _launch_agents_dir()
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
    agents_dir = _launch_agents_dir()
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


# Matches launchd's `launchctl list <label>` output, e.g.:
#     "LastExitStatus" = 512;
# The value is a wait(2) status: exit code in the high byte.
_LAST_EXIT_STATUS_RE = _re.compile(r'"LastExitStatus"\s*=\s*(\d+)')


def _agent_state(label: str) -> Dict[str, object]:
    """Query launchd for an agent's load state and last exit status.

    Returns ``{"active": bool, "last_exit": Optional[int]}``. ``active``
    means the plist is loaded; ``last_exit`` is the exit code of the most
    recent run (None when launchd doesn't report one, e.g. never ran).
    A loaded agent whose every run fails still counts as "active", which
    is exactly why callers should surface ``last_exit`` too.
    """
    result = _subprocess.run(
        ["launchctl", "list", label],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return {"active": False, "last_exit": None}
    last_exit: Optional[int] = None
    m = _LAST_EXIT_STATUS_RE.search(result.stdout or "")
    if m:
        raw = int(m.group(1))
        # launchctl reports a wait(2) status; a plain exit(N) shows up as
        # N << 8. Values under 256 are signal terminations — report as-is.
        last_exit = raw >> 8 if raw >= 256 else raw
    return {"active": True, "last_exit": last_exit}


def _repair_launchd(fresh_exe: List[str]) -> Tuple[List[Tuple[str, str, str, str]],
                                                   List[str], List[str]]:
    """Re-point every installed rotbyte plist at ``fresh_exe`` and reload it.

    Returns ``(repaired, already_ok, errors)`` where ``repaired`` is a list
    of ``(label, target_dir, old_prefix, new_prefix)`` tuples, ``already_ok``
    is the labels whose command already matched, and ``errors`` is
    human-readable failure strings.

    Only the interpreter/script prefix of ``ProgramArguments`` is rewritten;
    the schedule (StartInterval / StartCalendarInterval), log paths, Nice,
    and every scan flag are loaded from the existing plist and preserved. A
    rewritten plist is reloaded (``unload`` then ``load``) because launchd
    ignores on-disk edits to an already-loaded agent.
    """
    agents_dir = _launch_agents_dir()
    repaired: List[Tuple[str, str, str, str]] = []
    already_ok: List[str] = []
    errors: List[str] = []

    for plist_path in sorted(_glob.glob(os.path.join(agents_dir, "com.rotbyte.*.plist"))):
        label = os.path.basename(plist_path)[: -len(".plist")]
        try:
            with open(plist_path, "rb") as f:
                plist = _plistlib.load(f)
        except Exception:  # noqa: BLE001 — a broken plist shouldn't stop the rest
            errors.append(f"{label}: could not parse plist; re-run --track for this directory")
            continue

        args = list(plist.get("ProgramArguments", []))
        if not args:
            errors.append(f"{label}: plist has no ProgramArguments")
            continue

        if _exe_prefix_current(args, fresh_exe):
            already_ok.append(label)
            continue

        old_prefix = " ".join(args[: _exe_prefix_len(args)])
        new_args = _repair_exe_prefix(args, fresh_exe)
        target_dir = args[-1]

        plist["ProgramArguments"] = new_args
        try:
            with open(plist_path, "wb") as f:
                _plistlib.dump(plist, f)
        except OSError as e:
            errors.append(f"{label}: could not write plist: {e}")
            continue

        # Reload so launchd adopts the new command. Failures here are worth
        # reporting but the file is already fixed, so the next login/reboot
        # would pick it up regardless.
        _subprocess.run(["launchctl", "unload", plist_path], capture_output=True)
        result = _subprocess.run(["launchctl", "load", plist_path],
                                 capture_output=True, text=True)
        if result.returncode != 0:
            errors.append(f"{label}: reloaded plist but launchctl load failed: "
                          f"{(result.stderr or '').strip()}")

        repaired.append((label, target_dir, old_prefix, " ".join(fresh_exe)))

    return repaired, already_ok, errors


def _discover_launchd() -> Dict[str, Dict]:
    """Parse installed launchd plists to discover tracked directories."""
    agents_dir = _launch_agents_dir()
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

        state = _agent_state(label)
        missing_exe = _missing_command_path(args)

        if ".quick." in label:
            interval = plist.get("StartInterval", 3600)
            tracked[target_dir]["quick"] = {
                "interval": interval,
                "active": state["active"],
                "last_exit": state["last_exit"],
                "missing_exe": missing_exe,
                **_parse_cmd_flags(args),
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
                "active": state["active"],
                "last_exit": state["last_exit"],
                "missing_exe": missing_exe,
                **_parse_cmd_flags(args),
            }

    return tracked
