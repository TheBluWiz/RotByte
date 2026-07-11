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
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

from ..helpers import _format_clock_time, _format_duration
from ..platform import _IS_LINUX, _IS_MACOS, _IS_WINDOWS


def _dir_hash(target_dir: str) -> str:
    """Short hash of the target directory path for unique config naming.

    ``usedforsecurity=False`` (Python 3.9+) marks this as a naming digest,
    not a security primitive, so it keeps working on FIPS-mode systems
    (RHEL/CentOS in FIPS mode) where plain ``md5()`` raises ValueError and
    would otherwise abort every scheduler operation. The digest value is
    byte-identical to ``md5(...).hexdigest()`` — only the FIPS error
    behavior changes, so existing config names are unaffected.
    """
    return _hashlib.md5(target_dir.encode(), usedforsecurity=False).hexdigest()[:8]


# Matches a Homebrew Cellar path: <prefix>/Cellar/<package>/<version>/<rest>.
# Used to rewrite version-pinned paths to the upgrade-stable opt symlink.
_CELLAR_RE = _re.compile(r"^(?P<prefix>.*)/Cellar/(?P<pkg>[^/]+)/[^/]+/(?P<rest>.+)$")


def _stable_homebrew_path(path: str) -> str:
    """Rewrite a version-pinned Homebrew Cellar path to its opt equivalent.

    ``/opt/homebrew/Cellar/rotbyte/1.1.0/libexec/rotbyte.py`` becomes
    ``/opt/homebrew/opt/rotbyte/libexec/rotbyte.py``. The Cellar directory
    is deleted on ``brew upgrade`` + ``brew cleanup``, so baking a Cellar
    path into a persistent scheduler config (launchd plist, systemd unit,
    Task Scheduler XML) silently breaks every scheduled run after the
    next upgrade. The ``opt/<pkg>`` symlink always points at the current
    version, so scheduled commands keep working across upgrades.

    Returns ``path`` unchanged when it isn't a Cellar path or when the
    opt equivalent doesn't exist (e.g. a partially removed install —
    better to keep a path that works today than invent one that doesn't).
    """
    m = _CELLAR_RE.match(path)
    if not m:
        return path
    stable = f"{m.group('prefix')}/opt/{m.group('pkg')}/{m.group('rest')}"
    return stable if os.path.exists(stable) else path


def _find_rotbyte_executable() -> List[str]:
    """Find the command to run rotbyte from a scheduled task.

    Returns the command as an argument list (e.g. ``["/usr/bin/python3",
    "/path/rotbyte.py"]``) so paths containing spaces survive intact all
    the way into the platform scheduler config.

    On macOS, always returns '<python> <script.py>' form to avoid going
    through shell wrapper scripts (like Homebrew's bash wrappers). This
    is critical for Full Disk Access — TCC checks the binary that
    actually performs I/O (Python), and a bash wrapper in the chain
    breaks the attribution.

    On Linux (systemd), the shell wrapper is fine since there's no TCC.

    All returned paths pass through :func:`_stable_homebrew_path` so a
    Homebrew install never pins the scheduled command to a Cellar
    directory that the next ``brew upgrade`` deletes.
    """
    interpreter = _stable_homebrew_path(sys.executable)
    if _IS_MACOS:
        # Always use Python directly on macOS to avoid bash wrapper
        # attribution issues with Full Disk Access
        script = os.path.realpath(sys.argv[0])
        if script.endswith(".py"):
            return [interpreter, _stable_homebrew_path(script)]
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
                    return [interpreter, _stable_homebrew_path(match.group(1))]
            except OSError:
                pass
        return [interpreter, _stable_homebrew_path(script)]

    # Linux / other: shell wrappers work fine
    if not sys.argv[0].endswith(".py"):
        candidate = shutil.which(os.path.basename(sys.argv[0]))
        if candidate:
            return [_stable_homebrew_path(os.path.realpath(candidate))]

    candidate = shutil.which("rotbyte")
    if candidate:
        return [_stable_homebrew_path(os.path.realpath(candidate))]

    return [interpreter, _stable_homebrew_path(os.path.realpath(sys.argv[0]))]


def _fda_target_binary() -> str:
    """Resolve the Mach-O binary macOS's TCC checks for Full Disk Access.

    On a Python.framework build (Homebrew or python.org), TCC attributes
    file I/O to the framework's ``Python`` binary at
    ``Versions/X.Y/Python`` — not the thin ``Versions/X.Y/bin/pythonX.Y``
    launcher ``sys.executable`` resolves to (see docs/macos-permissions.md,
    "Finding the right binary"). Walks up from the resolved interpreter
    path to that sibling file when the framework layout is present; falls
    back to the resolved interpreter itself for non-framework builds
    (system Python, most pyenv/venv installs).
    """
    interpreter = os.path.realpath(sys.executable)
    versions_dir = os.path.dirname(os.path.dirname(interpreter))
    framework_binary = os.path.join(versions_dir, "Python")
    if (os.path.basename(os.path.dirname(versions_dir)) == "Versions"
            and os.path.isfile(framework_binary)):
        return framework_binary
    return interpreter


def _fda_granted() -> bool:
    """Best-effort check for whether this process can read Full-Disk-Access-gated paths.

    There's no public API to query TCC grant state, so this uses the same
    probe several menu-bar utilities rely on: ``~/Library/Application
    Support/com.apple.TCC`` is itself FDA-gated regardless of what else is,
    so listing it raises ``PermissionError`` without FDA and succeeds once
    it's granted.

    This is trustworthy as a negative (a ``PermissionError`` means this
    process genuinely lacks FDA) but only a hint as a positive: a process
    spawned from a terminal that itself has FDA inherits that grant, so a
    True here doesn't prove the *target* binary (see
    :func:`_fda_target_binary`) has been individually added — only that
    something in this process's ancestry has access. Callers should treat
    True as "probably fine, unconfirmed" rather than a guarantee, which
    matters most for schedules run by launchd (no terminal in the chain).
    """
    tcc_dir = os.path.expanduser("~/Library/Application Support/com.apple.TCC")
    try:
        os.listdir(tcc_dir)
        return True
    except OSError:
        return False


def _open_fda_settings() -> bool:
    """Open System Settings directly to the Full Disk Access pane.

    Returns False (rather than raising) on any failure — no GUI session
    (headless/SSH), no ``open`` binary, or a rejected URL scheme — so the
    caller can fall back to printing manual instructions.
    """
    try:
        subprocess.run(
            ["open", "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"],
            check=True, capture_output=True,
        )
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _reveal_in_finder(path: str) -> bool:
    """Reveal ``path`` in Finder so it's ready to drag into the FDA list.

    Returns False (rather than raising) when the path doesn't exist or
    Finder can't be reached (headless/SSH session), so the caller can fall
    back to printing the path for manual entry via Cmd+Shift+G.
    """
    if not os.path.exists(path):
        return False
    try:
        subprocess.run(["open", "-R", path], check=True, capture_output=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _run_grant_fda() -> int:
    """Check Full Disk Access and, if missing, open the settings pane for it.

    macOS only. If :func:`_fda_granted` already reads True, reports that —
    with the inheritance caveat, since the check can't distinguish a real
    per-binary grant from one inherited off an already-authorized terminal.
    Otherwise resolves the binary that actually needs the grant (the one
    :func:`_find_rotbyte_executable` would schedule under launchd), opens
    System Settings to Privacy & Security → Full Disk Access, and reveals
    that binary in Finder so it's one drag-and-drop away from being added.
    Idempotent and side-effect-free beyond opening those two UI surfaces —
    safe to run anytime.
    """
    if not _IS_MACOS:
        print(f"Error: --grant-fda is not supported on {sys.platform}.", file=sys.stderr)
        return _UNTRACK_INTERNAL

    print("═" * 60)
    print("  rotbyte — Full Disk Access")
    print("═" * 60)

    if _fda_granted():
        print("  ✓ Full Disk Access appears available to this process.")
        print(f"      {os.path.realpath(sys.executable)}")
        print()
        print("  Note: this reflects the process running this command, which")
        print("  may be inheriting access from an already-authorized terminal")
        print("  or IDE. It does not confirm the launchd-scheduled Python")
        print("  binary has its own grant — verify scheduled scans with:")
        print("    rotbyte --track ...  then  launchctl start com.rotbyte.full.HASH")
        print("  (see docs/macos-permissions.md, 'Verify it works').")
        print("═" * 60)
        return _UNTRACK_OK

    target = _fda_target_binary()
    print("  ✗ Full Disk Access is not granted.")
    print(f"      {target}")
    print()
    print("  Opening System Settings and revealing the binary in Finder —")
    print("  drag it into the Full Disk Access list, toggle it on, then")
    print("  restart your Mac for the change to take effect.")
    print()

    opened_settings = _open_fda_settings()
    if not opened_settings:
        print("  ! Could not open System Settings automatically.", file=sys.stderr)
        print("    Open it manually: System Settings → Privacy & Security → "
              "Full Disk Access", file=sys.stderr)

    revealed = _reveal_in_finder(target)
    if not revealed:
        print(f"  ! Could not reveal {target} in Finder.", file=sys.stderr)
        print("    Locate it manually with Cmd+Shift+G in the file picker.",
              file=sys.stderr)

    print("═" * 60)
    return _UNTRACK_OK if (opened_settings and revealed) else _UNTRACK_IO_ERROR


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


def _missing_command_path(args: List[str]) -> Optional[str]:
    """Return the first command path in ``args`` that no longer exists.

    Checks the interpreter (args[0]) and, when the second argument is a
    ``.py`` script, the script itself. This is how a stale scheduler
    config manifests in practice: a Homebrew upgrade deletes the old
    Cellar directory and every scheduled run dies at exec with
    "[Errno 2] No such file or directory" — invisible unless someone
    reads the log. Surfacing it here lets --status say so.
    """
    if not args:
        return None
    if os.path.isabs(args[0]) and not os.path.exists(args[0]):
        return args[0]
    if (len(args) > 1 and args[1].endswith(".py")
            and os.path.isabs(args[1]) and not os.path.exists(args[1])):
        return args[1]
    return None


def _exe_prefix_len(args: List[str]) -> int:
    """Length of the interpreter/script prefix at the head of a command.

    ``[python, rotbyte.py, --flag, dir]`` → 2; ``[rotbyte-wrapper, dir]`` → 1.
    Mirrors the shape :func:`_find_rotbyte_executable` produces and the
    shape :func:`_missing_command_path` inspects.
    """
    if len(args) > 1 and args[1].endswith(".py"):
        return 2
    return 1


def _exe_prefix_current(args: List[str], fresh_exe: List[str]) -> bool:
    """True when a command already begins with the fresh executable prefix.

    A schedule whose prefix matches needs no repair; one that differs is
    either broken (the old path was deleted by an upgrade) or merely stale
    (still a Cellar path that the next upgrade will delete). Both should be
    rewritten to the current upgrade-stable form.
    """
    return list(args[:_exe_prefix_len(args)]) == list(fresh_exe)


def _repair_exe_prefix(args: List[str], fresh_exe: List[str]) -> List[str]:
    """Swap a command's interpreter/script prefix for ``fresh_exe``.

    Every trailing argument — flags like ``--due``/``--notify``/
    ``--auto-export`` and the target directory — is preserved verbatim, so
    repair never silently drops behavior the way a reconstruct-from-scratch
    would.
    """
    return list(fresh_exe) + list(args[_exe_prefix_len(args):])


def _run_repair() -> int:
    """Rewrite installed schedules to the current rotbyte/Python paths.

    The launchd plists / systemd units persist an absolute interpreter and
    script path. A Homebrew upgrade that deletes the old Cellar tree (or a
    schedule written before paths were stabilized) leaves those pointing at
    a file that no longer exists, so every scheduled run dies at exec —
    silently. ``--repair`` re-points each schedule at the executable this
    rotbyte resolves to today and reloads it, in place, preserving all
    flags and the target directory. Idempotent: schedules already on the
    current path are reported as such and left untouched.

    Returns a process exit code mirroring the untrack helpers (0 ok,
    6 if any platform command failed, 7 if unsupported).
    """
    if not (_IS_MACOS or _IS_LINUX or _IS_WINDOWS):
        print(f"Error: --repair is not supported on {sys.platform}.", file=sys.stderr)
        return _UNTRACK_INTERNAL

    fresh_exe = _find_rotbyte_executable()

    print("═" * 60)
    print("  rotbyte — Repairing scheduled scans")
    print("═" * 60)
    print(f"  Current command: {' '.join(fresh_exe)}")
    print()

    if _IS_WINDOWS:
        # Task Scheduler tasks don't suffer the Homebrew Cellar-path
        # breakage (no Homebrew on Windows), so there's nothing to rewrite.
        from . import schtasks
        tracked = schtasks._discover_schtasks()
        if not tracked:
            print("  No scheduled scans found.")
            return _UNTRACK_OK
        print("  Windows scheduled tasks use stable paths — no repair needed.")
        print("  If a task is genuinely broken, re-run --track for its directory:")
        for d in sorted(tracked):
            print(f"    {d}")
        print("═" * 60)
        return _UNTRACK_OK

    if _IS_MACOS:
        from . import launchd
        backend = "launchd"
        try:
            repaired, already_ok, errors = launchd._repair_launchd(fresh_exe)
        except Exception as e:  # noqa: BLE001 — platform repair failure
            print(f"Error: launchd repair failed: {e}", file=sys.stderr)
            return _UNTRACK_INTERNAL
    else:
        from . import systemd
        backend = "systemd"
        try:
            repaired, already_ok, errors = systemd._repair_systemd(fresh_exe)
        except Exception as e:  # noqa: BLE001
            print(f"Error: systemd repair failed: {e}", file=sys.stderr)
            return _UNTRACK_INTERNAL

    if not repaired and not already_ok and not errors:
        print("  No scheduled scans found.")
        print()
        print("  Use --track to set up scheduled scanning.")
        print("═" * 60)
        return _UNTRACK_OK

    for label, target_dir, old_prefix, new_prefix in repaired:
        print(f"  ✓ Repaired: {label}")
        print(f"      {target_dir}")
        print(f"      was: {old_prefix}")
        print(f"      now: {new_prefix}")
    for label in already_ok:
        print(f"  · Already current: {label}")
    if errors:
        for msg in errors:
            print(f"  ! {msg}", file=sys.stderr)

    print()
    n = len(repaired)
    print(f"  Repaired {n} schedule{'s' if n != 1 else ''} ({backend}).")
    if repaired:
        print("  Scheduled runs now use the current, upgrade-stable path.")
    print("═" * 60)
    return _UNTRACK_IO_ERROR if errors else _UNTRACK_OK


def _run_track(target_dir: str, every_seconds: int,
               full_at: Optional[List[Tuple[int, int]]],
               budget_seconds: Optional[int],
               rotbyte_exe,
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

    # Use the imported platform constants as the single source of truth
    # (previously is_linux was recomputed from sys.platform right next to
    # the imported _IS_LINUX, which could disagree under test monkeypatching).
    is_mac = _IS_MACOS
    is_windows = _IS_WINDOWS
    is_linux = _IS_LINUX

    if not is_mac and not is_linux and not is_windows:
        print(f"Error: --track is not supported on {sys.platform}.", file=sys.stderr)
        print("  Supported platforms: macOS (launchd), Linux (systemd), Windows (Task Scheduler).",
              file=sys.stderr)
        sys.exit(1)

    # --run-on-battery only affects the Windows Task Scheduler backend; on
    # macOS/Linux it is silently ignored (launchd/systemd have no battery gate).

    dhash = _dir_hash(target_dir)

    # rotbyte_exe is an argument list from _find_rotbyte_executable().
    # A plain string ("python /path/to/rotbyte.py") is tolerated for
    # backward compatibility, but note that whitespace-splitting a string
    # cannot preserve paths that contain spaces — pass a list for those.
    if isinstance(rotbyte_exe, str):
        exe_parts = rotbyte_exe.split()
    else:
        exe_parts = list(rotbyte_exe)

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
        print("  Manifest   : auto-exported after each full scan")
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

    # A full-scan budget at or above the quick-scan interval guarantees
    # that quick scans fire while the full scan still holds the database
    # lock — each collision exits 5 having done nothing, and the operator
    # never hears about it. Warn loudly at install time, when the numbers
    # are still easy to change.
    if full_at and budget_seconds and budget_seconds >= every_seconds:
        print(f"  ! Warning: the full-scan budget "
              f"({_format_duration(budget_seconds)}) is not shorter than the "
              f"quick-scan interval ({_format_duration(every_seconds)}).",
              file=sys.stderr)
        print("  ! Quick scans that fire during a full scan will find the "
              "database locked and exit without scanning.", file=sys.stderr)
        print("  ! Consider a smaller --budget or a larger --every.",
              file=sys.stderr)
        print(file=sys.stderr)

    # Install through the platform backend. Wrap the call the same way the
    # untrack/repair verbs already do (see _run_untrack, _run_repair) so a
    # backend failure — a missing systemctl, a rejected systemctl/launchctl/
    # schtasks command, a half-written config — degrades to a friendly
    # message instead of dumping a raw traceback. The backends unlink any
    # config file they wrote before raising, so a failed install leaves
    # nothing orphaned behind.
    try:
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
    except Exception as e:  # noqa: BLE001 — platform install failure
        print(f"Error: could not install scheduled scans: {e}", file=sys.stderr)
        sys.exit(1)

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
    # Wrap discovery in the same try/except style the untrack/repair verbs
    # use so a backend failure degrades to an empty result plus a friendly
    # message instead of a traceback out of --status.
    try:
        if is_mac:
            return launchd._discover_launchd()
        # Linux → systemd. On distros without systemd (Alpine/OpenRC,
        # Void/runit, Devuan) shelling out to systemctl would raise
        # FileNotFoundError; a preflight turns that into one actionable line.
        if shutil.which("systemctl") is None:
            print("systemd not found; scheduled scans require systemd "
                  "(or a manual cron entry).", file=sys.stderr)
            return {}
        return systemd._discover_systemd()
    except Exception as e:  # noqa: BLE001 — platform discovery failure
        print(f"Error: could not read scheduled scans: {e}", file=sys.stderr)
        return {}


# Exit-code values returned by _run_untrack[_all]. These mirror the
# documented public exit codes (0 / 6 / 7) so the caller in rotbyte.py
# can hand them straight to sys.exit.
_UNTRACK_OK = 0
_UNTRACK_IO_ERROR = 6
_UNTRACK_INTERNAL = 7


def _run_untrack(target_dir: str) -> int:
    """Remove scheduled rotbyte runs for ``target_dir``.

    Returns the process exit code: 0 on success (including the friendly
    "no schedule found" no-op), 6 if any platform command failed, 7 if
    the platform isn't supported or an internal error occurred.
    """
    from . import launchd, schtasks, systemd

    if _IS_MACOS:
        backend_label = "launchd"
        try:
            removed, errors = launchd._uninstall_launchd(target_dir)
        except Exception as e:  # noqa: BLE001 — platform uninstall failure
            print(f"Error: launchd uninstall failed: {e}", file=sys.stderr)
            return _UNTRACK_INTERNAL
    elif _IS_LINUX:
        backend_label = "systemd"
        try:
            removed, errors = systemd._uninstall_systemd(target_dir)
        except Exception as e:  # noqa: BLE001
            print(f"Error: systemd uninstall failed: {e}", file=sys.stderr)
            return _UNTRACK_INTERNAL
    elif _IS_WINDOWS:
        backend_label = "Task Scheduler"
        try:
            removed, errors = schtasks._uninstall_schtasks(target_dir)
        except Exception as e:  # noqa: BLE001
            print(f"Error: Task Scheduler uninstall failed: {e}", file=sys.stderr)
            return _UNTRACK_INTERNAL
    else:
        print(f"Error: --untrack is not supported on {sys.platform}.", file=sys.stderr)
        return _UNTRACK_INTERNAL

    if not removed and not errors:
        print(f"  No scheduled run found for {target_dir}")
        return _UNTRACK_OK

    if removed:
        print(f"  ✓ Removed scheduled run for {target_dir} ({backend_label})")
        for name in removed:
            print(f"      {name}")

    if errors:
        for msg in errors:
            print(f"  ! {msg}", file=sys.stderr)
        return _UNTRACK_IO_ERROR

    return _UNTRACK_OK


def _run_untrack_all() -> int:
    """Remove every scheduled rotbyte run on the system.

    Returns the process exit code: 0 on success (including the friendly
    "nothing to remove" no-op), 6 if any platform command failed, 7 if
    the platform isn't supported or an internal error occurred.
    """
    from . import launchd, schtasks, systemd

    if _IS_MACOS:
        backend_label = "launchd"
        try:
            removed, errors = launchd._uninstall_all_launchd()
        except Exception as e:  # noqa: BLE001
            print(f"Error: launchd uninstall failed: {e}", file=sys.stderr)
            return _UNTRACK_INTERNAL
    elif _IS_LINUX:
        backend_label = "systemd"
        try:
            removed, errors = systemd._uninstall_all_systemd()
        except Exception as e:  # noqa: BLE001
            print(f"Error: systemd uninstall failed: {e}", file=sys.stderr)
            return _UNTRACK_INTERNAL
    elif _IS_WINDOWS:
        backend_label = "Task Scheduler"
        try:
            removed, errors = schtasks._uninstall_all_schtasks()
        except Exception as e:  # noqa: BLE001
            print(f"Error: Task Scheduler uninstall failed: {e}", file=sys.stderr)
            return _UNTRACK_INTERNAL
    else:
        print(f"Error: --untrack-all is not supported on {sys.platform}.",
              file=sys.stderr)
        return _UNTRACK_INTERNAL

    if not removed and not errors:
        print("  No scheduled runs found.")
        return _UNTRACK_OK

    for name in removed:
        print(f"  ✓ Removed: {name}")
    if errors:
        for msg in errors:
            print(f"  ! {msg}", file=sys.stderr)

    n = len(removed)
    plural = "s" if n != 1 else ""
    print(f"\n  Removed {n} scheduled run{plural} ({backend_label})")

    return _UNTRACK_IO_ERROR if errors else _UNTRACK_OK


def _run_clear_logs() -> int:
    """Clear rotbyte's scheduler log files.

    Only macOS keeps rotbyte-owned log files on disk (launchd's
    ``StandardOutPath``): the live log of each still-installed job is
    truncated in place and rotated generations plus orphaned logs left
    behind by past ``--untrack`` / ``--repair`` are deleted. On Linux the
    scheduled-scan output lives in the systemd journal, and on Windows in
    Task Scheduler's history — rotbyte owns no files there, so both
    platforms print where to look instead of clearing anything.

    Returns the process exit code: 0 on success (including the friendly
    "nothing to clear" and informational no-ops), 6 if any file operation
    failed, 7 if the platform isn't supported.
    """
    from . import launchd

    if _IS_MACOS:
        try:
            truncated, deleted, errors = launchd._clear_launchd_logs()
        except Exception as e:  # noqa: BLE001 — platform log-clear failure
            print(f"Error: could not clear launchd logs: {e}", file=sys.stderr)
            return _UNTRACK_INTERNAL
    elif _IS_LINUX:
        # systemd routes scheduled-scan output to the shared user journal,
        # not to files rotbyte manages. Vacuuming the journal here would be
        # both surprising and overreaching, so point at journalctl instead.
        print("  On Linux, scheduled-scan logs live in the systemd journal, "
              "not in files rotbyte manages — nothing to clear.")
        print("  Inspect:  journalctl --user -u 'rotbyte-*'")
        print("  Vacuum:   journalctl --user --vacuum-time=7d")
        return _UNTRACK_OK
    elif _IS_WINDOWS:
        # Task Scheduler captures each run's output to its own Task History,
        # not to a rotbyte-owned file, so there is nothing on disk to clear.
        print("  On Windows, scheduled-scan output lives in Task Scheduler's "
              "history, not in files rotbyte manages — nothing to clear.")
        print("  Inspect:  Task Scheduler → Task Scheduler Library → rotbyte "
              "→ History")
        return _UNTRACK_OK
    else:
        print(f"Error: --clear-logs is not supported on {sys.platform}.",
              file=sys.stderr)
        return _UNTRACK_INTERNAL

    if not truncated and not deleted and not errors:
        print("  No rotbyte logs found to clear.")
        return _UNTRACK_OK

    for path in truncated:
        print(f"  ✓ Cleared (in place): {path}")
    for path in deleted:
        print(f"  ✓ Removed: {path}")
    if errors:
        for msg in errors:
            print(f"  ! {msg}", file=sys.stderr)

    n = len(truncated) + len(deleted)
    plural = "s" if n != 1 else ""
    print(f"\n  Cleared {n} log file{plural} (launchd)")

    return _UNTRACK_IO_ERROR if errors else _UNTRACK_OK
