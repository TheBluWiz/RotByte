"""systemd user timer/service unit generation, installation, and discovery."""

from __future__ import annotations

import glob as _glob
import os
import re as _re
import shutil as _shutil
import subprocess as _subprocess
import textwrap as _textwrap
from typing import Dict, List, Optional, Tuple

from . import (_exe_prefix_current, _exe_prefix_len, _missing_command_path,
               _parse_cmd_flags, _repair_exe_prefix)


# Actionable message when systemd isn't installed (Alpine/OpenRC, Void/runit,
# Devuan, containers, …). systemd user timers are the only backend rotbyte
# knows on Linux, so without systemctl there's nothing to install into.
_SYSTEMD_MISSING_MSG = ("systemd not found; scheduled scans require systemd "
                        "(or a manual cron entry).")


def _systemd_user_dir() -> str:
    """Return ``~/.config/systemd/user``, resolved fresh on each call.

    Kept as a function (rather than an import-time constant) so it honors a
    later-patched ``$HOME`` / ``os.path.expanduser`` — the whole test suite
    redirects HOME per-test — while still giving every function in this
    module one source of truth for the unit directory.
    """
    return os.path.expanduser("~/.config/systemd/user")


def _systemd_escape_arg(arg: str) -> str:
    """Escape a single ExecStart argument per systemd.service(5).

    systemd's command-line parser is *not* a POSIX shell — it has its own
    rules. Whitespace separates arguments, ``\\`` introduces an escape,
    and quoting with ``"..."`` lets you embed spaces. Crucially, systemd
    expands ``%`` specifiers (``%h``, ``%i``, …) and ``$VAR`` / ``${VAR}``
    references *before* argument splitting, and double-quoting does **not**
    suppress that expansion. So we must also double ``%`` → ``%%`` and
    ``$`` → ``$$`` inside the quotes, otherwise a tracked path like
    ``/backup/%h`` would silently scan ``/backup/<hostname>`` instead.

    Order matters: escape ``\\`` first (later steps must not re-escape the
    backslashes it introduces), then ``"``, then ``%``, then ``$`` — the
    ``%%``/``$$`` doubling adds only ``%``/``$`` characters, never
    backslashes or quotes, so it is safe to apply last.
    :func:`_split_exec_start` reverses the ``%%``/``$$`` doubling on read.

    Closes a prior bug where ``" ".join(command)`` let a target path with
    a space silently split into two ExecStart arguments.
    """
    return ('"' + arg.replace("\\", "\\\\").replace('"', '\\"')
            .replace("%", "%%").replace("$", "$$") + '"')


def _split_exec_start(exec_line: str) -> List[str]:
    """Tokenize an ExecStart= command line back into an argument list.

    Inverse of the ``_systemd_escape_arg`` quoting: arguments are
    whitespace-separated, ``"..."`` groups may contain spaces, and inside
    quotes ``\\\\`` and ``\\"`` are escapes. Unquoted tokens (units written
    by rotbyte ≤ 1.0, or hand-edited files) are split on whitespace as
    before.

    Each recovered token also has systemd's ``%%`` → ``%`` and ``$$`` → ``$``
    doubling reversed, undoing what :func:`_systemd_escape_arg` writes. This
    is plain systemd semantics (``%%`` always denotes a literal ``%`` and
    ``$$`` a literal ``$`` in a command line, quoted or not), so it is correct
    for legacy/hand-edited lines too, and it keeps ``--repair`` idempotent:
    without it, re-escaping a discovered arg would double the doubling on
    every repair (``%h`` → ``%%h`` → ``%%%%h`` …).

    A naive ``str.split()`` here broke --status for every unit written
    since the 1.1.0 quoting fix: the quoted target path came back as
    ``"/path"`` (quotes included), failed ``os.path.isabs()``, and the
    whole tracked directory silently vanished from the report.
    """
    args: List[str] = []
    buf: List[str] = []
    in_quotes = False
    escaped = False
    started = False
    for ch in exec_line:
        if escaped:
            buf.append(ch)
            escaped = False
        elif in_quotes and ch == "\\":
            escaped = True
        elif ch == '"':
            in_quotes = not in_quotes
            started = True
        elif ch in (" ", "\t") and not in_quotes:
            if started or buf:
                args.append("".join(buf))
                buf = []
                started = False
        else:
            buf.append(ch)
            started = True
    if started or buf:
        args.append("".join(buf))
    # Reverse systemd's %%/$$ doubling (see _systemd_escape_arg). Applied
    # per-token after unquoting; %% and $$ never introduce quotes/backslashes
    # so this can't interfere with the escapes already resolved above.
    return [a.replace("%%", "%").replace("$$", "$") for a in args]


def _systemd_escape_description(description: str) -> str:
    """Escape a single-line value for a systemd unit field (Description=).

    Strips CR/LF (which would terminate the line and let an attacker
    inject another directive) and replaces them with a space.

    Also doubles ``%`` → ``%%`` so a target path containing a specifier
    like ``%h`` shows the literal path in ``systemctl status`` instead of
    the expanded hostname — systemd applies ``%`` specifier expansion to
    Description=. ``$`` is deliberately *not* doubled here: unlike command
    settings (ExecStart=), Description= is not subject to ``$VAR``/``${VAR}``
    substitution, so doubling ``$`` would merely render a literal ``$$``.
    """
    return (description.replace("\r", " ").replace("\n", " ")
            .replace("%", "%%"))


def _generate_systemd_unit(description: str, command: List[str]) -> str:
    """Generate a systemd .service unit file."""
    exec_start = " ".join(_systemd_escape_arg(c) for c in command)
    safe_desc = _systemd_escape_description(description)
    return _textwrap.dedent(f"""\
        [Unit]
        Description={safe_desc}

        [Service]
        Type=oneshot
        ExecStart={exec_start}
        Nice=10

        [Install]
        WantedBy=default.target
    """)


def _generate_systemd_timer(description: str,
                            interval_seconds: Optional[int] = None,
                            calendar_times: Optional[List[Tuple[int, int]]] = None) -> str:
    """Generate a systemd .timer unit file."""
    if interval_seconds is not None:
        minutes = max(1, interval_seconds // 60)
        schedule = f"    OnBootSec=5min\n    OnUnitActiveSec={minutes}min"
    elif calendar_times is not None:
        entries = []
        for hour, minute in calendar_times:
            entries.append(f"    OnCalendar=*-*-* {hour:02d}:{minute:02d}:00")
        schedule = "\n".join(entries) + "\n    Persistent=true"
    else:
        raise ValueError("Must provide interval_seconds or calendar_times")

    safe_desc = _systemd_escape_description(description)
    return _textwrap.dedent(f"""\
        [Unit]
        Description={safe_desc}

        [Timer]
        {schedule}

        [Install]
        WantedBy=timers.target
    """)


def _install_systemd(target_dir: str, dhash: str, quick_cmd: List[str],
                     every_seconds: int, full_cmd: Optional[List[str]],
                     full_at: Optional[List[Tuple[int, int]]]):
    """Write and enable systemd user timer/service pairs.

    Raises RuntimeError (never a bare traceback) when systemd is absent or a
    ``systemctl`` command fails; on a systemctl failure the just-written unit
    files are unlinked so a rejected install leaves no half-configured units
    behind. The caller (_run_track) turns the RuntimeError into a friendly
    message.
    """
    # Preflight: without systemd there is no backend to install into. Fail
    # cleanly with an actionable message instead of letting subprocess raise
    # FileNotFoundError on non-systemd distros (Alpine/OpenRC, Void/runit, …).
    if _shutil.which("systemctl") is None:
        raise RuntimeError(_SYSTEMD_MISSING_MSG)

    unit_dir = _systemd_user_dir()
    os.makedirs(unit_dir, exist_ok=True)

    quick_name = f"rotbyte-quick-{dhash}"

    # Quick scan service + timer
    service_content = _generate_systemd_unit(
        f"rotbyte quick scan ({target_dir})", quick_cmd,
    )
    timer_content = _generate_systemd_timer(
        f"rotbyte quick scan timer ({target_dir})",
        interval_seconds=every_seconds,
    )

    quick_paths = [os.path.join(unit_dir, f"{quick_name}.service"),
                   os.path.join(unit_dir, f"{quick_name}.timer")]
    with open(quick_paths[0], "w") as f:
        f.write(service_content)
    with open(quick_paths[1], "w") as f:
        f.write(timer_content)

    full_name = None
    full_paths: List[str] = []
    if full_cmd and full_at:
        full_name = f"rotbyte-full-{dhash}"

        service_content = _generate_systemd_unit(
            f"rotbyte full scan ({target_dir})", full_cmd,
        )
        timer_content = _generate_systemd_timer(
            f"rotbyte full scan timer ({target_dir})",
            calendar_times=full_at,
        )

        full_paths = [os.path.join(unit_dir, f"{full_name}.service"),
                      os.path.join(unit_dir, f"{full_name}.timer")]
        with open(full_paths[0], "w") as f:
            f.write(service_content)
        with open(full_paths[1], "w") as f:
            f.write(timer_content)

    def _unlink(paths: List[str]) -> None:
        for p in paths:
            try:
                os.unlink(p)
            except OSError:
                pass

    def _run(cmd: List[str], cleanup: List[str]) -> None:
        """Run a systemctl command; on failure remove ``cleanup`` and raise."""
        result = _subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            _unlink(cleanup)
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(
                f"{' '.join(cmd)} failed (exit {result.returncode})"
                + (f": {detail}" if detail else "")
            )

    # Reload once, after every unit file is on disk, so systemd sees the
    # full unit before its enable runs (previously the reload happened
    # between the quick and full writes, leaving the full timer to be
    # enabled against a stale unit cache). A failed command unlinks the
    # units it would have activated so a partial install doesn't linger.
    _run(["systemctl", "--user", "daemon-reload"], quick_paths + full_paths)
    _run(["systemctl", "--user", "enable", "--now", f"{quick_name}.timer"],
         quick_paths + full_paths)
    print(f"  ✓ Installed: {quick_name}.timer + .service")
    if full_name:
        # Quick already enabled successfully; only the full units are the
        # unfinished part to clean up if this last step fails.
        _run(["systemctl", "--user", "enable", "--now", f"{full_name}.timer"],
             full_paths)
        print(f"  ✓ Installed: {full_name}.timer + .service")


def _uninstall_systemd(target_dir: str) -> Tuple[List[str], List[str]]:
    """Disable and delete the systemd user units for a target directory.

    Returns ``(removed_unit_names, error_messages)``. A pair of empty
    lists means no units existed for this target.
    """
    from . import _dir_hash
    dhash = _dir_hash(target_dir)
    names = [f"rotbyte-quick-{dhash}", f"rotbyte-full-{dhash}"]
    return _disable_and_unlink(names)


def _uninstall_all_systemd() -> Tuple[List[str], List[str]]:
    """Disable and delete every ``rotbyte-*`` systemd user unit pair."""
    unit_dir = _systemd_user_dir()
    timers = sorted(_glob.glob(os.path.join(unit_dir, "rotbyte-*.timer")))
    names = [os.path.basename(t)[: -len(".timer")] for t in timers]
    return _disable_and_unlink(names)


def _disable_and_unlink(names: List[str]) -> Tuple[List[str], List[str]]:
    """Stop, disable, and remove a list of systemd user timer/service pairs.

    Per-unit disable failures are best-effort (the timer may already be
    stopped); only ``unlink`` failures count as errors. A single
    ``daemon-reload`` runs at the end if anything was actually removed,
    so systemd forgets the deleted units.
    """
    unit_dir = _systemd_user_dir()
    removed: List[str] = []
    errors: List[str] = []
    any_unlinked = False
    for name in names:
        timer = os.path.join(unit_dir, f"{name}.timer")
        service = os.path.join(unit_dir, f"{name}.service")
        if not (os.path.isfile(timer) or os.path.isfile(service)):
            continue
        # Best-effort disable+stop. Ignore non-zero (timer may already
        # be stopped or never have been enabled).
        _subprocess.run(
            ["systemctl", "--user", "disable", "--now", f"{name}.timer"],
            capture_output=True, text=True,
        )
        unit_removed = False
        for path in (timer, service):
            if os.path.isfile(path):
                try:
                    os.unlink(path)
                    unit_removed = True
                    any_unlinked = True
                except OSError as e:
                    errors.append(f"could not remove {path}: {e}")
        if unit_removed:
            removed.append(name)
    if any_unlinked:
        # Reload so systemd's in-memory unit cache forgets the deleted files.
        _subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            capture_output=True, text=True,
        )
    return removed, errors


def _repair_systemd(fresh_exe: List[str]) -> Tuple[List[Tuple[str, str, str, str]],
                                                   List[str], List[str]]:
    """Rewrite the ExecStart interpreter/script prefix in every rotbyte unit.

    Returns ``(repaired, already_ok, errors)`` in the same shape as
    :func:`launchd._repair_launchd`. Only the leading interpreter/script of
    ``ExecStart=`` is replaced; the schedule (in the sibling ``.timer``),
    the flags, and the target directory are preserved. A single
    ``daemon-reload`` runs at the end when anything changed so systemd
    forgets the stale ExecStart.
    """
    unit_dir = _systemd_user_dir()
    repaired: List[Tuple[str, str, str, str]] = []
    already_ok: List[str] = []
    errors: List[str] = []
    changed = False

    for service_path in sorted(_glob.glob(os.path.join(unit_dir, "rotbyte-*.service"))):
        name = os.path.basename(service_path).replace(".service", "")
        try:
            with open(service_path, "r") as f:
                content = f.read()
        except OSError as e:
            errors.append(f"{name}: could not read unit: {e}")
            continue

        exec_line = None
        for line in content.splitlines():
            if line.startswith("ExecStart="):
                exec_line = line[len("ExecStart="):]
                break
        if not exec_line:
            errors.append(f"{name}: no ExecStart line")
            continue

        args = _split_exec_start(exec_line)
        if not args:
            errors.append(f"{name}: empty ExecStart")
            continue

        if _exe_prefix_current(args, fresh_exe):
            already_ok.append(name)
            continue

        old_prefix = " ".join(args[: _exe_prefix_len(args)])
        new_args = _repair_exe_prefix(args, fresh_exe)
        new_exec = " ".join(_systemd_escape_arg(a) for a in new_args)
        target_dir = args[-1]

        # Replace only the ExecStart line; leave every other directive intact.
        new_lines = []
        for line in content.splitlines():
            if line.startswith("ExecStart="):
                new_lines.append("ExecStart=" + new_exec)
            else:
                new_lines.append(line)
        new_content = "\n".join(new_lines)
        if content.endswith("\n"):
            new_content += "\n"

        try:
            with open(service_path, "w") as f:
                f.write(new_content)
        except OSError as e:
            errors.append(f"{name}: could not write unit: {e}")
            continue

        repaired.append((name, target_dir, old_prefix, " ".join(fresh_exe)))
        changed = True

    if changed:
        _subprocess.run(["systemctl", "--user", "daemon-reload"],
                        capture_output=True, text=True)

    return repaired, already_ok, errors


def _discover_systemd() -> Dict[str, Dict]:
    """Parse installed systemd user units to discover tracked directories."""
    unit_dir = _systemd_user_dir()
    tracked: Dict[str, Dict] = {}

    for service_path in sorted(_glob.glob(os.path.join(unit_dir, "rotbyte-*.service"))):
        basename = os.path.basename(service_path)
        # e.g. rotbyte-quick-a1b2c3d4.service
        name = basename.replace(".service", "")

        try:
            with open(service_path, "r") as f:
                content = f.read()
        except OSError:
            continue

        # Extract ExecStart line
        exec_line = None
        for line in content.splitlines():
            if line.startswith("ExecStart="):
                exec_line = line[len("ExecStart="):]
                break
        if not exec_line:
            continue

        args = _split_exec_start(exec_line)
        target_dir = args[-1] if args else None
        if not target_dir or not os.path.isabs(target_dir):
            continue

        if target_dir not in tracked:
            tracked[target_dir] = {}

        # Check if timer is active. Guard the shell-out so a stray unit file
        # on a host without systemctl (or a systemctl that has since gone
        # away) degrades to "inactive" rather than raising FileNotFoundError
        # out of --status.
        timer_name = f"{name}.timer"
        try:
            result = _subprocess.run(
                ["systemctl", "--user", "is-active", timer_name],
                capture_output=True, text=True,
            )
            active = result.stdout.strip() == "active"
        except FileNotFoundError:
            active = False
        missing_exe = _missing_command_path(args)

        is_quick = "-quick-" in name

        if is_quick:
            # Parse interval from timer file
            timer_path = service_path.replace(".service", ".timer")
            interval = 3600  # default
            try:
                with open(timer_path, "r") as f:
                    for line in f:
                        if line.strip().startswith("OnUnitActiveSec="):
                            val = line.strip().split("=", 1)[1]
                            # Parse "60min" format
                            m = _re.match(r"(\d+)min", val)
                            if m:
                                interval = int(m.group(1)) * 60
                            break
            except OSError:
                pass
            tracked[target_dir]["quick"] = {
                "interval": interval,
                "active": active,
                "missing_exe": missing_exe,
                **_parse_cmd_flags(args),
            }
        else:
            # Parse calendar times from timer file
            timer_path = service_path.replace(".service", ".timer")
            times = []
            try:
                with open(timer_path, "r") as f:
                    for line in f:
                        if line.strip().startswith("OnCalendar="):
                            val = line.strip().split("=", 1)[1]
                            # Parse "*-*-* HH:MM:00"
                            m = _re.search(r"(\d{2}):(\d{2}):00", val)
                            if m:
                                times.append((int(m.group(1)), int(m.group(2))))
            except OSError:
                pass
            tracked[target_dir]["full"] = {
                "times": times,
                "active": active,
                "missing_exe": missing_exe,
                **_parse_cmd_flags(args),
            }

    return tracked
