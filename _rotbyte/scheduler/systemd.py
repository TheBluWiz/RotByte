"""systemd user timer/service unit generation, installation, and discovery."""

from __future__ import annotations

import glob as _glob
import os
import re as _re
import subprocess as _subprocess
import textwrap as _textwrap
from typing import Dict, List, Optional, Tuple

from . import _parse_cmd_flags


def _systemd_escape_arg(arg: str) -> str:
    """Escape a single ExecStart argument per systemd.service(5).

    systemd's command-line parser is *not* a POSIX shell — it has its own
    rules. Whitespace separates arguments, ``\\`` introduces an escape,
    and quoting with ``"..."`` lets you embed spaces. The safe move is to
    quote every argument and backslash-escape the inner ``\\`` and ``"``
    so paths containing spaces, quotes, dollar signs, or backslashes
    survive verbatim.

    Closes a prior bug where ``" ".join(command)`` let a target path with
    a space silently split into two ExecStart arguments.
    """
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _systemd_escape_description(description: str) -> str:
    """Escape a single-line value for a systemd unit field.

    Strips CR/LF (which would terminate the line and let an attacker
    inject another directive) and replaces them with a space.
    """
    return description.replace("\r", " ").replace("\n", " ")


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
    """Write and enable systemd user timer/service pairs."""
    unit_dir = os.path.expanduser("~/.config/systemd/user")
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

    with open(os.path.join(unit_dir, f"{quick_name}.service"), "w") as f:
        f.write(service_content)
    with open(os.path.join(unit_dir, f"{quick_name}.timer"), "w") as f:
        f.write(timer_content)

    _subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    _subprocess.run(["systemctl", "--user", "enable", "--now", f"{quick_name}.timer"],
                    check=True)
    print(f"  ✓ Installed: {quick_name}.timer + .service")

    if full_cmd and full_at:
        full_name = f"rotbyte-full-{dhash}"

        service_content = _generate_systemd_unit(
            f"rotbyte full scan ({target_dir})", full_cmd,
        )
        timer_content = _generate_systemd_timer(
            f"rotbyte full scan timer ({target_dir})",
            calendar_times=full_at,
        )

        with open(os.path.join(unit_dir, f"{full_name}.service"), "w") as f:
            f.write(service_content)
        with open(os.path.join(unit_dir, f"{full_name}.timer"), "w") as f:
            f.write(timer_content)

        _subprocess.run(["systemctl", "--user", "enable", "--now", f"{full_name}.timer"],
                        check=True)
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
    unit_dir = os.path.expanduser("~/.config/systemd/user")
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
    unit_dir = os.path.expanduser("~/.config/systemd/user")
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


def _discover_systemd() -> Dict[str, Dict]:
    """Parse installed systemd user units to discover tracked directories."""
    unit_dir = os.path.expanduser("~/.config/systemd/user")
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

        args = exec_line.split()
        target_dir = args[-1] if args else None
        if not target_dir or not os.path.isabs(target_dir):
            continue

        if target_dir not in tracked:
            tracked[target_dir] = {}

        # Check if timer is active
        timer_name = f"{name}.timer"
        result = _subprocess.run(
            ["systemctl", "--user", "is-active", timer_name],
            capture_output=True, text=True,
        )
        active = result.stdout.strip() == "active"

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
                **_parse_cmd_flags(args),
            }

    return tracked
