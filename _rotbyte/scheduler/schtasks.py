"""Windows Task Scheduler XML generation, installation, and discovery."""

from __future__ import annotations

import os
import re as _re
import subprocess as _subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple


def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&apos;"))


def _generate_task_xml(description: str, command: List[str],
                       triggers_xml: str, run_on_battery: bool,
                       execution_time_limit: Optional[str] = None,
                       task_name: Optional[str] = None) -> str:
    """Generate a Windows Task Scheduler XML definition.

    `triggers_xml` is a <Triggers>...</Triggers> block the caller assembles
    (interval-based for quick scans, calendar-based for full scans).
    `execution_time_limit` is an ISO 8601 duration like "PT2H" that maps
    directly to --budget for full scans.
    `task_name` is the leaf task name (e.g. "rotbyte-quick-abc123"); when
    provided it is used to build the `<URI>` element so the XML matches
    the registered ``\\rotbyte\\<name>`` path.

    Every interpolated user-controlled value (command args, description,
    author, task name) passes through _xml_escape so a target directory
    containing ``<``, ``>``, ``&``, ``"`` or ``'`` cannot inject extra
    XML elements or attributes.
    """
    if not command:
        raise ValueError("command must not be empty")
    program = _xml_escape(command[0])
    arguments = _xml_escape(_quote_windows_args(command[1:])) if len(command) > 1 else ""
    desc = _xml_escape(description)
    author = _xml_escape(os.environ.get("USERNAME", "rotbyte"))
    uri_leaf = _xml_escape(task_name) if task_name else _xml_escape(description)
    # Default: stop after 24 hours of runtime even if the task never finished,
    # to avoid stuck tasks blocking the next schedule. Full scans override via
    # execution_time_limit when --budget is set.
    time_limit = execution_time_limit or "PT24H"
    battery_flags = (
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        if run_on_battery else
        "    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\n"
    )
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        '  <RegistrationInfo>\n'
        f'    <Description>{desc}</Description>\n'
        f'    <Author>{author}</Author>\n'
        f'    <URI>\\rotbyte\\{uri_leaf}</URI>\n'
        '  </RegistrationInfo>\n'
        f'  {triggers_xml}\n'
        '  <Principals>\n'
        '    <Principal id="Author">\n'
        '      <LogonType>InteractiveToken</LogonType>\n'
        '      <RunLevel>LeastPrivilege</RunLevel>\n'
        '    </Principal>\n'
        '  </Principals>\n'
        '  <Settings>\n'
        '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n'
        + battery_flags +
        '    <AllowHardTerminate>true</AllowHardTerminate>\n'
        '    <StartWhenAvailable>true</StartWhenAvailable>\n'
        '    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n'
        '    <AllowStartOnDemand>true</AllowStartOnDemand>\n'
        '    <Enabled>true</Enabled>\n'
        '    <Hidden>false</Hidden>\n'
        '    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n'
        '    <WakeToRun>false</WakeToRun>\n'
        f'    <ExecutionTimeLimit>{time_limit}</ExecutionTimeLimit>\n'
        '    <Priority>7</Priority>\n'
        '  </Settings>\n'
        '  <Actions Context="Author">\n'
        '    <Exec>\n'
        f'      <Command>{program}</Command>\n'
        + (f'      <Arguments>{arguments}</Arguments>\n' if arguments else '') +
        '    </Exec>\n'
        '  </Actions>\n'
        '</Task>\n'
    )


def _quote_windows_args(args: List[str]) -> str:
    """Quote a list of arguments for a Windows <Arguments> element.

    Uses the CommandLineToArgvW convention: wrap in double quotes any
    argument that contains a space or double quote, and escape embedded
    quotes by doubling backslashes + quote.
    """
    out = []
    for a in args:
        if not a:
            out.append('""')
            continue
        needs_quote = any(c in a for c in ' \t"')
        if not needs_quote:
            out.append(a)
            continue
        # Escape per MS rules
        escaped = a.replace("\\", "\\\\").replace('"', '\\"')
        out.append(f'"{escaped}"')
    return " ".join(out)


def _iso_duration(seconds: int) -> str:
    """Convert seconds to ISO 8601 duration (e.g. PT2H, PT30M, PT1H30M)."""
    hours, rem = divmod(max(seconds, 0), 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if hours:
        parts.append(f"{hours}H")
    if minutes:
        parts.append(f"{minutes}M")
    if secs and not (hours or minutes):
        parts.append(f"{secs}S")
    return "PT" + ("".join(parts) if parts else "1M")


def _parse_iso_duration(s: Optional[str]) -> Optional[int]:
    """Parse an ISO 8601 duration (PT2H30M) into seconds. Best-effort."""
    if not s or not s.startswith("PT"):
        return None
    total = 0
    for num, unit in _re.findall(r"(\d+)([HMS])", s[2:]):
        n = int(num)
        if unit == "H":
            total += n * 3600
        elif unit == "M":
            total += n * 60
        elif unit == "S":
            total += n
    return total or None


def _install_schtasks(target_dir: str, dhash: str, quick_cmd: List[str],
                      every_seconds: int, full_cmd: Optional[List[str]],
                      full_at: Optional[List[Tuple[int, int]]],
                      budget_seconds: Optional[int] = None,
                      run_on_battery: bool = False):
    """Register Windows Task Scheduler tasks under \\rotbyte\\.

    Uses `schtasks.exe /Create /XML` so the full richness of the task
    definition (ExecutionTimeLimit, battery policy, StartWhenAvailable)
    is preserved. Requires no elevated privileges for user-level tasks.
    """
    tasks_dir = os.path.join(os.environ.get("LOCALAPPDATA",
                             os.path.expanduser("~")), "rotbyte", "tasks")
    os.makedirs(tasks_dir, exist_ok=True)

    # ── Quick scan ─────────────────────────────────────────────────────
    quick_name = f"rotbyte-quick-{dhash}"
    quick_path = f"\\rotbyte\\{quick_name}"
    interval_iso = _iso_duration(every_seconds)
    # Start trigger a minute from now so the task has a concrete StartBoundary.
    start = datetime.now().replace(microsecond=0).isoformat()
    quick_triggers = (
        '<Triggers>\n'
        '    <TimeTrigger>\n'
        f'      <StartBoundary>{start}</StartBoundary>\n'
        '      <Enabled>true</Enabled>\n'
        '      <Repetition>\n'
        f'        <Interval>{interval_iso}</Interval>\n'
        '        <StopAtDurationEnd>false</StopAtDurationEnd>\n'
        '      </Repetition>\n'
        '    </TimeTrigger>\n'
        '  </Triggers>'
    )
    quick_xml = _generate_task_xml(
        f"rotbyte quick scan ({target_dir})", quick_cmd,
        quick_triggers, run_on_battery, task_name=quick_name,
    )
    quick_xml_path = os.path.join(tasks_dir, f"{quick_name}.xml")
    # schtasks expects UTF-16-LE with BOM for /XML input.
    with open(quick_xml_path, "wb") as f:
        f.write(quick_xml.encode("utf-16"))

    _subprocess.run(
        ["schtasks.exe", "/Create", "/TN", quick_path, "/XML", quick_xml_path, "/F"],
        check=True,
    )
    print(f"  ✓ Installed: {quick_path}")

    # ── Full scan ──────────────────────────────────────────────────────
    if full_cmd and full_at:
        full_name = f"rotbyte-full-{dhash}"
        full_task_path = f"\\rotbyte\\{full_name}"
        # Multiple CalendarTrigger blocks, one per clock time.
        trigger_parts = ['<Triggers>']
        for hh, mm in full_at:
            today = datetime.now().date()
            sb = f"{today.isoformat()}T{hh:02d}:{mm:02d}:00"
            trigger_parts.append(
                '    <CalendarTrigger>\n'
                f'      <StartBoundary>{sb}</StartBoundary>\n'
                '      <Enabled>true</Enabled>\n'
                '      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>\n'
                '    </CalendarTrigger>'
            )
        trigger_parts.append('  </Triggers>')
        full_triggers = "\n".join(trigger_parts)
        # Map --budget to ExecutionTimeLimit so the task auto-stops when
        # the budget is exhausted, matching launchd/systemd behavior.
        limit = _iso_duration(budget_seconds) if budget_seconds else None
        full_xml = _generate_task_xml(
            f"rotbyte full scan ({target_dir})", full_cmd,
            full_triggers, run_on_battery, execution_time_limit=limit,
            task_name=full_name,
        )
        full_xml_path = os.path.join(tasks_dir, f"{full_name}.xml")
        with open(full_xml_path, "wb") as f:
            f.write(full_xml.encode("utf-16"))
        _subprocess.run(
            ["schtasks.exe", "/Create", "/TN", full_task_path, "/XML", full_xml_path, "/F"],
            check=True,
        )
        print(f"  ✓ Installed: {full_task_path}")


def _uninstall_schtasks(target_dir: str) -> Tuple[List[str], List[str]]:
    """Delete the Task Scheduler tasks installed for a target directory.

    Returns ``(removed_task_names, error_messages)``. A pair of empty
    lists means no tasks existed for this target.
    """
    from . import _dir_hash
    dhash = _dir_hash(target_dir)
    names = [f"rotbyte-quick-{dhash}", f"rotbyte-full-{dhash}"]
    return _delete_tasks(names)


def _uninstall_all_schtasks() -> Tuple[List[str], List[str]]:
    """Delete every rotbyte task registered under ``\\rotbyte\\``."""
    from . import _dir_hash
    discovered = _discover_schtasks()
    names: List[str] = []
    for target_dir in discovered:
        dhash = _dir_hash(target_dir)
        names.extend([f"rotbyte-quick-{dhash}", f"rotbyte-full-{dhash}"])
    return _delete_tasks(names)


def _delete_tasks(names: List[str]) -> Tuple[List[str], List[str]]:
    """Issue ``schtasks /Delete /F`` for each name; aggregate results.

    Tasks that don't exist are silently ignored — schtasks reports them
    as "ERROR: The system cannot find the file specified" or similar,
    which we translate to "nothing to remove" rather than treating as
    a real failure. Anything else lands in the error list.
    """
    removed: List[str] = []
    errors: List[str] = []
    for name in names:
        task_path = f"\\rotbyte\\{name}"
        try:
            result = _subprocess.run(
                ["schtasks.exe", "/Delete", "/TN", task_path, "/F"],
                capture_output=True, text=True,
            )
        except FileNotFoundError as e:
            errors.append(f"schtasks.exe not available: {e}")
            continue
        if result.returncode == 0:
            removed.append(name)
            continue
        # Distinguish "task didn't exist" from real failures by stderr text.
        msg = ((result.stderr or "") + (result.stdout or "")).lower()
        if "cannot find" in msg or "does not exist" in msg:
            continue  # nothing to remove for this name
        errors.append(
            f"schtasks /Delete {task_path} failed: "
            f"{(result.stderr or result.stdout).strip()}"
        )
    return removed, errors


def _discover_schtasks() -> Dict[str, Dict]:
    """Query Task Scheduler for installed rotbyte tasks.

    Parses `schtasks /Query /XML` output to reconstruct per-directory
    schedule info for --status.
    """
    try:
        result = _subprocess.run(
            ["schtasks.exe", "/Query", "/TN", "\\rotbyte\\", "/XML"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return {}
    if result.returncode != 0 or not result.stdout:
        return {}

    # Output is a concatenated series of Task XML docs. Split on the
    # XML prolog to recover each one.
    docs = [d for d in _re.split(r'(?=<\?xml )', result.stdout) if d.strip()]
    import xml.etree.ElementTree as ET
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

    found: Dict[str, Dict] = {}
    for doc in docs:
        try:
            root = ET.fromstring(doc)
        except ET.ParseError:
            continue
        desc_el = root.find("t:RegistrationInfo/t:Description", ns)
        desc = desc_el.text if desc_el is not None and desc_el.text else ""
        # Description format: "rotbyte quick scan (TARGET)" / "rotbyte full scan (TARGET)"
        m = _re.match(r"rotbyte (quick|full) scan \((.+)\)", desc)
        if not m:
            continue
        kind, target = m.group(1), m.group(2)
        entry = found.setdefault(target, {"target_dir": target, "platform": "windows"})
        if kind == "quick":
            interval_el = root.find(
                "t:Triggers/t:TimeTrigger/t:Repetition/t:Interval", ns)
            entry["quick_interval"] = _parse_iso_duration(interval_el.text) if interval_el is not None else None
        else:
            times = []
            for ct in root.findall("t:Triggers/t:CalendarTrigger", ns):
                sb = ct.find("t:StartBoundary", ns)
                if sb is None or not sb.text:
                    continue
                try:
                    dt = datetime.fromisoformat(sb.text)
                    times.append((dt.hour, dt.minute))
                except ValueError:
                    continue
            entry["full_at"] = times
            limit_el = root.find("t:Settings/t:ExecutionTimeLimit", ns)
            if limit_el is not None and limit_el.text:
                entry["budget"] = _parse_iso_duration(limit_el.text)
    return found
