# Windows Task Scheduler notes

`rotbyte --track` on Windows registers user-level tasks under the
`\rotbyte\` folder in Task Scheduler. No administrator elevation is
required — tasks run as the current user with `LeastPrivilege`.

## Inspecting installed tasks

```powershell
# List all rotbyte tasks
schtasks /Query /TN \rotbyte\ /FO LIST

# Show the full XML definition for one task
schtasks /Query /TN \rotbyte\rotbyte-quick-<hash> /XML
```

You can also open **Task Scheduler** (`taskschd.msc`) and browse to
**Task Scheduler Library → rotbyte**.

## Logs

rotbyte's own stdout/stderr for scheduled runs is written to:

```
%LOCALAPPDATA%\rotbyte\logs\quick-<hash>.log
%LOCALAPPDATA%\rotbyte\logs\full-<hash>.log
```

Task Scheduler also records each run's exit code and timing under
**Task History** for the task (enable the History pane in the
Task Scheduler UI if it's collapsed).

## Uninstalling

```powershell
# Remove one task
schtasks /Delete /TN \rotbyte\rotbyte-quick-<hash> /F

# Remove every rotbyte task at once
schtasks /Query /TN \rotbyte\ /FO CSV /NH | ForEach-Object {
    $name = ($_ -split ',')[0].Trim('"')
    if ($name) { schtasks /Delete /TN $name /F }
}
```

The generated task XML files live in `%LOCALAPPDATA%\rotbyte\tasks\`
and can be deleted manually after uninstall.

## Battery behavior

By default, scheduled scans are configured with
`DisallowStartIfOnBatteries=true` and `StopIfGoingOnBatteries=true`,
matching what most users expect for I/O-heavy background work on a
laptop. Pass `--run-on-battery` with `--track` if you want scans to
run regardless of power state:

```powershell
rotbyte --track --every 1h --full-at 2h --run-on-battery D:\Media
```

## Controlled Folder Access

If you use Windows Defender's Controlled Folder Access, the
`python.exe` that pipx installed rotbyte under may need to be added
to the allow-list before it can read protected directories (Desktop,
Documents, etc.). You'll see access-denied errors in rotbyte's log
if this is the case.

## Long paths

Paths longer than 260 characters require the `LongPathsEnabled`
registry value to be set (Windows 10 1607+). If you hit path-length
errors on deep hierarchies, see Microsoft's
[LongPathsEnabled documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation).
