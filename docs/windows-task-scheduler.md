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

## Notifications

`--notify email` and `--notify healthchecks` work on Windows the same way
they do elsewhere. See `rotbyte --docs notify` and
`rotbyte --docs healthchecks`. Windows specifics:

- **Config file:** `%USERPROFILE%\.config\rotbyte\notify.conf`. If
  `XDG_CONFIG_HOME` is set, the file is in `rotbyte\` under that directory
  instead.
- **Secrets:** the SMTP password and the healthchecks.io ping key are stored
  in **Credential Manager** (Windows Credentials), under names starting
  with `rotbyte-notify:`.
- **Check names:** the `<hash>` in a task's name, e.g.
  `\rotbyte\rotbyte-quick-<hash>`, is the same hash that ends the directory's
  healthchecks.io check names (`rotbyte-<name>-quick-<hash>`). Use it to
  match a check to its task.
- **Battery:** a scan skipped because the laptop is on battery sends no
  ping, so its healthchecks.io check can go down. Pass `--run-on-battery`, or
  give the check enough grace time to cover the time you spend on battery.

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
