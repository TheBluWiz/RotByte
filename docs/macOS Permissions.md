# rotbyte — macOS Permissions Guide

macOS restricts access to certain directories through a system called TCC
(Transparency, Consent, and Control). rotbyte works fine from the terminal
out of the box, but **scheduled scans via `--track`** run in the background
without a terminal, so they need explicit permission.

This guide covers the one-time setup to let rotbyte run unattended.

> **Requires rotbyte v0.1.1 or later.** Earlier versions route launchd through
> a bash wrapper, which breaks TCC attribution regardless of FDA settings.

---

## Do I need this?

**No** if you're only scanning directories that aren't TCC-protected, such as
`/data`, `/srv`, `/tmp`, or directories you created directly under `~` (e.g.
`~/media`).

**Yes** if you're scanning any of these with `--track`:
- `~/Desktop`, `~/Documents`, `~/Downloads`
- External drives (`/Volumes/...`)
- Time Machine backups
- Any directory under macOS privacy protection

If you only run rotbyte manually from the terminal, your terminal app's
existing FDA grant covers it. The steps below are only needed for scheduled
background scans.

---

## 1. Grant Full Disk Access to Python

When rotbyte runs via launchd, macOS checks whether the process performing
file I/O has Full Disk Access. Since v0.1.1, rotbyte's launchd plists invoke
Python directly (skipping the Homebrew bash wrapper), so **Python is the only
binary that needs FDA**.

### Finding the right binary

The FDA file picker only accepts Mach-O executables and `.app` bundles — not
scripts or symlinks. Homebrew's `python3` is a chain of symlinks, so you need
the real binary.

**Step 1: Find your Python version**

```bash
python3 --version
```

**Step 2: Locate the Mach-O binary**

Replace `3.14` below with your actual version:

```bash
file /opt/homebrew/Cellar/python@3.14/*/Frameworks/Python.framework/Versions/3.14/Python
```

This should report `Mach-O 64-bit executable`. That's the file you need.

If using Intel Mac, the path starts with `/usr/local/Cellar/` instead.

**Step 3: Add it in System Settings**

1. Open **System Settings → Privacy & Security → Full Disk Access**
2. Click **+** (unlock with your password if needed)
3. Press **Cmd+Shift+G** in the file picker
4. Paste the path to the `Versions/3.XX/` directory
5. Select the file named `Python` (no extension)
6. Toggle the switch **on**

Alternatively, look for `Python.app`:

```bash
ls /opt/homebrew/Cellar/python@3.14/*/Frameworks/Python.framework/Versions/3.14/Resources/Python.app
```

If it exists, you can add that instead — `.app` bundles are always accepted.

**Step 4: Restart your Mac**

TCC changes for launchd agents often don't take effect until after a full
reboot. A `launchctl unload/load` cycle is not sufficient.

### Verify it works

After restarting, regenerate the plists and test:

```bash
rotbyte --track ~/Desktop/myfiles --full-at 2h
launchctl start com.rotbyte.full.HASH
sleep 3
cat /tmp/com.rotbyte.full.HASH.log
```

(Replace `HASH` with the hash shown in the `--track` output.)

A blank log means success — `--quiet` suppresses normal output. If you see
"authorization denied," see Troubleshooting below.

> **Note:** When Homebrew upgrades Python (e.g. 3.14 → 3.15), the binary path
> changes and you'll need to re-add the new version to Full Disk Access.

---

## 2. Allow background items

Starting with macOS Ventura (13.0), the system notifies you when a new
background agent is installed. When you run `rotbyte --track`, macOS may show:

> **"rotbyte" added items that can run in the background**

Open **System Settings → General → Login Items & Extensions** and make sure
the rotbyte entries are **allowed** (toggled on). If you dismiss the
notification without allowing, the scheduled scans won't run.

---

## 3. Prevent sleep during overnight scans

Scheduled scans won't run if your Mac is asleep. If you're running overnight
full verifies (e.g. `--full-at 2h`):

- **Desktops:** System Settings → Energy → enable "Prevent automatic sleeping
  when the display is off"
- **Laptops:** System Settings → Battery → Options → enable "Wake for network
  access"

---

## 4. External volumes

External drives under `/Volumes/` may need both Full Disk Access and correct
POSIX permissions. If you see errors on an external drive:

1. Ensure FDA is granted (step 1)
2. Check ownership: `ls -la /Volumes/YourDrive/`
3. If needed: **Finder → right-click drive → Get Info → check "Ignore
   ownership on this volume"**

---

## 5. Confirm the right rotbyte is running

If you have rotbyte installed in multiple locations (e.g. a personal copy in
`~/.bin` and Homebrew in `/opt/homebrew/bin`), the plist will use whichever
`which rotbyte` finds first. Verify:

```bash
which rotbyte
```

This should return `/opt/homebrew/bin/rotbyte`. If it returns a different path,
either remove the other copy or use the full Homebrew path when running
`--track`:

```bash
/opt/homebrew/bin/rotbyte --track ~/Desktop --full-at 2h
```

After running `--track`, verify the plist calls Python directly:

```bash
grep -A5 ProgramArguments ~/Library/LaunchAgents/com.rotbyte.full.*.plist
```

You should see `python3.14` and `rotbyte.py` as separate entries — **not** a
single path to a bash wrapper script.

---

## Quick checklist

| Step | Required for | Where |
|------|-------------|-------|
| FDA for Python Mach-O binary | `--track` on protected dirs | System Settings → Privacy & Security → Full Disk Access |
| Allow background items | `--track` on macOS 13+ | System Settings → General → Login Items & Extensions |
| Restart Mac | After FDA changes | Apple menu → Restart |
| Prevent sleep | Overnight `--full-at` scans | System Settings → Energy / Battery |
| Volume ownership | External drives | Finder → Get Info on the volume |
| Correct `which rotbyte` | All `--track` usage | Remove duplicate copies from PATH |

---

## Troubleshooting

**"authorization denied" when opening the database**
→ Full Disk Access is not granted to the correct Python binary. Follow step 1
above — you need the Mach-O binary named `Python`, not a symlink or script in
`bin/`. Restart your Mac after making changes.

**Scheduled scan finds 0 files but terminal scan works**
→ Same cause — FDA is missing. The scan runs but can't read the directory.

**Python binary is grayed out in the FDA file picker**
→ You're looking at `bin/python3.XX` which is a script, not the real binary.
Use the `file` command to locate the Mach-O executable — it's named `Python`
(no extension) one level up from `bin/` in the framework directory.

**Log shows errors but `rotbyte` works fine from the terminal**
→ Your terminal has FDA (which child processes inherit), but the launchd
Python process does not. Grant FDA to Python directly and restart.

**Plist points to a personal script instead of Homebrew**
→ Check `which rotbyte`. If it resolves to `~/.bin/rotbyte` or similar instead
of `/opt/homebrew/bin/rotbyte`, the wrong version is generating the plist.
Remove the personal copy or use the full Homebrew path with `--track`.

**`--status` shows "no scheduled scans found"**
→ The plist may be malformed. Verify with:
```bash
python3 -c "import plistlib; plistlib.load(open('$HOME/Library/LaunchAgents/com.rotbyte.quick.HASH.plist', 'rb'))"
```
If this fails, update to v0.1.1+ and re-run `--track` to regenerate.

**`--full-at` consumes the directory path as a time argument**
→ `--full-at` accepts multiple values and is greedy. Put the path before it:
```bash
rotbyte --track ~/Desktop --full-at 2h
```

**FDA changes don't take effect**
→ Restart your Mac. Logging out and back in is not enough for launchd agents.