# rotbyte — macOS Permissions Guide

macOS restricts access to certain directories and resources through a system
called TCC (Transparency, Consent, and Control). rotbyte works fine from the
terminal out of the box, but **scheduled scans via `--track`** run in the
background without a terminal, so they need explicit permission.

This guide covers everything you need to set up once so rotbyte can run
unattended.

---

## 1. Full Disk Access

**Why:** macOS protects `~/Desktop`, `~/Documents`, `~/Downloads`, and external
volumes. When rotbyte runs from a launchd agent (via `--track`), it has no
terminal parent to inherit permissions from. Without Full Disk Access, scheduled
scans silently skip protected files or fail entirely.

**When you need it:** If you're scanning any of these locations:
- `~/Desktop`, `~/Documents`, `~/Downloads`
- External drives (`/Volumes/...`)
- Time Machine backups
- Any directory under macOS privacy protection

**How to grant it:**

1. Open **System Settings → Privacy & Security → Full Disk Access**
2. Click the **+** button (you may need to unlock with your password)
3. Navigate to the Python interpreter rotbyte uses. Find it with:

   ```bash
   which python3
   ```

   Typically `/opt/homebrew/bin/python3` or
   `/opt/homebrew/Cellar/python@3.13/3.13.x/bin/python3.13`

   **Tip:** In the file picker, press `Cmd+Shift+G` to type the path directly,
   since `/opt` and `/usr/local` are hidden by default.

4. Toggle the switch **on** for the Python binary you just added

**Verify it worked:**

```bash
# This should succeed without "Operation not permitted"
python3 -c "import os; os.listdir(os.path.expanduser('~/Desktop'))"
```

> **Note:** If you're scanning directories that are _not_ TCC-protected
> (e.g. `/data`, `/srv`, a non-protected external drive), you don't need
> Full Disk Access. rotbyte will work fine without it.

---

## 2. Background Items approval

**Why:** Starting with macOS Ventura (13.0), the system notifies you when a
new Login Item or background agent is installed. When you run
`rotbyte --track`, macOS may show a notification:

> **"rotbyte" added items that can run in the background**

**What to do:** This is expected. Open **System Settings → General → Login Items
& Extensions** and make sure the rotbyte entries are **allowed** (toggled on).
If you dismiss the notification without allowing, the scheduled scans won't
run.

---

## 3. Notification permissions (for `--notify`)

The `--notify email` feature uses outbound SMTP, which doesn't require any
macOS permission. No setup needed here — it just works.

If a future version adds macOS Notification Center alerts (`--notify desktop`),
you would need to allow notifications for Python in **System Settings →
Notifications**.

---

## 4. External volumes

External drives mounted under `/Volumes/` may be subject to both Full Disk
Access restrictions and standard POSIX permissions. If you see permission
errors on an external drive:

1. Ensure Full Disk Access is granted (step 1 above)
2. Check ownership:

   ```bash
   ls -la /Volumes/YourDrive/
   ```

   If files are owned by a different user (common with drives shared between
   machines), you may need to fix ownership:

   ```bash
   sudo chown -R $(whoami) /Volumes/YourDrive/
   ```

   Or ignore ownership on the volume:
   **Finder → right-click the drive → Get Info → check "Ignore ownership on
   this volume"**

---

## 5. Energy settings (preventing sleep)

Scheduled scans won't run if your Mac is asleep. If you're running overnight
full verifies (e.g. `--full-at 2h`):

- Open **System Settings → Energy** (or Battery → Options on laptops)
- Enable **"Prevent automatic sleeping when the display is off"** (desktops)
- Or enable **"Wake for network access"** (laptops)

The launchd agent includes a `Nice` value of 10, so rotbyte runs at low
priority and won't interfere with normal use.

---

## Quick checklist

| Step | Required for | How to check |
|------|-------------|--------------|
| Full Disk Access for Python | `--track` on protected dirs | System Settings → Privacy & Security → Full Disk Access |
| Allow background items | `--track` on macOS 13+ | System Settings → General → Login Items & Extensions |
| Prevent sleep | Overnight `--full-at` scans | System Settings → Energy |
| Volume ownership | External drives | `ls -la /Volumes/YourDrive/` |

---

## Troubleshooting

**Scheduled scan runs but finds 0 files**
→ Missing Full Disk Access. The scan runs but can't read the directory. Grant
FDA to the Python binary and re-run.

**Scheduled scan doesn't run at all**
→ Check the log file: `cat /tmp/com.rotbyte.quick.HASH.log`
→ Verify the agent is loaded: `launchctl list | grep rotbyte`
→ Check if background items are allowed in System Settings.

**"Operation not permitted" in the log**
→ Full Disk Access is not granted or not taking effect. Try removing and
re-adding Python in the FDA list, then log out and back in.

**Scan works in terminal but not via `--track`**
→ Classic TCC issue. Your terminal has FDA (which child processes inherit), but
launchd does not. Grant FDA to Python directly.

**`--status` shows "no scheduled scans found"**
→ The plist file may be malformed. Check with:
```bash
python3 -c "import plistlib; plistlib.load(open('$HOME/Library/LaunchAgents/com.rotbyte.quick.HASH.plist', 'rb'))"
```
If this fails, re-run `--track` with the latest version of rotbyte to
regenerate the plist.