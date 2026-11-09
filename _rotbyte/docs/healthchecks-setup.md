# rotbyte — healthchecks.io Setup

Set up `rotbyte --notify healthchecks` to monitor your scans with
[healthchecks.io](https://healthchecks.io) or a self-hosted
[Healthchecks](https://github.com/healthchecks/healthchecks) instance.

Email only speaks up when a scan runs. healthchecks.io also tells you when
scans **stop running**: a Mac that's asleep or switched off, an unmounted
volume, or a schedule broken by an upgrade. Every scan pings its check, so
healthchecks.io notices when the pings stop arriving.

This is a one-time setup. It works on its own or alongside email
(`--notify email,healthchecks`; see `rotbyte --docs notify`).

## Quick start

```bash
rotbyte --notify-setup healthchecks
```

You'll be prompted for:

- **Ping endpoint.** Press Enter to accept `https://hc-ping.com`. For a
  self-hosted instance, see [Self-hosted Healthchecks](#self-hosted-healthchecks).
- **Ping key.** On healthchecks.io, open your project's **Settings** page.
  The ping key is listed there next to your project's API keys. Create one
  if the project doesn't have one yet.

Setup then sends a test ping to confirm the key works and saves the config.

**Setup session:**

```
$ rotbyte --notify-setup healthchecks

  Ping endpoint [https://hc-ping.com]:
  Ping key:

  Testing ping key... ok.
  Config saved to /Users/you/Library/Application Support/rotbyte/notify.conf
  Ping key stored in keychain (account: healthchecks@hc-ping.com)
  A 'rotbyte-setup-test' check was created to verify the key.
  It never alerts; delete it from the dashboard whenever you like.
```

The test ping creates a check named `rotbyte-setup-test`. It only receives a
*log* ping, which never changes a check's status, so it stays in the "new"
state and never alerts. You can delete it.

**Config location** (shared with [email](email-notification-setup.md); each
backend has its own section):

- macOS: `~/Library/Application Support/rotbyte/notify.conf`
- Linux: `~/.config/rotbyte/notify.conf` (or `$XDG_CONFIG_HOME/rotbyte/notify.conf`)
- Windows: `%USERPROFILE%\.config\rotbyte\notify.conf`

**Where the ping key is stored.** Like the SMTP password, it goes into the
platform credential store:

- macOS: Keychain
- Windows: Credential Manager
- Linux: libsecret, via `secret-tool`

If none of these is available, the key is saved in `notify.conf` with `0600`
permissions and setup prints a warning. Treat the key as a secret: anyone who
has it can ping your project's checks, including sending fake "success" pings.

---

## Usage

Add `--notify healthchecks` to any scan, or to `--track` so every scheduled
scan reports:

```bash
# One-off scan
rotbyte --check --notify healthchecks /Volumes/Media

# Scheduled scans, with both email and healthchecks.io
rotbyte --track --every 1h --full-at 2h --budget 2h \
        --notify email,healthchecks /Volumes/Media
```

`rotbyte --track-setup` also asks whether to ping healthchecks.io.

---

## How it works

**One check per directory and scan type.** Each tracked directory gets two
checks, one for quick scans and one for full scans:

```
rotbyte-media-quick-1a2b3c4d     quick scans of /Volumes/Media
rotbyte-media-full-1a2b3c4d      full re-verifies (--check / --due)
```

- **Name part.** The directory name, folded to the characters healthchecks.io
  allows in a slug.
- **Hash part.** The same 8-character hash that names the directory's
  launchd, systemd, or Task Scheduler jobs. Two directories with the same
  name still get separate checks.

A broken nightly full scan can't hide behind healthy hourly quick scans,
because they report to different checks.

**Checks are created automatically** on their first ping, using
healthchecks.io's auto-provisioning (`?create=1`). `rotbyte --track` prints
the names of the checks it will use, and `rotbyte --status` lists them for
each tracked directory.

**Every run pings, whatever the outcome.** A run first sends a *start* signal.
When it finishes, it pings with rotbyte's exit code: `0` marks the check up,
anything else marks it down.

| Situation | Ping | Check |
|-----------|------|-------|
| Scan begins | `/start` | running (not sent on a directory's first scan; see below) |
| Clean scan | `/0` | up |
| Missing files | `/1` | **down** |
| Bit rot detected | `/2` | **down** |
| Scan interrupted (Ctrl-C, shutdown) | `/3` | **down** |
| Database corrupt, or made by a newer rotbyte | `/4` | **down** |
| Quick scan skipped: another rotbyte run is scanning this directory | success | up |
| Full scan skipped: another rotbyte run is scanning this directory | `/log` | unchanged; goes **down** if full scans keep getting skipped |
| Database lock file can't be opened | `/5` | **down** |
| Directory unreachable (e.g. volume not mounted) | `/6` | **down** |
| Internal error | `/7` | **down** |
| The scan never runs at all | nothing | **down** once period + grace pass |

**Start and result pings are paired** with a per-run ID, so healthchecks.io
shows how long each scan took.

**Skipped scans are treated differently by type.** A quick scan that fires
during a long full scan finds the database locked and skips. It counts as a
run, so the quick-scan check doesn't false-alarm. A full scan that's skipped
only *logs* the skip. Its check isn't reset, so a nightly full scan that keeps
missing its slot still goes down.

**Every ping carries the scan report** as its body, so the check's event log
shows what the scan found. This is the same report the email contains,
including counts, change since the last run, and duration. As with email,
**file paths are never sent**. The report names the directory and host, and
tells you to run `rotbyte --report <dir>` on that machine to list the
affected files.

**Network trouble never affects the scan.** Each ping retries a couple of
times, then gives up with a warning on stderr. rotbyte's exit code is never
changed by a failed ping.

---

## Tune each check's period and grace time

New checks start with healthchecks.io's defaults: a **period of 1 day** and a
**grace time of 1 hour**. Those defaults rarely fit:

- **The period is wrong for quick scans.** With an hourly quick scan, the
  check wouldn't notice a dead schedule for a day.
- **The grace is too short for full scans.** rotbyte sends a start signal, and
  healthchecks.io expects the matching result within the grace time. A full
  scan that runs longer than that is reported down while it's still working.

`rotbyte --track` prints suggested values for the schedule it just installed:

```
  healthchecks.io checks (created on first ping — then set these in the dashboard):
    rotbyte-media-quick-1a2b3c4d
      Period 1 hour · Grace 1 hour (more if quick scans hash many new files)
    rotbyte-media-full-1a2b3c4d
      Period 1 day · Grace 3 hours
```

The rules behind those suggestions:

| Check | Period | Grace |
|-------|--------|-------|
| quick | your `--every` interval | 1 hour; more if quick scans often hash many new files |
| full  | 1 day, or the shortest gap between your `--full-at` times | `--budget` + 1 hour; without a budget, longer than your longest full scan |

The check is created by its first ping, so it won't exist in the dashboard
until each scan type has run once. Set the values after that. For full scans
you can use a **Cron** schedule in the dashboard instead, such as `0 2 * * *`
in your time zone.

**A directory's very first scan** indexes every file, which can take hours.
rotbyte skips the start signal on that run, so a fresh check isn't marked down
during the initial index. The result ping at the end still creates the check
and records the outcome.

---

## Self-hosted Healthchecks

At the **Ping endpoint** prompt, enter your instance's `PING_ENDPOINT` URL.
This is usually your site's address followed by `/ping`, for example:

```
  Ping endpoint [https://hc-ping.com]: https://hc.example.com/ping
```

Notes:

- **Copy it from your dashboard.** The endpoint is the part of any check's
  ping URL before the UUID.
- **Trailing slash is optional.** rotbyte adds or strips it as needed.
- **Recent version required.** The instance must support slug URLs and
  auto-provisioning (`?create=1`). On an older instance, setup's test ping
  fails with HTTP 404.
- **Plain `http://` works but isn't encrypted.** The ping key would cross the
  network in the clear, and setup warns you about it.
- **Self-hosted keeps less of each ping body.** It stores 10 kB per ping by
  default (`PING_BODY_LIMIT`), compared with 100 kB on healthchecks.io.
  rotbyte's reports are only a few hundred bytes, so they fit either way.

---

## Reconfiguring

Run `rotbyte --notify-setup healthchecks` again at any time to change the
endpoint or key. Only the `[healthchecks]` section of `notify.conf` is
replaced, so your email settings are kept. Running `--notify-setup email`
likewise leaves the healthchecks.io settings alone.

To stop pinging for a tracked directory, re-run `--track` for it without
`healthchecks` in `--notify`.

## Troubleshooting

**"Testing ping key... failed. Error: HTTP 404"**

- The ping key wasn't recognized. Copy it again from the project's Settings
  page, and make sure you pasted the key itself, not a full ping URL.
- On a self-hosted instance, the server may be too old for
  auto-provisioning. See [Self-hosted Healthchecks](#self-hosted-healthchecks).

**"Testing ping key... failed. Error: HTTP 400"**

- The ping key is malformed, usually because only part of it was copied.
  healthchecks.io ping keys are 22 characters. Copy the key again.
- If you entered a custom ping endpoint, check it as well.

**The full-scan check goes down every night while the scan is running**

- The grace time is shorter than the scan. Raise it to at least your
  `--budget` plus an hour. See [Tune each check's period and
  grace time](#tune-each-checks-period-and-grace-time).

**A check goes down even though scans seem to run**

- Run `rotbyte --status`. The `Notify:` line should include `healthchecks`,
  and the `checks:` line names the checks the directory pings.
- Look for `Warning: healthchecks.io ping failed` in the scheduled-scan log:
  - macOS: `~/Library/Logs/rotbyte/`
  - Linux: `journalctl --user -u 'rotbyte-*'`
  - Windows: `%LOCALAPPDATA%\rotbyte\logs\`, or the task's history in
    Task Scheduler

**"healthchecks.io config is unavailable" in a scheduled-scan log**

- The `[healthchecks]` section is missing, or the ping key couldn't be read
  from the credential store. The scan still runs, but it can't ping. Run
  `rotbyte --notify-setup healthchecks` again.
