# rotbyte — Email Notification Setup

Set up `rotbyte --notify email` to get an email health report after every
full re-verify, plus an alert when a scheduled quick scan finds a problem.
This is a one-time setup. Once it's done, notifications work automatically.

Email can only report on scans that actually run. To also be alerted when
scans **stop running** (a sleeping Mac, an unmounted volume, a schedule broken
by an upgrade), add [healthchecks.io](healthchecks-setup.md) monitoring
(`rotbyte --docs healthchecks`). You can use both at once with
`--notify email,healthchecks`.

## Quick start

```bash
rotbyte --notify-setup email
```

You'll be prompted, in order, for:

1. **SMTP host**
2. **SMTP port**, default `587`
3. **Username**, which is your email address
4. **Password**, which must be an app password (see below)
5. **Send alerts to**, which defaults to your username
6. **Send alerts from**, which defaults to your username. Set it to an alias
   if you want alerts to come from a different address.

Port `587` uses STARTTLS and port `465` uses implicit TLS. Both verify the
server's certificate. A test email is sent at the end to confirm everything
works.

**Where things are stored:**

- **SMTP password:** your OS credential store. That's the macOS Keychain
  (service `rotbyte-notify`, account `<username>@<smtp host>`), Windows
  Credential Manager, or libsecret on Linux. If no credential store is
  available, the password is saved in the config file with `0600`
  permissions, and setup prints a warning.
- **Everything else:** a config file with `0600` permissions:
  - macOS: `~/Library/Application Support/rotbyte/notify.conf`
  - Linux: `~/.config/rotbyte/notify.conf` (or `$XDG_CONFIG_HOME/rotbyte/notify.conf`)
  - Windows: `%USERPROFILE%\.config\rotbyte\notify.conf`

The same file holds the [healthchecks.io](healthchecks-setup.md) settings in
their own section. Setting up one backend never changes the other.

---

## Provider settings

Every provider below requires an **app password**. Your regular account
password won't work. Each section walks you through generating one.

---

### Gmail

**SMTP settings:**

| Field     | Value              |
|-----------|--------------------|
| SMTP host | `smtp.gmail.com`   |
| Port      | `587`              |
| Username  | `you@gmail.com`    |
| Password  | App password       |

**Generate an app password:**

1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Sign in (2-Step Verification must be enabled first)
3. Enter a name like "rotbyte" and click **Create**
4. Copy the 16-character password

**Setup session:**

```
$ rotbyte --notify-setup email

  SMTP host (e.g. smtp.gmail.com): smtp.gmail.com
  SMTP port [587]:
  Username (your email address): you@gmail.com
  Password / app password:
  Send alerts to [you@gmail.com]:
  Send alerts from [you@gmail.com]:

  Testing connection... ok.
  Config saved to /Users/you/Library/Application Support/rotbyte/notify.conf
  Password stored in keychain (account: you@gmail.com@smtp.gmail.com)
  Test email sent to you@gmail.com — check your inbox.
```

The password prompt doesn't echo what you type. Paste the app password and
press Enter.

---

### iCloud Mail

**Generate an app password:**

1. Go to [appleid.apple.com](https://appleid.apple.com) and sign in
2. Go to **App-Specific Passwords**
3. Click the **+** button, enter a name like "rotbyte"
4. Copy the generated password (it includes hyphens — that's fine)

Two-factor authentication must be enabled on your Apple account.

**SMTP settings:**

| Field     | Value                |
|-----------|----------------------|
| SMTP host | `smtp.mail.me.com`   |
| Port      | `587`                |
| Username  | `you@icloud.com`     |
| Password  | App password         |

Your username is your **full** iCloud email address, including the domain.
Addresses ending in `@me.com` and `@mac.com` use the same server.

If you use iCloud email aliases, set "Send alerts from" to the alias address
so alerts appear to come from that address rather than your primary login.

**Setup session:**

```
$ rotbyte --notify-setup email

  SMTP host (e.g. smtp.gmail.com): smtp.mail.me.com
  SMTP port [587]:
  Username (your email address): you@icloud.com
  Password / app password:
  Send alerts to [you@icloud.com]:
  Send alerts from [you@icloud.com]: alias@icloud.com

  Testing connection... ok.
```

---

### Outlook / Hotmail / Live

**SMTP settings:**

| Field     | Value                       |
|-----------|-----------------------------|
| SMTP host | `smtp-mail.outlook.com`     |
| Port      | `587`                       |
| Username  | `you@outlook.com`           |
| Password  | App password                |

This covers `@outlook.com`, `@hotmail.com`, and `@live.com` addresses.
For Microsoft 365 work/school accounts, use `smtp.office365.com` instead.

**Generate an app password:**

1. Go to [account.microsoft.com/security](https://account.microsoft.com/security)
2. Enable **Two-step verification** if not already on
3. Find **App passwords** and click **Create a new app password**
4. Copy the generated password

**Setup session:**

```
$ rotbyte --notify-setup email

  SMTP host (e.g. smtp.gmail.com): smtp-mail.outlook.com
  SMTP port [587]:
  Username (your email address): you@outlook.com
  Password / app password:
  Send alerts to [you@outlook.com]:
  Send alerts from [you@outlook.com]:

  Testing connection... ok.
```

---

## Usage

Once configured, add `--notify email` to any scan:

```bash
# One-off scan with notification
rotbyte --check --notify email /Volumes/Media

# Bake it into scheduled scans
rotbyte --track --every 1h --full-at 2h --notify email /Volumes/Media

# Email plus healthchecks.io monitoring
rotbyte --track --every 1h --full-at 2h --notify email,healthchecks /Volumes/Media
```

`rotbyte --track-setup` also asks whether to send email.

---

## What to expect

**When an email is sent:**

| Scan | Email |
|------|-------|
| Full re-verify (`--check`, or `--due`, which implies it) | Always: a health report, even when everything is clean |
| Scheduled quick scan | Only when it finds bit rot or missing files, or is interrupted |
| Quick scan you run by hand with `--notify email` | Always |

**The subject line** shows the outcome, the directory, and the machine that
sent it, so inbox rules can sort by either:

| Subject | Meaning |
|---------|---------|
| `rotbyte: PASS — /Volumes/Media  ·  mac-mini` | No bit rot and no missing files. |
| `rotbyte: DETECTED — bit rot in 3 files, 1 file missing — /Volumes/Media  ·  mac-mini` | Problems were found. |
| `rotbyte: PASS 64% (30/47 due) — /Volumes/Media  ·  mac-mini` | A `--due` scan: 30 of the 47 files that were due were verified this run. |
| `rotbyte: PASS (interrupted) — /Volumes/Media  ·  mac-mini` | The scan was cut short (Ctrl-C or a shutdown). Run it again to finish. |

**The email** is sent as both plain text and a formatted HTML view.

The body always includes:

- The host, scan time, and directory.
- A scan summary: verified OK, new, updated, failed, missing, skipped, and
  data hashed.
- The scan duration.

It also includes, when they apply:

- **The change since the previous run**, e.g. `bit rot 0 → 2`, which shows a
  regression or a recovery at a glance.
- **For `--due` scans, progress through the due files.** If some are still
  due, the email says whether the `--budget` ran out or files couldn't be
  read.
- **For `--due` scans, overall verification freshness.**

**File paths are never included.** Email isn't a private channel, and the
affected paths would sit in your mailbox unencrypted. When problems are
found, the email names the command to run on that machine to list them:

```
To list the affected files, run this on mac-mini:
  rotbyte --report /Volumes/Media
Run `rotbyte --accept <file>` after restoring a file from backup.
```

## Reconfiguring

Run `rotbyte --notify-setup email` again at any time to update your settings.
Only the `[email]` section of `notify.conf` is replaced. Any
[healthchecks.io](healthchecks-setup.md) settings are kept.

To stop emails for a tracked directory, re-run `--track` for it without
`email` in `--notify`. `rotbyte --status` shows each directory's current
`Notify:` setting.

## Troubleshooting

**"Testing connection... failed."**

- Double-check your app password. Regular account passwords won't work.
- Make sure 2FA / two-step verification is enabled on your account.
- Verify you're using the correct SMTP host and port for your provider.

**Emails going to spam**

- Check your spam/junk folder after the test email.
- Add the sending address to your contacts.

**"No notification config found" or "No [email] section"**

- Run `rotbyte --notify-setup email` to create the config.

**Scheduled emails stopped arriving**

- A clean scheduled quick scan doesn't email, so silence between full scans
  is normal. If full-scan reports stop too, the schedule itself may have
  stopped running:
  - Run `rotbyte --status` and look for `BROKEN ✗` or a failing last run.
  - If it looks broken, run `rotbyte --repair`.
- To be alerted automatically next time, add
  [healthchecks.io](healthchecks-setup.md) (`rotbyte --docs healthchecks`).
