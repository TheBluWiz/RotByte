# rotbyte — Email Notification Setup

Set up `rotbyte --notify email` to receive email health reports after full
re-verifies and alerts when problems are found on any scan. This is a
one-time setup — once configured, notifications work automatically.

## Quick start

```bash
rotbyte --notify-setup email
```

You'll be prompted for: username, password, SMTP host, SMTP port, recipient
address (Send alerts to), and sender address (Send alerts from). The sender
address defaults to your username — set it to an alias if you want alerts to
come from a different address. A test email is sent at the end to confirm
everything works. Your credentials are saved to a local config file with
restricted permissions (0600).

**Config location:**
- macOS: `~/Library/Application Support/rotbyte/notify.conf`
- Linux: `~/.config/rotbyte/notify.conf`

---

## Provider settings

Every provider below requires an **app password** — your regular account
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

  Username (your email address): you@gmail.com
  Password / app password: abcd efgh ijkl mnop
  SMTP host (e.g. smtp.gmail.com): smtp.gmail.com
  SMTP port [587]: 587
  Send alerts to [you@gmail.com]:
  Send alerts from [you@gmail.com]:

  Testing connection... ok.
  Config saved to /Users/you/Library/Application Support/rotbyte/notify.conf
  Test email sent to you@gmail.com — check your inbox.
```

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

Your username is your **full** iCloud email address (including the domain).
Addresses ending in `@me.com` and `@mac.com` use the same server.

If you use iCloud email aliases, set "Send alerts from" to the alias address
so alerts appear to come from that address rather than your primary login.

**Setup session:**

```
$ rotbyte --notify-setup email

  Username (your email address): you@icloud.com
  Password / app password: abcd-efgh-ijkl-mnop
  SMTP host (e.g. smtp.gmail.com): smtp.mail.me.com
  SMTP port [587]: 587
  Send alerts to [you@icloud.com]:
  Send alerts from [you@icloud.com]:

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

  Username (your email address): you@outlook.com
  Password / app password: abcdefghijklmnop
  SMTP host (e.g. smtp.gmail.com): smtp-mail.outlook.com
  SMTP port [587]: 587
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
```

---

## What to expect

Full re-verifies (`--check`) always send an email. Quick scans only send
when problems are found.

Each email has a subject line that reflects one of four outcomes:

| Subject | Meaning |
|---------|---------|
| `rotbyte ✓ /path — all files OK` | Full re-verify completed clean — no bit rot, no missing files, no read errors. |
| `rotbyte ⚠ /path — N read errors` | Checksums clean, but N files could not be read. May indicate a hardware issue or permission problem. Re-run `--check` to retry. |
| `rotbyte ✗ /path — N failed, N missing` | Bit rot or missing files detected. Email body lists the affected files. |
| `rotbyte ⚠ /path — scan interrupted` | Full scan was cut short (Ctrl-C or system signal). Some files were not verified. Re-run `--check` to finish. |

The email body includes the affected file paths (for failures) or guidance on
next steps. Run `rotbyte --report` at any time for the full database view.

## Reconfiguring

Run `--notify-setup email` again at any time to update your credentials. The
config file is overwritten with the new values.

## Troubleshooting

**"Testing connection... failed."**
- Double-check your app password — regular account passwords won't work.
- Make sure 2FA / two-step verification is enabled on your account.
- Verify you're using the correct SMTP host for your provider.

**Emails going to spam**
- Check your spam/junk folder after the test email.
- Add the sending address to your contacts.

**"No notification config found"**
- Run `rotbyte --notify-setup email` to create the config file.