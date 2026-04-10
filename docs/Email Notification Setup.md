# rotbyte — Email Notification Setup

Set up `rotbyte --notify email` to get an alert when bit rot or missing files
are detected. This is a one-time setup — once configured, notifications work
automatically on every scan.

## Quick start

```bash
rotbyte --notify-setup email
```

You'll be prompted for your SMTP host, port, username, password, and recipient
address. A test email is sent at the end to confirm everything works. Your
credentials are saved to a local config file with restricted permissions (0600).

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

  SMTP host (e.g. smtp.gmail.com): smtp.gmail.com
  SMTP port [587]: 587
  Username (your email address): you@gmail.com
  Password / app password: abcd efgh ijkl mnop
  Send alerts to [you@gmail.com]:

  Testing connection... ok.
  Config saved to /Users/you/Library/Application Support/rotbyte/notify.conf
  Test email sent to you@gmail.com — check your inbox.
```

---

### iCloud Mail

**SMTP settings:**

| Field     | Value                |
|-----------|----------------------|
| SMTP host | `smtp.mail.me.com`   |
| Port      | `587`                |
| Username  | `you@icloud.com`     |
| Password  | App password         |

Your username is your **full** iCloud email address (including the domain).
Addresses ending in `@me.com` and `@mac.com` use the same server.

**Generate an app password:**

1. Go to [appleid.apple.com](https://appleid.apple.com) and sign in
2. Go to **App-Specific Passwords**
3. Click the **+** button, enter a name like "rotbyte"
4. Copy the generated password (it includes hyphens — that's fine)

Two-factor authentication must be enabled on your Apple account.

**Setup session:**

```
$ rotbyte --notify-setup email

  SMTP host (e.g. smtp.gmail.com): smtp.mail.me.com
  SMTP port [587]: 587
  Username (your email address): you@icloud.com
  Password / app password: abcd-efgh-ijkl-mnop
  Send alerts to [you@icloud.com]:

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
  SMTP port [587]: 587
  Username (your email address): you@outlook.com
  Password / app password: abcdefghijklmnop
  Send alerts to [you@outlook.com]:

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

When everything is fine, no email is sent. When problems are found, you get a
message with the affected files and next steps.

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