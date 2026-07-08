"""Email notifications and SMTP credential storage.

Passwords are routed through the platform credential store at setup
time: macOS Keychain (``security``), Windows Credential Manager
(``cmdkey`` + ``CredReadW`` via ctypes), Linux libsecret (``secret-tool``)
when available. Falls back to plaintext ``notify.conf`` with chmod 0600
and a stderr warning when no platform store is usable.
"""

from __future__ import annotations

import configparser
import email.mime.multipart
import email.mime.text
import html as _html
import os
import shutil
import smtplib
import socket
import subprocess as _subprocess
import sys
from typing import Dict, List, Optional, Tuple

from .helpers import _format_duration, _format_size
from .platform import _IS_MACOS, _IS_WINDOWS

# Service identifier under which we register SMTP passwords with the OS keychain.
_KEYCHAIN_SERVICE = "rotbyte-notify"


def _keychain_account(username: str, smtp_host: str) -> str:
    """Compose the per-(user, host) keychain account label.

    Distinct identifier per SMTP destination so a user can have separate
    credentials for, say, work and personal Gmail without collision.
    """
    return f"{username}@{smtp_host}"


def _keychain_set(account: str, password: str) -> Tuple[bool, str]:
    """Store ``password`` under ``account`` in the platform credential store.

    Returns ``(stored, backend)`` where ``backend`` is one of ``"keychain"``
    (macOS), ``"secret-service"`` (Linux libsecret), ``"credential-manager"``
    (Windows), or ``"plaintext"`` if no platform store was usable.

    Shells out to platform tools so rotbyte stays stdlib-only:
      - macOS:   ``security add-generic-password -U``
      - Linux:   ``secret-tool store`` (from libsecret-tools, optional)
      - Windows: ``cmdkey /generic:...``
    """
    if _IS_MACOS:
        try:
            _subprocess.run(
                ["security", "add-generic-password",
                 "-U", "-a", account, "-s", _KEYCHAIN_SERVICE,
                 "-w", password],
                check=True, capture_output=True, text=True, timeout=10,
            )
            return True, "keychain"
        except (FileNotFoundError, _subprocess.CalledProcessError,
                _subprocess.TimeoutExpired):
            return False, "plaintext"
    if _IS_WINDOWS:
        target = f"{_KEYCHAIN_SERVICE}:{account}"
        try:
            _subprocess.run(
                ["cmdkey", f"/generic:{target}", f"/user:{account}",
                 f"/pass:{password}"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            return True, "credential-manager"
        except (FileNotFoundError, _subprocess.CalledProcessError,
                _subprocess.TimeoutExpired):
            return False, "plaintext"
    # Linux (and any other POSIX): try libsecret if present, else plaintext.
    if shutil.which("secret-tool"):
        try:
            _subprocess.run(
                ["secret-tool", "store", "--label=rotbyte SMTP",
                 "service", _KEYCHAIN_SERVICE, "account", account],
                input=password, check=True, capture_output=True,
                text=True, timeout=10,
            )
            return True, "secret-service"
        except (FileNotFoundError, _subprocess.CalledProcessError,
                _subprocess.TimeoutExpired):
            pass
    return False, "plaintext"


def _keychain_get(account: str) -> Optional[str]:
    """Look up the password for ``account``. Returns None if not stored."""
    if _IS_MACOS:
        try:
            result = _subprocess.run(
                ["security", "find-generic-password",
                 "-a", account, "-s", _KEYCHAIN_SERVICE, "-w"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            # `security -w` prints the password followed by a newline.
            return result.stdout.rstrip("\n")
        except (FileNotFoundError, _subprocess.CalledProcessError,
                _subprocess.TimeoutExpired):
            return None
    if _IS_WINDOWS:
        # Windows: cmdkey doesn't expose a read interface. Use the Win32
        # CredReadW API via ctypes; the credential blob is stored as
        # UTF-16-LE bytes.
        return _windows_credential_get(f"{_KEYCHAIN_SERVICE}:{account}")
    if shutil.which("secret-tool"):
        try:
            result = _subprocess.run(
                ["secret-tool", "lookup",
                 "service", _KEYCHAIN_SERVICE, "account", account],
                check=True, capture_output=True, text=True, timeout=10,
            )
            # `secret-tool lookup` prints the secret with no trailing newline,
            # but tolerate one anyway in case future versions add it.
            return result.stdout.rstrip("\n")
        except (FileNotFoundError, _subprocess.CalledProcessError,
                _subprocess.TimeoutExpired):
            return None
    return None


def _windows_credential_get(target: str) -> Optional[str]:
    """Read a Windows generic credential by target name via Win32 CredReadW.

    Returns the credential's password as a string, or None if the target
    is not present or the API call fails. ctypes is stdlib so this keeps
    rotbyte's zero-runtime-deps guarantee on Windows.
    """
    if not _IS_WINDOWS:
        return None
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None

    CRED_TYPE_GENERIC = 1

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    advapi32.CredReadW.restype = wintypes.BOOL
    advapi32.CredReadW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(CREDENTIAL)),
    ]
    advapi32.CredFree.restype = None
    advapi32.CredFree.argtypes = [ctypes.c_void_p]

    cred_ptr = ctypes.POINTER(CREDENTIAL)()
    if not advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(cred_ptr)):
        return None
    try:
        cred = cred_ptr.contents
        size = int(cred.CredentialBlobSize)
        if size <= 0:
            return ""
        blob = ctypes.string_at(cred.CredentialBlob, size)
        # cmdkey stores generic credentials as UTF-16-LE.
        try:
            return blob.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            return None
    finally:
        advapi32.CredFree(cred_ptr)


def _notify_config_path() -> str:
    """Return the platform-appropriate path for the notify config file."""
    if _IS_MACOS:
        base = os.path.expanduser("~/Library/Application Support/rotbyte")
    else:
        base = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
        base = os.path.join(base, "rotbyte")
    return os.path.join(base, "notify.conf")


def _load_notify_config() -> configparser.ConfigParser:
    """Load and return the notification config, or exit with an error.

    The on-disk config never contains the SMTP password directly when a
    keychain backend was usable at setup time — instead it carries a
    ``password_backend`` field naming the platform store. The password is
    fetched lazily here and merged back into the in-memory config object
    so callers can keep treating ``config["email"]["password"]`` as the
    single source of truth.
    """
    path = _notify_config_path()
    if not os.path.isfile(path):
        print(f"Error: No notification config found at {path}", file=sys.stderr)
        print("  Run `rotbyte --notify-setup email` to configure.", file=sys.stderr)
        sys.exit(1)
    # interpolation=None: values are opaque strings, and SMTP passwords may
    # legitimately contain '%' — with the default BasicInterpolation a lone
    # '%' raises InterpolationSyntaxError at *read* time, long after setup
    # appeared to succeed.
    config = configparser.ConfigParser(interpolation=None)
    config.read(path)
    if "email" not in config:
        print(f"Error: No [email] section in {path}", file=sys.stderr)
        print("  Run `rotbyte --notify-setup email` to reconfigure.", file=sys.stderr)
        sys.exit(1)
    for key in ("smtp_host", "smtp_port", "username", "to"):
        if key not in config["email"]:
            print(f"Error: Missing '{key}' in [email] section of {path}", file=sys.stderr)
            print("  Run `rotbyte --notify-setup email` to reconfigure.", file=sys.stderr)
            sys.exit(1)

    section = config["email"]
    if "password" not in section:
        backend = section.get("password_backend", "")
        if backend in ("keychain", "credential-manager", "secret-service"):
            account = _keychain_account(section["username"], section["smtp_host"])
            secret = _keychain_get(account)
            if secret is None:
                print(f"Error: Could not read SMTP password from {backend} for {account}",
                      file=sys.stderr)
                print("  Run `rotbyte --notify-setup email` to reconfigure.",
                      file=sys.stderr)
                sys.exit(1)
            section["password"] = secret
        else:
            print(f"Error: Missing 'password' in [email] section of {path}",
                  file=sys.stderr)
            print("  Run `rotbyte --notify-setup email` to reconfigure.",
                  file=sys.stderr)
            sys.exit(1)
    return config


def _run_notify_setup():
    """Interactive setup for email notifications."""
    print("═" * 60)
    print("  rotbyte — Email notification setup")
    print("═" * 60)
    print()
    print("  You'll need SMTP credentials for your email provider.")
    print("  For Gmail, use an App Password (not your account password).")
    print("  See: https://support.google.com/accounts/answer/185833")
    print()

    smtp_host = input("  SMTP host (e.g. smtp.gmail.com): ").strip()
    if not smtp_host:
        print("Error: SMTP host is required.", file=sys.stderr)
        sys.exit(1)

    smtp_port_str = input("  SMTP port [587]: ").strip()
    smtp_port = int(smtp_port_str) if smtp_port_str else 587

    username = input("  Username (your email address): ").strip()
    if not username:
        print("Error: Username is required.", file=sys.stderr)
        sys.exit(1)

    password = input("  Password / app password: ").strip()
    if not password:
        print("Error: Password is required.", file=sys.stderr)
        sys.exit(1)

    to_addr = input(f"  Send alerts to [{username}]: ").strip()
    if not to_addr:
        to_addr = username

    # Sender address may differ from the login username — e.g. iCloud
    # aliases, where mail must appear to come from the alias rather than
    # the primary login address. Defaults to the username.
    from_addr = input(f"  Send alerts from [{username}]: ").strip()
    if not from_addr:
        from_addr = username

    # Test the connection
    print()
    print("  Testing connection...", end="", flush=True)
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(username, password)

            msg = email.mime.text.MIMEText(
                "This is a test notification from rotbyte.\n\n"
                "If you received this, email notifications are working correctly.\n"
            )
            msg["Subject"] = "rotbyte: test notification"
            msg["From"] = from_addr
            msg["To"] = to_addr
            server.sendmail(from_addr, [to_addr], msg.as_string())
    except Exception as e:  # noqa: BLE001 — SMTP raises a zoo of types
        # smtplib can raise SMTPException, TimeoutError, socket.gaierror,
        # ConnectionRefusedError, ssl.SSLError, and OSError. Catch the
        # common-ancestor so the user sees a readable one-liner instead
        # of a traceback during interactive setup.
        print(f" failed.\n\n  Error: {e}", file=sys.stderr)
        sys.exit(1)
    print(" ok.")

    # Write config — try the platform credential store first so the
    # password never lands in the config file. Fall back to plaintext +
    # 0600 if no usable store is available (e.g. Linux without
    # libsecret-tools installed).
    config_path = _notify_config_path()
    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    account = _keychain_account(username, smtp_host)
    stored, backend = _keychain_set(account, password)

    config = configparser.ConfigParser(interpolation=None)
    email_section: Dict[str, str] = {
        "smtp_host": smtp_host,
        "smtp_port": str(smtp_port),
        "username": username,
        "to": to_addr,
        "from": from_addr,
    }
    if stored:
        email_section["password_backend"] = backend
    else:
        email_section["password"] = password
        email_section["password_backend"] = "plaintext"
    config["email"] = email_section
    with open(config_path, "w") as f:
        config.write(f)
    os.chmod(config_path, 0o600)

    print(f"  Config saved to {config_path}")
    if stored:
        print(f"  Password stored in {backend} (account: {account})")
    else:
        print(f"  Warning: no platform credential store available — password "
              f"saved plaintext at {config_path} (chmod 0600).",
              file=sys.stderr)
        print("  Use an app-specific password (Gmail App Password etc.) for "
              "this account, never your primary password.",
              file=sys.stderr)
    print(f"  Test email sent to {to_addr} — check your inbox.")
    print()
    print("  Usage:")
    print("    rotbyte --check --notify email /Volumes/Media")
    print("    rotbyte --track --notify email --every 1h /Volumes/Media")


def _send_email_notification(target_dir: str, failed: int, count_missing: int,
                             failed_files: List[Dict],
                             freshness: Optional[tuple] = None,
                             *,
                             elapsed_seconds: Optional[float] = None,
                             due_progress: Optional[Tuple[int, int]] = None,
                             interrupted: bool = False,
                             budget_exceeded: bool = False,
                             errors: int = 0,
                             stats: Optional[Dict] = None,
                             host: Optional[str] = None,
                             scan_time: Optional[str] = None):
    """Send an email notification summarizing a completed scan.

    Subject distinguishes two outcomes:
      - PASS: no bit rot and no missing files
      - DETECTED: failed hashes or missing files
    Interruption is appended to the subject as ``(interrupted)``. The
    sending host is appended so an alert is attributable at a glance on a
    multi-machine / NAS setup.

    ``due_progress`` is ``(done, start)`` — files verified this run out of
    those that were overdue at scan start. When present, the subject
    embeds the percentage (e.g. ``PASS 64% (30/47 due)``).

    ``budget_exceeded`` and ``errors`` affect only the body: when due
    progress is < 100%, the body explains whether the gap was the
    ``--budget`` cap or per-file read errors (distinct causes, same
    observable outcome of "files still due").

    ``stats`` is an optional per-outcome counts dict (``ok``, ``new``,
    ``updated``, ``skipped``, ``bytes_hashed``); when present it is
    rendered on every email — including clean PASS ones — so a healthy
    report carries the numbers that prove it, not just "completed cleanly".

    File paths are deliberately never included: an integrity alert routed
    through SMTP is not a private channel, and the affected paths would sit
    in the mailbox unencrypted. The body instead names the exact terminal
    command that lists them locally.

    A message is always sent as ``multipart/alternative`` (plain text +
    HTML) so terminal and rich mail clients each get an appropriate view.

    Best-effort: prints a warning on failure but never prevents the scan
    from completing with its normal exit code.
    """
    try:
        config = _load_notify_config()
    except SystemExit:
        # _load_notify_config calls sys.exit on error; during notification
        # we want to warn, not abort.
        print("  Warning: could not load email config — skipping notification.",
              file=sys.stderr)
        return

    section = config["email"]

    if host is None:
        # Attribute the alert to a machine. gethostname() can raise on a
        # misconfigured box — never let that sink the notification.
        try:
            host = socket.gethostname() or "unknown-host"
        except OSError:
            host = "unknown-host"

    has_problems = failed > 0 or count_missing > 0
    outcome = "DETECTED" if has_problems else "PASS"

    # Build subject
    subject_parts = [f"rotbyte: {outcome}"]
    if due_progress is not None:
        done, start = due_progress
        pct = (done / start * 100) if start > 0 else 100.0
        subject_parts.append(f"{pct:.0f}% ({done:,}/{start:,} due)")
    if interrupted:
        subject_parts.append("(interrupted)")
    subject = " ".join(subject_parts)
    if has_problems:
        detail = []
        if failed > 0:
            detail.append(f"bit rot in {failed} file{'s' if failed != 1 else ''}")
        if count_missing > 0:
            detail.append(f"{count_missing} file{'s' if count_missing != 1 else ''} missing")
        subject += f" — {', '.join(detail)}"
    subject += f" — {target_dir}"
    # Host trails the subject so inbox rules can group by machine without
    # disturbing the outcome/detail prefix the body mirrors.
    subject += f"  ·  {host}"

    # ── Plain-text body ────────────────────────────────────────────────
    lines: List[str] = [f"Host      : {host}"]
    if scan_time:
        lines.append(f"Scan time : {scan_time}")
    lines.append(f"Directory : {target_dir}")
    lines.append("")

    if has_problems:
        lines.append(f"rotbyte detected problems in {target_dir}:\n")
        if failed > 0:
            lines.append(f"  Bit rot detected: {failed} file{'s' if failed != 1 else ''}")
        if count_missing > 0:
            lines.append(f"  Missing files:    {count_missing}")
        lines.append("")
    else:
        lines.append(f"rotbyte scan completed cleanly for {target_dir}.\n")

    if interrupted:
        lines.append("Scan was interrupted before completion (Ctrl-C / SIGTERM).")
        lines.append("")

    counts = _stats_rows(stats, failed, count_missing)
    if counts:
        lines.append("Scan summary:")
        for label, value in counts:
            lines.append(f"  {label:<12}: {value}")
        lines.append("")

    if due_progress is not None:
        done, start = due_progress
        remaining = start - done
        pct = (done / start * 100) if start > 0 else 100.0
        lines.append(f"Due-file progress: {done:,} / {start:,} verified this run ({pct:.1f}%)")
        if remaining > 0:
            # Distinguish budget cap from per-file errors so the operator
            # knows whether to extend --budget or investigate I/O issues.
            if budget_exceeded and errors > 0:
                lines.append(f"  {remaining:,} file{'s' if remaining != 1 else ''} still due — "
                             f"time budget exhausted; {errors:,} additional read error"
                             f"{'s' if errors != 1 else ''} during scan.")
            elif budget_exceeded:
                lines.append(f"  {remaining:,} file{'s' if remaining != 1 else ''} still due — "
                             f"time budget exhausted. Consider raising `--budget`.")
            elif errors > 0:
                lines.append(f"  {remaining:,} file{'s' if remaining != 1 else ''} still due — "
                             f"{errors:,} read error{'s' if errors != 1 else ''} during scan.")
            else:
                lines.append(f"  {remaining:,} file{'s' if remaining != 1 else ''} still due.")
        lines.append("")

    if freshness is not None:
        f_total, f_verified, f_due = freshness
        f_pct = (f_verified / f_total * 100) if f_total else 0.0
        lines.append(f"Verification freshness: {f_verified:,} / {f_total:,} files verified ({f_pct:.1f}%); {f_due:,} due for re-verification")
        lines.append("")

    if elapsed_seconds is not None:
        lines.append(f"Scan duration: {_format_duration(elapsed_seconds)}")
        lines.append("")

    if has_problems:
        # Paths stay out of the email (privacy over SMTP); point at the
        # local command that lists them instead.
        lines.append(f"To list the affected files, run this on {host}:")
        lines.append(f"  rotbyte --report {target_dir}")
        lines.append("Run `rotbyte --accept <file>` after restoring a file from backup.")

    body = "\n".join(lines)
    html_body = _build_html_body(
        target_dir=target_dir, host=host, scan_time=scan_time,
        has_problems=has_problems, outcome=outcome, failed=failed,
        count_missing=count_missing, interrupted=interrupted,
        counts=counts, due_progress=due_progress, freshness=freshness,
        elapsed_seconds=elapsed_seconds,
    )

    try:
        msg = email.mime.multipart.MIMEMultipart("alternative")
        msg["Subject"] = subject
        # 'from' is optional (added by --notify-setup for alias support,
        # e.g. iCloud aliases); fall back to the login username.
        from_addr = section.get("from", "").strip() or section["username"]
        msg["From"] = from_addr
        msg["To"] = section["to"]
        # Order matters: the last part is the client's preferred rendering,
        # so HTML goes last and plain text is the graceful fallback.
        msg.attach(email.mime.text.MIMEText(body, "plain", "utf-8"))
        msg.attach(email.mime.text.MIMEText(html_body, "html", "utf-8"))

        with smtplib.SMTP(section["smtp_host"], int(section["smtp_port"]),
                          timeout=30) as server:
            server.starttls()
            server.login(section["username"], section["password"])
            server.sendmail(from_addr, [section["to"]], msg.as_string())
    except Exception as e:  # noqa: BLE001 — best-effort notification
        # smtplib/socket/ssl can raise across an entire type hierarchy.
        # Email delivery is best-effort: log and continue so a transient
        # SMTP blip never masks the real scan exit code.
        print(f"\n  Warning: failed to send email notification: {e}", file=sys.stderr)


def _stats_rows(stats: Optional[Dict], failed: int,
                count_missing: int) -> List[Tuple[str, str]]:
    """Build the (label, value) rows for the scan-summary block.

    Returns an empty list when ``stats`` is absent so callers can decide
    whether to render the block at all. Failed/missing come from the
    caller's authoritative counts, not ``stats``, so the summary always
    agrees with the outcome line above it.
    """
    if not stats:
        return []
    rows: List[Tuple[str, str]] = [
        ("Verified OK", f"{stats.get('ok', 0):,}"),
        ("New", f"{stats.get('new', 0):,}"),
        ("Updated", f"{stats.get('updated', 0):,}"),
        ("Failed", f"{failed:,}"),
        ("Missing", f"{count_missing:,}"),
        ("Skipped", f"{stats.get('skipped', 0):,}"),
    ]
    if stats.get("bytes_hashed"):
        rows.append(("Data hashed", _format_size(stats["bytes_hashed"])))
    return rows


def _build_html_body(*, target_dir: str, host: str, scan_time: Optional[str],
                     has_problems: bool, outcome: str, failed: int,
                     count_missing: int, interrupted: bool,
                     counts: List[Tuple[str, str]],
                     due_progress: Optional[Tuple[int, int]],
                     freshness: Optional[tuple],
                     elapsed_seconds: Optional[float]) -> str:
    """Render the HTML alternative part.

    Deliberately path-free, like the plain-text part. Uses only inline
    styles (many mail clients strip <style> blocks) and a restrained
    palette so it reads in both light and dark clients.
    """
    esc = _html.escape
    accent = "#c0392b" if has_problems else "#1e8449"
    banner = ("Problems detected" if has_problems
              else ("Scan interrupted" if interrupted else "Scan passed"))

    parts: List[str] = []
    parts.append('<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;'
                 'max-width:640px;margin:0 auto;color:#222;">')
    parts.append(f'<div style="background:{accent};color:#fff;padding:14px 18px;'
                 f'border-radius:6px 6px 0 0;font-size:16px;font-weight:600;">'
                 f'rotbyte — {esc(banner)}</div>')
    parts.append('<div style="border:1px solid #ddd;border-top:none;'
                 'border-radius:0 0 6px 6px;padding:16px 18px;">')

    # Metadata table
    parts.append('<table style="border-collapse:collapse;font-size:14px;margin-bottom:12px;">')
    meta_rows = [("Host", host), ("Directory", target_dir)]
    if scan_time:
        meta_rows.insert(1, ("Scan time", scan_time))
    for k, v in meta_rows:
        parts.append(f'<tr><td style="padding:2px 12px 2px 0;color:#777;">{esc(k)}</td>'
                     f'<td style="padding:2px 0;"><code>{esc(str(v))}</code></td></tr>')
    parts.append('</table>')

    if has_problems:
        detail = []
        if failed > 0:
            detail.append(f"bit rot in {failed} file{'s' if failed != 1 else ''}")
        if count_missing > 0:
            detail.append(f"{count_missing} file{'s' if count_missing != 1 else ''} missing")
        parts.append(f'<p style="font-size:14px;margin:0 0 12px;">'
                     f'rotbyte detected <strong>{esc(", ".join(detail))}</strong>.</p>')
    else:
        parts.append('<p style="font-size:14px;margin:0 0 12px;">'
                     'Scan completed cleanly — no bit rot and no missing files.</p>')

    if interrupted:
        parts.append('<p style="font-size:14px;margin:0 0 12px;color:#b9770e;">'
                     'Scan was interrupted before completion (Ctrl-C / SIGTERM).</p>')

    # Counts table
    if counts:
        parts.append('<table style="border-collapse:collapse;font-size:14px;'
                     'width:100%;margin-bottom:12px;">')
        for label, value in counts:
            emphasize = label in ("Failed", "Missing") and value not in ("0", "0,")
            style = f'color:{accent};font-weight:600;' if emphasize else ''
            parts.append(f'<tr><td style="padding:4px 12px 4px 0;border-bottom:1px solid #eee;">'
                         f'{esc(label)}</td>'
                         f'<td style="padding:4px 0;border-bottom:1px solid #eee;'
                         f'text-align:right;{style}">{esc(value)}</td></tr>')
        parts.append('</table>')

    # Progress / freshness / duration
    detail_lines: List[str] = []
    if due_progress is not None:
        done, start = due_progress
        pct = (done / start * 100) if start > 0 else 100.0
        detail_lines.append(f"Due-file progress: {done:,} / {start:,} verified this run ({pct:.1f}%)")
    if freshness is not None:
        f_total, f_verified, f_due = freshness
        f_pct = (f_verified / f_total * 100) if f_total else 0.0
        detail_lines.append(f"Verification freshness: {f_verified:,} / {f_total:,} "
                            f"verified ({f_pct:.1f}%); {f_due:,} due for re-verification")
    if elapsed_seconds is not None:
        detail_lines.append(f"Scan duration: {_format_duration(elapsed_seconds)}")
    for dl in detail_lines:
        parts.append(f'<p style="font-size:13px;color:#555;margin:2px 0;">{esc(dl)}</p>')

    if has_problems:
        parts.append('<div style="margin-top:14px;padding:12px;background:#f7f7f7;'
                     'border-radius:4px;font-size:13px;">'
                     f'To list the affected files, run this on <strong>{esc(host)}</strong>:'
                     f'<pre style="margin:6px 0 0;font-size:13px;">'
                     f'rotbyte --report {esc(target_dir)}</pre>'
                     'After restoring a file from backup, run '
                     '<code>rotbyte --accept &lt;file&gt;</code>.</div>')

    parts.append('</div></div>')
    return "".join(parts)
