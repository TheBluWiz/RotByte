# Changelog

## Unreleased

### Security
- launchd plist generation now uses `plistlib.dumps()`; target paths containing `<`, `>`, `&`, or `"` can no longer produce malformed or injected XML
- systemd `ExecStart=` now quotes each argument per `systemd.service(5)` C-escape rules; paths with spaces no longer silently split into multiple arguments
- systemd `Description=` strips CR/LF so a newline in a target path can't inject another directive
- Task Scheduler XML `<URI>` now built from the actual task name and passed through `_xml_escape` consistently with the other user-controlled fields
- `FileLock` opens the lock file with `O_NOFOLLOW` on POSIX; a symlink at `<db>.lock` can no longer redirect the PID-record write
- SMTP credentials now stored in the OS credential store by default: macOS Keychain (`security`), Windows Credential Manager (`cmdkey` + `CredReadW` via ctypes), or Linux libsecret (`secret-tool`) when available — plaintext `notify.conf` (chmod 0600) is used only as a fallback and prints a stderr warning when it happens

### Added
- `--case-insensitive` opt-in flag normalises scanned paths to lowercase so a rename-by-case on APFS or NTFS doesn't produce phantom MISSINGs; flipping it on an existing database rewrites every tracked path on the next scan (one-way migration, documented)
- Exit codes 5 (`DB_LOCKED` — another rotbyte process holds the lock), 6 (`IO` — target unreachable, permission denied), and 7 (`INTERNAL` — worker pool died, unexpected exception). **Minor breaking change** for callers that treated any non-zero as "corruption detected"
- Windows `FILE_ATTRIBUTE_HIDDEN` is now honored by `--include-hidden`; the flag no longer skips only POSIX dotfiles on Windows
- Named `EXIT_*` constants exported from `rotbyte` for programmatic callers

### Changed
- `rotbyte.py` is now a thin entry point (≈1,400 lines, down from ≈3,500); implementation lives in a new internal `_rotbyte/` package (`platform`, `helpers`, `progress`, `database`, `hashing`, `notify`, `scheduler/{launchd,systemd,schtasks}`). The public `rotbyte.X` symbol surface used by integrations and tests is unchanged
- launchd log files moved from `/tmp/com.rotbyte.*.log` (volatile, unbounded) to `~/Library/Logs/rotbyte/` (persistent, size-rotated); logs over 10 MB are rotated at `--track` install time with 3 generations kept
- `hash_file()` now returns an error message on failure; the parent process aggregates per-file read errors and prints the first 10 inline with a "... N more suppressed" summary, instead of each worker spamming stderr
- `os.path.realpath()` is now cached process-wide via `functools.lru_cache` (`_resolve` in `_rotbyte.helpers`); rotbyte is one-shot so the cache is bounded
- `os.walk()` now passes an `onerror` callback so a network drive vanishing mid-scan surfaces as a stderr warning and the scan continues with what was collected, rather than aborting
- `ChecksumDB` gained a `transaction()` context manager; `run_hashing`, `detect_missing`, and `_run_accept_all` use it instead of hand-rolled begin/commit/rollback blocks
- Platform detection consolidated behind `_IS_WINDOWS` / `_IS_MACOS` / `_IS_LINUX` constants; `sys.platform` and `platform.system()` calls are no longer mixed across the codebase
- Late mid-file imports of `re`/`glob`/`plistlib`/`platform`/`subprocess`/`textwrap` hoisted to the module top
- `hash_file()` return shape changed from 4-tuple to 5-tuple (trailing error slot); direct callers must unpack the extra field

### Fixed
- Files that vanish between the prescan and hash phases are now routed to `MISSING` (which is what they are) instead of counted as read errors
- Windows Task Scheduler XML `<URI>` element no longer contains the free-form description string; it matches the registered task path
- README and man page exit-status tables updated for codes 4–7

### Documented
- Hardlinks are hashed once per link (no `(st_dev, st_ino)` dedup) — added to README as a known limitation rather than changing schema semantics
- `--case-insensitive` migration behaviour and its one-way nature called out in README
- SMTP credential storage paths (Keychain / Credential Manager / libsecret / plaintext) surfaced in `rotbyte --notify-setup` output

---

**Database rename and indexing**
- Default database file renamed from `.{dirname}_checksums.db` to `.{dirname}_rotbyte.db` for clearer tool attribution, especially on backup drives where multiple DBs may sit side by side
- Leading dot preserved (hidden on POSIX); dirname prefix retained so DBs remain distinguishable when copied
- Legacy `.{dirname}_checksums.db` files are **auto-migrated on first open** — the DB plus its `.lock`, `-wal`, `-shm`, and `.manifest` sidecars are atomically renamed via `os.replace()`, with all history preserved. A single `Renamed legacy database to …` notice is printed to stderr
- Ambiguous state (both legacy and current files present for the same sidecar) is detected and refused loudly rather than silently clobbering either side
- Custom `--db` paths are left alone — users with non-default paths manage their own renames
- New schema version **3** adds `idx_baseline_checksum`, dramatically accelerating move detection when many files are renamed or reorganized (previously O(n) per lookup → O(log n); the quadratic blow-up on large reshuffles is gone)
- `_ensure_indexes()` runs after migration so fresh databases and upgraded v1/v2 databases both end up with the same index set
- `PRAGMA optimize` is now run at close time to keep the query planner's statistics accurate as the database grows — cheap (milliseconds) and follows SQLite's recommended close-time hygiene
- Man page references updated to the new filename
- Module docstring and `--db` help text updated
- 9 new tests: fresh-DB index presence, schema v3 on new DBs, in-place v2→v3 upgrade, PRAGMA optimize no-error on close, and 5 covering the rename path (migration runs, history preserved, sidecars migrate, custom `--db` path is not touched, ambiguous state refused)

**Windows support**
- Added full Windows support. rotbyte now runs on macOS, Linux, and Windows with no runtime dependencies outside the standard library.
- File locking uses `msvcrt.locking` on Windows and `fcntl.flock` on POSIX via a unified `_try_lock`/`_unlock` shim; conditional `fcntl` import avoids the ImportError on Windows
- `SIGTERM` handler is now registered only on POSIX (Windows has no SIGTERM); `SIGINT` still works everywhere
- `--track` on Windows registers user-level Task Scheduler tasks under `\rotbyte\` via `schtasks.exe /Create /XML`; no administrator elevation required
- Generated Task XML maps `--budget` to `ExecutionTimeLimit` and sets `StartWhenAvailable=true` so missed runs catch up
- New `--run-on-battery` flag (Windows-only effect): default is to skip scheduled runs on battery power, matching typical Task Scheduler defaults; pass the flag with `--track` to override
- `--status` discovers Windows tasks via `schtasks /Query /XML` and parses the XML back into schedule summaries
- Windows log paths: `%LOCALAPPDATA%\rotbyte\logs\`; generated Task XML stored at `%LOCALAPPDATA%\rotbyte\tasks\`
- New docs page `docs/Windows Task Scheduler.md` covering inspection, uninstall, battery behavior, Controlled Folder Access, and long-path handling

**Packaging**
- Added `pyproject.toml` with a `rotbyte = rotbyte:main` console entry point; rotbyte can now be installed via `pipx install rotbyte` on any platform
- Zero runtime dependencies; Python 3.9+ only
- Single-file module layout preserved (`py-modules = ["rotbyte"]`) so the source remains one file
- Data-files entries ship the man page and shell completions for system-wide pip installs (pipx places neither — documented)

**Database durability**
- Database integrity is now verified on every invocation via `PRAGMA quick_check`
- Integrity failures exit with new code **4** (previously exit 1) and print a 3-option recovery message pointing at backups, `--import`, and starting fresh
- New `--auto-export` flag (off by default): after a successful `--check`, writes `<db_path>.manifest` atomically (tmp + rename) as a b2sum-compatible independent backup of the checksum set
- `--auto-export` persists through `--track` — the flag is embedded in the generated scheduler command so every scheduled full scan refreshes the manifest
- Cross-volume DB detection: when the database lives on a different volume than the data it tracks (the recommended durability pattern), rotbyte prints `DB on separate volume: ✓` at startup; silent when same volume, suppressed under `--quiet` and `--json`
- README gains a "Protecting the database itself" section documenting the pattern

**Documentation**
- README install section now leads with `pipx install rotbyte`; Homebrew is listed as the macOS-specific alternative that also ships the man page and completions
- Added one-line explanation of BLAKE2b choice (cryptographic strength + speed over SHA-256)
- Added "rotbyte and backups" section clarifying rotbyte is a tripwire, not a backup; recommends the 3-2-1 backup model alongside
- Scheduling section documents Windows Task Scheduler and the battery default
- Requirements line updated to reflect Python 3.9+ on macOS, Linux, or Windows
- Exit code 4 added to the exit codes table and the `--help` epilogue

**Tests**
- 38 new test functions covering the new surface
- Platform-agnostic: `_IS_WINDOWS` constant, `_quote_windows_args` (6 cases), `_iso_duration`/`_parse_iso_duration` round-trips (11 cases), `_generate_task_xml` structure and escaping (10 cases), `_try_lock`/`_unlock` shim (3 cases), `--auto-export` behavior (4 cases), integrity exit-code-4 path (1 case), cross-volume DB detection (2 cases)
- Windows-only, gated with `@pytest.mark.skipif(sys.platform != "win32")`: schtasks install→discover round-trip, `--run-on-battery` flag reaches installed XML, backslash path handling — all 3 skipped on macOS/Linux but activate automatically on a `windows-latest` CI runner
- Total: 240 passing, 3 skipped (Windows-only) on macOS/Linux

**Notifications**
- Added `--scheduled` flag (set internally by `--track`) to distinguish scheduled runs from manual ones
- `--track` now bakes `--scheduled` into stored command strings so scheduled runs are identifiable
- Scheduled partial scans (no `--full-at`) suppress email notifications with a "Skipping email notification (scheduled partial scan)" message
- Scheduled full scans (`--full-at`) always send email, even if budget-interrupted
- Manual (untracked) runs with `--notify email` always send email regardless of `--budget`
- 4 new tests covering all notification combinations: untracked always-sends, scheduled-partial suppresses, scheduled-full sends, and budget-interrupted-full sends

**Freshness stats for `--track` + `--due`**
- `--status` now shows a verification freshness summary when a tracked directory has `--due` configured: counts of files verified within the window vs. due for re-verification, plus a coverage percentage
- `--notify` email bodies now include the same freshness summary line when `--due` is active
- New `ChecksumDB.freshness_stats(prefix, days)` method returns `(total, verified_within, due)` counts for non-MISSING files, using the indexed `last_verified` column
- 13 new tests covering the DB method, `--status` output presence/absence, and email body with and without freshness data

**Verification**
- `--verify-file <path>` checks a single file against its stored baseline checksum without scanning the entire directory tree
- Database discovery checks the current working directory first, then walks up the directory tree from the file's location to find the nearest `.db` file
- Exit codes follow existing conventions: 0 (OK), 1 (error), 2 (checksum mismatch)
- New internals: `_discover_db_for_file()`, `_run_verify_file()`, `ChecksumDB.get_file_record()`, `ChecksumDB.update_last_verified()`
- 8 new tests covering verification success, bit rot detection, missing/untracked files, `last_verified` updates, and all three database discovery paths

---

## 1.0.0 — 2026-04-12

**Notifications**
- `--notify email` now sends a health report after every full re-verify (`--check`), not only when problems are found
- Four distinct email states with matching subject lines: pass (✓ all files OK), warning (⚠ N read errors), fail (✗ N failed, N missing), interrupted (⚠ scan interrupted)
- Quick scans still only notify when problems are detected
- `--notify-setup` now collects a "Send alerts from" address for custom sender and alias support; credentials include a `from` key alongside `username`, `to`, `smtp_host`, and `smtp_port`

**Documentation**
- Comprehensive documentation audit and polish pass for v1.0.0
- Consistent use of "full re-verify" throughout all docs
- Added "What to expect" section to `docs/Email Notification Setup.md` with the four notification states
- Updated `docs/macOS Permissions.md` version references to v1.0.0

---

## 0.1.1 — 2026-04-10

**Notifications**
- `--notify email` sends an alert when bit rot or missing files are detected
- `--notify-setup email` interactive SMTP configuration with test email
- Credentials stored in `~/.config/rotbyte/notify.conf` (Linux) or `~/Library/Application Support/rotbyte/notify.conf` (macOS) with 0600 permissions
- Notification is best-effort: send failures print a warning but never change the scan exit code
- `--notify` carries through `--track` into generated launchd/systemd commands
- `--status` displays notify configuration for tracked directories

**macOS Full Disk Access fix**
- `--track` now generates launchd plists that invoke Python directly instead of going through the Homebrew bash wrapper
- This fixes "authorization denied" errors on TCC-protected directories (`~/Desktop`, `~/Documents`, `~/Downloads`, `/Volumes/...`) when Full Disk Access is granted to the Python binary
- Linux (systemd) is unaffected

**Plist generation fix**
- Fixed malformed XML in generated launchd plists caused by `textwrap.dedent` with interpolated variables
- Plists now pass `plistlib` validation, fixing `--status` showing "no scheduled scans found"

**Shell completions**
- Added `--notify` and `--notify-setup` to Bash, Zsh, and Fish completions

**Documentation**
- Added macOS permissions guide (`docs/macOS Permissions.md`)
- Added email notification setup guide with Gmail, iCloud, and Outlook instructions (`docs/Email Notification Setup.md`)
- Added Notifications section to README
- Updated man page with `--notify` and `--notify-setup` entries

## 0.1.0 — 2026-04-08

Initial release.

**Core**
- BLAKE2b-512 checksums stored in a per-directory SQLite database
- Quick scans re-hash only files whose size or mtime changed; `--check` forces a full re-verify to catch silent bit rot
- Edit-aware: changed hash + changed metadata = intentional edit, not corruption
- Parallel hashing via `--workers` (defaults to CPU count)
- Interrupt-safe: Ctrl-C finishes the current batch, commits progress, and resumes on next run
- File lock prevents concurrent runs against the same database

**Verification**
- `--budget` caps wall-clock time on full scans, verifying stalest files first
- `--due` targets only files not checked within N days; combines with `--budget`
- Move detection: flags new files whose checksum matches a missing file

**Recovery**
- `--accept` re-baselines a single file after restoring from backup
- `--accept-all` clears all MISSING and FAILED records at once
- `--import` ingests existing `.b2sum`/`.b2` sidecar files, verifies them, and removes the originals

**Scheduling**
- `--track` installs native launchd (macOS) or systemd (Linux) timers with configurable `--every` and `--full-at` schedules
- `--status` shows all scheduled scans, last activity, and file health

**Output**
- `--report` prints a human-readable integrity summary
- `--json` produces machine-readable results for scripts and monitoring
- `--export` writes a b2sum-compatible plain-text manifest
- `--quiet` suppresses everything except problems (cron-friendly)
- Live progress bar with throughput stats; degrades gracefully when piped

**Other**
- `--exclude` skips directories; `--include-hidden` opts in to dotfiles
- `--db` allows a custom database location
- Shell completions for Bash, Zsh, and Fish
- Man page (`rotbyte.1`)
- Exit codes: 0 (OK), 1 (missing), 2 (bit rot), 3 (interrupted)
- Requires Python 3.9+ on macOS or Linux