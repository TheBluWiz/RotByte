# Changelog

## 1.3.0 — 2026-07-11

### Added
- **`--help` now prints a short, task-oriented quick reference instead of the full flag dump.** It shows the handful of commands people actually reach for day to day (`--check`, `--report`, `--accept-all`, `--status`), the two setup wizards (`--track-setup`, `--notify-setup email`), and pointers to `--help-all`, `--docs`, and `man rotbyte`. The original full option list, `Examples`, and `Exit codes` are unchanged and now live behind the new `--help-all` flag (registered via argparse's own `help` action, so its output is byte-identical to the old `--help`). The short help's ANSI colors are pulled from argparse's own color theme (`_colorize`, Python 3.13+) so it matches `--help-all`'s palette exactly and respects `NO_COLOR`/`FORCE_COLOR` identically; falls back to plain text on Python <3.13 or if that private theme API ever changes shape, since `--help` must never crash
- **Shell completions (bash/zsh/fish) now cover every flag, including the new `--help-all`.** `--verify-file`, `--case-insensitive`, `--auto-export`, and `--run-on-battery` had drifted out of sync with the CLI and were missing from all three. `--scheduled` stays out on purpose — it's internal, set by `--track`
- **Added a wordmark logo to the top of the README**
- **`--docs [TOPIC]` shows the setup guides in the terminal.** The email-notification, macOS-permissions, and Windows-Task-Scheduler guides now ship *inside* the package (`_rotbyte/docs/`) instead of only living on GitHub, so they travel with every install (Homebrew, pipx, pip) and stay version-matched to the binary. `rotbyte --docs` lists the topics; `rotbyte --docs notify` (also `permissions`, `scheduler`, plus aliases like `email`/`macos`/`windows`) prints a guide, paged when stdout is a terminal. This mirrors `git help <topic>` and, unlike man pages, works on Windows too. Standalone verb — refused in combination with any other mode flag
- **Setup guides are installed on disk, not just linked from the README.** Homebrew/pip installs place the markdown guides under `share/doc/rotbyte/`, and the formula's `caveats` points at them after install (see the formula changes accompanying this release)
- **The email-notification and macOS-permissions guides are installed as section-7 man pages** (`rotbyte-notify(7)`, `rotbyte-permissions(7)`), cross-referenced from `rotbyte(1)`'s `SEE ALSO` and discoverable via `apropos rotbyte`. They are generated from the same bundled markdown by `generate-man.sh` (committed as `.7` files so no build-time pandoc dependency), and are kept as one source of truth with `--docs`. The Windows Task Scheduler guide ships via `--docs`/`share/doc` only, since `man` does not exist on Windows
- **`--clear-logs` tidies up scheduler logs.** After a `brew upgrade` leaves stale exec-error spam behind, or an `--untrack` / `--repair` strands a directory's old log, the log directory accumulates confusing files that make a later `--status` harder to read. `--clear-logs` cleans them: on macOS it truncates the live log of each still-installed scan **in place** (launchd holds the `StandardOutPath` FD open between runs, so unlinking it would leak disk until the next reload) and deletes rotated generations (`.log.1`, `.log.2`) plus any orphaned log whose plist no longer exists. Only macOS keeps rotbyte-owned log files; on Linux the scheduled-scan output lives in the systemd journal and on Windows in Task Scheduler's history, so on those platforms `--clear-logs` reports where to look (`journalctl` / Task Scheduler) rather than deleting anything. Checksum databases are never touched; exits 0 even when there is nothing to clear. Standalone verb — refused in combination with any other mode flag

## 1.2.1 — 2026-07-10

### Fixed
- **`--notify-setup email` now stores the SMTP password in the macOS Keychain instead of falling back to plaintext.** `_keychain_set` runs `security add-generic-password -w` and feeds the password over stdin, but `security` reads it via `readpassphrase(3)`, which reads from the controlling terminal (`/dev/tty`) — not our pipe — whenever a terminal is present. During interactive setup one always is, so `security` blocked on a prompt the user never sees, hit the 10-second timeout, and the password silently degraded to plaintext in `notify.conf` (`chmod 0600`) with a misleading "no platform credential store available" warning. The bug was invisible to every non-interactive test (no controlling terminal → `readpassphrase` falls back to stdin and it works), which is why it only surfaced in real use. Fixed by passing `start_new_session=True` to the subprocess so `setsid()` detaches `security` from the terminal; `readpassphrase` can no longer open `/dev/tty` and reads the piped stdin. Preserves the existing guarantee that the password never appears in `argv` (visible via `ps`)

## 1.2.0 — 2026-07-08

### Added
- **`--repair` re-points broken scheduled scans after an upgrade.** Installed launchd plists / systemd units pin an absolute interpreter + script path; a Homebrew upgrade that deletes the old path leaves every scheduled run failing silently at exec. `--repair` rewrites each installed schedule in place to the executable this rotbyte resolves to today and reloads it, preserving every flag (`--due`, `--budget`, `--notify`, `--auto-export`, …) and the target directory. Idempotent — schedules already on the current path are reported and left untouched. macOS (launchd) and Linux (systemd) rewrite in place; Windows tasks use stable paths and need no repair. The Homebrew formula's `caveats` now tells users to run it after `brew upgrade` (Homebrew sandboxes `post_install`, so it can't be automatic)
- **Notification emails are substantially more informative.** Sent as `multipart/alternative` (plain text + a formatted HTML view). Every email now names the **sending host** (in both subject and body) so an alert is attributable on a multi-machine / NAS setup, includes the **scan timestamp**, carries the full **scan summary counts** — including on clean PASS emails, which previously said only "completed cleanly" — and reports the **change since the previous run** ("bit rot 1 → 3", or a recovery "3 → 0") when it differs. For privacy, affected file **paths are never included** (an integrity alert over SMTP is not a private channel); the body instead names the exact local command — `rotbyte --report <dir>` — that lists them
- **`--status` shows the next scheduled full-scan time** and a countdown (e.g. `next 2 AM (in 6h 12m)`) for active calendar schedules
- **The terminal scan summary reports a time-budget cutoff.** A `--budget` scan that runs out of time now prints a note that not every file was verified this run — previously visible only in the email

### Changed
- **`--status` "Last" now reflects the actual last-run finish time** (from the run record) rather than the newest file-verification timestamp — a run that verified nothing new still updates it, and a run that started but never completed is shown as "in progress or interrupted" rather than silently
- **`--status` shows the `NEW` state instead of hiding it.** Newly-indexed-but-never-re-verified files were folded into the `OK` count; they now display as a distinct `N NEW` token, so files that have never actually been checked for rot are visible
- **`--report` timestamps are localized**, matching `--status` (both were reading the same stored UTC instant but rendering it in different timezones), and each FAILED entry now shows **"Tracked since"** (`first_seen`). The "not verified recently" window follows the schedule's `--due` value when one is configured (was hardcoded to 90 days), and the stale-file listing states "showing first 20 of N" instead of announcing the full count then silently printing only 10

### Internal
- Database schema **v4**: `last_run` gains `failed` / `missing` columns to carry a run's problem counts forward for the next notification's comparison. Auto-migrates in place; nullable, so a just-upgraded database reports "no prior counts" for one run rather than a bogus "was 0"

## 1.1.2 — 2026-07-07

### Fixed
- **Scheduled scans no longer break on `brew upgrade`.** `--track` baked the version-pinned Homebrew Cellar path (e.g. `/opt/homebrew/Cellar/rotbyte/1.1.0/libexec/rotbyte.py`) into launchd plists / systemd units; the next upgrade deleted that directory and every scheduled run died at exec with "[Errno 2] No such file or directory" — silently, since `--status` still reported the agent as active. Scheduler commands now rewrite Cellar paths to the upgrade-stable `opt/<package>` symlink (interpreter and script both)
- **`--status` now reports schedule health, not just load state.** A loaded job whose command no longer exists shows `BROKEN ✗` with the missing path and the remedy; a loaded job whose last run exited non-zero shows `active ⚠ (last run exited N)` (launchd `LastExitStatus`). Every tracked directory also shows its notification state, so a schedule installed without `--notify` is visible instead of silently mute
- **Linux `--status` discovery repaired** (regression from the 1.1.0 ExecStart quoting fix): discovery split `ExecStart=` on whitespace, so the quoted target path came back with literal quotes, failed `os.path.isabs()`, and the tracked directory vanished from the report; quoted flags (`--due`, `--notify`, …) were likewise unparseable. ExecStart lines are now tokenized with the inverse of the quoting rules (legacy unquoted units still parse)
- **Windows `--status` discovery repaired**: `_discover_schtasks` returned a different data shape than the renderer consumed, so installed tasks displayed as "(not configured)". It now produces the same `quick`/`full` structure as launchd/systemd, including flags recovered from the task's `<Arguments>`
- **The `from` address in `notify.conf` is honored again** (regression from the 1.1.0 notify rewrite; the v1.0.0 setup collected it for alias support and the docs still describe it). `--notify-setup email` prompts for "Send alerts from" once more, and notification emails use it as the header From and envelope sender, falling back to the login username
- **A broken email config no longer disables scheduled scanning.** `--scheduled` runs downgrade the fail-fast notify-config check to a stderr warning and scan anyway; manual runs still abort early so misconfiguration is noticed
- **SMTP passwords containing `%` no longer crash config readback** — both notify config readers/writers construct `ConfigParser(interpolation=None)`
- **Windows argument quoting corrected to CommandLineToArgvW rules**: backslashes are only doubled before quotes; the previous blanket doubling corrupted quoted paths (`"C:\\Program Files"` parsed back with doubled separators). Discovery gained the matching splitter
- **systemd install reloads once, after all unit files are written** — previously `daemon-reload` ran between the quick and full unit writes, so the full timer was enabled against a stale unit cache
- `_find_rotbyte_executable()` returns an argument list instead of a whitespace-joined string, so interpreter/script paths containing spaces survive into scheduler configs intact

### Added
- `--track` warns at install time when the full-scan `--budget` is not shorter than the quick-scan `--every` interval — that combination guarantees quick scans collide with the full scan's database lock and exit without scanning

## 1.1.1 — 2026-05-16

### Fixed
- Scheduled `--notify email` runs never sent emails. The suppression check in `_run_phases` keyed on `args.full_at`, which is a `--track` install-time flag and is not propagated into the scheduled commands the scheduler installs — so the gate evaluated `True` for every scheduled run, both quick and full. The check now keys on `args.check` and whether problems were detected: full re-verifies always send a health report, scheduled quick scans send only when failures, missing files, or interruptions are present, and manual runs continue to always send

### Tests
- `TestNotifyPartialScan` rewritten around the corrected semantics: untracked always-sends, scheduled full sends (clean and budget-capped), scheduled quick sends on missing-file problem, scheduled quick stays silent on a clean tree (5 tests total)

---

## 1.1.0 — 2026-04-18

### Security
- launchd plist generation now uses `plistlib.dumps()`; target paths containing `<`, `>`, `&`, or `"` can no longer produce malformed or injected XML
- systemd `ExecStart=` now quotes each argument per `systemd.service(5)` C-escape rules; paths with spaces no longer silently split into multiple arguments
- systemd `Description=` strips CR/LF so a newline in a target path can't inject another directive
- Task Scheduler XML `<URI>` now built from the actual task name and passed through `_xml_escape` consistently with the other user-controlled fields
- `FileLock` opens the lock file with `O_NOFOLLOW` on POSIX; a symlink at `<db>.lock` can no longer redirect the PID-record write
- SMTP credentials now stored in the OS credential store by default: macOS Keychain (`security`), Windows Credential Manager (`cmdkey` + `CredReadW` via ctypes), or Linux libsecret (`secret-tool`) when available — plaintext `notify.conf` (chmod 0600) is used only as a fallback and prints a stderr warning when it happens

### Added
- `--untrack [PATH]` removes the scheduled rotbyte runs installed for a directory (defaults to the current working directory if omitted). Path is canonicalised the same way `--track` canonicalises it at install time, so the same directory always maps to the same scheduled units. Per-platform: launchd `bootout` + plist unlink on macOS, `systemctl --user disable --now` + unit unlink + `daemon-reload` on Linux, `schtasks /Delete` on Windows. Friendly no-op (exit 0) when nothing is installed for the target.
- `--untrack-all` removes every rotbyte schedule on the machine. Discovers installed units the same way `--status` does and removes each one. Friendly no-op when nothing is installed.
- `--case-insensitive` opt-in flag normalises scanned paths to lowercase so a rename-by-case on APFS or NTFS doesn't produce phantom MISSINGs; flipping it on an existing database rewrites every tracked path on the next scan (one-way migration, documented)
- Exit codes 5 (`DB_LOCKED` — another rotbyte process holds the lock), 6 (`IO` — target unreachable, permission denied, scheduler unload/unlink failure), and 7 (`INTERNAL` — worker pool died, unexpected exception). **Minor breaking change** for callers that treated any non-zero as "corruption detected"
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
- Total: 284 passing, 3 skipped (Windows-only) on macOS/Linux

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