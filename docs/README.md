# rotbyte documentation

These Markdown guides are the **single source of truth** — edit them here.
They are also readable in the terminal via `rotbyte --docs <topic>` and, for the
Unix guides, as man pages.

| Guide | Terminal | Also as |
|-------|----------|---------|
| [Email Notification Setup](email-notification-setup.md) | `rotbyte --docs notify` | `man rotbyte-notify` |
| [macOS Permissions (Full Disk Access)](macos-permissions.md) | `rotbyte --docs permissions` | `man rotbyte-permissions` |
| [Windows Task Scheduler](windows-task-scheduler.md) | `rotbyte --docs scheduler` | — (no `man` on Windows) |

`rotbyte --docs` with no topic lists them. Aliases like `email`, `macos`, and
`windows` resolve to the guides above.

## For maintainers

The files in this folder are the source of truth. Everything else is **derived**
by [`generate-man.sh`](../generate-man.sh) (run it after editing any guide):

- `_rotbyte/docs/*.md` — byte-identical copies bundled inside the package so
  `rotbyte --docs` works on Homebrew, pipx, and pip. A test
  (`test_bundled_copies_match_source_of_truth`) fails if they drift from these.
- `man/rotbyte-notify.7`, `man/rotbyte-permissions.7` — section-7 man pages
  generated with `pandoc`, committed so no build-time pandoc dependency is
  needed. Regenerate after bumping `VERSION` in `rotbyte.py` (it is stamped
  into each page's `.TH` line).

Do not hand-edit the derived files; your changes will be overwritten on the next
`generate-man.sh` run. See [`CLAUDE.md`](../CLAUDE.md) for the full workflow.
