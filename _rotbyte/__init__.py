"""rotbyte internal package.

This is not a stable public API — the entry point is the top-level
``rotbyte`` module. Subpackages:

- :mod:`_rotbyte.platform` — platform constants, locking primitives
- :mod:`_rotbyte.helpers`  — time, format, and parse utilities
- :mod:`_rotbyte.progress` — spinner and progress-bar widgets
- :mod:`_rotbyte.database` — SQLite-backed ChecksumDB
- :mod:`_rotbyte.hashing`  — hash pipeline, prescan, missing detection
- :mod:`_rotbyte.notify`   — SMTP notifications + keychain storage
- :mod:`_rotbyte.scheduler` — launchd / systemd / Task Scheduler install
"""
