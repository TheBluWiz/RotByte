"""In-tool documentation topics (`rotbyte --docs [TOPIC]`).

The setup guides ship inside the package (``_rotbyte/docs/*.md``) so they
travel with every install method — Homebrew, pipx, pip — and stay version-
matched to the binary that prints them. This mirrors ``git help <topic>``:
the terminal is where a CLI user already is, and unlike man pages it works
on Windows too (where the scheduler guide is the relevant one).
"""

from __future__ import annotations

import importlib.resources
import pydoc
import sys
from typing import Dict, List, Optional, Tuple

# Canonical topic → (filename stem in docs/, one-line description). The topic
# keyword is the short CLI verb (`--docs notify`); the file uses a descriptive
# kebab-case name (docs/email-notification-setup.md).
_TOPICS: Dict[str, Tuple[str, str]] = {
    "notify": ("email-notification-setup",
               "Set up email notifications (Gmail, iCloud, Outlook)"),
    "permissions": ("macos-permissions",
                    "Grant macOS Full Disk Access for scanning protected folders"),
    "scheduler": ("windows-task-scheduler",
                  "Windows Task Scheduler notes for --track"),
}

# Convenience aliases so a user's first guess resolves.
_ALIASES: Dict[str, str] = {
    "email": "notify",
    "notifications": "notify",
    "macos": "permissions",
    "fda": "permissions",
    "windows": "scheduler",
    "tasks": "scheduler",
    "taskscheduler": "scheduler",
}


def _resolve(topic: str) -> Optional[str]:
    """Map a user-supplied topic (or alias) to a canonical topic, or None."""
    key = topic.strip().lower()
    if key in _TOPICS:
        return key
    return _ALIASES.get(key)


def _read_topic(topic: str) -> str:
    """Return the markdown body for a canonical topic.

    Uses importlib.resources so the lookup is correct regardless of how the
    package was installed (zip-safe, prefix-relative, or a plain copy).
    """
    stem = _TOPICS[topic][0]
    return (importlib.resources.files("_rotbyte")
            .joinpath("docs", f"{stem}.md").read_text(encoding="utf-8"))


def _topic_lines() -> List[str]:
    """Formatted ``  topic   description`` lines for the topic listing."""
    width = max(len(t) for t in _TOPICS)
    return [f"  {t.ljust(width)}   {desc}" for t, (stem, desc) in _TOPICS.items()]


def run_docs(topic: Optional[str]) -> int:
    """Print a documentation topic, or list topics when ``topic`` is falsy.

    Returns a process exit code: 0 on success (including the listing), 1 for
    an unknown topic. The doc body is sent through ``pydoc.pager`` so it
    pages when stdout is a terminal and prints plainly otherwise; the listing
    and error text always go straight to stdout/stderr, never the pager.
    """
    if not topic:
        print("Available help topics (rotbyte --docs <topic>):\n")
        for line in _topic_lines():
            print(line)
        return 0

    canonical = _resolve(topic)
    if canonical is None:
        print(f"Error: unknown help topic '{topic}'.", file=sys.stderr)
        print("\nAvailable topics:", file=sys.stderr)
        for line in _topic_lines():
            print(line, file=sys.stderr)
        return 1

    try:
        body = _read_topic(canonical)
    except (FileNotFoundError, OSError) as e:  # bundled file missing/unreadable
        print(f"Error: could not read the '{canonical}' guide — {e}",
              file=sys.stderr)
        return 1

    pydoc.pager(body)
    return 0
