#!/usr/bin/env bash
#
# Regenerate every DERIVED documentation artifact from the single source of
# truth in docs/.  Run this after editing anything in docs/*.md.
#
# Source of truth (human-edited):
#   docs/email-notification-setup.md, docs/macos-permissions.md,
#   docs/windows-task-scheduler.md
#
# Derived (never hand-edit — this script overwrites them):
#   _rotbyte/docs/*.md   byte-identical copies bundled into the package so
#                        `rotbyte --docs` works on Homebrew, pipx, and pip
#   man/rotbyte-*.7      section-7 man pages (pandoc) for the notify and
#                        permissions guides; the Windows scheduler guide has
#                        no man page since man(1) does not exist on Windows
#
# A test (test_bundled_copies_match_source_of_truth) asserts docs/ and
# _rotbyte/docs/ stay byte-identical, so drift fails the suite.
#
set -euo pipefail
cd "$(dirname "$0")"

# ── 1. Sync the bundled package copies (every guide, no pandoc needed) ───────
mkdir -p _rotbyte/docs
for src in docs/*.md; do
  base="$(basename "$src")"
  [ "$base" = "README.md" ] && continue   # docs/README.md is the index, not a guide
  cp "$src" "_rotbyte/docs/${base}"
done
echo "synced _rotbyte/docs/ from docs/"

# ── 2. Man pages (Unix-relevant guides only; requires pandoc) ────────────────
if ! command -v pandoc >/dev/null 2>&1; then
  echo "warning: pandoc not found — bundled copies synced, but man pages were" \
       "NOT regenerated" >&2
  exit 0
fi

VERSION="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' rotbyte.py)"
DATE="$(date +%Y-%m-%d)"

gen_man() {
  # topic = short CLI/man name (rotbyte-<topic>.7); stem = kebab source file.
  local topic="$1" stem="$2" desc="$3"
  local name="rotbyte-${topic}"
  local out="man/${name}.7"
  # .TH title is uppercase by man convention (cf. ROTBYTE(1)); the NAME line
  # keeps the real lowercase command name for apropos. Wrap the guide body in
  # NAME + DESCRIPTION sections (dropping the source H1) so the roff carries a
  # proper NAME line instead of pandoc turning the H1 into a bogus .TH title.
  local title_uc
  title_uc="$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"
  {
    printf '# NAME\n\n%s - %s\n\n# DESCRIPTION\n\n' "$name" "$desc"
    tail -n +2 "docs/${stem}.md"
  } | pandoc -s -t man \
        --metadata title="$title_uc" \
        --metadata section=7 \
        --metadata date="$DATE" \
        --metadata footer="rotbyte ${VERSION}" \
        --metadata header="rotbyte Manual" \
        -o "$out"
  echo "wrote ${out}"
}

mkdir -p man
gen_man notify      email-notification-setup "configure email notifications for rotbyte"
gen_man permissions macos-permissions        "grant macOS Full Disk Access for rotbyte scans"
