#!/usr/bin/env python3
"""Assemble CHANGELOG.md sections from a flat git-cliff draft.

Input:  lines `date|sha|category|message` on stdin (the flat-draft template
        in cliff.toml — see the "Flat draft" comment there).
Output: one `## <date> · sha-<last-commit-of-the-day>` section per day,
        Keep a Changelog categories (Added/Changed/Removed/Fixed/Docs)
        inside, oldest first — the hand-editing pass then rewrites the
        terse commit subjects and trims whatever landed before the first
        image was ever published.

Why a script and not a pure git-cliff template: tera cannot group by a
computed attribute (day = timestamp floored), and `group_by` on the raw
timestamp yields one group per commit. The flat draft carries everything
git-cliff parsed; the day-sectioning is trivial afterwards.

Post-processing convention (see `.agents/AGENTS.md` → "Maintaining
CHANGELOG.md" for the canonical rule):

  - This script's output is the structural source of truth: section
    anchors, dates, and category placement.
  - The hand-editing pass rewrites the terse commit subjects into
    prose-style multi-line bullets, one bullet per logical change.
  - The output is OLDEST first (matching git-cliff's `sort_commits =
    "oldest"`); when integrating into CHANGELOG.md, REVERSE the
    dated sections so the freshest sits directly below the manual
    `## Unreleased` block.
  - New in-progress work (commits not yet on an image tag) lives in
    a manual `## Unreleased (YYYY-MM-DD)` pre-block above the dated
    sections; the hand-editing pass adds it there, not via this
    pipeline.
  - Pre-image commits are kept (no trim); do not delete early
    sections even if they predate the first GHCR-published image.
"""
import sys
from collections import OrderedDict

CATEGORIES = ["Added", "Changed", "Removed", "Fixed", "Security", "Docs"]
# Internal (chore/dependabot merges) never changes the shipped image.
DROPPED = ["Internal"]

def main() -> None:
    days: "OrderedDict[str, list[tuple[str, str, str]]]" = OrderedDict()
    for line in sys.stdin:
        line = line.rstrip("\n")
        # The cliff.toml header precedes the draft; only the pipe-formatted
        # draft lines carry four fields.
        if not line or "|" not in line:
            continue
        date, sha, category, message = line.split("|", 3)
        if category in DROPPED:
            continue
        days.setdefault(date, []).append((sha, category, message))

    for date, commits in days.items():
        # The image tag carries the sha of the LAST commit of the batch
        # (docker/metadata-action tags the built ref).
        anchor = commits[-1][0]
        print(f"## {date} · sha-{anchor}\n")
        by_cat: "OrderedDict[str, list[str]]" = OrderedDict()
        for _sha, category, message in commits:
            by_cat.setdefault(category, []).append(message)
        for category in CATEGORIES:
            for name, messages in by_cat.items():
                if name != category:
                    continue
                print(f"### {category}\n")
                for message in messages:
                    print(f"- {message}")
                print()

if __name__ == "__main__":
    main()
