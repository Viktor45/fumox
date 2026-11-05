#!/usr/bin/env python3
"""Assemble CHANGELOG.md sections from a flat git-cliff draft.

Input:  lines `date|sha|category|message` on stdin (the flat-draft template
        in cliff.toml, see the "Flat draft" comment there).
Output: one `## <date> · sha-<last-commit-of-the-day>` section per day,
        Keep a Changelog categories (Added/Changed/Removed/Fixed/Security/Docs)
        inside, oldest first, the hand-editing pass then rewrites the
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
import re
import sys
from collections import OrderedDict

CATEGORIES = ["Added", "Changed", "Removed", "Fixed", "Security", "Docs"]
# Internal (chore/dependabot merges) never changes the shipped image.
DROPPED = ["Internal"]
# The date field of a draft line: the cliff template writes %Y-%m-%d.
# Everything else is the draft's header, not a commit.
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# The sha field: a full or abbreviated git object name, lowercase hex. A
# header fragment that happens to carry three pipes must not reach the
# section anchor (`## <date> · sha-<sha>`), where it would be printed as is.
SHA = re.compile(r"^[0-9a-f]{7,40}$")


def sanitize_message(message):
    """Fold a commit subject onto one line and defuse Markdown syntax.

    A subject with a raw newline or tab would split the bullet, so
    whitespace runs collapse to one space. `[`, `]`, `(` and `)` are
    backslash-escaped: a subject that carries `[text](url)` would
    otherwise be read as a Markdown link by every renderer that
    re-parses CHANGELOG.md.
    """
    message = re.sub(r"[\r\n\t ]+", " ", message).strip()
    return re.sub(r"([\[\]()])", r"\\\1", message)


def parse_draft(lines):
    """Yield (date, sha, category, message) for every draft line.

    A line is a commit only when it has all four fields, a date that
    looks like one and a sha that is a git object name. The header
    git-cliff writes above the draft has no pipes at all, but a header
    line that happens to carry three of them must not be mistaken for a
    commit.
    """
    for line in lines:
        line = line.rstrip("\r\n")
        parts = line.split("|", 3)
        if len(parts) != 4:
            continue
        date, sha, category, message = parts
        if not DATE.match(date):
            continue
        if not SHA.match(sha):
            continue
        yield date, sha, category, sanitize_message(message)


def main() -> None:
    days: "OrderedDict[str, list[tuple[str, str, str]]]" = OrderedDict()
    unknown: "OrderedDict[str, None]" = OrderedDict()
    for date, sha, category, message in parse_draft(sys.stdin):
        if category in DROPPED:
            continue
        if category not in CATEGORIES:
            # A category outside the taxonomy: it keeps its own heading
            # below, but it is worth naming, because a new category
            # usually means a new commit-prefix convention.
            unknown.setdefault(category, None)
        days.setdefault(date, []).append((sha, category, message))

    for date in sorted(days):
        # The image tag carries the sha of the LAST commit of the batch
        # (docker/metadata-action tags the built ref). Within a day the
        # draft arrives in commit order (git-cliff sorts oldest first), so
        # the last entry is the anchor; only the days themselves are
        # re-ordered here, so the sections do not depend on input order.
        commits = days[date]
        anchor = commits[-1][0]
        print(f"## {date} · sha-{anchor}\n")
        by_cat: "OrderedDict[str, list[str]]" = OrderedDict()
        for _sha, category, message in commits:
            by_cat.setdefault(category, []).append(message)
        for category in CATEGORIES:
            if category not in by_cat:
                continue
            print(f"### {category}\n")
            for message in by_cat[category]:
                print(f"- {message}")
            print()
        # Categories outside the taxonomy are printed under their own
        # heading: a commit must not disappear because its category is
        # new.
        for category, messages in by_cat.items():
            if category in CATEGORIES:
                continue
            print(f"### {category}\n")
            for message in messages:
                print(f"- {message}")
            print()

    if unknown:
        print(
            "note: categories outside the Keep a Changelog taxonomy: "
            + ", ".join(unknown)
            + " (printed under their own heading)",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
