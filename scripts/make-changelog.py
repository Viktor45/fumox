#!/usr/bin/env python3
"""Assemble CHANGELOG.md sections from a flat git-cliff draft.

Input:  lines `date|sha|category|message` on stdin (the flat-draft template
        in cliff.toml, see the "Flat draft" comment there).
Output: one `## <date> · sha-<last-commit-of-the-day>` section per day,
        Keep a Changelog categories (Added/Changed/Removed/Fixed/Security/Docs)
        inside, oldest first; the hand-editing pass then rewrites the terse
        subjects into prose bullets.

Why a script and not a pure git-cliff template: tera cannot group by a
computed attribute (day = timestamp floored), and `group_by` on the raw
timestamp yields one group per commit.

Convention (see `.agents/AGENTS.md` → "Maintaining CHANGELOG.md"):
  - this output is the structural source of truth (anchors, dates, category
    placement); the hand-editing pass rewrites subjects only
  - output is OLDEST first (matching git-cliff's `sort_commits = "oldest"`),
    so REVERSE the dated sections when integrating into CHANGELOG.md below
    the manual `## Unreleased` block
  - new in-progress work goes into that manual Unreleased pre-block, not
    through this pipeline; pre-image sections are kept, never trimmed
"""
import re
import sys
from collections import OrderedDict

CATEGORIES = ["Added", "Changed", "Removed", "Fixed", "Security", "Docs"]
# Internal (chore/dependabot merges) never changes the shipped image
DROPPED = ["Internal"]
# The date field of a draft line (the cliff template writes %Y-%m-%d),
# everything else is the draft's header, not a commit
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# A header fragment that happens to carry three pipes must not reach the
# section anchor (`## <date> · sha-<sha>`), where it would be printed as is
SHA = re.compile(r"^[0-9a-f]{7,40}$")


def sanitize_message(message):
    """Fold a commit subject onto one line and defuse Markdown syntax.

    A raw newline or tab would split the bullet, so whitespace runs collapse
    to one space. `[`, `]`, `(` and `)` are backslash-escaped: a subject
    carrying `[text](url)` would be read as a Markdown link by renderers
    that re-parse CHANGELOG.md.
    """
    message = re.sub(r"[\r\n\t ]+", " ", message).strip()
    return re.sub(r"([\[\]()])", r"\\\1", message)


def parse_draft(lines):
    """Yield (date, sha, category, message) for every draft line.

    The checks below are not paranoia: the header git-cliff writes above the
    draft has no pipes at all, but a header line that happens to carry three
    must not be mistaken for a commit.
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
            # A new category usually means a new commit-prefix convention, so
            # it is named in the note below instead of being dropped
            unknown.setdefault(category, None)
        days.setdefault(date, []).append((sha, category, message))

    for date in sorted(days):
        # The image tag carries the sha of the LAST commit of the batch
        # (docker/metadata-action tags the built ref), and within a day the
        # draft arrives in commit order (git-cliff sorts oldest first), so
        # the last entry is the anchor
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
        # A commit must not disappear because its category is new
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
