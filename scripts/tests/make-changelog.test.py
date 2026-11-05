#!/usr/bin/env python3
"""Tests for scripts/make-changelog.py.

The generator turns git-cliff's flat `date|sha|category|message` draft into
the dated, categorised sections of CHANGELOG.md. Three things it must never
do: drop a category it does not know, crash on a malformed line, and leave
a carriage return at the end of a message.

Run directly:  python3 scripts/tests/make-changelog.test.py
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "make-changelog.py"

failures = []


def check(condition, message):
    if condition:
        print(f"  ok: {message}")
    else:
        print(f"FAIL: {message}", file=sys.stderr)
        failures.append(message)


def run(draft):
    """Feed `draft` to the generator and return (stdout, stderr, exit code)."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=draft,
        capture_output=True,
        text=True,
    )
    return proc.stdout, proc.stderr, proc.returncode


def main():
    # ── the ordinary draft ───────────────────────────────────────────
    out, err, code = run(
        "2026-08-28|9b478b9|Docs|Docs: manual update\n"
        "2026-08-28|68e4cb6|Fixed|Fix: ui soft-wrap\n"
    )
    check(code == 0, "an ordinary draft exits 0")
    check("## 2026-08-28 · sha-68e4cb6" in out, "the section header carries the last sha of the day")
    check("### Docs" in out and "- Docs: manual update" in out, "the Docs category is printed")
    check("### Fixed" in out and "- Fix: ui soft-wrap" in out, "the Fixed category is printed")

    # ── a category outside the taxonomy ──────────────────────────────
    out, err, code = run("2026-09-01|aaaaaaa|Refactor|tidy up\n")
    check(code == 0, "an unknown category does not abort the run")
    check("Refactor" in out, "an unknown category keeps its own heading")
    check("- tidy up" in out, "the commit under an unknown category is printed")
    check("Refactor" in err, "the unknown category is named on stderr")

    # ── CRLF input ───────────────────────────────────────────────────
    out, err, code = run("2026-09-01|aaaaaaa|Added|windows line endings\r\n")
    check(code == 0, "CRLF input exits 0")
    check("- windows line endings\n" in out, "CRLF input leaves no carriage return behind")

    # ── malformed lines ──────────────────────────────────────────────
    out, err, code = run(
        "# Changelog\n"
        "\n"
        "a line with one | pipe\n"
        "a line with two | pipes | here\n"
        "not a date|bbbbbbb|Added|no date\n"
        "2026-09-01|ccccccc|Added|kept\n"
    )
    check(code == 0, "malformed lines do not crash the generator")
    check("- kept" in out, "the well-formed line survives the malformed ones")
    check("no date" not in out, "a line with a date field that is not a date is skipped")

    # ── the Internal category is dropped ─────────────────────────────
    out, err, code = run(
        "2026-09-01|ddddddd|Internal|chore: bump deps\n"
        "2026-09-01|eeeeeee|Added|feat: real\n"
    )
    check(code == 0, "an Internal commit exits 0")
    check("chore: bump deps" not in out, "an Internal commit is dropped")
    check("- feat: real" in out, "the remaining commit is printed")

    # ── a sha that is not a git object name is dropped ──────────────
    # The sha anchors the section heading, so a header fragment that
    # carries pipes must not reach it verbatim.
    out, err, code = run(
        "2026-09-01|not-hex!|Added|dropped, not hex\n"
        "2026-09-01|abc|Added|dropped, too short\n"
        "2026-09-01|1234567890abcdef1234567890abcdef12345678|Added|full sha kept\n"
        "2026-09-02|ab12cd3|Added|short sha kept\n"
    )
    check(code == 0, "a draft with malformed shas exits 0")
    check("dropped, not hex" not in out, "a non-hex sha field is dropped")
    check("dropped, too short" not in out, "a sha shorter than 7 hex digits is dropped")
    check("- full sha kept" in out, "a full 40-hex sha survives")
    check("sha-1234567890abcdef1234567890abcdef12345678" in out, "the full sha anchors the section")
    check("- short sha kept" in out, "a 7-hex sha survives")
    check("sha-ab12cd3" in out, "the last surviving sha of the day anchors the section")

    # ── a message cannot smuggle Markdown syntax ────────────────────
    out, err, code = run("2026-09-01|abcd123|Added|see [docs](http://x) now\n")
    check(code == 0, "a message with Markdown constructs exits 0")
    check("- see \\[docs\\]\\(http://x\\) now" in out, "the Markdown link syntax is escaped")

    # ── a message lands on one line ─────────────────────────────────
    out, err, code = run("2026-09-01|abcd123|Added|a\tb c\n")
    check(code == 0, "a message with a tab exits 0")
    check("- a b c" in out, "whitespace runs collapse to one space")

    # ── the days are printed in sorted order ────────────────────────
    out, err, code = run(
        "2026-09-02|bbb1111|Added|later day\n"
        "2026-08-28|aaa2222|Added|earlier day\n"
    )
    check(code == 0, "an out-of-order draft exits 0")
    check(
        out.index("2026-08-28") < out.index("2026-09-02"),
        "the dated sections come out in sorted order regardless of input order",
    )

    print()
    if failures:
        print(f"make-changelog.py: {len(failures)} check(s) failed", file=sys.stderr)
        return 1
    print("make-changelog.py: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
