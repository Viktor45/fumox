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

    print()
    if failures:
        print(f"make-changelog.py: {len(failures)} check(s) failed", file=sys.stderr)
        return 1
    print("make-changelog.py: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
