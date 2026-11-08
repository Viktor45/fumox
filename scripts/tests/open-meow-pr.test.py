#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/open-meow-pr.sh"
STUB = '''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as out:
    out.write(json.dumps([name, *args]) + "\\n")
if name == "gh":
    if args[:2] == ["pr", "list"]:
        print(os.environ.get("PRS", "[]"))
        sys.exit(int(os.environ.get("LIST_FAIL", "0")))
    if args[:2] == ["pr", "create"]:
        sys.exit(int(os.environ.get("CREATE_FAIL", "0")))
    sys.exit(99)
command = args[0]
if command == "ls-remote":
    sys.exit(int(os.environ.get("REMOTE_CODE", "0" if pathlib.Path(os.environ["BRANCH"]).exists() else "2")))
if command == "rev-parse":
    print("expected")
elif command == "hash-object":
    print("different" if os.environ.get("MISMATCH") else "expected")
elif command == "diff":
    print(os.environ.get("CHANGED", "docker/meow/Dockerfile"))
elif command == "push":
    pathlib.Path(os.environ["BRANCH"]).touch()
elif command not in ("check-ref-format", "fetch", "switch", "add", "-c"):
    sys.exit(99)
'''


class OpenMeowPrTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        for name in ("gh", "git"):
            tool = self.path / name
            tool.write_text(STUB)
            tool.chmod(0o755)
        self.calls = self.path / "calls"
        self.branch = self.path / "branch"
        self.env = dict(os.environ, PATH=str(self.path) + os.pathsep + os.environ["PATH"],
                        CALLS=str(self.calls), BRANCH=str(self.branch), VERSION="v0.29.0", PREVIOUS="v0.27.0",
                        BASE="main", SHA256_AMD64="1" * 64, SHA256_ARM64="2" * 64)

    def run_script(self, **extra):
        return subprocess.run(["bash", str(SCRIPT)], cwd=ROOT, env=dict(self.env, **extra),
                              text=True, capture_output=True)

    def recorded(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_failed_creation_retries_existing_verified_branch_without_push(self):
        first = self.run_script(CREATE_FAIL="1")
        self.assertNotEqual(first.returncode, 0)
        self.assertIn("branch is retained for retry", first.stderr)
        self.assertTrue(self.branch.exists())
        self.calls.write_text("")
        second = self.run_script()
        self.assertEqual(second.returncode, 0, second.stderr)
        calls = self.recorded()
        self.assertTrue(any(call[:3] == ["gh", "pr", "create"] for call in calls))
        self.assertFalse(any(call[:2] in (["git", "push"], ["git", "switch"], ["git", "add"], ["git", "-c"]) for call in calls))
        self.assertEqual(sum(call[:2] == ["git", "hash-object"] for call in calls), 5)

    def test_existing_pr_is_respected_in_every_state(self):
        for state in ("OPEN", "CLOSED", "MERGED"):
            self.calls.write_text("")
            result = self.run_script(PRS=json.dumps([{"number": 1, "state": state, "url": "fixture"}]))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(self.recorded()), 2)

    def test_query_failures_never_push_or_create(self):
        for error in ({"LIST_FAIL": "1"}, {"REMOTE_CODE": "128"}):
            self.calls.write_text("")
            self.assertNotEqual(self.run_script(**error).returncode, 0)
            self.assertFalse(self.branch.exists())
            self.assertFalse(any(call[:3] == ["gh", "pr", "create"] for call in self.recorded()))

    def test_existing_branch_must_match_verified_files_and_scope(self):
        self.branch.touch()
        for error in ({"MISMATCH": "1"}, {"CHANGED": ".github/workflows/ci.yml"}):
            self.calls.write_text("")
            self.assertNotEqual(self.run_script(**error).returncode, 0)
            self.assertFalse(any(call[:3] == ["gh", "pr", "create"] for call in self.recorded()))
            self.assertFalse(any(call[:2] == ["git", "push"] for call in self.recorded()))


if __name__ == "__main__":
    unittest.main()
