#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "release-tags.py"


class ReleaseTagsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cwd = self.temp.name
        self.env = dict(os.environ, GIT_AUTHOR_NAME="Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                        GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        self.git("init", "-q")
        tree = self.git("mktree", data="")
        self.sha = self.git("commit-tree", tree, "-m", "main")
        self.off_main = self.git("commit-tree", tree, "-m", "off main")
        self.git("update-ref", "refs/remotes/origin/main", self.sha)
        for tag in ("v1.2.3", "v1.2.10", "v1.3.0", "v01.2.3", "v2.0.0-rc.1"):
            self.git("update-ref", f"refs/tags/{tag}", self.sha)
        self.git("update-ref", "refs/tags/v9.0.0", self.off_main)

    def git(self, *args, data=None):
        return subprocess.run(["git", *args], cwd=self.cwd, env=self.env, input=data,
                              text=True, capture_output=True, check=True).stdout.strip()

    def flags(self, ref, event="push", sha=None, fails=False):
        env = dict(self.env, GITHUB_REF=ref, GITHUB_EVENT_NAME=event, GITHUB_SHA=sha or self.sha)
        result = subprocess.run(["python3", str(SCRIPT)], cwd=self.cwd, env=env, text=True, capture_output=True)
        if fails:
            self.assertNotEqual(result.returncode, 0)
            return
        self.assertEqual(result.returncode, 0, result.stderr)
        return tuple(line.split("=")[1] == "true" for line in result.stdout.splitlines())

    def test_release_series_and_numeric_ordering(self):
        self.assertEqual(self.flags("refs/tags/v1.3.0"), (True, True, True))
        self.assertEqual(self.flags("refs/tags/v1.2.10"), (True, False, True))
        self.assertEqual(self.flags("refs/tags/v1.2.3"), (True, False, False))

    def test_nonrelease_refs_and_manual_dispatch(self):
        for ref in ("refs/heads/main", "refs/tags/v2.0.0-rc.1", "refs/tags/v01.2.3"):
            self.assertEqual(self.flags(ref), (False, False, False))
        self.assertEqual(self.flags("refs/tags/v1.3.0", event="workflow_dispatch"), (False, False, False))
        self.assertEqual(self.flags("refs/tags/v9.0.0", sha=self.off_main), (False, False, False))

    def test_missing_main_fails_closed(self):
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        self.flags("refs/tags/v1.3.0", fails=True)

    def test_moved_tag_fails_closed(self):
        self.git("update-ref", "refs/tags/v1.3.0", self.off_main)
        self.flags("refs/tags/v1.3.0", fails=True)


if __name__ == "__main__":
    unittest.main()
