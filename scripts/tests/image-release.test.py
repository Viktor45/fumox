#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/image-release.sh"
INDEX = "sha256:" + "a" * 64
IMAGE = "ghcr.io/example/fixture"
STUB = '''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as out:
    out.write(json.dumps([name, *args]) + "\\n")
if name == "gh":
    sys.exit(int(os.environ.get("ATTEST_FAIL", "0")))
if args[:3] == ["buildx", "imagetools", "inspect"]:
    if "--raw" in args:
        print(os.environ["MANIFEST"])
    else:
        print(os.environ.get("ACTUAL_DIGEST", os.environ["INDEX_DIGEST"]))
elif args[:3] != ["buildx", "imagetools", "create"]:
    sys.exit(2)
'''


def descriptor(arch, digit="1", os_name="linux"):
    return {"digest": "sha256:" + digit * 64, "platform": {"os": os_name, "architecture": arch}}


class ImageReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        for tool in ("gh", "docker"):
            executable = self.path / tool
            executable.write_text(STUB)
            executable.chmod(0o755)
        digests = self.path / "digests"
        digests.mkdir()
        for digit in ("1", "2"):
            (digests / (digit * 64)).touch()
        self.calls = self.path / "calls"
        self.env = dict(os.environ, PATH=str(self.path) + os.pathsep + os.environ["PATH"],
                        CALLS=str(self.calls), DIGEST_DIR=str(digests), IMAGE=IMAGE,
                        INDEX_DIGEST=INDEX, GITHUB_SHA="b" * 40, GITHUB_RUN_ID="17", GITHUB_RUN_ATTEMPT="2",
                        GITHUB_OUTPUT=str(self.path / "output"), GITHUB_REPOSITORY="example/fixture",
                        TAGS=f"{IMAGE}:latest\n{IMAGE}:1.2.3")
        self.manifests = [descriptor("amd64"), descriptor("arm64", "2")]

    def run_script(self, command, **extra):
        env = dict(self.env, MANIFEST=json.dumps({"schemaVersion": 2, "manifests": self.manifests}), **extra)
        return subprocess.run(["bash", str(SCRIPT), command], env=env, text=True, capture_output=True)

    def recorded(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_candidate_does_not_publish_release_tags(self):
        result = self.run_script("candidate")
        self.assertEqual(result.returncode, 0, result.stderr)
        create = self.recorded()[0]
        self.assertEqual(create[4:6], ["-t", f"{IMAGE}:sha-bbbbbbb-candidate-17-2"])
        self.assertEqual(create[6:], [f"{IMAGE}@sha256:{digit * 64}" for digit in ("1", "2")])
        self.assertEqual((self.path / "output").read_text(), f"digest={INDEX}\n")

    def test_requires_two_sources_and_valid_digest(self):
        (self.path / "digests" / ("2" * 64)).unlink()
        self.assertNotEqual(self.run_script("candidate").returncode, 0)
        self.assertFalse(self.calls.exists())
        (self.path / "digests" / ("2" * 64)).touch()
        self.assertNotEqual(self.run_script("candidate", ACTUAL_DIGEST="").returncode, 0)

    def test_exact_platforms_and_attestations(self):
        attestation = descriptor("unknown", "3", "unknown")
        attestation["annotations"] = {"vnd.docker.reference.type": "attestation-manifest"}
        self.manifests.append(attestation)
        result = self.run_script("verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.recorded()
        self.assertEqual(calls[0][4], f"{IMAGE}@{INDEX}")
        self.assertEqual(len([call for call in calls if call[0] == "gh"]), 3)
        self.assertNotEqual(self.run_script("verify", ATTEST_FAIL="1").returncode, 0)

    def test_rejects_missing_duplicate_extra_and_unknown_platforms(self):
        for manifests in ([descriptor("amd64")],
                          [descriptor("amd64"), descriptor("amd64", "2")],
                          [*self.manifests, descriptor("s390x", "3")],
                          [*self.manifests, descriptor("unknown", "3", "unknown")],
                          [descriptor("amd64"), descriptor("arm64", "2", "windows")],
                          [{}], []):
            with self.subTest(manifests=manifests):
                self.manifests = manifests
                self.assertNotEqual(self.run_script("verify").returncode, 0)

    def test_promotion_copies_verified_digest(self):
        result = self.run_script("promote")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.recorded()[0][4:], ["-t", f"{IMAGE}:latest", "-t", f"{IMAGE}:1.2.3", f"{IMAGE}@{INDEX}"])
        self.assertNotEqual(self.run_script("promote", ACTUAL_DIGEST="sha256:" + "f" * 64).returncode, 0)

    def test_publishers_gate_promotion_and_never_delete(self):
        for filename in ("docker.yml", "docker-meow.yml"):
            workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
            jobs = workflow["jobs"]
            self.assertEqual(jobs["quality"]["uses"], "./.github/workflows/ci.yml")
            self.assertEqual(jobs["build"]["needs"], "quality")
            self.assertIn("quality", jobs["merge"]["needs"])
            steps = jobs["merge"]["steps"]
            runs = [step.get("run", "") for step in steps]
            candidate = runs.index("bash scripts/image-release.sh candidate")
            verify = runs.index("bash scripts/image-release.sh verify")
            promote = runs.index("bash scripts/image-release.sh promote")
            self.assertLess(candidate, verify)
            self.assertLess(verify, promote)
            self.assertTrue(any("attest-build-provenance@" in step.get("uses", "") for step in steps[candidate:verify]))
            for step in steps:
                self.assertNotIn("if", step)
                self.assertNotIn("DELETE", step.get("run", ""))
                if "docker/metadata-action@" in step.get("uses", ""):
                    self.assertEqual(step["with"]["flavor"], "latest=false")
                    self.assertIn("type=ref,event=branch,prefix=branch-", step["with"]["tags"])
            self.assertEqual(workflow["concurrency"]["group"], "ghcr-images")
        fumox = yaml.safe_load((ROOT / ".github/workflows/docker.yml").read_text())
        metadata = next(step for step in fumox["jobs"]["merge"]["steps"] if step.get("id") == "meta")
        self.assertIn("pattern={{version}},enable=${{ env.IS_RELEASE == 'true' }}", metadata["with"]["tags"])

    def test_frontend_directives_are_first_and_pinned(self):
        for relative in ("Dockerfile", "docker/meow/Dockerfile", "docker/nginx/Dockerfile"):
            first = (ROOT / relative).read_text().splitlines()[0]
            self.assertRegex(first, r"^# syntax=docker/dockerfile:1@sha256:[0-9a-f]{64}$")

    def test_ci_gate_requires_all_jobs_and_expected_image_state(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        jobs = workflow["jobs"]
        gate = jobs["gate"]
        self.assertEqual(set(gate["needs"]), {"check", "msrv", "audit", "images"})
        self.assertEqual(gate["if"], "always()")
        script = gate["steps"][0]["run"]
        for skip in ("true", "false", ""):
            expected = "skipped" if skip == "true" else "success"
            env = dict(os.environ, CHECK="success", MSRV="success", AUDIT="success", IMAGES=expected, SKIP_IMAGES=skip)
            self.assertEqual(subprocess.run(["bash", "-e", "-c", script], env=env).returncode, 0)
            for key in ("CHECK", "MSRV", "AUDIT", "IMAGES"):
                for state in ("failure", "cancelled", "skipped"):
                    if key == "IMAGES" and state == expected:
                        continue
                    result = subprocess.run(["bash", "-e", "-c", script], env=dict(env, **{key: state}))
                    self.assertNotEqual(result.returncode, 0, (skip, key, state))
        matrix = jobs["images"]["strategy"]["matrix"]
        self.assertEqual({image["context"] for image in matrix["image"]}, {".", "./docker/meow", "./docker/nginx"})
        self.assertEqual({target["platform"] for target in matrix["target"]}, {"linux/amd64", "linux/arm64"})
        build = jobs["images"]["steps"][-1]
        self.assertIs(build["with"]["push"], False)
        cleanup = yaml.safe_load((ROOT / ".github/workflows/cleanup-ghcr.yml").read_text())
        self.assertEqual(cleanup["concurrency"]["group"], "ghcr-images")


if __name__ == "__main__":
    unittest.main()
