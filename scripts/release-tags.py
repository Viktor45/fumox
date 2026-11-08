#!/usr/bin/env python3
import os
import re
import subprocess


STABLE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def git(*args):
    return subprocess.run(["git", *args], text=True, capture_output=True, check=True).stdout.strip()


def on_main(commit):
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"],
        capture_output=True,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.decode())
    return result.returncode == 0


def release_flags(event, ref, sha):
    flags = dict(IS_RELEASE=False, IS_LATEST=False, IS_SERIES_LATEST=False)
    match = STABLE.fullmatch(ref.removeprefix("refs/tags/")) if ref.startswith("refs/tags/") else None
    if event != "push" or not match:
        return flags
    git("rev-parse", "--verify", "refs/remotes/origin/main")
    if not on_main(sha):
        return flags
    if git("rev-parse", f"{ref}^{{commit}}") != sha:
        raise RuntimeError("release tag no longer points at the triggering commit")
    current = tuple(map(int, match.groups()))
    versions = [current]
    for tag in git("tag", "--list", "v*").splitlines():
        candidate = STABLE.fullmatch(tag)
        if candidate and on_main(f"refs/tags/{tag}^{{commit}}"):
            versions.append(tuple(map(int, candidate.groups())))
    flags["IS_RELEASE"] = True
    flags["IS_LATEST"] = current == max(versions)
    flags["IS_SERIES_LATEST"] = current == max(v for v in versions if v[:2] == current[:2])
    return flags


if __name__ == "__main__":
    for key, value in release_flags(os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REF"], os.environ["GITHUB_SHA"]).items():
        print(f"{key}={str(value).lower()}")
