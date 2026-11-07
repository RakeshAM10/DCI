"""Minimal, injection-safe git access (argument lists only, never a shell)."""
from __future__ import annotations

import re
import subprocess

_REV = re.compile(r"^[A-Za-z0-9._/@^~{}:+\-]+$")
TIMEOUT = 120


class GitError(RuntimeError):
    pass


def check_rev(rev: str) -> str:
    if not rev or rev.startswith("-") or not _REV.match(rev):
        raise GitError(f"Refusing unsafe revision name: {rev!r}")
    return rev


def run_git(repo: str, *args: str, input: bytes | None = None) -> bytes:
    try:
        p = subprocess.run(
            ["git", "-C", repo, *args], input=input, capture_output=True, timeout=TIMEOUT, check=False,
            env={"GIT_TERMINAL_PROMPT": "0", "PATH": _path(), "HOME": _home(), "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GitError(f"git {args[0] if args else ''} failed: {e}") from e
    if p.returncode != 0:
        raise GitError(f"git {' '.join(args[:2])} failed: {p.stderr.decode('utf-8', 'replace').strip()[:300]}")
    return p.stdout


def _path() -> str:
    import os
    return os.environ.get("PATH", "/usr/bin:/bin")


def _home() -> str:
    import os
    return os.environ.get("HOME", "/tmp")


def is_repo(path: str) -> bool:
    try:
        run_git(path, "rev-parse", "--git-dir")
        return True
    except GitError:
        return False


def rev_sha(repo: str, rev: str) -> str:
    return run_git(repo, "rev-parse", "--verify", "--quiet", check_rev(rev) + "^{commit}").decode().strip()


def merge_base(repo: str, base: str, head: str) -> str:
    return run_git(repo, "merge-base", check_rev(base), check_rev(head)).decode().strip()


def changed_files(repo: str, base_sha: str, head_sha: str) -> list[tuple[str, str]]:
    """(status, path) for A/M/D between two commits, renames reported as D+A."""
    out = run_git(repo, "diff", "--name-status", "-z", "--no-renames", base_sha, head_sha, "--")
    parts = out.decode("utf-8", "replace").split("\0")
    res = []
    i = 0
    while i + 1 < len(parts):
        status, path = parts[i], parts[i + 1]
        if status:
            res.append((status[0], path))
        i += 2
    return res


def show_file(repo: str, rev: str, relpath: str) -> bytes | None:
    """Content of `relpath` (relative to `repo`) at `rev`, or None when it does not exist there."""
    check_rev(rev)
    if not relpath or relpath.startswith("-") or "\0" in relpath:
        raise GitError(f"Refusing unsafe path: {relpath!r}")
    try:
        return run_git(repo, "show", f"{rev}:./{relpath}")
    except GitError:
        try:
            run_git(repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
        except GitError:
            raise
        return None
