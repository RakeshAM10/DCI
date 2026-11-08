"""Read-only views of source trees: a working directory or an immutable git revision.
Neither ever follows symlinks or executes anything."""
from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterator

from . import gitutil

EXCLUDED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "virtualenv", "__pycache__", "site-packages", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "build", "dist", ".eggs", ".idea", ".next", ".gradle", "target",
}
MAX_FILE_BYTES = 2_000_000


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """'**/' = any number of directories (including none); '*' and '?' stay within a path segment."""
    i, n, out = 0, len(pattern), ["^"]
    while i < n:
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    out.append("$")
    return re.compile("".join(out))


class Matcher:
    def __init__(self, patterns: list[str]):
        self._rx = [glob_to_regex(p) for p in patterns]

    def __call__(self, path: str) -> bool:
        return any(r.match(path) for r in self._rx)


class Tree:
    name: str
    parallel_safe = False  # True when read() may be called from forked worker processes

    def files(self) -> Iterator[tuple[str, int]]:  # pragma: no cover - interface
        raise NotImplementedError

    def read(self, path: str) -> str | None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        pass


def _excluded(parts: list[str]) -> bool:
    return any(p in EXCLUDED_DIRS for p in parts)


class FsTree(Tree):
    parallel_safe = True

    def __init__(self, root: str, name: str, max_bytes: int = MAX_FILE_BYTES):
        self.root = os.path.realpath(root)
        self.name = name
        self.max_bytes = max_bytes

    def files(self) -> Iterator[tuple[str, int]]:
        stack = [self.root]
        while stack:
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except OSError:
                continue
            for e in entries:
                try:
                    if e.is_symlink():
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if e.name not in EXCLUDED_DIRS:
                            stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        rel = os.path.relpath(e.path, self.root).replace(os.sep, "/")
                        yield rel, e.stat(follow_symlinks=False).st_size
                except OSError:
                    continue

    def read(self, path: str) -> str | None:
        full = os.path.realpath(os.path.join(self.root, path))
        if not full.startswith(self.root + os.sep) or os.path.islink(os.path.join(self.root, path)):
            return None
        try:
            with open(full, "rb") as fh:
                data = fh.read(self.max_bytes + 1)
        except OSError:
            return None
        if len(data) > self.max_bytes:
            return None
        return data.decode("utf-8", "replace")


class GitTree(Tree):
    """Files of one commit, read from the object database via a single `git cat-file --batch` process."""

    def __init__(self, repo: str, sha: str, name: str, max_bytes: int = MAX_FILE_BYTES):
        self.repo, self.sha, self.name, self.max_bytes = repo, sha, name, max_bytes
        # In a partial clone `ls-tree -l` fetches every blob just to print sizes (minutes on a large monorepo): skip it and enforce the
        # size limit when a file is read instead.
        self._sizes_known = not gitutil.is_partial_clone(repo)
        raw = gitutil.run_git(repo, "ls-tree", "-r", "-z", *(["-l"] if self._sizes_known else []), sha)
        self._entries: dict[str, tuple[str, int]] = {}
        for rec in raw.split(b"\0"):
            if not rec:
                continue
            meta, _, path = rec.partition(b"\t")
            fields = meta.split()
            if len(fields) < (4 if self._sizes_known else 3):
                continue
            mode, typ, blob = fields[0], fields[1], fields[2]
            size = fields[3] if self._sizes_known and len(fields) > 3 else b"0"
            if typ != b"blob" or mode in (b"120000", b"160000"):
                continue
            p = path.decode("utf-8", "replace")
            if _excluded(p.split("/")[:-1]):
                continue
            self._entries[p] = (blob.decode(), int(size) if size.isdigit() else 0)
        self._proc: subprocess.Popen | None = None

    def files(self) -> Iterator[tuple[str, int]]:
        for p, (_, size) in sorted(self._entries.items()):
            yield p, size

    def _ensure(self) -> subprocess.Popen:
        if self._proc is None:
            self._proc = subprocess.Popen(
                ["git", "-C", self.repo, "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env={"GIT_TERMINAL_PROMPT": "0", "PATH": gitutil._path(), "HOME": gitutil._home()},
            )
        return self._proc

    def read(self, path: str) -> str | None:
        ent = self._entries.get(path)
        if not ent or ent[1] > self.max_bytes:
            return None
        proc = self._ensure()
        assert proc.stdin and proc.stdout
        proc.stdin.write(ent[0].encode() + b"\n")
        proc.stdin.flush()
        header = proc.stdout.readline().split()
        if len(header) < 3 or header[1] != b"blob":
            return None
        size = int(header[2])
        if size > self.max_bytes:  # unknown until now in a partial clone: drain the content, keep the stream in sync
            left = size + 1
            while left > 0:
                chunk = proc.stdout.read(min(left, 1 << 20))
                if not chunk:
                    break
                left -= len(chunk)
            return None
        data = proc.stdout.read(size)
        proc.stdout.read(1)
        return data.decode("utf-8", "replace")

    def close(self) -> None:
        if self._proc:
            try:
                if self._proc.stdin:
                    self._proc.stdin.close()
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()
            self._proc = None
