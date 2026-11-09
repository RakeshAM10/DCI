"""Configuration check: environment variables declared for deployment (docker-compose, Kubernetes env, Dockerfile ENV, .env files) vs. code that reads them.

Removed declaration (CFG101): a variable the pull request removes from every *deployment* declaration while code at head still reads it.
  CONFIRMED only for a Python read that has no default (os.environ["X"] raises KeyError); reads that tolerate absence are POSSIBLE.
  Removal from an example file only (.env.example / .sample / .template) is POSSIBLE: those files do not define the deployed environment.
New required variable (CFG102): code added by the pull request reads os.environ["X"] without a default and no declaration for X exists anywhere. POSSIBLE:
  the variable may be supplied by the platform, which this check cannot see."""
from __future__ import annotations

import os
import re
from collections import defaultdict

from dci.analyze import _check_workspace
from dci.config import Config, ConfigError
from dci.models import Confidence, Coverage, Finding, Reference, Severity
from dci.redact import redact
from dci.sources import Matcher, Tree

from . import syntax
from .check_api import KEEP, _finish, _mk, _sorted, _trees

_KEY = r"[A-Z][A-Z0-9_]{1,80}"
_COMPOSE = re.compile(r"^(?:docker-)?compose[\w.\-]*\.ya?ml$", re.I)
_EXAMPLE_ENV = re.compile(r"^\.env\.(?:example|sample|template|dist)$|\.env\.example$", re.I)
_ENV_FILE = re.compile(r"^\.env(?:\.[\w\-]+)?$", re.I)
_DOCKERFILE = re.compile(r"(?:^|/)(?:Dockerfile[\w.\-]*|[\w.\-]+\.Dockerfile)$")
_YAML = re.compile(r"\.ya?ml$", re.I)

_PY_REQUIRED = re.compile(r"""os\.environ\s*\[\s*(['"])(%s)\1\s*\]""" % _KEY)
_PY_OPTIONAL = re.compile(r"""os\.(?:environ\.get|getenv)\s*\(\s*(['"])(%s)\1\s*([,)])""" % _KEY)
_JS_READ = re.compile(r"process\.env\.(%s)\b|process\.env\[\s*(['\"])(%s)\2\s*\]" % (_KEY, _KEY))
_GO_READ = re.compile(r"""os\.(?:Getenv|LookupEnv)\(\s*"(%s)"\s*\)""" % _KEY)
_CODE = {".py": "py", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js", ".go": "go"}


def _declarations(path: str, text: str) -> tuple[set[str], str] | None:
    """(keys, level) with level 'deploy' or 'example', or None when the file declares nothing."""
    base = os.path.basename(path)
    keys: set[str] = set()
    if _EXAMPLE_ENV.search(base) or _ENV_FILE.match(base):
        for line in text.split("\n"):
            m = re.match(r"^\s*(?:export\s+)?(%s)\s*=" % _KEY, line)
            if m:
                keys.add(m.group(1))
        return keys, "example" if _EXAMPLE_ENV.search(base) else "deploy"
    if _DOCKERFILE.search(path):
        for line in text.split("\n"):
            m = re.match(r"^\s*ENV\s+(%s)\b" % _KEY, line, re.I)
            if m:
                keys.add(m.group(1))
            else:
                for pair in re.findall(r"\b(%s)=" % _KEY, line) if re.match(r"^\s*ENV\s", line, re.I) else []:
                    keys.add(pair)
        return keys, "deploy"
    if _COMPOSE.match(base) or _YAML.search(path):
        in_env, indent = False, 0
        for line in text.split("\n"):
            s = line.strip()
            cur = len(line) - len(line.lstrip())
            if re.match(r"^\s*(?:-\s+)?name:\s*['\"]?(%s)['\"]?\s*$" % _KEY, line):  # Kubernetes `- name: KEY` (env, envFrom items)
                keys.add(re.match(r"^\s*(?:-\s+)?name:\s*['\"]?(%s)" % _KEY, line).group(1))
            if re.match(r"^\s*environment:\s*$", line):
                in_env, indent = True, cur
                continue
            if in_env:
                if s and not s.startswith("#") and cur <= indent:
                    in_env = False
                else:
                    m = re.match(r"^\s*-\s*['\"]?(%s)(?:=|['\"]?\s*$)" % _KEY, line) or re.match(r"^\s*(%s)\s*:" % _KEY, line)
                    if m:
                        keys.add(m.group(1))
        return keys, "deploy"
    return None


def _collect(tree: Tree, ignore) -> dict[str, str]:
    """key -> strongest declaration level ('deploy' beats 'example')."""
    res: dict[str, str] = {}
    for path, _ in tree.files():
        if ignore(path):
            continue
        base = os.path.basename(path)
        if not (_EXAMPLE_ENV.search(base) or _ENV_FILE.match(base) or _DOCKERFILE.search(path) or _YAML.search(path)):
            continue
        txt = tree.read(path)
        d = _declarations(path, txt) if txt else None
        if d:
            for k in d[0]:
                if res.get(k) != "deploy":
                    res[k] = d[1]
    return res


def _reads(tree: Tree, tree_name: str, ignore, test_match, cov: Coverage, keys: set[str] | None) -> dict[str, list[tuple[Reference, str]]]:
    """key -> [(reference, 'required'|'optional')]. `keys` limits the search; None = everything required."""
    out: dict[str, list[tuple[Reference, str]]] = defaultdict(list)
    n = 0
    for path, _ in tree.files():
        kind = _CODE.get(os.path.splitext(path)[1].lower())
        if not kind or ignore(path):
            continue
        txt = tree.read(path)
        if txt is None:
            continue
        n += 1
        txt = syntax.blank_comments(path, txt)
        is_test = test_match(path)
        for i, line in enumerate(txt.split("\n"), 1):
            if len(line) > 2000 or "env" not in line.lower():
                continue
            hits: list[tuple[str, str]] = []
            if kind == "py":
                hits += [(m.group(2), "required") for m in _PY_REQUIRED.finditer(line)]
                hits += [(m.group(2), "optional" if m.group(3) == ")" else "defaulted") for m in _PY_OPTIONAL.finditer(line)]
            elif kind == "js":
                hits += [((m.group(1) or m.group(3)), "optional") for m in _JS_READ.finditer(line)]
            else:
                hits += [(m.group(1), "optional") for m in _GO_READ.finditer(line)]
            for key, how in hits:
                if keys is not None and key not in keys:
                    continue
                b = out[key]
                if len(b) < KEEP:
                    b.append((Reference(None, None, path, i, tree_name, "env_read", "ref", Confidence.CONFIRMED if how == "required" else Confidence.POSSIBLE,
                                        redact(line.strip()), is_test=is_test, anchor=i, note=how), how))
    cov.notes.append(f"Environment reads: {n} source file(s) searched in {tree_name}")
    return out


def run(cfg: Config, cov: Coverage) -> list[Finding]:
    repo = os.path.realpath(cfg.repo)
    if not os.path.isdir(repo):
        raise ConfigError(f"Repository path does not exist: {cfg.repo}")
    _check_workspace(cfg, repo)
    ignore, test_match = Matcher(cfg.ignore_paths), Matcher(cfg.test_globs)
    base_tree, head_tree, opened, changed = _trees(cfg, repo)
    try:
        findings: list[Finding] = []
        old, new = _collect(base_tree, ignore), _collect(head_tree, ignore)
        removed = {k for k in old if k not in new or (old[k] == "deploy" and new[k] != "deploy")}
        reads = _reads(head_tree, "head", ignore, test_match, cov, removed) if removed else {}
        for key in sorted(removed):
            rs = [(r, how) for r, how in reads.get(key, []) if how != "defaulted"]
            if not rs:
                continue
            level = old[key]
            required = [r for r, how in rs if how == "required" and not r.is_test]
            deploy = level == "deploy"
            conf = Confidence.CONFIRMED if (deploy and required) else Confidence.POSSIBLE
            refs = [r for r, _ in rs]
            if conf is not Confidence.CONFIRMED:
                for r in refs:
                    r.confidence = Confidence.POSSIBLE
            where = next(iter(p for _, p in changed), "") or ""
            findings.append(_mk("CFG101", Severity.ERROR if conf is Confidence.CONFIRMED else Severity.WARNING, conf, "Removed environment variable is still read",
                                f"This pull request removes the {'deployment declaration' if deploy else 'example declaration'} of {key}, but code at the head revision still reads it"
                                + (" and fails with KeyError when it is unset." if conf is Confidence.CONFIRMED else
                                   ("; the read tolerates absence, so this may be intended." if deploy else "; example files do not define the deployed environment, so this may be intended.")),
                                where, 1, refs, [f"Keep {key} declared, or change the code so it no longer needs it."], cfg))
        # new required variables
        all_new = set(new)
        head_req = {k: v for k, v in _reads(head_tree, "head", ignore, test_match, Coverage(), None).items()
                    if any(h == "required" and not r.is_test for r, h in v)}
        if head_req:
            base_req = _reads(base_tree, "base", ignore, test_match, Coverage(), None)
            for key in sorted(head_req):
                if key in all_new or any(h == "required" for _, h in base_req.get(key, [])):
                    continue
                refs = [r for r, h in head_req[key] if h == "required" and not r.is_test]
                findings.append(_mk("CFG102", Severity.WARNING, Confidence.POSSIBLE, "New required environment variable is not declared",
                                    f"Code added by this pull request requires {key} (os.environ[...] has no default) but no deployment or example file declares it. "
                                    "If the platform does not set it, the service will fail at startup or on first use.", refs[0].file, refs[0].line, refs,
                                    [f"Declare {key} in the deployment configuration and in the example env file, or give the read a default."], cfg))
        return _finish(findings, cfg, cov, "CFG901")
    finally:
        for t in opened:
            t.close()
