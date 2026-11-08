"""Dependency check: manifest changes in a pull request (requirements*.txt, pyproject.toml, package.json, go.mod).

CONFIRMED (blocks) only when a dependency that the pull request removes is still imported by code at the head revision (DEP101): the import
will fail at runtime. A package is matched by its exact import name (npm and Go: the package/module path; Python: the normalised distribution
name, so a distribution whose import name differs, e.g. PyYAML/yaml, is not matched and produces no finding rather than a guess).
Major-version upgrades (DEP102) are POSSIBLE: a major bump may break callers, but nothing here proves it."""
from __future__ import annotations

import json
import os
import re
import tomllib
from collections import defaultdict

from dci.analyze import _check_workspace
from dci.config import Config, ConfigError
from dci.models import Confidence, Coverage, Finding, Reference, Severity
from dci.redact import redact
from dci.sources import Matcher, Tree

from .check_api import KEEP, _finish, _mk, _sorted, _trees

MAX_MANIFEST_BYTES = 10_000_000
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_VER = re.compile(r"(\d+)(?:\.(\d+))?")
_PY_IMPORT = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w]*)(?:\.[\w.]*)?\s+import\b|import\s+([A-Za-z_][\w]*)(?:\.[\w.]*)?(?:\s+as\s+\w+)?(?:\s*,\s*[\w.]+(?:\s+as\s+\w+)?)*\s*$)")
_JS_IMPORT = re.compile(r"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)(['"])(@?[A-Za-z0-9][\w.\-]*(?:/[\w.\-]+)?)(?:/[^'"]*)?\1""")
_GO_IMPORT = re.compile(r'"([A-Za-z0-9][\w.\-]*\.[\w.\-]+/[^"\s]+)"')
_JS_EXT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte")
Deps = dict[str, str]  # name -> version spec


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _kind(path: str) -> str | None:
    base = os.path.basename(path).lower()
    if re.fullmatch(r"requirements[\w.\-]*\.(txt|in)", base):
        return "pip"
    return {"pyproject.toml": "pyproject", "package.json": "npm", "go.mod": "go"}.get(base)


def _parse_requirements(text: str) -> Deps:
    out: Deps = {}
    for raw in text.split("\n"):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("-", "#", "http:", "https:", "git+")) or "://" in line:
            continue
        m = _REQ_NAME.match(line.split(";")[0])
        if m:
            out[_norm(m.group(1))] = m.group(2).strip()
    return out


def _parse_pyproject(text: str) -> Deps:
    data = tomllib.loads(text)
    out: Deps = {}
    proj = data.get("project", {})
    lists = [proj.get("dependencies", [])] + list(proj.get("optional-dependencies", {}).values()) + list(data.get("dependency-groups", {}).values())
    for lst in lists:
        for item in lst if isinstance(lst, list) else []:
            if isinstance(item, str):
                out.update(_parse_requirements(item))
    poetry = data.get("tool", {}).get("poetry", {})
    for sect in ([poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})] + [g.get("dependencies", {}) for g in poetry.get("group", {}).values()]):
        for k, v in (sect or {}).items():
            if k.lower() != "python":
                out[_norm(k)] = v if isinstance(v, str) else str((v or {}).get("version", "")) if isinstance(v, dict) else ""
    return out


def _parse_npm(text: str) -> Deps:
    data = json.loads(text)
    out: Deps = {}
    if not isinstance(data, dict):
        return out
    for sect in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        d = data.get(sect)
        if isinstance(d, dict):
            out.update({k: str(v) for k, v in d.items()})
    return out


def _parse_go(text: str) -> Deps:
    out: Deps = {}
    in_block = False
    for raw in text.split("\n"):
        line = raw.split("//")[0].strip()
        if line.startswith("require ("):
            in_block = True
        elif in_block and line == ")":
            in_block = False
        elif in_block or line.startswith("require "):
            parts = line.removeprefix("require ").split()
            if len(parts) >= 2:
                out[parts[0]] = parts[1]
    return out


_PARSERS = {"pip": _parse_requirements, "pyproject": _parse_pyproject, "npm": _parse_npm, "go": _parse_go}
_ECO = {"pip": "python", "pyproject": "python", "npm": "npm", "go": "go"}


def _major(spec: str) -> int | None:
    m = _VER.search(spec.lstrip("^~<>=! v"))
    return int(m.group(1)) if m else None


def _collect(tree: Tree, paths: list[str], cov: Coverage) -> dict[str, Deps]:
    """ecosystem -> union of dependencies across every manifest of that ecosystem at this revision."""
    res: dict[str, Deps] = defaultdict(dict)
    for p in paths:
        kind = _kind(p)
        txt = tree.read(p) if kind else None
        if txt is None:
            continue
        try:
            res[_ECO[kind]].update(_PARSERS[kind](txt))
        except (ValueError, tomllib.TOMLDecodeError, RecursionError) as e:
            cov.notes.append(f"{p}: could not be parsed ({e.__class__.__name__}); its dependency changes were not checked")
    return res


def _importers(tree: Tree, wanted: dict[str, set[str]], ignore, test_match, cov: Coverage) -> dict[tuple[str, str], list[Reference]]:
    found: dict[tuple[str, str], list[Reference]] = defaultdict(list)
    seen = 0
    for path, _ in tree.files():
        low = path.lower()
        eco = "python" if low.endswith(".py") else "npm" if low.endswith(_JS_EXT) else "go" if low.endswith(".go") else None
        if eco is None or not wanted.get(eco) or ignore(path):
            continue
        text = tree.read(path)
        if text is None:
            continue
        seen += 1
        is_test = test_match(path)
        for i, line in enumerate(text.split("\n"), 1):
            if len(line) > 2000:
                continue
            names: list[str] = []
            if eco == "python":
                m = _PY_IMPORT.match(line)
                names = [_norm(g) for g in (m.groups() if m else ()) if g]
            elif eco == "npm":
                names = [m.group(2) for m in _JS_IMPORT.finditer(line)]
            else:
                for m in _GO_IMPORT.finditer(line):
                    path_s = m.group(1)
                    names = [w for w in wanted["go"] if path_s == w or path_s.startswith(w + "/")]
            for n in names:
                if n in wanted[eco]:
                    bucket = found[(eco, n)]
                    if len(bucket) < KEEP:
                        bucket.append(Reference(None, None, path, i, "head", "import", "ref", Confidence.CONFIRMED, redact(line.strip()), is_test=is_test, anchor=i))
    cov.notes.append(f"Dependency importers: {seen} source file(s) searched at head")
    return found


def run(cfg: Config, cov: Coverage) -> list[Finding]:
    repo = os.path.realpath(cfg.repo)
    if not os.path.isdir(repo):
        raise ConfigError(f"Repository path does not exist: {cfg.repo}")
    _check_workspace(cfg, repo)
    ignore, test_match = Matcher(cfg.ignore_paths), Matcher(cfg.test_globs)
    base_tree, head_tree, opened, changed = _trees(cfg, repo)
    try:
        touched = [p for st, p in changed if _kind(p) and not ignore(p)]
        cov.notes.append(f"Dependency manifests changed in this pull request: {len(touched)}" + (": " + ", ".join(touched[:5]) if touched else ""))
        findings: list[Finding] = []
        if not touched:
            return _finish(findings, cfg, cov, "DEP901")
        base_paths = [p for p, _ in base_tree.files() if _kind(p) and not ignore(p)]
        head_paths = [p for p, _ in head_tree.files() if _kind(p) and not ignore(p)]
        old, new = _collect(base_tree, base_paths, cov), _collect(head_tree, head_paths, cov)
        removed: dict[str, set[str]] = {eco: set(old.get(eco, {})) - set(new.get(eco, {})) for eco in old}
        removed = {k: v for k, v in removed.items() if v}
        refs = _importers(head_tree, removed, ignore, test_match, cov) if removed else {}
        where = touched[0]
        for eco, names in sorted(removed.items()):
            for n in sorted(names):
                ev = _sorted(refs.get((eco, n), []))
                if ev:
                    prod = [r for r in ev if not r.is_test]
                    findings.append(_mk("DEP101", Severity.ERROR, Confidence.CONFIRMED, "Removed dependency is still imported",
                                        f"This pull request removes the {eco} dependency '{n}', but {len(ev)} import(s) of it remain in the code at the head revision"
                                        f"{'' if prod else ' (tests only)'}. They will fail with an import error.", where, 1, ev,
                                        [f"Restore '{n}' in the manifest, or remove every import of it.",
                                         "If it is now provided by another dependency, add that dependency explicitly."], cfg))
                else:
                    findings.append(_mk("DEP103", Severity.INFO, Confidence.UNKNOWN, "Dependency removed",
                                        f"'{n}' ({eco}) was removed and no import of it was found. Imports under a different name, dynamic imports or other repositories cannot be seen.",
                                        where, 1, [], [], cfg))
        for eco, deps in sorted(new.items()):
            for n, spec in sorted(deps.items()):
                before = old.get(eco, {}).get(n)
                if before is None:
                    continue
                a, b = _major(before), _major(spec)
                if a is not None and b is not None and b > a:
                    findings.append(_mk("DEP102", Severity.WARNING, Confidence.POSSIBLE, "Major version upgrade",
                                        f"'{n}' ({eco}) changes from {before or 'any'} to {spec}, a new major version. Major versions may remove or change APIs the code uses.",
                                        where, 1, [], ["Read the release notes and run the tests before merging."], cfg))
        return _finish(findings, cfg, cov, "DEP901")
    finally:
        for t in opened:
            t.close()
