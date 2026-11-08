"""API-contract check: OpenAPI specs changed in a pull request, compared with the base branch, tied to the code and traffic that use them."""
from __future__ import annotations

import os
from collections import Counter, defaultdict
from dataclasses import replace

from dci import gitutil
from dci.analyze import _check_workspace
from dci.config import Config, ConfigError
from dci.models import Confidence, Coverage, Finding, Reference, Severity
from dci.sources import FsTree, GitTree, Matcher, Tree

from . import accesslog, callers, oas

_TITLES = {
    "API111": "A request parameter became required or new",
    "API112": "A request body became required",
    "API113": "A request property became required or new",
    "API114": "A request type changed",
    "API115": "A request enum lost values",
    "API116": "A success response was removed",
    "API121": "A response property was removed",
    "API122": "A response property changed type",
    "API123": "A response property is no longer always present",
    "API124": "A response enum gained values",
}
_COMPAT = [
    "Keep the old behaviour working: make new request fields optional with a default, add new fields instead of changing types, keep old enum values.",
    "If the break is intended, publish it as a new version (for example /v2) and keep the old one until its traffic is gone.",
]
_REMOVAL = [
    "Keep the endpoint, mark it `deprecated: true` and announce a sunset date instead of deleting it.",
    "Check that callers (listed above, and any outside the scanned code) have moved, then remove it in a later release.",
]
KEEP = callers.KEEP_PER_CATEGORY
_SEV = {"error": Severity.ERROR, "warning": Severity.WARNING, "info": Severity.INFO}
_ORDER = {"error": 3, "warning": 2, "info": 1}


def _sorted(refs: list[Reference]) -> list[Reference]:
    return sorted(refs, key=lambda r: (r.tree.startswith("runtime:"), r.tree != "head", r.file, r.line))


def _line_of(text: str | None, needle: str) -> int:
    if text:
        for i, ln in enumerate(text.split("\n"), 1):
            if needle in ln:
                return i
    return 1


def _split(refs: list[Reference]):
    cn = [r for r in refs if r.confidence == Confidence.CONFIRMED and not r.is_test]
    ct = [r for r in refs if r.confidence == Confidence.CONFIRMED and r.is_test]
    lines = {(r.file, r.line) for r in cn + ct}
    po = [r for r in refs if r.confidence != Confidence.CONFIRMED and (r.file, r.line) not in lines]
    return cn, ct, po


def _mk(rid, sev, conf, title, msg, spec, line, refs, rec, cfg, total=None) -> Finding:
    ev = _sorted(refs)
    return Finding(rid, sev, conf, title, msg, None, ev[:cfg.max_evidence], rec, total_evidence=max(len(ev), total or 0), file=spec, line=line)


def _read_spec(tree: Tree, path: str) -> str | None:
    """Specifications may be far larger than the per-file source limit; read them under their own limit."""
    old = tree.max_bytes
    tree.max_bytes = max(old, oas.MAX_SPEC_BYTES)
    try:
        return tree.read(path)
    finally:
        tree.max_bytes = old


def _trees(cfg: Config, repo: str) -> tuple[Tree, Tree, list[Tree], list[tuple[str, str]]]:
    if not cfg.base:
        raise ConfigError("The API check needs --base REV to find the specifications changed in the pull request")
    if not gitutil.is_repo(repo):
        raise ConfigError("--base requires a git repository")
    head_rev = cfg.head or "HEAD"
    head_sha = gitutil.rev_sha(repo, head_rev)
    base_sha = gitutil.merge_base(repo, cfg.base, head_rev)
    base_tree = GitTree(repo, base_sha, "base", cfg.max_file_bytes)
    head_tree: Tree = GitTree(repo, head_sha, "head", cfg.max_file_bytes) if cfg.head else FsTree(repo, "head", cfg.max_file_bytes)
    return base_tree, head_tree, [base_tree, head_tree], gitutil.changed_files(repo, base_sha, head_sha)


def run(cfg: Config, cov: Coverage) -> list[Finding]:
    repo = os.path.realpath(cfg.repo)
    if not os.path.isdir(repo):
        raise ConfigError(f"Repository path does not exist: {cfg.repo}")
    _check_workspace(cfg, repo)
    ignore_match = Matcher(cfg.ignore_paths)
    spec_match = Matcher(cfg.api_spec_globs)
    test_match = Matcher(cfg.test_globs)
    base_tree, head_tree, opened, changed = _trees(cfg, repo)
    extra: list[Tree] = []
    try:
        findings: list[Finding] = []
        specs = [(st, p) for st, p in changed if spec_match(p) and not ignore_match(p)]
        cov.notes.append(f"API specifications changed in this pull request: {len(specs)}" + (": " + ", ".join(p for _, p in specs[:5]) if specs else ""))
        ops_changes: dict[tuple[str, str, str], list[oas.ApiChange]] = defaultdict(list)
        spec_of: dict[tuple[str, str, str], tuple[str, int]] = {}
        prefixes: list[str] = []
        for status, path in specs:
            if status == "A":
                cov.notes.append(f"{path}: new specification, nothing to compare it with")
                continue
            if status == "D":
                cov.notes.append(f"{path}: specification was deleted; DCI cannot tell whether its endpoints were removed or moved")
                continue
            btxt, htxt = _read_spec(base_tree, path), _read_spec(head_tree, path)
            try:
                if btxt is None:
                    raise oas.SpecError("the base version could not be read (missing or too large)")
                if htxt is None:
                    raise oas.SpecError("the new version could not be read (missing or too large)")
                b, h = oas.parse_spec(btxt), oas.parse_spec(htxt)
            except oas.SpecError as e:
                findings.append(Finding("API902", Severity.WARNING, Confidence.UNKNOWN, "API specification could not be checked",
                                        f"{path} changed but was not compared: {e}. Breaking changes in it were not evaluated.", None, file=path, line=1))
                continue
            changes, notes = oas.diff(b, h)
            cov.notes.extend(f"{path}: {n}" for n in notes)
            prefixes += oas.server_prefixes(b) + oas.server_prefixes(h)
            for c in changes:
                key = (c.rule, c.method, c.path)
                ops_changes[key].append(c)
                spec_of[key] = (path, _line_of(btxt if c.rule == "API101" else htxt, c.path))
        if not ops_changes:
            return _finish(findings, cfg, cov)

        affected = sorted({(m, p) for (_, m, p) in ops_changes})
        matchers = callers.build_matchers(affected, sorted(set(prefixes)))
        found = callers.Found({k: [] for k in affected}, Counter())
        logrefs: dict[tuple[str, str], list[Reference]] = {k: [] for k in affected}
        scan_trees: list[tuple[Tree, str]] = [(head_tree, "head")]
        for name, path in [*cfg.consumer_repos, *cfg.config_consumer_repos]:
            if not os.path.isdir(path):
                raise ConfigError(f"Consumer repository path does not exist: {path}")
            t = FsTree(path, f"consumer:{name}", cfg.max_file_bytes)
            extra.append(t)
            scan_trees.append((t, f"consumer:{name}"))
        for tree, name in scan_trees:
            cov.trees_scanned.append(name)
            callers.scan_tree(tree, matchers, name, test_match, ignore_match, cov, cfg.time_budget_seconds, cfg.max_total_bytes, found)
        for log in cfg.api_access_logs:
            got, rows, distinct = accesslog.references(log, matchers, cfg.runtime_blocks)
            cov.trees_scanned.append(f"runtime:{os.path.basename(log)}")
            cov.notes.append(f"Access log {os.path.basename(log)}: {rows} request(s), {distinct} distinct endpoint(s). "
                             + ("Treated as CONFIRMED (--runtime-blocks)." if cfg.runtime_blocks else "Reported as POSSIBLE: a log does not prove the caller still exists."))
            for k, v in got.items():
                logrefs[k].extend(v)

        groups: dict[tuple, list] = defaultdict(list)
        for (rule, method, path), changes in sorted(ops_changes.items()):
            spec, line = spec_of[(rule, method, path)]
            key = (method, path)
            r = found.refs[key] + logrefs[key]
            op = f"{method.upper()} {path}"

            def tot(conf_in, test):
                n = sum(found.totals[(key, c, test)] for c in conf_in)
                return n + sum(1 for x in logrefs[key] if x.confidence in conf_in and x.is_test == test)
            n_all = sum(n for (o, _, _), n in found.totals.items() if o == key) + len(logrefs[key])
            if rule == "API101":
                cn, ct, po = _split(r)
                dep = " It was already marked deprecated." if changes[0].deprecated else ""
                if cn:
                    findings.append(_mk("API101", Severity.ERROR, Confidence.CONFIRMED, "Removed endpoint is still called",
                                        f"{op} is removed from the specification, but {tot({Confidence.CONFIRMED}, False)} call(s) to it remain.{dep}", spec, line, cn, _REMOVAL, cfg, tot({Confidence.CONFIRMED}, False)))
                if ct:
                    findings.append(_mk("API102", Severity.WARNING, Confidence.CONFIRMED, "Removed endpoint is called only from tests",
                                        f"{tot({Confidence.CONFIRMED}, True)} test call(s) to {op} remain and will fail.{dep}", spec, line, ct, _REMOVAL, cfg, tot({Confidence.CONFIRMED}, True)))
                if po:
                    findings.append(_mk("API103", Severity.WARNING, Confidence.POSSIBLE, "Removed endpoint may still be called",
                                        f"{tot({Confidence.POSSIBLE}, False) + tot({Confidence.POSSIBLE}, True)} location(s) or log entr(ies) may call {op}: the path matches but the HTTP method or full path is not provable.{dep}",
                                        spec, line, po, _REMOVAL, cfg, tot({Confidence.POSSIBLE}, False) + tot({Confidence.POSSIBLE}, True)))
                if not (cn or ct or po):
                    findings.append(_mk("API105", Severity.INFO, Confidence.UNKNOWN, "Callers outside the scanned code and logs are not visible",
                                        f"{op} is removed. No caller was found in the scanned code or supplied logs, but mobile apps, partners and other services "
                                        f"cannot be seen, and absence of a finding is not proof that nobody uses it.{dep}", spec, line, [], _REMOVAL, cfg))
                continue
            sev = max((c.severity for c in changes), key=lambda s: _ORDER[s])
            details = tuple(sorted({c.detail for c in changes}))
            groups[(rule, details)].append((op, spec, line, r, n_all, sev))
        # Informational changes (an enum gained a value, an optional response field was dropped) are merged per rule once there are many.
        info = defaultdict(list)
        for k, items in groups.items():
            if all(it[5] == "info" for it in items):
                info[k[0]].append(k)
        for rule, keys in info.items():
            if len(keys) > 3:
                merged = [it for k in keys for it in groups.pop(k)]
                details = tuple(sorted({d for k in keys for d in k[1]}))
                groups[(rule, details)] = merged
        # One shared schema change shows up on every endpoint that uses it: report identical changes once, listing the endpoints.
        for (rule, details), items in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[1][0][1], kv[1][0][2])):
            sev = max((it[5] for it in items), key=lambda s: _ORDER[s])
            ops_txt = ", ".join(it[0] for it in items[:8]) + (f" (+{len(items) - 8} more)" if len(items) > 8 else "")
            lines = "\n".join(f"- {d}" for d in details[:20]) + (f"\n- … and {len(details) - 20} more" if len(details) > 20 else "")
            refs_all = [x for it in items for x in it[3]]
            n_all = sum(it[4] for it in items)
            who = (f"{n_all} caller location(s) of {'these endpoints' if len(items) > 1 else 'this endpoint'} were found; check they still work." if refs_all
                   else "No callers were found in the scanned code or supplied logs; clients outside them cannot be seen.")
            head = f"{ops_txt}:" if len(items) == 1 else f"{len(items)} endpoints are affected: {ops_txt}\nChanges (not every endpoint has every change):"
            findings.append(_mk(rule, _SEV[sev], Confidence.POSSIBLE, _TITLES[rule], f"{head}\n{lines}\n{who}", items[0][1], items[0][2],
                                [replace(x, confidence=Confidence.POSSIBLE) for x in refs_all], _COMPAT, cfg, n_all))
        return _finish(findings, cfg, cov)
    finally:
        for t in [*opened, *extra]:
            t.close()


def _finish(findings: list[Finding], cfg: Config, cov: Coverage, rule: str = "API901") -> list[Finding]:
    if cov.scan_incomplete:
        findings.append(Finding(rule, Severity.WARNING, Confidence.UNKNOWN, "Caller scan incomplete",
                                f"The scan stopped at its size or time budget; {cov.files_not_scanned} file(s) were not read, so callers may be missing.", None))
    return [f for f in findings if f.rule_id not in cfg.ignore_rules]
