"""Orchestration: find changed migrations, parse them, scan consumers at head (and base), evaluate rules."""
from __future__ import annotations

import os
import re

from . import __version__, gitutil, rules, runtime
from .config import Config, ConfigError
from .consumers import Scanner
from .identifiers import DEFAULT_SCHEMA, tkey
from .migrations import parse_migration
from .models import Change, ChangeKind, Confidence, Coverage, Finding, ParseIssue, Report, Severity
from .sources import FsTree, GitTree, Matcher, Tree

_SUPPRESS = re.compile(r"(?i)dci:\s*ignore(?:\[([A-Za-z0-9_,\s]+)\])?")
_MIG_EXT = (".py", ".sql")


def _inside(repo: str, path: str) -> str:
    full = os.path.realpath(path if os.path.isabs(path) else os.path.join(repo, path))
    if not (full == repo or full.startswith(repo + os.sep)):
        raise ConfigError(f"Migration path is outside the repository: {path}")
    return os.path.relpath(full, repo).replace(os.sep, "/")


def analyze(cfg: Config) -> Report:
    repo = os.path.realpath(cfg.repo)
    if not os.path.isdir(repo):
        raise ConfigError(f"Repository path does not exist: {cfg.repo}")
    _check_workspace(cfg, repo)
    cov = Coverage()
    migration_match = Matcher(cfg.migration_globs)
    ignore_match = Matcher(cfg.ignore_paths)
    test_match = Matcher(cfg.test_globs)
    trees: list[Tree] = []
    try:
        is_git = gitutil.is_repo(repo)
        base_tree: Tree | None = None
        head_tree: Tree
        mig_paths: list[str] = []

        if cfg.base:
            if not is_git:
                raise ConfigError("--base requires a git repository")
            head_rev = cfg.head or "HEAD"
            head_sha = gitutil.rev_sha(repo, head_rev)
            base_sha = gitutil.merge_base(repo, cfg.base, head_rev)
            base_tree = GitTree(repo, base_sha, "base", cfg.max_file_bytes)
            trees.append(base_tree)
            head_tree = GitTree(repo, head_sha, "head", cfg.max_file_bytes) if cfg.head else FsTree(repo, "head", cfg.max_file_bytes)
            if not cfg.migrations:
                for status, path in gitutil.changed_files(repo, base_sha, head_sha):
                    if status in ("A", "M") and path.endswith(_MIG_EXT) and migration_match(path) and not ignore_match(path):
                        mig_paths.append(path)
                        if status == "M":
                            cov.notes.append(f"{path}: an existing migration was modified; applied migrations should be immutable")
        else:
            head_tree = (GitTree(repo, gitutil.rev_sha(repo, cfg.head), "head", cfg.max_file_bytes) if (cfg.head and is_git)
                         else FsTree(repo, "head", cfg.max_file_bytes))
            cov.notes.append("No --base revision: rollout-window rules (old version vs new schema) were not evaluated.")
        trees.append(head_tree)
        if cfg.migrations:
            mig_paths = [_inside(repo, m) for m in cfg.migrations]
        elif not cfg.base:
            raise ConfigError("Provide --base REV (to find migrations changed in the PR) or --migration FILE")

        changes: list[Change] = []
        issues: list[ParseIssue] = []
        created: set[tuple[str, str]] = set()
        mig_text: dict[str, str] = {}
        for p in sorted(set(mig_paths)):
            text = head_tree.read(p)
            if text is None:
                issues.append(ParseIssue(p, 1, "Migration file could not be read (missing, too large or unreadable)"))
                continue
            mig_text[p] = text
            ch, iss, cr = parse_migration(p, text)
            cov.migration_files.append(p)
            changes.extend(ch)
            issues.extend(iss)
            created |= cr

        targets: dict[tuple[str, str], set[str]] = {}
        for c in changes:
            if c.kind == ChangeKind.CREATE_TABLE:
                continue
            cols = targets.setdefault(tkey(c.schema, c.table), set())
            if c.kind in (ChangeKind.DROP_COLUMN, ChangeKind.RENAME_COLUMN, ChangeKind.SET_NOT_NULL, ChangeKind.ADD_COLUMN, ChangeKind.ALTER_TYPE) and c.column:
                cols.add(c.column)
        other = sorted({c.schema for c in changes if c.schema and c.schema != DEFAULT_SCHEMA})
        if other:
            cov.notes.append(f"Changes in non-default schema(s) {', '.join(other)}: unqualified table names in code are assumed to be in "
                             f"'{DEFAULT_SCHEMA}' (a search_path set in the application or the database role is not analysed), so they are not matched to these changes.")
        scanner = Scanner(targets, migration_match, ignore_match, test_match, cov, cfg.max_file_bytes, cfg.workers,
                          cfg.time_budget_seconds, cfg.max_total_bytes, cfg.parallel_min_files)

        head_refs = []
        base_refs = None
        if targets:
            head_refs.extend(scanner.scan(head_tree).refs)
            for name, path in [*cfg.consumer_repos, *cfg.config_consumer_repos]:
                if not os.path.isdir(path):
                    raise ConfigError(f"Consumer repository path does not exist: {path}")
                t = FsTree(path, f"consumer:{name}", cfg.max_file_bytes)
                trees.append(t)
                head_refs.extend(scanner.scan(t).refs)
            for qpath in cfg.runtime_queries:
                rrefs, n_q, n_bad = runtime.runtime_references(qpath, cfg.runtime_blocks)
                head_refs.extend(r for r in rrefs if scanner._wanted(r))
                cov.trees_scanned.append(f"runtime:{os.path.basename(qpath)}")
                cov.notes.append(f"Runtime evidence {os.path.basename(qpath)}: {n_q} queries read, {n_bad} could not be parsed. "
                                 + ("Treated as CONFIRMED (--runtime-blocks)." if cfg.runtime_blocks else
                                    "Reported as POSSIBLE: statistics carry no timestamp, so a query may come from retired code."))
            if base_tree is not None:
                base_refs = scanner.scan(base_tree).refs
        elif base_tree is not None:
            base_refs = []

        findings = rules.evaluate(changes, issues, head_refs, base_refs, created, cfg)
        if cov.scan_incomplete:
            findings.append(Finding(
                "DCI901", Severity.WARNING, Confidence.UNKNOWN, "Scan incomplete",
                f"The scan stopped at its size or time budget; {cov.files_not_scanned} file(s) were not read. Code in those files may still "
                "use the changed tables or columns, so a missing finding is not evidence of safety. Raise time_budget_seconds or "
                "max_total_bytes, or narrow the scan with ignore_paths.", None))
        findings = _apply_suppressions(findings, mig_text, cov)
        return Report(__version__, changes, findings, issues, cov, cfg.fail_on)
    finally:
        for t in trees:
            t.close()


def _check_workspace(cfg: Config, repo: str) -> None:
    """When a workspace is set (always, in the GitHub Action) every path DCI reads must be inside it, wherever the path
    came from (CLI flag, action input or .dci.toml). Symlinks are resolved first."""
    if not cfg.workspace:
        # CLI default: paths named by a config file (which a pull request may have edited) may not leave the repo's parent dir
        if not cfg.allow_outside_config_paths:
            parent = os.path.dirname(repo)
            for name, path in cfg.config_consumer_repos:
                full = os.path.realpath(path)
                if not (full == parent or full.startswith(parent + os.sep)):
                    raise ConfigError(f"Consumer repository '{name}' (from the config file) is outside {parent}: {path}. "
                                      "Pass --allow-outside-config-paths if this is intended.")
        return
    ws = os.path.realpath(cfg.workspace)

    def inside(p: str) -> bool:
        full = os.path.realpath(p)
        return full == ws or full.startswith(ws + os.sep)

    if not inside(repo):
        raise ConfigError(f"Repository path is outside the workspace: {cfg.repo}")
    for name, path in [*cfg.consumer_repos, *cfg.config_consumer_repos]:
        if not inside(path):
            raise ConfigError(f"Consumer repository '{name}' is outside the workspace: {path}")


def _apply_suppressions(findings, mig_text: dict[str, str], cov: Coverage):
    kept = []
    for f in findings:
        if f.change is None or f.change.file not in mig_text:
            kept.append(f)
            continue
        lines = mig_text[f.change.file].splitlines()
        window = lines[max(0, f.change.line - 2): f.change.line]
        suppressed = False
        for ln in window:
            m = _SUPPRESS.search(ln)
            if m:
                ids = {x.strip().upper() for x in (m.group(1) or "").split(",") if x.strip()}
                if not ids or f.rule_id in ids:
                    suppressed = True
        if suppressed:
            cov.notes.append(f"suppressed {f.rule_id} at {f.change.file}:{f.change.line} by inline 'dci: ignore'")
        else:
            kept.append(f)
    return kept
