"""Command line interface. Exit codes: 0 pass, 1 blocking findings, 2 usage/config error, 3 internal error."""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__, report
from . import ai as ai_mod
from .analyze import analyze
from .config import Config, ConfigError, load_file
from .gitutil import GitError
from .github import GitHubError, upsert_comment


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dci", description="Database Change Intelligence: static compatibility checks for PostgreSQL migrations.")
    p.add_argument("--version", action="version", version=f"dci {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyse the migrations in a change")
    a.add_argument("--repo", default=".", help="repository root (default: .)")
    a.add_argument("--base", help="base revision (e.g. origin/main); migrations added/modified since the merge-base are analysed")
    a.add_argument("--head", help="head revision (default: working tree)")
    a.add_argument("--migration", action="append", default=[], help="analyse this migration file instead of using git (repeatable)")
    a.add_argument("--consumer", action="append", default=[], metavar="NAME=PATH", help="another repository whose code consumes this schema (repeatable)")
    a.add_argument("--allow-outside-config-paths", action="store_true", help="allow consumer repositories named in .dci.toml to live outside the repository's parent directory")
    a.add_argument("--config", help="path to .dci.toml (default: <repo>/.dci.toml if present)")
    a.add_argument("--workspace", help="reject the repository and every consumer repository (from flags or .dci.toml) that resolves outside this directory")
    a.add_argument("--format", choices=["text", "markdown", "json", "sarif", "html"], default="text")
    a.add_argument("--output", help="write the report to a file instead of stdout")
    a.add_argument("--fail-on", choices=["error", "warning", "never"], help="severity at which CONFIRMED findings fail the run")
    a.add_argument("--no-rolling-deploy", action="store_true", help="do not treat old-version/new-schema overlap as an error")
    a.add_argument("--ignore-rule", action="append", default=[], help="suppress a rule id (repeatable)")
    a.add_argument("--runtime-queries", action="append", default=[], help="file of queries seen in production, e.g. a pg_stat_statements export (CSV/JSON/JSONL); repeatable")
    a.add_argument("--runtime-blocks", action="store_true", help="treat runtime query evidence as CONFIRMED (you vouch the statistics are current)")
    a.add_argument("--workers", type=int, help="worker processes for scanning large trees (0 = automatic, 1 = off)")
    a.add_argument("--time-budget", type=float, help="seconds before the scan stops and reports itself incomplete (0 = unlimited)")
    a.add_argument("--ai", action="store_true", help="add advisory AI notes to findings (needs ANTHROPIC_API_KEY; sends redacted code excerpts to the API)")
    a.add_argument("--ai-model", help="model name for --ai")
    a.add_argument("--ai-max-findings", type=int, default=5, help="max findings analysed by --ai (1-20)")
    a.add_argument("--github-comment", action="store_true", help="post/update the report as a PR comment (needs GITHUB_TOKEN)")
    return p


def _build_config(ns: argparse.Namespace) -> Config:
    cfg = Config(repo=ns.repo)
    cfg_path = ns.config or os.path.join(ns.repo, ".dci.toml")
    if ns.config and not os.path.isfile(ns.config):
        raise ConfigError(f"Config file not found: {ns.config}")
    if os.path.isfile(cfg_path):
        load_file(cfg_path, cfg)
    cfg.base, cfg.head, cfg.migrations = ns.base, ns.head, list(ns.migration)
    cfg.workspace = ns.workspace
    cfg.allow_outside_config_paths = ns.allow_outside_config_paths
    cfg.runtime_queries = list(ns.runtime_queries)
    cfg.runtime_blocks = ns.runtime_blocks
    if ns.workers is not None:
        if not 0 <= ns.workers <= 64:
            raise ConfigError("--workers must be between 0 and 64")
        cfg.workers = ns.workers
    if ns.time_budget is not None:
        if ns.time_budget < 0:
            raise ConfigError("--time-budget must not be negative")
        cfg.time_budget_seconds = ns.time_budget
    for c in ns.consumer:
        name, sep, path = c.partition("=")
        if not sep or not name or not path:
            raise ConfigError(f"--consumer expects NAME=PATH, got: {c}")
        cfg.consumer_repos.append((name, path))
    if ns.fail_on:
        cfg.fail_on = ns.fail_on
    if ns.no_rolling_deploy:
        cfg.rolling_deploy = False
    cfg.ignore_rules = [*cfg.ignore_rules, *[r.upper() for r in ns.ignore_rule]]
    return cfg


def main(argv: list[str] | None = None, runner=None) -> int:
    """`runner(cfg) -> Report` replaces the database-only analysis (used by the `sci` command)."""
    ns = _parser().parse_args(argv)
    try:
        cfg = _build_config(ns)
        rep = (runner or analyze)(cfg)
    except (ConfigError, GitError) as e:
        print(f"dci: error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # fail closed: never report a pass when the analysis itself broke
        if os.environ.get("DCI_DEBUG"):
            raise
        print(f"dci: internal error: {e.__class__.__name__}: {e}", file=sys.stderr)
        return 3

    if ns.ai:
        key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        try:
            ai_cfg = ai_mod.AiConfig(api_key=key, model=ns.ai_model or ai_mod.DEFAULT_MODEL, max_findings=ns.ai_max_findings,
                                     base_url=os.environ.get("ANTHROPIC_BASE_URL", "").strip() or ai_mod.DEFAULT_BASE_URL)
        except ai_mod.AiError as e:
            print(f"dci: error: {e}", file=sys.stderr)
            return 2
        roots = {"head": cfg.repo, **{f"consumer:{n}": p for n, p in [*cfg.consumer_repos, *cfg.config_consumer_repos]}}
        try:
            ai_mod.enhance(rep, roots, ai_cfg)
        except Exception as e:  # noqa: BLE001 - advisory only
            print(f"dci: warning: AI assistance failed: {e.__class__.__name__}", file=sys.stderr)

    fmts = {"text": report.to_text, "markdown": report.to_markdown, "json": report.to_json, "sarif": report.to_sarif}
    if ns.format == "html":
        from sci.htmlreport import to_html
        fmts["html"] = to_html
    rendered = fmts[ns.format](rep)
    if ns.output:
        with open(ns.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    else:
        print(rendered)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(report.to_markdown(rep) + "\n")
        except OSError:
            pass
    if ns.github_comment:
        try:
            how = upsert_comment(report.to_markdown(rep, for_comment=True))
            print(f"dci: PR comment {how}", file=sys.stderr)
        except GitHubError as e:  # e.g. read-only token on fork PRs; the check result must not depend on this
            print(f"dci: warning: could not post PR comment: {e}", file=sys.stderr)
    return 1 if rep.blocking() else 0


if __name__ == "__main__":
    raise SystemExit(main())
