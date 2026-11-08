"""Run every enabled check and merge the results into one report (one verdict, one exit code)."""
from __future__ import annotations

from dci.analyze import analyze
from dci.config import Config, ConfigError
from dci.models import Coverage, Report

from . import __version__, check_api, check_config, check_deps, check_graphql, check_proto, check_sim

ALL_CHECKS = ("db", "api", "graphql", "proto", "deps", "config")
OPT_IN_CHECKS = ("sim",)  # executes repository code: never part of the default set


def run_checks(cfg: Config, checks: list[str] | tuple[str, ...] = ALL_CHECKS) -> Report:
    checks = list(dict.fromkeys(checks))
    bad = [c for c in checks if c not in ALL_CHECKS + OPT_IN_CHECKS]
    if bad or not checks:
        raise ConfigError(f"Unknown check(s) {bad}; choose from {', '.join(ALL_CHECKS + OPT_IN_CHECKS)}")
    if "db" in checks:
        rep = analyze(cfg)
    else:
        rep = Report(__version__, [], [], [], Coverage(), cfg.fail_on)
    if "api" in checks:
        rep.findings.extend(check_api.run(cfg, rep.coverage))
    if "graphql" in checks:
        rep.findings.extend(check_graphql.run(cfg, rep.coverage))
    if "proto" in checks:
        rep.findings.extend(check_proto.run(cfg, rep.coverage))
    if "deps" in checks:
        rep.findings.extend(check_deps.run(cfg, rep.coverage))
    if "config" in checks:
        rep.findings.extend(check_config.run(cfg, rep.coverage))
    if "sim" in checks:
        rep.findings.extend(check_sim.run(cfg, rep.coverage))
    rep.title = "SCI change check"
    n_db = len(rep.changes)
    from dci.report import _counts  # noqa: PLC0415 - avoid a module cycle at import time
    rep.headline = f"{_counts(rep)} · checks: {', '.join(checks)} · {n_db} schema change(s) · SCI {__version__}"
    return rep
