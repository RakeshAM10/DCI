"""Historical replay: run the SCI API check over every commit in a repository that changed an OpenAPI file, as if each commit were a PR
against its first parent. Prints every finding so a human can judge it. Usage: python tools/replay.py REPO [--max N] [--paths GLOB,...]"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time

from dci.config import Config
from dci.gitutil import run_git
from sci.run import run_checks


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--max", type=int, default=200)
    ap.add_argument("--checks", default="api")
    ap.add_argument("--jsonl", help="append every CONFIRMED (blocking) finding with its evidence to this file, for labelling")
    ap.add_argument("--globs", help="comma-separated spec globs (default: the standard OpenAPI file names)")
    ns = ap.parse_args()
    cfg0 = Config(repo=ns.repo)
    globs = ns.globs.split(",") if ns.globs else {"graphql": cfg0.graphql_schema_globs, "proto": cfg0.proto_globs, "db": cfg0.migration_globs,
        "deps": ["**/requirements*.txt", "**/requirements*.in", "**/pyproject.toml", "**/package.json", "**/go.mod"],
        "config": ["**/docker-compose*.yml", "**/docker-compose*.yaml", "**/compose*.yml", "**/compose*.yaml", "**/Dockerfile*", "**/.env*"]}.get(ns.checks, cfg0.api_spec_globs)
    pats = [g.replace("**/", "") for g in globs]
    out = run_git(ns.repo, "log", "--format=%H", "--first-parent", "--", *[f":(glob)**/{p}" for p in pats]).decode().split()
    print(f"{len(out)} commits touched a spec", file=sys.stderr)
    stats = {"commits": 0, "with_findings": 0, "errors": 0, "blocking": 0, "findings": 0}
    for sha in out[: ns.max]:
        try:
            run_git(ns.repo, "rev-parse", "--verify", "--quiet", sha + "^")
        except Exception:  # noqa: BLE001 - root commit
            continue
        cfg = Config(repo=ns.repo)
        if ns.checks not in ("db", "deps", "config"):
            cfg.api_spec_globs = cfg.graphql_schema_globs = cfg.proto_globs = globs
        cfg.base, cfg.head = sha + "^", sha
        cfg.time_budget_seconds = float(__import__("os").environ.get("REPLAY_BUDGET", cfg.time_budget_seconds))
        t = time.time()
        try:
            rep = run_checks(cfg, ns.checks.split(","))
        except Exception as e:  # noqa: BLE001
            stats["errors"] += 1
            print(f"{sha[:8]} ERROR {e.__class__.__name__}: {e}")
            continue
        stats["commits"] += 1
        if rep.findings:
            stats["with_findings"] += 1
        stats["findings"] += len(rep.findings)
        stats["blocking"] += bool(rep.blocking())
        subj = subprocess.run(["git", "-C", ns.repo, "log", "-1", "--format=%ad %s", "--date=short", sha], capture_output=True, text=True).stdout.strip()
        print(f"\n== {sha[:8]} {subj}  ({time.time() - t:.1f}s)")
        if ns.jsonl:
            import json, os
            with open(ns.jsonl, "a") as fh:
                for f in rep.blocking():
                    fh.write(json.dumps({"repo": os.path.basename(os.path.abspath(ns.repo)), "commit": sha, "subject": subj, "rule": f.rule_id,
                                         "title": f.title, "message": f.message, "file": f.file, "line": f.line,
                                         "evidence": [{"file": e.file, "line": e.line, "tree": e.tree, "snippet": e.snippet[:200]} for e in f.evidence[:5]]}) + "\n")
        for f in rep.findings:
            print(f"  [{f.rule_id}] {f.severity.value}/{f.confidence.value} {f.title}: {f.message.splitlines()[0][:110]}")
            for line in f.message.splitlines()[1:6]:
                print(f"      {line[:130]}")
            for e in f.evidence[:3]:
                print(f"      @ {e.file}:{e.line} {e.snippet[:90]}")
    print("\n" + " ".join(f"{k}={v}" for k, v in stats.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
