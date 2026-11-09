"""False-positive measurement. Replays real mainline commits as if each were a pull request against its first parent, records every BLOCKING
(CONFIRMED) finding, attaches objective signals, and writes a CSV for a human to label. `--score` then computes precision with a 95% interval.

  python tools/measure.py REPO --checks db,api,graphql,proto,deps,config --max 300 --out DIR [--window 50]
  python tools/measure.py --score DIR/findings.csv

Signals are evidence, not verdicts:
  evidence_valid   the cited file at the head commit has that line with that text (the finding points at real code)
  touched_later    the cited file was modified within WINDOW later mainline commits (a real break is usually fixed soon after; an FP never is)
Labels (column `label`): tp = the finding was a real break, fp = it was not, ? = cannot tell (excluded from precision)."""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import subprocess
import sys
import time

from dci.config import Config
from dci.gitutil import run_git
from sci.run import run_checks

COLS = ["repo", "commit", "date", "subject", "rule", "title", "file", "line", "snippet", "evidence_valid", "touched_later", "label", "note"]
MANIFESTS = ["package.json", "requirements*.txt", "pyproject.toml", "go.mod", "docker-compose*.y*ml", "compose*.y*ml", ".env*", "Dockerfile*"]


def _git(repo: str, *a: str) -> str:
    return run_git(repo, *a).decode("utf-8", "replace")


def _commits(repo: str, checks: list[str], cfg0: Config) -> list[str]:
    pats: list[str] = []
    if "db" in checks:
        pats += ["migrations/**", "alembic/**", "**/migrations/**", "*.sql"]
    if "api" in checks:
        pats += [g.replace("**/", "") for g in cfg0.api_spec_globs]
    if "graphql" in checks:
        pats += [g.replace("**/", "") for g in cfg0.graphql_schema_globs]
    if "proto" in checks:
        pats += ["*.proto"]
    if "deps" in checks or "config" in checks:
        pats += MANIFESTS
    specs = [f":(glob)**/{p.removeprefix('**/')}" for p in pats]
    return _git(repo, "log", "--format=%H", "--first-parent", "--", *specs).split()


def _valid(repo: str, sha: str, file: str, line: int, snippet: str) -> str:
    if not snippet or "[REDACTED" in snippet or line < 1:
        return "unchecked"
    try:
        text = _git(repo, "show", f"{sha}:{file}")
    except Exception:  # noqa: BLE001
        return "no"
    lines = text.split("\n")
    probe = snippet.strip()[:40]
    lo, hi = max(0, line - 1 - 3), min(len(lines), line + 3)  # multi-line constructs anchor a few lines away
    return "yes" if any(probe in ln for ln in lines[lo:hi]) else "no"


def _touched_later(repo: str, sha: str, file: str, window: int) -> str:
    try:
        out = _git(repo, "log", "--first-parent", "--format=%H", f"{sha}..HEAD", "--", file).split()
        if not out:
            return "never"
        nxt = out[-1]  # oldest later commit that touched the file
        dist = len(_git(repo, "rev-list", "--first-parent", f"{sha}..{nxt}").split())
        return f"yes({dist})" if dist <= window else f"later({dist})"
    except Exception:  # noqa: BLE001
        return "unknown"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - m) / d, (c + m) / d


def score(path: str) -> int:
    rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
    labelled = [r for r in rows if r["label"].strip().lower() in ("tp", "fp")]
    print(f"{len(rows)} blocking findings, {len(labelled)} labelled, {sum(1 for r in rows if r['label'].strip() == '?')} undecidable, "
          f"{len(rows) - len(labelled) - sum(1 for r in rows if r['label'].strip() == '?')} unlabelled")
    groups: dict[str, list[dict]] = {"ALL": labelled}
    for r in labelled:
        groups.setdefault(r["rule"], []).append(r)
    for name, g in groups.items():
        tp = sum(1 for r in g if r["label"].strip().lower() == "tp")
        lo, hi = wilson(tp, len(g))
        print(f"  {name:8} n={len(g):4}  precision={tp / len(g):.1%}  95% CI [{lo:.1%}, {hi:.1%}]  false-positive rate={1 - tp / len(g):.1%}" if g else f"  {name}: no labels")
    if len(labelled) < 30:
        print("note: fewer than 30 labels: the interval is wide; label more findings before trusting the number")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", nargs="?")
    ap.add_argument("--checks", default="db,api,graphql,proto,deps,config")
    ap.add_argument("--max", type=int, default=300)
    ap.add_argument("--window", type=int, default=50)
    ap.add_argument("--out", default="measure-out")
    ap.add_argument("--budget", type=float, default=120.0, help="seconds per commit for the caller scan")
    ap.add_argument("--score", help="findings.csv with the label column filled in")
    ns = ap.parse_args()
    if ns.score:
        return score(ns.score)
    if not ns.repo:
        ap.error("repo is required unless --score is used")
    checks = [c for c in ns.checks.split(",") if c]
    os.makedirs(ns.out, exist_ok=True)
    cfg0 = Config(repo=ns.repo)
    commits = _commits(ns.repo, checks, cfg0)
    name = os.path.basename(os.path.realpath(ns.repo))
    path = os.path.join(ns.out, "findings.csv")
    new = not os.path.exists(path)
    stats = {"repo": name, "commits_found": len(commits), "replayed": 0, "errors": 0, "commits_with_blocking": 0, "blocking_findings": 0,
             "incomplete_scans": 0, "evidence_checked": 0, "evidence_valid": 0, "touched_later": 0, "seconds": 0.0}
    t_all = time.time()
    with open(path, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, COLS)
        if new:
            w.writeheader()
        for sha in commits[: ns.max]:
            try:
                run_git(ns.repo, "rev-parse", "--verify", "--quiet", sha + "^")
            except Exception:  # noqa: BLE001
                continue
            cfg = Config(repo=ns.repo)
            cfg.base, cfg.head, cfg.time_budget_seconds = sha + "^", sha, ns.budget
            try:
                rep = run_checks(cfg, checks)
            except Exception as e:  # noqa: BLE001
                stats["errors"] += 1
                print(f"{sha[:8]} ERROR {e.__class__.__name__}: {e}", file=sys.stderr)
                continue
            stats["replayed"] += 1
            stats["incomplete_scans"] += bool(rep.coverage.scan_incomplete)
            blocking = rep.blocking()
            if not blocking:
                continue
            stats["commits_with_blocking"] += 1
            meta = _git(ns.repo, "log", "-1", "--format=%ad|%s", "--date=short", sha).strip().split("|", 1)
            for f in blocking:
                stats["blocking_findings"] += 1
                ev = next((e for e in f.evidence if e.tree == "head" or e.tree.startswith("runtime")), None) or (f.evidence[0] if f.evidence else None)
                file, line, snip = (ev.file, ev.line, ev.snippet) if ev else (f.file, f.line, "")
                valid = _valid(ns.repo, sha + "^" if ev and ev.tree == "base" else sha, file, line, snip) if ev else "contract"  # contract-level findings cite the changed spec itself
                later = _touched_later(ns.repo, sha, file, ns.window) if file else "unknown"
                if valid in ("yes", "no"):
                    stats["evidence_checked"] += 1
                    stats["evidence_valid"] += valid == "yes"
                stats["touched_later"] += later.startswith("yes")
                w.writerow({"repo": name, "commit": sha[:12], "date": meta[0], "subject": meta[1][:100], "rule": f.rule_id, "title": f.title, "file": file,
                            "line": line, "snippet": snip[:160].replace("\n", " "), "evidence_valid": valid, "touched_later": later, "label": "", "note": ""})
            fh.flush()
    stats["seconds"] = round(time.time() - t_all, 1)
    with open(os.path.join(ns.out, f"summary-{name}.json"), "w") as fh:
        json.dump(stats, fh, indent=2)
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
