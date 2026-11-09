"""False-positive statistics for blocking (CONFIRMED) findings.

  python tools/fp_report.py FINDINGS.jsonl... --labels labels.json [--commits N]

FINDINGS.jsonl is written by `tools/replay.py --jsonl`. labels.json maps a finding key ("repo:commit8:rule:file:line") to
{"label": "TP"|"FP"|"UNCLEAR", "why": "..."}. Prints, per rule and overall, the true-positive rate with a 95% Wilson interval,
and lists findings that still have no label. UNCLEAR findings are counted against the tool (as FP) in the conservative figure."""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict


def key(d: dict) -> str:
    return f"{d['repo']}:{d['commit'][:8]}:{d['rule']}:{d['file']}:{d['line']}"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - m) / d, (c + m) / d


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("findings", nargs="+")
    ap.add_argument("--labels", required=True)
    ap.add_argument("--commits", type=int, help="total commits replayed, to report findings per 100 commits")
    ns = ap.parse_args()
    labels = json.load(open(ns.labels))
    rows, seen = [], set()
    for path in ns.findings:
        for line in open(path):
            d = json.loads(line)
            if key(d) not in seen:
                seen.add(key(d))
                rows.append(d)
    by = defaultdict(lambda: {"TP": 0, "FP": 0, "UNCLEAR": 0, "NONE": 0})
    todo = []
    for d in rows:
        lab = labels.get(key(d), {}).get("label", "NONE")
        by[d["rule"]][lab] += 1
        by["ALL"][lab] += 1
        if lab == "NONE":
            todo.append(key(d))
    print(f"{'rule':8} {'n':>4} {'TP':>4} {'FP':>4} {'?':>4}  precision (labelled)   95% CI           conservative (? = FP)")
    for rule in sorted(by, key=lambda r: (r == "ALL", r)):
        c = by[rule]
        n = c["TP"] + c["FP"]
        lo, hi = wilson(c["TP"], n)
        lo2, hi2 = wilson(c["TP"], n + c["UNCLEAR"])
        p = f"{c['TP'] / n:.1%}" if n else "n/a"
        print(f"{rule:8} {n + c['UNCLEAR'] + c['NONE']:>4} {c['TP']:>4} {c['FP']:>4} {c['UNCLEAR']:>4}  {p:>9}   [{lo:.1%}, {hi:.1%}]   {c['TP'] / (n + c['UNCLEAR']) if n + c['UNCLEAR'] else 0:.1%} [{lo2:.1%}, {hi2:.1%}]")
    if ns.commits:
        print(f"\n{len(rows)} blocking findings over {ns.commits} replayed commits = {100 * len(rows) / ns.commits:.1f} per 100 commits")
    if todo:
        print(f"\n{len(todo)} unlabelled:\n  " + "\n  ".join(todo))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
