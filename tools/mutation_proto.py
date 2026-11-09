"""Recall measurement for the protobuf check by mutation, on real .proto files.

  python tools/mutation_proto.py REPO REV [--glob SUBSTR] [--max N]

For every field of every message in matching .proto files at REV, build a PR that renumbers the field (a wire-incompatible change by
definition) and run the proto check. The change is known-breaking by construction, so each one that is not CONFIRMED is a miss."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import tempfile

from dci.config import Config
from sci.run import run_checks

FIELD = re.compile(r"^(\s*(?:optional\s+|repeated\s+)?[A-Za-z_][\w.]*(?:\s*<[^>]*>)?\s+[A-Za-z_]\w*\s*=\s*)(\d+)(\s*[;\[])", re.M)


def git(d, *a):
    return subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True).stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo"), ap.add_argument("rev")
    ap.add_argument("--glob", default="")
    ap.add_argument("--max", type=int, default=300)
    ns = ap.parse_args()
    tmp = tempfile.mkdtemp()
    try:
        work = os.path.join(tmp, "w")
        os.makedirs(work)
        subprocess.run(f"git -C {ns.repo} archive {ns.rev} | tar -x -C {work}", shell=True, check=True)
        git(work, "init", "-q", "-b", "main"), git(work, "config", "user.email", "m@x"), git(work, "config", "user.name", "m")
        git(work, "add", "-A"), git(work, "commit", "-qm", "base")
        protos = [os.path.relpath(os.path.join(r, f), work) for r, _, fs in os.walk(work) for f in fs if f.endswith(".proto") and ns.glob in os.path.join(r, f)]
        n = hit = errors = reported_unknown = 0
        misses = []
        for rel in sorted(protos):
            path = os.path.join(work, rel)
            text = open(path, encoding="utf-8").read()
            for m in list(FIELD.finditer(text)):
                if n >= ns.max:
                    break
                if re.match(r"\s*(reserved|option|extensions|syntax|package|import|enum)\b", m.group(0)):
                    continue
                new = text[:m.start(2)] + str(int(m.group(2)) + 1000) + text[m.end(2):]
                n += 1
                open(path, "w", encoding="utf-8").write(new)
                git(work, "commit", "-aqm", "renumber")
                cfg = Config(repo=work)
                cfg.base, cfg.head = "HEAD~1", "HEAD"
                try:
                    rep = run_checks(cfg, ["proto"])
                    ok = any(f.rule_id == "PRT111" and f.confidence.value == "confirmed" for f in rep.blocking())
                    if not ok and any(f.rule_id == "PRT902" for f in rep.findings):
                        reported_unknown += 1  # could not be compiled; said so explicitly
                        git(work, "reset", "-q", "--hard", "HEAD~1")
                        continue
                except Exception as e:  # noqa: BLE001
                    errors += 1
                    ok = False
                    print("ERROR", rel, m.group(0).strip()[:60], repr(e)[:100])
                hit += ok
                if not ok:
                    misses.append(f"{rel}: {m.group(0).strip()[:70]}")
                git(work, "reset", "-q", "--hard", "HEAD~1")
        print(f"proto files: {len(protos)}  field renumberings: {n}  CONFIRMED wire-incompatible: {hit}  reported UNKNOWN (cannot compile): {reported_unknown}  SILENT MISSES: {len(misses)}  errors: {errors}")
        for x in misses[:40]:
            print("  MISS", x)
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
