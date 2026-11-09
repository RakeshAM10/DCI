"""Recall/false-positive measurement for the dependency check by mutation, on a real package.json.

  python tools/mutation_deps.py REPO REV [PACKAGE_JSON_PATH]

Removes each dependency from package.json in turn (a PR that drops it). Oracle, independent of SCI's matcher: the package name appears in a
quote-delimited import/require string in some JS/TS file. Reports CONFIRMED-without-oracle (false positives) and oracle-without-CONFIRMED (misses)."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile

from dci.config import Config
from sci.run import run_checks


def git(d, *a):
    return subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True).stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo"), ap.add_argument("rev"), ap.add_argument("path", nargs="?", default="package.json")
    ns = ap.parse_args()
    tmp = tempfile.mkdtemp()
    try:
        work = os.path.join(tmp, "w")
        os.makedirs(work)
        subprocess.run(f"git -C {ns.repo} archive {ns.rev} | tar -x -C {work}", shell=True, check=True)
        git(work, "init", "-q", "-b", "main"), git(work, "config", "user.email", "m@x"), git(work, "config", "user.name", "m")
        git(work, "add", "-A"), git(work, "commit", "-qm", "base")
        pj = os.path.join(work, ns.path)
        orig = json.load(open(pj))
        text = open(pj).read()
        src = []
        for r, ds, fs in os.walk(work):
            ds[:] = [d for d in ds if d not in (".git", "node_modules")]
            for f in fs:
                if f.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue")):
                    try:
                        src.append(open(os.path.join(r, f), encoding="utf-8").read())
                    except (OSError, UnicodeDecodeError):
                        pass
        blob = "\n".join(src)
        fp, miss, n, conf_n = [], [], 0, 0
        for sect in ("dependencies", "devDependencies"):
            for name in list(orig.get(sect, {})):
                d = json.loads(text)
                del d[sect][name]
                open(pj, "w").write(json.dumps(d, indent=2))
                git(work, "commit", "-aqm", f"drop {name}")
                cfg = Config(repo=work)
                cfg.base, cfg.head = "HEAD~1", "HEAD"
                rep = run_checks(cfg, ["deps"])
                conf = any(f.rule_id == "DEP101" and f"'{name}'" in f.message for f in rep.blocking())
                seen = bool(re.search(r"""['"]""" + re.escape(name) + r"""(/[^'"]*)?['"]""", blob))
                n += 1
                conf_n += conf
                if conf and not seen:
                    fp.append(name)
                if seen and not conf:
                    miss.append(name)
                git(work, "reset", "-q", "--hard", "HEAD~1")
        print(f"dependencies removed one at a time: {n}   CONFIRMED: {conf_n}")
        print(f"CONFIRMED but no import found by the oracle (false-positive candidates): {fp}")
        print(f"oracle sees an import but SCI did not confirm (misses, review): {miss}")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
