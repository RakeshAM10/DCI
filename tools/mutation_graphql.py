"""Recall/false-positive measurement for the GraphQL check by mutation, on a real repository.

  python tools/mutation_graphql.py REPO REV SCHEMA_PATH [--max N]

For every field in the schema at REV, build a PR that deletes just that field and run the GraphQL check. Ground truth by construction:
the field IS removed, so the change is breaking. A removal is *provable* only if some operation in the repository selects that field on
that type; an independent, deliberately crude oracle (the field name appears as a word in a non-schema file) says where a caller MAY exist.
Report: removals the tool called CONFIRMED where the oracle sees no mention anywhere (would be false positives), and removals the
oracle sees but the tool does not confirm (a human must look: usually the word is another type's field or plain prose)."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

from graphql import parse

from dci.config import Config
from sci.run import run_checks


def git(d, *a):
    return subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True).stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo"), ap.add_argument("rev"), ap.add_argument("schema")
    ap.add_argument("--max", type=int, default=1000)
    ns = ap.parse_args()
    tmp = tempfile.mkdtemp()
    try:
        work = os.path.join(tmp, "w")
        os.makedirs(work)
        subprocess.run(f"git -C {ns.repo} archive {ns.rev} | tar -x -C {work}", shell=True, check=True)
        git(work, "init", "-q", "-b", "main")
        git(work, "config", "user.email", "m@x"), git(work, "config", "user.name", "m")
        git(work, "add", "-A"), git(work, "commit", "-qm", "base")
        sp = os.path.join(work, ns.schema)
        text = open(sp, encoding="utf-8").read()
        doc = parse(text)
        words: dict[str, int] = {}
        corpus = []
        for root, dirs, files in os.walk(work):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            for f in files:
                p = os.path.join(root, f)
                if p != sp and f.endswith((".js", ".ts", ".jsx", ".tsx", ".graphql", ".gql", ".py", ".go", ".java")):
                    try:
                        corpus.append(open(p, encoding="utf-8").read())
                    except (OSError, UnicodeDecodeError):
                        pass
        blob = "\n".join(corpus)
        stats = {"fields": 0, "confirmed": 0, "oracle_mention": 0, "confirmed_no_mention": [], "mention_not_confirmed": [], "errors": 0}
        for d in doc.definitions:
            if d.kind != "object_type_definition":
                continue
            for fld in d.fields or []:
                if stats["fields"] >= ns.max:
                    break
                name = fld.name.value
                start = fld.description.loc.start if fld.description else fld.loc.start
                new = text[:start] + text[fld.loc.end:]
                try:
                    parse(new)
                except Exception:  # noqa: BLE001 - e.g. last field of a type: invalid SDL, skip
                    continue
                stats["fields"] += 1
                open(sp, "w", encoding="utf-8").write(new)
                git(work, "commit", "-aqm", f"remove {d.name.value}.{name}")
                cfg = Config(repo=work)
                cfg.base, cfg.head = "HEAD~1", "HEAD"
                try:
                    rep = run_checks(cfg, ["graphql"])
                except Exception as e:  # noqa: BLE001
                    stats["errors"] += 1
                    print(f"ERROR {d.name.value}.{name}: {e!r}")
                    git(work, "reset", "-q", "--hard", "HEAD~1")
                    continue
                conf = any(f.confidence.value == "confirmed" and f.rule_id in ("GQL101", "GQL104") and f"{d.name.value}.{name}" in f.message for f in rep.blocking())
                flagged = any(f"{d.name.value}.{name}" in f.message or f"{d.name.value}.{name}" in f.title for f in rep.findings)
                mention = bool(re.search(rf"\b{re.escape(name)}\b", blob))
                stats["confirmed"] += conf
                stats["oracle_mention"] += mention
                if conf and not mention:
                    stats["confirmed_no_mention"].append(f"{d.name.value}.{name}")
                if mention and not conf and not flagged:
                    stats["mention_not_confirmed"].append(f"{d.name.value}.{name}")
                git(work, "reset", "-q", "--hard", "HEAD~1")
        print(f"fields removed one at a time: {stats['fields']}  errors: {stats['errors']}")
        print(f"tool CONFIRMED (blocks): {stats['confirmed']}   oracle sees the name in code: {stats['oracle_mention']}")
        print(f"CONFIRMED but name appears nowhere (false-positive candidates): {stats['confirmed_no_mention']}")
        print(f"name appears in code but the tool said NOTHING about the removal (possible misses, review): {len(stats['mention_not_confirmed'])}")
        for x in stats["mention_not_confirmed"][:60]:
            print("   ", x)
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
