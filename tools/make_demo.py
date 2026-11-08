"""Create a small repository with a base branch and a pull-request branch that breaks the database, the REST API, GraphQL and gRPC
at once, each with real caller code. Used by the self-test workflow (a real GitHub runner) and by tools/demo_pr.sh.

    python tools/make_demo.py DIR [--shallow]   ->  DIR/origin.git (bare) and DIR/work (clone, 'pr' checked out, origin/main present)
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

BASE = {
    "migrations/001_init.sql": "CREATE TABLE orders (id integer PRIMARY KEY, legacy_status text, total numeric);\n",
    "app/models.py": ("from sqlalchemy import Column, Integer, String, Numeric\nfrom sqlalchemy.orm import declarative_base\nBase = declarative_base()\n\n\n"
                      "class Order(Base):\n    __tablename__ = 'orders'\n    id = Column(Integer, primary_key=True)\n    legacy_status = Column(String)\n    total = Column(Numeric)\n"),
    "app/report.py": "from .models import Order\n\n\ndef open_orders(session):\n    return session.query(Order.id).filter(Order.legacy_status == 'open').all()\n",
    "openapi.yaml": ("openapi: 3.0.3\ninfo: {title: demo, version: '1'}\nservers: [{url: https://api.example.com/v1}]\npaths:\n"
                     "  /users/{id}:\n    get:\n      parameters: [{name: id, in: path, required: true, schema: {type: string}}]\n"
                     "      responses: {'200': {description: ok}}\n    delete:\n      parameters: [{name: id, in: path, required: true, schema: {type: string}}]\n"
                     "      responses: {'204': {description: gone}}\n"),
    "svc/cleanup.py": 'import requests\nBASE = "https://api.example.com/v1"\n\n\ndef remove(uid):\n    requests.delete(f"{BASE}/users/{uid}")\n',
    "schema.graphql": "type Query { me: User legacyName: String }\ntype User { id: ID! }\n",
    "web/queries.ts": 'import { gql } from "@apollo/client";\nexport const LEGACY = gql`\n  query Legacy {\n    legacyName\n  }\n`;\n',
    "protos/hello.proto": ('syntax = "proto3";\npackage hello;\nservice Greeter {\n  rpc SayHello (Req) returns (Rep) {}\n  rpc Bye (Req) returns (Rep) {}\n}\n'
                           "message Req { string name = 1; }\nmessage Rep { string message = 1; }\n"),
    "go/client.go": 'package main\n\nfunc run(c pb.GreeterClient) {\n\t_, _ = c.Bye(ctx, &pb.Req{Name: "x"}) // hello.Greeter\n}\n',
}
PR = {
    "migrations/002_drop.sql": "ALTER TABLE orders DROP COLUMN legacy_status;\n",
    "openapi.yaml": BASE["openapi.yaml"].replace(
        "    delete:\n      parameters: [{name: id, in: path, required: true, schema: {type: string}}]\n      responses: {'204': {description: gone}}\n", ""),
    "schema.graphql": "type Query { me: User }\ntype User { id: ID! }\n",
    "protos/hello.proto": BASE["protos/hello.proto"].replace("  rpc Bye (Req) returns (Rep) {}\n", "").replace("string name = 1;", "string name = 7;"),
}


def _git(cwd: str, *a: str) -> None:
    subprocess.run(["git", "-C", cwd, "-c", "user.email=demo@example.invalid", "-c", "user.name=demo", *a], check=True, capture_output=True)


def _write(root: str, files: dict[str, str]) -> None:
    for rel, text in files.items():
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(text)


WORKFLOW = """name: SCI
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  sci:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: __ACTION__
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
"""


def make(dest: str, shallow: bool = False, action: str | None = None) -> str:
    """`action` (for example OWNER/sci@REF) also writes a workflow that runs it, for a real pull request on GitHub."""
    dest = os.path.abspath(dest)
    seed = os.path.join(dest, "seed")
    os.makedirs(seed)
    _git(seed, "init", "-q", "-b", "main")
    _write(seed, BASE)
    if action:
        _write(seed, {".github/workflows/sci.yml": WORKFLOW.replace("__ACTION__", action)})
    _git(seed, "add", "-A")
    _git(seed, "commit", "-qm", "base")
    _git(seed, "checkout", "-qb", "pr")
    _write(seed, PR)
    _git(seed, "add", "-A")
    _git(seed, "commit", "-qm", "breaking pull request")
    origin = os.path.join(dest, "origin.git")
    subprocess.run(["git", "clone", "-q", "--bare", seed, origin], check=True, capture_output=True)
    work = os.path.join(dest, "work")
    cmd = ["git", "clone", "-q", *(["--depth", "1"] if shallow else []), "--branch", "pr", f"file://{origin}", work]
    subprocess.run(cmd, check=True, capture_output=True)
    return work


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dest")
    ap.add_argument("--shallow", action="store_true", help="shallow single-branch clone, like actions/checkout's default")
    ap.add_argument("--action", help="write a workflow that uses this action (OWNER/REPO@REF)")
    ns = ap.parse_args()
    print(make(ns.dest, ns.shallow, ns.action))
    return 0


if __name__ == "__main__":
    sys.exit(main())
