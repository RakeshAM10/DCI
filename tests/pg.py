"""Ground truth from a real PostgreSQL engine (PGlite, PostgreSQL 18 compiled to WASM, run via node)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
RUNNER = os.path.join(HERE, "..", "tools", "pgcheck", "run_case.mjs")
AVAILABLE = bool(shutil.which("node")) and os.path.isdir(os.path.join(HERE, "..", "tools", "pgcheck", "node_modules", "@electric-sql"))


def run(setup: list[str], migration: list[str], queries: dict[str, str], pre_queries: dict[str, str] | None = None) -> dict:
    p = subprocess.run(["node", RUNNER], input=json.dumps({"setup": setup, "migration": migration, "queries": queries, "pre_queries": pre_queries or {}}),
                       capture_output=True, text=True, timeout=120, cwd=os.path.dirname(RUNNER))
    if p.returncode != 0:
        raise RuntimeError(p.stderr[-2000:])
    return json.loads(p.stdout.strip().splitlines()[-1])
