from __future__ import annotations

import os
import re
import subprocess

from dci.analyze import analyze
from dci.config import Config
from dci.models import Confidence, Report, Severity

MARK = re.compile(r"#\s*(Q\d+)\b")

ALEMBIC_TMPL = '''"""change"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"


def upgrade():
    {body}


def downgrade():
    pass
'''


def write_files(root: str, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)


def git(repo: str, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, text=True, env=env).stdout.strip()


def q_ids(report: Report, roots: dict[str, str], confidence: Confidence, severity: Severity | None = None) -> set[str]:
    """Marker ids (# Qn) of source lines that findings of the given confidence point at (head trees only)."""
    out: set[str] = set()
    for f in report.findings:
        if f.confidence != confidence or (severity and f.severity != severity) or f.rule_id.endswith(("04",)) and f.rule_id in ("DCI104", "DCI114", "DCI124", "DCI134", "DCI403"):
            continue
        for e in f.evidence:
            if e.tree not in roots or e.is_test:
                continue
            path = os.path.join(roots[e.tree], e.file)
            try:
                line = open(path, encoding="utf-8").read().splitlines()[e.line - 1]
            except (OSError, IndexError):
                continue
            m = MARK.search(line)
            if m:
                out.add(m.group(1))
    return out
