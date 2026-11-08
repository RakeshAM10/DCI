"""Runtime evidence: queries that were really executed against the database (for example an export of pg_stat_statements).

This is the language-independent counterpart of the static scan: a service written in any language shows up here as soon as it
runs a query that touches a changed table or column. The input is data supplied by the operator, never executed.

Accepted files (UTF-8), at most MAX_BYTES and MAX_ROWS rows:
- CSV with a header row containing a `query` column and optionally `calls`
  (e.g. psql: \\copy (select query, calls from pg_stat_statements) to 'q.csv' csv header)
- JSON: a list of {"query": ..., "calls": ...}, or {"queries": [...]}
- JSON Lines: one such object per line

Every reference found this way is POSSIBLE by default, because the statistics have no timestamp (a query can come from code that
was retired long ago). With `blocks=True` the operator declares the statistics current and they are treated as CONFIRMED."""
from __future__ import annotations

import csv
import io
import json
import os
from dataclasses import dataclass, replace

from .config import ConfigError
from .consumers import sql_references
from .models import Confidence, Reference
from .redact import redact

MAX_BYTES = 50_000_000
MAX_ROWS = 200_000
MAX_QUERY_CHARS = 100_000


@dataclass
class RuntimeQuery:
    query: str
    calls: int | None
    row: int


def _calls(v) -> int | None:
    try:
        n = int(float(str(v).strip()))
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def load_queries(path: str) -> list[RuntimeQuery]:
    try:
        size = os.path.getsize(path)
    except OSError as e:
        raise ConfigError(f"Runtime query file cannot be read: {path} ({e.__class__.__name__})") from None
    if size > MAX_BYTES:
        raise ConfigError(f"Runtime query file is larger than {MAX_BYTES // 1_000_000} MB: {path}")
    try:
        with open(path, "rb") as fh:
            text = fh.read(MAX_BYTES + 1).decode("utf-8-sig", "replace")
    except OSError as e:
        raise ConfigError(f"Runtime query file cannot be read: {path} ({e.__class__.__name__})") from None
    rows: list[tuple[object, object]] = []
    stripped = text.lstrip()
    if stripped.startswith(("[", "{")):
        try:
            data = json.loads(text)
            items = data.get("queries") if isinstance(data, dict) else data
            if not isinstance(items, list):
                raise ValueError("expected a list")
        except ValueError:
            items = []
            for ln in text.splitlines():  # JSON Lines
                if ln.strip():
                    try:
                        items.append(json.loads(ln))
                    except ValueError:
                        raise ConfigError(f"Runtime query file is not valid JSON or JSON Lines: {path}") from None
        for it in items:
            if not isinstance(it, dict) or not isinstance(it.get("query"), str):
                raise ConfigError(f"Runtime query file: every entry needs a string 'query' ({path})")
            rows.append((it["query"], it.get("calls")))
    else:
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or "query" not in [f.strip().lower() for f in reader.fieldnames]:
            raise ConfigError(f"Runtime query file needs a CSV header with a 'query' column, or JSON: {path}")
        names = {f.strip().lower(): f for f in reader.fieldnames}
        for rec in reader:
            rows.append((rec.get(names["query"]) or "", rec.get(names["calls"]) if "calls" in names else None))
    if len(rows) > MAX_ROWS:
        raise ConfigError(f"Runtime query file has more than {MAX_ROWS} rows: {path}")
    return [RuntimeQuery(q[:MAX_QUERY_CHARS], _calls(c), i + 1) for i, (q, c) in enumerate(rows) if isinstance(q, str) and q.strip()]


def runtime_references(path: str, blocks: bool = False) -> tuple[list[Reference], int, int]:
    """(references, queries read, queries that could not be parsed)."""
    name = os.path.basename(path)
    queries = load_queries(path)
    refs: list[Reference] = []
    unparsed = 0
    for q in queries:
        found, ok = sql_references(q.query, name, q.row, f"runtime:{name}", "runtime_query", False)
        if not ok:
            unparsed += 1
        seen = f"seen in {q.calls} execution(s)" if q.calls is not None else "seen in the query statistics"
        for r in found:
            refs.append(replace(r, tree=f"runtime:{name}", via="runtime_query", line=q.row, anchor=q.row, snippet=redact(" ".join(q.query.split())),
                                confidence=r.confidence if blocks else (Confidence.POSSIBLE if r.confidence == Confidence.CONFIRMED else r.confidence),
                                note=f"{seen}; runtime evidence has no timestamp" if not blocks else seen))
    return refs, len(queries), unparsed
