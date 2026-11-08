"""Runtime evidence for APIs: requests that were really served (access-log export). Parsed as data, never executed.

Accepted (UTF-8): JSON Lines / JSON list / CSV with `method` and `path` (or `url`) and optional `count`, `status`;
or lines in Common/Combined Log Format ("GET /users/1 HTTP/1.1" 200 ...). Requests are aggregated per (method, path)
while reading, so memory stays bounded by the number of distinct endpoints, not the number of requests."""
from __future__ import annotations

import csv
import io
import json
import os
import re
from collections import OrderedDict
from dataclasses import dataclass

from dci.config import ConfigError
from dci.models import Confidence, Reference
from dci.redact import redact

from .callers import OpMatcher, normalize

MAX_BYTES = 200_000_000
MAX_ROWS = 5_000_000
MAX_DISTINCT = 200_000
KEEP_PER_OP = 500
_CLF = re.compile(r'"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (\S{1,2048}) HTTP/[\d.]+"\s+(\d{3})')


@dataclass
class Hit:
    method: str
    path: str
    count: int
    ok: int  # requests with status < 400 or unknown status
    first_row: int


def _add(agg: OrderedDict, method, path, count, status, row) -> None:
    method = str(method).strip().lower()
    p = normalize(str(path).strip()) if str(path).strip().startswith(("/", "http")) else None
    if not p or method not in ("get", "post", "put", "patch", "delete", "head", "options"):
        return
    k = (method, re.sub(r"/\d+(?=/|$)", "/\x00", p))  # fold numeric ids so distinct paths stay bounded
    h = agg.get(k)
    if h is None:
        if len(agg) >= MAX_DISTINCT:
            return
        h = agg[k] = Hit(method, p, 0, 0, row)
    h.count += count
    try:
        okay = status is None or int(status) < 400
    except (TypeError, ValueError):
        okay = True
    if okay:
        h.ok += count


def _count(v) -> int:
    try:
        n = int(float(str(v).strip()))
        return n if n > 0 else 1
    except (TypeError, ValueError):
        return 1


def load(path: str) -> tuple[list[Hit], int]:
    """(aggregated hits, rows read)."""
    try:
        if os.path.getsize(path) > MAX_BYTES:
            raise ConfigError(f"Access log is larger than {MAX_BYTES // 1_000_000} MB: {path}")
        fh = open(path, "r", encoding="utf-8-sig", errors="replace")  # noqa: SIM115 - streamed below
    except OSError as e:
        raise ConfigError(f"Access log cannot be read: {path} ({e.__class__.__name__})") from None
    agg: OrderedDict = OrderedDict()
    rows = 0
    with fh:
        head = fh.read(4096)
        fh.seek(0)
        first = head.lstrip()[:1]
        if first == "[":
            try:
                items = json.load(fh)
            except ValueError:
                raise ConfigError(f"Access log is not valid JSON: {path}") from None
            for i, it in enumerate(items if isinstance(items, list) else [], 1):
                rows += 1
                if rows > MAX_ROWS:
                    raise ConfigError(f"Access log has more than {MAX_ROWS} rows: {path}")
                if isinstance(it, dict):
                    _add(agg, it.get("method", ""), it.get("path") or it.get("url") or "", _count(it.get("count", 1)), it.get("status"), i)
        elif first == "{":
            for i, ln in enumerate(fh, 1):
                if not ln.strip():
                    continue
                rows += 1
                if rows > MAX_ROWS:
                    raise ConfigError(f"Access log has more than {MAX_ROWS} rows: {path}")
                try:
                    it = json.loads(ln)
                except ValueError:
                    raise ConfigError(f"Access log line {i} is not valid JSON: {path}") from None
                if isinstance(it, dict):
                    _add(agg, it.get("method", ""), it.get("path") or it.get("url") or "", _count(it.get("count", 1)), it.get("status"), i)
        else:
            if "method" in head.splitlines()[0].lower() if head.strip() else False:
                reader = csv.DictReader(io.StringIO(fh.read(MAX_BYTES)))
                names = {(f or "").strip().lower(): f for f in (reader.fieldnames or [])}
                if "method" not in names or not ({"path", "url"} & set(names)):
                    raise ConfigError(f"Access log CSV needs 'method' and 'path' (or 'url') columns: {path}")
                pcol = names.get("path") or names["url"]
                for i, rec in enumerate(reader, 1):
                    rows += 1
                    if rows > MAX_ROWS:
                        raise ConfigError(f"Access log has more than {MAX_ROWS} rows: {path}")
                    _add(agg, rec.get(names["method"]) or "", rec.get(pcol) or "", _count(rec.get(names["count"])) if "count" in names else 1,
                         rec.get(names["status"]) if "status" in names else None, i)
            else:
                for i, ln in enumerate(fh, 1):
                    if len(ln) > 8192:
                        continue
                    m = _CLF.search(ln)
                    if m:
                        rows += 1
                        if rows > MAX_ROWS:
                            raise ConfigError(f"Access log has more than {MAX_ROWS} rows: {path}")
                        _add(agg, m.group(1), m.group(2), 1, m.group(3), i)
    if rows == 0:
        raise ConfigError(f"Access log contains no recognisable requests (expected JSON, JSON Lines, CSV with method/path, or Common Log Format): {path}")
    return list(agg.values()), rows


def references(path: str, matchers: list[OpMatcher], blocks: bool) -> tuple[dict[tuple[str, str], list[Reference]], int, int]:
    """Per-operation references from an access log, plus (rows read, distinct endpoints)."""
    name = os.path.basename(path)
    hits, rows = load(path)
    out: dict[tuple[str, str], list[Reference]] = {(m.method, m.path): [] for m in matchers}
    for h in hits:
        for op in matchers:
            if op.method == h.method and op.rx.match(h.path):
                if h.ok == 0:
                    continue  # only ever answered with an error (for example 404): nobody is successfully using it
                if len(out[(op.method, op.path)]) >= KEEP_PER_OP:
                    continue
                conf = Confidence.CONFIRMED if blocks else Confidence.POSSIBLE
                note = f"{h.ok} successful request(s) in the log" + ("" if blocks else "; logs carry no guarantee the caller still exists")
                out[(op.method, op.path)].append(Reference(None, None, name, h.first_row, f"runtime:{name}", "access_log", "ref", conf,
                                                         redact(f"{h.method.upper()} {h.path}"), note=note, anchor=h.first_row))
    return out, rows, len(hits)
