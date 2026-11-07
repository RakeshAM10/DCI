"""SQL helpers: quote-aware statement splitting and parameter normalisation."""
from __future__ import annotations

import re

MAX_SQL_LEN = 200_000


def split_statements(sql: str) -> list[tuple[str, int]]:
    """Split on top-level semicolons, respecting '...', "...", $tag$...$tag$, -- and /* */.
    Returns (statement_text, zero_based_line_offset_of_statement_start)."""
    out: list[tuple[str, int]] = []
    i, n = 0, len(sql)
    start = 0
    line = 0
    start_line = 0
    started = False
    while i < n:
        c = sql[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j == -1 else j
            continue
        if c == "/" and sql.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if sql.startswith("/*", j):
                    depth += 1
                    j += 2
                elif sql.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    if sql[j] == "\n":
                        line += 1
                    j += 1
            i = j
            continue
        if not started and not c.isspace():
            started = True
            start = i
            start_line = line
        if c == "'" or c == '"':
            q, j = c, i + 1
            while j < n:
                if sql[j] == "\n":
                    line += 1
                if sql[j] == q:
                    if j + 1 < n and sql[j + 1] == q:
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            continue
        if c == "$":
            m = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$", sql[i:])
            if m:
                tag = m.group(0)
                j = sql.find(tag, i + len(tag))
                end = n if j == -1 else j + len(tag)
                line += sql.count("\n", i, end)
                i = end
                continue
        if c == ";":
            stmt = sql[start:i].strip()
            if started and stmt:
                out.append((stmt, start_line))
            started = False
            i += 1
            continue
        i += 1
    tail = sql[start:].strip() if started else ""
    if tail:
        out.append((tail, start_line))
    return out


_PLACEHOLDERS = [
    (re.compile(r"%\(\w+\)s"), "NULL"),
    (re.compile(r"(?<!%)%s"), "NULL"),
    (re.compile(r"(?<!:):(?!:)[A-Za-z_]\w*"), "NULL"),
    (re.compile(r"\$\d+"), "NULL"),
]


def normalize_params(sql: str) -> str:
    """Replace driver bind placeholders (:name, %s, %(name)s, $1) with NULL so the SQL parses."""
    # Protect '::' casts from the :name rule.
    for rx, repl in _PLACEHOLDERS:
        sql = rx.sub(repl, sql)
    return sql


SQL_START = re.compile(r"^\s*\(?\s*(select|insert\s+into|update|delete\s+from|with|merge\s+into)\b", re.I)
