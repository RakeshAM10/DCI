"""Find code that calls an HTTP endpoint, in any language, by matching string literals against OpenAPI path templates.

This is deliberately language-independent text matching, not parsing: it sees `requests.delete(f"{BASE}/users/{uid}")`,
`fetch(`/users/${id}`, {method: "DELETE"})` and `http.NewRequest("DELETE", ...)` alike. Confidence follows the evidence on the line:
CONFIRMED needs a full path match AND the same HTTP method visible on the call; a path match without a visible method is POSSIBLE.
Route definitions of a server (decorators, router.get(...)) are skipped: they implement an endpoint, they do not call it."""
from __future__ import annotations

import re
import time
from collections import Counter
from dataclasses import dataclass

from dci.models import Confidence, Coverage, Reference
from dci.redact import redact
from dci.sources import Matcher, Tree

CODE_EXT = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".java", ".kt", ".kts", ".scala", ".rb", ".php", ".cs",
            ".rs", ".swift", ".dart", ".vue", ".svelte", ".sh", ".ex", ".exs", ".clj", ".groovy", ".lua", ".r", ".m")
MAX_LINE = 5000
KEEP_PER_CATEGORY = 500  # references stored per (operation, confidence, test/non-test); the rest are only counted, so memory stays flat
PH = "\x00"

_LIT = re.compile(r"""(["'`])((?:\\.|(?!\1)[^\\\n]){1,300})\1""")
_INTERP = re.compile(r"\$\{[^}\n]{0,100}\}|#\{[^}\n]{0,100}\}|\{[^{}/\s]{0,100}\}|%[sdvq]")
_HOST = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*:)?//[^/\s]*")
_METHOD_CALL = re.compile(r"\.(get|post|put|patch|delete|head|options)\s*\(", re.I)
_METHOD_TOKEN = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
_QUOTED_METHOD = re.compile(r"""["'](get|post|put|patch|delete|head|options)["']""", re.I)  # _request("delete", "/v1/x")
_METHOD_KV = re.compile(r"""(?i)\bmethod\s*[:=]\s*["']?(get|post|put|patch|delete|head|options)\b""")
_CURL_X = re.compile(r"(?i)(?:^|\s)-X\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
# a server declaring a route is not a caller
_DEFINITION = re.compile(
    r"""^\s*@\s*[\w.]+\.(?:route|get|post|put|patch|delete|head|options|api_route|websocket)\s*\("""      # Flask / FastAPI / Quart decorators
    r"""|^\s*@\s*(?:Get|Post|Put|Patch|Delete|Request)Mapping\b|^\s*@\s*(?:Path|GET|POST|PUT|DELETE|PATCH)\b"""  # Spring, JAX-RS
    r"""|\b(?:app|router|route|routes|bp|blueprint|server|mux|fastify|express|r|e|g|group)\.(?:get|post|put|patch|delete|head|options|route|all|use|handle|handlefunc|any)\s*\(\s*["'`]"""
    r"""|\b(?:path|re_path|url)\s*\(\s*r?["']"""  # Django
    r"""|\bHandleFunc\s*\(|\bHandle\s*\(\s*"|\bmapping\s*\(""", re.I)
_URL = re.compile(r"https?://[^\s\"'`)\]>,;]{1,300}")
_FETCH = re.compile(r"\bfetch\s*\(")
_SKIP_FILES = re.compile(r"(?:^|/)(?:routes?\.rb|urls\.py|openapi[^/]*|swagger[^/]*)$", re.I)


@dataclass
class OpMatcher:
    method: str
    path: str
    rx: re.Pattern
    prefixes: frozenset  # literal prefixes before the first placeholder (for "/users/" + id concatenation); empty when unusable
    anchor: str  # longest literal segment, for the cheap per-file prefilter


def _template_rx(path: str, prefixes: list[str]) -> tuple[re.Pattern, str, str]:
    segs = path.strip("/").split("/") if path.strip("/") else []
    parts = []
    for seg in segs:
        pieces = re.split(r"(\{[^{}/]*\})", seg)
        parts.append("".join("[^/]+" if x.startswith("{") and x.endswith("}") else re.escape(x) for x in pieces if x != ""))
    body = "/" + "/".join(parts)
    pre = "(?:" + "|".join(re.escape(p) for p in prefixes) + ")?" if prefixes else ""
    rx = re.compile("^" + pre + body + "/?$")
    literal = []
    for seg in segs:
        if "{" in seg:
            break
        literal.append(seg)
    prefix = "/" + "/".join(literal) + "/" if literal and len(literal) < len(segs) and "{" in segs[len(literal)] else ""
    if prefix:
        prefix = "\x01".join([prefix, *(b + prefix for b in prefixes)])  # joined, split again by the caller
    lits = [x for seg in segs for x in re.split(r"\{[^{}/]*\}", seg) if len(x) >= 3]
    return rx, prefix, max(lits, key=len) if lits else ""


def build_matchers(ops: list[tuple[str, str]], prefixes: list[str]) -> list[OpMatcher]:
    out = []
    for method, path in ops:
        rx, prefix, anchor = _template_rx(path, prefixes)
        out.append(OpMatcher(method, path, rx, frozenset(x for x in prefix.split("\x01") if x), anchor))
    return out


def normalize(lit: str) -> str | None:
    s = _INTERP.sub(PH, lit)
    s = _HOST.sub("", s)
    if s.startswith(PH + "/"):
        s = s[1:]
    s = s.split("?", 1)[0].split("#", 1)[0]
    return s if s.startswith("/") and len(s) > 1 else None


def method_hints(line: str, prev: str = "") -> set[str]:
    hints = set()
    for src in (line, prev if prev.rstrip().endswith(("(", ",")) else ""):
        if not src:
            continue
        hints.update(m.group(1).lower() for m in _METHOD_CALL.finditer(src))
        hints.update(m.group(1).lower() for m in _METHOD_TOKEN.finditer(src))
        hints.update(m.group(1).lower() for m in _METHOD_KV.finditer(src))
        hints.update(m.group(1).lower() for m in _QUOTED_METHOD.finditer(src))
        hints.update(m.group(1).lower() for m in _CURL_X.finditer(src))
    return hints


def match_line(line: str, prev: str, matchers: list[OpMatcher]) -> list[tuple[OpMatcher, Confidence, str]]:
    """(operation, confidence, note) for every operation this line calls."""
    out = []
    lits = None
    raws = [m.group(2) for m in _LIT.finditer(line)] + [m.group(0) for m in _URL.finditer(line)]  # quoted strings and bare URLs (shell, docs)
    for raw in raws:
        if "/" not in raw:
            continue
        p = normalize(raw)
        if p is None:
            continue
        if lits is None:
            lits = []
        lits.append(p)
    if not lits:
        return out
    hints = None
    for p in lits:
        for op in matchers:
            full = op.rx.match(p) is not None
            concat = (not full) and p in op.prefixes
            if not (full or concat):
                continue
            if hints is None:
                hints = method_hints(line, prev)
                if not hints and _FETCH.search(line):
                    hints = {"get"}  # fetch() without a method option is a GET
            if hints and op.method not in hints:
                continue
            if full and op.method in hints:
                out.append((op, Confidence.CONFIRMED, f"{op.method.upper()} {op.path}"))
            else:
                why = "path matches, HTTP method not visible on this line" if full else "path is built by concatenation; the method and the rest of the path are not visible"
                out.append((op, Confidence.POSSIBLE, f"{op.method.upper()} {op.path}: {why}"))
    return out


def is_definition(line: str) -> bool:
    return _DEFINITION.search(line) is not None


@dataclass
class Found:
    refs: dict  # (method, path) -> list[Reference], at most KEEP_PER_CATEGORY per (confidence, test) category
    totals: Counter  # ((method, path), confidence, is_test) -> true number of references

    def total(self, op: tuple[str, str], refs: list[Reference]) -> int:
        """True number of references of the same kind(s) as `refs` (which may have been capped)."""
        kinds = {(r.confidence, r.is_test) for r in refs}
        return sum(n for (o, c, t), n in self.totals.items() if o == op and (c, t) in kinds) if refs else 0


def scan_tree(tree: Tree, matchers: list[OpMatcher], tree_name: str, test_match: Matcher, ignore_match: Matcher, cov: Coverage,
              time_budget: float = 0.0, max_total_bytes: int = 0, found: Found | None = None) -> Found:
    found = found or Found({(m.method, m.path): [] for m in matchers}, Counter())
    if not matchers:
        return found
    anchors = sorted({m.anchor for m in matchers if m.anchor})
    prefilter = re.compile("|".join(re.escape(a) for a in anchors)) if anchors and len(anchors) <= 2000 and all(m.anchor for m in matchers) else None
    start = time.monotonic()
    total = 0
    skipped_defs = 0
    files = 0
    for path, size in tree.files():
        if not path.lower().endswith(CODE_EXT) or _SKIP_FILES.search(path) or ignore_match(path):
            continue
        if (time_budget and time.monotonic() - start > time_budget) or (max_total_bytes and total > max_total_bytes):
            cov.scan_incomplete = True
            cov.files_not_scanned += 1
            continue
        text = tree.read(path)
        if text is None:
            continue
        total += size
        if "\0" in text[:1000] or (prefilter is not None and not prefilter.search(text)):
            continue
        files += 1
        is_test = test_match(path)
        prev = ""
        for i, line in enumerate(text.split("\n"), 1):
            cur, prev_line = line, prev
            prev = line
            if len(cur) > MAX_LINE or "/" not in cur:
                continue
            hits = match_line(cur, prev_line, matchers)
            if not hits:
                continue
            if is_definition(cur):
                skipped_defs += 1
                continue
            done = set()
            for op, conf, note in hits:
                key = (op.method, op.path)
                if key in done:
                    continue
                done.add(key)
                found.totals[(key, conf, is_test)] += 1
                bucket = found.refs[key]
                if found.totals[(key, conf, is_test)] <= KEEP_PER_CATEGORY:
                    bucket.append(Reference(None, None, path, i, tree_name, "api_call", "ref", conf, redact(cur), is_test=is_test, note=note, anchor=i))
    cov.notes.append(f"API callers: {files} source file(s) searched in {tree_name}" + (f"; {skipped_defs} route definition(s) skipped (they implement an endpoint, they do not call it)" if skipped_defs else ""))
    return found
