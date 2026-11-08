"""Find code that depends on database tables/columns.

Python (SQLAlchemy) is parsed with `ast`: nothing is imported or executed. SQL (raw strings, f-strings, .sql files)
is parsed with SQLGlot. Anything that cannot be resolved to a concrete table/column is reported as POSSIBLE
(dynamic SQL, ambiguous names), never CONFIRMED."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp

from .identifiers import alias_key, ident_name, node_line, table_schema, tkey
from .models import Confidence, Coverage, Reference
from .redact import redact
from .sources import Matcher, Tree
from .sqlutil import SQL_START, normalize_params, split_statements

MODEL_MARKERS = ("__tablename__", "Column(", "mapped_column(", "Table(", "table=True")
UNANALYZED_EXT = {".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs", ".scala", ".ex", ".exs", ".swift"}
_WORD = re.compile(r"[a-z_][a-z0-9_]*")
_STRUCT = re.compile(r"(?is)\b(from|into|join)\s+[\w\"{]|\bupdate\s+[\w\"{]+\s+set\b|\bset\b.*=")
MAX_PY_STRING = 100_000
# `from x import y as z` (single line, or inside a parenthesised import list): only such files are parsed to collect aliases
_ALIAS_IMPORT = re.compile(r"(?m)^[ \t]*from[ \t]+[\w.]+[ \t]+import\b[^\n]*\bas[ \t]+\w|^[ \t]*from[ \t]+[\w.]+[ \t]+import[ \t]*\([^)]*\bas[ \t]+\w")
_META_SCHEMA = re.compile(r"MetaData\([^)]*\bschema\s*=")


_PCT_FMT = re.compile(r"%(?:\([^)]*\))?[-+# 0]*\d*(?:\.\d+)?[sdrifx]")
DYN_TABLE = "*dyn_table*"
DYN_COLS = "*dyn_cols*"
_DYN_TABLE = re.compile(r"(?i)\b(?:from|join|into|update|table)\s+\{[^{}]*\}")
_SELECT_LIST = re.compile(r"(?is)\bselect\s+(.*?)\s+\bfrom\b")


def _fname(func) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _cstr(n) -> str | None:
    return n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None


def _snake(name: str) -> str:
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()


# ------------------------------------------------------------------ model registry

@dataclass
class ColDef:
    attr: str
    dbcol: str
    file: str
    line: int
    snippet: str
    has_default: bool


@dataclass
class ClassInfo:
    name: str
    file: str
    line: int
    bases: list[str]
    tablename: str | None
    schema: str | None
    cols: dict[str, ColDef]
    tablename_line: int = 0
    derived_name: bool = False


@dataclass
class TableVar:
    var: str
    table: str
    file: str
    line: int
    cols: dict[str, ColDef]
    schema: str | None = None
    meta: str | None = None  # name of the MetaData variable passed to Table(), resolved against the registry later


@dataclass
class AliasDef:
    """`from <module> import <orig> as <alias>` found in <file>."""
    orig: str
    file: str
    module: str
    level: int
    local: bool = False  # True for an assignment alias (`Alias = Orig`, `Alias = pkg.Orig`) rather than an import alias


# module-level `Alias = Orig` / `Alias = pkg.mod.Orig` (text pre-filter; confirmed with the AST before use)
_ASSIGN_ALIAS = re.compile(r"(?m)^(\w+)[ \t]*(?::[^=\r\n]+)?=[ \t]*(?:\w+\.)*(\w+)[ \t]*(?:#[^\r\n]*)?\r?$")


def assign_aliases(module: ast.Module) -> list[tuple[str, AliasDef]]:
    out = []
    for node in module.body:
        target, value = None, None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        if not isinstance(target, ast.Name):
            continue
        if isinstance(value, ast.Name):
            orig = value.id
        elif isinstance(value, ast.Attribute):
            orig = value.attr
        else:
            continue
        if orig != target.id:
            out.append((target.id, AliasDef(orig, "", "", 0, True)))
    return out


def alias_imports(module: ast.Module) -> list[tuple[str, AliasDef]]:
    out = []
    for node in ast.walk(module):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.asname and a.asname != a.name:
                    out.append((a.asname, AliasDef(a.name, "", node.module or "", node.level)))
    return out


def _module_matches(file: str, module: str, level: int) -> bool:
    """Could `from <module> import X` (relative if level > 0) be importing from `file`? Path-suffix match, no execution."""
    stem = file[:-3] if file.endswith(".py") else file
    is_pkg = stem == "__init__" or stem.endswith("/__init__")
    if is_pkg:
        stem = stem[: -len("/__init__")] if "/" in stem else ""
    parts = [p for p in module.split(".") if p] if module else []
    if not parts:
        return level > 0 and is_pkg
    suffix = "/".join(parts)
    return stem == suffix or stem.endswith("/" + suffix)


def _coldef(attr: str, call: ast.Call, file: str, lines: list[str]) -> ColDef:
    db = None
    if call.args:
        db = _cstr(call.args[0])
    kws = {k.arg: k.value for k in call.keywords if k.arg}
    if db is None:
        db = _cstr(kws.get("name"))
    has_default = False
    for key in ("server_default", "default", "insert_default"):
        v = kws.get(key)
        if v is not None and not (isinstance(v, ast.Constant) and v.value is None):
            has_default = True
    pk = isinstance(kws.get("primary_key"), ast.Constant) and kws["primary_key"].value is True
    if pk:
        has_default = True  # serial / identity primary keys are generated
    for a in call.args:
        if isinstance(a, ast.Call) and _fname(a.func) in ("Identity", "Sequence", "Computed"):
            has_default = True
    i = call.lineno - 1
    return ColDef(attr, db or attr, file, call.lineno, redact(lines[i]) if 0 <= i < len(lines) else "", has_default)


def _meta_schema(call: ast.Call) -> tuple[str, str | None]:
    """('ok', schema) for MetaData(schema='s'), ('none', None) without schema=, ('dynamic', None) for a non-literal schema."""
    for k in call.keywords:
        if k.arg == "schema":
            v = _cstr(k.value)
            return ("ok", v) if v is not None else ("dynamic", None)
    return "none", None


def collect_meta(module: ast.Module) -> tuple[dict[str, str], dict[str, str], int]:
    """Schemas set through MetaData(schema=...): (base class / declarative base name -> schema, MetaData variable -> schema,
    number of MetaData(schema=...) uses whose schema is not a string literal)."""
    bases: dict[str, str] = {}
    metas: dict[str, str] = {}
    dynamic = 0
    nodes = list(ast.walk(module))
    for node in nodes:  # MetaData variables first
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and isinstance(node.value, ast.Call) and _fname(node.value.func) == "MetaData":
            kind, sch = _meta_schema(node.value)
            if kind == "ok":
                metas[node.targets[0].id] = sch
            elif kind == "dynamic":
                dynamic += 1
    for node in nodes:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and isinstance(node.value, ast.Call) and _fname(node.value.func) == "declarative_base":
            for k in node.value.keywords:
                if k.arg != "metadata":
                    continue
                if isinstance(k.value, ast.Call) and _fname(k.value.func) == "MetaData":
                    kind, sch = _meta_schema(k.value)
                    if kind == "ok":
                        bases[node.targets[0].id] = sch
                    elif kind == "dynamic":
                        dynamic += 1
                elif isinstance(k.value, ast.Name) and k.value.id in metas:
                    bases[node.targets[0].id] = metas[k.value.id]
        elif isinstance(node, ast.ClassDef):  # class Base(DeclarativeBase): metadata = MetaData(schema="s")
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name) \
                        and stmt.targets[0].id == "metadata" and isinstance(stmt.value, ast.Call) and _fname(stmt.value.func) == "MetaData":
                    kind, sch = _meta_schema(stmt.value)
                    if kind == "ok":
                        bases[node.name] = sch
                    elif kind == "dynamic":
                        dynamic += 1
    return bases, metas, dynamic


def collect_models(module: ast.Module, file: str, text: str) -> tuple[list[ClassInfo], list[TableVar]]:
    lines = text.splitlines()
    classes: list[ClassInfo] = []
    tvars: list[TableVar] = []
    for node in ast.walk(module):
        if isinstance(node, ast.ClassDef):
            tablename = schema = None
            tn_line = node.lineno
            cols: dict[str, ColDef] = {}
            for stmt in node.body:
                target = value = None
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    target, value = stmt.targets[0].id, stmt.value
                elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                    target, value = stmt.target.id, stmt.value
                if target is None:
                    continue
                if target == "__tablename__":
                    tablename = _cstr(value)
                    tn_line = stmt.lineno
                elif target == "__table_args__":
                    cand = value
                    if isinstance(value, ast.Tuple) and value.elts:
                        cand = value.elts[-1]
                    if isinstance(cand, ast.Dict):
                        for k, v in zip(cand.keys, cand.values):
                            if _cstr(k) == "schema":
                                schema = _cstr(v)
                elif isinstance(value, ast.Call) and _fname(value.func) in ("Column", "mapped_column"):
                    cols[target] = _coldef(target, value, file, lines)
            bases = [b.id if isinstance(b, ast.Name) else b.attr for b in node.bases if isinstance(b, (ast.Name, ast.Attribute))]
            derived = False
            if tablename is None and cols and any(isinstance(b, ast.Attribute) and b.attr == "Model" for b in node.bases):
                tablename, derived = _snake(node.name), True  # flask-sqlalchemy default naming
            if tablename is not None or cols:
                classes.append(ClassInfo(node.name, file, node.lineno, bases, tablename, schema, cols, tn_line, derived))
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and _fname(node.value.func) == "Table":
            call = node.value
            tname = _cstr(call.args[0]) if call.args else None
            if tname and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                cols = {}
                for a in call.args[1:]:
                    if isinstance(a, ast.Call) and _fname(a.func) == "Column":
                        cn = _cstr(a.args[0]) if a.args else None
                        if cn:
                            cols[cn] = _coldef(cn, a, file, lines)
                kws = {k.arg: k.value for k in call.keywords if k.arg}
                meta = call.args[1].id if len(call.args) > 1 and isinstance(call.args[1], ast.Name) else None
                tvars.append(TableVar(node.targets[0].id, tname, file, node.lineno, cols, _cstr(kws.get("schema")), meta))
    return classes, tvars


class Registry:
    def __init__(self) -> None:
        self.classes: dict[str, list[ClassInfo]] = {}
        self.tablevars: dict[str, list[TableVar]] = {}
        self._tcache: dict[int, str | None] = {}
        self._ccache: dict[int, dict[str, ColDef]] = {}
        self._scache: dict[int, str | None] = {}
        self.alias_defs: dict[str, list[AliasDef]] = {}
        self.base_schemas: dict[str, str] = {}  # declarative base name -> schema from MetaData(schema=...)
        self.meta_schemas: dict[str, str] = {}  # MetaData variable name -> schema
        self.meta_conflict: set[str] = set()

    def add_meta(self, bases: dict[str, str], metas: dict[str, str]) -> None:
        for store, new in ((self.base_schemas, bases), (self.meta_schemas, metas)):
            for k, v in new.items():
                if k in store and store[k] != v:
                    self.meta_conflict.add(k)
                store[k] = v

    def add(self, classes: list[ClassInfo], tvars: list[TableVar]) -> None:
        for c in classes:
            self.classes.setdefault(c.name, []).append(c)
        for t in tvars:
            self.tablevars.setdefault(t.var, []).append(t)

    def _bases(self, ci: ClassInfo) -> list[ClassInfo]:
        out = []
        for b in ci.bases:
            cands = self.classes.get(b, [])
            if len(cands) == 1:
                out.append(cands[0])
        return out

    def eff_table(self, ci: ClassInfo, depth: int = 0) -> str | None:
        k = id(ci)
        if k in self._tcache:
            return self._tcache[k]
        res = ci.tablename
        if res is None and depth < 20:
            for b in self._bases(ci):
                res = self.eff_table(b, depth + 1)
                if res:
                    break
        self._tcache[k] = res
        return res

    def eff_schema(self, ci: ClassInfo, depth: int = 0) -> str | None:
        k = id(ci)
        if k in self._scache:
            return self._scache[k]
        res = ci.schema
        if res is None and depth < 20:
            for b in self._bases(ci):
                res = self.eff_schema(b, depth + 1)
                if res:
                    break
        if res is None:
            for b in ci.bases:
                if b in self.base_schemas and b not in self.meta_conflict:
                    res = self.base_schemas[b]
                    break
        self._scache[k] = res
        return res

    def add_aliases(self, file: str, found: list[tuple[str, AliasDef]]) -> None:
        for alias, d in found:
            d.file = file
            self.alias_defs.setdefault(alias, []).append(d)

    def resolve_in_file(self, name: str, file: str | None, depth: int = 0) -> set[str]:
        """Model classes that `name` denotes inside `file` (file=None: anywhere) via assignment or import aliases."""
        out: set[str] = set()
        if depth > 8:
            return out
        for d in self.alias_defs.get(name, []):
            if file is not None and d.file != file:
                continue
            if d.orig in self.classes:
                out.add(d.orig)
            elif d.local:
                out |= self.resolve_in_file(d.orig, d.file, depth + 1)
            else:
                out |= self.resolve(d.orig, d.module, d.level, depth + 1)
        return out

    def resolve(self, name: str, module: str, level: int, depth: int = 0) -> set[str]:
        """Model class names that `from <module> import <name>` can denote through re-exported `as` aliases."""
        out: set[str] = set()
        if depth > 8:
            return out
        for d in self.alias_defs.get(name, []):
            if not _module_matches(d.file, module, level):
                continue
            if d.orig in self.classes:
                out.add(d.orig)
            elif d.local:
                out |= self.resolve_in_file(d.orig, d.file, depth + 1)
            else:
                out |= self.resolve(d.orig, d.module, d.level, depth + 1)
        return out

    def alias_closure(self, names: set[str]) -> set[str]:
        """Alias names (anywhere in the tree) that, directly or through other aliases, stand for one of `names`."""
        found: set[str] = set()
        changed = True
        while changed:
            changed = False
            for alias, defs in self.alias_defs.items():
                if alias not in found and any(d.orig in names or d.orig in found for d in defs):
                    found.add(alias)
                    changed = True
        return found

    def eff_cols(self, ci: ClassInfo, depth: int = 0) -> dict[str, ColDef]:
        k = id(ci)
        if k in self._ccache:
            return self._ccache[k]
        out: dict[str, ColDef] = {}
        if depth < 20:
            for b in self._bases(ci):
                out.update(self.eff_cols(b, depth + 1))
        out.update(ci.cols)
        self._ccache[k] = out
        return out

    def models(self, name: str) -> list[tuple[str, ClassInfo]]:
        res = []
        for ci in self.classes.get(name, []):
            t = self.eff_table(ci)
            if t:
                res.append((t, ci))
        return res


# --------------------------------------------------------------------- SQL refs

_SCOPES = (exp.Select, exp.Update, exp.Delete, exp.Merge)


def _cte_names(t: exp.Expression) -> set[str]:
    out = set()
    for c in t.find_all(exp.CTE):
        a = c.args.get("alias")
        if a is not None and isinstance(a.args.get("this"), exp.Identifier):
            out.add(ident_name(a.args["this"]))
    return out


def _scope_tables(node: exp.Expression, cte_names: set[str]) -> tuple[list[tuple[str, str]], bool]:
    """Direct table sources of the nearest enclosing scope as (schema, table) pairs.
    Returns (tables, has_derived_source)."""
    cur = node.parent
    while cur is not None:
        if isinstance(cur, _SCOPES):
            srcs: list[exp.Expression] = []
            if isinstance(cur, exp.Select):
                f = cur.args.get("from_") or cur.args.get("from")
                if f is not None:
                    srcs.append(f.this)
                for j in cur.args.get("joins") or []:
                    srcs.append(j.this)
            elif isinstance(cur, exp.Update):
                srcs.append(cur.this)
                f = cur.args.get("from_") or cur.args.get("from")
                if f is not None:
                    srcs.append(f.this)
                for j in cur.args.get("joins") or []:
                    srcs.append(j.this)
            elif isinstance(cur, exp.Delete):
                srcs.append(cur.this)
                for u in cur.args.get("using") or []:
                    srcs.append(u)
            tables, derived = [], False
            for s in srcs:
                if isinstance(s, exp.Table):
                    nm = ident_name(s)
                    if nm and not (nm in cte_names and not s.args.get("db")):
                        tables.append(tkey(table_schema(s), nm))
                    elif nm in cte_names:
                        derived = True
                elif s is not None:
                    derived = True
            if tables or derived:
                return tables, derived
        cur = cur.parent
    return [], False


def sql_references(sql: str, file: str, line: int, tree_name: str, via: str, is_test: bool) -> tuple[list[Reference], bool]:
    """Extract table/column references from SQL text that starts at 1-based `line` of `file`.
    Every reference carries the real source line of the identifier it came from. Returns (refs, fully_parsed)."""
    refs: list[Reference] = []
    ok = True
    for stmt, off in split_statements(normalize_params(sql)):
        try:
            t = sqlglot.parse_one(stmt, read="postgres", error_level=sqlglot.ErrorLevel.RAISE)
        except Exception:
            ok = False
            continue
        if t is None:
            continue
        if isinstance(t, exp.Create):
            kind = (t.args.get("kind") or "").upper()
            if kind not in ("VIEW",) or t.args.get("expression") is None:
                continue
            t = t.args["expression"]
        if isinstance(t, (exp.Alter, exp.Drop, exp.Command, exp.TruncateTable)):
            continue
        refs.extend(_refs_from_tree(t, file, line + off, tree_name, via, is_test, stmt, line))
    return refs, ok


def _refs_from_tree(t, file, base_line, tree_name, via, is_test, stmt, anchor) -> list[Reference]:
    out: list[Reference] = []
    stmt_lines = stmt.splitlines() or [stmt]
    whole = redact(" ".join(stmt.split()))

    def mk(table, column, role, conf, node=None, schema=None, **kw) -> Reference:
        ln = node_line(node, base_line) if node is not None else base_line
        idx = ln - base_line
        snippet = redact(" ".join(stmt_lines[idx].split())) if 0 <= idx < len(stmt_lines) and stmt_lines[idx].strip() else whole
        return Reference(table, column, file, ln, tree_name, via, role, conf, snippet, is_test=is_test, schema=schema, anchor=anchor, **kw)

    cte_names = _cte_names(t)
    alias_map: dict[str, tuple[str | None, str]] = {}
    tables: list[exp.Table] = []
    for tb in t.find_all(exp.Table):
        nm = ident_name(tb)
        if not nm or (nm in cte_names and not tb.args.get("db")):
            continue
        tables.append(tb)
        alias_map[alias_key(tb)] = (table_schema(tb), nm)
        alias_map.setdefault(nm, (table_schema(tb), nm))
    insert_targets: dict[int, tuple[str, list]] = {}
    if isinstance(t, exp.Insert) or t.find(exp.Insert):
        for ins in t.find_all(exp.Insert):
            this = ins.this
            tb = this.this if isinstance(this, exp.Schema) else this
            if isinstance(tb, exp.Table) and ident_name(tb):
                col_nodes = [i for i in this.expressions if ident_name(i)] if isinstance(this, exp.Schema) else None
                insert_targets[id(tb)] = (ident_name(tb), col_nodes)
    for tb in tables:
        sch = table_schema(tb)
        if id(tb) in insert_targets:
            name, col_nodes = insert_targets[id(tb)]
            cols = tuple(ident_name(i) for i in col_nodes) if col_nodes is not None else None
            out.append(mk(name, None, "insert", Confidence.CONFIRMED, node=tb, schema=sch, insert_columns=cols))
            for i in col_nodes or ():
                out.append(mk(name, ident_name(i), "ref", Confidence.CONFIRMED, node=i, schema=sch))
        else:
            out.append(mk(ident_name(tb), None, "ref", Confidence.CONFIRMED, node=tb, schema=sch))

    aliases_in_select = {ident_name(a.args["alias"]) for a in t.find_all(exp.Alias) if isinstance(a.args.get("alias"), exp.Identifier)}
    for c in t.find_all(exp.Column):
        q = ident_name(c.args["table"]) if c.args.get("table") is not None else ""
        if isinstance(c.this, exp.Star):
            tgt = alias_map.get(q)
            if tgt:
                out.append(mk(tgt[1], None, "star", Confidence.POSSIBLE, node=c, schema=tgt[0]))
            continue
        lname = ident_name(c)
        if not lname:
            continue
        if q:
            tgt = alias_map.get(q)
            if tgt:
                out.append(mk(tgt[1], lname, "ref", Confidence.CONFIRMED, node=c, schema=tgt[0]))
            continue
        if lname in aliases_in_select and any(isinstance(p, (exp.Order, exp.Group, exp.Having)) for p in _ancestors(c)):
            continue
        cand, derived = _scope_tables(c, cte_names)
        if len(cand) == 1 and not derived:
            out.append(mk(cand[0][1], lname, "ref", Confidence.CONFIRMED, node=c, schema=cand[0][0]))
        elif len(cand) >= 1:
            out.append(mk(None, lname, "ref", Confidence.POSSIBLE, node=c, candidates=tuple(sorted(set(cand))),
                          note="unqualified column over multiple/derived sources"))
    for sel in t.find_all(exp.Select):
        for e in sel.expressions:
            if isinstance(e, exp.Star):
                cand, _ = _scope_tables(e, cte_names)
                for sch, tbl in cand:
                    out.append(mk(tbl, None, "star", Confidence.POSSIBLE, node=e, schema=sch))
    return out


def _ancestors(node):
    cur = node.parent
    while cur is not None:
        yield cur
        cur = cur.parent


def _looks_like_sql(text: str) -> bool:
    return bool(SQL_START.match(text)) and bool(_STRUCT.search(text))


def _tokens(text: str) -> frozenset[str]:
    return frozenset(_WORD.findall(text.lower()))


# ------------------------------------------------------------------- the scanner

@dataclass
class ScanResult:
    refs: list[Reference] = field(default_factory=list)
    registry: Registry = field(default_factory=Registry)


class Scanner:
    def __init__(self, targets: dict[tuple[str, str], set[str]] | None, migration_match: Matcher, ignore_match: Matcher,
                 test_match: Matcher, coverage: Coverage, max_bytes: int,
                 workers: int = 0, time_budget_seconds: float = 900.0, max_total_bytes: int = 1_000_000_000,
                 parallel_min_files: int = 400):
        """`targets` maps (schema, table) -> changed column names, all in canonical (PostgreSQL-folded) spelling."""
        self.targets = {k: set(v) for k, v in targets.items()} if targets is not None else None
        self.migration_match, self.ignore_match, self.test_match = migration_match, ignore_match, test_match
        self.cov, self.max_bytes = coverage, max_bytes
        self.workers = workers
        self.time_budget_seconds = time_budget_seconds
        self.max_total_bytes = max_total_bytes
        self.parallel_min_files = parallel_min_files
        self.target_cols = {c for v in self.targets.values() for c in v} if self.targets is not None else None
        # lower-case words used only by the cheap text prefilter and by dynamic-SQL matching (both case-insensitive)
        self._words = ({t.lower() for _s, t in self.targets} | {c.lower() for c in self.target_cols}) if self.targets is not None else None

    # emission filter ------------------------------------------------------
    def _wanted(self, r: Reference) -> bool:
        if self.targets is None:
            return True
        if r.table is not None:
            return tkey(r.schema, r.table) in self.targets
        if r.role == "dynamic":
            return bool(r.tokens & (self._words or set()))
        if r.candidates:
            return any(c in self.targets for c in r.candidates)
        return r.column is not None and r.column in (self.target_cols or set())

    def scan(self, tree: Tree) -> ScanResult:
        res = ScanResult()
        self.cov.trees_scanned.append(tree.name)
        py_files: list[str] = []
        sql_files: list[str] = []
        for path, size in tree.files():
            if self.migration_match(path) or self.ignore_match(path):
                continue
            ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
            if ext not in (".py", ".sql", *UNANALYZED_EXT):
                continue
            if size > self.max_bytes:
                self.cov.files_skipped_too_large.append(f"{tree.name}:{path}")
                continue
            if ext == ".py":
                py_files.append(path)
            elif ext == ".sql":
                sql_files.append(path)
            else:
                self.cov.unanalyzed_files_by_ext[ext] = self.cov.unanalyzed_files_by_ext.get(ext, 0) + 1

        meta_dynamic = False
        # pass 1: models, Core tables and `from x import Y as Z` aliases (so a re-exported alias is still recognised)
        for path in py_files:
            text = tree.read(path)
            if text is None:
                continue
            is_model_file = any(m in text for m in MODEL_MARKERS)
            if not (is_model_file or _ALIAS_IMPORT.search(text)):
                continue
            mod = self._parse(path, text, tree.name)
            if mod is None:
                continue
            res.registry.add_aliases(path, alias_imports(mod))
            if is_model_file:
                classes, tvars = collect_models(mod, path, text)
                res.registry.add(classes, tvars)
                if _META_SCHEMA.search(text):
                    bases_m, metas_m, dyn = collect_meta(mod)
                    res.registry.add_meta(bases_m, metas_m)
                    if dyn:
                        meta_dynamic = True
        reg = res.registry
        for tvs in reg.tablevars.values():
            for tv in tvs:
                if tv.schema is None and tv.meta and tv.meta in reg.meta_schemas and tv.meta not in reg.meta_conflict:
                    tv.schema = reg.meta_schemas[tv.meta]
        if meta_dynamic or reg.meta_conflict:
            note = ("MetaData(schema=...) is used with a non-literal or conflicting schema: the schema of those models is not tracked, "
                    "so their table schema may be wrong.")
            if note not in self.cov.notes:
                self.cov.notes.append(note)

        # pass 1b: assignment aliases (`Ord = Order`), followed through chains; only files whose text could contain one
        cands: dict[str, list[str]] = {}
        for path in py_files:
            text = tree.read(path)
            if text is not None:
                found = [m.group(2) for m in _ASSIGN_ALIAS.finditer(text)]
                if found:
                    cands[path] = found
        known = set(res.registry.classes) | set(res.registry.alias_defs)
        parsed_b: set[str] = set()
        progress = True
        while progress:
            progress = False
            for path, origs in cands.items():
                if path in parsed_b or not any(o in known for o in origs):
                    continue
                parsed_b.add(path)
                text = tree.read(path)
                mod = self._parse(path, text, tree.name) if text is not None else None
                if mod is None:
                    continue
                found_a = assign_aliases(mod)
                res.registry.add_aliases(path, found_a)
                known |= {a for a, _ in found_a}
                progress = True
        reg = res.registry
        self.cov.models_found += sum(1 for cs in reg.classes.values() for c in cs if reg.eff_table(c))
        terms, alias_rx = self._terms(reg)

        self._emit_definitions(reg, res, tree.name)

        # pass 2: references
        for path in py_files:
            text = tree.read(path)
            if text is None:
                continue
            if terms is not None:
                low = text.lower()
                if not (any(t in low for t in terms) or (alias_rx is not None and alias_rx.search(text))):
                    self.cov.python_files_skipped_by_filter += 1
                    continue
            mod = self._parse(path, text, tree.name)
            if mod is None:
                continue
            self.cov.python_files_parsed += 1
            is_test = self.test_match(path)
            _FileScan(self, reg, res, path, text, tree.name, is_test).run(mod)

        for path in sql_files:
            text = tree.read(path)
            if text is None:
                continue
            if self._words is not None and not any(t in text.lower() for t in self._words):
                continue
            self.cov.sql_files_parsed += 1
            refs, ok = sql_references(text, path, 1, tree.name, "sql_file", self.test_match(path))
            if not ok:
                self.cov.notes.append(f"{tree.name}:{path}: some SQL statements could not be parsed (e.g. function bodies)")
            for r in refs:
                if self._wanted(r):
                    res.refs.append(r)
        res.refs = _dedupe(res.refs)
        return res

    def _terms(self, reg: Registry) -> tuple[set[str] | None, re.Pattern[str] | None]:
        """Relevance prefilter for Python files: lower-case words (substring match on lower-cased text) plus a word-boundary
        regex for import aliases of the affected model classes. A file that matches neither cannot refer to a changed object."""
        if self.targets is None:
            return None, None
        terms = set(self._words or set())
        class_names: set[str] = set()
        for name, cis in reg.classes.items():
            for ci in cis:
                t = reg.eff_table(ci)
                key = tkey(reg.eff_schema(ci), t) if t else None
                if key and key in self.targets:
                    class_names.add(name)
                    terms.add(name.lower())
                    for attr, cd in reg.eff_cols(ci).items():
                        if cd.dbcol in self.targets[key] or not self.targets[key]:
                            terms.add(attr.lower())
        for var, tvs in reg.tablevars.items():
            if any(tkey(tv.schema, tv.table) in self.targets for tv in tvs):
                terms.add(var.lower())
        aliases = reg.alias_closure(class_names)
        rx = re.compile(r"\b(?:" + "|".join(re.escape(a) for a in sorted(aliases)) + r")\b") if aliases else None
        return {t for t in terms if t}, rx

    def _parse(self, path: str, text: str, tree_name: str) -> ast.Module | None:
        try:
            return ast.parse(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            self.cov.python_files_failed.append(f"{tree_name}:{path}")
            return None

    def _emit_definitions(self, reg: Registry, res: ScanResult, tree_name: str) -> None:
        for name, cis in reg.classes.items():
            for ci in cis:
                t = reg.eff_table(ci)
                if not t or ci.tablename is None:
                    continue
                is_test = self.test_match(ci.file)
                for attr, cd in reg.eff_cols(ci).items():
                    r = Reference(t, cd.dbcol, cd.file, cd.line, tree_name, "orm_definition", "definition",
                                  Confidence.CONFIRMED, cd.snippet, is_test=self.test_match(cd.file), schema=reg.eff_schema(ci))
                    if self._wanted(r):
                        res.refs.append(r)
                r = Reference(t, None, ci.file, ci.tablename_line, tree_name, "orm_definition", "definition",
                              Confidence.CONFIRMED, f"class {ci.name} (table {t})", is_test=is_test, schema=reg.eff_schema(ci))
                if self._wanted(r):
                    res.refs.append(r)
        for var, tvs in reg.tablevars.items():
            for tv in tvs:
                is_test = self.test_match(tv.file)
                r = Reference(tv.table, None, tv.file, tv.line, tree_name, "table_def", "definition", Confidence.CONFIRMED,
                              f"{tv.var} = Table({tv.table!r}, ...)", is_test=is_test, schema=tv.schema)
                if self._wanted(r):
                    res.refs.append(r)
                for cn, cd in tv.cols.items():
                    r = Reference(tv.table, cd.dbcol, cd.file, cd.line, tree_name, "table_def", "definition",
                                  Confidence.CONFIRMED, cd.snippet, is_test=is_test, schema=tv.schema)
                    if self._wanted(r):
                        res.refs.append(r)


def _dedupe(refs: list[Reference]) -> list[Reference]:
    seen: dict[tuple, Reference] = {}
    for r in refs:
        k = (r.file, r.line, r.schema, r.table, r.column, r.via, r.role, r.insert_columns, r.candidates)
        if k not in seen:
            seen[k] = r
    return list(seen.values())


class _FileScan:
    def __init__(self, sc: Scanner, reg: Registry, res: ScanResult, path: str, text: str, tree_name: str, is_test: bool):
        self.sc, self.reg, self.res, self.path, self.tree_name, self.is_test = sc, reg, res, path, tree_name, is_test
        self.lines = text.splitlines()
        self.parents: dict[ast.AST, ast.AST] = {}
        self.imports: dict[str, tuple[str, str, int]] = {}  # local name -> (imported name, module, level)
        self.done: set[int] = set()

    def snip(self, node) -> str:
        i = getattr(node, "lineno", 1) - 1
        return redact(self.lines[i]) if 0 <= i < len(self.lines) else ""

    def emit(self, node, table, column, via, role, conf, **kw) -> None:
        r = Reference(table, column, self.path, getattr(node, "lineno", 1), self.tree_name, via, role, conf,
                      kw.pop("snippet", None) or self.snip(node), is_test=self.is_test, **kw)
        if self.sc._wanted(r):
            self.res.refs.append(r)

    def run(self, mod: ast.Module) -> None:
        for node in ast.walk(mod):
            for ch in ast.iter_child_nodes(node):
                self.parents[ch] = node
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    self.imports[a.asname or a.name] = (a.name, node.module or "", node.level)
        for node in ast.walk(mod):
            try:
                self.visit(node)
            except RecursionError:
                continue

    # class / table resolution -------------------------------------------
    def classes_of(self, expr) -> list[tuple[str, ClassInfo]]:
        name, imp = None, None
        if isinstance(expr, ast.Name):
            imp = self.imports.get(expr.id)
            name = imp[0] if imp else expr.id
        elif isinstance(expr, ast.Attribute):
            name = expr.attr
        elif isinstance(expr, ast.Call) and _fname(expr.func) in ("aliased", "with_polymorphic") and expr.args:
            return self.classes_of(expr.args[0])
        if name is None:
            return []
        ms = self.reg.models(name)
        if not ms and imp is not None:  # the imported name may be an `as` alias re-exported by another module
            for cls in sorted(self.reg.resolve(imp[0], imp[1], imp[2])):
                ms.extend(self.reg.models(cls))
        elif not ms and isinstance(expr, ast.Name):  # assignment alias defined in this file
            for cls in sorted(self.reg.resolve_in_file(expr.id, self.path)):
                ms.extend(self.reg.models(cls))
        elif not ms and isinstance(expr, ast.Attribute):  # `models.Ord`: module unknown, accept any alias of that name
            for cls in sorted(self.reg.resolve_in_file(name, None)):
                ms.extend(self.reg.models(cls))
        return ms

    def schema_of(self, ci: ClassInfo) -> str | None:
        return self.reg.eff_schema(ci)

    def _conf(self, ms: list[tuple[str, ClassInfo]]) -> tuple[Confidence, str]:
        tables = {(self.schema_of(ci), t) for t, ci in ms}
        if len(tables) > 1:
            return Confidence.POSSIBLE, "class name is defined for more than one table"
        return Confidence.CONFIRMED, ""

    def table_of_expr(self, expr) -> list[tuple[str | None, str]]:
        """Resolve a Core table expression (a Table variable or Model.__table__) to (schema, table) pairs."""
        if isinstance(expr, ast.Name):
            return [(tv.schema, tv.table) for tv in self.reg.tablevars.get(expr.id, [])]
        if isinstance(expr, ast.Attribute):
            if expr.attr == "__table__":
                return [(self.schema_of(ci), t) for t, ci in self.classes_of(expr.value)]
            return [(tv.schema, tv.table) for tv in self.reg.tablevars.get(expr.attr, [])]
        return []

    # dispatch ---------------------------------------------------------------
    def visit(self, node) -> None:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            ms = self.classes_of(node)
            if ms:
                conf, note = self._conf(ms)
                for sch, t in sorted({(self.schema_of(ci), t) for t, ci in ms}, key=lambda x: (x[0] or "", x[1])):
                    self.emit(node, t, None, "orm_attribute", "ref", conf, note=note, schema=sch)
        elif isinstance(node, ast.Attribute):
            self.visit_attribute(node)
        elif isinstance(node, ast.Subscript):
            self.visit_subscript(node)
        elif isinstance(node, ast.Call):
            self.visit_call(node)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            self.visit_string_const(node)
        elif isinstance(node, ast.JoinedStr):
            self.visit_joined(node)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            self.visit_binop(node)

    def visit_attribute(self, node: ast.Attribute) -> None:
        ms = self.classes_of(node.value)
        if ms:
            conf, note = self._conf(ms)
            for t, ci in ms:
                cd = self.reg.eff_cols(ci).get(node.attr)
                if cd:
                    self.emit(node, t, cd.dbcol, "orm_attribute", "ref", conf, note=note, schema=self.schema_of(ci))
        elif isinstance(node.value, (ast.Name, ast.Attribute)):
            # module-qualified model class (`models.Order`, `app.models.Order`): the class itself is used
            qms = self.classes_of(node)
            if qms:
                conf, note = self._conf(qms)
                for sch, t in sorted({(self.schema_of(ci), t) for t, ci in qms}, key=lambda x: (x[0] or "", x[1])):
                    self.emit(node, t, None, "orm_attribute", "ref", conf, note=note, schema=sch)
        inner = node.value
        if isinstance(inner, ast.Attribute) and inner.attr in ("c", "columns"):
            for sch, t in self.table_of_expr(inner.value):
                self.emit(node, t, node.attr, "table_def", "ref", Confidence.CONFIRMED, schema=sch)

    def visit_subscript(self, node: ast.Subscript) -> None:
        key = _cstr(node.slice)
        v = node.value
        if key and isinstance(v, ast.Attribute) and v.attr in ("c", "columns"):
            for sch, t in self.table_of_expr(v.value):
                self.emit(node, t, key, "table_def", "ref", Confidence.CONFIRMED, schema=sch)

    def visit_call(self, node: ast.Call) -> None:
        fn = _fname(node.func)
        # constructor: Model(a=1, b=2)
        if isinstance(node.func, (ast.Name, ast.Attribute)) and fn not in ("aliased", "with_polymorphic"):
            ms = self.classes_of(node.func)
            if ms:
                conf, note = self._conf(ms)
                dynamic = any(k.arg is None for k in node.keywords)
                for t, ci in ms:
                    cols = self.reg.eff_cols(ci)
                    sch = self.schema_of(ci)
                    given = tuple(cols[k.arg].dbcol for k in node.keywords if k.arg in cols)
                    defaulted = tuple(cd.dbcol for cd in cols.values() if cd.has_default)
                    self.emit(node, t, None, "orm_constructor", "insert", conf if not dynamic else Confidence.POSSIBLE,
                              insert_columns=None if dynamic else given, defaulted=defaulted, schema=sch,
                              note=note or ("constructor called with **kwargs" if dynamic else ""))
                    for g in given:
                        self.emit(node, t, g, "orm_constructor", "ref", conf, schema=sch)
        if fn == "getattr" and len(node.args) >= 2 and _cstr(node.args[1]):
            for t, ci in self.classes_of(node.args[0]):
                cd = self.reg.eff_cols(ci).get(_cstr(node.args[1]) or "")
                if cd:
                    self.emit(node, t, cd.dbcol, "orm_attribute", "ref", Confidence.CONFIRMED, schema=self.schema_of(ci))
        elif fn == "ForeignKey" and node.args and _cstr(node.args[0]):
            parts = _cstr(node.args[0]).split(".")  # [schema.]table.column, spelled exactly as SQLAlchemy resolves it
            if len(parts) >= 2:
                self.emit(node, parts[-2], parts[-1], "orm_foreign_key", "ref", Confidence.CONFIRMED,
                          schema=parts[-3] if len(parts) >= 3 else None)
        elif fn == "table" and node.args and _cstr(node.args[0]):  # sqlalchemy.table("t", column("c"), schema="s")
            t = _cstr(node.args[0])
            sch = next((_cstr(k.value) for k in node.keywords if k.arg == "schema"), None)
            self.emit(node, t, None, "table_def", "ref", Confidence.CONFIRMED, schema=sch)
            for a in node.args[1:]:
                if isinstance(a, ast.Call) and _fname(a.func) == "column" and a.args and _cstr(a.args[0]):
                    self.emit(a, t, _cstr(a.args[0]), "table_def", "ref", Confidence.CONFIRMED, schema=sch)
        elif fn == "filter_by" and isinstance(node.func, ast.Attribute):
            models = self.model_in_chain(node.func.value)
            for kw in node.keywords:
                if kw.arg is None:
                    continue
                hit = False
                for t, ci in models:
                    cd = self.reg.eff_cols(ci).get(kw.arg)
                    if cd:
                        hit = True
                        self.emit(node, t, cd.dbcol, "orm_attribute", "ref", Confidence.CONFIRMED, schema=self.schema_of(ci))
                if not models:
                    self.emit(node, None, kw.arg, "orm_filter_by", "ref", Confidence.POSSIBLE,
                              note="filter_by on an unresolved model")
        elif fn == "format" and isinstance(node.func, ast.Attribute) and _cstr(node.func.value) is not None:
            self.sql_text(node.func.value, _cstr(node.func.value) or "", dynamic=True)
            self.done.add(id(node.func.value))

    def model_in_chain(self, expr) -> list[tuple[str, ClassInfo]]:
        depth = 0
        while expr is not None and depth < 40:
            depth += 1
            if isinstance(expr, ast.Call):
                fn = _fname(expr.func)
                if fn in ("query", "select", "delete", "update", "insert", "get", "filter", "join") and expr.args:
                    first = expr.args[0]
                    ms = self.classes_of(first)
                    if not ms and isinstance(first, ast.Attribute):
                        ms = self.classes_of(first.value)
                    if ms:
                        return ms
                expr = expr.func
            elif isinstance(expr, ast.Attribute):
                if expr.attr == "query":
                    ms = self.classes_of(expr.value)
                    if ms:
                        return ms
                expr = expr.value
            else:
                return self.classes_of(expr)
        return []

    # strings --------------------------------------------------------------
    def visit_string_const(self, node: ast.Constant) -> None:
        if id(node) in self.done:
            return
        parent = self.parents.get(node)
        if isinstance(parent, ast.Expr):
            return  # docstring / bare string: never executed
        if isinstance(parent, (ast.JoinedStr, ast.FormattedValue)):
            return
        if isinstance(parent, ast.BinOp) and isinstance(parent.op, (ast.Add, ast.Mod)):
            return  # handled at the top of the chain
        if len(node.value) > MAX_PY_STRING or len(node.value) < 10:
            return
        self.sql_text(node, node.value, dynamic=False)

    def sql_text(self, node, text: str, dynamic: bool) -> None:
        if not SQL_START.match(text):
            return
        marks: set[str] = set()
        if dynamic:
            if _DYN_TABLE.search(text):
                marks.add(DYN_TABLE)  # the table name itself is built at run time
            sel = _SELECT_LIST.search(text)
            if sel and "{" in sel.group(1):
                marks.add(DYN_COLS)  # the column list is built at run time
            text = re.sub(r"\{[^{}]*\}", "NULL", text)
        refs, ok = sql_references(text, self.path, getattr(node, "lineno", 1), self.tree_name, "raw_sql", self.is_test)
        for r in refs:
            if DYN_TABLE in marks and r.table == "null":
                continue  # the NULL stands for the unknown table name, it is not a real table
            if self.sc._wanted(r):
                self.res.refs.append(r)
        if (dynamic or not ok) and _looks_like_sql(text):
            note = "dynamically built SQL" if dynamic else "SQL text that could not be fully parsed"
            if DYN_TABLE in marks:
                note = "SQL whose table name is built at run time"
            elif DYN_COLS in marks:
                note = "SQL whose column list is built at run time"
            self.emit(node, None, None, "dynamic_sql", "dynamic", Confidence.POSSIBLE, tokens=_tokens(text) | marks,
                      snippet=redact(" ".join(text.split())), note=note)

    def visit_joined(self, node: ast.JoinedStr) -> None:
        if isinstance(self.parents.get(node), ast.FormattedValue):
            return
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
                self.done.add(id(v))
            else:
                parts.append("{}")
        text = "".join(parts)
        if 10 <= len(text) <= MAX_PY_STRING:
            self.sql_text(node, text, dynamic=True)

    def visit_binop(self, node: ast.BinOp) -> None:
        parent = self.parents.get(node)
        if isinstance(parent, ast.BinOp) and isinstance(parent.op, type(node.op)):
            return
        if isinstance(node.op, ast.Mod):
            left = _cstr(node.left)
            if left is not None:
                self.done.add(id(node.left))
                if 10 <= len(left) <= MAX_PY_STRING:
                    # `"..." % x` interpolates into the SQL text itself (it is not a driver parameter): treat as dynamic
                    self.sql_text(node.left, _PCT_FMT.sub("{}", left), dynamic=bool(_PCT_FMT.search(left)))
            return
        leaves: list[ast.AST] = []

        def flat(n):
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                flat(n.left)
                flat(n.right)
            else:
                leaves.append(n)

        flat(node)
        if not any(_cstr(x) is not None for x in leaves):
            return
        parts = []
        for x in leaves:
            s = _cstr(x)
            if s is not None:
                parts.append(s)
                self.done.add(id(x))
            else:
                parts.append("{}")
        text = "".join(parts)
        if 10 <= len(text) <= MAX_PY_STRING:
            self.sql_text(node, text, dynamic=True)
