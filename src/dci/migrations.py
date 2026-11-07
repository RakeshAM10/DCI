"""Extract schema changes from migrations. Alembic files are parsed with `ast` (never imported or executed);
SQL files and op.execute() strings are parsed with SQLGlot (PostgreSQL dialect)."""
from __future__ import annotations

import ast
import re

import sqlglot
from sqlglot import exp

from .identifiers import DEFAULT_SCHEMA, ident_name, table_schema, tkey
from .models import Change, ChangeKind, ParseIssue
from .redact import redact
from .sqlutil import MAX_SQL_LEN, split_statements

_IGNORED_COMMANDS = re.compile(r"^\s*(set|begin|commit|rollback|comment|grant|revoke|create\s+extension|analyze|vacuum|notify|select|insert|update|delete)\b", re.I)
_RISKY_COMMANDS = re.compile(r"^\s*(alter|drop|create|do|truncate)\b", re.I)


def _name(node) -> str | None:
    """Canonical (PostgreSQL-folded) name of an identifier-like node."""
    return ident_name(node) if node is not None else None


def _table_of(t: exp.Table) -> tuple[str, str | None]:
    return ident_name(t), table_schema(t)


# --------------------------------------------------------------------------- SQL

_SET_SP = re.compile(r"(?is)^\s*set\s+(?:session\s+|local\s+)?search_path\s*(?:to|=)\s*(.+?)\s*;?\s*$")
_RESET_SP = re.compile(r"(?is)^\s*reset\s+search_path\b|^\s*set\s+(?:session\s+|local\s+)?search_path\s*(?:to|=)\s*default\b")
_SET_CONFIG_SP = re.compile(r"(?is)^\s*select\s+(?:pg_catalog\.)?set_config\(\s*'search_path'\s*,\s*'((?:[^']|'')*)'")


def _parse_search_path(text: str) -> list[str]:
    """Schemas of a search_path value, PostgreSQL-folded (unquoted -> lower case, quoted -> exact); $user is skipped."""
    out = []
    for m in re.finditer(r'\s*(?:"((?:[^"]|"")*)"|\'((?:[^\']|\'\')*)\'|([^,\s]+))\s*(?:,|$)', text):
        quoted, single, bare = m.group(1), m.group(2), m.group(3)
        name = quoted.replace('""', '"') if quoted is not None else (single.replace("''", "'") if single is not None else bare.lower())
        if name and name != "$user" and not (bare is not None and name == "pg_catalog"):
            out.append(name)
    return out


def changes_from_sql(sql: str, file: str, base_line: int = 1) -> tuple[list[Change], list[ParseIssue], set[tuple[str, str]]]:
    """Parse SQL text; base_line is the 1-based line where `sql` begins in `file`."""
    changes: list[Change] = []
    issues: list[ParseIssue] = []
    created: set[tuple[str, str]] = set()
    if len(sql) > MAX_SQL_LEN:
        issues.append(ParseIssue(file, base_line, f"SQL text too large to analyse safely ({len(sql)} bytes)"))
        return changes, issues, created
    search_path: str | None = None  # first schema of a non-default search_path set earlier in this text
    for stmt, off in split_statements(sql):
        line = base_line + off
        snippet = redact(stmt.splitlines()[0]) if stmt else ""
        m_sp = _SET_SP.match(stmt) or _SET_CONFIG_SP.match(stmt)
        if _RESET_SP.match(stmt):
            search_path = None
            continue
        if m_sp:
            schemas = _parse_search_path(m_sp.group(1))
            search_path = schemas[0] if schemas and schemas[0] != "public" else None
            if len(schemas) > 1 and search_path:
                issues.append(ParseIssue(file, line, f"search_path lists several schemas; unqualified tables are assumed to be in '{search_path}'", snippet))
            continue
        try:
            tree = sqlglot.parse_one(stmt, read="postgres", error_level=sqlglot.ErrorLevel.RAISE)
        except Exception:
            if _RISKY_COMMANDS.match(stmt):
                issues.append(ParseIssue(file, line, "Statement could not be parsed; review manually", snippet))
            continue
        if tree is None:
            continue
        n_before, created_before = len(changes), set(created)
        _handle(tree, stmt, file, line, snippet, changes, issues, created)
        if search_path:  # unqualified names resolve through the search_path set above
            for c in changes[n_before:]:
                if c.schema is None:
                    c.schema = search_path
            for key in created - created_before:
                if key[0] == DEFAULT_SCHEMA:
                    created.discard(key)
                    created.add(tkey(search_path, key[1]))
    return changes, issues, created


def _handle(tree, stmt, file, line, snippet, changes, issues, created) -> None:
    if isinstance(tree, exp.Command):
        text = stmt
        if re.search(r"(?is)^\s*alter\s+table\b.*\badd\s+constraint\b.*\bunique\s+using\s+index\b", text):
            return  # safe pattern: promotes an already-built index
        if _IGNORED_COMMANDS.match(text):
            return
        if _RISKY_COMMANDS.match(text):
            issues.append(ParseIssue(file, line, "Unrecognised statement; review manually", snippet))
        return

    if isinstance(tree, exp.Alter) and (tree.args.get("kind") or "").upper() == "TABLE":
        tbl, schema = _table_of(tree.this)
        for action in tree.args.get("actions") or []:
            _alter_action(tree, action, tbl, schema, file, line, snippet, changes, issues)
        return

    if isinstance(tree, exp.Drop):
        kind = (tree.args.get("kind") or "").upper()
        if kind == "TABLE":
            for t in tree.args.get("tables") or []:
                if isinstance(t, exp.Table):
                    n, s = _table_of(t)
                    changes.append(Change(ChangeKind.DROP_TABLE, n, file, line, schema=s, snippet=snippet))
        return

    if isinstance(tree, exp.TruncateTable):
        issues.append(ParseIssue(file, line, "TRUNCATE removes all rows; verify consumers tolerate empty tables", snippet))
        return

    if isinstance(tree, exp.Create):
        kind = (tree.args.get("kind") or "").upper()
        if kind == "TABLE":
            target = tree.this.this if isinstance(tree.this, exp.Schema) else tree.this
            if isinstance(target, exp.Table):
                n, s = _table_of(target)
                created.add(tkey(s, n))
                changes.append(Change(ChangeKind.CREATE_TABLE, n, file, line, schema=s, snippet=snippet))
        elif kind == "INDEX":
            idx = tree.this
            if isinstance(idx, exp.Index) and isinstance(idx.args.get("table"), exp.Table):
                n, s = _table_of(idx.args["table"])
                cols = []
                params = idx.args.get("params")
                for o in (params.args.get("columns") or []) if params is not None else []:
                    col = o.this if isinstance(o, exp.Ordered) else o
                    cols.append(col.name if hasattr(col, "name") else "")
                changes.append(
                    Change(
                        ChangeKind.CREATE_INDEX, n, file, line, schema=s,
                        column=",".join(c for c in cols if c) or None,
                        concurrently=bool(tree.args.get("concurrently")),
                        unique=bool(tree.args.get("unique")), snippet=snippet,
                    )
                )
        return


def _alter_action(tree, action, tbl, schema, file, line, snippet, changes, issues) -> None:
    if isinstance(action, exp.Drop):
        kind = (action.args.get("kind") or "").upper()
        if kind == "COLUMN":
            for c in action.args.get("tables") or []:
                changes.append(Change(ChangeKind.DROP_COLUMN, tbl, file, line, column=_name(c), schema=schema, snippet=snippet))
        return
    if isinstance(action, exp.RenameColumn):
        changes.append(Change(ChangeKind.RENAME_COLUMN, tbl, file, line, column=_name(action.this), new_name=_name(action.args.get("to")), schema=schema, snippet=snippet))
        return
    if isinstance(action, exp.AlterRename):
        tgt = action.this
        changes.append(Change(ChangeKind.RENAME_TABLE, tbl, file, line, new_name=_name(tgt), schema=schema, snippet=snippet))
        return
    if isinstance(action, exp.AlterColumn):
        col = _name(action.this)
        if action.args.get("dtype") is not None:
            changes.append(Change(ChangeKind.ALTER_TYPE, tbl, file, line, column=col, new_type=action.args["dtype"].sql("postgres"), schema=schema, snippet=snippet))
        if action.args.get("allow_null") is False and not action.args.get("drop"):
            changes.append(Change(ChangeKind.SET_NOT_NULL, tbl, file, line, column=col, schema=schema, snippet=snippet))
        return
    if isinstance(action, exp.ColumnDef):
        nullable, has_default = True, False
        for c in action.args.get("constraints") or []:
            k = c.args.get("kind")
            if isinstance(k, exp.NotNullColumnConstraint):
                nullable = False
            elif isinstance(k, exp.PrimaryKeyColumnConstraint):
                nullable = False
            elif isinstance(k, (exp.DefaultColumnConstraint, exp.GeneratedAsIdentityColumnConstraint, exp.ComputedColumnConstraint)):
                has_default = True
        kind = action.args.get("kind")
        changes.append(Change(ChangeKind.ADD_COLUMN, tbl, file, line, column=_name(action.this), new_type=kind.sql("postgres") if kind is not None else None, nullable=nullable, has_default=has_default, schema=schema, snippet=snippet))
        return
    if isinstance(action, exp.AddConstraint):
        not_valid = bool(tree.args.get("not_valid"))
        for con in action.expressions:
            inner = list(con.expressions) if isinstance(con, exp.Constraint) else [con]
            for part in inner:
                if isinstance(part, (exp.UniqueColumnConstraint, exp.PrimaryKey)):
                    changes.append(Change(ChangeKind.ADD_UNIQUE, tbl, file, line, schema=schema, snippet=snippet))
                elif isinstance(part, exp.ForeignKey):
                    changes.append(Change(ChangeKind.ADD_FOREIGN_KEY, tbl, file, line, schema=schema, not_valid=not_valid, snippet=snippet))
                elif isinstance(part, exp.CheckColumnConstraint):
                    changes.append(Change(ChangeKind.ADD_CHECK, tbl, file, line, schema=schema, not_valid=not_valid, snippet=snippet))
        return


# ---------------------------------------------------------------------- Alembic

def _norm_alembic_type(node) -> str:
    """sa.Text() -> 'text', sa.String() -> 'varchar', sa.String(50) -> 'varchar(50)', otherwise the lowercased source."""
    src = ast.unparse(node)
    src = re.sub(r"^(?:sa|sqlalchemy)\.(?:dialects\.postgresql\.)?", "", src)
    m = re.fullmatch(r"(\w+)\((.*)\)", src)
    name, args = (m.group(1), m.group(2).strip()) if m else (src, "")
    low = name.lower()
    if low in ("text", "unicodetext"):
        return "text"
    if low in ("string", "unicode", "varchar"):
        return f"varchar({args})" if args and args.split(",")[0].strip().isdigit() else "varchar"
    return src.lower()


def _const_str(node) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _const_bool(node) -> bool | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, bool) else None


class _Args:
    def __init__(self, args: list, keywords: dict):
        self.args, self.kw = args, keywords

    def get(self, idx: int | None, name: str | None = None):
        if name is not None and name in self.kw:
            return self.kw[name]
        if idx is not None and idx < len(self.args):
            return self.args[idx]
        return None


def _is_alembic(tree: ast.Module) -> ast.FunctionDef | None:
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name == "upgrade":
            return n
    return None


def _column_info(node) -> tuple[str | None, str | None, bool, bool]:
    """name, type, nullable, has_default from sa.Column(...) / Column(...)."""
    if not isinstance(node, ast.Call):
        return None, None, True, False
    fn = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
    if fn != "Column":
        return None, None, True, False
    name = _const_str(node.args[0]) if node.args else None
    type_node = node.args[1] if len(node.args) > 1 else None
    kws = {k.arg: k.value for k in node.keywords if k.arg}
    nullable_kw = _const_bool(kws.get("nullable"))
    pk = _const_bool(kws.get("primary_key")) is True
    nullable = (nullable_kw if nullable_kw is not None else (not pk))
    sd = kws.get("server_default")
    has_default = (sd is not None and not (isinstance(sd, ast.Constant) and sd.value is None))
    for a in node.args[1:]:
        if isinstance(a, ast.Call):
            f = a.func.attr if isinstance(a.func, ast.Attribute) else getattr(a.func, "id", "")
            if f in ("Identity", "Computed", "Sequence"):
                has_default = True
    if _const_bool(kws.get("autoincrement")) and pk:
        has_default = True
    return name, (ast.unparse(type_node) if type_node is not None else None), nullable, has_default


def parse_alembic(rel: str, text: str) -> tuple[list[Change], list[ParseIssue], set[tuple[str, str]], bool]:
    """Returns (changes, issues, tables_created_in_file, is_alembic)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError) as e:
        return [], [ParseIssue(rel, getattr(e, "lineno", 1) or 1, f"Python syntax error: {e.__class__.__name__}")], set(), False
    up = _is_alembic(tree)
    if up is None:
        return [], [], set(), False
    changes: list[Change] = []
    issues: list[ParseIssue] = []
    created: set[tuple[str, str]] = set()
    lines = text.splitlines()

    def snip(n) -> str:
        i = getattr(n, "lineno", 1) - 1
        return redact(lines[i]) if 0 <= i < len(lines) else ""

    batch_vars: dict[str, tuple[str | None, str | None]] = {}
    for node in ast.walk(up):
        if isinstance(node, ast.With):
            for item in node.items:
                c = item.context_expr
                if (isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "batch_alter_table"
                        and isinstance(item.optional_vars, ast.Name) and c.args):
                    kws = {k.arg: k.value for k in c.keywords if k.arg}
                    batch_vars[item.optional_vars.id] = (_const_str(c.args[0]), _const_str(kws.get("schema")))

    for node in ast.walk(up):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)):
            continue
        owner, method = node.func.value.id, node.func.attr
        kws = {k.arg: k.value for k in node.keywords if k.arg}
        schema = _const_str(kws.get("schema"))
        args = list(node.args)
        if owner == "op":
            if method == "execute":
                _execute(node, rel, lines, changes, issues, created)
                continue
            if method == "batch_alter_table":
                continue
        elif owner in batch_vars:
            tbl_name, schema = batch_vars[owner]
            if tbl_name is None:
                issues.append(ParseIssue(rel, node.lineno, "batch_alter_table target is not a string literal", snip(node)))
                continue
            # batch methods omit the table argument; insert it so one handler serves both.
            args = [ast.Constant(value=tbl_name)] + args
            if method in ("create_index", "create_unique_constraint", "create_foreign_key", "create_check_constraint"):
                pass
        else:
            continue
        a = _Args(args, kws)
        line, sn = node.lineno, snip(node)

        def tbl(idx: int, name: str) -> str | None:
            v = _const_str(a.get(idx, name))
            if v is None:
                issues.append(ParseIssue(rel, line, f"op.{method}: table name is not a string literal", sn))
            return v

        if method == "add_column":
            t = tbl(0, "table_name")
            col, ty, nullable, has_default = _column_info(a.get(1, "column"))
            if t and col:
                changes.append(Change(ChangeKind.ADD_COLUMN, t, rel, line, column=col, new_type=ty, nullable=nullable, has_default=has_default, schema=schema, snippet=sn))
            elif t:
                issues.append(ParseIssue(rel, line, "add_column column definition is not a literal sa.Column(...)", sn))
        elif method == "drop_column":
            t = tbl(0, "table_name")
            col = _const_str(a.get(1, "column_name"))
            if t and col:
                changes.append(Change(ChangeKind.DROP_COLUMN, t, rel, line, column=col, schema=schema, snippet=sn))
            elif t:
                issues.append(ParseIssue(rel, line, "drop_column column name is not a string literal", sn))
        elif method == "alter_column":
            t = tbl(0, "table_name")
            col = _const_str(a.get(1, "column_name"))
            if not (t and col):
                if t:
                    issues.append(ParseIssue(rel, line, "alter_column column name is not a string literal", sn))
                continue
            new_name = _const_str(kws.get("new_column_name"))
            if new_name:
                changes.append(Change(ChangeKind.RENAME_COLUMN, t, rel, line, column=col, new_name=new_name, schema=schema, snippet=sn))
            if "type_" in kws:
                changes.append(Change(ChangeKind.ALTER_TYPE, t, rel, line, column=col, new_type=_norm_alembic_type(kws["type_"]), schema=schema, snippet=sn))
            if _const_bool(kws.get("nullable")) is False:
                sd = kws.get("server_default")
                has_default = sd is not None and not (isinstance(sd, ast.Constant) and sd.value is None)
                changes.append(Change(ChangeKind.SET_NOT_NULL, t, rel, line, column=col, has_default=has_default, schema=schema, snippet=sn))
        elif method == "rename_table":
            old = _const_str(a.get(0, "old_table_name"))
            new = _const_str(a.get(1, "new_table_name"))
            if old and new:
                changes.append(Change(ChangeKind.RENAME_TABLE, old, rel, line, new_name=new, schema=schema, snippet=sn))
            else:
                issues.append(ParseIssue(rel, line, "rename_table names are not string literals", sn))
        elif method == "drop_table":
            t = tbl(0, "table_name")
            if t:
                changes.append(Change(ChangeKind.DROP_TABLE, t, rel, line, schema=schema, snippet=sn))
        elif method == "create_table":
            t = tbl(0, "table_name")
            if t:
                created.add(tkey(schema, t))
                changes.append(Change(ChangeKind.CREATE_TABLE, t, rel, line, schema=schema, snippet=sn))
        elif method == "create_index":
            t = _const_str(a.get(1, "table_name"))
            if t is None:
                issues.append(ParseIssue(rel, line, "op.create_index: table name is not a string literal", sn))
                continue
            cols = a.get(2, "columns")
            names = []
            if isinstance(cols, (ast.List, ast.Tuple)):
                names = [s for s in (_const_str(e) for e in cols.elts) if s]
            conc = _const_bool(kws.get("postgresql_concurrently")) is True
            changes.append(Change(ChangeKind.CREATE_INDEX, t, rel, line, column=",".join(names) or None, concurrently=conc, unique=_const_bool(kws.get("unique")) is True, schema=schema, snippet=sn))
        elif method == "create_unique_constraint":
            t = _const_str(a.get(1, "table_name"))
            if t:
                changes.append(Change(ChangeKind.ADD_UNIQUE, t, rel, line, schema=schema, snippet=sn))
            else:
                issues.append(ParseIssue(rel, line, "create_unique_constraint table is not a string literal", sn))
        elif method == "create_foreign_key":
            t = _const_str(a.get(1, "source_table"))
            if t:
                nv = _const_bool(kws.get("postgresql_not_valid")) is True
                changes.append(Change(ChangeKind.ADD_FOREIGN_KEY, t, rel, line, schema=schema, not_valid=nv, snippet=sn))
            else:
                issues.append(ParseIssue(rel, line, "create_foreign_key source table is not a string literal", sn))
        elif method == "create_check_constraint":
            t = _const_str(a.get(1, "table_name"))
            if t:
                nv = _const_bool(kws.get("postgresql_not_valid")) is True
                changes.append(Change(ChangeKind.ADD_CHECK, t, rel, line, schema=schema, not_valid=nv, snippet=sn))
    changes.sort(key=lambda c: (c.line, c.kind.value))
    return changes, issues, created, True


def _sql_text(node) -> str | None:
    s = _const_str(node)
    if s is not None:
        return s
    if isinstance(node, ast.Call):
        fn = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
        if fn == "text" and node.args:
            return _const_str(node.args[0])
    return None


def _execute(node: ast.Call, rel, lines, changes, issues, created) -> None:
    arg = node.args[0] if node.args else None
    sql = _sql_text(arg) if arg is not None else None
    sn = redact(lines[node.lineno - 1]) if 0 < node.lineno <= len(lines) else ""
    if sql is None:
        issues.append(ParseIssue(rel, node.lineno, "op.execute() argument is dynamic (not a string literal); review manually", sn))
        return
    ch, iss, cr = changes_from_sql(sql, rel, base_line=arg.lineno if arg is not None else node.lineno)
    changes.extend(ch)
    issues.extend(iss)
    created.update(cr)


def parse_migration(rel: str, text: str) -> tuple[list[Change], list[ParseIssue], set[tuple[str, str]]]:
    """Dispatch by extension. Returns (changes, issues, tables_created_in_file)."""
    if rel.endswith(".sql"):
        return changes_from_sql(text, rel, 1)
    if rel.endswith(".py"):
        ch, iss, cr, is_alembic = parse_alembic(rel, text)
        if not is_alembic and not iss:
            return [], [], set()
        return ch, iss, cr
    return [], [], set()
