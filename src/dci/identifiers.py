"""PostgreSQL identifier semantics, in one place.

Canonical form: an unquoted identifier is folded to lower case; a quoted identifier keeps its exact spelling.
Names that come from Python strings (SQLAlchemy models, Alembic ops) are used exactly as written, because SQLAlchemy
quotes any name that is not all lower case. An unqualified table lives in the default schema ('public'); DCI does not
analyse a custom search_path."""
from __future__ import annotations

import re

from sqlglot import exp

DEFAULT_SCHEMA = "public"
_PLAIN = re.compile(r"^[a-z_][a-z0-9_$]*$")


def ident_name(node) -> str:
    """Canonical name of an Identifier, or of a Table/Column/ColumnDef whose `this` is an Identifier."""
    if node is None:
        return ""
    if isinstance(node, str):  # some sqlglot dialect paths yield a bare string for db/catalog
        return node.lower()
    ident = node if isinstance(node, exp.Identifier) else node.args.get("this")
    if isinstance(ident, exp.Identifier):
        return ident.name if ident.args.get("quoted") else ident.name.lower()
    return (getattr(node, "name", "") or "").lower()


def table_schema(tb: exp.Table) -> str | None:
    db = tb.args.get("db")
    return (ident_name(db) or None) if db is not None else None


def alias_key(tb: exp.Table) -> str:
    """The name a query uses to qualify columns of this table: its alias, else its own name."""
    alias = tb.args.get("alias")
    if alias is not None and isinstance(alias.args.get("this"), exp.Identifier):
        return ident_name(alias.args["this"])
    return ident_name(tb)


def tkey(schema: str | None, table: str) -> tuple[str, str]:
    """Identity of a table: (schema, name), with the default schema made explicit."""
    return (schema or DEFAULT_SCHEMA, table)


def quote_ident(name: str) -> str:
    return name if _PLAIN.match(name) else '"' + name.replace('"', '""') + '"'


def node_line(node, base_line: int) -> int:
    """1-based source line of a parsed SQL node, given the line where the statement starts."""
    ident = node if isinstance(node, exp.Identifier) else node.args.get("this")
    meta = getattr(ident, "meta", None) or {}
    ln = meta.get("line")
    return base_line + ln - 1 if isinstance(ln, int) and ln >= 1 else base_line
