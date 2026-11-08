"""GraphQL check: schema (SDL) changes in a pull request, compared with the base branch, tied to the client operations that use them.

Unlike REST, GraphQL clients name every field they use, so DCI can *prove* a break: operation documents found in code
(`gql` templates, triple-quoted strings, .graphql files) are parsed with graphql-core and resolved against the base schema.
A removed field that an operation selects, or a new required argument that an operation does not pass, is CONFIRMED."""
from __future__ import annotations

import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from dci import gitutil
from dci.analyze import _check_workspace
from dci.config import Config, ConfigError
from dci.models import Confidence, Coverage, Finding, Reference, Severity
from dci.redact import redact
from dci.sources import FsTree, Matcher, Tree
from graphql import (GraphQLError, GraphQLSchema, TypeInfo, TypeInfoVisitor, Visitor, build_ast_schema, extend_schema, find_breaking_changes,
                     find_dangerous_changes, get_named_type, parse, visit)
from graphql.language import ast as gast

from . import callers
from .check_api import KEEP, _finish, _read_spec, _trees
from .oas import MAX_SPEC_BYTES

MAX_DOC_CHARS = 20_000
_BACKTICK = re.compile(r"`([^`]{1,20000})`")
_TRIPLE = re.compile(r'"""(.{1,20000}?)"""|\'\'\'(.{1,20000}?)\'\'\'', re.S)
_QUOTED = re.compile(r'"((?:\\.|[^"\\\n]){1,2000})"')
_LOOKS = re.compile(r"(?:^\s*\{)|\b(?:query|mutation|subscription|fragment)\b[^{}]{0,300}\{", re.S)
_INTERP = re.compile(r"\$\{[^{}\n]{0,200}\}")
_RX = {
    "TYPE_REMOVED": re.compile(r"^(\w+) was removed\.$"),
    "FIELD_REMOVED": re.compile(r"^(\w+)\.(\w+) was removed\.$"),
    "ARG_REMOVED": re.compile(r"^(\w+)\.(\w+) arg (\w+) was removed\.$"),
    "VALUE_REMOVED_FROM_ENUM": re.compile(r"^(\w+) was removed from enum type (\w+)\.$"),
    "REQUIRED_ARG_ADDED": re.compile(r"^A required arg (\w+) on (\w+)\.(\w+) was added\.$"),
    "FIELD_CHANGED_KIND": re.compile(r"^(\w+)\.(\w+) changed type from (.+) to (.+)\.$"),
    "ARG_CHANGED_KIND": re.compile(r"^(\w+)\.(\w+) arg (\w+) has changed type from (.+) to (.+)\.$"),
}
_REMOVAL = ["Keep the schema member and mark it `@deprecated(reason: ...)` until every client has moved, then remove it.",
            "Clients are listed above; clients outside the scanned code (mobile apps, partners) cannot be seen."]
_REQUIRED = ["Make the new argument optional or give it a default value.", "If it must be required, add a new field and deprecate the old one."]
_CHANGED = ["Keep the old type working (add a new field, deprecate the old one) rather than changing a field's type in place."]


@dataclass
class Use:
    file: str
    line: int
    snippet: str
    tree: str
    is_test: bool
    supplied: frozenset = frozenset()


@dataclass
class Usage:
    fields: dict = field(default_factory=lambda: defaultdict(list))
    args: dict = field(default_factory=lambda: defaultdict(list))
    types: dict = field(default_factory=lambda: defaultdict(list))
    enums: dict = field(default_factory=lambda: defaultdict(list))
    totals: Counter = field(default_factory=Counter)

    def add(self, bucket: dict, key, use: Use) -> None:
        self.totals[(id(bucket), key, use.is_test)] += 1
        if len(bucket[key]) < KEEP:
            bucket[key].append(use)


# ------------------------------------------------------------------ schema building

def _is_schema_doc(doc) -> bool:
    return not any(isinstance(d, (gast.OperationDefinitionNode, gast.FragmentDefinitionNode)) for d in doc.definitions)


_SDL_LOOKS = re.compile(r"\b(?:type|input|interface|enum|union|scalar|schema|extend\s+type)\b\s*\w*\s*(?:implements\b[^{]*)?[{=@]")


def sdl_strings(text: str) -> list[str]:
    """Schema definitions embedded in code (`typeDefs = gql`...``, triple-quoted strings)."""
    out, taken = [], []
    for rx in (_TRIPLE, _BACKTICK):
        for m in rx.finditer(text):
            if any(a <= m.start() < b for a, b in taken):
                continue
            g = next((x for x in m.groups() if x), None)
            if g and _SDL_LOOKS.search(g) and not _LOOKS.search(g.split("{", 1)[0] + "{"):
                taken.append((m.start(), m.end()))
                out.append(_INTERP.sub(lambda mm: " " * len(mm.group(0)), g))
    return out


def build(tree: Tree, paths: list[str], code_paths: list[str] = ()) -> tuple[GraphQLSchema | None, dict[str, str], str | None]:
    """(schema, texts of the schema sources, error). Every schema source of the revision is merged, so a schema split over several
    files (or kept in code strings) works."""
    texts: dict[str, str] = {}
    base_defs, exts = [], []
    sources: list[tuple[str, str]] = []
    for p in paths:
        t = _read_spec(tree, p)
        if t is not None:
            sources.append((p, t))
    for p in code_paths:
        t = tree.read(p)
        if t is not None:
            sources.extend((p, g) for g in sdl_strings(t))
    for p, t in sources:
        try:
            doc = parse(t)
        except GraphQLError:
            return None, texts, f"{p} is not valid GraphQL"
        if not _is_schema_doc(doc) or not doc.definitions:
            continue
        texts[p] = texts.get(p, "") + t + "\n"
        for d in doc.definitions:
            (exts if isinstance(d, (gast.TypeExtensionNode, gast.SchemaExtensionNode)) else base_defs).append(d)
    if not texts:
        return None, texts, None
    try:
        schema = build_ast_schema(gast.DocumentNode(definitions=tuple(base_defs)), assume_valid_sdl=True)
        if exts:
            schema = extend_schema(schema, gast.DocumentNode(definitions=tuple(exts)), assume_valid_sdl=True)
    except (GraphQLError, TypeError, KeyError) as e:
        return None, texts, f"the schema could not be built: {str(e)[:150]}"
    return schema, texts, None


def _locate(texts: dict[str, str], type_name: str | None, member: str | None) -> tuple[str, int]:
    """Best-effort file and line of a type or one of its members."""
    for path, t in texts.items():
        lines = t.split("\n")
        start = None
        if type_name:
            for i, ln in enumerate(lines):
                if re.search(rf"\b(?:type|input|interface|enum|union|scalar|extend\s+type)\s+{re.escape(type_name)}\b", ln):
                    start = i
                    break
        if start is None and type_name:
            continue
        if not member:
            return path, (start or 0) + 1
        for i in range(start or 0, min(len(lines), (start or 0) + 400)):
            if re.search(rf"\b{re.escape(member)}\b", lines[i]):
                return path, i + 1
        return path, (start or 0) + 1
    first = next(iter(texts), "")
    return first, 1


# ------------------------------------------------------------------ operation usage

class _Collector(Visitor):
    def __init__(self, ti: TypeInfo, usage: Usage, mk):
        super().__init__()
        self.ti, self.usage, self.mk = ti, usage, mk

    def enter_field(self, node, *_):
        parent = self.ti.get_parent_type()
        if parent is None or self.ti.get_field_def() is None:
            return
        supplied = frozenset(a.name.value for a in node.arguments or ())
        self.usage.add(self.usage.fields, (get_named_type(parent).name, node.name.value), self.mk(node, supplied))

    def enter_argument(self, node, *_):
        parent, fdef = self.ti.get_parent_type(), self.ti.get_field_def()
        if parent is not None and fdef is not None:
            self.usage.add(self.usage.args, (get_named_type(parent).name, fdef.ast_node.name.value if fdef.ast_node else "", node.name.value), self.mk(node, frozenset()))

    def enter_named_type(self, node, *_):
        self.usage.add(self.usage.types, node.name.value, self.mk(node, frozenset()))

    def enter_enum_value(self, node, *_):
        t = self.ti.get_input_type()
        if t is not None:
            self.usage.add(self.usage.enums, (get_named_type(t).name, node.value), self.mk(node, frozenset()))


def _candidates(path: str, text: str):
    """(start offset, document text) of every string in the file that could hold a GraphQL operation."""
    if path.lower().endswith((".graphql", ".gql", ".graphqls")):
        yield 0, text
        return
    taken: list[tuple[int, int]] = []  # spans already yielded (a triple-quoted string also contains quoted pairs)
    for rx in (_TRIPLE, _BACKTICK, _QUOTED):
        for m in rx.finditer(text):
            if any(a <= m.start() < b for a, b in taken):
                continue
            g = next((x for x in m.groups() if x), None)
            if g and "{" in g and _LOOKS.search(g):
                taken.append((m.start(), m.end()))
                yield m.start(1 if rx is not _TRIPLE else (1 if m.group(1) else 2)), g


def collect_usage(tree: Tree, tree_name: str, schema: GraphQLSchema, names: set[str], test_match: Matcher, ignore_match: Matcher,
                  cov: Coverage, usage: Usage, time_budget: float, max_total_bytes: int) -> None:
    import time
    start, total, docs, bad, files = time.monotonic(), 0, 0, 0, 0
    pre = re.compile("|".join(re.escape(n) for n in sorted(names))) if names else None
    for path, size in tree.files():
        if not (path.lower().endswith(callers.CODE_EXT) or path.lower().endswith((".graphql", ".gql"))) or ignore_match(path):
            continue
        if (time_budget and time.monotonic() - start > time_budget) or (max_total_bytes and total > max_total_bytes):
            cov.scan_incomplete = True
            cov.files_not_scanned += 1
            continue
        text = tree.read(path)
        if text is None:
            continue
        total += size
        if pre is not None and not pre.search(text):
            continue
        files += 1
        is_test = test_match(path)
        for off, doc_text in _candidates(path, text):
            if len(doc_text) > MAX_DOC_CHARS:
                continue
            clean = _INTERP.sub(lambda m: " " * len(m.group(0)), doc_text)
            try:
                doc = parse(clean)
            except GraphQLError:
                bad += 1
                continue
            if _is_schema_doc(doc) is False or any(isinstance(d, gast.OperationDefinitionNode | gast.FragmentDefinitionNode) for d in doc.definitions):
                docs += 1
                line0 = text.count("\n", 0, off)
                lines = text.split("\n")

                def mk(node, supplied, line0=line0, lines=lines, clean=clean):
                    ln = line0 + clean.count("\n", 0, node.loc.start if node.loc else 0) + 1
                    return Use(path, ln, redact(lines[ln - 1] if 0 < ln <= len(lines) else ""), tree_name, is_test, supplied)

                ti = TypeInfo(schema)
                visit(doc, TypeInfoVisitor(ti, _Collector(ti, usage, mk)))
    cov.notes.append(f"GraphQL clients: {docs} operation document(s) in {files} file(s) of {tree_name} resolved against the base schema"
                     + (f"; {bad} string(s) looked like GraphQL but did not parse" if bad else ""))


# ------------------------------------------------------------------ check

def _refs(uses: list[Use], note: str, conf: Confidence) -> list[Reference]:
    return [Reference(None, None, u.file, u.line, u.tree, "graphql_operation", "ref", conf, u.snippet, is_test=u.is_test, note=note, anchor=u.line) for u in uses]


def run(cfg: Config, cov: Coverage) -> list[Finding]:
    repo = os.path.realpath(cfg.repo)
    if not os.path.isdir(repo):
        raise ConfigError(f"Repository path does not exist: {cfg.repo}")
    _check_workspace(cfg, repo)
    ignore_match, schema_match, test_match = Matcher(cfg.ignore_paths), Matcher(cfg.graphql_schema_globs), Matcher(cfg.test_globs)
    base_tree, head_tree, opened, changed = _trees(cfg, repo)
    extra: list[Tree] = []
    try:
        changed_schema = [p for st, p in changed if schema_match(p) and not ignore_match(p)]
        # code files changed in the PR that hold schema definitions in strings (Apollo `typeDefs = gql`...`)
        code_sdl = []
        for st, p in changed:
            if st != "D" and p.lower().endswith(callers.CODE_EXT) and not schema_match(p) and not ignore_match(p) and not test_match(p):
                t = head_tree.read(p)
                if t is not None and sdl_strings(t):
                    code_sdl.append(p)
        if not changed_schema and not code_sdl:
            return []
        changed_schema += code_sdl
        paths_of = lambda tr: [p for p, sz in tr.files() if schema_match(p) and not ignore_match(p) and sz <= MAX_SPEC_BYTES]  # noqa: E731
        old, old_texts, e1 = build(base_tree, paths_of(base_tree), code_sdl)
        new, new_texts, e2 = build(head_tree, paths_of(head_tree), code_sdl)
        findings: list[Finding] = []
        cov.notes.append(f"GraphQL schema files changed in this pull request: {len(changed_schema)}")
        if old is None and new is None:
            cov.notes.append("The changed .graphql files are not schema definitions (client operations); no schema comparison was made.")
            return []
        if old is None and new is not None and not e1:
            cov.notes.append("A GraphQL schema was added in this pull request; there is no earlier version to compare it with.")
            return []
        if e1 or e2 or old is None or new is None:
            file = next(iter(new_texts or old_texts), changed_schema[0])
            findings.append(Finding("GQL902", Severity.WARNING, Confidence.UNKNOWN, "GraphQL schema could not be checked",
                                    f"The schema was not compared: {e2 or e1 or 'it exists on only one side of the change'}. Breaking changes in it were not evaluated.",
                                    None, file=file, line=1))
            return [f for f in findings if f.rule_id not in cfg.ignore_rules]

        breaking = find_breaking_changes(old, new)
        dangerous = find_dangerous_changes(old, new)
        parsed = []
        for c in breaking:
            rx = _RX.get(c.type.name)
            m = rx.match(c.description) if rx else None
            parsed.append((c, m))
        names: set[str] = set()
        for c, m in parsed:
            if m:
                names.update(g for g in m.groups() if g and re.fullmatch(r"\w+", g))
        usage = Usage()
        scan = [(head_tree, "head")]
        for name, path in [*cfg.consumer_repos, *cfg.config_consumer_repos]:
            if not os.path.isdir(path):
                raise ConfigError(f"Consumer repository path does not exist: {path}")
            t = FsTree(path, f"consumer:{name}", cfg.max_file_bytes)
            extra.append(t)
            scan.append((t, f"consumer:{name}"))
        if names:
            for tree, tname in scan:
                cov.trees_scanned.append(tname)
                collect_usage(tree, tname, old, names, test_match, ignore_match, cov, usage, cfg.time_budget_seconds, cfg.max_total_bytes)

        def emit(rid, sev, conf, title, msg, loc, uses, rec, total=None):
            refs = _refs(uses, "", conf)
            refs.sort(key=lambda r: (r.tree != "head", r.file, r.line))
            findings.append(Finding(rid, sev, conf, title, msg, None, refs[:cfg.max_evidence], rec, total_evidence=max(len(refs), total or 0), file=loc[0], line=loc[1]))

        def split(uses):
            return [u for u in uses if not u.is_test], [u for u in uses if u.is_test]

        def removal(c, m, what, uses, bucket, key, texts_for_loc, member):
            loc = _locate(old_texts, m.group(1) if what != "enum" else m.group(2), member)
            n, nt = usage.totals[(id(bucket), key, False)], usage.totals[(id(bucket), key, True)]
            cn, ct = split(uses)
            if cn:
                emit("GQL101", Severity.ERROR, Confidence.CONFIRMED, "Removed schema member is still used by a client operation",
                     f"{c.description} {n} client operation(s) still use it and will fail validation.", loc, cn, _REMOVAL, n)
            if ct:
                emit("GQL102", Severity.WARNING, Confidence.CONFIRMED, "Removed schema member is used only by tests",
                     f"{c.description} {nt} test operation(s) use it.", loc, ct, _REMOVAL, nt)
            if not (cn or ct):
                emit("GQL105", Severity.INFO, Confidence.UNKNOWN, "Clients outside the scanned code are not visible",
                     f"{c.description} No operation in the scanned code uses it, but other clients (mobile apps, partners) cannot be seen.", loc, [], _REMOVAL)

        other: list[str] = []
        for c, m in parsed:
            kind = c.type.name
            if m and kind == "FIELD_REMOVED":
                removal(c, m, "field", usage.fields.get((m.group(1), m.group(2)), []), usage.fields, (m.group(1), m.group(2)), old_texts, m.group(2))
            elif m and kind == "ARG_REMOVED":
                removal(c, m, "arg", usage.args.get((m.group(1), m.group(2), m.group(3)), []), usage.args, (m.group(1), m.group(2), m.group(3)), old_texts, m.group(2))
            elif m and kind == "TYPE_REMOVED":
                removal(c, m, "type", usage.types.get(m.group(1), []), usage.types, m.group(1), old_texts, None)
            elif m and kind == "VALUE_REMOVED_FROM_ENUM":
                removal(c, m, "enum", usage.enums.get((m.group(2), m.group(1)), []), usage.enums, (m.group(2), m.group(1)), old_texts, m.group(1))
            elif m and kind == "REQUIRED_ARG_ADDED":
                arg, t, f = m.group(1), m.group(2), m.group(3)
                loc = _locate(new_texts, t, f)
                missing = [u for u in usage.fields.get((t, f), []) if arg not in u.supplied]
                cn, ct = split(missing)
                if cn:
                    emit("GQL104", Severity.ERROR, Confidence.CONFIRMED, "Operations do not pass a newly required argument",
                         f"{c.description} {len(cn)} client operation(s) select {t}.{f} without `{arg}` and will fail validation.", loc, cn, _REQUIRED)
                if ct:
                    emit("GQL106", Severity.WARNING, Confidence.CONFIRMED, "Test operations do not pass a newly required argument",
                         f"{c.description} {len(ct)} test operation(s) select {t}.{f} without `{arg}`.", loc, ct, _REQUIRED)
                if not missing:
                    emit("GQL105", Severity.INFO, Confidence.UNKNOWN, "Clients outside the scanned code are not visible",
                         f"{c.description} No operation in the scanned code selects it without the argument, but other clients cannot be seen.", loc, [], _REQUIRED)
            elif m and kind in ("FIELD_CHANGED_KIND", "ARG_CHANGED_KIND"):
                t, f = m.group(1), m.group(2)
                uses = usage.fields.get((t, f), [])
                emit("GQL113", Severity.WARNING, Confidence.POSSIBLE, "A field or argument changed type",
                     f"{c.description} {len(uses)} client operation(s) select {t}.{f}; check they handle the new type." if uses
                     else f"{c.description} No operation in the scanned code uses it; other clients cannot be seen.", _locate(new_texts, t, f), uses, _CHANGED)
            else:
                other.append(c.description)
        if other:
            loc = _locate(new_texts, None, None)
            emit("GQL114", Severity.WARNING, Confidence.POSSIBLE, "Other breaking schema changes",
                 "These breaking changes have no client-usage analysis:\n" + "\n".join(f"- {d}" for d in other[:30]) + (f"\n- … and {len(other) - 30} more" if len(other) > 30 else ""),
                 loc, [], ["Check every client of the affected types before shipping."])
        if dangerous:
            emit("GQL121", Severity.INFO, Confidence.POSSIBLE, "Changes that can affect clients",
                 "\n".join(f"- {d.description}" for d in dangerous[:30]) + (f"\n- … and {len(dangerous) - 30} more" if len(dangerous) > 30 else ""),
                 _locate(new_texts, None, None), [], ["Clients with exhaustive enum or union handling may need an update."])
        return _finish(findings, cfg, cov, "GQL901")
    finally:
        for t in [*opened, *extra]:
            t.close()
