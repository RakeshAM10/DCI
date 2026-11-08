"""Compatibility rules. Deterministic: every CONFIRMED finding links to concrete evidence or a documented
PostgreSQL behaviour of the statement itself. Dynamic/ambiguous matches are POSSIBLE and never block CI."""
from __future__ import annotations

from collections import Counter
from dataclasses import replace

from .config import Config
from .identifiers import quote_ident as qi
from .identifiers import tkey
from .models import Change, ChangeKind, Confidence, Finding, ParseIssue, Reference, Severity

C, P, U = Confidence.CONFIRMED, Confidence.POSSIBLE, Confidence.UNKNOWN
_TEXTLIKE = ("text", "varchar", "character varying")


# ----------------------------------------------------------------- matching

def _t(change: Change) -> tuple[str, str]:
    """Identity of the changed table: (schema, name), default schema made explicit. Names are already canonical."""
    return tkey(change.schema, change.table)


def _rtk(r: Reference) -> tuple[str, str] | None:
    return tkey(r.schema, r.table) if r.table is not None else None


def match_table(refs: list[Reference], tk: tuple[str, str]) -> list[Reference]:
    out = []
    for r in refs:
        if r.role == "dynamic":  # dynamic SQL is matched on words only (POSSIBLE), so case and schema are ignored
            if tk[1].lower() in r.tokens:
                out.append(r)
        elif r.table is not None:
            if _rtk(r) == tk:
                out.append(r)
        elif r.candidates and tk in r.candidates:
            out.append(r)
    return out


def match_column(refs: list[Reference], tk: tuple[str, str], col: str) -> list[Reference]:
    out = []
    for r in refs:
        if r.role == "dynamic":
            t_in, c_in = tk[1].lower() in r.tokens, col.lower() in r.tokens
            if (t_in and c_in) or ("*dyn_table*" in r.tokens and c_in) or ("*dyn_cols*" in r.tokens and t_in):
                out.append(r)
        elif r.table is not None:
            if _rtk(r) != tk:
                continue
            if r.column == col or r.role == "star":
                out.append(r)
        elif r.column == col and (not r.candidates or tk in r.candidates):
            out.append(r)
    return out


def _downgrade_unused_definitions(matched: list[Reference], table_refs: list[Reference]) -> list[Reference]:
    """A model definition only counts as a consumer if the model is actually used somewhere in that tree."""
    used_trees = {r.tree for r in table_refs if r.role != "definition" and r.table is not None}
    out = []
    for r in matched:
        if r.role == "definition" and r.tree not in used_trees and r.confidence == C:
            out.append(replace(r, confidence=P, note="model is defined but no usage was found in this tree"))
        else:
            out.append(r)
    return out


def _ident(r: Reference) -> tuple:
    """Stable identity of a dependency for base-versus-head comparison: where (file), on what (schema, table, column),
    how (via, role). Snippet text, line numbers and the tree name are deliberately NOT part of it, so reformatting,
    unrelated edits to the same statement or moved lines do not make a dependency look removed."""
    return (r.file, _rtk(r), r.column, r.via, r.role)


def _removed(base_refs: list[Reference], head_refs: list[Reference]) -> list[Reference]:
    """Base references with no counterpart at head. Compared by identity with multiplicity: if the base used a column
    in three places of a file and head still has two, one is removed. Only the PR repository's own head tree counts;
    a consumer repository's files must never mask a removal."""
    have = Counter(_ident(r) for r in head_refs if r.tree == "head")
    out = []
    for r in sorted(base_refs, key=lambda r: (r.file, r.line)):
        k = _ident(r)
        if have[k] > 0:
            have[k] -= 1
        else:
            out.append(r)
    return out


def _split(matched: list[Reference]) -> tuple[list[Reference], list[Reference], list[Reference]]:
    """(confirmed non-test, confirmed test, possible). A POSSIBLE ref is dropped if the same line has a CONFIRMED one."""
    confirmed_lines = {(r.file, r.anchor or r.line) for r in matched if r.confidence == C and r.role != "dynamic"}
    cn, ct, po = [], [], []
    for r in matched:
        if r.confidence == C:
            (ct if r.is_test else cn).append(r)
        elif r.role == "dynamic" and (r.file, r.anchor or r.line) in confirmed_lines:
            continue
        else:
            po.append(r)
    return cn, ct, po


def _sorted(refs: list[Reference]) -> list[Reference]:
    return sorted(refs, key=lambda r: (r.tree != "head", r.confidence != C, r.is_test, r.file, r.line))


# ---------------------------------------------------------------- finding helper

def _mk(rid, sev, conf, title, msg, change, evidence=None, rec=None, cfg: Config | None = None) -> Finding:
    ev = _sorted(evidence or [])
    cap = cfg.max_evidence if cfg else 25
    return Finding(rid, sev, conf, title, msg, change, ev[:cap], rec or [], total_evidence=len(ev),
                   file=change.file if change else "", line=change.line if change else 0)


def _where(refs: list[Reference]) -> str:
    trees = sorted({r.tree for r in refs})
    names = [t.removeprefix("consumer:") if t.startswith("consumer:") else "this repository" for t in trees]
    return ", ".join(names)


# ---------------------------------------------------------------- destructive rules

_DESTRUCTIVE = {
    ChangeKind.DROP_COLUMN: (101, "Dropped column is still referenced", "drops", "column"),
    ChangeKind.RENAME_COLUMN: (111, "Renamed column is still referenced under its old name", "renames", "column"),
    ChangeKind.DROP_TABLE: (121, "Dropped table is still referenced", "drops", "table"),
    ChangeKind.RENAME_TABLE: (131, "Renamed table is still referenced under its old name", "renames", "table"),
}


def _recommend_destructive(ch: Change) -> list[str]:
    obj = f"{ch.table}.{ch.column}" if ch.column else ch.table
    tq = qi(ch.table)
    if ch.kind == ChangeKind.DROP_COLUMN:
        return [
            f"Release N: deploy code that no longer reads or writes {obj}; keep the column.",
            "Confirm no old application version, job or report still runs (deployment history; runtime query evidence if available).",
            f"Release N+1: drop {obj}. Optionally rename it to a *_deprecated name first so a hidden consumer fails loudly while the change is still reversible.",
        ]
    if ch.kind == ChangeKind.RENAME_COLUMN:
        return [
            f"Expand: add {ch.table}.{ch.new_name} (nullable); write to both columns (application dual-write or trigger); backfill in batches.",
            f"Migrate: switch all readers to {ch.new_name}, then stop writing {ch.column}.",
            f"Contract: drop {obj} in a later release once no old version is running.",
        ]
    if ch.kind == ChangeKind.DROP_TABLE:
        return [
            f"Stop all reads and writes of {ch.table}; deploy that first.",
            f"Rename it to {qi(ch.table + '_deprecated')} and wait a full release cycle (reversible).",
            "Take a backup, then drop it in a later release.",
        ]
    return [
        f"Keep consumers working: after the rename, add a compatibility view: CREATE VIEW {tq} AS SELECT * FROM {qi(ch.new_name or '')};",
        f"Migrate all consumers to {ch.new_name}, then drop the view in a later release.",
        "Alternatively create the new table, dual-write, backfill, switch readers, then drop the old table.",
    ]


def _destructive(ch: Change, head: list[Reference], base: list[Reference] | None, cfg: Config,
                 head_all: list[Reference]) -> list[Finding]:
    base_id, title, verb, level = _DESTRUCTIVE[ch.kind]
    t = _t(ch)
    obj = f"{ch.table}.{ch.column}" if ch.column else ch.table
    if level == "column":
        matched = match_column(head, t, ch.column or "")
    else:
        matched = match_table(head, t)
    matched = _downgrade_unused_definitions(matched, match_table(head, t))
    cn, ct, po = _split(matched)
    out: list[Finding] = []
    rec = _recommend_destructive(ch)

    if cn:
        out.append(_mk(
            f"DCI{base_id}", Severity.ERROR, C, title,
            f"This migration {verb} {obj}, but {len(cn)} reference(s) remain in the code at the merge commit "
            f"({_where(cn)}). Once applied, these code paths will fail with an undefined-{level} error.",
            ch, cn, rec, cfg))
    if ct:
        out.append(_mk(
            f"DCI{base_id + 1}", Severity.WARNING, C, f"{title.split(' is ')[0]} is referenced only from tests",
            f"{len(ct)} reference(s) to {obj} remain in test code and will fail after the migration.", ch, ct, None, cfg))
    if po:
        if all(r.via == "runtime_query" for r in po):
            out.append(_mk(
                f"DCI{base_id + 2}", Severity.WARNING, P, "Queries seen in production reference this",
                f"{len(po)} query/queries from the supplied runtime statistics use {obj}. The statistics carry no timestamp, so "
                "they may come from retired code; check that no live service still runs them.", ch, po, None, cfg))
        else:
            out.append(_mk(
                f"DCI{base_id + 2}", Severity.WARNING, P, "Possible references (dynamic, ambiguous or runtime-observed SQL)",
                f"{len(po)} location(s) may reference {obj} through dynamic SQL, ambiguous names, SELECT * or queries seen at runtime. "
                "DCI could not prove or rule these out; review them.", ch, po, None, cfg))

    if base is not None:
        base_m = match_column(base, t, ch.column or "") if level == "column" else match_table(base, t)
        base_m = _downgrade_unused_definitions(base_m, match_table(base, t))
        removed = _removed([r for r in base_m if r.confidence == C and not r.is_test], matched)
        if removed:
            sev = Severity.ERROR if cfg.rolling_deploy else Severity.INFO
            out.append(_mk(
                f"DCI{base_id + 3}", sev, C, "Previous application version still uses it (rollout window)",
                f"The currently deployed code references {obj} in {len(removed)} place(s) that this change removes. "
                f"If the migration runs before every old instance is replaced (rolling deploy, migrate-then-deploy), "
                f"old instances will fail while the new version is rolling out. Split into expand/contract releases.",
                ch, removed, rec, cfg))
    seen = len({r.tree for r in head_all})
    out.append(_mk(
        f"DCI{base_id + 4}", Severity.INFO, U, "Consumers outside the scanned code are not visible",
        f"DCI scanned {seen} source tree(s). Other services, scheduled jobs, BI/reporting tools, ad-hoc scripts and "
        f"non-Python code cannot be seen, and absence of a finding is not proof that nothing uses {obj}. "
        f"This change is irreversible once applied.", ch, [], rec if not out else None, cfg))
    return out


# ------------------------------------------------------------------- other rules

def _writers_missing(refs: list[Reference], tk: tuple[str, str], col: str, respect_defaults: bool) -> list[Reference]:
    out = []
    for r in refs:
        if r.role != "insert" or r.table is None or _rtk(r) != tk:
            continue
        if r.insert_columns is None:
            continue
        if col in r.insert_columns:
            continue
        if respect_defaults and col in r.defaulted:
            continue
        out.append(r)
    return out


def evaluate(changes: list[Change], issues: list[ParseIssue], head: list[Reference], base: list[Reference] | None,
             created: set[str], cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    for ch in changes:
        t = _t(ch)
        if ch.kind in _DESTRUCTIVE:
            out.extend(_destructive(ch, head, base, cfg, head))
        elif ch.kind == ChangeKind.ALTER_TYPE:
            ty = (ch.new_type or "").lower()
            if ty.startswith(_TEXTLIKE) and "(" not in ty:
                continue  # unbounded text/varchar target: binary-coercible from the common string types
            refs = _downgrade_unused_definitions(match_column(head, t, ch.column or ""), match_table(head, t))
            cn, ct, po = _split(refs)
            out.append(_mk(
                "DCI201", Severity.WARNING, P, "Column type change may rewrite the table",
                f"ALTER COLUMN TYPE on {ch.table}.{ch.column} to {ch.new_type} rewrites the table under an ACCESS EXCLUSIVE "
                f"lock unless the old and new types are binary-coercible (DCI does not know the old type). "
                f"{len(cn)} code reference(s) use this column; verify they accept the new type.",
                ch, cn, [
                    "Check the table size and test the statement on a copy.",
                    "Prefer expand/contract: add a new column of the new type, dual-write, backfill in batches, switch readers, drop the old column.",
                ], cfg))
        elif ch.kind == ChangeKind.SET_NOT_NULL:
            out.append(_mk(
                "DCI301", Severity.WARNING, C, "SET NOT NULL scans the whole table under a lock",
                f"ALTER COLUMN {ch.table}.{ch.column} SET NOT NULL validates every row while holding an ACCESS EXCLUSIVE lock, "
                f"and fails if any NULL exists.", ch, [], [
                    f"ALTER TABLE {qi(ch.table)} ADD CONSTRAINT {qi(f'{ch.table}_{ch.column}_nn')} CHECK ({qi(ch.column or '')} IS NOT NULL) NOT VALID;",
                    f"ALTER TABLE {qi(ch.table)} VALIDATE CONSTRAINT {qi(f'{ch.table}_{ch.column}_nn')};  -- does not block writes",
                    f"ALTER TABLE {qi(ch.table)} ALTER COLUMN {qi(ch.column or '')} SET NOT NULL;  -- PostgreSQL 12+ skips the scan thanks to the validated CHECK",
                ], cfg))
            if not ch.has_default:
                w = _writers_missing(head, t, ch.column or "", respect_defaults=True)
                if w:
                    out.append(_mk(
                        "DCI302", Severity.WARNING, P, "Writers that omit the column may start failing",
                        f"{len(w)} INSERT(s) into {ch.table} do not supply {ch.column}. If the column has no default they will "
                        f"violate NOT NULL after this change.", ch, w, None, cfg))
        elif ch.kind == ChangeKind.ADD_COLUMN:
            if ch.nullable is False and not ch.has_default and t not in created:
                col = ch.column or ""
                out.append(_mk(
                    "DCI401", Severity.WARNING, P, "NOT NULL column without default fails on a non-empty table",
                    f"ADD COLUMN {ch.table}.{ch.column} NOT NULL with no DEFAULT fails if the table contains any rows, "
                    f"and every existing writer that does not supply it will fail.", ch, [], [
                        "Add the column as nullable (or with a constant DEFAULT), deploy writers that set it, backfill in batches,",
                        f"then ADD CONSTRAINT ... CHECK ({ch.column} IS NOT NULL) NOT VALID, VALIDATE CONSTRAINT, SET NOT NULL.",
                    ], cfg))
                hw = _writers_missing(head, t, col, respect_defaults=True)
                if hw:
                    out.append(_mk(
                        "DCI402", Severity.ERROR, C, "Writers do not supply the new NOT NULL column",
                        f"{len(hw)} INSERT(s) into {ch.table} at the merge commit omit {ch.column}, which has no default; "
                        f"they will fail with a NOT NULL violation.", ch, hw, None, cfg))
                if base is not None:
                    bw = [r for r in base if r.role == "insert" and _rtk(r) == t and r.confidence == C
                          and not r.is_test and (r.insert_columns is not None) and col not in r.insert_columns]
                    if bw:
                        sev = Severity.ERROR if cfg.rolling_deploy else Severity.INFO
                        out.append(_mk(
                            "DCI403", sev, C, "Previous application version cannot supply the new NOT NULL column (rollout window)",
                            f"The currently deployed code inserts into {ch.table} in {len(bw)} place(s) and does not know {ch.column}. "
                            f"Until those instances are replaced, their inserts will fail.", ch, bw, None, cfg))
        elif ch.kind == ChangeKind.CREATE_INDEX:
            if not ch.concurrently and t not in created:
                out.append(_mk(
                    "DCI501", Severity.WARNING, C, "Index built without CONCURRENTLY blocks writes",
                    f"CREATE INDEX on {ch.table}({ch.column or '…'}) takes a SHARE lock that blocks INSERT/UPDATE/DELETE for the "
                    f"duration of the build.", ch, [], [
                        "Use CREATE INDEX CONCURRENTLY (Alembic: postgresql_concurrently=True inside op.get_context().autocommit_block()).",
                    ], cfg))
        elif ch.kind == ChangeKind.ADD_UNIQUE and t not in created:
            out.append(_mk(
                "DCI502", Severity.WARNING, C, "Adding a unique/primary-key constraint builds an index under a lock",
                f"ADD CONSTRAINT on {ch.table} builds its index while holding an ACCESS EXCLUSIVE lock.", ch, [], [
                    "CREATE UNIQUE INDEX CONCURRENTLY first, then ALTER TABLE ... ADD CONSTRAINT ... UNIQUE USING INDEX <index>.",
                ], cfg))
        elif ch.kind == ChangeKind.ADD_FOREIGN_KEY and not ch.not_valid and t not in created:
            out.append(_mk(
                "DCI503", Severity.WARNING, C, "Foreign key validated while locking both tables",
                f"ADD FOREIGN KEY on {ch.table} validates all rows holding a SHARE ROW EXCLUSIVE lock on both tables.", ch, [], [
                    "ADD CONSTRAINT ... NOT VALID (Alembic: postgresql_not_valid=True), then VALIDATE CONSTRAINT in a separate step.",
                ], cfg))
        elif ch.kind == ChangeKind.ADD_CHECK and not ch.not_valid and t not in created:
            out.append(_mk(
                "DCI504", Severity.WARNING, C, "CHECK constraint validated under an ACCESS EXCLUSIVE lock",
                f"ADD CHECK on {ch.table} scans the whole table under an ACCESS EXCLUSIVE lock.", ch, [], [
                    "ADD CONSTRAINT ... NOT VALID, then VALIDATE CONSTRAINT separately.",
                ], cfg))
    for i in issues:
        out.append(Finding("DCI900", Severity.WARNING, U, "Migration statement could not be analysed",
                           f"{i.message}. DCI makes no claim about this statement.", None, [], [], 0, i.file, i.line))
    return [f for f in out if f.rule_id not in cfg.ignore_rules]
