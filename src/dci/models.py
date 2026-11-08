"""Core data model. Every finding carries provenance (file, line, tree, how it was found)."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(str, enum.Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Confidence(str, enum.Enum):
    CONFIRMED = "confirmed"  # resolved statically to a concrete file/line
    POSSIBLE = "possible"  # dynamic or ambiguous; needs human review
    UNKNOWN = "unknown"  # evidence is missing / outside what DCI can see


class ChangeKind(str, enum.Enum):
    DROP_COLUMN = "drop_column"
    DROP_TABLE = "drop_table"
    RENAME_COLUMN = "rename_column"
    RENAME_TABLE = "rename_table"
    ALTER_TYPE = "alter_type"
    SET_NOT_NULL = "set_not_null"
    ADD_COLUMN = "add_column"
    CREATE_INDEX = "create_index"
    ADD_UNIQUE = "add_unique"
    ADD_FOREIGN_KEY = "add_foreign_key"
    ADD_CHECK = "add_check"
    CREATE_TABLE = "create_table"


@dataclass
class Change:
    """One schema operation extracted from a migration's upgrade path."""

    kind: ChangeKind
    table: str
    file: str
    line: int
    column: str | None = None
    new_name: str | None = None  # rename target
    new_type: str | None = None
    schema: str | None = None
    nullable: bool | None = None  # for ADD_COLUMN
    has_default: bool | None = None  # for ADD_COLUMN / SET_NOT_NULL in same op
    concurrently: bool = False
    not_valid: bool = False
    unique: bool = False
    snippet: str = ""

    def describe(self) -> str:
        t = f"{self.schema}.{self.table}" if self.schema else self.table
        if self.kind in (ChangeKind.RENAME_TABLE,):
            return f"rename table {t} -> {self.new_name}"
        if self.kind == ChangeKind.RENAME_COLUMN:
            return f"rename column {t}.{self.column} -> {self.new_name}"
        if self.column:
            return f"{self.kind.value.replace('_', ' ')} {t}.{self.column}"
        return f"{self.kind.value.replace('_', ' ')} {t}"


@dataclass
class ParseIssue:
    """Something in a migration DCI could not statically interpret. Never silently dropped."""

    file: str
    line: int
    message: str
    snippet: str = ""


@dataclass
class Reference:
    """A place in source code that depends on a table/column."""

    table: str | None
    column: str | None
    file: str
    line: int
    tree: str  # "head", "base" or "consumer:<name>"
    via: str  # orm_attribute | orm_definition | orm_constructor | raw_sql | table_def | dynamic_sql | sql_file
    role: str  # ref | definition | insert | write | star | dynamic
    confidence: Confidence
    snippet: str = ""
    insert_columns: tuple[str, ...] | None = None
    candidates: tuple[tuple[str, str], ...] = ()  # (schema, table) pairs an unqualified column may belong to
    defaulted: tuple[str, ...] = ()  # columns the writer need not supply (ORM/server default)
    tokens: frozenset[str] = frozenset()
    is_test: bool = False
    note: str = ""
    schema: str | None = None  # None = unqualified (the default schema, 'public')
    anchor: int = 0  # first line of the construct (SQL string/statement) this came from; 0 = same as `line`

    def key(self) -> tuple:
        return (self.file, self.line, self.schema, self.table, self.column, self.via, self.role)


@dataclass
class AiNote:
    """Advisory, model-written analysis of a finding. It never changes severity, confidence or the pass/fail result."""

    verdict: str  # likely_breaks | likely_safe | unclear
    summary: str
    suggested_fix: str = ""
    citations: list[dict] = field(default_factory=list)  # verified {file, line, quote}
    model: str = ""


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    confidence: Confidence
    title: str
    message: str
    change: Change | None
    evidence: list[Reference] = field(default_factory=list)
    recommendation: list[str] = field(default_factory=list)
    total_evidence: int = 0
    file: str = ""
    line: int = 0
    ai: AiNote | None = None


@dataclass
class Coverage:
    migration_files: list[str] = field(default_factory=list)
    trees_scanned: list[str] = field(default_factory=list)
    python_files_parsed: int = 0
    python_files_skipped_by_filter: int = 0
    python_files_failed: list[str] = field(default_factory=list)
    sql_files_parsed: int = 0
    unanalyzed_files_by_ext: dict[str, int] = field(default_factory=dict)
    files_skipped_too_large: list[str] = field(default_factory=list)
    models_found: int = 0
    notes: list[str] = field(default_factory=list)
    scan_incomplete: bool = False  # a size or time budget stopped the scan: absence of findings proves less
    files_not_scanned: int = 0


@dataclass
class Report:
    version: str
    changes: list[Change]
    findings: list[Finding]
    issues: list[ParseIssue]
    coverage: Coverage
    fail_on: str = "error"
    title: str = "DCI database change check"
    headline: str = ""  # replaces the schema-change summary line when set (multi-check runs)

    def blocking(self) -> list[Finding]:
        """Only confirmed findings at the configured severity can fail CI. Possible/unknown never block."""
        order = {"error": 3, "warning": 2, "info": 1, "never": 99}
        threshold = order.get(self.fail_on, 3)
        return [
            f
            for f in self.findings
            if f.confidence == Confidence.CONFIRMED and order[f.severity.value] >= threshold
        ]
