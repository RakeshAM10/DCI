"""Regression tests for the problems found in the 5 Nov 2026 review. Every test uses real files and, where git matters,
a real temporary git repository. PostgreSQL-backed counterparts of the schema / quoted-identifier tests are in
corpus.py (run by test_groundtruth.py)."""
from __future__ import annotations

import os

import pytest

from dci import cli
from dci.analyze import analyze
from dci.config import Config, ConfigError, load_file
from dci.identifiers import quote_ident, tkey
from dci.migrations import changes_from_sql, parse_alembic
from dci.models import Confidence
from helpers import git, write_files

MODELS = '''from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base
Base = declarative_base()


class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
    legacy_status = Column(String(20))
'''
DROP_COL = "ALTER TABLE orders DROP COLUMN legacy_status;\n"
DROP_TABLE = "DROP TABLE orders;\n"
MIG = "db/migrations/0002.sql"


def rule_ids(rep) -> list[str]:
    return sorted(f.rule_id for f in rep.findings)


def evidence(rep, rule: str) -> list[tuple[str, str, int]]:
    return sorted((e.tree, e.file, e.line) for f in rep.findings if f.rule_id == rule for e in f.evidence)


def run(tmp_path, files: dict[str, str], migration_sql: str = DROP_COL, **cfg) -> object:
    write_files(str(tmp_path), {MIG: migration_sql, **files})
    return analyze(Config(repo=str(tmp_path), migrations=[MIG], **cfg))


def pr_repo(tmp_path, base: dict[str, str], pr: dict[str, str]) -> str:
    repo = str(tmp_path / "repo")
    write_files(repo, base)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    git(repo, "checkout", "-qb", "pr")
    write_files(repo, pr)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "pr")
    return repo


# ------------------------------------------------------------------ 1. line numbers

def test_sql_file_references_report_their_real_line(tmp_path):
    sql = "SELECT 1;\nSELECT 2;\n\n-- third\nSELECT id\n  FROM orders\n WHERE legacy_status = 'x';\n\nUPDATE orders SET legacy_status = NULL WHERE id = 1;\n"
    rep = run(tmp_path, {"reports/q.sql": sql})
    lines = [ln for _t, f, ln in evidence(rep, "DCI101") if f == "reports/q.sql"]
    assert lines == [7, 9], lines


def test_multi_statement_python_string_reports_real_lines(tmp_path):
    src = ('from sqlalchemy import text\n\n\ndef f(c):\n    c.execute(text("""\n        SELECT id\n          FROM orders;\n'
           '        UPDATE orders SET legacy_status = 1;\n    """))\n')
    rep = run(tmp_path, {"app/q.py": src})
    assert [ln for _t, f, ln in evidence(rep, "DCI101") if f == "app/q.py"] == [8]


def test_multiline_dynamic_sql_with_confirmed_refs_is_not_also_reported_as_possible(tmp_path):
    src = ('def f(c, oid):\n    c.execute(f"""SELECT id,\n        legacy_status\n        FROM orders WHERE id = {oid}""")\n')
    rep = run(tmp_path, {"app/q.py": src})
    assert "DCI101" in rule_ids(rep) and "DCI103" not in rule_ids(rep), rule_ids(rep)
    assert [ln for _t, _f, ln in evidence(rep, "DCI101")] == [3]


# ------------------------------------------------------------- 2. base versus head

Q_ONE_LINE = 'from sqlalchemy import text\n\n\ndef f(c):\n    return c.execute(text("SELECT id, legacy_status FROM orders"))\n'
Q_REFORMATTED = ('from sqlalchemy import text\n\n# reformatted, extra column, moved down\n\n\ndef f(c):\n    return c.execute(text("""\n'
                 '        SELECT id,\n               total,\n               legacy_status\n          FROM orders\n    """))\n')


def test_formatting_only_change_is_not_reported_as_a_removed_dependency(tmp_path):
    repo = pr_repo(tmp_path, {"app/q.py": Q_ONE_LINE}, {"app/q.py": Q_REFORMATTED, MIG: DROP_COL})
    rep = analyze(Config(repo=repo, base="main", head="HEAD"))
    ids = rule_ids(rep)
    assert "DCI101" in ids, ids  # code still uses the column: this blocks
    assert "DCI104" not in ids, f"formatting change was reported as removal: {ids}"


def test_real_removal_is_still_a_rollout_window_finding(tmp_path):
    repo = pr_repo(tmp_path, {"app/q.py": Q_ONE_LINE}, {"app/q.py": "def f(c):\n    return None\n", MIG: DROP_COL})
    rep = analyze(Config(repo=repo, base="main", head="HEAD"))
    assert "DCI104" in rule_ids(rep) and "DCI101" not in rule_ids(rep), rule_ids(rep)
    assert {t for t, _f, _l in evidence(rep, "DCI104")} == {"base"}


def test_removing_one_of_two_usages_reports_exactly_one_removed(tmp_path):
    two = 'from sqlalchemy import text\n\n\ndef a(c):\n    return c.execute(text("SELECT legacy_status FROM orders"))\n\n\ndef b(c):\n    return c.execute(text("SELECT legacy_status FROM orders"))\n'
    one = 'from sqlalchemy import text\n\n\ndef b(c):\n    return c.execute(text("SELECT legacy_status FROM orders"))\n'
    repo = pr_repo(tmp_path, {"app/q.py": two}, {"app/q.py": one, MIG: DROP_COL})
    rep = analyze(Config(repo=repo, base="main", head="HEAD"))
    assert len(evidence(rep, "DCI104")) == 1, evidence(rep, "DCI104")
    assert len(evidence(rep, "DCI101")) == 1, evidence(rep, "DCI101")


def test_a_consumer_repository_cannot_mask_a_removal_in_this_repository(tmp_path):
    repo = pr_repo(tmp_path, {"app/q.py": Q_ONE_LINE}, {"app/q.py": "def f(c):\n    return None\n", MIG: DROP_COL})
    other = tmp_path / "other"
    write_files(str(other), {"app/q.py": Q_ONE_LINE})  # same relative path and same statement
    rep = analyze(Config(repo=repo, base="main", head="HEAD", consumer_repos=[("other", str(other))]))
    assert "DCI104" in rule_ids(rep), rule_ids(rep)
    assert "DCI101" in rule_ids(rep)  # and the consumer itself is reported


# ------------------------------------------------------------------------ 3. schema

def _schema_files() -> dict[str, str]:
    t = 'from sqlalchemy import text\n\n\ndef f(c):\n    return c.execute(text("SELECT legacy_status FROM {}"))\n'
    return {"app/arch.py": t.format("archive.orders"), "app/pub.py": t.format("public.orders"), "app/plain.py": t.format("orders")}


def test_public_migration_matches_public_and_unqualified_but_not_archive(tmp_path):
    rep = run(tmp_path, _schema_files(), "ALTER TABLE public.orders DROP COLUMN legacy_status;\n")
    assert sorted(f for _t, f, _l in evidence(rep, "DCI101")) == ["app/plain.py", "app/pub.py"]


def test_unqualified_migration_means_public(tmp_path):
    rep = run(tmp_path, _schema_files())
    assert sorted(f for _t, f, _l in evidence(rep, "DCI101")) == ["app/plain.py", "app/pub.py"]


def test_archive_migration_matches_only_archive_and_says_search_path_is_not_analysed(tmp_path):
    rep = run(tmp_path, _schema_files(), "ALTER TABLE archive.orders DROP COLUMN legacy_status;\n")
    assert sorted(f for _t, f, _l in evidence(rep, "DCI101")) == ["app/arch.py"]
    assert any("search_path" in n for n in rep.coverage.notes)


def test_orm_model_schema_from_table_args_is_respected(tmp_path):
    arch_model = MODELS.replace('    __tablename__ = "orders"\n', '    __tablename__ = "orders"\n    __table_args__ = {"schema": "archive"}\n')
    use = "from .models import Order\n\n\ndef f(s):\n    return s.query(Order.legacy_status).all()\n"
    files = {"svc/models.py": arch_model, "svc/use.py": use}
    assert "DCI101" not in rule_ids(run(tmp_path / "a", files, "ALTER TABLE public.orders DROP COLUMN legacy_status;\n"))
    assert "DCI101" in rule_ids(run(tmp_path / "b", files, "ALTER TABLE archive.orders DROP COLUMN legacy_status;\n"))


def test_core_table_schema_keyword_is_respected(tmp_path):
    core = ('import sqlalchemy as sa\nmd = sa.MetaData()\norders = sa.Table("orders", md, sa.Column("id", sa.Integer), sa.Column("legacy_status", sa.String), schema="archive")\n\n\n'
            'def f(c):\n    return c.execute(sa.select(orders.c.legacy_status))\n')
    assert "DCI101" not in rule_ids(run(tmp_path / "a", {"svc/core.py": core}))
    assert "DCI101" in rule_ids(run(tmp_path / "b", {"svc/core.py": core}, "ALTER TABLE archive.orders DROP COLUMN legacy_status;\n"))


def test_three_part_foreign_key_keeps_its_schema(tmp_path):
    fk = ('from sqlalchemy import Column, ForeignKey, Integer\nfrom sqlalchemy.orm import declarative_base\nBase = declarative_base()\n\n\n'
          'class Note(Base):\n    __tablename__ = "notes"\n    id = Column(Integer, primary_key=True)\n    order_id = Column(Integer, ForeignKey("archive.orders.id"))\n')
    mig = "ALTER TABLE orders DROP COLUMN id;\n"
    assert "DCI101" not in rule_ids(run(tmp_path / "a", {"svc/n.py": fk}, mig))
    assert "DCI101" in rule_ids(run(tmp_path / "b", {"svc/n.py": fk}, "ALTER TABLE archive.orders DROP COLUMN id;\n"))


# ----------------------------------------------------------------- 4. path validation

def _toml_consumer(ws: str, rel: str) -> None:
    write_files(ws, {".dci.toml": f'[[consumer_repos]]\nname = "x"\npath = "{rel}"\n'})


def test_workspace_rejects_consumer_path_from_config_file(tmp_path):
    ws, out = tmp_path / "ws", tmp_path / "outside"
    write_files(str(ws), {MIG: DROP_COL})
    write_files(str(out), {"secret.sql": "SELECT legacy_status FROM orders;\n"})
    _toml_consumer(str(ws), "../outside")
    cfg = Config(repo=str(ws), migrations=[MIG], workspace=str(ws))
    load_file(str(ws / ".dci.toml"), cfg)
    with pytest.raises(ConfigError, match="outside the workspace"):
        analyze(cfg)


def test_workspace_resolves_symlinks_before_checking(tmp_path):
    ws, out = tmp_path / "ws", tmp_path / "outside"
    write_files(str(ws), {MIG: DROP_COL})
    write_files(str(out), {"secret.sql": "SELECT legacy_status FROM orders;\n"})
    os.symlink(str(out), str(ws / "link"))
    cfg = Config(repo=str(ws), migrations=[MIG], workspace=str(ws), consumer_repos=[("x", str(ws / "link"))])
    with pytest.raises(ConfigError, match="outside the workspace"):
        analyze(cfg)


def test_workspace_allows_a_consumer_inside_it(tmp_path):
    ws = tmp_path / "ws"
    write_files(str(ws), {MIG: DROP_COL, "consumers/billing/q.sql": "SELECT legacy_status FROM orders;\n"})
    cfg = Config(repo=str(ws), migrations=[MIG], workspace=str(ws), consumer_repos=[("billing", str(ws / "consumers" / "billing"))])
    assert any(t.startswith("consumer:billing") for t, _f, _l in evidence(analyze(cfg), "DCI101"))


def test_cli_workspace_flag_rejects_config_consumer_outside(tmp_path, capsys):
    ws, out = tmp_path / "ws", tmp_path / "outside"
    write_files(str(ws), {MIG: DROP_COL})
    write_files(str(out), {"q.sql": "SELECT legacy_status FROM orders;\n"})
    _toml_consumer(str(ws), "../outside")
    rc = cli.main(["analyze", "--repo", str(ws), "--migration", MIG, "--workspace", str(ws)])
    assert rc == 2 and "outside the workspace" in capsys.readouterr().err


def test_action_rejects_dci_toml_consumer_outside_workspace(tmp_path):
    from test_action import make_origin, run_action
    ws = make_origin(tmp_path, {".dci.toml": '[[consumer_repos]]\nname = "x"\npath = "../outside"\n'})
    write_files(str(tmp_path / "outside"), {"secret.sql": "SELECT legacy_status FROM orders;\n"})
    p, outputs, _summary = run_action(ws, tmp_path, extra_env={"INPUT_TRUST_PR_CONFIG": "true"})
    assert p.returncode == 2, p.stdout + p.stderr
    assert "outside the workspace" in p.stdout
    assert "secret.sql" not in p.stdout


# --------------------------------------------------------------------- 5. aliases

ALIAS_FILES = {
    "app/models.py": MODELS,
    "app/db.py": "from app.models import Order as O\n",
    "app/reexport.py": "def g(s):\n    from app.db import O\n    return s.query(O).all()\n",
    "app/chain.py": "from app.db import O as P\n\n\ndef g(s):\n    return s.query(P).all()\n",
    "app/direct.py": "from app.models import Order as Z\n\n\ndef g(s):\n    return s.query(Z).all()\n",
    "app/modq.py": "import app.models as m\n\n\ndef g(s):\n    return s.query(m.Order).all()\n",
    "app/pkgq.py": "from app import models\n\n\ndef g(s):\n    return s.query(models.Order).all()\n",
    "app/unrelated.py": "from other.thing import O\n\n\ndef g(s):\n    return s.query(O).all()\n",
}


def test_aliases_reexports_and_module_qualified_models_are_all_found(tmp_path):
    rep = run(tmp_path, ALIAS_FILES, DROP_TABLE)
    found = {f for _t, f, _l in evidence(rep, "DCI121")}
    for name in ("direct", "reexport", "chain", "modq", "pkgq"):
        assert f"app/{name}.py" in found, f"{name}.py not found; found={sorted(found)}"
    assert "app/unrelated.py" not in found, "an `O` imported from an unrelated module must not resolve to Order"


def test_unused_model_check_sees_module_qualified_usage(tmp_path):
    """`models.Order` is the only use of the model: it must count as used, so the finding stays CONFIRMED and blocks."""
    files = {"app/models.py": MODELS, "app/use.py": "from app import models\n\n\ndef g(s):\n    return s.query(models.Order).all()\n"}
    rep = run(tmp_path, files, DROP_TABLE)
    assert any(f.rule_id == "DCI121" and f.confidence == Confidence.CONFIRMED for f in rep.findings), rule_ids(rep)
    assert rep.blocking()


def test_file_using_only_an_alias_is_not_skipped_by_the_relevance_filter(tmp_path):
    rep = run(tmp_path, {"app/models.py": MODELS, "app/db.py": "from app.models import Order as Thing\n", "app/use.py": "from app.db import Thing\n\n\ndef g(s):\n    return s.query(Thing).all()\n"}, DROP_TABLE)
    assert "app/use.py" in {f for _t, f, _l in evidence(rep, "DCI121")}


# ------------------------------------------------------------ 6. quoted identifiers

def test_sql_migration_identifiers_follow_postgresql_folding():
    ch, _iss, created = changes_from_sql('ALTER TABLE Orders DROP COLUMN Legacy;\nALTER TABLE "Orders" DROP COLUMN "Legacy";\nCREATE TABLE "Shipments" (id int);\n', "m.sql")
    assert [(c.table, c.column) for c in ch if c.column] == [("orders", "legacy"), ("Orders", "Legacy")]
    assert created == {tkey(None, "Shipments")}


def test_alembic_names_are_used_exactly_as_written():
    src = 'from alembic import op\n\n\ndef upgrade():\n    op.drop_column("Orders", "Legacy")\n    op.drop_column("orders", "legacy")\n'
    ch, _iss, _cr, ok = parse_alembic("v/0002.py", src)
    assert ok and [(c.table, c.column) for c in ch] == [("Orders", "Legacy"), ("orders", "legacy")]


def test_quoted_mixed_case_table_does_not_match_unquoted_code(tmp_path):
    code = 'from sqlalchemy import text\n\n\ndef f(c):\n    return c.execute(text("SELECT legacy_status FROM orders"))\n'
    assert "DCI101" not in rule_ids(run(tmp_path, {"app/q.py": code}, 'ALTER TABLE "Orders" DROP COLUMN legacy_status;\n'))


def test_unquoted_mixed_case_code_folds_and_matches(tmp_path):
    code = 'from sqlalchemy import text\n\n\ndef f(c):\n    return c.execute(text("SELECT Legacy_Status FROM Orders"))\n'
    assert "DCI101" in rule_ids(run(tmp_path, {"app/q.py": code}))


def test_quoted_code_matches_quoted_migration_only(tmp_path):
    code = 'from sqlalchemy import text\n\n\ndef f(c):\n    return c.execute(text(\'SELECT "Legacy" FROM "Orders"\'))\n'
    assert "DCI101" in rule_ids(run(tmp_path / "a", {"app/q.py": code}, 'ALTER TABLE "Orders" DROP COLUMN "Legacy";\n'))
    assert "DCI101" not in rule_ids(run(tmp_path / "b", {"app/q.py": code}, "ALTER TABLE orders DROP COLUMN legacy;\n"))


def test_orm_mixed_case_tablename_is_case_sensitive(tmp_path):
    model = ('from sqlalchemy import Column, Integer, String\nfrom sqlalchemy.orm import declarative_base\nBase = declarative_base()\n\n\n'
             'class Mixed(Base):\n    __tablename__ = "Orders"\n    id = Column(Integer, primary_key=True)\n    legacy_status = Column(String)\n\n\n'
             'def f(s):\n    return s.query(Mixed.legacy_status).all()\n')
    assert "DCI101" not in rule_ids(run(tmp_path / "a", {"svc/m.py": model}))  # plain `orders` is a different table
    assert "DCI101" in rule_ids(run(tmp_path / "b", {"svc/m.py": model}, 'ALTER TABLE "Orders" DROP COLUMN legacy_status;\n'))


def test_recommendations_quote_identifiers_that_need_it():
    assert quote_ident("orders") == "orders" and quote_ident("Orders") == '"Orders"' and quote_ident('a"b') == '"a""b"'


def test_set_not_null_recommendation_quotes_mixed_case_table(tmp_path):
    rep = run(tmp_path, {}, 'ALTER TABLE "Orders" ALTER COLUMN status SET NOT NULL;\n')
    rec = next(f for f in rep.findings if f.rule_id == "DCI301").recommendation
    assert any('"Orders"' in r for r in rec), rec


# ----------------------------------------------------- 0. GitTree crash (--head, no --base)

def test_head_without_base_works_on_a_git_repository(tmp_path, capsys):
    repo = str(tmp_path / "repo")
    write_files(repo, {"svc/models.py": MODELS, "svc/q.py": "from .models import Order\n\n\ndef f(s):\n    return s.query(Order.legacy_status).all()\n", MIG: DROP_COL})
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "x")
    rc = cli.main(["analyze", "--repo", repo, "--head", "HEAD", "--migration", MIG])
    out = capsys.readouterr()
    assert rc == 1, out.err  # blocking finding, not an internal error (3)
    assert "DCI101" in out.out


# ------------------------------------------------- 6. config trust, CLI path default, assignment aliases

def _drop_pr() -> dict[str, str]:
    from test_action import DROP
    return {"svc/alembic/versions/0002_drop.py": DROP}


def test_action_ignores_pr_edited_config_and_uses_base_branch(tmp_path):
    """A PR that sets fail_on=never / ignore_rules in .dci.toml must not weaken the check."""
    from test_action import make_origin, run_action
    pr = {**_drop_pr(), ".dci.toml": 'fail_on = "never"\nignore_rules = ["DCI101", "DCI104"]\n'}
    ws = make_origin(tmp_path, pr)
    p, outputs, _s = run_action(ws, tmp_path, extra_env={"INPUT_FAIL_ON": ""})
    assert p.returncode == 1, p.stdout + p.stderr
    assert outputs["verdict"] != "pass" and "adds .dci.toml" in p.stdout


def test_action_uses_base_branch_config_and_flags_a_pr_that_changes_it(tmp_path):
    from test_action import make_origin, run_action
    base = {".dci.toml": 'fail_on = "never"\n'}
    pr = {**_drop_pr(), ".dci.toml": 'fail_on = "error"\n'}
    ws = make_origin(tmp_path, pr, base_files=base)
    p, _o, _s = run_action(ws, tmp_path, extra_env={"INPUT_FAIL_ON": ""})
    assert p.returncode == 0, p.stdout + p.stderr  # base says never; the PR's stricter value is not used either
    assert "changes .dci.toml" in p.stdout


def test_action_trust_pr_config_opt_in_uses_pr_version(tmp_path):
    from test_action import make_origin, run_action
    pr = {**_drop_pr(), ".dci.toml": 'fail_on = "never"\n'}
    ws = make_origin(tmp_path, pr)
    p, _o, _s = run_action(ws, tmp_path, extra_env={"INPUT_FAIL_ON": "", "INPUT_TRUST_PR_CONFIG": "true"})
    assert p.returncode == 0, p.stdout + p.stderr
    assert "::warning title=DCI configuration" not in p.stdout


def test_action_deleting_config_in_pr_does_not_drop_base_settings(tmp_path):
    from test_action import make_origin, run_action
    ws = make_origin(tmp_path, _drop_pr(), base_files={".dci.toml": 'ignore_paths = ["svc/**"]\n'})
    (ws / ".dci.toml").unlink(missing_ok=True)
    p, _o, _s = run_action(ws, tmp_path, extra_env={"INPUT_FAIL_ON": ""})
    assert "deletes .dci.toml" in p.stdout
    assert p.returncode == 0, p.stdout + p.stderr  # base config ignores svc/** (where the only consumer is): still honoured


def test_cli_rejects_config_consumer_outside_repo_parent_by_default(tmp_path, capsys):
    parent = tmp_path / "parent"
    repo, out = parent / "repo", tmp_path / "elsewhere"
    write_files(str(repo), {MIG: DROP_COL})
    write_files(str(out), {"q.sql": "SELECT legacy_status FROM orders;\n"})
    _toml_consumer(str(repo), "../../elsewhere")
    rc = cli.main(["analyze", "--repo", str(repo), "--migration", MIG])
    assert rc == 2 and "--allow-outside-config-paths" in capsys.readouterr().err
    rc = cli.main(["analyze", "--repo", str(repo), "--migration", MIG, "--allow-outside-config-paths"])
    assert rc == 1  # opted in: the consumer is read and the confirmed reference blocks


def test_cli_allows_sibling_consumer_from_config_and_unrestricted_flag(tmp_path, capsys):
    parent = tmp_path / "parent"
    repo, sib, far = parent / "repo", parent / "billing", tmp_path / "far"
    write_files(str(repo), {MIG: DROP_COL})
    write_files(str(sib), {"q.sql": "SELECT legacy_status FROM orders;\n"})
    write_files(str(far), {"q.sql": "SELECT 1;\n"})
    _toml_consumer(str(repo), "../billing")
    assert cli.main(["analyze", "--repo", str(repo), "--migration", MIG]) == 1
    # an explicit --consumer flag is the operator's own choice and stays unrestricted
    (repo / ".dci.toml").unlink()
    assert cli.main(["analyze", "--repo", str(repo), "--migration", MIG, "--consumer", f"far={far}"]) in (0, 1)


def _alias_scan_evidence(tmp_path, files, rule="DCI101"):
    write_files(str(tmp_path), {MIG: DROP_COL, **files})
    rep = analyze(Config(repo=str(tmp_path), migrations=[MIG]))
    return evidence(rep, rule)


def test_assignment_alias_same_module(tmp_path):
    ev = _alias_scan_evidence(tmp_path, {
        "app/models.py": MODELS,
        "app/use.py": "from app.models import Order\n\nOrd = Order\n\n\ndef f(s):\n    return s.query(Ord.legacy_status).all()\n"})
    assert any(f == "app/use.py" and l == 7 for _t, f, l in ev), ev


def test_assignment_alias_cross_module_and_chain(tmp_path):
    ev = _alias_scan_evidence(tmp_path, {
        "app/models.py": MODELS,
        "app/shortcuts.py": "from app.models import Order\n\nOrd = Order\nOrd2 = Ord\n",
        "app/use.py": "from app.shortcuts import Ord2\n\n\ndef f(s):\n    return s.query(Ord2.legacy_status).all()\n"})
    assert any(f == "app/use.py" and l == 5 for _t, f, l in ev), ev


def test_assignment_alias_via_module_attribute(tmp_path):
    ev = _alias_scan_evidence(tmp_path, {
        "app/models.py": MODELS,
        "app/shortcuts.py": "import app.models as m\n\nOrd = m.Order\n",
        "app/use.py": "from app import shortcuts\n\n\ndef f(s):\n    return s.query(shortcuts.Ord.legacy_status).all()\n"})
    assert any(f == "app/use.py" and l == 5 for _t, f, l in ev), ev


def test_unrelated_assignment_is_not_an_alias(tmp_path):
    ev = _alias_scan_evidence(tmp_path, {
        "app/models.py": MODELS,
        "app/use.py": "Thing = dict\nOrd = Thing\n\n\ndef f():\n    return Ord.legacy_status\n"})
    assert not any(f == "app/use.py" for _t, f, _l in ev), ev


# ------------------------------------------- 7. MetaData(schema), search_path, dynamic SQL

META_MODELS = '''from sqlalchemy import Column, Integer, String, MetaData
from sqlalchemy.orm import declarative_base
Base = declarative_base(metadata=MetaData(schema="archive"))


class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
    legacy_status = Column(String(20))
'''
META_USE = "from app.models import Order\n\n\ndef f(s):\n    return s.query(Order.legacy_status).all()\n"


def test_metadata_schema_model_is_not_matched_by_public_table_change(tmp_path):
    write_files(str(tmp_path), {"app/models.py": META_MODELS, "app/use.py": META_USE,
                                "m.sql": "ALTER TABLE public.orders DROP COLUMN legacy_status;\n"})
    rep = analyze(Config(repo=str(tmp_path), migrations=["m.sql"]))
    assert not rep.blocking() and not evidence(rep, "DCI101")


def test_metadata_schema_model_is_matched_by_its_own_schema(tmp_path):
    write_files(str(tmp_path), {"app/models.py": META_MODELS, "app/use.py": META_USE,
                                "m.sql": "ALTER TABLE archive.orders DROP COLUMN legacy_status;\n"})
    rep = analyze(Config(repo=str(tmp_path), migrations=["m.sql"]))
    assert any(f == "app/use.py" for _t, f, _l in evidence(rep, "DCI101"))


def test_metadata_variable_and_declarative_base_class_forms(tmp_path):
    forms = {
        "var": "meta = MetaData(schema='archive')\nBase = declarative_base(metadata=meta)\n",
        "cls": "class Base(DeclarativeBase):\n    metadata = MetaData(schema='archive')\n",
    }
    for name, head in forms.items():
        d = tmp_path / name
        models = ("from sqlalchemy import Column, Integer, String, MetaData\nfrom sqlalchemy.orm import declarative_base, DeclarativeBase\n"
                  + head + "\n\nclass Order(Base):\n    __tablename__ = 'orders'\n    id = Column(Integer, primary_key=True)\n    legacy_status = Column(String(20))\n")
        write_files(str(d), {"app/models.py": models, "app/use.py": META_USE, "m.sql": "ALTER TABLE public.orders DROP COLUMN legacy_status;\n"})
        assert not analyze(Config(repo=str(d), migrations=["m.sql"])).blocking(), name


def test_metadata_with_non_literal_schema_keeps_the_warning_note(tmp_path):
    models = META_MODELS.replace('MetaData(schema="archive")', "MetaData(schema=SCHEMA)").replace("Base =", "SCHEMA = 'x'\nBase =")
    write_files(str(tmp_path), {"app/models.py": models, "m.sql": "ALTER TABLE orders DROP COLUMN legacy_status;\n"})
    rep = analyze(Config(repo=str(tmp_path), migrations=["m.sql"]))
    assert any("non-literal" in n for n in rep.coverage.notes)


def test_search_path_in_migration_scopes_unqualified_tables():
    ch, _i, created = changes_from_sql("SET search_path TO billing;\nALTER TABLE orders DROP COLUMN legacy_status;\n", "m.sql")
    assert [(c.schema, c.table) for c in ch] == [("billing", "orders")]
    ch, _i, _c = changes_from_sql("SET search_path TO billing;\nRESET search_path;\nALTER TABLE orders DROP COLUMN legacy_status;\n", "m.sql")
    assert ch[0].schema is None
    ch, _i, _c = changes_from_sql("SET search_path TO public;\nALTER TABLE orders DROP COLUMN legacy_status;\n", "m.sql")
    assert ch[0].schema is None
    ch, _i, created = changes_from_sql('SET LOCAL search_path = "Billing", public;\nCREATE TABLE t (id int);\n', "m.sql")
    assert ch[0].schema == "Billing" and ("Billing", "t") in created


def test_search_path_migration_does_not_block_public_consumer(tmp_path):
    write_files(str(tmp_path), {"app/q.sql": "SELECT legacy_status FROM orders;\n",
                                "m.sql": "SET search_path TO billing;\nALTER TABLE orders DROP COLUMN legacy_status;\n"})
    assert not analyze(Config(repo=str(tmp_path), migrations=["m.sql"])).blocking()
    write_files(str(tmp_path), {"app/q.sql": "SELECT legacy_status FROM billing.orders;\n"})
    assert analyze(Config(repo=str(tmp_path), migrations=["m.sql"])).blocking()


@pytest.mark.parametrize("code", [
    "def h(s, t):\n    return s.execute('SELECT legacy_status FROM {}'.format(t))\n",
    "def h(s, t):\n    return s.execute(f'SELECT legacy_status FROM {t}')\n",
    "def h(s, t):\n    return s.execute('SELECT legacy_status FROM %s' % t)\n",
    "def h(s, t):\n    return s.execute('SELECT legacy_status FROM ' + t)\n",
])
def test_dynamic_table_name_with_changed_column_is_reported_as_possible(tmp_path, code):
    write_files(str(tmp_path), {"app/q.py": code, "m.sql": DROP_COL})
    rep = analyze(Config(repo=str(tmp_path), migrations=["m.sql"]))
    assert any(f == "app/q.py" for _t, f, _l in evidence(rep, "DCI103")), code
    assert not rep.blocking()  # POSSIBLE never blocks


def test_dynamic_column_list_on_changed_table_is_possible(tmp_path):
    write_files(str(tmp_path), {"app/q.py": "def f(s, cols):\n    return s.execute('SELECT ' + cols + ' FROM orders')\n", "m.sql": DROP_COL})
    rep = analyze(Config(repo=str(tmp_path), migrations=["m.sql"]))
    assert any(f == "app/q.py" for _t, f, _l in evidence(rep, "DCI103"))


def test_dynamic_sql_about_other_tables_is_not_reported(tmp_path):
    write_files(str(tmp_path), {"app/q.py": "def f(s, t):\n    return s.execute('SELECT name FROM {}'.format(t))\n", "m.sql": DROP_COL})
    assert not evidence(analyze(Config(repo=str(tmp_path), migrations=["m.sql"])), "DCI103")


def test_action_caps_annotations_to_what_github_displays(tmp_path):
    """GitHub shows at most 10 error and 10 warning annotations per step; the runner must prioritise and say what was omitted."""
    from test_action import make_origin, run_action
    cols = [f"c{i}" for i in range(12)]
    models = ("from sqlalchemy import Column, Integer\nfrom sqlalchemy.orm import declarative_base\nBase = declarative_base()\n\n\n"
              "class Order(Base):\n    __tablename__ = 'orders'\n    id = Column(Integer, primary_key=True)\n"
              + "".join(f"    {c} = Column(Integer)\n" for c in cols))
    repo = "def f(s):\n    return s.execute('SELECT " + ", ".join(cols) + " FROM orders')\n"
    mig = "from alembic import op\n\n\ndef upgrade():\n" + "".join(f"    op.drop_column('orders', '{c}')\n" for c in cols)
    ws = make_origin(tmp_path, {"svc/alembic/versions/0002_drop.py": mig}, base_files={"svc/models.py": models, "svc/repo.py": repo})
    p, outputs, _s = run_action(ws, tmp_path, extra_env={"INPUT_FAIL_ON": ""})
    errors = [ln for ln in p.stdout.splitlines() if ln.startswith("::error file=")]
    assert p.returncode == 1 and outputs["blocking-count"] == "12"
    assert len(errors) == 10
    assert "::notice title=DCI::" in p.stdout and "more finding(s)" in p.stdout


from test_action import github  # noqa: E402,F401  (pytest fixture: a local TLS server that stands in for api.github.com)


def test_pr_without_schema_changes_gets_no_new_comment_but_existing_one_is_updated(tmp_path, github):
    from test_action import FakeGitHub, make_origin, run_action
    ws = make_origin(tmp_path, {"svc/readme.txt": "docs only\n"})
    p, outputs, _s = run_action(ws, tmp_path, github)
    assert p.returncode == 0 and outputs["verdict"] == "pass"
    assert FakeGitHub.comments == [], "a PR DCI has nothing to say about must not get a comment"
    FakeGitHub.comments.append({"id": 1, "body": "<!-- dci-report -->\nold result"})
    p, _o, _s = run_action(ws, tmp_path, github)
    assert p.returncode == 0 and len(FakeGitHub.comments) == 1 and "old result" not in FakeGitHub.comments[0]["body"]


def test_editing_an_old_migration_does_not_re_report_its_old_drops(tmp_path):
    """Found by replaying redash history: a PR that only changed an import in an applied migration was blocked for a drop made years earlier."""
    import os, subprocess
    from dci.analyze import analyze
    from dci.config import Config
    r = str(tmp_path / "r")
    os.makedirs(r + "/migrations/versions"); os.makedirs(r + "/app")
    mig = "from alembic import op\n\ndef upgrade():\n    op.drop_column('orders', 'legacy')\n"
    open(r + "/migrations/versions/001_x.py", "w").write(mig)
    open(r + "/app/m.py", "w").write("from sqlalchemy import Column, String\nfrom sqlalchemy.orm import declarative_base\nBase = declarative_base()\nclass Order(Base):\n    __tablename__ = 'orders'\n    legacy = Column(String)\n    other = Column(String)\n")
    g = lambda *a: subprocess.run(["git", "-C", r, *a], check=True, capture_output=True)  # noqa: E731
    g("init", "-q", "-b", "main"); g("config", "user.email", "a@b"); g("config", "user.name", "t"); g("add", "-A"); g("commit", "-qm", "base")
    g("checkout", "-qb", "feat")
    open(r + "/migrations/versions/001_x.py", "w").write("import sqlalchemy as sa\n" + mig)  # edit unrelated to the drop
    g("add", "-A"); g("commit", "-qm", "tidy")
    cfg = Config(repo=r); cfg.base, cfg.head = "main", "feat"
    rep = analyze(cfg)
    assert not rep.blocking() and not rep.changes
    # but a NEW drop added inside an edited migration is still caught
    open(r + "/migrations/versions/001_x.py", "w").write(mig + "    op.drop_column('orders', 'other')\n")
    open(r + "/app/use.py", "w").write("from app.m import Order\nvalue = Order.other\n")
    g("add", "-A"); g("commit", "-qm", "more")
    rep2 = analyze(cfg)
    assert [c.column for c in rep2.changes] == ["other"] and rep2.blocking()


def test_column_dropped_and_added_again_in_one_migration_is_not_a_removal(tmp_path):
    """Found by replaying redash history: 'recreate the column as another type' (drop then add) was reported as a dropped column."""
    from dci.migrations import parse_migration
    from dci.analyze import _net_recreated
    mig = ("from alembic import op\nimport sqlalchemy as sa\n\ndef upgrade():\n"
           "    op.drop_column('queries', 'schedule')\n    op.add_column('queries', sa.Column('schedule', sa.JSON()))\n"
           "    op.drop_column('queries', 'old')\n    op.drop_table('t')\n    op.create_table('t', sa.Column('id', sa.Integer()))\n")
    ch, _iss, _cr = parse_migration("migrations/versions/1.py", mig)
    kinds = [(c.kind.value, c.column or c.table) for c in _net_recreated(ch)]
    assert ("drop_column", "schedule") not in kinds and ("drop_table", "t") not in kinds
    assert ("drop_column", "old") in kinds and ("add_column", "schedule") in kinds
