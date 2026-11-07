"""Every seeded case is checked against a REAL PostgreSQL engine: a query that errors after the migration must be
exactly what DCI reports as CONFIRMED. Safe changes must produce no findings."""
from __future__ import annotations

import pytest

import pg
from corpus import CASES, SETUP, SEED, Case
from helpers import ALEMBIC_TMPL, q_ids, write_files
from dci.analyze import analyze
from dci.config import Config
from dci.models import Confidence, Severity

_GT: dict[str, dict] = {}


def _truth(case: Case) -> dict:
    if case.name not in _GT:
        _GT[case.name] = pg.run(SETUP + case.setup_extra + (SEED if case.seed else []), case.sql, case.queries)
    return _GT[case.name]


pytestmark = pytest.mark.skipif(not pg.AVAILABLE, reason="PGlite (node) not installed")


def _run(case: Case, tmp_path, flavour: str):
    repo = tmp_path / f"repo_{flavour}"
    write_files(str(repo), case.files)
    roots = {"head": str(repo)}
    if flavour == "alembic":
        assert case.alembic is not None
        mig = "svc_orders/alembic/versions/0002_change.py"
        write_files(str(repo), {mig: ALEMBIC_TMPL.format(body=case.alembic)})
    else:
        mig = "db/migrations/0002_change.sql"
        write_files(str(repo), {mig: ";\n".join(case.sql) + ";\n"})
    consumers = []
    for name, files in case.consumers.items():
        croot = tmp_path / f"consumer_{name}_{flavour}"
        write_files(str(croot), files)
        consumers.append((name, str(croot)))
        roots[f"consumer:{name}"] = str(croot)
    rep = analyze(Config(repo=str(repo), migrations=[mig], consumer_repos=consumers))
    return rep, roots


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_case_against_real_postgres(case: Case, tmp_path):
    flavours = ["sql"] + (["alembic"] if case.alembic else [])
    rule_sets = {}
    for fl in flavours:
        rep, roots = _run(case, tmp_path, fl)
        rule_sets[fl] = {f.rule_id for f in rep.findings}
        assert rule_sets[fl] == case.rules, f"{fl}: expected {case.rules}, got {rule_sets[fl]}\n" + "\n".join(f"{f.rule_id} {f.title}" for f in rep.findings)
        if case.gt and case.queries:
            truth = _truth(case)
            assert truth["migration_error"] is None, truth
            broken = set(truth["query_errors"])
            confirmed = q_ids(rep, roots, Confidence.CONFIRMED, Severity.ERROR)
            possible = q_ids(rep, roots, Confidence.POSSIBLE)
            expected_confirmed = broken - case.known_miss - case.possible
            assert confirmed == expected_confirmed, f"{fl}: confirmed={confirmed} expected={expected_confirmed} broken={broken}"
            assert case.possible <= possible, f"{fl}: possible={possible} should include {case.possible}"
            assert not (confirmed - broken), "CONFIRMED finding points at a query that does not break (false positive)"
            # blocking findings must have real breakage behind them
            if rep.blocking():
                assert broken, "blocked CI although nothing breaks in PostgreSQL"
    if len(rule_sets) == 2 and case.parity:
        assert rule_sets["sql"] == rule_sets["alembic"]


def test_documented_limitations_really_break(tmp_path):
    """Queries built from strings at run time truly break in PostgreSQL. DCI cannot prove it (so they are never CONFIRMED) but
    it must report them: Q2/Q3 as POSSIBLE (DCI103) and the rest of the unseen surface as UNKNOWN (DCI105)."""
    case = next(c for c in CASES if c.name == "dynamic_sql")
    truth = _truth(case)
    assert set(truth["query_errors"]) == {"Q1", "Q2", "Q3"}
    rep, _ = _run(case, tmp_path, "sql")
    assert any(f.rule_id == "DCI105" and f.confidence == Confidence.UNKNOWN for f in rep.findings)
    assert any(f.rule_id == "DCI103" and f.confidence == Confidence.POSSIBLE for f in rep.findings)
