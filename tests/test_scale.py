"""Scale and resource-limit behaviour, on real generated source trees (no mocks)."""
from __future__ import annotations

import os

import pytest

from dci import cli, report
from dci.analyze import analyze
from dci.config import Config, ConfigError, load_text
from helpers import write_files

MODELS = ("from sqlalchemy import Column, Integer, String\nfrom sqlalchemy.orm import declarative_base\nBase = declarative_base()\n\n\n"
          + "".join(f"class M{i}(Base):\n    __tablename__ = 't{i}'\n    id = Column(Integer, primary_key=True)\n    legacy_status = Column(String(20))\n\n\n" for i in range(30)))
MIG = "migrations/0002.sql"


def make_tree(root, n: int) -> None:
    files = {"app/models.py": MODELS, MIG: "".join(f"ALTER TABLE t{i} DROP COLUMN legacy_status;\n" for i in range(0, 30, 3))}
    for i in range(n):
        body = "import os\n\n\ndef noop(x):\n    return x * 2\n"
        if i % 3 == 0:
            body += f"from app.models import M{i % 30}\n\n\ndef q(s):\n    return s.query(M{i % 30}.legacy_status).all()\n"
        if i % 7 == 0:
            body += f"\n\ndef raw(s):\n    return s.execute('SELECT legacy_status FROM t{i % 30} WHERE id = 1')\n"
        if i % 11 == 0:
            body += "\n\ndef dyn(s, t):\n    return s.execute(f'SELECT legacy_status FROM {t}')\n"
        files[f"pkg{i % 9}/sub{i % 4}/m{i}.py"] = body
    write_files(str(root), files)


@pytest.fixture(scope="module")
def tree(tmp_path_factory):
    root = tmp_path_factory.mktemp("big")
    make_tree(root, 600)
    return str(root)


def run(root, **cfg):
    return analyze(Config(repo=root, migrations=[MIG], **cfg))


def test_parallel_scan_gives_exactly_the_same_report_as_serial(tree):
    serial = run(tree, workers=1)
    parallel = run(tree, workers=4, parallel_min_files=1)
    assert report.to_json(serial) == report.to_json(parallel)
    assert len(serial.findings) > 5 and serial.coverage.python_files_parsed > 200


def test_parallel_scan_is_deterministic_across_runs(tree):
    a = report.to_json(run(tree, workers=3, parallel_min_files=1))
    b = report.to_json(run(tree, workers=2, parallel_min_files=1))
    assert a == b


def test_size_budget_stops_the_scan_and_says_so(tree):
    rep = run(tree, max_total_bytes=20_000, workers=1)
    assert rep.coverage.scan_incomplete and rep.coverage.files_not_scanned > 0
    f = next(x for x in rep.findings if x.rule_id == "DCI901")
    assert f.confidence.value == "unknown" and f.severity.value == "warning"
    assert not any(x.rule_id == "DCI901" and x in rep.blocking() for x in rep.findings)
    md = report.to_markdown(rep)
    assert "Scan incomplete" in md and ("WARN" in md.splitlines()[0] or "FAIL" in md.splitlines()[0])


@pytest.mark.parametrize("workers,min_files", [(1, 400), (3, 1)])
def test_time_budget_stops_the_scan_and_never_crashes(tree, workers, min_files):
    rep = run(tree, time_budget_seconds=1e-9, workers=workers, parallel_min_files=min_files)
    assert rep.coverage.scan_incomplete and any(f.rule_id == "DCI901" for f in rep.findings)
    assert any("time budget" in n for n in rep.coverage.notes)


def test_complete_scan_has_no_dci901(tree):
    rep = run(tree, workers=1)
    assert not rep.coverage.scan_incomplete and not any(f.rule_id == "DCI901" for f in rep.findings)


def test_oversized_and_deeply_nested_files_are_skipped_safely(tmp_path):
    nested = "x = " + "(" * 500 + "1" + ")" * 500 + "\n"
    big = "# " + "a" * 3000 + "\n"
    write_files(str(tmp_path), {"app/models.py": MODELS, MIG: "ALTER TABLE t0 DROP COLUMN legacy_status;\n",
                                "app/nested.py": nested + "from app.models import M0\nM0.legacy_status\n", "app/big.py": big})
    rep = analyze(Config(repo=str(tmp_path), migrations=[MIG], max_file_bytes=2000))
    assert any("big.py" in x for x in rep.coverage.files_skipped_too_large)


def test_config_validation_of_scale_settings():
    cfg = Config()
    load_text("workers = 4\ntime_budget_seconds = 30\nmax_total_bytes = 5000000\n", cfg, ".")
    assert (cfg.workers, cfg.time_budget_seconds, cfg.max_total_bytes) == (4, 30.0, 5_000_000)
    for bad in ("workers = -1", "workers = 1000", "workers = 'x'", "time_budget_seconds = -5", "max_total_bytes = true"):
        with pytest.raises(ConfigError):
            load_text(bad + "\n", Config(), ".")


def test_cli_scale_flags(tree, capsys):
    assert cli.main(["analyze", "--repo", tree, "--migration", MIG, "--workers", "2", "--time-budget", "600"]) in (0, 1)
    assert cli.main(["analyze", "--repo", tree, "--migration", MIG, "--workers", "-3"]) == 2


# ---------------------------------------------------------------- denial-of-service guards (found by adversarial testing)
def _fast(fn, seconds):
    import time
    t = time.perf_counter()
    fn()
    assert time.perf_counter() - t < seconds, f"took {time.perf_counter() - t:.1f}s"


def test_regexes_do_not_blow_up_on_hostile_input():
    from dci.consumers import _select_list_is_dynamic
    from dci.redact import redact
    from dci.sqlutil import SQL_START
    n = 100_000
    _fast(lambda: SQL_START.match(" " * n), 1)            # was quadratic: two adjacent \s*
    _fast(lambda: SQL_START.match("\t" * n + "x"), 1)
    _fast(lambda: redact("a." * (n // 2)), 1)             # was quadratic: unbounded scheme in the URL pattern
    _fast(lambda: redact("http://" + "a:" * (n // 2)), 1)
    _fast(lambda: redact("password " * (n // 9)), 1)
    _fast(lambda: _select_list_is_dynamic("select" + " " * n + "x"), 1)  # a regex here was quadratic


def test_redaction_still_removes_credentials_after_the_hardening():
    from dci.redact import redact
    assert "s3cr3t" not in redact("dsn = 'postgresql://app:s3cr3t@db.internal/x'")
    assert "p" * 1500 not in redact("url = 'https://u:" + "p" * 1500 + "@h/x'")
    assert len(redact("x" * 1_000_000)) <= 200


@pytest.mark.parametrize("sql", [
    " UNION ALL ".join("SELECT legacy_status FROM t0" for _ in range(20000)) + ";",
    "SELECT 1 FROM t0 " + " ".join(f"JOIN j{i} ON j{i}.id = t0.id" for i in range(1, 5000)) + ";",
    "INSERT INTO t0 (legacy_status) VALUES " + ",".join("(1)" for _ in range(100000)) + ";",
])
def test_huge_sql_statements_are_analysed_in_bounded_time(sql):
    from dci.consumers import sql_references
    _fast(lambda: sql_references(sql, "x.sql", 1, "head", "sql_file", False), 25)
