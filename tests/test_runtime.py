"""Runtime evidence. tests/data/pg_stat_statements_pg16.csv is a real export from a PostgreSQL 16 server with pg_stat_statements
(workload: 3x select legacy_status ... where id = N, one update of legacy_status, one select of id,total)."""
import json
import os
import subprocess

import pytest

from dci import runtime
from dci.analyze import analyze
from dci.config import Config, ConfigError

DATA = os.path.join(os.path.dirname(__file__), "data", "pg_stat_statements_pg16.csv")


def _repo(tmp_path, sql="ALTER TABLE orders DROP COLUMN legacy_status;"):
    r = str(tmp_path / "repo")
    os.makedirs(os.path.join(r, "migrations"))
    def g(*a):
        subprocess.run(["git", "-C", r, *a], check=True, capture_output=True)
    g("init", "-q", "-b", "main"); g("config", "user.email", "a@b"); g("config", "user.name", "t")
    open(os.path.join(r, "README.md"), "w").write("x")
    g("add", "-A"); g("commit", "-qm", "base"); g("checkout", "-qb", "feat")
    open(os.path.join(r, "migrations", "001.sql"), "w").write(sql)
    g("add", "-A"); g("commit", "-qm", "m")
    return r


def _run(repo, files, blocks=False):
    cfg = Config(repo=repo)
    cfg.base = "main"
    cfg.runtime_queries = files
    cfg.runtime_blocks = blocks
    return analyze(cfg)


def test_real_export_is_reported_possible_and_precise(tmp_path):
    res = _run(_repo(tmp_path), [DATA])
    f = [x for x in res.findings if x.rule_id == "DCI103"]
    assert len(f) == 1 and f[0].confidence.value == "possible"
    snippets = " ".join(r.snippet for r in f[0].evidence)
    assert "legacy_status = $1 where customer_id" in snippets and "where id = $1" in snippets
    assert "o.total" not in snippets  # the query that does not touch the column is not blamed
    assert not any(x.confidence.value == "confirmed" and x.severity.value == "error" for x in res.findings)


def test_blocks_flag_makes_runtime_evidence_confirmed(tmp_path):
    res = _run(_repo(tmp_path), [DATA], blocks=True)
    assert any(x.rule_id == "DCI101" and x.confidence.value == "confirmed" for x in res.findings)


def test_other_column_unaffected(tmp_path):
    res = _run(_repo(tmp_path, "ALTER TABLE orders DROP COLUMN customer_id;"), [DATA])
    assert any("customer_id" in r.snippet for x in res.findings for r in x.evidence)
    res2 = _run(_repo(tmp_path / "b", "ALTER TABLE orders DROP COLUMN nothing_here;"), [DATA])
    assert not any(r.via == "runtime_query" for x in res2.findings for r in x.evidence)


def test_json_and_jsonl_and_wrapped(tmp_path):
    rows = [{"query": "select legacy_status from orders where id = $1", "calls": 7}]
    for name, text in (("a.json", json.dumps(rows)), ("b.json", json.dumps({"queries": rows})), ("c.jsonl", json.dumps(rows[0]) + "\n")):
        p = tmp_path / name
        p.write_text(text)
        q = runtime.load_queries(str(p))
        assert len(q) == 1 and q[0].calls == 7


@pytest.mark.parametrize("text", ["id,calls\n1,2\n", '[{"calls": 1}]', "{not json", ""])
def test_malformed_files_fail_closed(tmp_path, text):
    p = tmp_path / "bad.dat"
    p.write_text(text)
    with pytest.raises(ConfigError):
        runtime.load_queries(str(p))


def test_missing_file_and_limits(tmp_path, monkeypatch):
    with pytest.raises(ConfigError):
        runtime.load_queries(str(tmp_path / "nope.csv"))
    monkeypatch.setattr(runtime, "MAX_ROWS", 2)
    p = tmp_path / "many.csv"
    p.write_text("query\n" + "select 1\n" * 3)
    with pytest.raises(ConfigError):
        runtime.load_queries(str(p))
    monkeypatch.setattr(runtime, "MAX_BYTES", 10)
    with pytest.raises(ConfigError):
        runtime.load_queries(DATA)


def test_secrets_in_literals_are_redacted_and_garbage_does_not_crash(tmp_path):
    p = tmp_path / "q.jsonl"
    p.write_text(json.dumps({"query": "select legacy_status from orders where token = 'ghp_" + "a" * 36 + "'"}) + "\n"
                 + json.dumps({"query": "this is ((( not sql"}) + "\n")
    refs, n, bad = runtime.runtime_references(str(p))
    assert n == 2 and bad >= 1
    assert all("ghp_" + "a" * 36 not in r.snippet for r in refs)
