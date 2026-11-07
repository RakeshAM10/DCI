"""Unit tests for the small modules (redaction, SQL helpers, source trees, reports, GitHub client, CLI)."""
from __future__ import annotations

import json
import os

import pytest

from dci import cli, github, report
from dci.analyze import analyze
from dci.config import Config
from dci.redact import redact
from dci.sources import FsTree, GitTree, Matcher, glob_to_regex
from dci.sqlutil import normalize_params, split_statements
from helpers import git, write_files


# ------------------------------------------------------------------ redact
@pytest.mark.parametrize("line,secret", [
    ("password = 'hunter2hunter2'", "hunter2"),
    ("API_KEY: \"abcd1234\"", "abcd1234"),
    ("url = 'postgresql://app:s3cr3t@db/x'", "s3cr3t"),
    ("k = 'AKIAABCDEFGHIJKLMNOP'", "AKIAABCDEFGHIJKLMNOP"),
    ("t = 'ghp_" + "a1" * 15 + "'", "ghp_"),
    ("SELECT * FROM users WHERE email = 'a@b.com'", "a@b.com"),
    ("INSERT INTO t (a) VALUES ('x', 'y')", "'x'"),
    ("WHERE name LIKE 'ali%'", "ali%"),
])
def test_redact_removes_secrets_and_literals(line, secret):
    assert secret not in redact(line)


def test_redact_keeps_identifiers_and_truncates():
    assert "legacy_status" in redact("SELECT legacy_status FROM orders")
    assert len(redact("x" * 5000)) <= 200


# ------------------------------------------------------------------ sqlutil
def test_split_statements_respects_quotes_comments_and_dollar_bodies():
    sql = ("SELECT 'a;b';\n-- c; d\nSELECT \"x;y\";\n/* e; */ SELECT 3;\n"
           "CREATE FUNCTION f() RETURNS int AS $b$ SELECT 1; SELECT 2; $b$ LANGUAGE sql;\nSELECT 4")
    stmts = [s for s, _ in split_statements(sql)]
    assert len(stmts) == 5 and stmts[0] == "SELECT 'a;b'" and "SELECT 2;" in stmts[3] and stmts[4] == "SELECT 4"


def test_split_statements_reports_line_offsets():
    out = split_statements("SELECT 1;\n\nSELECT 2;")
    assert [off for _s, off in out] == [0, 2]


def test_normalize_params_and_casts():
    assert normalize_params("SELECT a::int FROM t WHERE x = :id AND y = %s AND z = $1") == \
        "SELECT a::int FROM t WHERE x = NULL AND y = NULL AND z = NULL"
    assert "NULL" in normalize_params("WHERE a = %(name)s")


# ------------------------------------------------------------------ sources
def test_glob_semantics():
    m = Matcher(["**/versions/*.py", "tests/**", "*.sql", "a?c.txt"])
    assert m("versions/1.py") and m("x/y/versions/1.py") and not m("versions/sub/1.py")
    assert m("tests/a/b.py") and m("x.sql") and not m("d/x.sql") and m("abc.txt") and not m("a/c.txt")
    assert glob_to_regex("a.b").match("a.b") and not glob_to_regex("a.b").match("axb")


def test_fstree_skips_symlinks_excluded_dirs_and_oversized(tmp_path):
    write_files(str(tmp_path / "r"), {"a.py": "x=1\n", "node_modules/b.py": "x\n", ".git/c": "x\n", "big.txt": "y" * 100})
    out = tmp_path / "outside.txt"
    out.write_text("secret")
    os.symlink(str(out), str(tmp_path / "r" / "link.txt"))
    os.symlink(str(tmp_path), str(tmp_path / "r" / "dirlink"))
    t = FsTree(str(tmp_path / "r"), "head", max_bytes=50)
    assert sorted(p for p, _ in t.files()) == ["a.py", "big.txt"]
    assert t.read("a.py") == "x=1\n" and t.read("big.txt") is None
    assert t.read("link.txt") is None and t.read("../outside.txt") is None


def test_gittree_reads_commit_not_working_tree_and_skips_symlinks(tmp_path):
    r = str(tmp_path / "r")
    write_files(r, {"a.py": "old\n"})
    git(r, "init", "-q", "-b", "main")
    os.symlink("/etc/passwd", os.path.join(r, "l"))
    git(r, "add", "-A")
    git(r, "commit", "-qm", "c")
    sha = git(r, "rev-parse", "HEAD").strip() if isinstance(git(r, "rev-parse", "HEAD"), str) else git(r, "rev-parse", "HEAD").decode().strip()
    write_files(r, {"a.py": "new\n"})
    t = GitTree(r, sha, "base")
    assert [p for p, _ in t.files()] == ["a.py"] and t.read("a.py") == "old\n" and t.read("l") is None
    assert t.read("missing") is None
    t.close()


# ------------------------------------------------------------------ report
def _rep(tmp_path):
    write_files(str(tmp_path), {"app/q.sql": "SELECT legacy_status FROM orders;\n", "m.sql": "ALTER TABLE orders DROP COLUMN legacy_status;\n"})
    return analyze(Config(repo=str(tmp_path), migrations=["m.sql"]))


def test_report_renderers_are_valid_and_consistent(tmp_path):
    rep = _rep(tmp_path)
    md, txt = report.to_markdown(rep), report.to_text(rep)
    assert md.splitlines()[0].startswith("## ") and "FAIL" in md and "DCI101" in md and "app/q.sql" in md
    assert "DCI101" in txt
    js = json.loads(report.to_json(rep))
    assert js["verdict"].startswith("FAIL") and any(f["rule_id"] == "DCI101" for f in js["findings"])
    sarif = json.loads(report.to_sarif(rep))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert "<!-- dci-report -->" in report.to_markdown(rep, for_comment=True)


def test_report_never_contains_literals_from_snippets(tmp_path):
    write_files(str(tmp_path), {"app/q.sql": "SELECT legacy_status FROM orders WHERE token = 'TOPSECRETVALUE1234';\n",
                                "m.sql": "ALTER TABLE orders DROP COLUMN legacy_status;\n"})
    rep = analyze(Config(repo=str(tmp_path), migrations=["m.sql"]))
    for out in (report.to_markdown(rep), report.to_json(rep), report.to_sarif(rep), report.to_text(rep)):
        assert "TOPSECRETVALUE1234" not in out


def test_clean_report_passes(tmp_path):
    write_files(str(tmp_path), {"m.sql": "ALTER TABLE orders ADD COLUMN channel text;\n"})
    rep = analyze(Config(repo=str(tmp_path), migrations=["m.sql"]))
    assert not rep.blocking() and "PASS" in report.to_markdown(rep).splitlines()[0]


# ------------------------------------------------------------------ github client
def test_api_base_requires_https(monkeypatch):
    monkeypatch.setenv("GITHUB_API_URL", "http://evil.example")
    with pytest.raises(github.GitHubError, match="https"):
        github._api_base()
    monkeypatch.setenv("GITHUB_API_URL", "https://ghe.example/api/v3/")
    assert github._api_base() == "https://ghe.example/api/v3"


def test_pr_number_from_event(tmp_path, monkeypatch):
    ev = tmp_path / "e.json"
    ev.write_text(json.dumps({"pull_request": {"number": 12}}))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(ev))
    assert github.pr_number_from_event() == 12
    ev.write_text("not json")
    assert github.pr_number_from_event() is None
    monkeypatch.delenv("GITHUB_EVENT_PATH")
    assert github.pr_number_from_event() is None


def test_upsert_requires_token_repo_and_pr(monkeypatch):
    for k in ("GITHUB_TOKEN", "GITHUB_REPOSITORY", "GITHUB_EVENT_PATH"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(github.GitHubError):
        github.upsert_comment("x")


# ------------------------------------------------------------------ cli
def test_cli_exit_codes_and_formats(tmp_path, capsys):
    write_files(str(tmp_path), {"app/q.sql": "SELECT legacy_status FROM orders;\n", "m.sql": "ALTER TABLE orders DROP COLUMN legacy_status;\n"})
    base = ["analyze", "--repo", str(tmp_path), "--migration", "m.sql"]
    assert cli.main(base) == 1
    assert cli.main([*base, "--fail-on", "never"]) == 0
    assert cli.main([*base, "--ignore-rule", "dci101", "--ignore-rule", "DCI104"]) == 0
    capsys.readouterr()
    assert cli.main([*base, "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["findings"]
    out = tmp_path / "r.sarif"
    cli.main([*base, "--format", "sarif", "--output", str(out)])
    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_cli_usage_errors_return_2(tmp_path, capsys):
    assert cli.main(["analyze", "--repo", str(tmp_path / "nope")]) == 2
    assert cli.main(["analyze", "--repo", str(tmp_path), "--consumer", "bad"]) == 2
    assert cli.main(["analyze", "--repo", str(tmp_path), "--config", str(tmp_path / "x.toml")]) == 2
    (tmp_path / ".dci.toml").write_text("fail_on = 'sometimes'\n")
    assert cli.main(["analyze", "--repo", str(tmp_path)]) == 2
    (tmp_path / ".dci.toml").write_text("not = [valid\n")
    assert cli.main(["analyze", "--repo", str(tmp_path)]) == 2
    capsys.readouterr()


def test_cli_internal_error_fails_closed(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "analyze", lambda cfg: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.delenv("DCI_DEBUG", raising=False)
    assert cli.main(["analyze", "--repo", str(tmp_path)]) == 3
    assert "internal error" in capsys.readouterr().err
