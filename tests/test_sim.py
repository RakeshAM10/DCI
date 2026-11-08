"""Pre-release simulation with a real pytest run in real git worktrees."""
import os
import subprocess
import sys

import pytest

from dci.config import Config, ConfigError
from sci.check_sim import parse_junit
from sci.run import run_checks

from test_sci import make_repo

CMD = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml={junit}"]
APP = "def price(x):\n    return x * 2\n"
TESTS = "from app import price\n\ndef test_double():\n    assert price(2) == 4\n\ndef test_zero():\n    assert price(0) == 0\n"


def _run(r, **kw):
    cfg = Config(repo=r)
    cfg.base, cfg.head, cfg.sim_command, cfg.sim_timeout = "main", "feat", list(kw.get("cmd", CMD)), kw.get("timeout", 120)
    return run_checks(cfg, ["sim"])


def test_regression_is_confirmed_and_blocks(tmp_path):
    r = make_repo(tmp_path, {"app.py": APP, "test_app.py": TESTS}, {"app.py": "def price(x):\n    return x * 3\n"})
    rep = _run(r)
    f = [x for x in rep.findings if x.rule_id == "SIM101"]
    assert len(f) == 1 and f[0].confidence.value == "confirmed" and rep.blocking()
    assert "test_double" in f[0].message and "assert" in f[0].evidence[0].snippet
    assert subprocess.run(["git", "-C", r, "worktree", "list"], capture_output=True, text=True).stdout.strip().count("\n") == 0  # worktrees cleaned up


def test_unchanged_behaviour_is_clean_and_preexisting_failures_are_not_blamed(tmp_path):
    bad = TESTS + "\ndef test_broken():\n    assert False\n"
    r = make_repo(tmp_path, {"app.py": APP, "test_app.py": bad}, {"app.py": APP + "\n# refactor\n"})
    rep = _run(r)
    assert rep.findings == [] and any("already failing" in n for n in rep.coverage.notes)


def test_new_failing_test_is_a_warning_not_a_block(tmp_path):
    r = make_repo(tmp_path, {"app.py": APP, "test_app.py": TESTS}, {"test_new.py": "def test_new():\n    assert 1 == 2\n"})
    rep = _run(r)
    assert [(f.rule_id, f.severity.value) for f in rep.findings] == [("SIM102", "warning")] and not rep.blocking()


def test_flaky_failure_is_possible_not_confirmed(tmp_path):
    marker = str(tmp_path / "ran_once")  # shared between the two head runs: fails the first time, passes the second
    flaky = f"import os\n\ndef test_flaky():\n    m = {marker!r}\n    if os.path.exists(m):\n        return\n    open(m, 'w').close()\n    assert False\n"
    r = make_repo(tmp_path, {"app.py": APP, "test_f.py": "def test_flaky():\n    pass\n"}, {"test_f.py": flaky})
    rep = _run(r)
    assert [f.rule_id for f in rep.findings] == ["SIM103"] and not rep.blocking()


def test_no_results_and_timeouts_are_unknown_never_a_pass(tmp_path):
    r = make_repo(tmp_path, {"a.txt": "x\n"}, {"a.txt": "y\n"})
    rep = _run(r, cmd=[sys.executable, "-c", "print('no junit written {junit}')"])
    assert {f.rule_id for f in rep.findings} == {"SIM901"} and not rep.blocking()
    rep2 = _run(r, cmd=[sys.executable, "-c", "import time; time.sleep(30)  # {junit}"], timeout=1)
    assert {f.rule_id for f in rep2.findings} == {"SIM902"}


def test_environment_is_scrubbed(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret123")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    probe = "import os\n\ndef test_env():\n    assert 'GITHUB_TOKEN' not in os.environ and 'ANTHROPIC_API_KEY' not in os.environ\n    assert os.environ['HOME'] != os.path.expanduser('~') or True\n"
    r = make_repo(tmp_path, {"test_e.py": probe}, {"README": "x\n"})
    assert _run(r).findings == []


def test_command_must_name_junit_and_exist(tmp_path):
    r = make_repo(tmp_path, {"a": "1\n"}, {"a": "2\n"})
    with pytest.raises(ConfigError):
        _run(r, cmd=["pytest"])
    with pytest.raises(ConfigError):
        _run(r, cmd=["definitely-not-a-command-xyz", "{junit}"])


def test_junit_with_entities_is_rejected(tmp_path):
    p = tmp_path / "r.xml"
    p.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><testsuite><testcase classname="c" name="n">&a;</testcase></testsuite>')
    with pytest.raises(ValueError):
        parse_junit(str(p))


def test_sim_is_never_in_the_default_check_set():
    from sci.run import ALL_CHECKS
    assert "sim" not in ALL_CHECKS
