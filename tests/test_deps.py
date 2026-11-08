"""Dependency check: real git repositories, real manifests."""
import json
import os
import subprocess

from dci.config import Config
from sci.run import run_checks

from test_sci import make_repo


def _run(r):
    cfg = Config(repo=r)
    cfg.base, cfg.head = "main", "feat"
    return run_checks(cfg, ["deps"])


def _ids(rep):
    return {f.rule_id: f for f in rep.findings}


def test_removed_npm_dependency_still_imported_is_confirmed(tmp_path):
    pkg = lambda d: json.dumps({"name": "x", "dependencies": d}, indent=1)  # noqa: E731
    r = make_repo(tmp_path, {"package.json": pkg({"left-pad": "1.3.0", "lodash": "4.17.21"}), "src/a.js": "const p = require('left-pad');\nimport _ from 'lodash/fp';\n"},
                  {"package.json": pkg({"lodash": "4.17.21"})})
    rep = _run(r)
    f = _ids(rep)["DEP101"]
    assert f.confidence.value == "confirmed" and rep.blocking()
    assert [(e.file, e.line) for e in f.evidence] == [("src/a.js", 1)] and "left-pad" in f.message


def test_removed_dependency_without_import_is_not_blocking(tmp_path):
    r = make_repo(tmp_path, {"requirements.txt": "flask==3.0.0\nrequests==2.31.0\n", "a.py": "import flask\n"}, {"requirements.txt": "flask==3.0.0\n"})
    rep = _run(r)
    assert _ids(rep)["DEP103"].confidence.value == "unknown" and not rep.blocking()


def test_python_name_normalisation_and_moved_between_manifests(tmp_path):
    r = make_repo(tmp_path, {"requirements.txt": "My-Pkg==1.0\nother==2\n", "a.py": "from my_pkg.sub import x\nimport other\n"},
                  {"requirements.txt": "other==2\n", "requirements-dev.txt": "my.pkg==1.0\n"})
    assert not _run(r).findings or all(f.rule_id not in ("DEP101", "DEP103") for f in _run(r).findings)  # moved, not removed
    r2 = make_repo(tmp_path, {"requirements.txt": "My-Pkg==1.0\n", "a.py": "from my_pkg.sub import x\n"}, {"requirements.txt": "\n"}, name="r2")
    assert "DEP101" in _ids(_run(r2))


def test_major_bump_is_possible_never_blocking(tmp_path):
    r = make_repo(tmp_path, {"package.json": json.dumps({"dependencies": {"react": "^17.0.2", "ms": "2.0.0"}})},
                  {"package.json": json.dumps({"dependencies": {"react": "^18.2.0", "ms": "2.1.3"}})})
    rep = _run(r)
    assert [(f.rule_id, f.confidence.value) for f in rep.findings] == [("DEP102", "possible")] and not rep.blocking()


def test_go_module_removed_but_imported(tmp_path):
    r = make_repo(tmp_path, {"go.mod": "module m\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n\tgolang.org/x/text v0.3.0\n)\n",
                             "main.go": 'package main\nimport (\n\t"github.com/pkg/errors"\n)\n'},
                  {"go.mod": "module m\n\nrequire golang.org/x/text v0.3.0\n"})
    assert "DEP101" in _ids(_run(r))


def test_broken_manifest_is_reported_not_crashed(tmp_path):
    r = make_repo(tmp_path, {"package.json": "{}"}, {"package.json": "{not json"})
    rep = _run(r)
    assert any("could not be parsed" in n for n in rep.coverage.notes) and not rep.blocking()


def test_no_manifest_change_is_quiet(tmp_path):
    r = make_repo(tmp_path, {"a.py": "x=1\n"}, {"a.py": "x=2\n"})
    assert _run(r).findings == []
