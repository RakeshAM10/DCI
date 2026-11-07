"""GitHub Action tests: static lint of action.yml, escaping/validation, and end-to-end runs of the real entrypoint
against a real shallow git clone with a real TLS server standing in for api.github.com."""
from __future__ import annotations

import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import yaml

from dci import action_runner as ar
from dci.config import ConfigError
from dci.models import Confidence, Finding, Severity
from helpers import git, write_files

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
ACTION = yaml.safe_load(open(os.path.join(ROOT, "action.yml"), encoding="utf-8"))


# ------------------------------------------------------------------ static lint

def test_action_is_composite_and_never_interpolates_into_shell():
    assert ACTION["runs"]["using"] == "composite"
    for step in ACTION["runs"]["steps"]:
        if "run" in step:
            assert "${{" not in step["run"], f"expression injection risk in: {step.get('name')}"
            assert step["shell"] == "bash"


def test_every_input_the_runner_reads_is_mapped_in_action_yml():
    src = open(os.path.join(ROOT, "src", "dci", "action_runner.py"), encoding="utf-8").read()
    names = set(re.findall(r'_(?:in|bool)\("([a-z\-]+)"', src))
    run_step = next(s for s in ACTION["runs"]["steps"] if s.get("id") == "dci")
    mapped = set(run_step["env"])
    for n in names:
        assert "INPUT_" + n.upper().replace("-", "_") in mapped, n
    for n in names:
        assert n in ACTION["inputs"], n


def test_outputs_exist_and_actions_are_versioned():
    for out in ("verdict", "blocking-count", "report-path", "json-path", "sarif-path"):
        assert out in ACTION["outputs"]
    for step in ACTION["runs"]["steps"]:
        if "uses" in step:
            assert re.search(r"@[0-9a-f]{40}(\s|$)", step["uses"]), f"pin to a commit SHA: {step['uses']}"


def test_every_workflow_in_the_repo_pins_third_party_actions_to_a_sha():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for d in (".github/workflows", "examples/workflows"):
        for f in sorted(os.listdir(os.path.join(root, d))):
            for ln in open(os.path.join(root, d, f), encoding="utf-8"):
                m = re.search(r"uses:\s*(\S+)", ln)
                if m and not m.group(1).startswith(("./", "YOUR-ORG/")):
                    assert re.search(r"@[0-9a-f]{40}$", m.group(1)), f"{d}/{f}: {m.group(1)}"


def test_constraints_pin_exact_versions():
    for line in open(os.path.join(ROOT, "constraints.txt"), encoding="utf-8"):
        if line.strip() and not line.startswith("#"):
            assert "==" in line


# --------------------------------------------------------------- unit behaviour

def test_annotation_escaping_and_levels():
    f = Finding("DCI101", Severity.ERROR, Confidence.CONFIRMED, "Dropped: column, still used", "line1\nline2 100%", None, file="a,b:c.py", line=7)
    a = ar.annotation(f, True)
    assert a.startswith("::error file=a%2Cb%3Ac.py,line=7,title=")
    assert "%0A" in a and "100%25" in a and "\n" not in a
    info = Finding("DCI105", Severity.INFO, Confidence.UNKNOWN, "t", "m", None)
    assert ar.annotation(info, False) is None
    warn = Finding("DCI501", Severity.WARNING, Confidence.CONFIRMED, "t", "m", None, file="x.py", line=1)
    assert ar.annotation(warn, False).startswith("::warning ")


def test_consumer_parsing_rejects_traversal_and_missing(tmp_path):
    ws = tmp_path / "ws"
    (ws / "consumers" / "billing").mkdir(parents=True)
    ok = ar.parse_consumers("# comment\n\nbilling=consumers/billing\n", str(ws.resolve()))
    assert ok == [("billing", str((ws / "consumers" / "billing").resolve()))]
    with pytest.raises(ConfigError):
        ar.parse_consumers("x=../../etc", str(ws.resolve()))
    with pytest.raises(ConfigError):
        ar.parse_consumers("bad line", str(ws.resolve()))
    with pytest.raises(ConfigError):
        ar.parse_consumers("x=missing", str(ws.resolve()))


# ---------------------------------------------------------- end-to-end harness

MODELS = '''from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base
Base = declarative_base()


class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
    legacy_status = Column(String(20))
'''
MODELS_NEW = MODELS.replace("    legacy_status = Column(String(20))\n", "")
REPO_OLD = "from .models import Order\n\n\ndef f(s):\n    return s.query(Order.id).filter_by(legacy_status='x').all()\n"
REPO_NEW = "def f(s):\n    return []\n"
DROP = 'from alembic import op\n\n\ndef upgrade():\n    op.drop_column("orders", "legacy_status")\n\n\ndef downgrade():\n    pass\n'
ADD_NULLABLE = 'from alembic import op\nimport sqlalchemy as sa\n\n\ndef upgrade():\n    op.add_column("orders", sa.Column("channel", sa.Text(), nullable=True))\n\n\ndef downgrade():\n    pass\n'


def make_origin(tmp_path, pr_files: dict[str, str], base_files: dict[str, str] | None = None):
    """origin (bare) with main, and a PR branch; returns a SHALLOW single-branch clone of the PR branch like actions/checkout."""
    work = tmp_path / "work"
    write_files(str(work), {"svc/models.py": MODELS, "svc/repo.py": REPO_OLD, **(base_files or {})})
    git(str(work), "init", "-q", "-b", "main")
    git(str(work), "add", "-A")
    git(str(work), "commit", "-qm", "base")
    git(str(work), "checkout", "-qb", "pr")
    for rel, content in pr_files.items():
        write_files(str(work), {rel: content})
    git(str(work), "add", "-A")
    git(str(work), "commit", "-qm", "pr")
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(work), str(bare)], check=True)
    ws = tmp_path / "ws"
    subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", "pr", f"file://{bare}", str(ws)], check=True)
    return ws


class FakeGitHub(BaseHTTPRequestHandler):
    comments: list[dict] = []
    seen_auth: list[str | None] = []
    mode = "ok"

    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        FakeGitHub.seen_auth.append(self.headers.get("Authorization"))
        if FakeGitHub.mode == "forbidden":
            return self._send(403, {"message": "Resource not accessible by integration"})
        self._send(200, FakeGitHub.comments)

    def do_POST(self):
        FakeGitHub.seen_auth.append(self.headers.get("Authorization"))
        if FakeGitHub.mode == "forbidden":
            return self._send(403, {"message": "nope"})
        c = {"id": len(FakeGitHub.comments) + 1, "body": self._body()["body"]}
        FakeGitHub.comments.append(c)
        self._send(201, c)

    def do_PATCH(self):
        FakeGitHub.seen_auth.append(self.headers.get("Authorization"))
        cid = int(self.path.rsplit("/", 1)[1])
        for c in FakeGitHub.comments:
            if c["id"] == cid:
                c["body"] = self._body()["body"]
                return self._send(200, c)
        self._send(404, {})


@pytest.fixture()
def github(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
    FakeGitHub.comments, FakeGitHub.seen_auth, FakeGitHub.mode = [], [], "ok"
    srv = HTTPServer(("127.0.0.1", 0), FakeGitHub)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield {"url": f"https://localhost:{srv.server_address[1]}", "cert": str(cert)}
    srv.shutdown()


def run_action(ws, tmp_path, github=None, extra_env=None, event="pull_request"):
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps({"pull_request": {"number": 7}}))
    out, summary, temp = tmp_path / "output.txt", tmp_path / "summary.md", tmp_path / "runner_temp"
    temp.mkdir(exist_ok=True)
    env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp"), "GITHUB_WORKSPACE": str(ws),
           "GITHUB_EVENT_NAME": event, "GITHUB_BASE_REF": "main", "GITHUB_EVENT_PATH": str(event_file),
           "GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary), "RUNNER_TEMP": str(temp),
           "GITHUB_REPOSITORY": "acme/shop", "INPUT_COMMENT": "true"}
    for k in ("SystemRoot", "SYSTEMDRIVE", "COMSPEC", "PATHEXT"):
        if k in os.environ:
            env[k] = os.environ[k]
    if github:
        env.update({"GITHUB_TOKEN": "test-token", "GITHUB_API_URL": github["url"], "SSL_CERT_FILE": github["cert"]})
    env.update(extra_env or {})
    p = subprocess.run([sys.executable, "-m", "dci.action_runner"], cwd=str(ws), env=env, capture_output=True, text=True, timeout=120)
    outputs = dict(l.split("=", 1) for l in out.read_text().splitlines()) if out.exists() else {}
    return p, outputs, summary


def test_blocking_pr_fails_annotates_comments_and_updates_idempotently(tmp_path, github):
    ws = make_origin(tmp_path, {"svc/models.py": MODELS_NEW, "svc/repo.py": REPO_NEW, "svc/alembic/versions/0002_drop.py": DROP})
    assert subprocess.run(["git", "-C", str(ws), "rev-parse", "--is-shallow-repository"], capture_output=True, text=True).stdout.strip() == "true"
    p, outputs, summary = run_action(ws, tmp_path, github)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "::error file=svc/alembic/versions/0002_drop.py,line=5,title=DCI104" in p.stdout
    assert outputs["verdict"] == "fail" and outputs["blocking-count"] == "1"
    assert os.path.isfile(outputs["sarif-path"]) and json.load(open(outputs["sarif-path"]))["version"] == "2.1.0"
    assert json.load(open(outputs["json-path"]))["verdict"].startswith("FAIL")
    assert "DCI104" in summary.read_text()
    assert len(FakeGitHub.comments) == 1 and "<!-- dci-report -->" in FakeGitHub.comments[0]["body"]
    assert set(FakeGitHub.seen_auth) == {"Bearer test-token"}
    p2, _, _ = run_action(ws, tmp_path, github)
    assert p2.returncode == 1
    assert len(FakeGitHub.comments) == 1, "second run must update the same comment, not add another"
    assert "test-token" not in p.stdout + p.stderr


def test_clean_pr_passes_without_blocking(tmp_path, github):
    ws = make_origin(tmp_path, {"svc/alembic/versions/0002_add.py": ADD_NULLABLE})
    p, outputs, _ = run_action(ws, tmp_path, github)
    assert p.returncode == 0, p.stdout + p.stderr
    assert outputs["verdict"] == "pass" and outputs["blocking-count"] == "0"
    assert "::error" not in p.stdout


def test_comment_failure_on_read_only_token_does_not_change_result(tmp_path, github):
    FakeGitHub.mode = "forbidden"
    ws = make_origin(tmp_path, {"svc/models.py": MODELS_NEW, "svc/repo.py": REPO_NEW, "svc/alembic/versions/0002_drop.py": DROP})
    p, outputs, _ = run_action(ws, tmp_path, github)
    assert p.returncode == 1
    assert "::warning title=DCI could not post the PR comment" in p.stdout
    second = tmp_path / "second"
    second.mkdir()
    ws2 = make_origin(second, {"svc/alembic/versions/0002_add.py": ADD_NULLABLE})
    p2, _, _ = run_action(ws2, second, github)
    assert p2.returncode == 0


def test_non_pr_event_without_base_is_skipped(tmp_path):
    ws = make_origin(tmp_path, {"svc/alembic/versions/0002_add.py": ADD_NULLABLE})
    p, outputs, _ = run_action(ws, tmp_path, None, {"GITHUB_BASE_REF": ""}, event="push")
    assert p.returncode == 0 and "::notice title=DCI skipped" in p.stdout
    assert outputs["verdict"] == "skipped"


@pytest.mark.parametrize("bad", ["--evil", "a..b", "x y", "main;rm -rf /", "$(id)"])
def test_unsafe_base_ref_is_rejected(tmp_path, bad):
    ws = make_origin(tmp_path, {"svc/alembic/versions/0002_add.py": ADD_NULLABLE})
    p, _, _ = run_action(ws, tmp_path, None, {"INPUT_BASE_REF": bad})
    assert p.returncode == 2 and "::error title=DCI configuration error" in p.stdout


def test_fail_on_never_and_invalid_inputs(tmp_path):
    ws = make_origin(tmp_path, {"svc/models.py": MODELS_NEW, "svc/repo.py": REPO_NEW, "svc/alembic/versions/0002_drop.py": DROP})
    p, outputs, _ = run_action(ws, tmp_path, None, {"INPUT_FAIL_ON": "never"})
    assert p.returncode == 0 and outputs["verdict"] in ("warn", "pass", "fail")
    p, _, _ = run_action(ws, tmp_path, None, {"INPUT_FAIL_ON": "whatever"})
    assert p.returncode == 2
    p, _, _ = run_action(ws, tmp_path, None, {"INPUT_ROLLING_DEPLOY": "maybe"})
    assert p.returncode == 2
    p, outputs, _ = run_action(ws, tmp_path, None, {"INPUT_ROLLING_DEPLOY": "false"})
    assert p.returncode == 0, "without rolling-deploy the rollout-window finding is informational"


def test_missing_base_branch_is_a_clear_error(tmp_path):
    ws = make_origin(tmp_path, {"svc/alembic/versions/0002_add.py": ADD_NULLABLE})
    p, _, _ = run_action(ws, tmp_path, None, {"INPUT_BASE_REF": "no-such-branch"})
    assert p.returncode == 2 and "no-such-branch" in p.stdout
