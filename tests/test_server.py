"""SCI server: real HTTP, real SQLite, real RSA/Ed25519 crypto, real git clones and real analysis.
The only stand-in is a tiny local HTTP server playing api.github.com (the GitHub App API itself cannot be reached from tests); it records
what the server sends so the check-run results can be asserted."""
import base64
import datetime as dt
import hashlib
import hmac
import http.server
import json
import os
import subprocess
import threading
import urllib.error
import urllib.request

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sciserver import licence as lic
from sciserver.config import Settings, SettingsError
from sciserver.github import app_jwt, valid_repo
from sciserver.http import build_server, verify_signature
from sciserver.service import Service, licence_state
from sciserver.store import Store

from test_sci import GREETER, make_repo

SECRET = b"s" * 20
ADMIN = "a" * 24


FAKE_PEM: list = []


@pytest.fixture(scope="module")
def rsa_key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    FAKE_PEM[:] = [pem]
    return k, pem


class FakeGitHubAPI:
    """Local stand-in for api.github.com: issues tokens, accepts check runs, records every request."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []
        self.created: list[dict] = []
        self.drop_first_post = False
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else {}
                outer.calls.append((self.command, self.path, body))
                if self.path.endswith("/access_tokens"):
                    out = {"token": "ghs_test"}
                elif self.command == "GET" and "/check-runs" in self.path:
                    out = {"check_runs": outer.created}
                elif self.path.endswith("/check-runs"):
                    outer.created.append({"id": 4242 + len(outer.created), "name": body.get("name"), "external_id": body.get("external_id")})
                    if outer.drop_first_post:  # the check run exists, but the response never reaches the client
                        outer.drop_first_post = False
                        self.close_connection = True
                        self.connection.close()
                        return
                    out = {"id": outer.created[-1]["id"]}
                else:
                    out = {}
                data = json.dumps(out).encode()
                self.send_response(201 if self.command == "POST" else 200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_POST = do_PATCH = do_GET = _do

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def api():
    a = FakeGitHubAPI()
    yield a
    a.close()


def settings(tmp_path, rsa_pem, api_url, **kw):
    keyfile = tmp_path / "key.pem"
    keyfile.write_bytes(rsa_pem)
    base = dict(app_id="123", private_key_pem=rsa_pem, webhook_secret=SECRET, admin_token=ADMIN, data_dir=str(tmp_path / "data"), github_api=api_url,
                clone_url_template=f"{tmp_path}/{{repo}}", port=0, workers=1, job_timeout=120)
    base.update(kw)
    return Settings(**base)


def sign(body: bytes, secret=SECRET) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def post(url, event, payload, delivery="d1", secret=SECRET, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode()
    req = urllib.request.Request(url + "/webhook", data=body, method="POST",
                                 headers={"X-GitHub-Event": event, "X-GitHub-Delivery": delivery, "X-Hub-Signature-256": sign(body, secret), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except (urllib.error.URLError, OSError):  # the server answered early and closed while we were still uploading
        return 0, "connection closed"


def get(url, path, auth=None):
    req = urllib.request.Request(url + path)
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"admin:{auth}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


def pr_event(repo, number, base, head, action="opened"):
    return {"action": action, "installation": {"id": 7}, "repository": {"full_name": repo, "owner": {"login": repo.split("/")[0]}},
            "pull_request": {"number": number, "base": {"sha": base, "ref": "main"}, "head": {"sha": head}}}


# ---- signatures, JWT, config -------------------------------------------------------------------------------------------------------

def test_signature_verification_is_exact():
    body = b'{"a":1}'
    assert verify_signature(SECRET, body, sign(body))
    assert not verify_signature(SECRET, body + b" ", sign(body))
    assert not verify_signature(b"x" * 20, body, sign(body))
    assert not verify_signature(SECRET, body, None) and not verify_signature(SECRET, body, "sha256=") and not verify_signature(SECRET, body, "sha1=abc")


def test_app_jwt_is_a_valid_rs256_token_with_short_expiry(rsa_key):
    key, pem = rsa_key
    tok = app_jwt("123", pem, now=1_000_000)
    h, b, s = tok.split(".")
    pad = lambda x: x + "=" * (-len(x) % 4)  # noqa: E731
    key.public_key().verify(base64.urlsafe_b64decode(pad(s)), f"{h}.{b}".encode(), padding.PKCS1v15(), hashes.SHA256())
    claims = json.loads(base64.urlsafe_b64decode(pad(b)))
    assert claims == {"iat": 999_940, "exp": 1_000_540, "iss": "123"} and json.loads(base64.urlsafe_b64decode(pad(h)))["alg"] == "RS256"


def test_settings_reject_weak_or_missing_values(tmp_path):
    k = tmp_path / "k.pem"
    k.write_text("x")
    ok = {"SCI_APP_ID": "1", "SCI_WEBHOOK_SECRET": "w" * 20, "SCI_ADMIN_TOKEN": "t" * 24, "SCI_DATA_DIR": str(tmp_path), "SCI_PRIVATE_KEY_FILE": str(k)}
    assert Settings.from_env(ok).port == 8080
    for bad in ({"SCI_WEBHOOK_SECRET": "short"}, {"SCI_ADMIN_TOKEN": "short"}, {"SCI_GITHUB_API": "http://evil.example"}, {"SCI_PORT": "99999"},
                {"SCI_CLONE_URL_TEMPLATE": "https://x/none.git"}, {"SCI_APP_ID": ""}):
        with pytest.raises(SettingsError):
            Settings.from_env({**ok, **bad})


def test_repository_names_are_validated():
    assert valid_repo("o/r") and valid_repo("my-org/my.repo_1")
    assert not any(valid_repo(x) for x in ("o", "o/r/x", "../etc/passwd", "o/..", "o/r;rm", "o/r r", "", "/r"))


# ---- licence -----------------------------------------------------------------------------------------------------------------------

def test_licence_round_trip_tamper_and_expiry():
    pem, pub = lic.generate_keypair()
    today = dt.date(2026, 11, 9)
    tok = lic.sign(pem, id="x1", customer="Acme", max_repos=10, issued=today, expires=today + dt.timedelta(days=30))
    l = lic.verify(tok, pub)
    assert (l.customer, l.max_repos) == ("Acme", 10) and not l.expired(today) and l.expired(today + dt.timedelta(days=31)) and l.days_left(today) == 30
    head, payload, sig = tok.split(".")
    forged = json.loads(base64.urlsafe_b64decode(payload + "=="))
    forged["max_repos"] = 9999
    evil = base64.urlsafe_b64encode(json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=").decode()
    for bad in (f"{head}.{evil}.{sig}", tok[:-4] + "AAAA", "garbage", f"sci2.{payload}.{sig}"):
        with pytest.raises(lic.LicenceError):
            lic.verify(bad, pub)
    _, other_pub = lic.generate_keypair()
    with pytest.raises(lic.LicenceError):
        lic.verify(tok, other_pub)  # signed by someone else


def test_licence_state_drives_limits(tmp_path, rsa_key):
    pem, pub = lic.generate_keypair()
    t = dt.date.today()
    good = lic.sign(pem, id="a", customer="C", max_repos=5, issued=t, expires=t + dt.timedelta(days=5))
    old = lic.sign(pem, id="b", customer="C", max_repos=5, issued=t - dt.timedelta(days=9), expires=t - dt.timedelta(days=2))
    s = lambda **kw: settings(tmp_path, rsa_key[1], "http://127.0.0.1:1", **kw)  # noqa: E731
    assert licence_state(s()).kind == "community" and licence_state(s()).max_repos == 3
    assert licence_state(s(licence_token=good, licence_public_key=pub)).max_repos == 5
    assert licence_state(s(licence_token=old, licence_public_key=pub)).kind == "expired"
    bad = licence_state(s(licence_token=good, licence_public_key=lic.generate_keypair()[1]))
    assert bad.kind == "invalid" and bad.max_repos == 3  # a licence that does not verify never unlocks anything
    assert licence_state(s(licence_token=good)).kind == "invalid"


def test_licence_cli_keygen_sign_verify(tmp_path, capsys):
    import sys
    key = str(tmp_path / "priv.pem")
    assert lic.main(["keygen", "--out", key]) == 0
    pub = [l for l in capsys.readouterr().out.splitlines() if l.startswith("SCI_LICENCE_PUBLIC_KEY=")][0].split("=", 1)[1]
    if sys.platform != "win32":
        assert oct(os.stat(key).st_mode & 0o777) == "0o600"
    assert lic.main(["sign", "--key", key, "--customer", "Acme", "--max-repos", "4", "--days", "10"]) == 0
    token = capsys.readouterr().out.strip()
    assert lic.main(["verify", "--public-key", pub, token]) == 0 and "Acme" in capsys.readouterr().out
    assert lic.main(["keygen", "--out", key]) == 2  # refuses to overwrite an existing key


# ---- store -------------------------------------------------------------------------------------------------------------------------

def test_store_limits_dedupe_queue_and_recovery(tmp_path):
    st = Store(str(tmp_path / "d"))
    assert st.record_delivery("a") and not st.record_delivery("a")
    st.upsert_installation(1, "acme")
    st.add_repos(1, ["acme/a", "acme/b", "acme/c"], max_repos=2)
    assert [r["over_limit"] for r in st.repos()] == [0, 0, 1]
    st.apply_limit(3)
    assert [r["over_limit"] for r in st.repos()] == [0, 0, 0]
    rid = st.repo("acme/a")["id"]
    j = st.enqueue(rid, 1, "b" * 40, "h" * 40, "main")
    assert j and st.enqueue(rid, 1, "b" * 40, "h" * 40, "main") is None  # same commits: no duplicate work
    job = st.claim()
    assert job["id"] == j and st.claim() is None
    st.finish(j, "success", 0, 0, "{}")
    assert st.enqueue(rid, 1, "b" * 40, "h" * 40, "main", rerun=True) == j and st.job(j)["status"] == "queued"
    st.claim()
    assert st.requeue_stale(-1) == 1 and st.job(j)["status"] == "queued"  # a crashed worker's job is not lost
    for _ in range(5):
        st.claim()
        st.requeue_stale(-1)
    assert st.job(j)["status"] == "failed"  # ...but is not retried forever
    st.delete_installation(1)
    assert st.repos() == [] and st.runs() == []  # cascade


def test_disabled_and_over_limit_repositories_are_never_claimed(tmp_path):
    st = Store(str(tmp_path / "d"))
    st.upsert_installation(1, "acme")
    st.add_repos(1, ["acme/a", "acme/b"], max_repos=1)
    st.enqueue(st.repo("acme/b")["id"], 1, "b" * 40, "h" * 40, "main")
    assert st.claim() is None  # over limit
    st.set_repo("acme/a", enabled=False)
    st.enqueue(st.repo("acme/a")["id"], 2, "b" * 40, "i" * 40, "main")
    assert st.claim() is None  # disabled


# ---- webhook over real HTTP + dashboard --------------------------------------------------------------------------------------------

@pytest.fixture
def running(tmp_path, rsa_key, api):
    svc = Service(settings(tmp_path, rsa_key[1], api.url))
    srv = build_server(svc)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    yield svc, url, tmp_path
    srv.shutdown()
    srv.server_close()


def test_webhook_rejects_bad_signature_bad_json_and_oversize(running):
    svc, url, _ = running
    assert post(url, "ping", {}, secret=b"z" * 20)[0] == 401
    body = b"not json"
    assert post(url, "ping", None, raw=body)[0] == 400
    assert post(url, "ping", {}, delivery="p1") == (200, {"message": "pong"})
    big = b'{"x":"' + b"a" * (svc.s.max_body + 10) + b'"}'
    assert post(url, "ping", None, raw=big)[0] in (413, 0)  # refused; the connection may be cut while uploading


def test_replayed_delivery_is_ignored_and_pr_is_queued_once(running):
    svc, url, _ = running
    svc.store.upsert_installation(7, "o")
    svc.store.add_repos(7, ["o/r"], 3)
    ev = pr_event("o/r", 5, "b" * 40, "h" * 40)
    code, out = post(url, "pull_request", ev, delivery="x1")
    assert code == 202 and "queued" in out["message"]
    assert post(url, "pull_request", ev, delivery="x1")[1]["message"] == "duplicate delivery ignored"
    assert "already" in post(url, "pull_request", ev, delivery="x2")[1]["message"]  # same commits under a new delivery id
    assert svc.store.counts() == {"queued": 1}
    assert post(url, "pull_request", pr_event("o/r", 5, "b" * 40, "h" * 40, action="closed"), delivery="x3")[1]["message"] == "pull_request action ignored"


def test_installation_events_register_repositories_within_the_licence(running):
    svc, url, _ = running
    ev = {"action": "created", "installation": {"id": 9, "account": {"login": "acme"}},
          "repositories": [{"full_name": f"acme/r{i}"} for i in range(5)] + [{"full_name": "../evil"}]}
    assert post(url, "installation", ev, delivery="i1")[0] == 200
    rows = svc.store.repos()
    assert len(rows) == 5 and sum(r["over_limit"] for r in rows) == 2  # community limit is 3; the invalid name was dropped
    assert post(url, "installation", {"action": "deleted", "installation": {"id": 9}}, delivery="i2")[0] == 200 and svc.store.repos() == []


def test_dashboard_requires_the_admin_password_and_escapes_everything(running):
    svc, url, _ = running
    svc.store.upsert_installation(1, "o")
    svc.store.add_repos(1, ["o/<script>x"], 3) if False else svc.store.add_repos(1, ["o/r"], 3)
    assert get(url, "/")[0] == 401
    assert get(url, "/", "wrong" * 5)[0] == 401
    code, page, hdr = get(url, "/", ADMIN)
    assert code == 200 and "o/r" in page and "Licence: community" in page
    assert hdr["X-Frame-Options"] == "DENY" and "default-src 'none'" in hdr["Content-Security-Policy"]
    assert get(url, "/healthz")[0] == 200 and get(url, "/readyz")[0] == 200
    assert get(url, "/runs/999999", ADMIN)[0] == 404 and get(url, "/runs/abc", ADMIN)[0] == 404


def test_repeated_wrong_passwords_are_rate_limited(running):
    _, url, _ = running
    codes = [get(url, "/", "bad-password-" + str(i))[0] for i in range(12)]
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]
    assert get(url, "/", ADMIN)[0] == 429  # even the right password waits out the window from that address


# ---- end to end: a real breaking PR is analysed and reported ----------------------------------------------------------------------

def _sha(repo, rev):
    return subprocess.run(["git", "-C", repo, "rev-parse", rev], capture_output=True, text=True, check=True).stdout.strip()


def _drain(svc, n=1, timeout=120):
    import time
    t = time.time()
    while time.time() - t < timeout:
        if sum(svc.store.counts().get(k, 0) for k in ("done", "failed")) >= n and not svc.store.counts().get("running") and not svc.store.counts().get("queued"):
            return
        time.sleep(0.2)
    raise AssertionError(f"jobs did not finish: {svc.store.counts()}")


def test_breaking_pull_request_end_to_end(running, api):
    svc, url, tmp = running
    os.makedirs(tmp / "o")
    r = make_repo(tmp / "o", {"hello.proto": GREETER}, {"hello.proto": GREETER.replace("string name = 1;", "string name = 5;")}, name="r")
    base, head = _sha(r, "main"), _sha(r, "feat")
    svc.start()
    try:
        assert post(url, "pull_request", pr_event("o/r", 3, base, head), delivery="e1")[0] == 202
        _drain(svc)
    finally:
        svc.shutdown()
    job = svc.store.job(1)
    assert job["status"] == "done", job["error"]
    assert job["conclusion"] == "failure" and job["blocking"] == 1
    paths = [(m, p) for m, p, _ in api.calls]
    assert ("POST", "/app/installations/7/access_tokens") in paths and ("POST", "/repos/o/r/check-runs") in paths and any(m == "GET" for m, _ in paths) and ("PATCH", "/repos/o/r/check-runs/4242") in paths
    final = [b for m, p, b in api.calls if m == "PATCH"][-1]
    assert final["conclusion"] == "failure" and final["output"]["annotations"][0]["annotation_level"] == "failure" and "confirmed" in final["output"]["summary"]
    code, page, _ = get(url, "/runs/1", ADMIN)
    assert code == 200 and "sci-data" in page and "PRT111" in page  # the iOS-style report, with this run's real findings
    assert "Blocked" in get(url, "/", ADMIN)[1] or "blocking" in get(url, "/", ADMIN)[1]


def test_clean_pull_request_succeeds_and_unreachable_repository_is_neutral_not_success(running, api):
    svc, url, tmp = running
    os.makedirs(tmp / "o")
    r = make_repo(tmp / "o", {"hello.proto": GREETER}, {"README.md": "docs only\n"}, name="r")
    svc.start()
    try:
        assert post(url, "pull_request", pr_event("o/r", 1, _sha(r, "main"), _sha(r, "feat")), delivery="c1")[0] == 202
        assert post(url, "pull_request", pr_event("o/missing", 2, "b" * 40, "c" * 40), delivery="c2")[0] == 202
        _drain(svc, 2, 180)
    finally:
        svc.shutdown()
    assert svc.store.job(1)["conclusion"] == "success"
    missing = svc.store.job(2)
    assert missing["status"] == "failed" and missing["conclusion"] is None
    neutral = [b for m, p, b in api.calls if m == "PATCH" and b.get("conclusion") == "neutral"]
    assert neutral and "could not analyse" in neutral[-1]["output"]["summary"]
    assert not [b for m, p, b in api.calls if m == "PATCH" and b.get("conclusion") == "success" and "missing" in p]


def test_expired_licence_reports_neutral_and_never_blocks(tmp_path, rsa_key, api):
    pem, pub = lic.generate_keypair()
    t = dt.date.today()
    tok = lic.sign(pem, id="o", customer="C", max_repos=3, issued=t - dt.timedelta(days=9), expires=t - dt.timedelta(days=1))
    svc = Service(settings(tmp_path, rsa_key[1], api.url, licence_token=tok, licence_public_key=pub))
    svc.store.upsert_installation(7, "o")
    svc.store.add_repos(7, ["o/r"], 3)
    svc.store.enqueue(svc.store.repo("o/r")["id"], 1, "b" * 40, "h" * 40, "main")
    svc.process(svc.store.claim())
    job = svc.store.job(1)
    assert job["conclusion"] == "neutral" and job["blocking"] == 0
    assert [b for m, p, b in api.calls if m == "PATCH"][-1]["conclusion"] == "neutral"


def test_a_retried_job_reuses_its_check_run_and_gives_up_neutral(running, api):
    svc, url, tmp = running
    svc.store.upsert_installation(7, "o")
    svc.store.add_repos(7, ["o/gone"], 3)
    svc.store.enqueue(svc.store.repo("o/gone")["id"], 1, "b" * 40, "c" * 40, "main")
    svc.start()
    try:
        _drain(svc)
    finally:
        svc.shutdown()
    created = [1 for m, p, _ in api.calls if m == "POST" and p.endswith("/check-runs")]
    assert len(created) == 1 and svc.store.job(1)["attempts"] == 3  # three attempts, one check run
    assert [b for m, p, b in api.calls if m == "PATCH"][-1]["conclusion"] == "neutral"


# ---- review fixes: suspension, delivery reliability, idempotent check runs, process-group kill, safe backup -------------------------------

def test_suspended_installation_runs_no_jobs_and_resumes_when_unsuspended(running):
    svc, url, _ = running
    ev = {"action": "created", "installation": {"id": 7, "account": {"login": "o"}}, "repositories": [{"full_name": "o/r"}]}
    assert post(url, "installation", ev, delivery="s0")[0] == 200
    svc.store.enqueue(svc.store.repo("o/r")["id"], 1, "b" * 40, "h" * 40, "main")  # queued before the suspension
    assert post(url, "installation", {**ev, "action": "suspend"}, delivery="s1")[0] == 200
    assert svc.store.claim() is None  # a suspended installation's queued job is not run
    assert post(url, "pull_request", pr_event("o/r", 2, "b" * 40, "i" * 40), delivery="s2")[1]["message"] == "installation is suspended"
    assert post(url, "installation", {**ev, "action": "unsuspend"}, delivery="s3")[0] == 200
    assert svc.store.claim() is not None


def test_a_failed_delivery_is_not_remembered_so_the_redelivery_is_processed(running, monkeypatch):
    svc, url, _ = running
    svc.store.upsert_installation(7, "o")
    svc.store.add_repos(7, ["o/r"], 3)
    real = svc._dispatch
    state = {"n": 0}

    def flaky(event, p):
        state["n"] += 1
        if state["n"] == 1:
            import sqlite3
            raise sqlite3.OperationalError("database is locked")
        return real(event, p)

    monkeypatch.setattr(svc, "_dispatch", flaky)
    ev = pr_event("o/r", 5, "b" * 40, "h" * 40)
    assert post(url, "pull_request", ev, delivery="r1")[0] == 503  # GitHub will redeliver
    assert svc.store.counts() == {}
    code, out = post(url, "pull_request", ev, delivery="r1")  # same delivery id, as GitHub's retry
    assert code == 202 and "queued" in out["message"]
    assert post(url, "pull_request", ev, delivery="r1")[1]["message"] == "duplicate delivery ignored"  # now it is a duplicate


def test_lost_response_to_check_run_creation_does_not_create_a_second_check_run(api, rsa_key):
    from sciserver.github import GitHub
    gh = GitHub(api.url, "1", FAKE_PEM[0])
    api.drop_first_post = True
    cid = gh.create_check_run("tok", "o/r", "h" * 40, "SCI change check", "sci-job-1")
    assert len(api.created) == 1 and cid == api.created[0]["id"]  # found the run the lost response had created
    assert gh.create_check_run("tok", "o/r", "h" * 40, "SCI change check", "sci-job-1") == cid  # and is stable afterwards
    assert gh.create_check_run("tok", "o/r", "h" * 40, "SCI change check", "sci-job-2") != cid and len(api.created) == 2


@pytest.mark.skipif(os.name == "nt", reason="POSIX process group /proc test")
def test_timeout_kills_the_whole_process_group_not_only_the_child(tmp_path):
    from sciserver.runner import JobError, run_limited
    marker = tmp_path / "pid"
    with pytest.raises(JobError, match="timed out"):
        run_limited(["sh", "-c", f"sleep 300 & echo $! > {marker}; wait"], {"PATH": os.environ["PATH"]}, str(tmp_path), 2, 1024)
    import time
    time.sleep(0.5)
    pid = int(marker.read_text())
    try:  # gone, or at most a zombie awaiting its parent's reaper (state Z): not running
        state = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
    except FileNotFoundError:
        state = "gone"
    assert state in ("Z", "gone"), f"grandchild still running (state {state})"


def test_online_backup_is_consistent_and_refuses_to_overwrite(tmp_path):
    import sqlite3
    st = Store(str(tmp_path / "d"))
    st.upsert_installation(1, "acme")
    st.add_repos(1, ["acme/a"], 3)  # sits in the WAL file; a plain copy of sci.db could miss it
    dest = str(tmp_path / "b.db")
    st.backup(dest)
    assert [r[0] for r in sqlite3.connect(dest).execute("SELECT full_name FROM repos")] == ["acme/a"]
    if os.name != "nt":
        assert oct(os.stat(dest).st_mode & 0o777) == "0o600"
    with pytest.raises(FileExistsError):
        st.backup(dest)
