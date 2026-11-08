"""SCI: API-contract check. Repositories are real git repositories; the access log in tests/data was written by a real HTTP server
(a Python http.server handling real curl requests); there are no mocks."""
import json
import os
import subprocess
import textwrap

import pytest

from dci.config import Config, ConfigError
from sci import accesslog, callers, oas
from sci.cli import main as sci_main
from sci.run import run_checks

LOG = os.path.join(os.path.dirname(__file__), "data", "access_real_http_server.log")

SPEC = textwrap.dedent("""\
    openapi: 3.0.3
    info: {title: t, version: "1"}
    servers: [{url: https://api.example.com/v1}]
    paths:
      /users/{id}:
        get:
          parameters: [{name: id, in: path, required: true, schema: {type: string}}]
          responses:
            "200": {description: ok, content: {application/json: {schema: {$ref: '#/components/schemas/User'}}}}
        delete:
          parameters: [{name: id, in: path, required: true, schema: {type: string}}]
          responses: {"204": {description: gone}}
      /orders:
        post:
          requestBody: {required: true, content: {application/json: {schema: {$ref: '#/components/schemas/NewOrder'}}}}
          responses: {"201": {description: created}}
    components:
      schemas:
        User: {type: object, required: [id, email], properties: {id: {type: string}, email: {type: string}}}
        NewOrder: {type: object, required: [sku], properties: {sku: {type: string}, qty: {type: integer}}}
    """)
SPEC_NEW = (SPEC.replace("""    delete:
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"204": {description: gone}}
""", "").replace("required: [id, email]", "required: [id]").replace("required: [sku]", "required: [sku, currency]")
            .replace("qty: {type: integer}", "qty: {type: integer}, currency: {type: string}"))


def _git(r, *a):
    subprocess.run(["git", "-C", r, *a], check=True, capture_output=True)


def make_repo(tmp_path, files: dict, new_files: dict, name="repo") -> str:
    r = str(tmp_path / name)
    os.makedirs(r)
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "a@b")
    _git(r, "config", "user.name", "t")
    for rel, text in files.items():
        os.makedirs(os.path.dirname(os.path.join(r, rel)) or r, exist_ok=True)
        open(os.path.join(r, rel), "w").write(text)
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    _git(r, "checkout", "-qb", "feat")
    for rel, text in new_files.items():
        os.makedirs(os.path.dirname(os.path.join(r, rel)) or r, exist_ok=True)
        open(os.path.join(r, rel), "w").write(text)
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "change")
    return r


CODE = {
    "svc/cleanup.py": 'import requests\nBASE = "https://api.example.com/v1"\ndef remove(uid):\n    requests.delete(f"{BASE}/users/{uid}")\n',
    "web/api.ts": 'export const rm = (id: string) => fetch(`/v1/users/${id}`, { method: "DELETE" });\nexport const get = (id: string) => fetch(`/v1/users/${id}`);\n',
    "tools/purge.go": 'package tools\nfunc P(id string) { r, _ := http.NewRequest("DELETE", "https://api.example.com/v1/users/"+id, nil); _ = r }\n',
    "svc/server.py": '@app.route("/users/<id>", methods=["DELETE"])\ndef d(id): ...\n@app.delete("/v1/users/{id}")\ndef d2(id): ...\n',
    "tests/test_users.py": 'def test_delete(client):\n    client.delete("/users/1")\n',
}


def _cfg(repo, **kw):
    c = Config(repo=repo)
    c.base = "main"
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def by_rule(rep):
    d = {}
    for f in rep.findings:
        d.setdefault(f.rule_id, []).append(f)
    return d


# ---------------------------------------------------------------- end to end

def test_removed_endpoint_confirmed_from_python_ts_and_go_and_servers_are_ignored(tmp_path):
    r = make_repo(tmp_path, {"openapi.yaml": SPEC, **CODE}, {"openapi.yaml": SPEC_NEW})
    rep = run_checks(_cfg(r), ["api"])
    f = by_rule(rep)
    api101 = f["API101"][0]
    assert api101.confidence.value == "confirmed" and api101.severity.value == "error"
    assert {e.file for e in api101.evidence} == {"svc/cleanup.py", "web/api.ts"}
    assert [e.file for e in f["API102"][0].evidence] == ["tests/test_users.py"]
    assert [e.file for e in f["API103"][0].evidence] == ["tools/purge.go"]  # concatenation: method visible, full path is not
    assert all(e.file != "svc/server.py" for x in rep.findings for e in x.evidence)  # route definitions implement, not call
    assert rep.blocking() and rep.title == "SCI change check"


def test_fetch_without_method_is_a_get_not_a_delete(tmp_path):
    r = make_repo(tmp_path, {"openapi.yaml": SPEC, "web/api.ts": CODE["web/api.ts"]}, {"openapi.yaml": SPEC_NEW})
    rep = run_checks(_cfg(r), ["api"])
    lines = {(e.file, e.line) for x in rep.findings if x.rule_id in ("API101", "API103") for e in x.evidence}
    assert lines == {("web/api.ts", 1)}


def test_contract_changes_are_possible_never_confirmed_and_never_block(tmp_path):
    only_changes = SPEC.replace("""    delete:
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"204": {description: gone}}
""", "    delete:\n      parameters: [{name: id, in: path, required: true, schema: {type: string}}]\n      responses: {\"204\": {description: gone}}\n")
    new = only_changes.replace("required: [sku]", "required: [sku, currency]").replace("qty: {type: integer}", "qty: {type: integer}, currency: {type: string}")
    r = make_repo(tmp_path, {"openapi.yaml": only_changes, **CODE}, {"openapi.yaml": new})
    rep = run_checks(_cfg(r), ["api"])
    assert [f.rule_id for f in rep.findings] == ["API113"]
    assert rep.findings[0].confidence.value == "possible" and not rep.blocking()


def test_no_spec_change_no_findings(tmp_path):
    r = make_repo(tmp_path, {"openapi.yaml": SPEC, "a.py": "x=1\n"}, {"a.py": "x=2\n"})
    rep = run_checks(_cfg(r), ["api"])
    assert rep.findings == [] and not rep.blocking()


def test_unparseable_spec_is_reported_not_silently_passed(tmp_path):
    r = make_repo(tmp_path, {"openapi.yaml": SPEC}, {"openapi.yaml": "openapi: 3.0.0\npaths: [unclosed\n"})
    rep = run_checks(_cfg(r), ["api"])
    assert [f.rule_id for f in rep.findings] == ["API902"] and rep.findings[0].confidence.value == "unknown"


def test_access_log_alone_is_possible_and_blocks_only_when_declared_current(tmp_path):
    r = make_repo(tmp_path, {"openapi.yaml": SPEC}, {"openapi.yaml": SPEC_NEW})
    rep = run_checks(_cfg(r, api_access_logs=[LOG]), ["api"])
    f = by_rule(rep)
    assert "API101" not in f and f["API103"][0].evidence[0].via == "access_log" and not rep.blocking()
    rep2 = run_checks(_cfg(r, api_access_logs=[LOG], runtime_blocks=True), ["api"])
    assert by_rule(rep2)["API101"][0].confidence.value == "confirmed" and rep2.blocking()


def test_removed_endpoint_with_no_evidence_says_so(tmp_path):
    r = make_repo(tmp_path, {"openapi.yaml": SPEC}, {"openapi.yaml": SPEC_NEW})
    f = by_rule(run_checks(_cfg(r), ["api"]))
    assert f["API105"][0].confidence.value == "unknown" and f["API105"][0].severity.value == "info"


def test_cli_exit_codes_and_combined_db_and_api(tmp_path, capsys):
    files = {"openapi.yaml": SPEC, **CODE, "migrations/001.sql": "CREATE TABLE t(id int);\n"}
    r = make_repo(tmp_path, files, {"openapi.yaml": SPEC_NEW, "migrations/002.sql": "ALTER TABLE t DROP COLUMN id;\n"})
    assert sci_main(["--repo", r, "--base", "main", "--format", "json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    ids = {f["rule_id"] for f in doc["findings"]}
    assert "API101" in ids and any(i.startswith("DCI") for i in ids) and doc["title"] == "SCI change check"
    assert sci_main(["--repo", r, "--base", "main", "--checks", "db", "--format", "json"]) == 0
    assert sci_main(["--repo", r, "--base", "main", "--checks", "bogus"]) == 2
    assert sci_main(["--repo", r, "--checks", "api"]) == 2  # no --base
    assert sci_main(["--version"]) == 0


def test_ignore_rule_and_workspace_are_honoured(tmp_path):
    r = make_repo(tmp_path, {"openapi.yaml": SPEC, **CODE}, {"openapi.yaml": SPEC_NEW})
    rep = run_checks(_cfg(r, ignore_rules=["API101"]), ["api"])
    assert "API101" not in by_rule(rep)
    with pytest.raises(ConfigError):
        run_checks(_cfg(r, workspace=str(tmp_path / "elsewhere")), ["api"])


# ---------------------------------------------------------------- spec parsing and diff

def test_yaml_alias_bomb_is_rejected_quickly():
    lines = ["openapi: 3.0.0", "x0: &a0 [a, a, a, a, a, a, a, a, a, a]"]
    for i in range(1, 12):
        lines.append(f"x{i}: &a{i} [" + ", ".join([f"*a{i-1}"] * 10) + "]")
    with pytest.raises(oas.SpecError):
        oas.parse_spec("\n".join(lines))


def test_multidoc_and_non_objects_are_rejected():
    for text in ("openapi: 3.0.0\n---\nopenapi: 3.0.0\n", "- a\n- b\n", "openapi: 4.0.0\n"):
        with pytest.raises(oas.SpecError):
            oas.parse_spec(text)


def test_json_specs_integer_status_keys_and_remote_refs_are_safe():
    spec = oas.parse_spec("""openapi: 3.0.0
paths:
  /a:
    get:
      responses:
        200: {content: {application/json: {schema: {$ref: 'http://evil.invalid/x.json#/S'}}}}
""")
    assert "200" in spec["paths"]["/a"]["get"]["responses"]
    changes, notes = oas.diff(spec, spec)
    assert changes == [] and any("could not be resolved" in n for n in notes)  # never fetched
    assert oas.parse_spec(json.dumps({"openapi": "3.1.0", "paths": {}}))["openapi"] == "3.1.0"


def _d(base, head):
    return {(c.rule, c.method) for c in oas.diff(oas.parse_spec(base), oas.parse_spec(head))[0]}


def _spec(schema_resp="{type: object, properties: {a: {type: string}}}", params="[]", body=""):
    return f"openapi: 3.0.0\npaths:\n  /x/{{id}}:\n    post:\n      parameters: {params}\n{body}      responses:\n        '200': {{content: {{application/json: {{schema: {schema_resp}}}}}}}\n"


def test_diff_rules():
    p = "{name: id, in: path, required: true, schema: {type: string}}"
    base = _spec(params=f"[{p}]")
    assert _d(base, _spec(params=f"[{p.replace('name: id', 'name: other')}]")) == set()  # renaming a path variable is not a change
    assert _d(base, _spec(params=f"[{p}, {{name: q, in: query, required: true, schema: {{type: string}}}}]")) == {("API111", "post")}
    assert _d(base, _spec(params=f"[{p}, {{name: q, in: query, schema: {{type: string}}}}]")) == set()  # optional new parameter is fine
    assert _d(base, _spec(schema_resp="{type: object, properties: {a: {type: integer}}}", params=f"[{p}]")) == {("API122", "post")}
    assert _d(base, _spec(schema_resp="{type: object}", params=f"[{p}]")) == {("API121", "post")}
    assert _d(base, _spec(schema_resp="{type: object, properties: {a: {type: string}, b: {type: string}}}", params=f"[{p}]")) == set()  # added response property is fine
    # allOf, readOnly and unions
    allof = "{allOf: [{type: object, required: [a], properties: {a: {type: string}}}, {properties: {b: {type: integer}}}]}"
    assert _d(_spec(allof, f"[{p}]"), _spec("{type: object, properties: {a: {type: string}}}", f"[{p}]")) == {("API121", "post"), ("API123", "post")}
    union = "{oneOf: [{type: string}, {type: integer}]}"
    assert _d(_spec(union, f"[{p}]"), _spec("{type: string}", f"[{p}]")) == set()  # unions are not compared (no guessing)


def test_request_enum_narrowing_and_required_body():
    p = "{name: id, in: path, required: true, schema: {type: string}}"
    b1 = "      requestBody: {required: false, content: {application/json: {schema: {type: object, properties: {k: {type: string, enum: [a, b]}}}}}}\n"
    b2 = "      requestBody: {required: true, content: {application/json: {schema: {type: object, properties: {k: {type: string, enum: [a]}}}}}}\n"
    assert _d(_spec(params=f"[{p}]", body=b1), _spec(params=f"[{p}]", body=b2)) == {("API112", "post"), ("API115", "post")}


def test_cyclic_refs_terminate():
    s = """openapi: 3.0.0
paths:
  /n:
    get:
      responses: {'200': {content: {application/json: {schema: {$ref: '#/components/schemas/N'}}}}}
components:
  schemas:
    N: {type: object, properties: {child: {$ref: '#/components/schemas/N'}, v: {type: string}}}
"""
    assert oas.diff(oas.parse_spec(s), oas.parse_spec(s.replace("v: {type: string}", "v: {type: integer}")))[0][0].rule == "API122"


# ---------------------------------------------------------------- caller matching

def _m(*ops, prefixes=()):
    return callers.build_matchers(list(ops), list(prefixes))


@pytest.mark.parametrize("line,expected", [
    ('requests.delete(f"{BASE}/users/{uid}")', "confirmed"),
    ("axios.delete(`/users/${id}`)", "confirmed"),
    ('curl -X DELETE https://h.example/users/5', "confirmed"),
    ("http.NewRequest(\"DELETE\", \"/users/7\", nil)", "confirmed"),
    ('url = "/users/" + uid', "possible"),
    ('x = "/users/5"', "possible"),
    ('requests.get("/users/5")', None),  # a GET is not a DELETE
    ('requests.delete("/users")', None),  # the collection is another endpoint
    ('requests.delete("/users/5/orders")', None),
    ('log("/users/{id} not found")', "possible"),
])
def test_match_line(line, expected):
    hits = callers.match_line(line, "", _m(("delete", "/users/{id}")))
    assert (hits[0][1].value if hits else None) == expected


def test_multiline_call_takes_method_from_the_opening_line_and_server_prefix_is_optional():
    ms = _m(("delete", "/users/{id}"), prefixes=["/v1"])
    assert callers.match_line('    "/v1/users/3",', "requests.delete(", ms)[0][1].value == "confirmed"
    assert callers.match_line('    "/users/3",', "requests.delete(", ms)[0][1].value == "confirmed"
    assert callers.match_line('"/v2/users/3"', "requests.delete(", ms) == []


def test_definitions_are_recognised():
    for ln in ('@app.route("/users/<id>")', '@router.delete("/users/{id}")', 'app.delete("/users/:id", h)', '@DeleteMapping("/users/{id}")',
               'path("users/<int:id>/", view)', 'mux.HandleFunc("/users/", h)'):
        assert callers.is_definition(ln), ln
    assert not callers.is_definition('requests.delete("/users/5")')
    assert not callers.is_definition('client.get("/users/5")')


def test_redos_resistant_on_hostile_lines():
    import time
    ms = _m(("get", "/a/{b}/c"))
    t = time.time()
    callers.match_line('"' + "/a" * 150 + "\\" * 5000, "", ms)
    callers.match_line("'" + "{" * 4000 + "/a/b/c", "", ms)
    callers.match_line("`" + "${" * 2000, "", ms)
    assert time.time() - t < 2


# ---------------------------------------------------------------- access logs

def test_real_server_log_is_read_and_error_only_endpoints_are_ignored():
    hits, rows = accesslog.load(LOG)
    assert rows == 5 and {(h.method, h.ok > 0) for h in hits} >= {("delete", True), ("get", True), ("post", False)}
    refs, _, _ = accesslog.references(LOG, _m(("post", "/orders/old")), False)
    assert refs[("post", "/orders/old")] == []  # only ever answered 404


def test_json_csv_and_bad_logs(tmp_path):
    (tmp_path / "a.jsonl").write_text('{"method":"DELETE","path":"/v1/users/4?x=1","count":9,"status":204}\n')
    (tmp_path / "b.csv").write_text("method,path,count\nDELETE,/v1/users/4,3\n")
    (tmp_path / "c.json").write_text('[{"method":"GET","url":"https://h/v1/users/4"}]')
    for n in ("a.jsonl", "b.csv", "c.json"):
        hits, rows = accesslog.load(str(tmp_path / n))
        assert rows == 1 and hits[0].path.startswith("/v1/users/4")
    assert accesslog.load(str(tmp_path / "a.jsonl"))[0][0].count == 9
    for bad in ("hello world\n", "", "{not json\n", "method,x\nGET,/a\n"):
        (tmp_path / "bad.log").write_text(bad)
        with pytest.raises(ConfigError):
            accesslog.load(str(tmp_path / "bad.log"))
    with pytest.raises(ConfigError):
        accesslog.load(str(tmp_path / "missing.log"))


def test_log_limits_and_bounded_distinct_paths(tmp_path, monkeypatch):
    p = tmp_path / "many.jsonl"
    p.write_text("\n".join(json.dumps({"method": "GET", "path": f"/p{i}"}) for i in range(50)) + "\n")
    monkeypatch.setattr(accesslog, "MAX_DISTINCT", 10)
    assert len(accesslog.load(str(p))[0]) == 10
    monkeypatch.setattr(accesslog, "MAX_ROWS", 5)
    with pytest.raises(ConfigError):
        accesslog.load(str(p))
    monkeypatch.setattr(accesslog, "MAX_BYTES", 10)
    with pytest.raises(ConfigError):
        accesslog.load(str(p))


# ---------------------------------------------------------------- GitHub Action (real git, shallow checkout like actions/checkout)

from test_action import github, make_origin, run_action  # noqa: E402,F401  (fixture import)


def test_action_runs_api_check_annotates_the_spec_and_fails_on_confirmed_removal(tmp_path, github, caplog):
    ws = make_origin(tmp_path, {"openapi.yaml": SPEC_NEW}, base_files={"openapi.yaml": SPEC, **CODE})
    log = tmp_path / "ws" / "access.log"
    log.write_text(open(LOG).read())
    p, outputs, summary = run_action(ws, tmp_path, github, extra_env={"INPUT_CHECKS": "db,api", "INPUT_API_ACCESS_LOGS": "access.log"})
    assert p.returncode == 1, p.stdout + p.stderr
    assert "::error file=openapi.yaml,line=" in p.stdout and "title=API101" in p.stdout
    assert outputs["verdict"] == "fail"
    text = summary.read_text()
    assert "SCI change check" in text and "API101" in text and "access.log" in text
    sarif = json.load(open(outputs["sarif-path"]))
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "sci"


def test_action_api_logs_must_be_inside_the_workspace(tmp_path, github):
    ws = make_origin(tmp_path, {"openapi.yaml": SPEC_NEW}, base_files={"openapi.yaml": SPEC})
    p, _, _ = run_action(ws, tmp_path, github, extra_env={"INPUT_CHECKS": "api", "INPUT_API_ACCESS_LOGS": "../../etc/passwd"})
    assert p.returncode == 2 and "inside the workspace" in (p.stdout + p.stderr)


def test_action_default_is_still_db_only(tmp_path, github):
    ws = make_origin(tmp_path, {"openapi.yaml": SPEC_NEW}, base_files={"openapi.yaml": SPEC, **CODE})
    p, _, _ = run_action(ws, tmp_path, github)
    assert p.returncode == 0 and "API101" not in p.stdout


def test_hit_flood_keeps_memory_flat_but_counts_everything(tmp_path):
    from collections import Counter

    from dci.models import Coverage
    from dci.sources import FsTree, Matcher
    root = tmp_path / "hot"
    root.mkdir()
    for f in range(4):
        (root / f"f{f}.py").write_text("".join(f'client.delete("/users/{i}")\n' for i in range(400)))
    ms = callers.build_matchers([("delete", "/users/{id}")], [])
    found = callers.scan_tree(FsTree(str(root), "head"), ms, "head", Matcher([]), Matcher([]), Coverage())
    key = ("delete", "/users/{id}")
    assert len(found.refs[key]) == callers.KEEP_PER_CATEGORY and sum(found.totals.values()) == 1600
    assert found.total(key, found.refs[key]) == 1600
    assert found.refs[key][0].file == "f0.py" and found.refs[key][0].line == 1  # deterministic: first hits in file order
    assert isinstance(found.totals, Counter)


def test_ai_does_not_send_non_database_findings(tmp_path):
    from dci import ai as ai_mod
    r = make_repo(tmp_path, {"openapi.yaml": SPEC, **CODE}, {"openapi.yaml": SPEC_NEW})
    rep = run_checks(_cfg(r), ["api"])
    cfg = ai_mod.AiConfig(api_key="k", model="m", max_findings=5, base_url="https://127.0.0.1:9")
    assert ai_mod.enhance(rep, {"head": r}, cfg) == 0 and all(f.ai is None for f in rep.findings)


# ---------------------------------------------------------------- lessons from replaying real repositories (petstore, museum, Stripe)

def _resp_spec(responses: str) -> str:
    return f"openapi: 3.0.0\npaths:\n  /p:\n    get:\n      responses:\n{responses}"


def test_default_response_redefined_as_error_is_not_a_contract_break():
    """swagger-petstore commit 39b7b5f: `default` described the success body, then became the error body, next to an unchanged 200."""
    ok = "        '200': {content: {application/json: {schema: {type: object, properties: {id: {type: integer}}}}}}\n"
    old = _resp_spec(ok + "        default: {content: {application/json: {schema: {type: object, properties: {id: {type: integer}}}}}}\n")
    new = _resp_spec(ok + "        default: {content: {application/json: {schema: {type: object, properties: {message: {type: string}}}}}}\n")
    assert oas.diff(oas.parse_spec(old), oas.parse_spec(new))[0] == []


def test_default_used_as_success_is_compared_with_the_new_explicit_success():
    body = "{content: {application/json: {schema: {type: object, properties: {id: {type: integer}}}}}}"
    old = _resp_spec(f"        default: {body}\n")
    same = _resp_spec(f"        '200': {body}\n")
    changed = _resp_spec("        '200': {content: {application/json: {schema: {type: object, properties: {id: {type: string}}}}}}\n")
    assert oas.diff(oas.parse_spec(old), oas.parse_spec(same))[0] == []
    assert [c.rule for c in oas.diff(oas.parse_spec(old), oas.parse_spec(changed))[0]] == ["API122"]


def test_success_status_code_change_is_explained():
    old = _resp_spec("        '200': {description: ok}\n")
    new = _resp_spec("        '201': {description: created}\n")
    (c,), _ = oas.diff(oas.parse_spec(old), oas.parse_spec(new))
    assert c.rule == "API116" and "replaced by 201" in c.detail


def test_specs_larger_than_the_source_file_limit_are_still_compared(tmp_path):
    """Stripe's spec is 8 MB; the per-file source limit (2 MB) must not apply to specifications."""
    props = ",".join(f'"p{i}":{{"type":"string","description":"{"x" * 60}"}}' for i in range(30000))
    def spec(extra):
        return ('{"openapi":"3.0.0","paths":{"/big":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":'
                '{"type":"object","properties":{' + props + extra + '}}}}}}}}}}')
    old, new = spec(""), spec("")
    assert len(old) > 2_000_000
    new = new.replace('"p0":{"type":"string"', '"p0":{"type":"integer"', 1)
    r = make_repo(tmp_path, {"openapi.json": old}, {"openapi.json": new})
    rep = run_checks(_cfg(r), ["api"])
    assert [f.rule_id for f in rep.findings] == ["API122"], [(f.rule_id, f.message[:120]) for f in rep.findings]


def test_same_change_on_many_endpoints_is_one_finding_and_info_is_merged(tmp_path):
    shared = "{type: object, properties: {state: {type: string, enum: [a, b]}}}"
    shared_new = "{type: object, properties: {state: {type: string, enum: [a, b, c]}}}"
    def spec(schema, n=6):
        paths = "".join(f"  /r{i}:\n    get:\n      responses:\n        '200': {{content: {{application/json: {{schema: {schema}}}}}}}\n" for i in range(n))
        return f"openapi: 3.0.0\npaths:\n{paths}"
    r = make_repo(tmp_path, {"openapi.yaml": spec(shared)}, {"openapi.yaml": spec(shared_new)})
    rep = run_checks(_cfg(r), ["api"])
    assert len(rep.findings) == 1 and "6 endpoints are affected" in rep.findings[0].message and rep.findings[0].severity.value == "info"


def test_method_given_as_a_quoted_argument_on_the_previous_line():
    """Real stripe-python code: `cls._static_request(\\n "delete",\\n "/v1/customers/{customer}/sources/{id}".format(...)`."""
    ms = _m(("delete", "/v1/customers/{customer}/sources/{id}"), ("get", "/v1/customers/{customer}/sources/{id}"))
    hits = callers.match_line('                "/v1/customers/{customer}/sources/{id}".format(', '                "delete",', ms)
    assert [(h[0].method, h[1].value) for h in hits] == [("delete", "confirmed")]
    assert callers.match_line('_request("get", "/v1/customers/{customer}/sources/{id}")', "", ms)[0][0].method == "get"


# ---------------------------------------------------------------- Swagger 2.0 (tests/data/swagger2_petstore_expanded.json is the official OAI example)

SW2 = os.path.join(os.path.dirname(__file__), "data", "swagger2_petstore_expanded.json")


def _sw2():
    return json.load(open(SW2))


def test_real_swagger2_example_parses_and_identical_specs_have_no_changes():
    spec = oas.parse_spec(open(SW2).read())
    ops = oas.extract(spec)
    assert sorted(ops) == [("delete", "/pets/{id}"), ("get", "/pets"), ("get", "/pets/{id}"), ("post", "/pets")]
    assert oas.server_prefixes(spec) == ["/api"]
    assert oas.diff(spec, spec)[0] == []
    post = ops[("post", "/pets")]
    assert post.request_required["application/json"] is True and post.request["application/json"]["name"].required


def test_swagger2_breaking_changes_are_found():
    base, head = _sw2(), _sw2()
    del head["paths"]["/pets/{id}"]["delete"]
    head["definitions"]["NewPet"]["required"].append("tag")                       # request property now required
    head["definitions"]["Pet"]["allOf"][1]["properties"]["id"]["type"] = "string"  # response type change (through allOf + $ref)
    head["paths"]["/pets"]["get"]["parameters"].append({"name": "owner", "in": "query", "required": True, "type": "string"})
    got = {(c.rule, c.method, c.path) for c in oas.diff(oas.parse_spec(json.dumps(base)), oas.parse_spec(json.dumps(head)))[0]}
    assert ("API101", "delete", "/pets/{id}") in got
    assert ("API113", "post", "/pets") in got
    assert ("API111", "get", "/pets") in got
    assert any(r == "API122" and p == "/pets/{id}" for r, _, p in got)


def test_swagger2_path_variable_rename_global_parameters_and_formdata():
    sw = {"swagger": "2.0", "basePath": "/v1", "consumes": ["application/json"], "produces": ["application/json"],
          "parameters": {"Lim": {"name": "limit", "in": "query", "required": False, "type": "integer"}},
          "responses": {"Gone": {"description": "gone", "schema": {"type": "object", "properties": {"why": {"type": "string"}}}}},
          "paths": {"/u/{id}": {"get": {"parameters": [{"$ref": "#/parameters/Lim"}, {"name": "id", "in": "path", "required": True, "type": "string"}],
                                        "responses": {"410": {"$ref": "#/responses/Gone"}}},
                                "post": {"consumes": ["multipart/form-data"],
                                         "parameters": [{"name": "id", "in": "path", "required": True, "type": "string"},
                                                        {"name": "file", "in": "formData", "type": "file"}],
                                         "responses": {"200": {"description": "ok"}}}}}}
    head = json.loads(json.dumps(sw))
    head["paths"]["/u/{userId}"] = head["paths"].pop("/u/{id}")
    for op in head["paths"]["/u/{userId}"].values():
        op["parameters"][-1 if op["parameters"][-1].get("in") == "path" else 0]["name"] = "userId" if op["parameters"][-1].get("in") == "path" else op["parameters"][0]["name"]
    a, b = oas.parse_spec(json.dumps(sw)), oas.parse_spec(json.dumps(head))
    assert oas.diff(a, b)[0] == []  # renaming a path variable is not a change
    ops = oas.extract(a)
    assert ops[("get", "/u/{id}")].responses["410"]["application/json"]["why"].type == "string"
    assert "multipart/form-data" in ops[("post", "/u/{id}")].request
    head["paths"]["/u/{userId}"]["get"]["parameters"][0] = {"name": "limit", "in": "query", "required": True, "type": "string"}
    assert {c.rule for c in oas.diff(a, oas.parse_spec(json.dumps(head)))[0]} == {"API111", "API114"}


def test_swagger2_end_to_end_in_a_repo(tmp_path):
    old = open(SW2).read()
    new = json.loads(old)
    del new["paths"]["/pets/{id}"]["delete"]
    code = {"client.py": 'import requests\nrequests.delete("http://x.example/api/pets/5")\n'}
    r = make_repo(tmp_path, {"swagger.json": old, **code}, {"swagger.json": json.dumps(new, indent=2)})
    f = by_rule(run_checks(_cfg(r), ["api"]))
    assert f["API101"][0].evidence[0].file == "client.py"  # the /api base path from the spec is understood


def test_unsupported_versions_still_rejected():
    for text in ('{"swagger": "1.2"}', '{"asyncapi": "2.0.0"}'):
        with pytest.raises(oas.SpecError):
            oas.parse_spec(text)


# ---------------------------------------------------------------- GraphQL

GQL_OLD = '''type Query { users(first: Int): [User!]! user(id: ID!): User legacy: String }
type Mutation { setStatus(s: Status): Int }
type User { id: ID! name: String email: String status: Status }
enum Status { ACTIVE BANNED }
'''
GQL_NEW = '''type Query { users(first: Int, org: ID!): [User!]! user(id: ID!): User }
type Mutation { setStatus(s: Status): Int }
type User { id: ID! name: String status: Status }
enum Status { ACTIVE }
'''
GQL_CODE = {
    "web/q.ts": 'import {gql} from "x";\nexport const Q = gql`\n  query U($id: ID!) {\n    user(id: $id) { id email status }\n    users(first: 5) { name }\n  }\n`;\n',
    "svc/q.py": 'LEGACY = """\nquery { legacy }\n"""\nBAN = """query { users(first: 1, org: "x") { status } }\nmutation M { setStatus(s: BANNED) }"""\n',
    "tests/t.py": 'Q = """query { user(id: 1) { email } }"""\n',
    "web/frag.graphql": "fragment F on User { id name }\n",
}


def test_graphql_removed_members_and_missing_required_args_are_proved_from_operations(tmp_path):
    r = make_repo(tmp_path, {"schema.graphql": GQL_OLD, **GQL_CODE}, {"schema.graphql": GQL_NEW})
    rep = run_checks(_cfg(r), ["graphql"])
    got = {(f.rule_id, f.confidence.value, f.message.split(" ", 1)[0] + ":" + e.file + ":" + str(e.line)) for f in rep.findings for e in f.evidence}
    assert ("GQL101", "confirmed", "Query.legacy:svc/q.py:2") in got
    assert ("GQL101", "confirmed", "User.email:web/q.ts:4") in got
    assert any(r_ == "GQL101" and "BANNED" in f.message and f.evidence[0].file == "svc/q.py" for f in rep.findings for r_ in [f.rule_id])
    assert any(f.rule_id == "GQL104" and f.evidence[0].snippet.strip().startswith("users(first: 5)") for f in rep.findings)  # missing arg proved
    assert [f for f in rep.findings if f.rule_id == "GQL102"][0].evidence[0].file == "tests/t.py"
    assert not any(e.file == "svc/q.py" and e.line == 4 and f.rule_id == "GQL104" for f in rep.findings for e in f.evidence)  # this call passes `org`
    assert rep.blocking()


def test_graphql_unused_removal_is_unknown_and_split_schemas_are_merged(tmp_path):
    old = {"schema/a.graphql": "type Query { a: String b: Int }\n", "schema/b.graphql": "type Other { x: Int }\n"}
    new = {"schema/a.graphql": "type Query { a: String }\n"}
    r = make_repo(tmp_path, old, new)
    f = run_checks(_cfg(r), ["graphql"]).findings
    assert [x.rule_id for x in f] == ["GQL105"] and f[0].confidence.value == "unknown" and f[0].file == "schema/a.graphql"


def test_graphql_changes_that_are_not_proofs_stay_possible_or_info(tmp_path):
    old = "type Query { n: Int u: U } type A { x: Int } type B { y: Int } union U = A | B enum E { P }\n"
    new = "type Query { n: String u: U } type A { x: Int } union U = A enum E { P Q }\n"
    r = make_repo(tmp_path, {"s.graphql": old, "c.py": 'Q = """query { n }"""\n'}, {"s.graphql": new})
    ids = {f.rule_id: f for f in run_checks(_cfg(r), ["graphql"]).findings}
    assert ids["GQL113"].confidence.value == "possible" and ids["GQL113"].evidence[0].file == "c.py"
    assert "GQL114" in ids and ids["GQL114"].confidence.value == "possible"  # B removed from union: no usage analysis
    assert ids["GQL121"].severity.value == "info"
    assert not run_checks(_cfg(r), ["graphql"]).blocking()


def test_graphql_client_operation_files_and_broken_schema_are_handled(tmp_path):
    r = make_repo(tmp_path, {"ops.graphql": "query { a }\n", "s.graphql": "type Query { a: String }\n"}, {"ops.graphql": "query { b }\n"})
    assert run_checks(_cfg(r), ["graphql"]).findings == []  # an operations file changed, no schema did
    r2 = make_repo(tmp_path, {"s.graphql": "type Query { a: String }\n"}, {"s.graphql": "type Query { a: \n"}, name="bad")
    f = run_checks(_cfg(r2), ["graphql"]).findings
    assert [x.rule_id for x in f] == ["GQL902"] and f[0].confidence.value == "unknown"


def test_graphql_hostile_strings_do_not_hang(tmp_path):
    import time
    junk = '`' + '{' * 15000 + '`\n' + '"""' + 'query ' * 3000 + '{"""\n' + 'x = "' + 'query { ' * 200 + '"\n'
    r = make_repo(tmp_path, {"s.graphql": "type Query { a: String b: Int }\n", "j.py": junk + "a b\n"}, {"s.graphql": "type Query { a: String }\n"})
    t = time.time()
    run_checks(_cfg(r), ["graphql"])
    assert time.time() - t < 5


def test_sci_cli_runs_all_three_checks_by_default(tmp_path, capsys):
    r = make_repo(tmp_path, {"schema.graphql": GQL_OLD, **GQL_CODE}, {"schema.graphql": GQL_NEW})
    assert sci_main(["--repo", r, "--base", "main", "--format", "json"]) == 1
    ids = {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert {"GQL101", "GQL104"} <= ids
    assert sci_main(["--repo", r, "--base", "main", "--checks", "db,api", "--format", "json"]) == 0


def test_graphql_schema_kept_in_code_strings(tmp_path):
    """Apollo-style servers keep the SDL in `typeDefs = gql`...``; a changed code file with SDL is a schema source."""
    old = 'const typeDefs = gql`\n  type Query { me: User old: String }\n  type User { id: ID! }\n`;\n'
    new = 'const typeDefs = gql`\n  type Query { me: User }\n  type User { id: ID! }\n`;\n'
    r = make_repo(tmp_path, {"server/schema.js": old, "web/q.js": 'const Q = gql`query { old }`;\n'}, {"server/schema.js": new})
    f = run_checks(_cfg(r), ["graphql"]).findings
    assert [(x.rule_id, x.confidence.value, x.evidence[0].file) for x in f] == [("GQL101", "confirmed", "web/q.js")]
    assert f[0].file == "server/schema.js"
    # SDL inside test files is a mock, not the schema
    r2 = make_repo(tmp_path, {"tests/mock.js": old}, {"tests/mock.js": new}, name="mock")
    assert run_checks(_cfg(r2), ["graphql"]).findings == []


def test_default_test_globs_cover_common_js_java_go_layouts():
    from dci.config import DEFAULT_TEST_GLOBS
    from dci.sources import Matcher
    m = Matcher(DEFAULT_TEST_GLOBS)
    for p in ("src/schema/__tests__/film.spec.js", "web/a.test.tsx", "app/b.spec.ts", "svc/x_test.go", "src/test/java/FooTest.java", "tests/t.py", "lib/__mocks__/m.js"):
        assert m(p), p
    for p in ("src/schema/film.js", "svc/contest.py", "web/latest.ts"):
        assert not m(p), p


# ---------------------------------------------------------------- gRPC / Protocol Buffers (real protoc; tests/data/route_guide.proto is grpc-go's example)

RG = os.path.join(os.path.dirname(__file__), "data", "route_guide.proto")
GREETER = 'syntax = "proto3";\npackage hello;\nservice Greeter {\n  rpc SayHello (Req) returns (Rep) {}\n  rpc Bye (Req) returns (Rep) {}\n}\nmessage Req { string name = 1; int32 n = 2; }\nmessage Rep { string message = 1; }\nenum Color { RED = 0; BLUE = 1; }\n'


def _proto_run(tmp_path, old, new, extra=None, name="repo"):
    r = make_repo(tmp_path, {**(extra or {}), **old}, new, name=name)
    return run_checks(_cfg(r), ["proto"])


def test_proto_real_route_guide_wire_breaks_and_removed_rpc_with_a_go_caller(tmp_path):
    old = open(RG).read()
    new = old.replace("int32 latitude = 1;", "int32 latitude = 3;").replace("int32 longitude = 2;", "string longitude = 2;")
    new = "\n".join(ln for ln in new.split("\n") if "rpc ListFeatures" not in ln)
    client = 'package main\nfunc run(client pb.RouteGuideClient) {\n\tstream, err := client.ListFeatures(ctx, rect)\n}\n'
    server = 'package main\nfunc (s *routeGuideServer) ListFeatures(rect *pb.Rectangle, stream pb.RouteGuide_ListFeaturesServer) error { return nil }\n'
    generated = 'package pb\nfunc (c *c) ListFeatures(ctx context.Context) {}\nconst x = "RouteGuide"\n'
    rep = _proto_run(tmp_path, {"routeguide/route_guide.proto": old},
                     {"routeguide/route_guide.proto": new},
                     {"client/client.go": client, "server/server.go": server, "routeguide/route_guide_grpc.pb.go": generated})
    ids = {f.rule_id: f for f in rep.findings}
    assert ids["PRT101"].confidence.value == "confirmed" and [(e.file, e.line) for e in ids["PRT101"].evidence] == [("client/client.go", 3)]
    w = ids["PRT111"]
    assert w.confidence.value == "confirmed" and "latitude changed number 1 -> 3" in w.message and "longitude changed to an incompatible type" in w.message
    assert rep.blocking()


def test_proto_reserved_removals_are_fine_unreserved_are_risky_and_compatible_types_are_not_breaks(tmp_path):
    new = (GREETER.replace("int32 n = 2;", "reserved 2; reserved \"n\";").replace("BLUE = 1;", "reserved 1;").replace("string name = 1;", "int64 name = 1;"))
    rep = _proto_run(tmp_path, {"hello.proto": GREETER}, {"hello.proto": new})
    msgs = " ".join(f.message for f in rep.findings if f.rule_id.startswith("PRT11"))
    assert "removed without" not in msgs  # both removals reserved
    assert "changed type string -> int64" in msgs.replace("TYPE_", "") or "incompatible" in msgs  # string -> int64 is a wire break
    new2 = GREETER.replace("int32 n = 2;", "int64 n = 2;").replace("string message = 1;", "bytes message = 1;")
    f2 = [f for f in _proto_run(tmp_path, {"hello.proto": GREETER}, {"hello.proto": new2}, name="r2").findings]
    assert {f.rule_id for f in f2} == {"PRT112"} and not any(f.confidence.value == "confirmed" for f in f2)
    new3 = GREETER.replace("int32 n = 2;", "")
    f3 = _proto_run(tmp_path, {"hello.proto": GREETER}, {"hello.proto": new3}, name="r3").findings
    assert [f.rule_id for f in f3] == ["PRT112"] and "removed without `reserved`" in f3[0].message


def test_proto_enum_number_change_required_field_and_rpc_signature_are_wire_breaks(tmp_path):
    p2 = 'syntax = "proto2";\npackage a;\nmessage M { optional string x = 1; }\nenum E { A = 0; B = 1; }\nservice S { rpc Do (M) returns (M); }\n'
    new = p2.replace("optional string x = 1;", "optional string x = 1; required int32 y = 2;").replace("B = 1;", "B = 5;").replace("returns (M)", "returns (stream M)")
    f = _proto_run(tmp_path, {"a.proto": p2}, {"a.proto": new}).findings
    text = " ".join(x.message for x in f if x.rule_id == "PRT111")
    assert "required field a.M.y" in text and "a.E.B changed number 1 -> 5" in text and "streaming changed" in text
    assert all(x.confidence.value == "confirmed" for x in f if x.rule_id == "PRT111")


def test_proto_ambiguous_method_names_and_full_method_paths(tmp_path):
    two = GREETER + 'service Other { rpc SayHello (Req) returns (Rep) {} }\n'
    new = two.replace("  rpc SayHello (Req) returns (Rep) {}\n", "", 1)
    code = {"a.py": 'import hello_pb2_grpc\nGreeterStub(ch).SayHello(req)\nOtherStub(ch).SayHello(req)\n',
            "b.sh": 'grpcurl localhost:50051 hello.Greeter/SayHello\n', "c.go": 'conn.Invoke(ctx, "/hello.Greeter/SayHello", in, out)\n'}
    f = {x.rule_id: x for x in _proto_run(tmp_path, {"hello.proto": two}, {"hello.proto": new}, code).findings}
    confirmed = {(e.file, e.line) for e in f["PRT101"].evidence}
    assert ("c.go", 1) in confirmed  # the full /pkg.Service/Method path is unambiguous
    assert ("a.py", 2) not in confirmed and "PRT103" in f  # Greeter.SayHello vs Other.SayHello cannot be told apart by name


def test_proto_missing_imports_are_left_out_and_reported_broken_protos_are_unknown_and_unchanged_is_quiet(tmp_path):
    needs = 'syntax = "proto3";\nimport "third_party/x.proto";\nmessage A { x.X v = 1; }\n'
    ok = 'syntax = "proto3";\nmessage B { int32 a = 1; }\n'
    r = make_repo(tmp_path, {"ok.proto": ok, "needs.proto": needs}, {"ok.proto": ok.replace("a = 1", "a = 2")})
    rep = run_checks(_cfg(r), ["proto"])
    assert any(f.rule_id == "PRT111" and "changed number" in f.message for f in rep.findings)
    assert any("left out" in n and "needs.proto" in n for n in rep.coverage.notes)
    r2 = make_repo(tmp_path, {"ok.proto": ok}, {"ok.proto": "syntax = \"proto3\";\nmessage B { int32 a = ; }\n"}, name="broken")
    f2 = run_checks(_cfg(r2), ["proto"]).findings
    assert [x.rule_id for x in f2] == ["PRT902"] and f2[0].confidence.value == "unknown"
    r3 = make_repo(tmp_path, {"ok.proto": ok, "x.py": "a=1\n"}, {"x.py": "a=2\n"}, name="quiet")
    assert run_checks(_cfg(r3), ["proto"]).findings == []


def test_sci_cli_default_includes_proto(tmp_path, capsys):
    r = make_repo(tmp_path, {"hello.proto": GREETER}, {"hello.proto": GREETER.replace("string name = 1;", "string name = 5;")})
    assert sci_main(["--repo", r, "--base", "main", "--format", "json"]) == 1
    assert "PRT111" in {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}


# ---------------------------------------------------------------- the demo pull request used on real runners

def test_demo_pr_is_blocked_by_every_check_through_the_action(tmp_path, github):
    sys_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
    import importlib.util
    spec = importlib.util.spec_from_file_location("make_demo", os.path.join(sys_path, "make_demo.py"))
    md = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(md)
    ws = md.make(str(tmp_path / "demo"), shallow=True)
    p, outputs, summary = run_action(ws, tmp_path, github, extra_env={"INPUT_CHECKS": "db,api,graphql,proto"})
    assert p.returncode == 1, p.stdout + p.stderr
    for rule in ("DCI101", "API101", "GQL101", "PRT101", "PRT111"):
        assert f"title={rule}" in p.stdout or rule in summary.read_text(), rule
    assert outputs["verdict"] == "fail" and int(outputs["blocking-count"]) >= 5


def test_partial_clone_works_without_downloading_every_blob_for_sizes(tmp_path):
    """`git ls-tree -l` fetches all blobs in a --filter=blob:none clone (minutes on a monorepo); GitTree must not use it there."""
    r = make_repo(tmp_path, {"openapi.yaml": SPEC, **CODE}, {"openapi.yaml": SPEC_NEW})
    for k, v in (("uploadpack.allowFilter", "true"), ("uploadpack.allowAnySHA1InWant", "true")):
        _git(r, "config", k, v)
    clone = str(tmp_path / "partial")
    subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", f"file://{r}", clone], check=True, capture_output=True)
    _git(clone, "checkout", "-q", "feat")
    _git(clone, "branch", "-f", "main", "origin/main")
    from dci import gitutil
    assert gitutil.is_partial_clone(clone) and not gitutil.is_partial_clone(r)
    cfg = _cfg(clone, head="feat")
    rep = run_checks(cfg, ["api"])
    assert by_rule(rep)["API101"][0].confidence.value == "confirmed"
    assert {e.file for e in by_rule(rep)["API101"][0].evidence} == {"svc/cleanup.py", "web/api.ts"}


def test_gittree_enforces_the_size_limit_at_read_time_and_stays_in_sync(tmp_path):
    from dci.sources import GitTree
    r = make_repo(tmp_path, {"big.txt": "x" * 5000, "small.txt": "ok\n", "z.txt": "last\n"}, {"z.txt": "last2\n"})
    sha = subprocess.run(["git", "-C", r, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    t = GitTree(r, sha, "head", max_bytes=1000)
    t._sizes_known = False  # as in a partial clone: sizes are not listed up front
    for k, (oid, _) in list(t._entries.items()):
        t._entries[k] = (oid, 0)
    assert t.read("big.txt") is None and t.read("small.txt") == "ok\n" and t.read("z.txt") == "last2\n"
    t.close()


# ---- iOS-style HTML report -------------------------------------------------

def _real_json_report(tmp_path):
    r = make_repo(tmp_path, {"hello.proto": GREETER}, {"hello.proto": GREETER.replace("string name = 1;", "string name = 5;")})
    out = tmp_path / "r.json"
    from sci import cli as sci_cli
    assert sci_cli.main(["--repo", r, "--base", "HEAD~1", "--head", "HEAD", "--format", "json", "--output", str(out)]) == 1
    return out


def test_html_report_embeds_the_real_report_and_loads_nothing_from_the_network(tmp_path):
    import json, re
    from sci import cli as sci_cli
    js = _real_json_report(tmp_path)
    from sci.htmlreport import render
    page = render(js.read_text())
    m = re.search(r'<script id="sci-data" type="application/json">(.*?)</script>', page, re.S)
    assert json.loads(m.group(1))["blocking_count"] == json.loads(js.read_text())["blocking_count"] >= 1
    assert not re.search(r'(src|href)\s*=\s*["\']https?:', page) and "default-src 'none'" in page


def test_html_embedding_cannot_break_out_of_the_script_tag():
    import json, re
    from sci.htmlreport import render
    evil = '</script><img src=x onerror=alert(1)><!--   &amp;'
    page = render(json.dumps({"findings": [{"title": evil, "evidence": [{"snippet": evil}]}]}))
    body = re.search(r'<script id="sci-data" type="application/json">(.*?)</script>', page, re.S).group(1)
    assert "<" not in body and ">" not in body and " " not in body
    assert json.loads(body)["findings"][0]["title"] == evil  # round-trips exactly, as data
    assert page.count("</script>") == 2  # data script + app script only


def test_sci_ui_rejects_a_file_that_is_not_a_report(tmp_path, capsys):
    from sci import cli as sci_cli
    bad = tmp_path / "x.json"
    bad.write_text('{"hello": 1}')
    assert sci_cli.main(["ui", str(bad), "--no-open"]) == 2
    assert "not an SCI report" in capsys.readouterr().err
