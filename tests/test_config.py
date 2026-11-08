"""Environment-variable check against real git repositories."""
from dci.config import Config
from sci.run import run_checks

from test_sci import make_repo

COMPOSE = "services:\n  web:\n    image: x\n    environment:\n      - DATABASE_URL=postgres://x\n      - SECRET_KEY=abc\n"
COMPOSE_NEW = "services:\n  web:\n    image: x\n    environment:\n      - DATABASE_URL=postgres://x\n"


def _run(r):
    cfg = Config(repo=r)
    cfg.base, cfg.head = "main", "feat"
    return run_checks(cfg, ["config"])


def test_required_read_of_variable_removed_from_compose_is_confirmed(tmp_path):
    r = make_repo(tmp_path, {"docker-compose.yml": COMPOSE, "app.py": 'import os\nKEY = os.environ["SECRET_KEY"]\nDB = os.environ["DATABASE_URL"]\n'},
                  {"docker-compose.yml": COMPOSE_NEW})
    rep = _run(r)
    f = [x for x in rep.findings if x.rule_id == "CFG101"]
    assert len(f) == 1 and f[0].confidence.value == "confirmed" and rep.blocking()
    assert (f[0].evidence[0].file, f[0].evidence[0].line) == ("app.py", 2) and "SECRET_KEY" in f[0].message


def test_tolerant_read_or_example_only_removal_never_blocks(tmp_path):
    r = make_repo(tmp_path, {"docker-compose.yml": COMPOSE, "app.py": 'import os\nK = os.environ.get("SECRET_KEY")\n'}, {"docker-compose.yml": COMPOSE_NEW})
    rep = _run(r)
    assert [x.confidence.value for x in rep.findings] == ["possible"] and not rep.blocking()
    r2 = make_repo(tmp_path, {".env.example": "A_KEY=1\n", "app.py": 'import os\nv = os.environ["A_KEY"]\n'}, {".env.example": "\n"}, name="r2")
    rep2 = _run(r2)
    assert [x.confidence.value for x in rep2.findings] == ["possible"] and not rep2.blocking()


def test_default_value_read_is_not_reported(tmp_path):
    r = make_repo(tmp_path, {"docker-compose.yml": COMPOSE, "app.py": 'import os\nK = os.environ.get("SECRET_KEY", "dev")\n'}, {"docker-compose.yml": COMPOSE_NEW})
    assert _run(r).findings == []


def test_variable_still_declared_elsewhere_is_fine(tmp_path):
    k8s = "kind: Deployment\nspec:\n  containers:\n  - env:\n    - name: SECRET_KEY\n      value: x\n"
    r = make_repo(tmp_path, {"docker-compose.yml": COMPOSE, "app.py": 'import os\nK = os.environ["SECRET_KEY"]\n'}, {"docker-compose.yml": COMPOSE_NEW, "k8s.yaml": k8s})
    assert _run(r).findings == []


def test_new_required_variable_without_declaration_is_possible(tmp_path):
    r = make_repo(tmp_path, {"app.py": "x = 1\n", "docker-compose.yml": COMPOSE_NEW},
                  {"app.py": 'import os\nTOKEN = os.environ["NEW_TOKEN"]\nDB = os.environ["DATABASE_URL"]\n'})
    rep = _run(r)
    assert [(x.rule_id, x.confidence.value) for x in rep.findings] == [("CFG102", "possible")] and not rep.blocking()
    assert "NEW_TOKEN" in rep.findings[0].message


def test_dockerfile_env_counts_as_declaration(tmp_path):
    r = make_repo(tmp_path, {"Dockerfile": "FROM x\nENV MODE=prod\n", "a.py": 'import os\nm = os.environ["MODE"]\n'}, {"Dockerfile": "FROM x\n"})
    rep = _run(r)
    assert rep.blocking() and rep.findings[0].rule_id == "CFG101"
