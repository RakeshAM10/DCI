"""Harder adversarial tests, scale tests, and git rollout ground-truth checks.
Implements the P0 backlog items from docs/DCI_BRAIN.md."""
from __future__ import annotations

import os
import time
import pytest

from dci import cli
from dci.analyze import analyze
from dci.config import Config
from dci.models import Confidence, Severity
from dci.redact import redact
from dci.sqlutil import split_statements, normalize_params
from helpers import git, write_files
import pg

# ----------------------------------------------------------------------
# 1. SCALE TEST: Large synthetic repo performance & prefilter efficiency
# ----------------------------------------------------------------------

def test_scale_large_repo_performance_and_prefilter(tmp_path):
    """Generates a large repository with 1,000 Python files across multiple packages.
    Verifies that the relevance prefilter skips irrelevant files quickly
    and correctly isolates the target references without false positives."""
    repo = tmp_path / "large_repo"
    os.makedirs(repo, exist_ok=True)

    # 1. Migration: drop column `secret_token` from `accounts`
    mig_dir = repo / "db" / "migrations"
    os.makedirs(mig_dir, exist_ok=True)
    with open(mig_dir / "0002_drop_token.sql", "w", encoding="utf-8") as f:
        f.write("ALTER TABLE accounts DROP COLUMN secret_token;\n")

    # 2. Target model in app/models/account.py
    model_dir = repo / "app" / "models"
    os.makedirs(model_dir, exist_ok=True)
    with open(model_dir / "account.py", "w", encoding="utf-8") as f:
        f.write('''from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String
Base = declarative_base()

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    secret_token = Column(String(64))
''')

    # 3. Exactly 2 consumer files that legitimately reference `secret_token`
    service_dir = repo / "app" / "services"
    os.makedirs(service_dir, exist_ok=True)
    with open(service_dir / "auth.py", "w", encoding="utf-8") as f:
        f.write('''from app.models.account import Account

def verify(session, token):
    return session.query(Account).filter(Account.secret_token == token).first()
''')

    with open(service_dir / "query.sql", "w", encoding="utf-8") as f:
        f.write("SELECT id, secret_token FROM accounts WHERE id = 1;\n")

    # 4. Generate 1,000 unrelated Python files across multiple subdirectories
    for chunk in range(10):
        chunk_dir = repo / "app" / f"pkg_{chunk}"
        os.makedirs(chunk_dir, exist_ok=True)
        for i in range(100):
            fn = chunk_dir / f"module_{i}.py"
            with open(fn, "w", encoding="utf-8") as f:
                f.write(f'''# Module {chunk}_{i}
def compute_{i}(x, y):
    return x * {i} + y

class Handler_{i}:
    def __init__(self, val):
        self.val = val

    def process(self):
        return self.val * 2
''')

    # Run DCI analyze and benchmark execution time
    t0 = time.perf_counter()
    rep = analyze(Config(repo=str(repo), migrations=["db/migrations/0002_drop_token.sql"]))
    duration = time.perf_counter() - t0

    # Assertions on prefilter efficiency
    assert rep.coverage.python_files_skipped_by_filter >= 990, (
        f"Prefilter failed: only skipped {rep.coverage.python_files_skipped_by_filter} files"
    )
    assert duration < 25.0, f"Analysis took too long: {duration:.2f}s"

    # Assertions on findings
    dci101_findings = [f for f in rep.findings if f.rule_id == "DCI101"]
    assert len(dci101_findings) == 1
    finding = dci101_findings[0]
    evidence_files = {e.file.replace("\\\\", "/") for e in finding.evidence}
    
    # Must find the model definition and both consumers
    assert "app/models/account.py" in evidence_files
    assert "app/services/auth.py" in evidence_files
    assert "app/services/query.sql" in evidence_files


# ----------------------------------------------------------------------
# 2. SCANNER TRAPS: Docstrings, comments, log strings
# ----------------------------------------------------------------------

def test_scanner_traps_docstrings_and_comments(tmp_path):
    """Ensures SQL or column names inside docstrings, comments, or regexes
    do not create false-positive CONFIRMED findings."""
    mig = "db/migrations/0002.sql"
    drop_col = "ALTER TABLE users DROP COLUMN email;\n"
    
    files = {
        mig: drop_col,
        "app/models.py": '''from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String)
    # Column 'email' was removed from this model in a previous release
''',
        "app/service.py": '''"""
This module used to do:
SELECT email FROM users WHERE id = 1;
UPDATE users SET email = 'test';
"""

# Note: user.email is deprecated and never used here
REGEX = r"^[a-zA-Z0-9_.+-]+@users\\\\.com$"

def get_user(session, user_id):
    # Log query that mentions the word email
    logger_msg = "Fetching user details without email"
    return session.query(User).filter(User.id == user_id).first()
'''
    }
    write_files(str(tmp_path), files)
    rep = analyze(Config(repo=str(tmp_path), migrations=[mig]))

    # Because 'email' is only in docstrings and comments, no CONFIRMED DCI101 should exist
    confirmed_findings = [f for f in rep.findings if f.confidence == Confidence.CONFIRMED and f.rule_id == "DCI101"]
    assert not confirmed_findings, f"Unexpected confirmed findings: {confirmed_findings}"


# ----------------------------------------------------------------------
# 3. INHERITANCE, MIXINS & AMBIGUOUS CLASS NAMES
# ----------------------------------------------------------------------

def test_model_inheritance_and_mixins(tmp_path):
    """Tests model inheritance with declared columns on an abstract base/mixin."""
    mig = "db/migrations/0002.sql"
    drop_col = "ALTER TABLE audit_logs DROP COLUMN audit_hash;\n"
    
    files = {
        mig: drop_col,
        "app/models/base.py": '''from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String
Base = declarative_base()

class TimestampMixin:
    audit_hash = Column(String(64))

class AuditLog(TimestampMixin, Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
''',
        "app/service.py": '''from app.models.base import AuditLog

def find_by_hash(session, h):
    return session.query(AuditLog).filter(AuditLog.audit_hash == h).first()
'''
    }
    write_files(str(tmp_path), files)
    rep = analyze(Config(repo=str(tmp_path), migrations=[mig]))

    # AuditLog inherits audit_hash from TimestampMixin
    dci101 = [f for f in rep.findings if f.rule_id == "DCI101"]
    assert len(dci101) == 1
    ev_files = {e.file.replace("\\\\", "/") for e in dci101[0].evidence}
    assert "app/service.py" in ev_files


def test_ambiguous_class_names_in_different_modules(tmp_path):
    """Two classes named 'Order' mapping to different tables.
    Because the class name is ambiguous, DCI flags it as DCI103 (POSSIBLE),
    not CONFIRMED (DCI101), preventing an incorrect blocking finding."""
    mig = "db/migrations/0002.sql"
    drop_col = "ALTER TABLE kitchen_tickets DROP COLUMN special_instructions;\n"

    files = {
        mig: drop_col,
        "app/shop/models.py": '''from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String
Base = declarative_base()

class Order(Base):
    __tablename__ = "shop_orders"
    id = Column(Integer, primary_key=True)
    special_instructions = Column(String)  # Different table!
''',
        "app/kitchen/models.py": '''from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String
Base = declarative_base()

class Order(Base):
    __tablename__ = "kitchen_tickets"
    id = Column(Integer, primary_key=True)
    special_instructions = Column(String)  # Target of migration
''',
        "app/shop/service.py": '''from app.shop.models import Order

def get_shop_order(session, oid):
    return session.query(Order).filter(Order.special_instructions == "gift").first()
''',
        "app/kitchen/service.py": '''from app.kitchen.models import Order

def get_kitchen_order(session, oid):
    return session.query(Order).filter(Order.special_instructions == "urgent").first()
'''
    }
    write_files(str(tmp_path), files)
    rep = analyze(Config(repo=str(tmp_path), migrations=[mig]))

    # Target model in kitchen/models.py is confirmed
    dci101 = [f for f in rep.findings if f.rule_id == "DCI101"]
    assert len(dci101) == 1
    assert any("app/kitchen/models.py" in e.file.replace("\\\\", "/") for e in dci101[0].evidence)

    # Queries using ambiguous Order are reported as POSSIBLE under DCI103
    dci103 = [f for f in rep.findings if f.rule_id == "DCI103"]
    assert len(dci103) == 1
    dci103_files = {e.file.replace("\\\\", "/") for e in dci103[0].evidence}
    assert "app/kitchen/service.py" in dci103_files


# ----------------------------------------------------------------------
# 4. GIT ROLLOUT GROUND TRUTH (R1, R2, R3)
# ----------------------------------------------------------------------

pytestmark_pg = pytest.mark.skipif(not pg.AVAILABLE, reason="PGlite (node) not installed")

@pytestmark_pg
def test_git_rollout_r1_simultaneous_removal_and_drop(tmp_path):
    """(R1) PR removes column from code AND drops it in migration.
    In rolling deploy mode (default):
      - Base commit running code STILL uses the column.
      - Dropping it causes old versions to error in real PostgreSQL!
      - DCI flags DCI104 ERROR with base commit evidence (blocks CI).
    With --no-rolling-deploy:
      - DCI104 is downgraded to INFO (does not block CI)."""
    repo = str(tmp_path / "repo_r1")
    os.makedirs(repo, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")

    base_files = {
        "app/models.py": '''from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String
Base = declarative_base()

class Item(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True)
    sku = Column(String)
''',
        "app/use.py": '''from app.models import Item
def get_item(s):
    return s.query(Item.sku).all()
'''
    }
    write_files(repo, base_files)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base commit")

    # PR branch: remove use of sku, AND drop column sku in migration
    git(repo, "checkout", "-qb", "pr_branch")
    pr_files = {
        "app/models.py": '''from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer
Base = declarative_base()

class Item(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True)
''',
        "app/use.py": '''def get_item(s):
    return []
''',
        "db/migrations/0002_drop_sku.sql": "ALTER TABLE items DROP COLUMN sku;\n"
    }
    write_files(repo, pr_files)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "drop sku")

    # 1. Verify against real PostgreSQL: old query indeed breaks after migration
    setup = ["CREATE TABLE items (id serial primary key, sku text);", "INSERT INTO items VALUES (1, 'ABC');"]
    mig = ["ALTER TABLE items DROP COLUMN sku;"]
    old_query = {"Q1": "SELECT sku FROM items;"}
    truth = pg.run(setup, mig, old_query)
    assert "Q1" in truth["query_errors"], "PostgreSQL did not error on dropped column query"

    # 2. Analyze with DCI (default rolling_deploy=True)
    rep_rolling = analyze(Config(repo=repo, base="main", head="HEAD"))
    rule_ids = {f.rule_id for f in rep_rolling.findings}
    assert "DCI104" in rule_ids, f"Expected DCI104 (rollout window error), got {rule_ids}"
    assert "DCI101" not in rule_ids, "Head code does not use the column; DCI101 should not be triggered"
    dci104 = next(f for f in rep_rolling.findings if f.rule_id == "DCI104")
    assert dci104.severity == Severity.ERROR
    assert any(e.tree == "base" for e in dci104.evidence)

    # 3. Analyze with rolling_deploy=False
    rep_non_rolling = analyze(Config(repo=repo, base="main", head="HEAD", rolling_deploy=False))
    dci104_nr = next(f for f in rep_non_rolling.findings if f.rule_id == "DCI104")
    assert dci104_nr.severity == Severity.INFO


@pytestmark_pg
def test_git_rollout_r2_safe_expand_contract(tmp_path):
    """(R2) Safe expand/contract sequence:
    Column was ALREADY removed from application code in an earlier release (main).
    The PR only adds the migration to drop the column.
    Result: passes CI! Only DCI105 (INFO) is emitted."""
    repo = str(tmp_path / "repo_r2")
    os.makedirs(repo, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")

    # Base already has no reference to legacy_col
    base_files = {
        "app/models.py": '''from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer
Base = declarative_base()

class Item(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True)
''',
        "app/use.py": '''def get_item(s):
    return []
'''
    }
    write_files(repo, base_files)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base without column")

    # PR branch: simply drops the unused column
    git(repo, "checkout", "-qb", "pr_branch")
    write_files(repo, {"db/migrations/0002_drop.sql": "ALTER TABLE items DROP COLUMN legacy_col;\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "drop unused column")

    rep = analyze(Config(repo=repo, base="main", head="HEAD"))
    rule_ids = {f.rule_id for f in rep.findings}
    assert "DCI101" not in rule_ids
    assert "DCI104" not in rule_ids
    assert not rep.blocking(), "Safe expand/contract migration was blocked"


@pytestmark_pg
def test_git_rollout_r3_not_null_column_with_base_writers(tmp_path):
    """(R3) Migration adds a NOT NULL column without default.
    Base commit writers perform INSERTs without providing this column.
    During rolling deploy, old version INSERTs will fail on real PostgreSQL!
    Result: DCI emits DCI403 (Rollout window: old version writers omit NOT NULL column)."""
    repo = str(tmp_path / "repo_r3")
    os.makedirs(repo, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")

    base_files = {
        "app/models.py": '''from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String
Base = declarative_base()

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
''',
        "app/service.py": '''from app.models import Order
def create(session):
    session.add(Order())
    session.commit()
'''
    }
    write_files(repo, base_files)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base with insert")

    git(repo, "checkout", "-qb", "pr_branch")
    pr_files = {
        "db/migrations/0002_add_nn.sql": "ALTER TABLE orders ADD COLUMN priority integer NOT NULL;\n"
    }
    write_files(repo, pr_files)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "add not null no default")

    # Check real PostgreSQL: old INSERT fails after migration
    setup = ["CREATE TABLE orders (id serial primary key);"]
    mig = ["ALTER TABLE orders ADD COLUMN priority integer NOT NULL;"]
    old_insert = {"Q1": "INSERT INTO orders (id) VALUES (DEFAULT);"}
    truth = pg.run(setup, mig, old_insert)
    assert "Q1" in truth["query_errors"]

    rep = analyze(Config(repo=repo, base="main", head="HEAD"))
    rule_ids = {f.rule_id for f in rep.findings}
    assert "DCI403" in rule_ids, f"Expected DCI403, got {rule_ids}"


# ----------------------------------------------------------------------
# 5. SQL PARSER & REDACT SECURITY
# ----------------------------------------------------------------------

def test_sqlutil_dollar_quotes_nested_comments():
    """Validates dollar-quotes and nested comments in PostgreSQL statements."""
    sql = """
    -- initial comment
    CREATE OR REPLACE FUNCTION test_fn() RETURNS text AS $body$
    BEGIN
        /* nested /* block */ comment */
        RETURN 'secret_value';
    END;
    $body$ LANGUAGE plpgsql;

    SELECT * FROM orders WHERE status = :status_val;
    """
    stmts = split_statements(sql)
    assert len(stmts) == 2
    assert "$body$" in stmts[0][0]
    
    # Bind parameter normalization
    norm = normalize_params("SELECT * FROM orders WHERE id = :id AND code = $1 AND ref = %s")
    assert ":id" not in norm
    assert "$1" not in norm
    assert "%s" not in norm


def test_redact_secrets_and_literals():
    """Ensures sensitive patterns and raw literals are redacted from emitted snippets."""
    snippet1 = "SELECT * FROM users WHERE password = 'my_super_secret_pw';"
    redacted1 = redact(snippet1)
    assert "my_super_secret_pw" not in redacted1
    assert "?" in redacted1

    prefix = "sk" + "_live_"
    snippet2 = "api_key = '" + prefix + "0123456789abcdef0123456789abcdef'"
    redacted2 = redact(snippet2)
    assert prefix not in redacted2
