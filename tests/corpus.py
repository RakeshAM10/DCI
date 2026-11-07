"""Seeded migration corpus. Every case is verified against a real PostgreSQL engine (see test_groundtruth.py)."""
from __future__ import annotations

from dataclasses import dataclass, field

SETUP = [
    "CREATE TABLE orders (id serial PRIMARY KEY, user_id int NOT NULL, status varchar(20) NOT NULL DEFAULT 'new', "
    "legacy_status varchar(20), total numeric(12,2))",
    "CREATE TABLE order_notes (id serial PRIMARY KEY, order_id int NOT NULL REFERENCES orders(id), body text)",
]
SEED = [
    "INSERT INTO orders (user_id, legacy_status, total) VALUES (1, 'x', 10)",
    "INSERT INTO order_notes (order_id, body) VALUES (1, 'n')",
]

MODELS = '''from sqlalchemy import Column, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False, server_default="new")
    legacy_status = Column(String(20))
    total = Column(Numeric(12, 2))
    EXTRA_COLUMNS


class OrderNote(Base):
    __tablename__ = "order_notes"
    id = Column(Integer, primary_key=True)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=False)
    body = Column(Text)
'''


def models(extra: str = "", legacy: bool = True) -> str:
    m = MODELS.replace("    EXTRA_COLUMNS\n", (f"    {extra}\n" if extra else ""))
    if not legacy:
        m = m.replace('    legacy_status = Column(String(20))\n', "")
    return m


@dataclass
class Case:
    name: str
    sql: list[str]
    alembic: str | None
    files: dict[str, str]
    queries: dict[str, str] = field(default_factory=dict)
    rules: set[str] = field(default_factory=set)
    seed: bool = True
    consumers: dict[str, dict[str, str]] = field(default_factory=dict)
    known_miss: set[str] = field(default_factory=set)  # documented limitation: broken but invisible to static analysis
    possible: set[str] = field(default_factory=set)  # broken, expected to be reported only as POSSIBLE
    gt: bool = True  # run against PostgreSQL
    parity: bool = True  # SQL file and Alembic version must give identical rule sets
    setup_extra: list[str] = field(default_factory=list)  # extra DDL applied before the seed (other schemas, mixed-case tables)


REPO_ORM = '''from sqlalchemy import select, text

from .models import Order


def by_legacy(s):
    return s.execute(select(Order.legacy_status))  # Q1


def by_filter(s):
    return s.query(Order.id).filter_by(legacy_status="x").all()  # Q2


def raw_sel(conn):
    return conn.execute(text("SELECT id, legacy_status FROM orders"))  # Q3


def raw_safe(conn):
    return conn.execute(text("SELECT id, status FROM orders"))  # Q4
'''
Q_ORM = {
    "Q1": "SELECT orders.legacy_status FROM orders",
    "Q2": "SELECT orders.id FROM orders WHERE orders.legacy_status = 'x'",
    "Q3": "SELECT id, legacy_status FROM orders",
    "Q4": "SELECT id, status FROM orders",
}

NOTES = '''from sqlalchemy import text

from .models import OrderNote


def all_notes(s):
    return s.query(OrderNote).all()  # Q1


def add_note(conn):
    conn.execute(text("INSERT INTO order_notes (order_id, body) VALUES (:o, :b)"))  # Q2


def count_orders(conn):
    return conn.execute(text("SELECT count(*) FROM orders"))  # Q3
'''
Q_NOTES = {
    "Q1": "SELECT order_notes.id, order_notes.order_id, order_notes.body FROM order_notes",
    "Q2": "INSERT INTO order_notes (order_id, body) VALUES (1, 'b')",
    "Q3": "SELECT count(*) FROM orders",
}

SQL_SHAPES = '''from sqlalchemy import text


def join_q(conn):
    return conn.execute(text("SELECT o.id, n.body FROM orders o JOIN order_notes n ON n.order_id = o.id WHERE o.legacy_status = 'x'"))  # Q1


def join_safe(conn):
    return conn.execute(text("SELECT o.id, n.body FROM orders o JOIN order_notes n ON n.order_id = o.id WHERE o.status = 'x'"))  # Q2


def ambiguous(conn):
    return conn.execute(text("SELECT legacy_status FROM orders o JOIN order_notes n ON n.order_id = o.id"))  # Q3


def derived(conn):
    return conn.execute(text("SELECT x.legacy_status FROM (SELECT 1 AS legacy_status) x"))  # Q4


def cte(conn):
    return conn.execute(text("WITH recent AS (SELECT id, legacy_status FROM orders) SELECT id FROM recent"))  # Q5


def subq(conn):
    return conn.execute(text("SELECT id FROM orders WHERE id IN (SELECT order_id FROM order_notes WHERE body = 'a')"))  # Q6
'''
Q_SHAPES = {
    "Q1": "SELECT o.id, n.body FROM orders o JOIN order_notes n ON n.order_id = o.id WHERE o.legacy_status = 'x'",
    "Q2": "SELECT o.id, n.body FROM orders o JOIN order_notes n ON n.order_id = o.id WHERE o.status = 'x'",
    "Q3": "SELECT legacy_status FROM orders o JOIN order_notes n ON n.order_id = o.id",
    "Q4": "SELECT x.legacy_status FROM (SELECT 1 AS legacy_status) x",
    "Q5": "WITH recent AS (SELECT id, legacy_status FROM orders) SELECT id FROM recent",
    "Q6": "SELECT id FROM orders WHERE id IN (SELECT order_id FROM order_notes WHERE body = 'a')",
}

DML = '''from sqlalchemy import text


def upd(conn):
    conn.execute(text("UPDATE orders SET legacy_status = :s WHERE id = :i"))  # Q1


def dele(cur):
    cur.execute("DELETE FROM orders WHERE legacy_status = %s", (1,))  # Q2


def ins(conn):
    conn.execute(text("INSERT INTO orders (user_id, legacy_status) VALUES (:u, :s)"))  # Q3


def ins_ok(conn):
    conn.execute(text("INSERT INTO orders (user_id, status) VALUES (:u, :s)"))  # Q4


def cast(conn):
    conn.execute(text("SELECT id::text, total FROM orders WHERE status = :st"))  # Q5
'''
Q_DML = {
    "Q1": "UPDATE orders SET legacy_status = 's' WHERE id = 1",
    "Q2": "DELETE FROM orders WHERE legacy_status = '1'",
    "Q3": "INSERT INTO orders (user_id, legacy_status) VALUES (1, 's')",
    "Q4": "INSERT INTO orders (user_id, status) VALUES (1, 's')",
    "Q5": "SELECT id::text, total FROM orders WHERE status = 'new'",
}

DYNAMIC = '''def f_dyn(conn, oid):
    conn.execute(f"SELECT id, legacy_status FROM orders WHERE id = {oid}")  # Q1


def concat(conn, cols):
    conn.execute("SELECT " + cols + " FROM orders")  # Q2


def fmt(conn):
    conn.execute("SELECT legacy_status FROM {} WHERE 1 = 1".format("orders"))  # Q3
'''
Q_DYNAMIC = {
    "Q1": "SELECT id, legacy_status FROM orders WHERE id = 1",
    "Q2": "SELECT legacy_status FROM orders",
    "Q3": "SELECT legacy_status FROM orders WHERE 1 = 1",
}

WRITERS = '''from sqlalchemy import text

from .models import Order


def raw_ins_bad(conn):
    conn.execute(text("INSERT INTO orders (user_id, total) VALUES (:u, :t)"))  # Q1


def orm_bad(s):
    s.add(Order(user_id=1, total=2))  # Q2


def orm_ok(s):
    s.add(Order(user_id=1, channel="web"))  # Q3


def raw_ok(conn):
    conn.execute(text("INSERT INTO orders (user_id, channel) VALUES (:u, :c)"))  # Q4
'''
Q_WRITERS = {
    "Q1": "INSERT INTO orders (user_id, total) VALUES (1, 2)",
    "Q2": "INSERT INTO orders (user_id, total) VALUES (1, 2)",
    "Q3": "INSERT INTO orders (user_id, channel) VALUES (1, 'web')",
    "Q4": "INSERT INTO orders (user_id, channel) VALUES (1, 'c')",
}

NN_WRITERS = '''from sqlalchemy import text


def omit(conn):
    conn.execute(text("INSERT INTO orders (user_id) VALUES (:u)"))  # Q1


def supply(conn):
    conn.execute(text("INSERT INTO orders (user_id, legacy_status) VALUES (:u, :s)"))  # Q2
'''
Q_NN = {"Q1": "INSERT INTO orders (user_id) VALUES (1)", "Q2": "INSERT INTO orders (user_id, legacy_status) VALUES (1, 's')"}

BILLING = '''import psycopg2


def invoices(cur):
    cur.execute("SELECT id, legacy_status FROM orders WHERE total > %s", (0,))  # Q1


def invoices_ok(cur):
    cur.execute("SELECT id, total FROM orders")  # Q2
'''
Q_BILLING = {"Q1": "SELECT id, legacy_status FROM orders WHERE total > 0", "Q2": "SELECT id, total FROM orders"}

SCHEMA_Q = '''from sqlalchemy import text


def public_q(conn):
    return conn.execute(text("SELECT id, legacy_status FROM public.orders"))  # Q1


def default_q(conn):
    return conn.execute(text("SELECT id, legacy_status FROM orders"))  # Q2


def archive_q(conn):
    return conn.execute(text("SELECT id, legacy_status FROM archive.orders"))  # Q3
'''
Q_SCHEMA = {"Q1": "SELECT id, legacy_status FROM public.orders", "Q2": "SELECT id, legacy_status FROM orders",
            "Q3": "SELECT id, legacy_status FROM archive.orders"}
SCHEMA_EXTRA = ["CREATE SCHEMA archive", "CREATE TABLE archive.orders (id serial PRIMARY KEY, legacy_status varchar(20))"]

QUOTED_Q = '''from sqlalchemy import Column, Integer, String, select, text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Mixed(Base):
    __tablename__ = "Orders"
    id = Column(Integer, primary_key=True)
    upper_legacy = Column("Legacy", String(20))
    lower_legacy = Column("legacy", String(20))


def q1(conn):
    return conn.execute(text('SELECT "Legacy" FROM "Orders"'))  # Q1


def q2(conn):
    return conn.execute(text('SELECT legacy FROM "Orders"'))  # Q2


def q3(conn):
    return conn.execute(text("SELECT legacy_status FROM orders"))  # Q3


def q4(conn):
    return conn.execute(text('SELECT LEGACY FROM "Orders"'))  # Q4


def q5(s):
    return s.execute(select(Mixed.upper_legacy))  # Q5


def q6(s):
    return s.execute(select(Mixed.lower_legacy))  # Q6
'''
Q_QUOTED = {"Q1": 'SELECT "Legacy" FROM "Orders"', "Q2": 'SELECT legacy FROM "Orders"', "Q3": "SELECT legacy_status FROM orders",
            "Q4": 'SELECT LEGACY FROM "Orders"', "Q5": 'SELECT "Orders"."Legacy" FROM "Orders"', "Q6": 'SELECT "Orders".legacy FROM "Orders"'}
QUOTED_EXTRA = ['CREATE TABLE "Orders" (id serial PRIMARY KEY, "Legacy" varchar(20), legacy varchar(20))']

FOLD_Q = '''from sqlalchemy import text


def exact(conn):
    return conn.execute(text("SELECT legacy_status FROM orders"))  # Q1


def folded(conn):
    return conn.execute(text("SELECT Legacy_Status FROM Orders"))  # Q2


def other_table(conn):
    return conn.execute(text('SELECT "Legacy" FROM "Orders"'))  # Q3
'''
Q_FOLD = {"Q1": "SELECT legacy_status FROM orders", "Q2": "SELECT Legacy_Status FROM Orders", "Q3": 'SELECT "Legacy" FROM "Orders"'}

TRIVIAL = "def nothing():\n    return 1\n"

D = "svc_orders"
ORM_FILES = {f"{D}/models.py": models(), f"{D}/repo.py": REPO_ORM}

CASES: list[Case] = [
    Case("drop_column_orm_and_raw", ["ALTER TABLE orders DROP COLUMN legacy_status"],
         'op.drop_column("orders", "legacy_status")', ORM_FILES, Q_ORM, {"DCI101", "DCI105"}),
    Case("rename_column", ["ALTER TABLE orders RENAME COLUMN legacy_status TO old_status"],
         'op.alter_column("orders", "legacy_status", new_column_name="old_status")', ORM_FILES, Q_ORM, {"DCI111", "DCI115"}),
    Case("drop_table", ["ALTER TABLE order_notes DROP CONSTRAINT order_notes_order_id_fkey", "DROP TABLE order_notes"],
         'op.drop_table("order_notes")', {f"{D}/models.py": models(), f"{D}/notes.py": NOTES}, Q_NOTES, {"DCI121", "DCI125"}, parity=False),
    Case("rename_table", ["ALTER TABLE order_notes RENAME TO order_comments"],
         'op.rename_table("order_notes", "order_comments")', {f"{D}/models.py": models(), f"{D}/notes.py": NOTES}, Q_NOTES, {"DCI131", "DCI135"}),
    Case("sql_shapes_joins_cte_derived", ["ALTER TABLE orders DROP COLUMN legacy_status"],
         'op.drop_column("orders", "legacy_status")', {f"{D}/models.py": models(legacy=False), f"{D}/shapes.py": SQL_SHAPES}, Q_SHAPES,
         {"DCI101", "DCI103", "DCI105"}, possible={"Q3"}),
    Case("sql_dml_bind_params", ["ALTER TABLE orders DROP COLUMN legacy_status"],
         'op.drop_column("orders", "legacy_status")', {f"{D}/models.py": models(legacy=False), f"{D}/dml.py": DML}, Q_DML, {"DCI101", "DCI105"}),
    Case("dynamic_sql", ["ALTER TABLE orders DROP COLUMN legacy_status"],
         'op.drop_column("orders", "legacy_status")', {f"{D}/models.py": models(legacy=False), f"{D}/dyn.py": DYNAMIC}, Q_DYNAMIC,
         {"DCI101", "DCI103", "DCI105"}, possible={"Q2", "Q3"}),
    Case("drop_column_batch_alembic", ["ALTER TABLE orders DROP COLUMN legacy_status"],
         'with op.batch_alter_table("orders") as batch_op:\n        batch_op.drop_column("legacy_status")', ORM_FILES, Q_ORM, {"DCI101", "DCI105"}),
    Case("drop_column_unreferenced", ["ALTER TABLE orders DROP COLUMN legacy_status"],
         'op.drop_column("orders", "legacy_status")',
         {f"{D}/models.py": models(legacy=False), f"{D}/repo.py": "from sqlalchemy import text\n\n\ndef ok(conn):\n    return conn.execute(text(\"SELECT id, status FROM orders\"))  # Q1\n"},
         {"Q1": "SELECT id, status FROM orders"}, {"DCI105"}),
    Case("drop_column_cross_repo_consumer", ["ALTER TABLE orders DROP COLUMN legacy_status"],
         'op.drop_column("orders", "legacy_status")', {f"{D}/models.py": models(legacy=False), f"{D}/x.py": TRIVIAL},
         Q_BILLING, {"DCI101", "DCI105"}, consumers={"billing": {"billing/invoices.py": BILLING}}),
    Case("add_notnull_no_default_writers", ["ALTER TABLE orders ADD COLUMN channel text NOT NULL"],
         'op.add_column("orders", sa.Column("channel", sa.Text(), nullable=False))',
         {f"{D}/models.py": models("channel = Column(String, nullable=False)"), f"{D}/w.py": WRITERS}, Q_WRITERS, {"DCI401", "DCI402"}, seed=False),
    Case("add_notnull_with_default_safe", ["ALTER TABLE orders ADD COLUMN channel text NOT NULL DEFAULT 'web'"],
         'op.add_column("orders", sa.Column("channel", sa.Text(), nullable=False, server_default="web"))',
         {f"{D}/models.py": models("channel = Column(String, nullable=False, server_default='web')"), f"{D}/w.py": WRITERS}, {
             "Q1": Q_WRITERS["Q1"], "Q2": Q_WRITERS["Q2"], "Q3": Q_WRITERS["Q3"], "Q4": Q_WRITERS["Q4"]}, set()),
    Case("add_nullable_column_safe", ["ALTER TABLE orders ADD COLUMN channel text"],
         'op.add_column("orders", sa.Column("channel", sa.Text(), nullable=True))',
         {f"{D}/models.py": models("channel = Column(String)"), f"{D}/w.py": WRITERS}, Q_WRITERS, set()),
    Case("set_not_null", ["ALTER TABLE orders ALTER COLUMN legacy_status SET NOT NULL"],
         'op.alter_column("orders", "legacy_status", nullable=False)',
         {f"{D}/models.py": models(), f"{D}/w.py": NN_WRITERS}, Q_NN, {"DCI301", "DCI302"}, possible={"Q1"}),
    Case("create_index_blocking", ["CREATE INDEX ix_orders_user ON orders (user_id)"],
         'op.create_index("ix_orders_user", "orders", ["user_id"])', {f"{D}/models.py": models()}, {}, {"DCI501"}),
    Case("create_index_concurrently_safe", ["CREATE INDEX CONCURRENTLY ix_orders_user ON orders (user_id)"],
         'op.create_index("ix_orders_user", "orders", ["user_id"], postgresql_concurrently=True)', {f"{D}/models.py": models()}, {}, set(), gt=False),
    Case("new_table_with_index_safe", ["CREATE TABLE shipments (id serial PRIMARY KEY, order_id int)", "CREATE INDEX ix_ship_order ON shipments (order_id)"],
         'op.create_table("shipments", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("order_id", sa.Integer()))\n    op.create_index("ix_ship_order", "shipments", ["order_id"])',
         {f"{D}/models.py": models()}, {}, set()),
    Case("add_unique_blocking", ["ALTER TABLE orders ADD CONSTRAINT uq_orders UNIQUE (user_id, total)"],
         'op.create_unique_constraint("uq_orders", "orders", ["user_id", "total"])', {f"{D}/models.py": models()}, {}, {"DCI502"}),
    Case("foreign_key_validated", ["ALTER TABLE order_notes ADD CONSTRAINT fk_notes_orders FOREIGN KEY (order_id) REFERENCES orders(id)"],
         'op.create_foreign_key("fk_notes_orders", "order_notes", "orders", ["order_id"], ["id"])', {f"{D}/models.py": models()}, {}, {"DCI503"}),
    Case("foreign_key_not_valid_safe", ["ALTER TABLE order_notes ADD CONSTRAINT fk_notes_orders FOREIGN KEY (order_id) REFERENCES orders(id) NOT VALID"],
         'op.create_foreign_key("fk_notes_orders", "order_notes", "orders", ["order_id"], ["id"], postgresql_not_valid=True)', {f"{D}/models.py": models()}, {}, set()),
    Case("alter_type_rewrite", ["ALTER TABLE orders ALTER COLUMN user_id TYPE bigint"],
         'op.alter_column("orders", "user_id", type_=sa.BigInteger())', {f"{D}/models.py": models()}, {}, {"DCI201"}),
    Case("alter_type_to_text_safe", ["ALTER TABLE orders ALTER COLUMN legacy_status TYPE text"],
         'op.alter_column("orders", "legacy_status", type_=sa.Text())', {f"{D}/models.py": models()}, {}, set()),
    Case("check_constraint_validated", ["ALTER TABLE orders ADD CONSTRAINT ck_total CHECK (total >= 0)"],
         'op.create_check_constraint("ck_total", "orders", "total >= 0")', {f"{D}/models.py": models()}, {}, {"DCI504"}),
    Case("check_constraint_not_valid_safe", ["ALTER TABLE orders ADD CONSTRAINT ck_total CHECK (total >= 0) NOT VALID"],
         'op.create_check_constraint("ck_total", "orders", "total >= 0", postgresql_not_valid=True)', {f"{D}/models.py": models()}, {}, set()),
    Case("schema_public_drop_spares_archive", ["ALTER TABLE public.orders DROP COLUMN legacy_status"],
         'op.drop_column("orders", "legacy_status", schema="public")', {f"{D}/models.py": models(), f"{D}/s.py": SCHEMA_Q}, Q_SCHEMA,
         {"DCI101", "DCI105"}, setup_extra=SCHEMA_EXTRA),
    Case("schema_archive_drop_spares_public", ["ALTER TABLE archive.orders DROP COLUMN legacy_status"],
         'op.drop_column("orders", "legacy_status", schema="archive")', {f"{D}/models.py": models(), f"{D}/s.py": SCHEMA_Q}, Q_SCHEMA,
         {"DCI101", "DCI105"}, setup_extra=SCHEMA_EXTRA),
    Case("quoted_identifiers_exact_match", ['ALTER TABLE "Orders" DROP COLUMN "Legacy"'],
         'op.drop_column("Orders", "Legacy")', {f"{D}/q.py": QUOTED_Q}, Q_QUOTED, {"DCI101", "DCI105"}, setup_extra=QUOTED_EXTRA),
    Case("unquoted_names_fold_quoted_do_not_match", ["ALTER TABLE orders DROP COLUMN legacy_status"],
         'op.drop_column("orders", "legacy_status")', {f"{D}/models.py": models(), f"{D}/f.py": FOLD_Q}, Q_FOLD, {"DCI101", "DCI105"},
         setup_extra=['CREATE TABLE "Orders" (id serial PRIMARY KEY, "Legacy" varchar(20))']),
]
