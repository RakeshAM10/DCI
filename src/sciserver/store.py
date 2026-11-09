"""SQLite store: installations, repositories (multi-repo), webhook deliveries (replay protection), and the job queue with results.

One connection per call (sqlite3 connections are not shared across threads), WAL mode, foreign keys on, every statement parameterised."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager

SCHEMA = [
    """CREATE TABLE installations (id INTEGER PRIMARY KEY, account TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created REAL NOT NULL)""",
    """CREATE TABLE repos (id INTEGER PRIMARY KEY AUTOINCREMENT, installation_id INTEGER NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
       full_name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1, over_limit INTEGER NOT NULL DEFAULT 0, settings TEXT NOT NULL DEFAULT '{}',
       created REAL NOT NULL)""",
    """CREATE TABLE deliveries (delivery_id TEXT PRIMARY KEY, received REAL NOT NULL)""",
    """CREATE TABLE jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
       pr_number INTEGER NOT NULL, base_sha TEXT NOT NULL, head_sha TEXT NOT NULL, base_ref TEXT NOT NULL DEFAULT '',
       status TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL, started REAL, finished REAL,
       check_run_id INTEGER, conclusion TEXT, blocking INTEGER, findings INTEGER, report TEXT, error TEXT,
       UNIQUE(repo_id, base_sha, head_sha))""",
    "CREATE INDEX jobs_status ON jobs(status, id)",
    "CREATE INDEX jobs_repo ON jobs(repo_id, id DESC)",
]
MAX_ATTEMPTS = 3


class Store:
    def __init__(self, data_dir: str):
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        self.path = os.path.join(data_dir, "sci.db")
        with self._c() as c:
            c.execute("PRAGMA journal_mode=WAL")
            v = c.execute("PRAGMA user_version").fetchone()[0]
            for i in range(v, len(SCHEMA)):
                c.execute(SCHEMA[i])
                c.execute(f"PRAGMA user_version={i + 1}")

    @contextmanager
    def _c(self):
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _tx(self):
        with self._c() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
            except BaseException:
                c.execute("ROLLBACK")
                raise
            c.execute("COMMIT")

    # -- webhooks ---------------------------------------------------------------------------------------------------------------
    def delivery_seen(self, delivery_id: str) -> bool:
        with self._c() as c:
            return c.execute("SELECT 1 FROM deliveries WHERE delivery_id=?", (delivery_id[:100],)).fetchone() is not None

    def record_delivery(self, delivery_id: str) -> bool:
        """Mark a delivery as successfully processed. Called only AFTER processing succeeded, so a failed attempt that GitHub retries is not
        mistaken for a duplicate. False if it was already recorded."""
        with self._c() as c:
            try:
                c.execute("INSERT INTO deliveries VALUES (?,?)", (delivery_id[:100], time.time()))
                return True
            except sqlite3.IntegrityError:
                return False

    def installation_active(self, inst_id: int) -> bool:
        with self._c() as c:
            r = c.execute("SELECT active FROM installations WHERE id=?", (inst_id,)).fetchone()
            return True if r is None else bool(r["active"])  # unknown installations are registered on first use

    def backup(self, dest: str) -> None:
        """Consistent online copy using SQLite's backup API (safe while the server runs and WAL is on; copying sci.db alone is not)."""
        if os.path.exists(dest):
            raise FileExistsError(dest)
        with self._c() as src:
            out = sqlite3.connect(dest)
            try:
                src.backup(out)
            finally:
                out.close()
        os.chmod(dest, 0o600)

    # -- installations / repositories --------------------------------------------------------------------------------------------
    def upsert_installation(self, inst_id: int, account: str, active: bool = True) -> None:
        with self._c() as c:
            c.execute("INSERT INTO installations VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET account=excluded.account, active=excluded.active",
                      (inst_id, account[:200], int(active), time.time()))

    def delete_installation(self, inst_id: int) -> None:
        with self._c() as c:
            c.execute("DELETE FROM installations WHERE id=?", (inst_id,))

    def add_repos(self, inst_id: int, names: list[str], max_repos: int) -> None:
        """Register repositories; those beyond the licence's repository limit are stored but flagged over_limit (never analysed)."""
        with self._tx() as c:
            for n in names:
                if c.execute("SELECT 1 FROM repos WHERE full_name=?", (n,)).fetchone():
                    c.execute("UPDATE repos SET installation_id=? WHERE full_name=?", (inst_id, n))
                    continue
                used = c.execute("SELECT COUNT(*) FROM repos WHERE over_limit=0").fetchone()[0]
                c.execute("INSERT INTO repos (installation_id, full_name, over_limit, created) VALUES (?,?,?,?)", (inst_id, n[:300], int(used >= max_repos), time.time()))

    def remove_repos(self, names: list[str]) -> None:
        with self._c() as c:
            c.executemany("DELETE FROM repos WHERE full_name=?", [(n,) for n in names])

    def apply_limit(self, max_repos: int) -> None:
        """Re-evaluate which repositories are within the licence limit (oldest first) after a licence change."""
        with self._tx() as c:
            ids = [r[0] for r in c.execute("SELECT id FROM repos ORDER BY created, id")]
            for i, rid in enumerate(ids):
                c.execute("UPDATE repos SET over_limit=? WHERE id=?", (int(i >= max_repos), rid))

    def repo(self, full_name: str) -> sqlite3.Row | None:
        with self._c() as c:
            return c.execute("SELECT * FROM repos WHERE full_name=?", (full_name,)).fetchone()

    def set_repo(self, full_name: str, *, enabled: bool | None = None, settings: dict | None = None) -> bool:
        with self._c() as c:
            r = c.execute("SELECT settings FROM repos WHERE full_name=?", (full_name,)).fetchone()
            if not r:
                return False
            if enabled is not None:
                c.execute("UPDATE repos SET enabled=? WHERE full_name=?", (int(enabled), full_name))
            if settings is not None:
                merged = {**json.loads(r["settings"]), **settings}
                c.execute("UPDATE repos SET settings=? WHERE full_name=?", (json.dumps(merged), full_name))
            return True

    def repos(self) -> list[sqlite3.Row]:
        with self._c() as c:
            return c.execute("""SELECT r.*, i.account, (SELECT conclusion FROM jobs j WHERE j.repo_id=r.id AND j.status='done' ORDER BY j.id DESC LIMIT 1) AS last_conclusion,
                                (SELECT COUNT(*) FROM jobs j WHERE j.repo_id=r.id) AS runs FROM repos r JOIN installations i ON i.id=r.installation_id
                                ORDER BY r.full_name""").fetchall()

    # -- jobs -------------------------------------------------------------------------------------------------------------------
    def enqueue(self, repo_id: int, pr: int, base_sha: str, head_sha: str, base_ref: str, *, rerun: bool = False) -> int | None:
        with self._tx() as c:
            row = c.execute("SELECT id, status FROM jobs WHERE repo_id=? AND base_sha=? AND head_sha=?", (repo_id, base_sha, head_sha)).fetchone()
            if row:
                if rerun and row["status"] in ("done", "failed"):
                    c.execute("UPDATE jobs SET status='queued', attempts=0, started=NULL, finished=NULL, error=NULL, check_run_id=NULL WHERE id=?", (row["id"],))
                    return row["id"]
                return None  # same commits already queued/analysed
            cur = c.execute("INSERT INTO jobs (repo_id, pr_number, base_sha, head_sha, base_ref, created) VALUES (?,?,?,?,?,?)",
                            (repo_id, pr, base_sha, head_sha, base_ref[:200], time.time()))
            return cur.lastrowid

    def claim(self) -> sqlite3.Row | None:
        with self._tx() as c:
            row = c.execute("""SELECT j.*, r.full_name, r.settings, r.installation_id FROM jobs j JOIN repos r ON r.id=j.repo_id JOIN installations i ON i.id=r.installation_id
                               WHERE j.status='queued' AND r.enabled=1 AND r.over_limit=0 AND i.active=1 ORDER BY j.id LIMIT 1""").fetchone()
            if not row:
                return None
            c.execute("UPDATE jobs SET status='running', started=?, attempts=attempts+1 WHERE id=?", (time.time(), row["id"]))
            return row

    def set_check_run(self, job_id: int, check_run_id: int) -> None:
        with self._c() as c:
            c.execute("UPDATE jobs SET check_run_id=? WHERE id=?", (check_run_id, job_id))

    def finish(self, job_id: int, conclusion: str, blocking: int, findings: int, report: str | None, error: str | None = None) -> None:
        with self._c() as c:
            c.execute("UPDATE jobs SET status='done', finished=?, conclusion=?, blocking=?, findings=?, report=?, error=? WHERE id=?",
                      (time.time(), conclusion, blocking, findings, report, error, job_id))

    def fail(self, job_id: int, error: str, retry: bool) -> None:
        with self._c() as c:
            row = c.execute("SELECT attempts FROM jobs WHERE id=?", (job_id,)).fetchone()
            if retry and row and row["attempts"] < MAX_ATTEMPTS:
                c.execute("UPDATE jobs SET status='queued', error=? WHERE id=?", (error[:2000], job_id))
            else:
                c.execute("UPDATE jobs SET status='failed', finished=?, error=? WHERE id=?", (time.time(), error[:2000], job_id))

    def requeue_stale(self, older_than: float) -> int:
        """Jobs left 'running' by a crashed process go back to the queue (bounded by MAX_ATTEMPTS)."""
        with self._c() as c:
            cur = c.execute("UPDATE jobs SET status='queued' WHERE status='running' AND started<? AND attempts<?", (time.time() - older_than, MAX_ATTEMPTS))
            c.execute("UPDATE jobs SET status='failed', finished=?, error='worker stopped repeatedly' WHERE status='running' AND started<? AND attempts>=?",
                      (time.time(), time.time() - older_than, MAX_ATTEMPTS))
            return cur.rowcount

    def job(self, job_id: int) -> sqlite3.Row | None:
        with self._c() as c:
            return c.execute("SELECT j.*, r.full_name FROM jobs j JOIN repos r ON r.id=j.repo_id WHERE j.id=?", (job_id,)).fetchone()

    def runs(self, limit: int = 50, repo: str | None = None) -> list[sqlite3.Row]:
        with self._c() as c:
            q = "SELECT j.id, j.pr_number, j.head_sha, j.status, j.conclusion, j.blocking, j.findings, j.created, j.finished, j.error, r.full_name FROM jobs j JOIN repos r ON r.id=j.repo_id"
            args: tuple = ()
            if repo:
                q += " WHERE r.full_name=?"
                args = (repo,)
            return c.execute(q + " ORDER BY j.id DESC LIMIT ?", (*args, limit)).fetchall()

    def counts(self) -> dict[str, int]:
        with self._c() as c:
            return {r[0]: r[1] for r in c.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status")}

    def prune(self, days: int) -> int:
        cutoff = time.time() - days * 86400
        with self._c() as c:
            c.execute("DELETE FROM deliveries WHERE received<?", (time.time() - 7 * 86400,))
            return c.execute("DELETE FROM jobs WHERE finished IS NOT NULL AND finished<?", (cutoff,)).rowcount
