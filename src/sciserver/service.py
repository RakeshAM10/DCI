"""Business logic: licence state, webhook event handling, and job processing. No HTTP in here, so it is testable on its own."""
from __future__ import annotations

import datetime as dt
import json
import threading
import time
from dataclasses import dataclass

from . import licence as lic
from .config import Settings
from .github import GitHub, GitHubError, valid_repo
from .runner import CHECK_NAME, JobError, conclusion_of, run_job, summarise
from .store import MAX_ATTEMPTS, Store

PR_ACTIONS = {"opened", "reopened", "synchronize", "ready_for_review"}


@dataclass(frozen=True)
class LicenceState:
    kind: str  # community | valid | expired | invalid
    max_repos: int
    customer: str = ""
    expires: str = ""
    message: str = ""


def licence_state(s: Settings, today: dt.date | None = None) -> LicenceState:
    if not s.licence_token:
        return LicenceState("community", s.community_max_repos, message=f"No licence: community limit of {s.community_max_repos} repositories.")
    if not s.licence_public_key:
        return LicenceState("invalid", s.community_max_repos, message="A licence is set but SCI_LICENCE_PUBLIC_KEY is not.")
    try:
        l = lic.verify(s.licence_token, s.licence_public_key)
    except lic.LicenceError as e:
        return LicenceState("invalid", s.community_max_repos, message=f"Licence rejected: {e}. Community limits apply.")
    if l.expired(today):
        return LicenceState("expired", l.max_repos, l.customer, l.expires.isoformat(), "Licence expired: checks report neutral until it is renewed. Merges are not blocked.")
    return LicenceState("valid", l.max_repos, l.customer, l.expires.isoformat(), f"{l.days_left(today)} days left.")


class Service:
    def __init__(self, settings: Settings, store: Store | None = None, github: GitHub | None = None):
        self.s = settings
        self.store = store or Store(settings.data_dir)
        self.github = github or GitHub(settings.github_api, settings.app_id, settings.private_key_pem)
        self.licence = licence_state(settings)
        self.store.apply_limit(self.licence.max_repos)
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []

    # -- webhook events -----------------------------------------------------------------------------------------------------------
    def handle_event(self, event: str, delivery: str, p: dict) -> tuple[int, str]:
        """Returns (http status, message). Called only after the signature has been verified."""
        if not delivery:
            return 400, "missing delivery id"
        if self.store.delivery_seen(delivery):
            return 200, "duplicate delivery ignored"
        try:
            code, msg = self._dispatch(event, p)
        except (KeyError, TypeError, ValueError, AttributeError):
            self.store.record_delivery(delivery)  # malformed: retrying the same bytes cannot help
            return 400, "malformed payload"
        except Exception:  # noqa: BLE001 - e.g. the database was busy: NOT recorded, so GitHub's redelivery is processed
            return 503, "temporary failure, please redeliver"
        self.store.record_delivery(delivery)
        return code, msg

    def _dispatch(self, event: str, p: dict) -> tuple[int, str]:
        if event == "ping":
            return 200, "pong"
        if event == "installation":
            return self._installation(p)
        if event == "installation_repositories":
            return self._installation_repos(p)
        if event == "pull_request":
            return self._pull_request(p)
        if event in ("check_run", "check_suite") and p.get("action") == "rerequested":
            return self._rerequest(event, p)
        return 200, f"event {event} ignored"

    def _names(self, items) -> list[str]:
        return [r["full_name"] for r in (items or []) if isinstance(r, dict) and valid_repo(str(r.get("full_name", "")))]

    def _installation(self, p: dict) -> tuple[int, str]:
        inst = int(p["installation"]["id"])
        action = p.get("action")
        if action == "deleted":
            self.store.delete_installation(inst)
            return 200, "installation removed"
        if action in ("created", "unsuspend", "new_permissions_accepted"):
            self.store.upsert_installation(inst, str(p["installation"]["account"]["login"]), True)
            self.store.add_repos(inst, self._names(p.get("repositories")), self.licence.max_repos)
            return 200, "installation registered"
        if action == "suspend":
            self.store.upsert_installation(inst, str(p["installation"]["account"]["login"]), False)
        return 200, f"installation {action}"

    def _installation_repos(self, p: dict) -> tuple[int, str]:
        inst = int(p["installation"]["id"])
        self.store.upsert_installation(inst, str(p["installation"]["account"]["login"]), True)
        self.store.add_repos(inst, self._names(p.get("repositories_added")), self.licence.max_repos)
        self.store.remove_repos(self._names(p.get("repositories_removed")))
        return 200, "repositories updated"

    def _queue(self, inst: int, account: str, repo: str, pr: int, base_sha: str, head_sha: str, base_ref: str, rerun: bool) -> tuple[int, str]:
        if not valid_repo(repo):
            return 400, "invalid repository name"
        if not self.store.installation_active(inst):
            return 200, "installation is suspended"
        row = self.store.repo(repo)
        if not row:  # a delivery for a repository we have not seen (e.g. a missed installation event)
            self.store.upsert_installation(inst, account, True)
            self.store.add_repos(inst, [repo], self.licence.max_repos)
            row = self.store.repo(repo)
        if not row["enabled"]:
            return 200, "repository disabled"
        if row["over_limit"]:
            return 200, "repository is over the licence limit"
        job = self.store.enqueue(row["id"], pr, base_sha, head_sha, base_ref, rerun=rerun)
        return 202, f"queued job {job}" if job else "already queued or analysed"

    def _pull_request(self, p: dict) -> tuple[int, str]:
        if p.get("action") not in PR_ACTIONS:
            return 200, "pull_request action ignored"
        pr = p["pull_request"]
        return self._queue(int(p["installation"]["id"]), str(p["repository"]["owner"]["login"]), p["repository"]["full_name"], int(pr["number"]),
                           pr["base"]["sha"], pr["head"]["sha"], pr["base"]["ref"], False)

    def _rerequest(self, event: str, p: dict) -> tuple[int, str]:
        suite = p["check_suite"] if event == "check_suite" else p["check_run"]["check_suite"]
        prs = suite.get("pull_requests") or []
        if not prs:
            return 200, "no pull request attached"
        pr = prs[0]
        return self._queue(int(p["installation"]["id"]), str(p["repository"]["owner"]["login"]), p["repository"]["full_name"], int(pr["number"]),
                           pr["base"]["sha"], pr["head"]["sha"], pr["base"]["ref"], True)

    # -- jobs ---------------------------------------------------------------------------------------------------------------------
    def process(self, job) -> None:
        j = dict(job)
        repo = j["full_name"]
        try:
            token = self.github.installation_token(j["installation_id"])
            check_id = j["check_run_id"]  # a retry completes the check run its first attempt created
            if not check_id:
                check_id = self.github.create_check_run(token, repo, j["head_sha"], CHECK_NAME, f"sci-job-{j['id']}")
                self.store.set_check_run(j["id"], check_id)
        except GitHubError as e:
            self.store.fail(j["id"], str(e), retry=e.retryable)
            return
        try:
            if self.licence.kind == "expired":
                self.github.complete_check_run(token, repo, check_id, "neutral", "Licence expired", self.licence.message, "", [])
                self.store.finish(j["id"], "neutral", 0, 0, None, "licence expired")
                return
            rep = run_job(j, self.s.clone_url_template.format(repo=repo), token, self.s.job_timeout, self.s.job_memory_mb, self.s.data_dir)
            conclusion = conclusion_of(rep)
            title, summary, text, ann = summarise(rep, conclusion)
            self.github.complete_check_run(token, repo, check_id, conclusion, title, summary, text, ann)
            self.store.finish(j["id"], conclusion, int(rep.get("blocking_count") or 0), len(rep["findings"]), json.dumps(rep))
        except JobError as e:
            self.store.fail(j["id"], str(e), retry=e.retryable)
            self._close_if_failed(j["id"], token)
        except GitHubError as e:
            self.store.fail(j["id"], str(e), retry=e.retryable)
            self._close_if_failed(j["id"], token)

    def _close_if_failed(self, job_id: int, token: str | None = None) -> None:
        """A job that has given up must never leave its check 'in progress' (or look like a pass): complete it as neutral and say why."""
        job = self.store.job(job_id)
        if not job or job["status"] != "failed" or not job["check_run_id"]:
            return
        try:
            token = token or self.github.installation_token(self.store.repo(job["full_name"])["installation_id"])
        except GitHubError:
            return
        self._neutral(token, job["full_name"], job["check_run_id"], f"SCI could not analyse this pull request: {job['error']}")

    def _neutral(self, token: str, repo: str, check_id: int, why: str) -> None:
        try:
            self.github.complete_check_run(token, repo, check_id, "neutral", "Not analysed", why, "", [])
        except GitHubError:
            pass

    def worker(self) -> None:
        while not self.stop.is_set():
            job = self.store.claim()
            if job is None:
                self.stop.wait(1.0)
                continue
            try:
                self.process(job)
            except Exception as e:  # noqa: BLE001 - one bad job must not kill the worker
                self.store.fail(job["id"], f"internal error: {e.__class__.__name__}", retry=True)
                self._close_if_failed(job["id"])

    def start(self) -> None:
        self.store.requeue_stale(self.s.job_timeout * 2)
        for i in range(self.s.workers):
            t = threading.Thread(target=self.worker, name=f"sci-worker-{i}", daemon=True)
            t.start()
            self.threads.append(t)
        t = threading.Thread(target=self._maintenance, name="sci-maintenance", daemon=True)
        t.start()
        self.threads.append(t)

    def _maintenance(self) -> None:
        while not self.stop.wait(300):
            self.store.requeue_stale(self.s.job_timeout * 2)
            self.store.prune(self.s.retention_days)

    def shutdown(self) -> None:
        self.stop.set()
        for t in self.threads:
            t.join(timeout=self.s.job_timeout + 30 if t.name.startswith("sci-worker") else 5)
