"""Pre-release simulation: run the project's own tests on the base revision and on the pull request, and report what the change breaks.

This is the only check that EXECUTES repository code, so it is opt-in (`--checks sim` with a command given by the operator, never read from
the repository's own config) and meant for CI. The command runs without a shell, in a throw-away git worktree, with a scrubbed environment
(no tokens, a temporary HOME), in its own process group, with a time limit and bounded output.

SIM101 (CONFIRMED, blocks): a test that passed on the base revision fails on the head, and failed again on a second run of the head.
SIM102 (CONFIRMED, warning): a test added by the pull request fails.
SIM103 (POSSIBLE): failed once and passed on re-run (flaky), so not attributed to the change.
SIM901/SIM902 (UNKNOWN): the run produced no results / hit the time limit: nothing is proven either way."""
from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from dci import gitutil
from dci.config import Config, ConfigError
from dci.models import Confidence, Coverage, Finding, Reference, Severity
from dci.redact import redact

MAX_JUNIT_BYTES = 200_000_000
MAX_TESTS = 2_000_000
MAX_OUTPUT = 1_000_000
KEEP_ENV = ("PATH", "LANG", "LC_ALL", "TZ", "VIRTUAL_ENV", "CI", "TMPDIR", "SYSTEMROOT")
FINDINGS_CAP = 25


@dataclass
class Run:
    results: dict[str, tuple[str, str, str]] = field(default_factory=dict)  # test id -> (status, file, message)
    exit_code: int | None = None
    timed_out: bool = False
    seconds: float = 0.0
    tail: str = ""
    parsed: bool = False


def parse_junit(path: str) -> dict[str, tuple[str, str, str]]:
    size = os.path.getsize(path)
    if size > MAX_JUNIT_BYTES:
        raise ValueError("result file is too large")
    with open(path, "rb") as fh:
        data = fh.read()
    if b"<!ENTITY" in data or b"<!DOCTYPE" in data:  # entity expansion is never needed in a result file
        raise ValueError("result file declares a DTD/entities")
    root = ET.fromstring(data)
    out: dict[str, tuple[str, str, str]] = {}
    for tc in root.iter("testcase"):
        if len(out) >= MAX_TESTS:
            raise ValueError("too many test cases")
        tid = f"{tc.get('classname', '')}::{tc.get('name', '')}"
        status, msg = "passed", ""
        for child in tc:
            if child.tag in ("failure", "error"):
                status, msg = "failed", (child.get("message") or (child.text or ""))[:300]
                break
            if child.tag == "skipped":
                status = "skipped"
        file = tc.get("file") or (tc.get("classname", "").replace(".", "/") + ".py" if tc.get("classname") else "")
        if tid in out and out[tid][0] == "failed":  # a duplicate id never hides a failure
            continue
        out[tid] = (status, file, msg)
    return out


def _env(extra: list[str], home: str) -> dict[str, str]:
    env = {k: os.environ[k] for k in KEEP_ENV if k in os.environ}
    for k in extra:
        if k in os.environ:
            env[k] = os.environ[k]
    env.setdefault("HOME", home)
    if "HOME" not in extra:
        env["HOME"] = home
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _execute(cmd: list[str], cwd: str, cfg: Config, label: str) -> Run:
    run = Run()
    scratch = tempfile.mkdtemp(prefix="sci-sim-")
    junit = os.path.join(scratch, "results.xml")
    argv = [a.replace("{junit}", junit) for a in cmd]
    log = os.path.join(scratch, "out.log")
    t0 = time.monotonic()
    try:
        with open(log, "wb") as out:
            p = subprocess.Popen(argv, cwd=cwd, env=_env(cfg.sim_env, os.path.join(scratch, "home")), stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                 start_new_session=True)
            try:
                run.exit_code = p.wait(timeout=cfg.sim_timeout or None)
            except subprocess.TimeoutExpired:
                run.timed_out = True
                if hasattr(os, 'killpg') and hasattr(signal, 'SIGKILL'):
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except (ProcessLookupError, OSError):
                        pass
                else:
                    try:
                        p.kill()
                    except OSError:
                        pass
                p.wait()
        run.seconds = time.monotonic() - t0
        with open(log, "rb") as fh:
            fh.seek(max(0, os.path.getsize(log) - 2000))
            run.tail = fh.read().decode("utf-8", "replace")
        if os.path.exists(junit):
            try:
                run.results = parse_junit(junit)
                run.parsed = True
            except (ET.ParseError, ValueError) as e:
                run.tail = f"result file could not be read: {e}\n" + run.tail
    except FileNotFoundError:
        raise ConfigError(f"Test command not found: {cmd[0]}") from None
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return run


def _worktree(repo: str, sha: str, root: str, name: str) -> str:
    path = os.path.join(root, name)
    gitutil.run_git(repo, "worktree", "add", "--detach", "--force", path, sha)
    return path


def _ref(test: str, file: str, msg: str, conf: Confidence) -> Reference:
    return Reference(None, None, file or test, 1, "head", "test_result", "ref", conf, redact(msg or "test failed"), note=test)


def run(cfg: Config, cov: Coverage) -> list[Finding]:
    if not cfg.sim_command:
        raise ConfigError("The sim check runs your tests: give the command with --sim-command (for example 'pytest -q --junitxml={junit}')")
    if not any("{junit}" in a for a in cfg.sim_command):
        raise ConfigError("--sim-command must contain {junit}, the path where the test runner writes its JUnit XML results")
    repo = os.path.realpath(cfg.repo)
    if not cfg.base or not gitutil.is_repo(repo):
        raise ConfigError("The sim check needs a git repository and --base REV")
    head_sha = gitutil.rev_sha(repo, cfg.head or "HEAD")
    base_sha = gitutil.merge_base(repo, cfg.base, cfg.head or "HEAD")
    root = tempfile.mkdtemp(prefix="sci-wt-")
    findings: list[Finding] = []
    trees: list[str] = []
    try:
        base_dir, head_dir = _worktree(repo, base_sha, root, "base"), _worktree(repo, head_sha, root, "head")
        trees = [base_dir, head_dir]
        base = _execute(cfg.sim_command, base_dir, cfg, "base")
        head = _execute(cfg.sim_command, head_dir, cfg, "head")
        cov.notes.append(f"Simulation: base ran {len(base.results)} test(s) in {base.seconds:.0f}s, head ran {len(head.results)} in {head.seconds:.0f}s")
        for name, r in (("base", base), ("head", head)):
            if r.timed_out:
                findings.append(Finding("SIM902", Severity.WARNING, Confidence.UNKNOWN, "Test run hit the time limit",
                                        f"The tests on the {name} revision did not finish within {cfg.sim_timeout:.0f}s, so nothing is proven about this change.", None))
            elif not r.parsed:
                findings.append(Finding("SIM901", Severity.WARNING, Confidence.UNKNOWN, "Test run produced no results",
                                        f"The command produced no readable JUnit results on the {name} revision (exit code {r.exit_code}). Last output: {redact(r.tail.strip()[-500:])}", None))
        if not (base.parsed and head.parsed) or base.timed_out or head.timed_out:
            return [f for f in findings if f.rule_id not in cfg.ignore_rules]
        new_fail = sorted(t for t, (s, *_r) in head.results.items() if s == "failed" and base.results.get(t, ("",))[0] == "passed")
        added_fail = sorted(t for t, (s, *_r) in head.results.items() if s == "failed" and t not in base.results)
        if new_fail or added_fail:
            again = _execute(cfg.sim_command, head_dir, cfg, "head-rerun")
            stable = lambda t: again.parsed and again.results.get(t, ("",))[0] == "failed"  # noqa: E731
        else:
            stable = lambda t: False  # noqa: E731
        for t in new_fail:
            _s, file, msg = head.results[t]
            if stable(t):
                findings.append(Finding("SIM101", Severity.ERROR, Confidence.CONFIRMED, "Test that passed before now fails",
                                        f"{t} passed on the base revision and fails with this pull request (twice).", None, [_ref(t, file, msg, Confidence.CONFIRMED)],
                                        ["Run this test on the pull request branch to see the failure; fix the code or update the test if the behaviour change is intended."],
                                        total_evidence=1, file=file, line=1))
            else:
                findings.append(Finding("SIM103", Severity.WARNING, Confidence.POSSIBLE, "Test failed once, then passed",
                                        f"{t} failed on the pull request but passed on a re-run, so it is flaky and not attributed to the change.", None,
                                        [_ref(t, file, msg, Confidence.POSSIBLE)], total_evidence=1, file=file, line=1))
        for t in added_fail:
            _s, file, msg = head.results[t]
            if stable(t):
                findings.append(Finding("SIM102", Severity.WARNING, Confidence.CONFIRMED, "A test added by this pull request fails",
                                        f"{t} is new in this pull request and fails.", None, [_ref(t, file, msg, Confidence.CONFIRMED)], total_evidence=1, file=file, line=1))
        still = sum(1 for t, (s, *_r) in head.results.items() if s == "failed" and base.results.get(t, ("",))[0] == "failed")
        if still:
            cov.notes.append(f"{still} test(s) were already failing on the base revision and are not attributed to this change")
        if len(findings) > FINDINGS_CAP:
            extra = len(findings) - FINDINGS_CAP
            findings = findings[:FINDINGS_CAP] + [Finding("SIM104", Severity.INFO, Confidence.CONFIRMED, "More failing tests",
                                                          f"{extra} further test(s) changed status; only the first {FINDINGS_CAP} findings are listed.", None)]
        return [f for f in findings if f.rule_id not in cfg.ignore_rules]
    finally:
        for d in trees:
            try:
                gitutil.run_git(repo, "worktree", "remove", "--force", d)
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(root, ignore_errors=True)
        try:
            gitutil.run_git(repo, "worktree", "prune")
        except Exception:  # noqa: BLE001
            pass
