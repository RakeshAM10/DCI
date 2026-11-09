"""Executes one analysis job: clone, run `sci` in a resource-limited subprocess, turn the report into a GitHub check result.

Trust model (same as the GitHub Action): the repository is analysed as data and never executed; the `.dci.toml` that applies is the one on the
PR's BASE commit, so a pull request cannot loosen its own checks; consumer repositories outside the clone are refused (--workspace)."""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile

try:
    import resource
except ImportError:
    resource = None

from sci.run import ALL_CHECKS

from .github import valid_repo

CHECK_NAME = "SCI change check"
SHA_LEN = (40, 64)


class JobError(RuntimeError):
    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


def _is_sha(s: str) -> bool:
    return len(s) in SHA_LEN and all(c in "0123456789abcdef" for c in s)


def _git_env(token: str | None) -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": tempfile.gettempdir(), "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    for k in ("SystemRoot", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "WINDIR", "TEMP", "TMP"):
        if k in os.environ:
            env[k] = os.environ[k]
    if token:  # via environment, never argv, so it is not visible in the process list
        import base64
        env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraheader",
                    "GIT_CONFIG_VALUE_0": "Authorization: Basic " + base64.b64encode(f"x-access-token:{token}".encode()).decode()})
    return env


def _git(args: list[str], env: dict, cwd: str | None = None, timeout: int = 600) -> str:
    try:
        p = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise JobError("git timed out", retryable=True) from None
    if p.returncode != 0:
        err = p.stderr.decode("utf-8", "replace")
        if token_leak := env.get("GIT_CONFIG_VALUE_0"):
            err = err.replace(token_leak, "***")
        raise JobError(f"git {args[0]} failed: {err.strip()[:300]}", retryable=True)
    return p.stdout.decode("utf-8", "replace")


def _has(workdir: str, sha: str, env: dict) -> bool:
    try:
        _git(["cat-file", "-e", f"{sha}^{{commit}}"], env, workdir, 60)
        return True
    except JobError:
        return False


def prepare(workdir: str, clone_url: str, token: str | None, pr: int, base_sha: str, head_sha: str) -> None:
    env = _git_env(token)
    _git(["clone", "--quiet", "--no-checkout", "--filter=blob:none", "--no-tags", clone_url, workdir], env)
    if not _has(workdir, head_sha, env):  # the head commit of a fork PR is only reachable through GitHub's pull ref
        _git(["fetch", "--quiet", "--no-tags", "--filter=blob:none", "origin", f"+refs/pull/{int(pr)}/head:refs/sci/head"], env, workdir)
    if not _has(workdir, base_sha, env):
        _git(["fetch", "--quiet", "--no-tags", "--filter=blob:none", "origin", base_sha], env, workdir)
    for sha in (base_sha, head_sha):
        if not _has(workdir, sha, env):
            raise JobError(f"commit {sha[:12]} is not available from the repository (force-pushed or deleted?)")


def _limits(mem_mb: int, cpu_s: int):
    def apply():
        if resource is not None:
            resource.setrlimit(resource.RLIMIT_AS, (mem_mb * 1024 * 1024,) * 2)
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 10))
            resource.setrlimit(resource.RLIMIT_NPROC, (512, 512))
            resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024 * 1024,) * 2)  # no single file larger than 512MB
        if hasattr(os, "setsid"):
            os.setsid()
    return apply


def run_limited(cmd: list[str], env: dict, cwd: str, timeout: int, mem_mb: int) -> tuple[int, bytes]:
    """Run cmd as the leader of its own process group with resource limits; on timeout kill the whole group (children included)."""
    preexec = _limits(mem_mb, timeout) if (resource is not None or hasattr(os, "setsid")) and os.name != "nt" else None
    proc = subprocess.Popen(cmd, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=preexec)
    try:
        _, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if hasattr(os, "killpg") and hasattr(signal, "SIGKILL"):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
        else:
            try:
                proc.kill()
            except OSError:
                pass
        proc.communicate()
        raise JobError("analysis timed out") from None
    return proc.returncode, stderr


def analyse(workdir: str, base_sha: str, head_sha: str, settings: dict, timeout: int, mem_mb: int) -> dict:
    """Run sci and return the parsed JSON report. Exit 0 and 1 are results; anything else is an error, never a pass."""
    checks = [c for c in settings.get("checks", ALL_CHECKS) if c in ALL_CHECKS]  # 'sim' executes repository code and is never allowed here
    if not checks:
        raise JobError("no valid checks configured for this repository")
    scratch = tempfile.mkdtemp(prefix="sci-run-")
    try:
        out = os.path.join(scratch, "report.json")
        cmd = [sys.executable, "-m", "sci", "--repo", workdir, "--base", base_sha, "--head", head_sha, "--format", "json", "--output", out,
               "--workspace", workdir, "--checks", ",".join(checks), "--time-budget", str(max(30, timeout - 60))]
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": scratch, "LC_ALL": "C", "PYTHONPATH": os.environ.get("PYTHONPATH", "")}
        for k in ("SystemRoot", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "WINDIR", "TEMP", "TMP"):
            if k in os.environ:
                env[k] = os.environ[k]
        git_env = _git_env(None)
        try:  # configuration comes from the base commit, never from the pull request
            cfg = subprocess.run(["git", "show", f"{base_sha}:.dci.toml"], cwd=workdir, env=git_env, capture_output=True, timeout=60, check=False)
        except subprocess.TimeoutExpired:
            raise JobError("git timed out reading configuration", retryable=True) from None
        if cfg.returncode == 0 and cfg.stdout:
            cfg_path = os.path.join(scratch, "base.dci.toml")
            with open(cfg_path, "wb") as fh:
                fh.write(cfg.stdout[:1_000_000])
            cmd += ["--config", cfg_path]
        if settings.get("fail_on") in ("error", "warning", "never"):
            cmd += ["--fail-on", settings["fail_on"]]
        returncode, stderr = run_limited(cmd, env, scratch, timeout, mem_mb)
        if returncode not in (0, 1) or not os.path.exists(out):
            raise JobError(f"analysis failed (exit {returncode}): {stderr.decode('utf-8', 'replace').strip()[-300:]}")
        with open(out, "rb") as fh:
            data = fh.read(100_000_001)
        if len(data) > 100_000_000:
            raise JobError("report too large")
        rep = json.loads(data)
        if not isinstance(rep, dict) or not isinstance(rep.get("findings"), list):
            raise JobError("analysis produced an invalid report")
        return rep
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def conclusion_of(rep: dict) -> str:
    if int(rep.get("blocking_count") or 0) > 0:
        return "failure"
    cov = rep.get("coverage") or {}
    unverified = any(str(f.get("rule_id", "")).endswith(("901", "902")) for f in rep["findings"])
    return "neutral" if cov.get("scan_incomplete") or unverified else "success"


def summarise(rep: dict, conclusion: str) -> tuple[str, str, str, list[dict]]:
    fs = rep["findings"]
    n = {"confirmed": 0, "possible": 0, "unknown": 0}
    for f in fs:
        n[f.get("confidence", "unknown")] = n.get(f.get("confidence", "unknown"), 0) + 1
    blocking = int(rep.get("blocking_count") or 0)
    title = {"failure": f"{blocking} confirmed breaking change{'s' if blocking != 1 else ''}", "neutral": "Some changes could not be verified",
             "success": "No breaking changes found"}[conclusion]
    summary = f"**{title}.** {n['confirmed']} confirmed, {n['possible']} possible, {n['unknown']} unknown. Only confirmed findings can block a merge."
    lines, ann = [], []
    for f in fs[:100]:
        loc = f"{f.get('file')}:{f.get('line')}" if f.get("file") else ""
        lines.append(f"### {f.get('title', f.get('rule_id'))} (`{f.get('rule_id')}`, {f.get('confidence')}) {loc}\n\n{f.get('message', '')}\n")
        for e in (f.get("evidence") or [])[:3]:
            lines.append(f"- `{e.get('file')}:{e.get('line')}` `{str(e.get('snippet', ''))[:120]}`")
        if f.get("file") and f.get("line") and len(ann) < 200:
            level = "failure" if f.get("confidence") == "confirmed" and f.get("severity") == "error" else "warning" if f.get("severity") != "info" else "notice"
            ann.append({"path": f["file"], "start_line": int(f["line"]), "end_line": int(f["line"]), "annotation_level": level,
                        "title": f"{f.get('rule_id')} {f.get('title', '')}"[:255], "message": str(f.get("message", ""))[:60000]})
    return title, summary, "\n".join(lines) or "No findings.", ann


def run_job(job: dict, clone_url: str, token: str | None, timeout: int, mem_mb: int, data_dir: str) -> dict:
    if not valid_repo(job["full_name"]) or not (_is_sha(job["base_sha"]) and _is_sha(job["head_sha"])):
        raise JobError("refusing a job with an invalid repository name or commit id")
    work_root = os.path.join(data_dir, "work")
    os.makedirs(work_root, mode=0o700, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix=f"job{job['id']}-", dir=work_root)
    try:
        prepare(os.path.join(workdir, "repo"), clone_url, token, job["pr_number"], job["base_sha"], job["head_sha"])
        return analyse(os.path.join(workdir, "repo"), job["base_sha"], job["head_sha"], json.loads(job.get("settings") or "{}"), timeout, mem_mb)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
