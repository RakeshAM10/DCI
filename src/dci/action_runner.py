"""GitHub Action entrypoint.

Security model: every action input arrives as an environment variable (INPUT_*) that action.yml maps explicitly.
Nothing from a workflow, branch name or PR is ever interpolated into a shell command. All values are validated here.
Exit codes: 0 pass (or skipped), 1 blocking findings, 2 configuration/usage error, 3 internal error (fail closed)."""
from __future__ import annotations

import os
import re
import sys
import tempfile

from . import __version__, gitutil, report
from .analyze import analyze
from .config import Config, ConfigError, load_file, load_text
from .gitutil import GitError
from .github import GitHubError, upsert_comment
from .models import Finding, Severity

_REF = re.compile(r"^[A-Za-z0-9._/\-]+$")
_CONSUMER = re.compile(r"^([A-Za-z0-9._\-]+)=(.+)$")
MAX_ANNOTATIONS = 50
MAX_SUMMARY = 900_000


def _in(name: str, default: str = "") -> str:
    return os.environ.get("INPUT_" + name.upper().replace("-", "_"), default).strip()


def _bool(name: str, default: bool) -> bool:
    v = _in(name).lower()
    if v == "":
        return default
    if v in ("true", "1", "yes"):
        return True
    if v in ("false", "0", "no"):
        return False
    raise ConfigError(f"Input '{name}' must be true or false")


def escape_data(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_prop(s: str) -> str:
    return escape_data(s).replace(":", "%3A").replace(",", "%2C")


def annotation(f: Finding, blocking: bool) -> str | None:
    if f.severity == Severity.INFO:
        return None
    level = "error" if (blocking or f.severity == Severity.ERROR) else "warning"
    props = []
    if f.file:
        props.append(f"file={escape_prop(f.file)}")
        props.append(f"line={max(1, f.line)}")
    props.append(f"title={escape_prop(f'{f.rule_id} {f.title} ({f.confidence.value})')}")
    return f"::{level} {','.join(props)}::{escape_data(f.message)}"


def _inside(root: str, p: str, what: str) -> str:
    full = os.path.realpath(p if os.path.isabs(p) else os.path.join(root, p))
    if not (full == root or full.startswith(root + os.sep)):
        raise ConfigError(f"{what} must be inside the workspace: {p}")
    return full


def parse_consumers(raw: str, workspace: str) -> list[tuple[str, str]]:
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _CONSUMER.match(line)
        if not m:
            raise ConfigError(f"consumer-repos entries must look like NAME=PATH, got: {line!r}")
        path = _inside(workspace, m.group(2).strip(), f"consumer repository '{m.group(1)}'")
        if not os.path.isdir(path):
            raise ConfigError(f"consumer repository '{m.group(1)}' not found at {m.group(2).strip()} (did you check it out?)")
        out.append((m.group(1), path))
    return out


def prepare_history(repo: str, base_ref: str) -> None:
    """A merge-base needs history. Shallow clones (the actions/checkout default) are deepened; the base branch is fetched."""
    try:
        if gitutil.run_git(repo, "rev-parse", "--is-shallow-repository").decode().strip() == "true":
            gitutil.run_git(repo, "fetch", "--no-tags", "--prune", "--unshallow", "origin")
    except GitError as e:
        print(f"::warning::Could not fetch full history ({e}); the merge-base may be wrong. Use actions/checkout with fetch-depth: 0.")
    remote_ref = f"origin/{base_ref}"
    try:
        gitutil.rev_sha(repo, remote_ref)
    except GitError:
        try:
            gitutil.run_git(repo, "fetch", "--no-tags", "origin", f"+refs/heads/{base_ref}:refs/remotes/origin/{base_ref}")
        except GitError as e:
            raise ConfigError(f"Base branch '{base_ref}' is not available: {e}") from e


def _write_output(pairs: dict[str, str]) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for k, v in pairs.items():
            if "\n" in v or "\r" in v:
                raise ValueError("output values must be single-line")
            fh.write(f"{k}={v}\n")


def main() -> int:
    try:
        return _run()
    except ConfigError as e:
        print(f"::error title=DCI configuration error::{escape_data(str(e))}")
        return 2
    except GitError as e:
        print(f"::error title=DCI git error::{escape_data(str(e))}")
        return 2
    except Exception as e:  # fail closed
        if os.environ.get("DCI_DEBUG"):
            raise
        print(f"::error title=DCI internal error::{escape_data(e.__class__.__name__ + ': ' + str(e))}")
        return 3


def _run() -> int:
    workspace = os.path.realpath(os.environ.get("GITHUB_WORKSPACE") or os.getcwd())
    base_ref = _in("base-ref") or os.environ.get("GITHUB_BASE_REF", "").strip()
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    if not base_ref:
        print(f"::notice title=DCI skipped::No base branch: DCI analyses pull requests (event was '{event or 'unknown'}'). "
              "Set the 'base-ref' input to run it on another event.")
        _write_output({"verdict": "skipped", "blocking-count": "0"})
        return 0
    if not _REF.match(base_ref) or base_ref.startswith("-") or ".." in base_ref:
        raise ConfigError(f"Unsafe base branch name: {base_ref!r}")

    repo = _inside(workspace, _in("working-directory") or ".", "working-directory")
    cfg = Config(repo=repo, workspace=workspace)  # analyze() rejects any repo/consumer path (from any source) outside it
    cfg_in = _in("config")
    cfg_path = _inside(workspace, cfg_in, "config") if cfg_in else os.path.join(repo, ".dci.toml")
    prepare_history(repo, base_ref)
    config_notes: list[str] = []
    if _bool("trust-pr-config", False):
        if cfg_in and not os.path.isfile(cfg_path):
            raise ConfigError(f"Config file not found: {cfg_in}")
        if os.path.isfile(cfg_path):
            load_file(cfg_path, cfg)
        config_notes.append("DCI configuration was read from the pull request (trust-pr-config=true): the PR author can change it.")
    else:
        # The PR author controls the working tree, so settings that decide whether the check passes (fail_on, ignore_rules,
        # ignore_paths, migration_globs, consumer paths) come from the BASE branch, as committed there.
        rel = os.path.relpath(cfg_path, repo).replace(os.sep, "/")
        if rel.startswith(".."):
            raise ConfigError("The config file must be inside the working directory (or set trust-pr-config=true).")
        base_raw = gitutil.show_file(repo, f"origin/{base_ref}", rel)
        head_raw = None
        if os.path.isfile(cfg_path):
            with open(cfg_path, "rb") as fh:
                head_raw = fh.read()
        if base_raw is not None:
            load_text(base_raw, cfg, os.path.dirname(cfg_path), f"{rel} (base branch)")
        if head_raw != base_raw:
            what = "changes" if base_raw is not None and head_raw is not None else ("adds" if base_raw is None else "deletes")
            msg = (f"This pull request {what} {rel}. DCI used the version on the base branch '{base_ref}' "
                   f"{'(no config)' if base_raw is None else ''}; the change takes effect after merge.").replace("  ", " ")
            print(f"::warning title=DCI configuration {what} in this PR::{escape_data(msg)}")
            config_notes.append(msg)
    cfg.base = f"origin/{base_ref}"
    cfg.consumer_repos = [*cfg.consumer_repos, *parse_consumers(_in("consumer-repos"), workspace)]
    fo = _in("fail-on")
    if fo:
        if fo not in ("error", "warning", "never"):
            raise ConfigError("fail-on must be one of: error, warning, never")
        cfg.fail_on = fo
    cfg.rolling_deploy = _bool("rolling-deploy", cfg.rolling_deploy)
    want_comment = _bool("comment", True)

    rep = analyze(cfg)
    rep.coverage.notes.extend(config_notes)

    out_dir = os.path.join(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir(), "dci")
    os.makedirs(out_dir, exist_ok=True)
    paths = {"report-path": "report.md", "json-path": "report.json", "sarif-path": "dci.sarif"}
    renderers = {"report-path": report.to_markdown, "json-path": report.to_json, "sarif-path": report.to_sarif}
    outputs: dict[str, str] = {}
    for key, fname in paths.items():
        p = os.path.join(out_dir, fname)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(renderers[key](rep))
        outputs[key] = p

    blocking = rep.blocking()
    blocking_ids = {id(f) for f in blocking}
    print(report.to_text(rep))
    shown = 0
    for f in sorted(rep.findings, key=lambda f: (id(f) not in blocking_ids, f.severity != Severity.ERROR)):
        a = annotation(f, id(f) in blocking_ids)
        if a and shown < MAX_ANNOTATIONS:
            print(a)
            shown += 1
    verdict = report.to_markdown(rep).splitlines()[0].split(": ", 1)[1]
    outputs.update({"verdict": verdict.split(" ")[0].lower(), "blocking-count": str(len(blocking))})
    _write_output(outputs)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report.to_markdown(rep)[:MAX_SUMMARY] + "\n")

    if want_comment and event in ("pull_request", "pull_request_target") and os.environ.get("GITHUB_TOKEN"):
        try:
            how = upsert_comment(report.to_markdown(rep, for_comment=True))
            print(f"DCI {__version__}: PR comment {how}")
        except GitHubError as e:  # read-only tokens (fork PRs) must not change the check result
            print(f"::warning title=DCI could not post the PR comment::{escape_data(str(e))}")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
