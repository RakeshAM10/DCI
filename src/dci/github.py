"""Post/update one idempotent PR comment through the GitHub REST API. Standard library only.
The token is only ever sent to the API host and is never logged."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from .report import MARKER

TIMEOUT = 30


class GitHubError(RuntimeError):
    pass


def _api_base() -> str:
    base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if not base.startswith("https://"):
        raise GitHubError("GITHUB_API_URL must use https")
    return base


def _req(method: str, url: str, token: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "dci/1.0", "Content-Type": "application/json",
    })
    try:
        context = None
        cafile = os.environ.get("SSL_CERT_FILE")
        if cafile and os.path.exists(cafile):
            import ssl
            context = ssl.create_default_context(cafile=cafile)
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=context) as resp:  # noqa: S310 - https enforced by _api_base
            return json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as e:
        raise GitHubError(f"GitHub API {method} {urllib.parse.urlsplit(url).path} failed: HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise GitHubError(f"GitHub API unreachable: {e.__class__.__name__}") from None


def pr_number_from_event() -> int | None:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            ev = json.load(fh)
    except (OSError, ValueError):
        return None
    n = (ev.get("pull_request") or {}).get("number") or ev.get("number")
    return int(n) if isinstance(n, int) else None


def upsert_comment(markdown: str, repo: str | None = None, pr: int | None = None, token: str | None = None) -> str:
    token = token or os.environ.get("GITHUB_TOKEN")
    repo = repo or os.environ.get("GITHUB_REPOSITORY")
    pr = pr or pr_number_from_event()
    if not (token and repo and pr):
        raise GitHubError("Need GITHUB_TOKEN, GITHUB_REPOSITORY and a pull request number (GITHUB_EVENT_PATH)")
    if "/" not in repo or repo.count("/") != 1 or ".." in repo:
        raise GitHubError("Invalid repository name")
    base = _api_base()
    comments_url = f"{base}/repos/{repo}/issues/{int(pr)}/comments"
    page, existing = 1, None
    while existing is None and page <= 20:
        batch = _req("GET", f"{comments_url}?per_page=100&page={page}", token) or []
        for c in batch:
            if MARKER in (c.get("body") or ""):
                existing = c["id"]
                break
        if len(batch) < 100:
            break
        page += 1
    if existing:
        _req("PATCH", f"{base}/repos/{repo}/issues/comments/{int(existing)}", token, {"body": markdown})
        return "updated"
    _req("POST", comments_url, token, {"body": markdown})
    return "created"
