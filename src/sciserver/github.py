"""Minimal GitHub App client: app JWT (RS256), installation tokens, Checks API. Standard library HTTP with TLS verification, timeouts and bounded retries."""
from __future__ import annotations

import base64
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

API_VERSION = "2022-11-28"
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")


class GitHubError(RuntimeError):
    def __init__(self, message: str, status: int = 0, retryable: bool = False):
        super().__init__(message)
        self.status, self.retryable = status, retryable


def valid_repo(name: str) -> bool:
    return bool(_REPO.match(name)) and ".." not in name


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def app_jwt(app_id: str, private_key_pem: bytes, now: float | None = None) -> str:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise GitHubError("the GitHub App private key must be an RSA key")
    t = int(now if now is not None else time.time())
    head = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps({"iat": t - 60, "exp": t + 540, "iss": str(app_id)}, separators=(",", ":")).encode())
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{_b64(sig)}"


class GitHub:
    def __init__(self, api: str, app_id: str, private_key_pem: bytes, timeout: float = 30):
        self.api, self.app_id, self.key, self.timeout = api.rstrip("/"), app_id, private_key_pem, timeout
        self._tokens: dict[int, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def _request(self, method: str, path: str, token: str, body: dict | None = None, retries: int = 4) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(retries):
            req = urllib.request.Request(self.api + path, data=data, method=method, headers={
                "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "sci-server", **({"Content-Type": "application/json"} if data else {})})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    raw = r.read(5_000_000)
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                retry_after = e.headers.get("Retry-After") if e.headers else None
                transient = e.code >= 500 or e.code == 429 or (e.code == 403 and retry_after)
                if transient and attempt < retries - 1:
                    time.sleep(min(float(retry_after) if retry_after and retry_after.isdigit() else 2 ** attempt, 30))
                    continue
                raise GitHubError(f"GitHub API {method} {path.split('?')[0]} -> HTTP {e.code}", e.code, transient) from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise GitHubError(f"GitHub API unreachable: {e.__class__.__name__}", 0, True) from None
        raise GitHubError("GitHub API retries exhausted", 0, True)

    def installation_token(self, installation_id: int) -> str:
        with self._lock:
            tok = self._tokens.get(installation_id)
            if tok and tok[1] - 120 > time.time():
                return tok[0]
        res = self._request("POST", f"/app/installations/{int(installation_id)}/access_tokens", app_jwt(self.app_id, self.key),
                            {"permissions": {"checks": "write", "contents": "read", "pull_requests": "read", "metadata": "read"}})
        token = res.get("token")
        if not isinstance(token, str):
            raise GitHubError("GitHub returned no installation token")
        with self._lock:
            self._tokens[installation_id] = (token, time.time() + 3000)
        return token

    def find_check_run(self, token: str, repo: str, head_sha: str, name: str, external_id: str) -> int | None:
        res = self._request("GET", f"/repos/{repo}/commits/{head_sha}/check-runs?check_name={urllib.parse.quote(name)}&per_page=100", token)
        for cr in res.get("check_runs") or []:
            if isinstance(cr, dict) and cr.get("external_id") == external_id and cr.get("name") == name:
                return int(cr["id"])
        return None

    def create_check_run(self, token: str, repo: str, head_sha: str, name: str, external_id: str) -> int:
        """Create the check run for a job exactly once. A POST whose response was lost may still have created it, so before every attempt we look
        for a run carrying this job's external_id, and the POST itself is never auto-retried."""
        body = {"name": name, "head_sha": head_sha, "external_id": external_id, "status": "in_progress",
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        last: GitHubError | None = None
        for attempt in range(3):
            found = self.find_check_run(token, repo, head_sha, name, external_id)
            if found:
                return found
            try:
                return int(self._request("POST", f"/repos/{repo}/check-runs", token, body, retries=1)["id"])
            except GitHubError as e:
                if not e.retryable:
                    raise
                last = e
                time.sleep(2 ** attempt)
        raise last or GitHubError("could not create the check run", 0, True)

    def complete_check_run(self, token: str, repo: str, check_run_id: int, conclusion: str, title: str, summary: str, text: str,
                           annotations: list[dict]) -> None:
        if conclusion not in ("success", "failure", "neutral", "cancelled", "timed_out", "action_required"):
            raise ValueError(conclusion)
        out = {"title": title[:255], "summary": summary[:60000], "text": text[:60000]}
        # the Checks API accepts 50 annotations per request
        first, rest = annotations[:50], annotations[50:200]
        self._request("PATCH", f"/repos/{repo}/check-runs/{int(check_run_id)}", token, {
            "status": "completed", "conclusion": conclusion, "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "output": {**out, **({"annotations": first} if first else {})}})
        for i in range(0, len(rest), 50):
            self._request("PATCH", f"/repos/{repo}/check-runs/{int(check_run_id)}", token, {"output": {**out, "annotations": rest[i:i + 50]}})
