"""Server settings, read once from the environment. Secrets are never logged and never passed to analysis subprocesses."""
from __future__ import annotations

import os
from dataclasses import dataclass


class SettingsError(ValueError):
    pass


def _int(env: dict, key: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(key)
    if raw in (None, ""):
        return default
    try:
        v = int(raw)
    except ValueError:
        raise SettingsError(f"{key} must be an integer") from None
    if not lo <= v <= hi:
        raise SettingsError(f"{key} must be between {lo} and {hi}")
    return v


def _read(path: str, what: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(1_000_000)
    except OSError as e:
        raise SettingsError(f"cannot read {what} ({path}): {e.strerror}") from None


@dataclass
class Settings:
    app_id: str
    private_key_pem: bytes
    webhook_secret: bytes
    admin_token: str
    data_dir: str
    licence_public_key: str = ""  # base64 raw Ed25519 public key of whoever issues licences
    licence_token: str = ""
    github_api: str = "https://api.github.com"
    clone_url_template: str = "https://github.com/{repo}.git"
    host: str = "127.0.0.1"
    port: int = 8080
    workers: int = 2
    job_timeout: int = 900
    job_memory_mb: int = 4096
    max_body: int = 10_000_000
    retention_days: int = 90
    community_max_repos: int = 3  # without a licence

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Settings":
        e = dict(os.environ if env is None else env)
        for k in ("SCI_APP_ID", "SCI_WEBHOOK_SECRET", "SCI_ADMIN_TOKEN", "SCI_DATA_DIR"):
            if not e.get(k):
                raise SettingsError(f"{k} is required")
        key = e.get("SCI_PRIVATE_KEY_FILE")
        if not key:
            raise SettingsError("SCI_PRIVATE_KEY_FILE is required (the GitHub App's private key, PEM)")
        if len(e["SCI_WEBHOOK_SECRET"]) < 16:
            raise SettingsError("SCI_WEBHOOK_SECRET must be at least 16 characters")
        if len(e["SCI_ADMIN_TOKEN"]) < 20:
            raise SettingsError("SCI_ADMIN_TOKEN must be at least 20 characters")
        api = e.get("SCI_GITHUB_API", "https://api.github.com").rstrip("/")
        if not api.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise SettingsError("SCI_GITHUB_API must be https (plain http only for localhost)")
        tmpl = e.get("SCI_CLONE_URL_TEMPLATE", "https://github.com/{repo}.git")
        if "{repo}" not in tmpl:
            raise SettingsError("SCI_CLONE_URL_TEMPLATE must contain {repo}")
        lic = e.get("SCI_LICENCE_FILE")
        token = _read(lic, "licence file").decode("utf-8", "replace").strip() if lic else e.get("SCI_LICENCE", "").strip()
        return cls(
            app_id=e["SCI_APP_ID"], private_key_pem=_read(key, "private key"), webhook_secret=e["SCI_WEBHOOK_SECRET"].encode(),
            admin_token=e["SCI_ADMIN_TOKEN"], data_dir=os.path.abspath(e["SCI_DATA_DIR"]),
            licence_public_key=e.get("SCI_LICENCE_PUBLIC_KEY", "").strip(), licence_token=token, github_api=api, clone_url_template=tmpl,
            host=e.get("SCI_HOST", "127.0.0.1"), port=_int(e, "SCI_PORT", 8080, 1, 65535), workers=_int(e, "SCI_WORKERS", 2, 1, 32),
            job_timeout=_int(e, "SCI_JOB_TIMEOUT", 900, 30, 7200), job_memory_mb=_int(e, "SCI_JOB_MEMORY_MB", 4096, 256, 65536),
            max_body=_int(e, "SCI_MAX_BODY", 10_000_000, 10_000, 100_000_000), retention_days=_int(e, "SCI_RETENTION_DAYS", 90, 1, 3650),
            community_max_repos=_int(e, "SCI_COMMUNITY_MAX_REPOS", 3, 1, 1000),
        )
