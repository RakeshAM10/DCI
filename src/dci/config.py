"""Configuration: defaults < .dci.toml < CLI flags."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field

DEFAULT_MIGRATION_GLOBS = ["**/versions/*.py", "**/migrations/**/*.sql"]
DEFAULT_TEST_GLOBS = ["**/tests/**", "**/test/**", "**/test_*.py", "**/*_test.py", "**/conftest.py"]


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    repo: str = "."
    base: str | None = None
    head: str | None = None
    migrations: list[str] = field(default_factory=list)  # explicit migration files (relative to repo)
    migration_globs: list[str] = field(default_factory=lambda: list(DEFAULT_MIGRATION_GLOBS))
    test_globs: list[str] = field(default_factory=lambda: list(DEFAULT_TEST_GLOBS))
    ignore_paths: list[str] = field(default_factory=list)
    consumer_repos: list[tuple[str, str]] = field(default_factory=list)  # (name, path)
    ignore_rules: list[str] = field(default_factory=list)
    fail_on: str = "error"  # error | warning | never
    rolling_deploy: bool = True
    max_file_bytes: int = 2_000_000
    max_evidence: int = 25
    workspace: str | None = None  # if set, the repo and every consumer repository must be inside it (enforced in analyze)
    config_consumer_repos: list[tuple[str, str]] = field(default_factory=list)  # consumer repos named by a .dci.toml (untrusted origin)
    allow_outside_config_paths: bool = False  # without a workspace, config-file consumer paths must be inside the repo's parent dir


def _list(d: dict, key: str) -> list[str] | None:
    if key not in d:
        return None
    v = d[key]
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f".dci.toml: '{key}' must be a list of strings")
    return v


def load_file(path: str, cfg: Config) -> Config:
    with open(path, "rb") as fh:
        raw = fh.read()
    return load_text(raw, cfg, os.path.dirname(os.path.abspath(path)), path)


def load_text(raw: bytes | str, cfg: Config, base_dir: str, label: str = ".dci.toml") -> Config:
    """Apply TOML text (e.g. the file as stored on the base branch). Relative consumer paths resolve against base_dir."""
    path = label
    try:
        data = tomllib.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise ConfigError(f"{path}: invalid TOML: {e}") from e
    d = data.get("dci", data)
    for key, attr in (("migration_globs", "migration_globs"), ("test_globs", "test_globs"), ("ignore_paths", "ignore_paths"), ("ignore_rules", "ignore_rules")):
        v = _list(d, key)
        if v is not None:
            setattr(cfg, attr, v)
    if "fail_on" in d:
        if d["fail_on"] not in ("error", "warning", "never"):
            raise ConfigError("fail_on must be one of: error, warning, never")
        cfg.fail_on = d["fail_on"]
    if "rolling_deploy" in d:
        if not isinstance(d["rolling_deploy"], bool):
            raise ConfigError("rolling_deploy must be true or false")
        cfg.rolling_deploy = d["rolling_deploy"]
    if "max_evidence" in d:
        if not isinstance(d["max_evidence"], int) or d["max_evidence"] < 1:
            raise ConfigError("max_evidence must be a positive integer")
        cfg.max_evidence = d["max_evidence"]
    for item in d.get("consumer_repos", []) or []:
        if not isinstance(item, dict) or "path" not in item:
            raise ConfigError("consumer_repos entries need a 'path'")
        p = item["path"]
        if not os.path.isabs(p):
            p = os.path.normpath(os.path.join(base_dir, p))
        cfg.config_consumer_repos.append((str(item.get("name") or os.path.basename(p.rstrip('/'))), p))
    return cfg
