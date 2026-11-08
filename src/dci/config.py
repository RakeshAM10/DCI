"""Configuration: defaults < .dci.toml < CLI flags."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field

DEFAULT_MIGRATION_GLOBS = ["**/versions/*.py", "**/migrations/**/*.sql"]
DEFAULT_API_SPEC_GLOBS = ["**/openapi*.json", "**/openapi*.yaml", "**/openapi*.yml", "**/swagger*.json", "**/swagger*.yaml", "**/swagger*.yml",
                          "**/*.openapi.json", "**/*.openapi.yaml", "**/*.openapi.yml"]
DEFAULT_GRAPHQL_GLOBS = ["**/*.graphql", "**/*.graphqls", "**/*.gql"]
DEFAULT_TEST_GLOBS = ["**/tests/**", "**/test/**", "**/__tests__/**", "**/__mocks__/**", "**/src/test/**", "**/test_*.py", "**/*_test.py", "**/conftest.py",
                      "**/*.test.*", "**/*.spec.*", "**/*_test.go", "**/*Test.java", "**/*Tests.java", "**/*Test.kt", "**/*_spec.rb", "**/*Test.php", "**/*Tests.cs"]


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
    workers: int = 0  # worker processes for scanning large source trees; 0 = automatic (up to 8), 1 = no parallelism
    time_budget_seconds: float = 900.0  # a scan that exceeds this stops and reports itself as incomplete (0 = unlimited)
    parallel_min_files: int = 400  # smaller trees are scanned in-process (a worker pool costs more than it saves)
    max_total_bytes: int = 1_000_000_000  # source bytes read per tree before the scan stops as incomplete (0 = unlimited)
    runtime_queries: list[str] = field(default_factory=list)  # query-statistics files (operator supplied, never from .dci.toml)
    runtime_blocks: bool = False  # treat runtime evidence as CONFIRMED (the operator vouches that the statistics are current)
    api_spec_globs: list[str] = field(default_factory=lambda: list(DEFAULT_API_SPEC_GLOBS))  # OpenAPI files whose changes are checked (SCI)
    graphql_schema_globs: list[str] = field(default_factory=lambda: list(DEFAULT_GRAPHQL_GLOBS))  # GraphQL SDL files (SCI)
    proto_globs: list[str] = field(default_factory=lambda: ["**/*.proto"])  # Protocol Buffers files (SCI)
    api_access_logs: list[str] = field(default_factory=list)  # access-log exports (operator supplied, never from .dci.toml)
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
    for key, attr in (("migration_globs", "migration_globs"), ("test_globs", "test_globs"), ("ignore_paths", "ignore_paths"), ("ignore_rules", "ignore_rules"), ("api_spec_globs", "api_spec_globs"), ("graphql_schema_globs", "graphql_schema_globs"), ("proto_globs", "proto_globs")):
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
    for key, attr, lo in (("workers", "workers", 0), ("max_total_bytes", "max_total_bytes", 0)):
        if key in d:
            if not isinstance(d[key], int) or isinstance(d[key], bool) or d[key] < lo or (key == "workers" and d[key] > 64):
                raise ConfigError(f"{key} must be a non-negative integer" + (" up to 64" if key == "workers" else ""))
            setattr(cfg, attr, d[key])
    if "time_budget_seconds" in d:
        if not isinstance(d["time_budget_seconds"], (int, float)) or isinstance(d["time_budget_seconds"], bool) or d["time_budget_seconds"] < 0:
            raise ConfigError("time_budget_seconds must be a non-negative number")
        cfg.time_budget_seconds = float(d["time_budget_seconds"])
    for item in d.get("consumer_repos", []) or []:
        if not isinstance(item, dict) or "path" not in item:
            raise ConfigError("consumer_repos entries need a 'path'")
        p = item["path"]
        if not os.path.isabs(p):
            p = os.path.normpath(os.path.join(base_dir, p))
        cfg.config_consumer_repos.append((str(item.get("name") or os.path.basename(p.rstrip('/'))), p))
    return cfg
