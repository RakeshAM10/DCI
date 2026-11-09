"""Redact secrets and SQL literals from any snippet that leaves the analysis process
(PR comments, JSON, SARIF). Source code is untrusted data and may contain credentials."""
from __future__ import annotations

import re

_MAX = 200
_PRE = 4000
_SECRET_KV = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization|bearer|private[_-]?key)\b"
    r"(\s*[=:]\s*)(['\"])[^'\"]*\3"
)
_URL_CRED = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{0,31}://)[^\s/:@'\"]{1,256}:[^\s/@'\"]{1,2048}@")
_AWS = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GH = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")
_BLOB = re.compile(r"\b(?=[A-Za-z0-9+/_\-]*\d)(?=[A-Za-z0-9+/_\-]*[A-Za-z])[A-Za-z0-9+/_\-]{32,}={0,2}")
# SQL literal values compared/assigned/inserted: keep identifiers, drop values.
_CMP_LIT = re.compile(r"((?:=|<>|!=|>=|<=|<|>)\s*)'[^']*'")
_LIKE_LIT = re.compile(r"(?i)(\b(?:LIKE|ILIKE)\s+)'[^']*'")
_VALUES_LIT = re.compile(r"(?i)(\bVALUES\s*\()([^)]*)\)")


def redact(line: str) -> str:
    s = line.strip()[:_PRE]  # bound the work: only the first 200 characters of the result are ever shown
    s = _SECRET_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}<redacted>{m.group(3)}", s)
    s = _URL_CRED.sub(lambda m: f"{m.group(1)}<redacted>@", s)
    s = _AWS.sub("<redacted>", s)
    s = _GH.sub("<redacted>", s)
    s = _JWT.sub("<redacted>", s)
    s = _CMP_LIT.sub(lambda m: f"{m.group(1)}'?'", s)
    s = _LIKE_LIT.sub(lambda m: f"{m.group(1)}'?'", s)
    s = _VALUES_LIT.sub(lambda m: f"{m.group(1)}?)", s)
    s = _BLOB.sub("<redacted>", s)
    if len(s) > _MAX:
        s = s[: _MAX - 1] + "…"
    return s
