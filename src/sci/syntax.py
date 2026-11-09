"""Syntax-aware preprocessing with tree-sitter (Python, JavaScript/TypeScript, Go, Java).

Caller, import and environment-variable detection is text matching so that it works in any language. The commonest false match is text inside a
comment (`// fetch("/v1/users")`, `# os.environ["X"]`), so for the languages above comments are blanked out (replaced by spaces, newlines kept,
so every offset and line number is unchanged) before matching. Any failure (parser missing, file too large, parse error) returns the text unchanged:
this layer can only remove matches, never add them, and never makes a file unreadable."""
from __future__ import annotations

import os

MAX_BYTES = 2_000_000
_LANG = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript",
         ".tsx": "tsx", ".go": "go", ".java": "java"}
_parsers: dict = {}
_unavailable: set[str] = set()


def _parser(lang: str):
    if lang in _unavailable:
        return None
    if lang not in _parsers:
        try:
            from tree_sitter import Language, Parser  # noqa: PLC0415
            if lang == "python":
                import tree_sitter_python as m  # noqa: PLC0415
                cap = m.language()
            elif lang == "javascript":
                import tree_sitter_javascript as m  # noqa: PLC0415
                cap = m.language()
            elif lang in ("typescript", "tsx"):
                import tree_sitter_typescript as m  # noqa: PLC0415
                cap = m.language_typescript() if lang == "typescript" else m.language_tsx()
            elif lang == "go":
                import tree_sitter_go as m  # noqa: PLC0415
                cap = m.language()
            else:
                import tree_sitter_java as m  # noqa: PLC0415
                cap = m.language()
            _parsers[lang] = Parser(Language(cap))
        except Exception:  # noqa: BLE001 - optional dependency or incompatible build
            _unavailable.add(lang)
            return None
    return _parsers[lang]


def supported(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in _LANG


def blank_comments(path: str, text: str) -> str:
    lang = _LANG.get(os.path.splitext(path)[1].lower())
    if not lang or len(text) > MAX_BYTES:
        return text
    parser = _parser(lang)
    if parser is None:
        return text
    try:
        data = text.encode("utf-8")
        tree = parser.parse(data)
        spans: list[tuple[int, int]] = []
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type in ("comment", "line_comment", "block_comment"):
                spans.append((n.start_byte, n.end_byte))
                continue
            if n.child_count:
                stack.extend(n.children)
        if not spans:
            return text
        out = bytearray(data)
        for a, b in spans:
            for i in range(a, b):
                if out[i] not in (10, 13):
                    out[i] = 32
        return out.decode("utf-8")
    except Exception:  # noqa: BLE001
        return text
