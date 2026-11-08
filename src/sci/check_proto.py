"""gRPC / Protocol Buffers check: .proto changes in a pull request, compared with the base branch.

The real protoc compiler (grpcio-tools) turns each revision into descriptors, so parsing is exact (nested types, oneof, maps, imports).
Wire-incompatible changes (a changed field number, an incompatible field type, a changed RPC signature, a new proto2 `required` field) are
CONFIRMED breaks of the contract itself: no caller needs to be found, every deployed peer is affected. A removed RPC is CONFIRMED only
when code that calls it is found; everything else is POSSIBLE or informational."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field

from dci.analyze import _check_workspace
from dci.config import Config, ConfigError
from dci.models import Confidence, Coverage, Finding, Reference, Severity
from dci.redact import redact
from dci.sources import FsTree, Matcher, Tree

from . import callers
from .check_api import KEEP, _finish, _trees

MAX_PROTO_BYTES = 5_000_000
MAX_PROTO_FILES = 5000
MAX_TOTAL_BYTES = 100_000_000
PROTOC_TIMEOUT = 120
_GENERATED = re.compile(r"(?:_pb2(?:_grpc)?\.pyi?|\.pb\.go|_grpc\.pb\.go|\.pb\.(?:cc|h)|_pb\.(?:js|d\.ts)|_grpc_pb\.js|Grpc\.java|OuterClass\.java|\.pb\.swift|_pb\.rb|_services_pb\.rb)$")
_IMPORT = re.compile(r'^\s*import\s+(?:public\s+|weak\s+)?"([^"\n]{1,300})"\s*;', re.M)
_ERR_MISSING = re.compile(r'^(\S+\.proto):\d+:\d+: Import "[^"]+" was not found', re.M)
_ERR_NOTFOUND = re.compile(r"^(\S+\.proto): File not found\.", re.M)

# Fields of the same wire format may change type without breaking parsers (still lossy: reported as POSSIBLE).
_COMPAT_GROUPS = [{"TYPE_INT32", "TYPE_UINT32", "TYPE_INT64", "TYPE_UINT64", "TYPE_BOOL"}, {"TYPE_SINT32", "TYPE_SINT64"},
                  {"TYPE_FIXED32", "TYPE_SFIXED32"}, {"TYPE_FIXED64", "TYPE_SFIXED64"}, {"TYPE_STRING", "TYPE_BYTES"}]
_REMOVAL = ["Keep the RPC and mark it `option deprecated = true;`, then remove it once no client calls it.",
            "Clients are listed above; clients outside the scanned code cannot be seen."]
_WIRE = ["Never change a field number or move a field to an incompatible type: add a new field with a new number and deprecate the old one.",
         "Reserve removed numbers and names: `reserved 4; reserved \"old_name\";`."]


@dataclass
class Model:
    messages: dict = field(default_factory=dict)  # full name -> {"file", "fields": {number: dict}, "reserved_nums": set, "reserved_names": set, "syntax"}
    enums: dict = field(default_factory=dict)  # full name -> {"file", "values": {name: number}, "reserved_nums", "reserved_names"}
    rpcs: dict = field(default_factory=dict)  # (service full, method) -> dict(input, output, cs, ss, file)
    services: dict = field(default_factory=dict)  # full -> simple name


# ------------------------------------------------------------------ compiling

def _safe_join(root: str, rel: str) -> str | None:
    full = os.path.realpath(os.path.join(root, rel))
    return full if full.startswith(os.path.realpath(root) + os.sep) else None


def _wellknown() -> str:
    import grpc_tools
    return os.path.join(os.path.dirname(grpc_tools.__file__), "_proto")


def _roots(paths: list[str], texts: dict[str, str]) -> list[str]:
    """Directories that `import "a/b.proto"` statements are relative to, inferred from where the imported files actually are."""
    allp = set(paths)
    roots = {""}
    for p in paths:
        for imp in _IMPORT.findall(texts.get(p, "")):
            for q in allp:
                if q == imp or q.endswith("/" + imp):
                    roots.add(q[: len(q) - len(imp)].rstrip("/"))
    for p in paths:  # a file's own directory resolves sibling imports
        roots.add(os.path.dirname(p))
    return sorted(roots, key=lambda r: (-r.count("/") if r else 1, r))


def compile_tree(tree: Tree, paths: list[str]) -> tuple[Model | None, dict[str, str], list[str], str | None]:
    """(model, texts, excluded files, error). Files whose imports cannot be found are left out (and reported), never guessed."""
    texts: dict[str, str] = {}
    total = 0
    for p in paths[:MAX_PROTO_FILES]:
        old = tree.max_bytes
        tree.max_bytes = max(old, MAX_PROTO_BYTES)
        try:
            t = tree.read(p)
        finally:
            tree.max_bytes = old
        if t is None:
            continue
        total += len(t)
        if total > MAX_TOTAL_BYTES:
            return None, texts, [], "the .proto files are larger than the limit"
        texts[p] = t
    if not texts:
        return Model(), texts, [], None
    excluded: list[str] = []
    with tempfile.TemporaryDirectory(prefix="sci-proto-") as tmp:
        for p, t in texts.items():
            full = _safe_join(tmp, p)
            if full is None:
                return None, texts, [], f"unsafe path in the repository: {p!r}"
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(t)
        roots = _roots(sorted(texts), texts)
        active = sorted(texts)
        for _ in range(8):
            out = os.path.join(tmp, "out.desc")
            cmd = [sys.executable, "-m", "grpc_tools.protoc", *[f"-I{os.path.join(tmp, r) if r else tmp}" for r in roots], f"-I{_wellknown()}",
                   f"--descriptor_set_out={out}", *[os.path.join(tmp, p) for p in active]]
            try:
                res = subprocess.run(cmd, capture_output=True, timeout=PROTOC_TIMEOUT, cwd=tmp, check=False,
                                     env={"PATH": os.environ.get("PATH", ""), "HOME": tmp, "LC_ALL": "C"})
            except (OSError, subprocess.TimeoutExpired) as e:
                return None, texts, excluded, f"protoc failed to run: {e.__class__.__name__}"
            clean_tmp = tmp.replace("\\", "/") + "/"
            err = res.stderr.decode("utf-8", "replace").replace("\\", "/").replace(clean_tmp, "").replace(tmp + os.sep, "")
            if res.returncode == 0:
                return _read_descriptors(out, set(active), texts), texts, excluded, None
            bad = {m for m in _ERR_MISSING.findall(err)} | {m for m in _ERR_NOTFOUND.findall(err)}
            bad = {b for b in bad if b in active or any(a.endswith("/" + b) or b.endswith("/" + a) or os.path.basename(a) == os.path.basename(b) for a in active)}
            drop = {a for a in active if a in bad or any(a.endswith("/" + b) or b.endswith("/" + a) or os.path.basename(a) == os.path.basename(b) for b in bad)}
            if not drop:
                first = next((ln for ln in err.splitlines() if ln.strip()), "protoc reported an error")
                return None, texts, excluded, f"protoc: {first[:200]}"
            excluded.extend(sorted(drop))
            active = [a for a in active if a not in drop]
            if not active:
                return None, texts, excluded, "no .proto file could be compiled (imports are missing from the repository)"
    return None, texts, excluded, "too many unresolved imports"


def _read_descriptors(path: str, wanted: set[str], texts: dict[str, str]) -> Model:
    from google.protobuf import descriptor_pb2
    fds = descriptor_pb2.FileDescriptorSet()
    with open(path, "rb") as fh:
        fds.ParseFromString(fh.read())
    model = Model()
    by_suffix = {w: w for w in wanted}

    def real(name: str) -> str:
        return next((w for w in by_suffix if w == name or w.endswith("/" + name)), name)

    def msg(m, prefix, fname, syntax):
        full = f"{prefix}.{m.name}" if prefix else m.name
        if m.options.map_entry:
            return
        flds = {}
        for f in m.field:
            flds[f.number] = {"name": f.name, "type": descriptor_pb2.FieldDescriptorProto.Type.Name(f.type),
                              "type_name": f.type_name.lstrip("."), "label": descriptor_pb2.FieldDescriptorProto.Label.Name(f.label),
                              "oneof": f.HasField("oneof_index")}
        model.messages[full] = {"file": fname, "fields": flds, "syntax": syntax,
                                "reserved_nums": {n for r in m.reserved_range for n in range(r.start, min(r.end, r.start + 5000))},
                                "reserved_names": set(m.reserved_name)}
        for e in m.enum_type:
            enum(e, full, fname)
        for n in m.nested_type:
            msg(n, full, fname, syntax)

    def enum(e, prefix, fname):
        full = f"{prefix}.{e.name}" if prefix else e.name
        model.enums[full] = {"file": fname, "values": {v.name: v.number for v in e.value},
                             "reserved_nums": {n for r in e.reserved_range for n in range(r.start, min(r.end + 1, r.start + 5000))},
                             "reserved_names": set(e.reserved_name)}

    for fd in fds.file:
        fname = real(fd.name)
        if fname not in wanted:
            continue
        pkg, syntax = fd.package, fd.syntax or "proto2"
        for m in fd.message_type:
            msg(m, pkg, fname, syntax)
        for e in fd.enum_type:
            enum(e, pkg, fname)
        for s in fd.service:
            sfull = f"{pkg}.{s.name}" if pkg else s.name
            model.services[sfull] = s.name
            for r in s.method:
                model.rpcs[(sfull, r.name)] = {"input": r.input_type.lstrip("."), "output": r.output_type.lstrip("."),
                                               "cs": r.client_streaming, "ss": r.server_streaming, "file": fname}
    return model


# ------------------------------------------------------------------ diff

@dataclass
class PChange:
    rule: str  # PRT101 removed rpc | PRT111 wire break | PRT112 risky | PRT121 info
    subject: str
    detail: str
    where: tuple  # ("rpc"|"message"|"enum", full name)
    severity: Severity
    confidence: Confidence
    rpc: tuple | None = None


def _wire_compatible(a: str, b: str) -> bool:
    return a == b or any(a in g and b in g for g in _COMPAT_GROUPS)


def diff(old: Model, new: Model) -> list[PChange]:
    out: list[PChange] = []
    E, W, C, P = Severity.ERROR, Severity.WARNING, Confidence.CONFIRMED, Confidence.POSSIBLE
    for key, r in sorted(old.rpcs.items()):
        n = new.rpcs.get(key)
        sname = f"{key[0]}/{key[1]}"
        if n is None:
            out.append(PChange("PRT101", sname, f"rpc {key[1]} was removed from service {key[0]}", ("rpc", key[0]), E, C, key))
            continue
        for side in ("input", "output"):
            if r[side] != n[side]:
                out.append(PChange("PRT111", sname, f"rpc {key[0]}.{key[1]} {side} type changed {r[side]} -> {n[side]}", ("rpc", key[0]), E, C))
        if r["cs"] != n["cs"] or r["ss"] != n["ss"]:
            out.append(PChange("PRT111", sname, f"rpc {key[0]}.{key[1]} streaming changed", ("rpc", key[0]), E, C))
    for name, om in sorted(old.messages.items()):
        nm = new.messages.get(name)
        if nm is None:
            out.append(PChange("PRT112", name, f"message {name} was removed", ("message", name), W, P))
            continue
        by_name_new = {f["name"]: (num, f) for num, f in nm["fields"].items()}
        for num, of in sorted(om["fields"].items()):
            nf = nm["fields"].get(num)
            if nf is None:
                if of["name"] in by_name_new:
                    out.append(PChange("PRT111", name, f"field {name}.{of['name']} changed number {num} -> {by_name_new[of['name']][0]}", ("message", name), E, C))
                elif num not in nm["reserved_nums"] and of["name"] not in nm["reserved_names"]:
                    out.append(PChange("PRT112", name, f"field {name}.{of['name']} = {num} was removed without `reserved` (the number could be reused)", ("message", name), W, P))
                continue
            if nf["name"] != of["name"]:
                out.append(PChange("PRT112", name, f"field {name} {num} was renamed {of['name']} -> {nf['name']} (breaks JSON and generated code)", ("message", name), W, P))
            if (of["label"] == "LABEL_REPEATED") != (nf["label"] == "LABEL_REPEATED"):
                out.append(PChange("PRT111", name, f"field {name}.{nf['name']} changed between singular and repeated", ("message", name), E, C))
            elif of["type"] != nf["type"] or of["type_name"] != nf["type_name"]:
                enum_int = {of["type"], nf["type"]} <= {"TYPE_ENUM", "TYPE_INT32", "TYPE_UINT32", "TYPE_INT64", "TYPE_UINT64"} and "TYPE_ENUM" in (of["type"], nf["type"])
                if of["type"] == nf["type"] == "TYPE_MESSAGE" or of["type"] == nf["type"] == "TYPE_ENUM":
                    out.append(PChange("PRT112", name, f"field {name}.{nf['name']} changed type {of['type_name']} -> {nf['type_name']}", ("message", name), W, P))
                elif _wire_compatible(of["type"], nf["type"]) or enum_int:
                    out.append(PChange("PRT112", name, f"field {name}.{nf['name']} changed type {of['type'][5:].lower()} -> {nf['type'][5:].lower()} (same wire format; values can be truncated)", ("message", name), W, P))
                else:
                    out.append(PChange("PRT111", name, f"field {name}.{nf['name']} changed to an incompatible type {of['type'][5:].lower()} -> {nf['type'][5:].lower()}", ("message", name), E, C))
        for num, nf in sorted(nm["fields"].items()):
            if num not in om["fields"] and nf["label"] == "LABEL_REQUIRED":
                out.append(PChange("PRT111", name, f"required field {name}.{nf['name']} = {num} was added (old messages no longer parse)", ("message", name), E, C))
    for name, oe in sorted(old.enums.items()):
        ne = new.enums.get(name)
        if ne is None:
            out.append(PChange("PRT112", name, f"enum {name} was removed", ("enum", name), W, P))
            continue
        for vname, num in sorted(oe["values"].items()):
            if vname not in ne["values"]:
                moved = [k for k, v in ne["values"].items() if v == num]
                if not moved and num not in ne["reserved_nums"] and vname not in ne["reserved_names"]:
                    out.append(PChange("PRT112", name, f"enum value {name}.{vname} = {num} was removed without `reserved`", ("enum", name), W, P))
            elif ne["values"][vname] != num:
                out.append(PChange("PRT111", name, f"enum value {name}.{vname} changed number {num} -> {ne['values'][vname]}", ("enum", name), E, C))
    return out


# ------------------------------------------------------------------ callers of removed RPCs

def _forms(method: str) -> list[str]:
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", method).lower()
    return sorted({method, method[:1].lower() + method[1:], snake})


_DEF = re.compile(r"\b(?:def|func|fun|function|void|override|async|Task<[^>]*>|Future<[^>]*>)\s+(?:\([^)]*\)\s*)?(?:[\w<>\[\],.? ]+\s+)?(?P<n>\w+)\s*\(")


def scan_rpc_callers(tree: Tree, tree_name: str, rpcs: list[tuple[str, str, str]], test_match: Matcher, ignore_match: Matcher,
                     cov: Coverage, found: dict, totals: Counter, time_budget: float, max_total_bytes: int) -> None:
    """rpcs: (service full name, service simple name, method). A call needs the method name AND the service name in the same file;
    when another service in the repository has a method of the same name, the match is only POSSIBLE."""
    import time
    if not rpcs:
        return
    start, total, files = time.monotonic(), 0, 0
    simple = sorted({s for _, s, _ in rpcs})
    pre = re.compile("|".join(re.escape(x) for x in simple + [m for _, _, m in rpcs] + [m[:1].lower() + m[1:] for _, _, m in rpcs]))
    for path, size in tree.files():
        if not path.lower().endswith(callers.CODE_EXT + (".proto",)) or path.lower().endswith(".proto") or _GENERATED.search(path) or ignore_match(path):
            continue
        if (time_budget and time.monotonic() - start > time_budget) or (max_total_bytes and total > max_total_bytes):
            cov.scan_incomplete = True
            cov.files_not_scanned += 1
            continue
        text = tree.read(path)
        if text is None:
            continue
        total += size
        if not pre.search(text):
            continue
        low = text.lower().replace("_", "")
        files += 1
        is_test = test_match(path)
        lines = text.split("\n")
        for sfull, sname, method in rpcs:
            has_service = sname.lower() in low
            full_path = f"/{sfull}/{method}"
            rx = re.compile(r"(?<![\w])(?:" + "|".join(re.escape(f) for f in _forms(method)) + r")\s*\(")
            ambiguous = sum(1 for (_, s2, m2) in rpcs if m2 == method and s2 != sname) > 0
            for i, ln in enumerate(lines, 1):
                if len(ln) > callers.MAX_LINE:
                    continue
                if full_path in ln:
                    conf, why = Confidence.CONFIRMED, f"calls {full_path}"
                elif has_service and rx.search(ln) and not _is_def(ln, method):
                    conf = Confidence.POSSIBLE if ambiguous else Confidence.CONFIRMED
                    why = f"calls {method} on a file that uses {sname}" + (" (another service has the same method name)" if ambiguous else "")
                else:
                    continue
                key = (sfull, method)
                totals[(key, conf, is_test)] += 1
                if totals[(key, conf, is_test)] <= KEEP:
                    found.setdefault(key, []).append(Reference(None, None, path, i, tree_name, "grpc_call", "ref", conf, redact(ln), is_test=is_test, note=why, anchor=i))
    cov.notes.append(f"gRPC callers: {files} source file(s) searched in {tree_name}")


def _is_def(line: str, method: str) -> bool:
    m = _DEF.search(line)
    return bool(m and m.group("n") in _forms(method))


# ------------------------------------------------------------------ check

def _locate(texts: dict[str, str], file: str, kind: str, name: str) -> int:
    t = texts.get(file)
    if t:
        short = name.rsplit(".", 1)[-1]
        rx = re.compile(rf"\b{'rpc' if kind == 'rpc' else kind}\s+{re.escape(short)}\b")
        for i, ln in enumerate(t.split("\n"), 1):
            if rx.search(ln):
                return i
    return 1


def run(cfg: Config, cov: Coverage) -> list[Finding]:
    repo = os.path.realpath(cfg.repo)
    if not os.path.isdir(repo):
        raise ConfigError(f"Repository path does not exist: {cfg.repo}")
    _check_workspace(cfg, repo)
    ignore_match, proto_match, test_match = Matcher(cfg.ignore_paths), Matcher(cfg.proto_globs), Matcher(cfg.test_globs)
    base_tree, head_tree, opened, changed = _trees(cfg, repo)
    extra: list[Tree] = []
    try:
        changed_protos = [p for st, p in changed if proto_match(p) and not ignore_match(p)]
        if not changed_protos:
            return []
        cov.notes.append(f"Protocol Buffers files changed in this pull request: {len(changed_protos)}")
        paths_of = lambda tr: [p for p, sz in tr.files() if proto_match(p) and not ignore_match(p)]  # noqa: E731
        old, old_t, ex1, e1 = compile_tree(base_tree, paths_of(base_tree))
        new, new_t, ex2, e2 = compile_tree(head_tree, paths_of(head_tree))
        if ex1 or ex2:
            cov.notes.append(f"{len(set(ex1) | set(ex2))} .proto file(s) were left out because their imports are not in the repository: " + ", ".join(sorted(set(ex1) | set(ex2))[:5]))
        findings: list[Finding] = []
        if e1 or e2 or old is None or new is None:
            findings.append(Finding("PRT902", Severity.WARNING, Confidence.UNKNOWN, "Protocol Buffers could not be checked",
                                    f"The .proto files were not compared: {e2 or e1}. Breaking changes in them were not evaluated.", None,
                                    file=changed_protos[0], line=1))
            return [f for f in findings if f.rule_id not in cfg.ignore_rules]
        changes = diff(old, new)
        if not changes:
            return []
        removed = [c for c in changes if c.rule == "PRT101"]
        rpcs = [(k[0], old.services.get(k[0], k[0].rsplit(".", 1)[-1]), k[1]) for k in (c.rpc for c in removed)]
        found: dict = {}
        totals: Counter = Counter()
        if rpcs:
            scan = [(head_tree, "head")]
            for name, path in [*cfg.consumer_repos, *cfg.config_consumer_repos]:
                if not os.path.isdir(path):
                    raise ConfigError(f"Consumer repository path does not exist: {path}")
                t = FsTree(path, f"consumer:{name}", cfg.max_file_bytes)
                extra.append(t)
                scan.append((t, f"consumer:{name}"))
            all_rpcs = sorted({(s, old.services.get(s, s.rsplit('.', 1)[-1]), m) for (s, m) in {*old.rpcs, *new.rpcs}})
            targets = [(s, sn, m) for s, sn, m in all_rpcs if (s, m) in {c.rpc for c in removed}]
            ambiguous_pool = all_rpcs  # so same-named methods of other services make a match POSSIBLE
            for tree, tname in scan:
                cov.trees_scanned.append(tname)
                scan_rpc_callers(tree, tname, targets + [x for x in ambiguous_pool if x not in targets and any(x[2] == t[2] for t in targets)],
                                 test_match, ignore_match, cov, found, totals, cfg.time_budget_seconds, cfg.max_total_bytes)

        def loc(c: PChange) -> tuple[str, int]:
            kind, name = c.where
            model_new = {"rpc": new.rpcs, "message": new.messages, "enum": new.enums}[kind]
            model_old = {"rpc": old.rpcs, "message": old.messages, "enum": old.enums}[kind]
            if kind == "rpc":
                src = next((v for k, v in {**model_old, **model_new}.items() if k[0] == name), None)
                fname = src["file"] if src else changed_protos[0]
                texts = new_t if any(k[0] == name for k in model_new) and c.rule != "PRT101" else old_t
                return fname, _locate(texts, fname, "rpc", c.rpc[1] if c.rpc else name)
            src = model_new.get(name) or model_old.get(name)
            fname = src["file"] if src else changed_protos[0]
            return fname, _locate(new_t if name in model_new else old_t, fname, kind, name)

        def refs_of(key, kind_filter):
            return [r for r in found.get(key, []) if kind_filter(r)]

        for c in removed:
            key = c.rpc
            refs = found.get(key, [])
            cn = [r for r in refs if r.confidence == Confidence.CONFIRMED and not r.is_test]
            ct = [r for r in refs if r.confidence == Confidence.CONFIRMED and r.is_test]
            po = [r for r in refs if r.confidence != Confidence.CONFIRMED]
            f, ln = loc(c)
            tot = lambda conf, t: totals[(key, conf, t)]  # noqa: E731
            def add(rid, sev, conf, title, msg, rs, n):
                rs = sorted(rs, key=lambda r: (r.tree != "head", r.file, r.line))
                findings.append(Finding(rid, sev, conf, title, msg, None, rs[:cfg.max_evidence], _REMOVAL, total_evidence=max(n, len(rs)), file=f, line=ln))
            if cn:
                add("PRT101", Severity.ERROR, Confidence.CONFIRMED, "Removed RPC is still called", f"{c.detail}, but {tot(Confidence.CONFIRMED, False)} call(s) to it remain.", cn, tot(Confidence.CONFIRMED, False))
            if ct:
                add("PRT102", Severity.WARNING, Confidence.CONFIRMED, "Removed RPC is called only from tests", f"{c.detail}; {tot(Confidence.CONFIRMED, True)} test call(s) remain.", ct, tot(Confidence.CONFIRMED, True))
            if po:
                n = tot(Confidence.POSSIBLE, False) + tot(Confidence.POSSIBLE, True)
                add("PRT103", Severity.WARNING, Confidence.POSSIBLE, "Removed RPC may still be called", f"{c.detail}; {n} location(s) may call it (the method name is shared with another service).", po, n)
            if not (cn or ct or po):
                add("PRT105", Severity.INFO, Confidence.UNKNOWN, "Clients outside the scanned code are not visible",
                    f"{c.detail}. No caller was found in the scanned code, but other services and apps cannot be seen.", [], 0)
        for rid, title, sev, conf, rec in (("PRT111", "Wire-incompatible Protocol Buffers change", Severity.ERROR, Confidence.CONFIRMED, _WIRE),
                                           ("PRT112", "Risky Protocol Buffers change", Severity.WARNING, Confidence.POSSIBLE, _WIRE)):
            group = [c for c in changes if c.rule == rid]
            by_file: dict[tuple[str, int], list[PChange]] = {}
            for c in group:
                by_file.setdefault(loc(c), []).append(c)
            for (f, ln), cs in sorted(by_file.items()):
                lines = "\n".join(f"- {c.detail}" for c in cs[:30]) + (f"\n- … and {len(cs) - 30} more" if len(cs) > 30 else "")
                findings.append(Finding(rid, sev, conf, title, lines, None, [], rec, total_evidence=0, file=f, line=ln))
        return [x for x in findings if x.rule_id not in cfg.ignore_rules] if not cov.scan_incomplete else _finish(findings, cfg, cov, "PRT901")
    finally:
        for t in [*opened, *extra]:
            t.close()
