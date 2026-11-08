"""OpenAPI 3.x contract model and breaking-change diff.

Specs are untrusted data: they are parsed, never executed; only local `#/...` references are followed (a remote $ref is never
fetched); YAML alias expansion, nesting and file size are bounded before anything is built."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
MAX_SPEC_BYTES = 50_000_000  # real-world specs reach 10-30 MB (Stripe)
MAX_NODES = 10_000_000  # expanded size of the YAML/JSON document, aliases included
MAX_DEPTH = 100
MAX_SCHEMA_DEPTH = 16
MAX_SCHEMA_PROPS = 5000


class SpecError(ValueError):
    pass


# ------------------------------------------------------------------ safe parsing

def _yaml_budget(text: str) -> None:
    """Reject documents whose alias expansion ('billion laughs'), nesting or document count exceed the limits, before loading."""
    import yaml
    stack: list[list] = []  # [expanded size, anchor]
    anchors: dict[str, int] = {}
    docs = 0
    try:
        for ev in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(ev, yaml.DocumentStartEvent):
                docs += 1
                if docs > 1:
                    raise SpecError("multi-document YAML is not supported")
                continue
            if isinstance(ev, (yaml.StreamStartEvent, yaml.StreamEndEvent, yaml.DocumentEndEvent)):
                continue
            if isinstance(ev, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                if len(stack) >= MAX_DEPTH:
                    raise SpecError("YAML nesting is too deep")
                stack.append([1, ev.anchor])
                continue
            anchor = None
            if isinstance(ev, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                size, anchor = stack.pop()
            elif isinstance(ev, yaml.AliasEvent):
                if ev.anchor not in anchors:
                    raise SpecError("YAML alias to an undefined anchor")
                size = anchors[ev.anchor]
            else:
                size, anchor = 1, getattr(ev, "anchor", None)
            if size > MAX_NODES:
                raise SpecError("YAML document expands to too many nodes (alias bomb?)")
            if anchor:
                anchors[anchor] = size
            if stack:
                stack[-1][0] += size
                if stack[-1][0] > MAX_NODES:
                    raise SpecError("YAML document expands to too many nodes (alias bomb?)")
    except yaml.YAMLError as e:
        raise SpecError(f"invalid YAML: {str(e).splitlines()[0][:150] if str(e) else 'syntax error'}") from None


def _norm(node, depth=0):
    """Dictionary keys become strings (YAML reads `200:` as an integer)."""
    if depth > MAX_DEPTH:
        raise SpecError("document nesting is too deep")
    if isinstance(node, dict):
        return {str(k): _norm(v, depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [_norm(v, depth + 1) for v in node]
    return node


def parse_spec(text: str) -> dict:
    if len(text) > MAX_SPEC_BYTES:
        raise SpecError("specification is larger than the limit")
    try:
        if text.lstrip().startswith("{"):
            data = json.loads(text)
        else:
            _yaml_budget(text)
            import yaml
            data = yaml.load(text, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))  # noqa: S506 - safe loader
        data = _norm(data)
    except SpecError:
        raise
    except (ValueError, RecursionError) as e:
        raise SpecError(f"cannot parse specification: {e.__class__.__name__}") from None
    except Exception as e:  # noqa: BLE001 - yaml/json internals
        raise SpecError(f"cannot parse specification: {e.__class__.__name__}") from None
    if not isinstance(data, dict):
        raise SpecError("specification is not an object")
    if str(data.get("swagger", "")).strip() == "2.0":
        return _from_swagger2(data)
    ver = data.get("openapi")
    if not isinstance(ver, str) or not ver.startswith("3."):
        raise SpecError("only OpenAPI 3.x and Swagger 2.0 specifications are supported")
    return data


# ------------------------------------------------------------------ Swagger 2.0 -> the OpenAPI 3 shape used by the diff

_REF_MAP = (("#/definitions/", "#/components/schemas/"), ("#/responses/", "#/components/responses/"))
_PARAM_SCHEMA_KEYS = ("type", "format", "enum", "items", "minimum", "maximum", "pattern", "default", "collectionFormat")


def _rewrite(node, depth=0):
    """Copy of `node` with Swagger 2 references pointing at their OpenAPI 3 locations and `x-nullable` read as `nullable`."""
    if depth > MAX_DEPTH:
        raise SpecError("document nesting is too deep")
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "$ref" and isinstance(v, str):
                for a, b in _REF_MAP:
                    if v.startswith(a):
                        v = b + v[len(a):]
                out[k] = v
            elif k == "x-nullable":
                out["nullable"] = v is True
            else:
                out[k] = _rewrite(v, depth + 1)
        if out.get("type") == "file":
            out["type"], out["format"] = "string", "binary"
        return out
    if isinstance(node, list):
        return [_rewrite(v, depth + 1) for v in node]
    return node


def _from_swagger2(sw: dict) -> dict:
    """Convert the parts of a Swagger 2.0 document that the contract diff reads. Only local references are followed."""
    glob_params = sw.get("parameters") if isinstance(sw.get("parameters"), dict) else {}
    consumes = sw.get("consumes") if isinstance(sw.get("consumes"), list) else ["application/json"]
    produces = sw.get("produces") if isinstance(sw.get("produces"), list) else ["application/json"]

    def deref_param(p):
        if isinstance(p, dict) and isinstance(p.get("$ref"), str) and p["$ref"].startswith("#/parameters/"):
            return glob_params.get(p["$ref"][len("#/parameters/"):])
        return p

    def response(r, prod):
        if not isinstance(r, dict):
            return r
        if "$ref" in r:
            return _rewrite(r)
        out = {k: v for k, v in r.items() if k not in ("schema", "headers", "examples")}
        if "schema" in r:
            out["content"] = {str(m): {"schema": _rewrite(r["schema"])} for m in prod}
        return out

    paths = {}
    for path, item in (sw.get("paths") or {}).items() if isinstance(sw.get("paths"), dict) else []:
        if not isinstance(item, dict):
            continue
        shared = [deref_param(p) for p in item.get("parameters") or []]
        new_item = {}
        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            merged: dict = {}
            for p in [*shared, *[deref_param(p) for p in op.get("parameters") or []]]:
                if isinstance(p, dict) and isinstance(p.get("in"), str) and isinstance(p.get("name"), str):
                    merged[(p["in"], p["name"])] = p
            params, body, form = [], None, []
            for p in merged.values():
                if p["in"] == "body":
                    body = p
                elif p["in"] == "formData":
                    form.append(p)
                else:
                    params.append({"name": p["name"], "in": p["in"], "required": p.get("required") is True,
                                   "schema": _rewrite({k: p[k] for k in _PARAM_SCHEMA_KEYS if k in p})})
            o: dict = {"parameters": params, "deprecated": op.get("deprecated") is True}
            cons = op.get("consumes") if isinstance(op.get("consumes"), list) else consumes
            if body is not None:
                o["requestBody"] = {"required": body.get("required") is True,
                                    "content": {str(m): {"schema": _rewrite(body.get("schema", {}))} for m in cons}}
            elif form:
                media = next((m for m in cons if "form" in str(m)), "application/x-www-form-urlencoded")
                schema = {"type": "object", "properties": {f["name"]: _rewrite({k: f[k] for k in _PARAM_SCHEMA_KEYS if k in f}) for f in form},
                          "required": [f["name"] for f in form if f.get("required") is True]}
                o["requestBody"] = {"required": any(f.get("required") is True for f in form), "content": {str(media): {"schema": schema}}}
            prod = op.get("produces") if isinstance(op.get("produces"), list) else produces
            o["responses"] = {str(c): response(r, prod) for c, r in (op.get("responses") or {}).items()} if isinstance(op.get("responses"), dict) else {}
            new_item[method] = o
        paths[path] = new_item
    comps: dict = {"schemas": _rewrite(sw.get("definitions") or {})}
    if isinstance(sw.get("responses"), dict):
        comps["responses"] = {k: response(v, produces) for k, v in sw["responses"].items()}
    base = sw.get("basePath") if isinstance(sw.get("basePath"), str) else ""
    return {"openapi": "3.0.0", "x-converted-from": "swagger-2.0", "servers": [{"url": (sw.get("host") and "https://" + str(sw["host"]) or "") + base or "/"}],
            "paths": paths, "components": comps}


# ------------------------------------------------------------------ model

@dataclass(frozen=True)
class Prop:
    type: str  # string integer number boolean object array null | any | union
    required: bool = False
    enum: frozenset | None = None
    nullable: bool = False


@dataclass
class Param:
    where: str
    name: str
    required: bool
    schema: Prop


@dataclass
class Operation:
    method: str
    path: str
    deprecated: bool = False
    params: dict = field(default_factory=dict)  # key -> Param
    request_required: dict = field(default_factory=dict)  # media -> bool
    request: dict = field(default_factory=dict)  # media -> {propath: Prop}
    responses: dict = field(default_factory=dict)  # status -> media -> {propath: Prop}


_PH = re.compile(r"\{[^{}/]*\}")


def canonical_path(path: str) -> str:
    return _PH.sub("{}", path)


class _Resolver:
    def __init__(self, root: dict):
        self.root = root
        self.unresolved: set[str] = set()
        self.truncated = False

    def resolve(self, ref: str):
        if not isinstance(ref, str) or not ref.startswith("#/"):
            self.unresolved.add(str(ref)[:80])
            return None
        node = self.root
        for part in ref[2:].split("/"):
            part = unquote(part).replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and part in node:
                node = node[part]
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                self.unresolved.add(ref[:80])
                return None
        return node

    def deref(self, node, seen=frozenset()):
        """Follow $ref chains; returns (node|None, seen)."""
        while isinstance(node, dict) and "$ref" in node:
            ref = node["$ref"]
            if ref in seen:
                return None, seen
            seen = seen | {ref}
            node = self.resolve(ref)
        return node, seen

    def merged(self, node: dict, seen, depth=0) -> dict:
        """Flatten allOf into one synthetic schema."""
        if "allOf" not in node or depth > MAX_SCHEMA_DEPTH:
            return node
        out = {k: v for k, v in node.items() if k != "allOf"}
        props = dict(out.get("properties") or {})
        req = list(out.get("required") or [])
        for part in node["allOf"] if isinstance(node["allOf"], list) else []:
            sub, s2 = self.deref(part, seen)
            if not isinstance(sub, dict):
                out["_opaque"] = True
                continue
            sub = self.merged(sub, s2, depth + 1)
            props.update(sub.get("properties") or {})
            req.extend(sub.get("required") or [])
            for k in ("type", "enum", "items", "nullable"):
                if k in sub and k not in out:
                    out[k] = sub[k]
            if sub.get("_opaque") or "oneOf" in sub or "anyOf" in sub:
                out["_opaque"] = True
        if props:
            out["properties"] = props
        if req:
            out["required"] = req
        return out

    def flatten(self, schema, side: str) -> dict[str, Prop]:
        out: dict[str, Prop] = {}
        self._walk(schema, "$", True, out, frozenset(), 0, side)
        return out

    def _walk(self, node, path, required, out, seen, depth, side):
        if depth > MAX_SCHEMA_DEPTH or len(out) >= MAX_SCHEMA_PROPS:
            self.truncated = True
            out[path] = Prop("any", required)
            return
        node, seen = self.deref(node, seen)
        if not isinstance(node, dict):
            out[path] = Prop("any", required)
            return
        node = self.merged(node, seen)
        if node.get("_opaque") or "oneOf" in node or "anyOf" in node or "not" in node:
            out[path] = Prop("union", required)
            return
        t = node.get("type")
        nullable = node.get("nullable") is True
        if isinstance(t, list):
            non_null = [x for x in t if x != "null"]
            nullable = nullable or "null" in t
            t = non_null[0] if len(non_null) == 1 else ("union" if non_null else "null")
        if not isinstance(t, str):
            t = "object" if "properties" in node else ("array" if "items" in node else "any")
        enum = node.get("enum")
        efs = None
        if isinstance(enum, list):
            efs = frozenset(json.dumps(v, sort_keys=True, default=str) for v in enum)
        out[path] = Prop(t, required, efs, nullable)
        if t == "object":
            req = node.get("required") if isinstance(node.get("required"), list) else []
            props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
            for name, sub in props.items():
                s, _ = self.deref(sub, seen)
                if isinstance(s, dict):
                    if side == "request" and s.get("readOnly") is True:
                        continue
                    if side == "response" and s.get("writeOnly") is True:
                        continue
                self._walk(sub, name if path == "$" else f"{path}.{name}", name in req, out, seen, depth + 1, side)
        elif t == "array" and "items" in node:
            self._walk(node["items"], f"{path}[]", True, out, seen, depth + 1, side)


def _content(rs: _Resolver, content, side: str) -> dict:
    res = {}
    if isinstance(content, dict):
        for media, body in content.items():
            if isinstance(body, dict) and "schema" in body:
                res[str(media).split(";")[0].strip().lower()] = rs.flatten(body["schema"], side)
    return res


def extract(spec: dict, rs: _Resolver | None = None) -> dict[tuple[str, str], Operation]:
    rs = rs or _Resolver(spec)
    ops: dict[tuple[str, str], Operation] = {}
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return ops
    for path, item in paths.items():
        item, _ = rs.deref(item)
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            raw = item.get(method)
            op, _ = rs.deref(raw)
            if not isinstance(op, dict):
                continue
            o = Operation(method, path, op.get("deprecated") is True)
            idx = 0
            order = {}
            for p in [*(item.get("parameters") or []), *(op.get("parameters") or [])]:
                p, _ = rs.deref(p)
                if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not isinstance(p.get("in"), str):
                    continue
                where, name = p["in"], p["name"]
                schema = rs.flatten(p.get("schema", {}), "request").get("$", Prop("any"))
                if where == "path":  # path variables are positional: renaming {id} to {user_id} is not a contract change
                    order.setdefault(name, len(order))
                    key = ("path", str(order[name]))
                else:
                    key = (where, name.lower() if where == "header" else name)
                o.params[key] = Param(where, name, p.get("required") is True or where == "path", schema)
                idx += 1
            body, _ = rs.deref(op.get("requestBody"))
            if isinstance(body, dict):
                for media, props in _content(rs, body.get("content"), "request").items():
                    o.request[media] = props
                    o.request_required[media] = body.get("required") is True
            responses = op.get("responses")
            if isinstance(responses, dict):
                for status, resp in responses.items():
                    resp, _ = rs.deref(resp)
                    o.responses[str(status)] = _content(rs, resp.get("content"), "response") if isinstance(resp, dict) else {}
            ops[(method, path)] = o
    return ops


def server_prefixes(spec: dict) -> list[str]:
    out = []
    for s in spec.get("servers") or []:
        if isinstance(s, dict) and isinstance(s.get("url"), str):
            url = s["url"]
            vars_ = s.get("variables") if isinstance(s.get("variables"), dict) else {}
            for k, v in vars_.items():
                if isinstance(v, dict) and "default" in v:
                    url = url.replace("{" + k + "}", str(v["default"]))
            m = re.match(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*:)?(?://[^/]*)?(/[^?#]*)?", url)
            p = (m.group(1) or "").rstrip("/") if m else ""
            if p and p != "/" and "{" not in p:
                out.append(p)
    return sorted(set(out))


# ------------------------------------------------------------------ diff

@dataclass
class ApiChange:
    rule: str  # API101 ...
    method: str
    path: str
    detail: str
    severity: str  # error | warning | info
    deprecated: bool = False


_RULES = {
    "op_removed": "API101", "param_required": "API111", "body_required": "API112", "body_prop_required": "API113",
    "request_type": "API114", "request_enum": "API115", "success_removed": "API116",
    "resp_prop_removed": "API121", "resp_type": "API122", "resp_optional": "API123", "resp_enum": "API124",
}


def _is_success(code: str) -> bool:
    return code.startswith("2") or code.lower() == "2xx"


def _cmp_types(a: Prop, b: Prop) -> bool:
    """True when both types are concrete and differ (nullable widening/narrowing handled separately by callers)."""
    skip = {"any", "union"}
    return a.type not in skip and b.type not in skip and a.type != b.type and not ({a.type, b.type} <= {"integer", "number"} and b.type == "number")


def diff(base: dict, head: dict) -> tuple[list[ApiChange], list[str]]:
    """Breaking-change candidates between two parsed specs, plus notes about what could not be compared."""
    notes: list[str] = []
    rb, rh = _Resolver(base), _Resolver(head)
    ob, oh = extract(base, rb), extract(head, rh)
    for r, label in ((rb, "base"), (rh, "head")):
        if r.unresolved:
            notes.append(f"{label} specification: {len(r.unresolved)} reference(s) could not be resolved locally (remote or missing), e.g. {sorted(r.unresolved)[0]}; schemas behind them were not compared.")
        if r.truncated:
            notes.append(f"{label} specification: a schema was deeper or larger than the comparison limit; the rest of it was not compared.")
    hmap = {(m, canonical_path(p)): o for (m, p), o in oh.items()}
    out: list[ApiChange] = []

    def add(kind, o, detail, sev):
        out.append(ApiChange(_RULES[kind], o.method, o.path, detail, sev, o.deprecated))

    for (m, p), b in sorted(ob.items()):
        h = hmap.get((m, canonical_path(p)))
        if h is None:
            add("op_removed", b, f"{m.upper()} {p} was removed" + (" (it was already marked deprecated)" if b.deprecated else ""), "error")
            continue
        _diff_op(b, h, add)
    return out, notes


def _diff_op(b: Operation, h: Operation, add) -> None:
    # parameters
    for key, hp in h.params.items():
        bp = b.params.get(key)
        if hp.required and (bp is None or not bp.required):
            add("param_required", h, f"{hp.where} parameter '{hp.name}' is " + ("new and required" if bp is None else "now required"), "warning")
        if bp is not None:
            if _cmp_types(bp.schema, hp.schema):
                add("request_type", h, f"{hp.where} parameter '{hp.name}' changed type {bp.schema.type} -> {hp.schema.type}", "warning")
            if bp.schema.enum is not None and hp.schema.enum is not None and (bp.schema.enum - hp.schema.enum):
                add("request_enum", h, f"{hp.where} parameter '{hp.name}' no longer accepts {_vals(bp.schema.enum - hp.schema.enum)}", "warning")
    # request body
    for media, hprops in h.request.items():
        if media not in b.request:
            if h.request_required.get(media) and not b.request:
                add("body_required", h, f"a {media} request body is now required", "warning")
            continue
        if h.request_required.get(media) and not b.request_required.get(media):
            add("body_required", h, f"the {media} request body is now required", "warning")
        bprops = b.request[media]
        for path, hp in hprops.items():
            bp = bprops.get(path)
            if hp.required and path != "$" and (bp is None or not bp.required) and _parent_exists(path, bprops):
                add("body_prop_required", h, f"request property '{path}' is " + ("new and required" if bp is None else "now required"), "warning")
            if bp is not None:
                if _cmp_types(bp, hp):
                    add("request_type", h, f"request property '{path}' changed type {bp.type} -> {hp.type}", "warning")
                elif bp.nullable and not hp.nullable and bp.type not in ("any", "union"):
                    add("request_type", h, f"request property '{path}' no longer accepts null", "warning")
                if bp.enum is not None and hp.enum is not None and (bp.enum - hp.enum):
                    add("request_enum", h, f"request property '{path}' no longer accepts {_vals(bp.enum - hp.enum)}", "warning")
    # responses
    bs = {c for c in b.responses if _is_success(c)}
    hs = {c for c in h.responses if _is_success(c)}
    added = sorted(hs - bs)
    for c in sorted(bs - hs):
        add("success_removed", h, f"success response {c} was " + (f"replaced by {', '.join(added)}: clients that check for {c} will misread it" if added else "removed"), "warning")
    # An operation with no explicit 2xx response uses `default` as its success response. When the head spells that response out
    # (a 2xx code) the contract did not change: compare the old default with the new success response, not with the new default
    # (which is then typically an error response).
    remap = {}
    if "default" in b.responses and not bs and hs:
        remap["default"] = sorted(hs)[0]
    for status, bmedia in b.responses.items():
        if status == "default" and status not in remap:
            continue  # the catch-all for undocumented codes (usually errors): redefining it is a clarification, not a contract break
        hmedia = h.responses.get(remap.get(status, status))
        if hmedia is None:
            continue
        for media, bprops in bmedia.items():
            hprops = hmedia.get(media)
            if hprops is None:
                continue
            for path, bp in bprops.items():
                hp = hprops.get(path)
                if hp is None:
                    if path != "$" and _parent_exists(path, hprops):
                        add("resp_prop_removed", h, f"{status} response property '{path}' was removed", "warning" if bp.required else "info")
                    continue
                if _cmp_types(bp, hp):
                    add("resp_type", h, f"{status} response property '{path}' changed type {bp.type} -> {hp.type}", "warning")
                elif hp.nullable and not bp.nullable and hp.type not in ("any", "union"):
                    add("resp_type", h, f"{status} response property '{path}' can now be null", "warning")
                if bp.required and not hp.required and path != "$":
                    add("resp_optional", h, f"{status} response property '{path}' is no longer always present", "warning")
                if bp.enum is not None and hp.enum is not None and (hp.enum - bp.enum):
                    add("resp_enum", h, f"{status} response property '{path}' can now return {_vals(hp.enum - bp.enum)}", "info")


def _parent_exists(path: str, props: dict) -> bool:
    """A property only counts as added/removed when its parent object/array was compared on both sides (not behind a union/any)."""
    if path.endswith("[]"):
        parent = path[:-2] or "$"
    elif "." in path:
        parent = path.rsplit(".", 1)[0]
    else:
        parent = "$"
    p = props.get(parent)
    return p is not None and p.type in ("object", "array")


def _vals(s: frozenset) -> str:
    return ", ".join(sorted(str(json.loads(v)) for v in s))[:120]
