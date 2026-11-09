"""HTTP front end: signed webhook endpoint, health probes and a password-protected, read-only dashboard. Standard library only; run it behind
a TLS-terminating reverse proxy (see deploy/)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sci.htmlreport import render

from .service import Service

SECURITY = {"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=31536000"}


def verify_signature(secret: bytes, body: bytes, header: str | None) -> bool:
    """GitHub signs the raw body: X-Hub-Signature-256 = 'sha256=' + HMAC-SHA256(secret, body). Compared in constant time."""
    if not header or not header.startswith("sha256="):
        return False
    return hmac.compare_digest(hmac.new(secret, body, hashlib.sha256).hexdigest(), header[7:])


class _FailureLimiter:
    def __init__(self, limit: int = 10, window: float = 300):
        self.limit, self.window, self.hits, self.lock = limit, window, {}, threading.Lock()

    def blocked(self, ip: str) -> bool:
        with self.lock:
            now = time.time()
            self.hits[ip] = [t for t in self.hits.get(ip, []) if now - t < self.window]
            return len(self.hits[ip]) >= self.limit

    def fail(self, ip: str) -> None:
        with self.lock:
            self.hits.setdefault(ip, []).append(time.time())


_CSS = """:root{--bg:#f2f2f7;--card:#fff;--l:#000;--l2:rgba(60,60,67,.6);--sep:rgba(60,60,67,.18);--blue:#007aff;--red:#ff3b30;--orange:#ff9500;--green:#34c759;--gray:#8e8e93}
@media(prefers-color-scheme:dark){:root{--bg:#000;--card:#1c1c1e;--l:#fff;--l2:rgba(235,235,245,.6);--sep:rgba(84,84,88,.65);--blue:#0a84ff;--red:#ff453a;--orange:#ff9f0a;--green:#30d158;--gray:#98989d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--l);font:17px/1.35 -apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue",Arial,sans-serif}
main{max-width:760px;margin:0 auto;padding:8px 16px 48px}h1{font-size:34px;margin:22px 0 4px;letter-spacing:.2px}.sub{color:var(--l2);font-size:15px;margin:0 0 16px}
.sect{color:var(--l2);font-size:13px;text-transform:uppercase;letter-spacing:.3px;margin:24px 16px 6px}.list{background:var(--card);border-radius:12px;overflow:hidden}
.row{display:flex;gap:12px;align-items:center;padding:12px 16px;color:inherit;text-decoration:none;position:relative}.row+.row:before{content:"";position:absolute;top:0;left:16px;right:0;border-top:.5px solid var(--sep)}
.dot{flex:none;width:10px;height:10px;border-radius:50%}.rt{flex:1;min-width:0}.rt b{display:block;font-weight:500;overflow-wrap:anywhere}.rt small{color:var(--l2);font-size:14px}
.tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.tile{background:var(--card);border-radius:14px;padding:12px 14px}.tile b{display:block;font-size:28px}.tile span{color:var(--l2);font-size:13px}
.note{background:var(--card);border-radius:12px;padding:12px 16px;margin:12px 0;color:var(--l2);font-size:15px}"""
_COLOR = {"failure": "var(--red)", "success": "var(--green)", "neutral": "var(--orange)"}


def _ago(t: float | None) -> str:
    if not t:
        return ""
    d = max(0, int(time.time() - t))
    return f"{d}s ago" if d < 90 else f"{d // 60}m ago" if d < 5400 else f"{d // 3600}h ago" if d < 172800 else f"{d // 86400}d ago"


def dashboard(svc: Service) -> str:
    e = html.escape
    st, lc = svc.store, svc.licence
    c = st.counts()
    out = [f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>SCI</title><style>{_CSS}</style></head><body><main>",
           "<h1>SCI</h1><p class=sub>Software change checks for your repositories</p>"]
    out.append(f"<div class=tiles><div class=tile><b>{c.get('queued', 0)}</b><span>Queued</span></div><div class=tile><b>{c.get('running', 0)}</b><span>Running</span></div>"
               f"<div class=tile><b>{c.get('failed', 0)}</b><span>Errors</span></div></div>")
    tone = {"valid": "", "community": "", "expired": " style='color:var(--red)'", "invalid": " style='color:var(--red)'"}[lc.kind]
    out.append(f"<div class=note{tone}><b>Licence: {e(lc.kind)}</b>{' · ' + e(lc.customer) if lc.customer else ''} · up to {lc.max_repos} repositories"
               f"{' · expires ' + e(lc.expires) if lc.expires else ''}<br>{e(lc.message)}</div>")
    out.append("<div class=sect>Repositories</div><div class=list>")
    repos = st.repos()
    for r in repos:
        state = "over licence limit" if r["over_limit"] else "disabled" if not r["enabled"] else f"{r['runs']} run(s)"
        out.append(f"<div class=row><span class=dot style='background:{_COLOR.get(r['last_conclusion'], 'var(--gray)')}'></span><div class=rt><b>{e(r['full_name'])}</b><small>{e(state)}</small></div></div>")
    if not repos:
        out.append("<div class=row><div class=rt><small>No repositories yet. Install the GitHub App on a repository.</small></div></div>")
    out.append("</div><div class=sect>Recent runs</div><div class=list>")
    runs = st.runs(30)
    for r in runs:
        label = r["conclusion"] or r["status"]
        sub = f"PR #{r['pr_number']} · {label}" + (f" · {r['blocking']} blocking" if r["blocking"] else "") + (f" · {e(str(r['error'])[:80])}" if r["error"] else "") + f" · {_ago(r['finished'] or r['created'])}"
        out.append(f"<a class=row href='/runs/{int(r['id'])}'><span class=dot style='background:{_COLOR.get(r['conclusion'], 'var(--gray)')}'></span><div class=rt><b>{e(r['full_name'])}</b><small>{sub}</small></div></a>")
    if not runs:
        out.append("<div class=row><div class=rt><small>No runs yet.</small></div></div>")
    out.append("</div></main></body></html>")
    return "".join(out)


def make_handler(svc: Service, limiter: _FailureLimiter):
    secret, admin = svc.s.webhook_secret, svc.s.admin_token.encode()

    class H(BaseHTTPRequestHandler):
        server_version = "sci"
        sys_version = ""
        timeout = 30

        def log_message(self, *a):
            pass

        def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8", extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in {**SECURITY, **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code: int, obj: dict):
            self._send(code, json.dumps(obj).encode(), "application/json")

        def _authed(self) -> bool:
            ip = self.client_address[0]
            if limiter.blocked(ip):
                self._send(429, b"too many failed attempts\n", extra={"Retry-After": "300"})
                return False
            h = self.headers.get("Authorization", "")
            if h.startswith("Basic "):
                try:
                    _, _, pw = base64.b64decode(h[6:], validate=True).decode("utf-8").partition(":")
                    if hmac.compare_digest(pw.encode(), admin):
                        return True
                except (ValueError, UnicodeDecodeError):
                    pass
            limiter.fail(ip)
            self._send(401, b"authentication required\n", extra={"WWW-Authenticate": 'Basic realm="SCI", charset="UTF-8"'})
            return False

        def do_POST(self):  # noqa: N802
            if self.path != "/webhook":
                return self._send(404, b"not found\n")
            try:
                n = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self._send(411, b"Content-Length required\n")
            if n < 0 or n > svc.s.max_body:
                return self._send(413, b"payload too large\n")
            body = self.rfile.read(n)
            if len(body) != n or not verify_signature(secret, body, self.headers.get("X-Hub-Signature-256")):
                return self._send(401, b"invalid signature\n")
            try:
                payload = json.loads(body)
                if not isinstance(payload, dict):
                    raise ValueError
            except ValueError:
                return self._send(400, b"invalid JSON\n")
            code, msg = svc.handle_event(self.headers.get("X-GitHub-Event", ""), self.headers.get("X-GitHub-Delivery", ""), payload)
            self._json(code, {"message": msg})

        def do_GET(self):  # noqa: N802
            path = self.path.split("?")[0]
            if path == "/healthz":
                return self._send(200, b"ok\n")
            if path == "/readyz":
                try:
                    svc.store.counts()
                except Exception:  # noqa: BLE001
                    return self._send(503, b"database unavailable\n")
                return self._send(200, b"ready\n")
            if not self._authed():
                return
            if path == "/":
                return self._send(200, dashboard(svc).encode(), "text/html; charset=utf-8")
            if path.startswith("/runs/"):
                tail = path[6:]
                job = svc.store.job(int(tail)) if tail.isdigit() and len(tail) < 12 else None
                if not job or not job["report"]:
                    return self._send(404, b"no report for this run\n")
                return self._send(200, render(job["report"]).encode(), "text/html; charset=utf-8")
            return self._send(404, b"not found\n")

        do_HEAD = do_GET  # noqa: N815

    return H


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


def build_server(svc: Service) -> Server:
    return Server((svc.s.host, svc.s.port), make_handler(svc, _FailureLimiter()))
