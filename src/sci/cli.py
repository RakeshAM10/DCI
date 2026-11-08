"""`sci`: run every enabled change check (database migrations, API contracts) with one verdict.
All `dci analyze` options apply (--repo, --base, --fail-on, --runtime-queries, --format, ...).
Exit codes: 0 pass, 1 blocking findings, 2 usage/config error, 3 internal error."""
from __future__ import annotations

import argparse
import sys

from dci import cli as dci_cli
from dci.config import ConfigError

from . import __version__
from .run import ALL_CHECKS, run_checks


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "ui":
        return ui_main(argv[1:])
    if argv and argv[0] == "--version":
        print(f"sci {__version__}")
        return 0
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--checks", default=",".join(ALL_CHECKS), help="comma-separated checks to run: db, api")
    p.add_argument("--api-access-log", action="append", default=[], help="access-log export used as runtime evidence for API changes (repeatable)")
    p.add_argument("--sim-command", help="test command for the opt-in `sim` check, e.g. 'pytest -q --junitxml={junit}' (run without a shell on base and head)")
    p.add_argument("--sim-timeout", type=float, default=1800.0, help="seconds allowed for each test run")
    p.add_argument("--sim-env", action="append", default=[], help="environment variable name to pass to the test command (repeatable)")
    own, rest = p.parse_known_args(argv)
    if "-h" in rest or "--help" in rest:
        print("usage: sci [--checks db,api] [--api-access-log FILE] [dci analyze options]\n\n"
              "Runs database-migration and API-contract checks with one verdict. Extra options are those of `dci analyze`:\n")
        return dci_cli.main(["analyze", "--help"])
    checks = [c.strip() for c in own.checks.split(",") if c.strip()]

    def runner(cfg):
        cfg.api_access_logs = list(own.api_access_log)
        if own.sim_command:
            import shlex
            cfg.sim_command = shlex.split(own.sim_command)
        cfg.sim_timeout, cfg.sim_env = own.sim_timeout, list(own.sim_env)
        try:
            return run_checks(cfg, checks)
        except ConfigError:
            raise

    return dci_cli.main(["analyze", *rest], runner=runner)


if __name__ == "__main__":
    raise SystemExit(main())


def ui_main(argv: list[str]) -> int:
    """`sci ui [REPORT.json]`: view a report in the browser. Serves only on this computer (127.0.0.1) until stopped with Ctrl-C."""
    import http.server
    import json
    import webbrowser

    from .htmlreport import render

    p = argparse.ArgumentParser(prog="sci ui")
    p.add_argument("report", nargs="?", help="JSON from `sci --format json` (omit to choose a file in the browser)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-open", action="store_true")
    ns = p.parse_args(argv)
    text = None
    if ns.report:
        try:
            with open(ns.report, "rb") as fh:
                raw = fh.read(100_000_001)
            if len(raw) > 100_000_000:
                raise ValueError("file is larger than 100MB")
            data = json.loads(raw)
            if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
                raise ValueError("not an SCI report (no findings list)")
            text = json.dumps(data)
        except (OSError, ValueError) as e:
            print(f"sci ui: cannot use {ns.report}: {e}", file=sys.stderr)
            return 2
    page = render(text).encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.split("?")[0] != "/":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *a):  # quiet
            pass

    try:
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", ns.port), Handler)
    except OSError as e:
        print(f"sci ui: cannot listen on 127.0.0.1:{ns.port}: {e}", file=sys.stderr)
        return 2
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"SCI report at {url}  (Ctrl-C to stop)")
    if not ns.no_open:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0
