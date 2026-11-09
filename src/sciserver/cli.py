"""`sci-server`: run the server and manage repositories and licence from the command line."""
from __future__ import annotations

import argparse
import json
import signal
import sys

from .config import Settings, SettingsError
from .service import Service


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sci-server", description="SCI GitHub App server. Configuration is read from SCI_* environment variables.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="start the webhook server and workers")
    sub.add_parser("licence", help="show the licence state")
    sub.add_parser("prune", help="delete old runs and delivery ids")
    b = sub.add_parser("backup", help="write a consistent copy of the database (safe while the server is running)")
    b.add_argument("dest")
    r = sub.add_parser("repos", help="list or configure repositories")
    r.add_argument("action", choices=["list", "enable", "disable", "set"])
    r.add_argument("repo", nargs="?")
    r.add_argument("--checks", help="comma-separated checks for this repository, e.g. db,api,graphql,proto,deps,config")
    r.add_argument("--fail-on", choices=["error", "warning", "never"])
    ns = p.parse_args(argv)
    try:
        svc = Service(Settings.from_env())
    except SettingsError as e:
        print(f"sci-server: {e}", file=sys.stderr)
        return 2
    if ns.cmd == "licence":
        l = svc.licence
        print(f"{l.kind}: up to {l.max_repos} repositories. {l.message}")
        return 0
    if ns.cmd == "backup":
        try:
            svc.store.backup(ns.dest)
        except (OSError, FileExistsError) as e:
            print(f"sci-server: backup failed: {e}", file=sys.stderr)
            return 2
        print(f"backup written to {ns.dest}")
        return 0
    if ns.cmd == "prune":
        print(f"removed {svc.store.prune(svc.s.retention_days)} old runs")
        return 0
    if ns.cmd == "repos":
        if ns.action == "list":
            for row in svc.store.repos():
                print(f"{row['full_name']:50} {'disabled' if not row['enabled'] else 'over-limit' if row['over_limit'] else 'active':10} {row['settings']}")
            return 0
        if not ns.repo:
            print("sci-server: a repository (owner/name) is required", file=sys.stderr)
            return 2
        settings = {}
        if ns.checks:
            from sci.run import ALL_CHECKS
            checks = [c.strip() for c in ns.checks.split(",") if c.strip()]
            bad = [c for c in checks if c not in ALL_CHECKS]
            if bad:
                print(f"sci-server: unknown checks {bad}; choose from {', '.join(ALL_CHECKS)}", file=sys.stderr)
                return 2
            settings["checks"] = checks
        if ns.fail_on:
            settings["fail_on"] = ns.fail_on
        ok = svc.store.set_repo(ns.repo, enabled={"enable": True, "disable": False}.get(ns.action), settings=settings or None)
        print("updated" if ok else "unknown repository", file=sys.stderr if not ok else sys.stdout)
        return 0 if ok else 1
    from .http import build_server
    srv = build_server(svc)
    svc.start()
    print(json.dumps({"event": "started", "listen": f"{svc.s.host}:{srv.server_address[1]}", "licence": svc.licence.kind, "workers": svc.s.workers}), flush=True)
    import threading
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=srv.shutdown, daemon=True).start())
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        svc.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
