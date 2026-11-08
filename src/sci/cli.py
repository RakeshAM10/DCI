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
    if argv and argv[0] == "--version":
        print(f"sci {__version__}")
        return 0
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--checks", default=",".join(ALL_CHECKS), help="comma-separated checks to run: db, api")
    p.add_argument("--api-access-log", action="append", default=[], help="access-log export used as runtime evidence for API changes (repeatable)")
    own, rest = p.parse_known_args(argv)
    if "-h" in rest or "--help" in rest:
        print("usage: sci [--checks db,api] [--api-access-log FILE] [dci analyze options]\n\n"
              "Runs database-migration and API-contract checks with one verdict. Extra options are those of `dci analyze`:\n")
        return dci_cli.main(["analyze", "--help"])
    checks = [c.strip() for c in own.checks.split(",") if c.strip()]

    def runner(cfg):
        cfg.api_access_logs = list(own.api_access_log)
        try:
            return run_checks(cfg, checks)
        except ConfigError:
            raise

    return dci_cli.main(["analyze", *rest], runner=runner)


if __name__ == "__main__":
    raise SystemExit(main())
