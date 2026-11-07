# DCI: Database Change Intelligence

> **Next-generation database safety: from PR static analysis to live runtime query intelligence and automated safe migration planning.**

A pull-request check for PostgreSQL migrations. When a PR adds an Alembic or SQL migration, DCI finds the code that
depends on the changed tables and columns (SQLAlchemy models and queries, raw SQL, `.sql` files, other repositories),
says whether the change can break it, **shows the file and line as evidence**, and suggests a safe expand/contract
sequence. Every finding is labelled `confirmed`, `possible` or `unknown`; **only confirmed findings can fail CI**.

DCI is deterministic static analysis. It never connects to your database and never imports or runs your code.

## Use it as a GitHub Action

```yaml
# .github/workflows/dci.yml
name: DCI database change check
on: pull_request
permissions:
  contents: read
  pull-requests: write      # PR comment
  security-events: write    # optional: SARIF upload
jobs:
  dci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: YOUR-ORG/dci@v1      # pin to a full commit SHA in production
```

Other services that share the database: check them out inside the workspace and list them, one per line:

```yaml
      - uses: YOUR-ORG/dci@v1
        with:
          consumer-repos: |
            billing=consumers/billing
```

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `base-ref` | PR base branch | Branch the PR targets |
| `consumer-repos` | empty | `NAME=PATH` lines for other repositories inside the workspace |
| `fail-on` | `error` | `error`, `warning` or `never`; applies to CONFIRMED findings only |
| `rolling-deploy` | `true` | Old app versions run against the new schema during deploys (rollout-window errors) |
| `config` | `.dci.toml` | Config file path (read from the **base branch**, not the PR) |
| `trust-pr-config` | `false` | Read the config from the PR instead. Off by default so a PR author cannot weaken the check by editing `.dci.toml` |
| `working-directory` | `.` | Repository root to analyse |
| `comment` | `true` | Post/update one PR comment |
| `github-token` | `github.token` | Used only for the PR comment |
| `python-version` | `3.12` | Python 3.11+ |

Outputs: `verdict` (`pass`, `warn`, `fail`, `skipped`), `blocking-count`, `report-path`, `json-path`, `sarif-path`.
On events that are not pull requests and without `base-ref`, the action skips with a notice.
Examples: `examples/workflows/`. Sample config: `examples/dci.toml`.

## Use it as a CLI

```bash
pip install .                     # Python 3.11+
dci analyze --base origin/main                      # migrations added/modified since the merge-base
dci analyze --migration db/migrations/0002.sql --consumer billing=../billing-service
dci analyze --base origin/main --format sarif --output dci.sarif
```
Exit codes: `0` pass, `1` blocking findings, `2` usage/config error, `3` internal error (fail closed).

## What it checks

Drop/rename of columns and tables that are still referenced (including the rollout window where the previous app
version still uses what the PR removes), NOT NULL changes and the writers they break, blocking index/unique/foreign-key/
check changes, risky type changes. Rule catalog and semantics: `docs/DCI_BRAIN.md` section 5.
Suppress an accepted risk inline with `# dci: ignore[DCI501] reason`; suppressions are listed in every report.

## Limits (read these)

Python/SQLAlchemy and SQL only; PostgreSQL only. Dynamic SQL whose names come from variables, other services, jobs and
BI tools are invisible unless their repository is passed in. No runtime evidence yet. Absence of a finding is not proof
of safety: each report prints its coverage. See `docs/DCI_BRAIN.md` section 13.

## Develop

```bash
pip install -e ".[dev]" sqlalchemy alembic
(cd tools/pgcheck && npm install)      # real PostgreSQL (PGlite) used as test ground truth
python -m pytest -q
```


## Config trust

In the Action, `.dci.toml` is read from the base branch as committed there. If a PR adds, changes or deletes it, DCI warns and the change applies after merge. The `fail-on`, `rolling-deploy` and other inputs live in the workflow file, so protect that file (CODEOWNERS / branch protection) as well. In the CLI, consumer repositories named in `.dci.toml` must be inside the repository's parent directory unless `--allow-outside-config-paths` is given (`--consumer` flags are never restricted; `--workspace` is stricter).

Recommended hardening: leave `fail-on` and `rolling-deploy` unset in the workflow and keep them in `.dci.toml` (read from the base branch), and require review of `.github/workflows/` and `.dci.toml` with CODEOWNERS (`examples/CODEOWNERS`) plus branch protection. A PR can edit an input that is written in the workflow file.
