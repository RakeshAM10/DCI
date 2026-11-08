# SCI: Software Change Intelligence

[![CI](https://github.com/RakeshAM10/SCI/actions/workflows/ci.yml/badge.svg)](https://github.com/RakeshAM10/SCI/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)

> **Deterministic, evidence-linked pull-request safety checks for backend changes: Database Migrations, REST/OpenAPI, GraphQL, and gRPC/Protobuf contracts verified against your actual code and production runtime traffic.**

When a pull request alters a database table, removes an API endpoint, drops a GraphQL field, or shifts a Protobuf wire format, **SCI** scans your entire codebase and production runtime evidence to answer one critical question: **Does any active code or production traffic break if we deploy this right now?**

Every finding is classified as `CONFIRMED`, `POSSIBLE`, or `UNKNOWN`. **Only confirmed findings can fail CI**, eliminating false alarms and alert fatigue.

---

## The 8 Change Intelligence Engines

| Check | Flag | What It Scans | Proof of Breakage | Can It Block? |
| :--- | :--- | :--- | :--- | :---: |
| **Database Migrations** | `db` | Alembic (Python) and SQL migrations | SQLAlchemy models, SQLModel, queries, constructors, raw SQL | **Yes** (`DCI101`) |
| **REST / OpenAPI** | `api` | OpenAPI 3.x and Swagger 2.0 (`.yaml`, `.json`) | Real client callers in Python, TypeScript, Go, cURL | **Yes** (`API101`) |
| **GraphQL SDL** | `graphql` | `.graphql`, `.gql`, inline `gql` code templates | Parsed client operation documents (`queries`, `mutations`) | **Yes** (`GQL101`, `GQL104`) |
| **gRPC / Protobuf** | `proto` | Protocol Buffers files (`.proto`) | Wire-incompatible tag changes & cross-service RPC callers | **Yes** (`PRT101`, `PRT111`) |
| **Dependencies** | `deps` | `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod` | Removed dependencies still imported by active code | **Yes** (`DEP101`) |
| **Environment & Config** | `config` | `docker-compose.yml`, K8s manifests, `Dockerfile ENV`, `.env` | Removed deployment env vars still read via `os.environ["VAR"]` | **Yes** (`CFG101`) |
| **Pre-Release Simulation** | `sim` | Real test suite executed in isolated throwaway worktrees | Regression tests that passed on base and fail on head | **Yes** (`SIM101`) |
| **Runtime Evidence** | `--runtime-queries` `--api-access-log` | `pg_stat_statements` exports & HTTP access logs | Real queries/requests captured in production traffic | **Yes** (with `--runtime-blocks`) |

---

## Use It as a GitHub Action

Add this workflow to your repository to gate all pull requests:

```yaml
# .github/workflows/sci.yml
name: SCI Change Check
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write   # Posts/updates PR comments
  security-events: write # Uploads SARIF annotations to GitHub Advanced Security

concurrency:
  group: sci-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  sci:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false

      - id: sci
        uses: RakeshAM10/SCI@v1    # Pin to a full commit SHA in production
        with:
          checks: db,api,graphql,proto,deps,config
          # Optional pre-release simulation (runs your test suite in isolated worktrees):
          # simulate-command: "python -m pytest -q --junitxml={junit}"
          # Optional production runtime evidence:
          # runtime-queries: evidence/pg_stat_statements.csv
          # api-access-logs: evidence/access.log
          # runtime-blocks: "false"  # Set "true" to treat production traffic as blocking

      - name: Upload HTML Report Artifact
        if: always() && steps.sci.outputs.html-path != ''
        uses: actions/upload-artifact@v4
        with:
          name: sci-report
          path: ${{ steps.sci.outputs.html-path }}

      - name: Upload SARIF to GitHub Code Scanning
        if: always() && steps.sci.outputs.sarif-path != ''
        continue-on-error: true
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.sci.outputs.sarif-path }}
          category: sci
```

### Action Inputs

| Input | Default | Meaning |
|---|---|---|
| `checks` | `db,api,graphql,proto,deps,config` | Comma-separated checks to run |
| `simulate-command` | empty | Pre-release test command with `{junit}` XML result path (opt-in `sim` check) |
| `simulate-timeout` | `1800` | Seconds allowed per simulation test run |
| `base-ref` | PR target branch | Base branch to compare against (e.g. `origin/main`) |
| `consumer-repos` | empty | `NAME=PATH` entries for external microservice repos |
| `fail-on` | `error` | Severity threshold: `error`, `warning`, or `never` |
| `rolling-deploy` | `true` | Enforces safe expand-contract rollout windows |
| `runtime-queries` | empty | File path to `pg_stat_statements` export (CSV, JSON, JSONL) |
| `api-access-logs` | empty | File path to HTTP server access log (CLF, JSON, CSV) |
| `runtime-blocks` | `false` | When `true`, production traffic evidence is elevated to CONFIRMED |
| `config` | `.dci.toml` | Path to configuration file |
| `comment` | `true` | Posts/updates a single clean, collapsible PR summary comment |
| `github-token` | `github.token` | Token used to publish PR comment and check annotations |

**Action Outputs:** `verdict` (`pass`, `warn`, `fail`), `blocking-count`, `report-path`, `json-path`, `html-path`, `sarif-path`.

---

## Interactive Visual Interface (`sci ui`) & HTML Reports

SCI comes with a built-in, standalone visual dashboard:

```bash
# Launch the interactive web inspector in your browser:
sci ui report.json

# Launch empty UI and drag-and-drop any report file:
sci ui
```

* **Zero external network dependencies:** All styling and JavaScript are inline with strict Content Security Policy (`default-src 'none'`).
* **Auto Dark/Light mode:** Matches your system preference seamlessly.
* **Filter & Accordion View:** Instantly toggle findings by confidence (*Confirmed*, *Possible*, *Unknown*) and click to reveal code snippets and mitigation advice.

You can also export self-contained HTML files directly:
```bash
sci --repo . --base origin/main --format html --output report.html
```

---

## Use It as a CLI

Install locally or in your custom CI runner (Python 3.11+):

```bash
pip install .
```

### Run All Checks (Database + API + GraphQL + gRPC)
```bash
# Compare your current working branch against main
sci --repo . --base origin/main

# Run specific checks only
sci --repo . --base origin/main --checks db,api

# Output JSON or SARIF for automated tooling
sci --repo . --base origin/main --format json --output report.json
sci --repo . --base origin/main --format sarif --output report.sarif
```

### Run Database Check Alone (`dci`)
```bash
dci analyze --base origin/main
dci analyze --migration migrations/002_drop_column.sql
```

---

## Detailed Rule Guides

### 1. Database Migrations (`dci`)
Scans Alembic revisions and raw SQL migrations. Parses models in SQLAlchemy, SQLModel, and raw SQL queries.

- **DCI101 (Error, Confirmed):** Dropped or renamed column/table is still referenced in code.
- **DCI102 (Warning, Confirmed):** Dropped column is only referenced in test files (non-blocking).
- **DCI103 (Error, Confirmed):** Rollout-window violation: old application versions will crash during rolling deployments.
- **DCI104 (Error, Confirmed):** New `NOT NULL` column added without a default value to an existing populated table.
- **DCI105 (Info, Unknown):** Advises caution when external consumers outside the scanned code cannot be seen.

### 2. REST & OpenAPI (`api`)
Compares the base specification with the candidate specification for OpenAPI 3.x and on-the-fly translated Swagger 2.0.

- **API101 (Error, Confirmed):** Endpoint removed from specification while active callers exist in code.
- **API102 (Warning, Confirmed):** Removed endpoint called only from test suites.
- **API111–116 (Warning, Possible):** New required parameter or request body, narrowed enum, or altered response schema.
- **API121–124 (Info, Possible):** Added response properties or expanded enum choices.

### 3. GraphQL Schemas (`graphql`)
Diffs `.graphql` SDL schemas and validates field-level usage against parsed Apollo/client operation documents (`queries` and `mutations`).

- **GQL101 (Error, Confirmed):** Removed type, field, or enum value that is still requested by a client operation.
- **GQL104 (Error, Confirmed):** New mandatory argument added to a field that existing client queries do not supply.
- **GQL102 / GQL106 (Warning):** Breaking schema change only affects test queries.
- **GQL113 / GQL114 (Possible):** Type alteration or union member modifications.

### 4. gRPC / Protocol Buffers (`proto`)
Compiles `.proto` revisions via `grpc_tools.protoc` into real descriptor sets.

- **PRT111 (Error, Confirmed):** Wire-incompatible change (field tag number modified, field moved to incompatible wire type, altered RPC signature).
- **PRT101 (Error, Confirmed):** Removed service RPC that is still invoked by client code.
- **PRT102 (Warning):** Removed RPC called only from test files.
- **PRT112 (Warning, Possible):** Unreserved field numbers or names removed without `reserved` declaration.

### 5. Dependency Manifests (`deps`)
Scans package manifests (`package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`).

- **DEP101 (Error, Confirmed):** Removed dependency is still imported by active code at head (causes runtime `ImportError`).
- **DEP102 (Warning, Possible):** Major-version dependency upgrade detected (may introduce breaking upstream changes).
- **DEP103 (Info, Unknown):** Dependency removed with no active code imports detected.

### 6. Deployment Configuration & Env (`config`)
Scans deployment declarations (`docker-compose.yml`, Kubernetes env, `Dockerfile ENV`, `.env` files) against environment variable reads in code.

- **CFG101 (Error, Confirmed):** Removed variable from deployment while code still reads `os.environ["VAR"]` without a default value.
- **CFG102 (Warning, Possible):** Code introduces new required `os.environ["VAR"]` without a declaration or fallback.

### 7. Pre-Release Simulation (`sim`)
Executes the project's own test suite in clean, isolated throwaway Git worktrees with scrubbed environments.

- **SIM101 (Error, Confirmed):** Test that passed on base revision fails on the pull request (verified twice to rule out flakiness).
- **SIM102 (Warning, Confirmed):** A new test added by the pull request fails.
- **SIM103 (Warning, Possible):** Flaky test detected (failed once, passed on re-run).
- **SIM901 / SIM902 (Warning, Unknown):** Test suite failed to produce JUnit results or timed out.

---

## Production Runtime Evidence

Static code scanning only sees code in the repositories you provide. To cover third-party services, legacy jobs, and mobile apps, ingest real production traffic:

### Database Query Ingestion
```sql
-- Export active query statistics from PostgreSQL
\copy (select query, calls from pg_stat_statements) to 'queries.csv' csv header
```
```bash
sci --repo . --base origin/main --runtime-queries queries.csv
# When you vouch statistics are current, elevate to blocking:
sci --repo . --base origin/main --runtime-queries queries.csv --runtime-blocks
```

### HTTP Access Log Ingestion
Accepts Common Log Format (CLF), Combined Log Format, JSON, JSON Lines, or CSV exports (`method`, `path`, `status`).
```bash
sci --repo . --base origin/main --api-access-log access.log
```

---

## Historical Replay & Validation Tool

Before enabling SCI as a blocking gate, evaluate its performance and calibrate rules over your team's real Git commit history:

```bash
# Replay all OpenAPI commits in history
python tools/replay.py . --max 50 --checks api

# Replay GraphQL commits
python tools/replay.py . --max 50 --checks graphql
```

---

## Security & Architecture Principles

- **Zero Database Connections:** Never connects to your live production database.
- **Zero Arbitrary Code Execution:** Static AST and SQLGlot parsing only. Never imports Python modules or executes scripts.
- **Strict Bounded Resources:** Bounded memory structures (flat memory footprint under high-volume hits), bounded YAML entity expansions, and configurable scan budgets (`--time-budget`, `--max-total-bytes`).
- **Data Privacy & Redaction:** SQL query literals and sensitive API tokens are automatically redacted before reporting.

---

## Development & Testing

Run the full automated test suite (250+ tests across PostgreSQL ground truth, AST scale repos, OpenAPI, GraphQL, Protobuf, Dependencies, Configuration, and Worktree Simulation):

```bash
# Setup environment
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .[dev]

# Run full test suite
pytest -q
```
