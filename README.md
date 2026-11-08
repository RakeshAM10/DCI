# DCI: Database Change Intelligence

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


## Optional AI assistance (advisory)

`ai-assist: true` (Action) or `--ai` (CLI) adds a verdict hint, a short explanation and a suggested fix to findings, using the Anthropic API. It is off by default.

- It can never change a finding's severity or confidence or the pass/fail result. Only the deterministic engine decides what blocks.
- Privacy: only code lines around each piece of evidence are sent, after the same redaction as reports (secrets, credentials in URLs, SQL literals), for at most `ai-max-findings` findings (default 5). Nothing is sent without an API key.
- Trust: a "likely breaks / likely safe" answer is kept only if a quote it cites really appears next to the cited line in the code that was sent; otherwise the answer is discarded. Answers are plain text only (no links, HTML or mentions).
- Failures (network, API errors, bad answers) become a coverage note and never fail the check. Fork pull requests get no secrets, so AI assistance is skipped there.

```yaml
- uses: YOUR-ORG/dci@<sha>
  with:
    ai-assist: "true"
    ai-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Runtime evidence (queries seen in production)

Static analysis only sees code in the scanned repositories. To also cover services in other languages, export the queries your database really ran and pass them in:

```sql
\copy (select query, calls from pg_stat_statements) to 'queries.csv' csv header
```

```
dci analyze --base main --runtime-queries queries.csv          # reported as POSSIBLE
dci analyze --base main --runtime-queries queries.csv --runtime-blocks   # you vouch the statistics are current: CONFIRMED, can fail the check
```

Action inputs: `runtime-queries`, `runtime-blocks`. Accepted formats: CSV with a `query` column, JSON list, `{"queries": [...]}`, or JSON Lines (max 50 MB / 200,000 rows). Files are parsed as data and never executed; literals are redacted in reports. Statistics have no timestamp, so by default they never block on their own.

## SCI: API-contract checks (`sci`)

`sci` runs every enabled change check with one verdict and one exit code. `dci analyze` still runs the database check alone.

```
sci --repo . --base origin/main                       # db + api
sci --repo . --base origin/main --checks api --api-access-log access.log
```

**What the API check does.** For each OpenAPI 3.x file changed in the PR (`api_spec_globs`, default `openapi*.{yaml,yml,json}`, `swagger*`, `*.openapi.*`), it compares the base and head versions and reports breaking changes:

| Rule | Change | Can it block? |
|---|---|---|
| API101 | endpoint removed and still called (method + path visible on a call) | yes, CONFIRMED |
| API102/103/105 | removed endpoint called only from tests / possibly called / no caller visible | no / no / info |
| API111-116 | new or newly required parameter, body or property; changed request type; narrowed request enum; success response removed | no (POSSIBLE) |
| API121-124 | response property removed, type changed, no longer always present; enum gained values | no (POSSIBLE) |
| API901/902 | scan incomplete / specification could not be parsed | no (UNKNOWN) |

Callers are found in **any language** by matching string literals (and bare URLs in scripts) against the path templates, and a route definition (`@app.route`, `router.get`, `@GetMapping`, `HandleFunc`...) is never counted as a caller. Only a removed endpoint can be CONFIRMED, because only then does a visible call prove the break; for every other change DCI cannot see what a client sends or reads, so it stays POSSIBLE.

**Runtime evidence.** `--api-access-log` accepts JSON, JSON Lines, CSV (`method`, `path`, optional `count`, `status`) or Common/Combined Log Format. Endpoints that only ever returned errors are ignored. Like query statistics, logs are POSSIBLE unless `--runtime-blocks` says they are current.

**Security.** Specifications and logs are data: YAML alias expansion, nesting, size and row counts are bounded before anything is built, remote `$ref`s are never fetched, nothing is executed. Memory stays flat on huge repositories (at most 500 references kept per category, the rest are counted).

**Swagger 2.0** files are converted on the fly (parameters, body, formData, responses, definitions, basePath) and checked with the same rules.

**Not covered yet:** gRPC/AsyncAPI, `oneOf`/`anyOf` bodies (not compared, to avoid guessing), changed authentication requirements, and callers that build URLs from several variables.

GitHub Action: `checks: db,api,graphql,proto` (default) and `api-access-logs`.

### Validating on your own history

`python tools/replay.py REPO [--max N] [--globs GLOB,...]` replays the API check over every commit that changed an OpenAPI file, as if each were a PR against its parent, and prints every finding for a human to judge. Use it before enabling the check as blocking. It was used on `swagger-petstore` (55 spec commits), Redocly's museum example and Stripe's 8 MB spec; those runs found and fixed three false-positive classes (a redefined `default` response, grouped identical findings, specs above the source-file size limit).

## SCI: GraphQL checks (`--checks graphql`)

GraphQL clients name every field they use, so this check can *prove* breaks. It builds the base and head schema from the SDL (`*.graphql`, `*.graphqls`, `*.gql`, merged across files, plus `typeDefs = gql`...`` strings in changed code files), compares them with graphql-core, then parses the operation documents found in code (`gql` templates, triple-quoted strings, `.graphql` files) and resolves every field, argument, type and enum value against the **base** schema.

| Rule | Meaning | Can it block? |
|---|---|---|
| GQL101 | removed field / argument / type / enum value that an operation still uses | yes, CONFIRMED |
| GQL104 | a new required argument that an operation does not pass | yes, CONFIRMED |
| GQL102 / GQL106 | the same, but only in test code | no (warning) |
| GQL105 | removal or addition with no visible client | no (info, UNKNOWN) |
| GQL113 | field or argument changed type; clients using it listed | no (POSSIBLE) |
| GQL114 | other breaking changes (union member, interface, directive) with no usage analysis | no (POSSIBLE) |
| GQL121 | changes that can affect clients (enum value added, optional argument added) | no (info) |
| GQL902 | a schema could not be built or parsed | no (UNKNOWN) |

Test files (`__tests__`, `*.spec.*`, `*.test.*`, `src/test`, ...) are recognised by `test_globs`. Limits: operations built by string concatenation, persisted queries and generated clients that no longer contain the query text cannot be seen; a schema split between unchanged code strings and `.graphql` files may fail to build (reported as GQL902, never silently passed).

## SCI: gRPC / Protocol Buffers checks (`--checks proto`)

Each revision's `.proto` files are compiled with the real `protoc` (grpcio-tools) into descriptors, so nested types, oneof, maps and imports are parsed exactly. Files whose imports are not in the repository are left out and listed in the coverage notes (never guessed).

| Rule | Meaning | Can it block? |
|---|---|---|
| PRT111 | wire-incompatible change: field number changed, incompatible field type, singular/repeated switch, new proto2 `required` field, enum number changed, RPC request/response/streaming changed | yes, CONFIRMED (the contract itself breaks every deployed peer; no caller needs to be found) |
| PRT101 | removed RPC that code still calls (`stub.Method(` in a file that also uses the service name, or the `/pkg.Service/Method` path) | yes, CONFIRMED |
| PRT102 / PRT103 / PRT105 | removed RPC called only from tests / possibly called (method name shared with another service) / no caller visible | no |
| PRT112 | risky: field or enum value removed without `reserved`, message removed, rename, same-wire type change (int32 to int64, string to bytes) | no (POSSIBLE) |
| PRT902 | the .proto files could not be compiled | no (UNKNOWN) |

Generated code (`*_pb2*.py`, `*.pb.go`, `*Grpc.java`, ...) and server implementations are never counted as callers. Limits: callers are matched by name, not by type; HTTP/JSON transcoding annotations are not compared.

## Trying SCI on a real pull request

1. Publish this repository and use it as an action: `uses: YOUR-ORG/sci@<full commit SHA>` (see `examples/workflows/sci.yml`).
2. `tools/demo_pr.sh YOUR-ORG/sci@<sha>` opens a private demo repository with a real pull request that breaks the database, the REST API, GraphQL and gRPC; the `SCI` check should fail with 5 blocking findings and post a PR comment. Delete the demo with `gh repo delete`.
3. `.github/workflows/selftest.yml` runs the same scenario on a GitHub runner on every push and fails if any of the five expected findings is missing.
