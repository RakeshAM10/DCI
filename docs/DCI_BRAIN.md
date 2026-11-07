# DCI BRAIN — master context for building Database Change Intelligence

Read this file completely before doing anything. It is the single source of truth for a fresh Claude session
(any account) that must continue this project without the original conversation.

Prepared: 5 Nov 2026. Project root: the folder that contains this `docs/` directory.

---------------------------------------------------------------------------------------------------

## 0. Kickoff prompt (paste this into the new session, with the project folder attached)

> You are continuing an existing project, "DCI" (Database Change Intelligence). Read `docs/DCI_BRAIN.md` fully, then
> `src/dci/*.py` and `tests/`. Do NOT redesign. First run the setup in section 9 and the full test suite, and report the
> real result. Then work through the backlog in section 10 in priority order. Hard rules are in section 11: no mock data,
> verify every behavioural claim against a real PostgreSQL engine, never state something as verified unless you ran it.

---------------------------------------------------------------------------------------------------

## 1. What DCI is (one paragraph)

DCI is a pull-request safety check. When a PR contains a PostgreSQL migration (Alembic `.py` or raw `.sql`), DCI finds
which application code depends on the changed tables/columns (SQLAlchemy models, ORM queries, raw SQL, f-strings, SQL
files, other repositories), decides whether the change can break that code, shows **evidence (file + line)** for every
finding, labels each finding **confirmed / possible / unknown**, and suggests a safe expand/contract sequence. Only
**confirmed** findings can fail CI. It is deterministic static analysis; it never executes customer code and never
touches a database.

## 2. Decision history (why this design)

* The user's strategy report (4 Nov 2026) recommended **CONDITIONAL GO**: do not build a broad "AI that understands all
  software"; build the narrow wedge "cross-service database migration compatibility during rolling deployments".
* My independent view: a build is only justified after discovery (≥5 teams with repeated costly migration incidents,
  real dependencies found that their process missed, ≥1 willingness to pay). The user nevertheless chose to build V1.
  Keep the discovery gates in section 12; do not claim market validation that has not happened.
* User chose defaults (no preference): **Python + SQLAlchemy/Alembic on PostgreSQL**, delivered as **CLI + GitHub Action**
  first, scope **V1 static engine**. A hosted GitHub App and runtime evidence (V2) are later phases.

## 3. Competitor research (what is verified)

Method used for "most efficient": static, deterministic analysis as the core; runtime telemetry later; LLM only for
explanation. Reasons: seconds and near-zero cost per PR, reproducible, every finding auditable.

### PlayerZero (Sim-1) — LLM simulation
Verified (from playerzero.ai/research/sim-1, fetched 4 Nov 2026; all numbers are vendor-reported, not independent):
* An ensemble of models plus specialised agents; builds a semantic dependency graph across services/repos; scenarios in
  plain English (or inferred from code/tickets); simulations trace execution paths with confidence scores and
  state traces linked to code lines.
* Default simulations 5–10 minutes ("90% of the value at 20% of the cost"); long runs >30 min; doubling inference compute
  reduces error ~40% (vendor claim).
* Numbers claimed: 2,770 scenarios; CodeSearchNet MRR 0.873 (prior SOTA 0.792); 96% cross-language behavioural
  similarity; 99.2% state consistency over long traces; 50+ service boundaries. An older resources page (3 Oct 2025)
  says 92.6% "simulation accuracy" vs 73.8% for general models. MRR is a code-retrieval metric, weak evidence for
  predicting migration breakage.
* Stated limits: non-deterministic / hardware-specific behaviour; external systems only from observed patterns.
* Not found: any schema/migration-specific capability; how the graph is built (static vs LLM vs tracing) is not disclosed.
* Funding seen: $15M Series A (Foundation Capital, Aug 2025); named customer Zuora. A Techleap headline says "$20M"
  (unread, unverified).
Lesson: do not copy broad simulation. It is slow, non-deterministic and unauditable for a "block the PR" decision.

### Datadog (Bits Release, DBM) — post-deploy telemetry
Verified from docs.datadoghq.com:
* Bits Release: **Preview**, access by request, GitHub only. Needs Datadog GitHub App (Contents: Read, Pull requests:
  Write), a `version` tag on services and the deployed commit SHA (`git.commit.sha`). Flow: PR merges → analyse expected
  impact → wait for deploy → evaluate telemetry → verdict (Passed / Failed / Not enough data / Inconclusive). It is
  **post-merge**, so it cannot stop a bad migration before deploy.
* DBM ↔ APM correlation: database spans need `db.system` and `db.statement`; query signature links spans to query
  samples/plans. Service-level attribution needs a **SQL comment** injected into queries with `dddbs` (service), `dde`
  (env), `ddps` (parent service), `ddpv` (service version). OpenTelemetry auto-instrumentation does NOT add the comment.
  Stored procedure calls (`CALL x()`) are not correlated.
* Q3 2026 results (8-K, 4 Nov 2026): revenue $1.197B, +35% YoY. **FY2025 figures in the user's report ($3.43B, 28%,
  32,700 customers) were NOT verified.** Do not cite them as current run-rate.
Lesson: reuse this mechanism for V2 runtime evidence (query comment with service+version, query fingerprints) instead
of building a telemetry backend.

### NOT researched (treat as unknown)
Arcan, Bytebase, Atlas (Ariga), Liquibase, Flyway, Squawk, pgroll, Greptile, Qodo, CodeScene, Cleric, Resolve AI,
Traversal. Research was cut off by a rate limit. Atlas and Bytebase are the most likely to add consumer analysis:
research them first (does Atlas lint/monitoring read application code? multi-repo consumer mapping?).
Problem frequency and market size are also unverified; unsourced statistics in earlier notes ("80% of DB outages",
"20%+ deployment failure") must not be used.

## 4. Architecture (what exists in `src/dci/`)

| File | Responsibility | Status |
|---|---|---|
| `models.py` | dataclasses: Change, Reference, Finding, Report, Coverage; enums Severity/Confidence/ChangeKind | written |
| `sqlutil.py` | quote/comment/dollar-quote aware statement splitter; bind-param normaliser (`:x`, `%s`, `%(x)s`, `$1` → NULL) | written, smoke-tested |
| `migrations.py` | Alembic `upgrade()` via `ast` (op.*, batch_alter_table, op.execute) + SQL via SQLGlot (postgres) → Change list; unparseable → ParseIssue (never silent) | written, smoke-tested |
| `consumers.py` | Two-pass scanner. Pass 1: SQLAlchemy models (Column/mapped_column, mixins, inheritance, flask default names), Core `Table`. Pass 2: ORM attributes, constructors, `filter_by`, `getattr`, `ForeignKey("t.c")`, `table()/column()`, raw SQL (text/execute/any SQL-like constant), f-strings, `+` concat, `%`, `.format`, `.sql` files. Relevance prefilter skips files that cannot mention changed objects | written, smoke-tested |
| `rules.py` | rule engine (catalog in section 5) | written, exercised by corpus |
| `analyze.py` | orchestration: git merge-base, changed migrations, head + base + consumer trees, targets, rules, inline suppressions | written |
| `sources.py` | read-only trees: working dir or git object DB (`cat-file --batch`); no symlink following, size limit, excluded dirs, glob matcher | written |
| `gitutil.py` | injection-safe git (arg lists, rev-name validation) | written |
| `config.py` | `.dci.toml` loading/validation | written |
| `report.py` | text, Markdown (PR comment with marker), JSON, SARIF 2.1.0 | written, not yet unit-tested |
| `github.py` | idempotent PR comment upsert (stdlib only, https enforced, token never logged) | written, not yet tested |
| `cli.py` | `dci analyze ...`; exit 0 pass / 1 blocking / 2 usage / 3 internal (fail closed) | written, not yet tested |
| `action_runner.py` + `action.yml` | GitHub Action: composite action, hardened entrypoint (inputs only via INPUT_* env, validated; shallow-clone history + base fetch; annotations; outputs; step summary; idempotent PR comment; SARIF/JSON/Markdown files) | written, tested end to end |
| `redact.py` | strips secrets/URL credentials/JWT/long tokens and SQL literal values from every emitted snippet | written, not yet unit-tested |

Data flow: migrations → `Change[]` → targets (table → columns) → Scanner(head trees [+ consumer repos], base tree) →
`Reference[]` → `rules.evaluate` → `Finding[]` → `Report` → renderers.

Rollout-window logic: references present in the **base** commit but removed in head are "old version still uses it".
They produce DCI104/114/124/134/403 (ERROR when `rolling_deploy=true`, the default; INFO otherwise).

## 4b. Verified status at hand-off (5 Nov 2026) — exactly what was and was not run

Ran and passed:
* `python3 -m pytest tests -q` → **76 passed** (about 5 minutes): 29 real-PostgreSQL ground-truth cases + 17 GitHub Action tests + 30 regression tests (`tests/test_regressions.py`, no PostgreSQL needed).
* GitHub Action tests: static lint of `action.yml` (no `${{ }}` inside shell scripts, every runner input mapped, pinned constraints); the real entrypoint run as a subprocess against a real **shallow** git clone with a real **TLS** server standing in for api.github.com (comment created then updated in place, bearer token used, token never printed, read-only-token failure leaves the verdict unchanged); unsafe base refs rejected; non-PR events skipped; install verified in a clean virtualenv with `constraints.txt`.
* Earlier ground-truth run: 25 seeded cases (drop/rename column and table, joins,
  CTE, derived table, DML with bind params, dynamic SQL, Alembic batch ops, cross-repo consumer, NOT NULL add with and
  without default, SET NOT NULL, index/unique/FK/check, type change, safe variants), each applied to a real PostgreSQL 18
  (PGlite) and compared with DCI's CONFIRMED findings; SQL-file and Alembic versions give identical rule sets.
* Manual end-to-end on a real temporary git repo: PR that removes a column from code AND drops it → DCI104 ERROR with
  base-commit evidence, exit 1; same with `--no-rolling-deploy` → exit 0; SARIF output parses; an option-like `--base`
  value is rejected (exit 2).
* One real bug was found by this harness and fixed: Alembic `sa.Text()` was not normalised, so a safe "type to text" change
  was flagged (DCI201). Lesson: keep running every rule against PostgreSQL.

### 4c. Review fixes applied after hand-off (each has regression tests that fail on the old code)

1. SQL line numbers: every SQL-derived reference carries the real source line of its identifier (statement offset + sqlglot position), also for `.sql` files and multi-statement strings. `Reference.anchor` keeps the construct start line so the dynamic-SQL de-duplication still works.
2. Base-versus-head: compared by semantic identity `(file, schema, table, column, via, role)` with multiplicity (`rules._removed`), never by snippet or line; only the PR repository's own head tree can match a base reference (a consumer cannot mask a removal). Known limit: code moved to another file still looks removed (DCI101 also fires, so the verdict does not change).
3. Schema: `Reference.schema` is filled from SQL (`schema.table`), ORM (`__table_args__`, inherited), Core (`Table(..., schema=)`, `table(..., schema=)`) and 3-part `ForeignKey`. Matching uses `identifiers.tkey`: no schema = `public`. A change in a non-public schema is NOT matched to unqualified code (search_path is not analysed); a coverage note says so. `MetaData(schema=...)` is not tracked (coverage note).
4. Workspace: `Config.workspace`, enforced once in `analyze()` for the repo and every consumer path from any origin (CLI flag, Action input, `.dci.toml`), symlinks resolved. The Action always sets it; the CLI has `--workspace`. Without it the CLI trusts local config paths (siblings like `../billing` are legitimate there). Still open: `.dci.toml` comes from the PR head in the Action, so a PR author can also change `fail_on` / `ignore_rules`; consider reading it from the base branch.
5. Aliases: the original claim (aliases are skipped by the filter) was wrong for same-file `from x import Y as Z`. Real gaps fixed: re-exported aliases across modules (resolved by module-path suffix, transitively), and module-qualified use (`models.Order`), which previously left the model looking unused and downgraded blocking findings. Not handled: `db.O` where `db` is an imported module exposing an alias. Cost: files with `from x import y as z` are parsed in pass 1 (3,000 such files: 0.26s to 1.24s).
6. Identifiers: one canonical form (`identifiers.py`): unquoted SQL names fold to lower case, quoted names keep their spelling, names from Python strings (SQLAlchemy, Alembic) are exact because SQLAlchemy quotes anything not all lower case. Generated SQL recommendations quote names that need it.
7. Also fixed: `--head` without `--base` on a git repository crashed with a TypeError (exit 3).

Not yet run or written (do these first, section 10 P0): unit tests for sqlutil/migrations/redact/sources/report/cli;
automated git rollout tests (R1–R3, partly covered by the Action end-to-end test); Dockerfile; license; running the action on a real GitHub runner (never done: needs a published repo); performance test on a large repo;
`config.py` and `github.py` have never been executed against real inputs; behaviour with `mapped_column` typed models,
mixins, Flask default table names and ambiguous class names is implemented but has no dedicated test yet.
Known documented miss in the corpus: `"SELECT " + cols + " FROM orders"` and `.format()` table names (reported as UNKNOWN only).

## 5. Rule catalog (IDs are public API; do not renumber)

Severity / confidence in brackets. Only CONFIRMED findings at the configured `fail_on` severity block CI.

| ID | Meaning |
|---|---|
| DCI101 / 111 / 121 / 131 | drop column / rename column / drop table / rename table: still referenced at head [ERROR, CONFIRMED] |
| DCI102 / 112 / 122 / 132 | same, but only referenced from tests [WARNING, CONFIRMED] |
| DCI103 / 113 / 123 / 133 | possible references: dynamic SQL, ambiguous unqualified columns, `SELECT *` [WARNING, POSSIBLE] |
| DCI104 / 114 / 124 / 134 | old application version (base commit) still uses it → rollout window [ERROR or INFO, CONFIRMED] |
| DCI105 / 115 / 125 / 135 | consumers outside scanned code are invisible; change irreversible [INFO, UNKNOWN] |
| DCI201 | ALTER TYPE may rewrite table under ACCESS EXCLUSIVE (old type unknown; skipped for unbounded text/varchar) [WARNING, POSSIBLE] |
| DCI301 | SET NOT NULL scans table under lock; recommends CHECK … NOT VALID → VALIDATE → SET NOT NULL [WARNING, CONFIRMED] |
| DCI302 | INSERTs omitting a column that becomes NOT NULL [WARNING, POSSIBLE] |
| DCI401 | ADD COLUMN NOT NULL without default fails on non-empty table (not for tables created in same migration) [WARNING, POSSIBLE] |
| DCI402 | writers at head omit the new NOT NULL no-default column (raw INSERT lists; ORM constructors without python/server default) [ERROR, CONFIRMED] |
| DCI403 | writers in the base commit cannot supply it → rollout window [ERROR/INFO, CONFIRMED] |
| DCI501 | CREATE INDEX without CONCURRENTLY on an existing table [WARNING, CONFIRMED] |
| DCI502 | ADD UNIQUE/PRIMARY KEY builds index under lock [WARNING, CONFIRMED] |
| DCI503 | ADD FOREIGN KEY without NOT VALID [WARNING, CONFIRMED] |
| DCI504 | ADD CHECK without NOT VALID [WARNING, CONFIRMED] |
| DCI900 | statement/operation DCI could not analyse (dynamic `op.execute`, unknown DDL) [WARNING, UNKNOWN] |

Safe changes must produce **no findings**: nullable ADD COLUMN, NOT NULL with a DEFAULT, `CONCURRENTLY` index,
`NOT VALID` constraints, objects created in the same migration, `ALTER TYPE … text`.

PostgreSQL facts the rules rely on (verify, do not assume more): SET NOT NULL scans under ACCESS EXCLUSIVE and PG12+
skips the scan if a validated CHECK proves non-nullness; plain CREATE INDEX takes a SHARE lock (blocks writes);
ADD UNIQUE/CHECK take ACCESS EXCLUSIVE and scan/build; ADD FOREIGN KEY takes SHARE ROW EXCLUSIVE on both tables and
scans unless NOT VALID; ALTER COLUMN TYPE rewrites unless binary-coercible; ADD COLUMN NOT NULL with no DEFAULT fails on
a non-empty table; a column drop makes any query naming it fail with "column does not exist".

## 6. Evidence and trust policy (non-negotiable)

* CONFIRMED = resolved to a concrete file/line, or a documented property of the statement itself.
* POSSIBLE = dynamic/ambiguous (f-strings, concatenation, unqualified columns over several tables, `SELECT *`,
  unresolved `filter_by`, model defined but unused). Never blocks.
* UNKNOWN = evidence missing (other services, jobs, BI, non-Python code, unparseable statements). Never blocks.
* "OBSERVED" (runtime evidence) is reserved for V2.
* No single opaque risk score. Absence of a finding is never proof of safety; the report always prints coverage
  (trees scanned, files parsed/skipped/failed, unanalysed languages).
* A model **definition** only counts as a consumer if that model is used somewhere in the same tree.
* Test-file references are WARNING, not ERROR.
* LLM output may never be labelled confirmed.

## 7. Security requirements

Source code and SQL are untrusted input. DCI must: never import/exec analysed code; never follow symlinks; enforce file
size limits; validate git revision names (no leading `-`); use argument lists, never a shell; redact secrets and SQL
literals from snippets before they leave the process; use read-only credentials; keep the GitHub token out of logs;
enforce https for the API; fail closed (exit 3) when the analysis itself breaks; limit PR-comment size (60k chars).
For the future hosted app: least-privilege GitHub App (Contents: Read, Pull requests: Write, Checks: Write), short-lived
installation tokens, ephemeral analysis containers, tenant isolation, retention/deletion controls, SOC 2 roadmap,
never request database credentials.

## 8. Verification strategy (this is the project's core credibility)

* **Ground truth from a real PostgreSQL engine.** `tools/pgcheck` uses PGlite (PostgreSQL 18 compiled to WASM, via node).
  For every seeded case: apply the migration to a real database, run the SQL that the consumer code emits, and require
  that the set of lines DCI reports as CONFIRMED equals exactly the set of queries that really fail (precision and
  recall on the corpus). Safe changes must yield zero findings. Cases and expectations live in `tests/corpus.py`;
  the harness is `tests/test_groundtruth.py`, `tests/pg.py`, `tests/helpers.py`.
* Every case runs twice (raw SQL file and Alembic file) and must give identical rule sets (parity).
* Corpus contains deliberate traps: CTE vs table names, derived-table aliases, `::` casts, docstrings that look like
  SQL, bind params, unqualified ambiguous columns, dynamic SQL, cross-repository consumers, a documented known miss.
* Corpus numbers are measured on a seeded corpus authored by us. Never present them as real-world accuracy.

## 9. Setup and commands

```bash
python3 -m pip install -e ".[dev]" sqlalchemy alembic     # needs Python >= 3.11
(cd tools/pgcheck && npm install)                          # installs @electric-sql/pglite (real PostgreSQL in WASM)
python3 -m pytest -q                                       # ground-truth suite starts a PGlite per case: allow several minutes
dci analyze --repo . --base origin/main --format markdown  # in a git repo with a PR checked out (fetch-depth: 0)
dci analyze --repo . --migration db/migrations/0002.sql --consumer billing=../billing-service
```
Config file `.dci.toml` (optional): `migration_globs`, `test_globs`, `ignore_paths`, `ignore_rules`, `fail_on`
(`error`|`warning`|`never`), `rolling_deploy`, `max_evidence`, `[[consumer_repos]] name/path`.
Inline suppression in a migration: `# dci: ignore[DCI501] reason` (or `-- dci: ignore` in SQL); suppressions are listed
in the report's coverage notes.

## 10. Backlog (priority order)

P0 — finish and prove V1
1. Run the full suite; fix every failure (any real bug found by PostgreSQL ground truth is a priority).
2. Add unit tests: `sqlutil` (dollar quotes, nested comments), `migrations` (all op.*, batch, dynamic execute → DCI900),
   `redact`, `sources` (symlink not followed, size limit, glob), scanner traps (docstring, test-file → WARNING,
   unused model → POSSIBLE, mixins/inheritance, aliased imports, ambiguous class names), `report` (Markdown size cap,
   JSON schema, SARIF structure), `cli` (exit codes 0/1/2/3, `--fail-on`, `--ignore-rule`), `github.upsert_comment`
   against a local HTTP server, config validation errors, git rev injection refusal.
3. Git rollout tests with a real temporary git repo and ground truth: (R1) PR removes column from code AND drops it →
   DCI104 ERROR, no DCI101, old-version queries really fail in PostgreSQL; `--no-rolling-deploy` → INFO and no block;
   (R2) code cleaned in an earlier release → only DCI105; (R3) NOT NULL add with base writers → DCI403.
4. DONE: `action.yml`, `src/dci/action_runner.py`, `README.md`, `examples/`, `.github/workflows/ci.yml`, `constraints.txt`.
   TODO: publish the repo, run the action on a real GitHub runner (verify SARIF upload, fork-PR behaviour, action ref pinning
   by commit SHA for `actions/setup-python` and `github/codeql-action`), tag `v1`, `Dockerfile`, license decision.
5. Performance check on a large synthetic repo (target: seconds for ~10k Python files; the prefilter must hold).

P1
6. Hosted GitHub App: webhook receiver, App JWT auth → installation tokens, Checks API (annotations), job queue
   (Redis/Celery), Postgres metadata, tenant isolation, ephemeral workers, retention controls.
7. V2 runtime evidence, designed to mirror Datadog's mechanism: parse the SQL comment (`service`, `env`, `version` in
   sqlcommenter or `dd*` form), read `pg_stat_statements` fingerprints / OpenTelemetry `db.*` attributes, map to
   service + version + schema objects, new confidence class OBSERVED with observation window; **absence of traffic is never
   proof of no dependency**.
8. Sharper type-change rule (track old types from models/previous migrations), `SELECT *` handling, `Model.__table__`
   Core forms, more ORMs (Django, SQLModel, Prisma) one at a time with a ground-truth corpus for each.

P2
9. V3: model old/new version coexistence per migration stage; migration plan generator with human approval; never execute
   production DDL.

## 11. Working rules for the next Claude (hard rules)

1. **No mock data.** Fixtures are real code/SQL; behaviour claims are checked against real PostgreSQL (PGlite).
2. Never write "verified" for something you did not run. Report test results exactly as they are, including failures.
3. Do not widen scope (no new databases/ORMs/languages) until the P0 list is done and green.
4. Keep rule IDs and the confidence semantics stable; add rules, do not renumber.
5. Prefer deterministic analysis; no LLM in the decision path for CONFIRMED findings.
6. Every emitted snippet must pass through `redact()`.
7. When a rule's PostgreSQL behaviour is uncertain, test it in PGlite before encoding it.
8. Keep answers concise; the owner prefers brief, direct, technically honest communication.

## 12. Product discovery gates (unchanged from the strategy report, still required before selling)

Interview 15–20 backend/platform/database engineers about their last failed or delayed migration; need ≥5 teams with a
repeated costly problem and their real workflow; pilot on real upcoming migrations with read-only access; ≥2 design
partners using it on real migrations and ≥1 willing to pay. Stop or change direction if the problem is rare, expand/
contract + linters already solve it, access requirements are unacceptable, or false positives cannot be kept low.
Pricing is a hypothesis to test (per repo / service / analysis volume), never per token.

## 13. Known limitations of V1 (state them honestly to users)

Python/SQLAlchemy and SQL only (JS/TS/Java/Go/Ruby files are counted but not analysed); PostgreSQL dialect only;
dynamic SQL whose table or column names come from variables is invisible (reported at best as POSSIBLE, otherwise
UNKNOWN); other services, scheduled jobs, BI tools and manual scripts are invisible unless their repository is passed
with `--consumer`; no runtime evidence yet; no ORM query semantics beyond the resolved forms listed in section 4;
the old column type is not tracked (DCI201 is POSSIBLE only).

## 14. Open questions for the owner

Naming/branding and license; hosted app vs open-core CLI; first target customers' ORM (is it really SQLAlchemy?);
whether a monorepo-first pilot is acceptable; who the likely acquirer/partner is (database tooling vs observability).


## 4d. Status after "next build" (6 Nov 2026): 86 tests passed (incl. PostgreSQL ground truth)

Done: (1) Action reads `.dci.toml` from the base branch (`gitutil.show_file`, `config.load_text`), warns when a PR adds/changes/deletes it, opt-in `trust-pr-config`; (2) CLI: config-file consumer paths limited to the repo's parent dir unless `--allow-outside-config-paths` (`Config.config_consumer_repos`); (3) assignment aliases (`Ord = Order`, chains, cross-module, `m.Order`) resolved in `consumers.py` (pass 1b, `AliasDef.local`).
Known limit: `fail-on` / `rolling-deploy` inputs come from the workflow file, which a PR can edit under `pull_request` unless protected. Still open: moved-code looks "removed", `MetaData(schema=)`, search_path, unit tests for sqlutil/redact/sources/report/github/cli, real-runner validation, Dockerfile/license, V2 runtime evidence.

## 4e. Status after bug-check round (6 Nov 2026): 124 tests (incl. PostgreSQL ground truth) — all pass

Reproduced and fixed: (a) MetaData(schema=...) was ignored -> false CONFIRMED block on public.<t> and missed match on <schema>.<t>; now tracked via `collect_meta` (declarative_base(metadata=...), MetaData variables, `DeclarativeBase` subclass attribute, `Table(name, meta)`); non-literal schema keeps a coverage note. (b) `SET search_path` / `set_config` in a migration now scopes unqualified tables (`migrations.changes_from_sql`). (c) Dynamic SQL (`.format`, f-string, `%`, concatenation) with a runtime table name or column list is reported POSSIBLE (DCI103) instead of silently missed (`*dyn_table*`/`*dyn_cols*` markers). (d) Actions pinned to commit SHAs (tag->SHA read 6 Nov 2026 with git ls-remote; re-verify before release), enforced by a test. (e) `fail-on`/`rolling-deploy` inputs default empty so base-branch `.dci.toml` applies; `examples/CODEOWNERS` added. (f) `tests/test_units.py`: redact, sqlutil, sources, report, github, cli.
Not a bug: moved code gives DCI104 because the old version still reads the column during rollout — correct.
Open: search_path/MetaData cases are covered by unit tests but not yet by PostgreSQL ground-truth corpus cases; app-side search_path and Alembic `op.execute("SET search_path")` across separate execute calls not tracked; no LICENSE/Dockerfile (license choice is the owner's); never run on a real GitHub runner; hosted app / V2 runtime evidence / other ORMs not built.
