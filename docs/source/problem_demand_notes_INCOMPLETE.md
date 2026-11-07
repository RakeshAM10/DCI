# Problem demand: cross-service DB migration compatibility during rolling deploys

STATUS: PARTIAL. Research was cut off after the first round of searches (usage limit hit: "5-hour limit, resets 12:40am Asia/Kolkata"). Only the items below were actually verified. Most key questions are unanswered and need a re-run. Nothing here is estimated or filled from memory.

## Public postmortems involving schema/migration changes (frequency, categories, multi-service/old-new version)

### Takeaway
Not answered. Search surfaced a few candidate postmortems, but I fetched none successfully, so there is no count, categorization, or share-of-postmortems estimate.

### Cited Findings
- Search returned titles suggesting migration-related postmortems (content NOT verified, treat as leads only): Val Town "post mortem db migration" (2025-04-02) — [Val Town blog](https://blog.val.town/post-mortem-db-migration); LootLocker "data loss during database migration" — [LootLocker](https://lootlocker.com/blog/db-postmortem-data-loss-during-database-migration); CxAlloy TQ downtime postmortem — [CxAlloy](https://www.cxalloy.com/cxalloy-tq-downtime-postmortem/); a 2026 migration-incident checklist post — [youngju.dev](https://www.youngju.dev/blog/database/2026-06-16-migration-incident-postmortems-checklist.en)
- The Val Town fetch failed, so I do not know its cause or whether old/new app versions were involved.

### Inferences
- Only inference: the search engine surfaces mostly small-company postmortems for this query, not the big names (GitHub, GitLab, Stripe, etc.). That is a weak signal and may just reflect the query.

### Gaps
- Nothing on GitHub, GitLab, Stripe, Shopify, Basecamp, Cloudflare, Heroku, Atlassian incidents.
- danluu/postmortems, learn-from-incidents, incident.io/Jeli collections not examined; no share-of-postmortems estimate.
- Nothing verified on multi-service or coexisting-version incidents specifically.

## Surveys and reports (DORA, Redgate, Liquibase, Percona, Stack Overflow)

### Takeaway
Only Liquibase 2026 was read. It gives deployment frequency and governance maturity but NO failure/incident/rollback rates, so it does not directly size incident cost. Self-selected vendor-community sample.

### Cited Findings
- Liquibase 2026 report: 426 respondents from Liquibase's own community (self-selected, vendor survey). 68.1% deploy database changes weekly or faster; 18.8% daily; 10.8% multiple times per day. — [BusinessWire](https://www.businesswire.com/news/home/20260311497754/en/Liquibase-2026-Report-Finds-AI-Now-Interacts-With-Production-Databases-in-96.5-of-Organizations-as-Governance-Automation-Lags)
- Same report: only 7.7% have fully automated governance (policy as code, real-time enforcement); 28.1% have standardized, consistently enforced governance; 42.3% are at Ad hoc or Emerging maturity. — same source
- Same report, telemetry (separate from survey): about 90% of Liquibase Secure sessions run outside CI. — same source
- Same report: 96.5% report at least one AI/LLM interaction with production databases; 46.5% cite ungoverned AI-generated SQL as a key concern; organizations average five database/data platform types. — same source
- The press release reports no statistics on failure, incident, rollback or delay rates (I asked specifically).
- Redgate publishes a State of Database DevOps report annually (2018, 2020, 2021 editions appear in search results; a newer one is referenced on the Redgate site) — [Redgate](https://www.red-gate.com/solutions/database-devops/linked-in/report/). Contents NOT read.
- Liquibase also ran surveys in 2019 ("State of Database Deployments in Application Delivery") — [Liquibase](https://www.liquibase.com/blog/results-state-of-database-deployments-2019). Contents NOT read; 2019 is old.

### Inferences
- Frequent database changes (weekly or faster for about two thirds of a vendor-community sample) imply many chances for a bad migration, but this sample is skewed toward people already using a migration tool.
- The 90% outside-CI telemetry figure suggests that even among tool users, checks are often not gated in CI. Only one vendor's telemetry, so weak.

### Gaps
- DORA change failure rate and anything DORA says about database change: not searched.
- Redgate figures, Percona, Stack Overflow survey, Harness: not read.
- No number tying database changes to production incidents or cost.

## Adoption of expand/contract, strong_migrations, squawk, pgroll, Atlas lint, Django tools

### Takeaway
Only one data point: strong_migrations has very large cumulative downloads, so Rails convention-plus-linter coverage is substantial. Everything else unanswered.

### Cited Findings
- strong_migrations on RubyGems: 87,352,818 total downloads; latest version 2.8.0 released May 14, 2026; 74 versions; 2.5.2 Dec 2025, 2.6.0 and 2.7.0 in April 2026. — [RubyGems](https://rubygems.org/gems/strong_migrations)

### Inferences
- Cumulative downloads include CI reinstalls and transitive installs, so they overstate unique teams. Treat as order-of-magnitude proof the tool is mainstream in Rails, not a team count.
- strong_migrations inspects a single repo's migration, so it cannot see consumers in other repos. This follows from how the tool works but I did not verify that against its README.

### Gaps
- No data on squawk, pgroll, Atlas, Django tools (django-pg-zero-downtime-migrations, django-migration-linter), Flyway/Liquibase adoption, or expand/contract awareness.
- No evidence on which scenarios remain unsolved (cross-repo consumers, workers, BI tools, external consumers).

## Shared-database microservices vs database-per-service; monorepo vs multi-repo

### Takeaway
Not researched.

### Cited Findings
- None.

### Inferences
- None.

### Gaps
- No prevalence data found or searched for.

## Developer sentiment and willingness to pay

### Takeaway
Not answered. One HN-oriented search returned nothing usable (results were generic SEO/blog pages).

### Cited Findings
- A Register article on PostgreSQL schema migration appeared in results (2022-01-12) — [The Register](https://www.theregister.com/2022/01/12/postgresql_schema_migration/). Not read.

### Inferences
- None.

### Gaps
- No HN, Reddit, Lobsters threads read; no evidence of paid tools or pricing (e.g. pgroll is OSS; Atlas, Liquibase, Redgate commercial tiers not examined).

## Rough sizing of target segment

### Takeaway
Not done; no supporting data gathered.

### Cited Findings
- None.

### Inferences
- None.

### Gaps
- Needs company counts for 20-200 engineer SaaS firms using Postgres/MySQL with multiple services, plus assumptions. Not attempted.
