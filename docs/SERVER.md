# SCI server (GitHub App)

Runs SCI on every pull request of every repository where the GitHub App is installed, posts a check run (pass / fail / neutral, with line
annotations), and keeps a read-only dashboard. Only CONFIRMED findings can fail a check. A job that cannot run reports **neutral**, never success.

## Set up
1. Create a GitHub App from `deploy/github-app-manifest.json` (Settings > Developer settings > GitHub Apps). Webhook URL `https://<domain>/webhook`,
   a webhook secret, permissions Checks: write, Contents: read, Pull requests: read, events Pull request / Check run / Check suite. (GitHub also sends `installation` and `installation_repositories` events to every App; SCI uses them to track installs, suspensions and added/removed repositories, and registers an unseen repository on its first PR if one is missed.) Download the private key.
2. `cp deploy/env.example deploy/.env`, fill it in, put the key at `deploy/github-app.pem`.
3. `docker compose -f deploy/docker-compose.yml up -d`. The dashboard is at `https://<domain>/` (any user name, password = `SCI_ADMIN_TOKEN`).
4. Install the App on repositories. Each repository is registered automatically.

## Operate
- `docker compose exec sci sci-server repos list | enable|disable OWNER/REPO | set OWNER/REPO --checks db,api --fail-on error`
- `docker compose exec sci sci-server licence` shows the licence state; `prune` removes old runs.
- Probes: `/healthz` (process), `/readyz` (database). Data lives in the `sci-data` volume (SQLite, WAL mode). Do NOT copy `sci.db` on its own while the server runs (committed data can still sit in the `-wal` file). Back up with `docker compose exec sci sci-server backup /data/backup-$(date +%F).db`, then copy that file out.
- Without a licence: 3 repositories. With a licence: its `max_repos`. An expired licence makes checks neutral (merges are never blocked by billing).

## Issue licences (vendor side, offline)
```
sci-licence keygen --out vendor.pem              # keep vendor.pem offline; prints SCI_LICENCE_PUBLIC_KEY=...
sci-licence sign --key vendor.pem --customer "Acme" --max-repos 25 --days 365   # prints the token for SCI_LICENCE
```

## Security model
- Webhooks are accepted only with a valid `X-Hub-Signature-256` (HMAC-SHA256, constant-time) and each delivery id is processed once.
- Repository code is never executed (the `sim` check is refused here). Analysis runs in a subprocess with memory/CPU/process limits and no secrets in its environment.
- The configuration used is `.dci.toml` from the PR's **base** commit; consumer paths outside the clone are refused.
- Installation tokens are passed to git through the environment (not the command line) and are not logged.
- Dashboard: password, failed-login rate limit, CSP, no external resources, everything escaped. Put it behind the TLS proxy provided.
