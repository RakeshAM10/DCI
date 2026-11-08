#!/usr/bin/env bash
# Open a REAL pull request on GitHub that breaks the database, REST API, GraphQL and gRPC at once, and run SCI on it.
#
#   tools/demo_pr.sh OWNER/SCI_REPO@REF [OWNER/demo-repo-name]
#
# Needs: git, python3, and the GitHub CLI logged in (gh auth login) with permission to create a repository.
# The demo repository is created PRIVATE. Delete it afterwards with: gh repo delete OWNER/NAME --yes
set -euo pipefail
ACTION="${1:?usage: tools/demo_pr.sh OWNER/SCI_REPO@REF [OWNER/demo-repo-name]}"
OWNER="$(gh api user --jq .login)"
DEMO="${2:-$OWNER/sci-demo-$(date +%s)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
python3 "$HERE/make_demo.py" "$TMP" --action "$ACTION" >/dev/null
cd "$TMP/work"
git branch -f main origin/main
gh repo create "$DEMO" --private >/dev/null
git remote set-url origin "https://github.com/$DEMO.git"
git push -q origin main pr
gh pr create --repo "$DEMO" --base main --head pr --title "Breaking change (SCI demo)" \
  --body "Drops orders.legacy_status, removes DELETE /users/{id}, removes a GraphQL field and an RPC, and renumbers a protobuf field. SCI should fail this check." >/dev/null
echo "Pull request: https://github.com/$DEMO/pulls"
echo "Watch the 'SCI' check; it should FAIL with 5 blocking findings and post a PR comment."
echo "Clean up: gh repo delete $DEMO --yes"
