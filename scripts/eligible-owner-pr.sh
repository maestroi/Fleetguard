#!/usr/bin/env bash
# Read a GitHub pulls/{number} JSON object on stdin.
# Exit success *only* for a current-head PR from maestroi in this repository.
set -euo pipefail
repo="${1:?usage: eligible-owner-pr.sh <owner/repo> <ci-head-sha>}"
sha="${2:?usage: eligible-owner-pr.sh <owner/repo> <ci-head-sha>}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || exit 1
jq -e --arg repo "$repo" --arg sha "$sha" '
  .state == "open" and .draft == false and
  .user.login == "maestroi" and
  .base.ref == "main" and .base.repo.full_name == $repo and
  .head.repo.full_name == $repo and .head.sha == $sha
'
