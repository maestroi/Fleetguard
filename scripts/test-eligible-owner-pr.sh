#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sha='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
repo='maestroi/Fleetguard'
fixture='{"state":"open","draft":false,"user":{"login":"maestroi"},"base":{"ref":"main","repo":{"full_name":"maestroi/Fleetguard"}},"head":{"repo":{"full_name":"maestroi/Fleetguard"},"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'
expect_rejected() {
  local data="$1"
  if bash "$root/eligible-owner-pr.sh" "$repo" "$sha" <<<"$data" >/dev/null; then
    echo "Invalid PR accepted: $data" >&2
    exit 1
  fi
}
bash "$root/eligible-owner-pr.sh" "$repo" "$sha" <<<"$fixture" >/dev/null
expect_rejected "$(jq -c '.user.login="someone-else"' <<<"$fixture")"
expect_rejected "$(jq -c '.state="closed"' <<<"$fixture")"
expect_rejected "$(jq -c '.draft=true' <<<"$fixture")"
expect_rejected "$(jq -c '.base.ref="develop"' <<<"$fixture")"
expect_rejected "$(jq -c '.base.repo.full_name="external/repo"' <<<"$fixture")"
expect_rejected "$(jq -c '.head.repo.full_name="external/repo"' <<<"$fixture")"
expect_rejected "$(jq -c '.head.sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' <<<"$fixture")"
expect_rejected '{}'
echo 'Owner auto-merge eligibility tests passed'
