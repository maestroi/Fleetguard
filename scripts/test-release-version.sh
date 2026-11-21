#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git -C "$tmp" init -q -b main
git -C "$tmp" -c user.name='Fleetguard CI' -c user.email='ci@example.invalid' commit -q --allow-empty -m one
[[ "$(cd "$tmp" && bash "$root/release-version.sh" HEAD)" == v0.1.1 ]]
git -C "$tmp" -c user.name='Fleetguard CI' -c user.email='ci@example.invalid' commit -q --allow-empty -m two
[[ "$(cd "$tmp" && bash "$root/release-version.sh" HEAD)" == v0.1.2 ]]
if (cd "$tmp" && bash "$root/release-version.sh" no-such-commit >/dev/null 2>&1); then
  echo 'Unknown commit unexpectedly generated a version.' >&2
  exit 1
fi
echo 'Release version tests passed'
