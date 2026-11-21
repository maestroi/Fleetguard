#!/usr/bin/env bash
# Stable, monotonically increasing prerelease version per main first-parent commit.
set -euo pipefail
sha="${1:?usage: release-version.sh <commit-sha>}"
git cat-file -e "${sha}^{commit}"
printf 'v0.1.%s\n' "$(git rev-list --first-parent --count "$sha")"
