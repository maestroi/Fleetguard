# CI, trusted auto-merge, and per-main-commit releases

Fleetguard is experimental. A published GitHub Release is a build artifact, **not** a production-readiness assertion. The standalone controller binary currently needs `libsqlite3` installed on the target Linux host, and all firewall enforcement remains disabled.

## CI policy

Every PR into `main` is checked by **Go CI** (`.github/workflows/ci.yml`), without write permissions: formatting, module tidiness, vet, protocol and simulated-backend tests, TLS controller tests, race-enabled unit tests, Linux AMD64 builds and an unprivileged smoke run. The automation policy and version-numbering helpers are tested as well.

## Automatic merging

After a successful **Go CI** PR run, `.github/workflows/automerge.yml` attempts to squash-merge **only** when all of these hold:

- PR author is exactly GitHub user `maestroi`.
- The PR targets `maestroi/Fleetguard:main`, originates from the **same** repository (not a fork), is open and is **not** a draft.
- The PR's **current head SHA** matches the SHA for which the completed PR CI run succeeded; stale checks never authorize a newer commit.
- GitHub itself allows merging at that moment. The workflow does **not** use administrative bypass or override required checks/reviews.

Other contributors, including Dependabot, stay manual. A failed CI run, changed head, draft PR or conflicting merge also stays unmerged. The privileged auto-merge workflow only checks out the trusted `main` branch to read its policy script; it **never** checks out or executes untrusted PR code. It merges via GitHub's REST API with a head-SHA precondition.

**First-time activation:** merge the workflow PR manually. The auto-merge workflow must already be on the default branch before GitHub can trigger it. Fleetguard's native "Allow auto-merge" repository setting can remain disabled: this workflow merges passing owner PRs directly rather than queuing GitHub's native auto-merge feature.

**Recommended GitHub setting:** protect `main` with a GitHub ruleset requiring a pull request and the successful **Go CI / test-and-build** check. Do not require manual approval if you want your own PRs to merge automatically. Repository rulesets/branch protection cannot be installed by a normal code PR, so configure this in **Settings → Rules → Rulesets** (or Branch protection) yourself. Until then, users with direct write permission can bypass the PR/CI route by pushing directly; direct pushes still run the release build checks before publishing.

## Versioning and publishing

`.github/workflows/release.yml` triggers on **every push to `main`**, including docs-only pushes, and also supports a manually dispatched specific commit SHA on `main`.

For merges performed with the repository's `GITHUB_TOKEN`, GitHub does **not** emit another push-triggered Actions run. The trusted auto-merge workflow therefore explicitly dispatches `release.yml` for the exact merge SHA after it merges the PR. A manually merged PR or direct push uses the normal `push` trigger. The release queue is serial with `queue: max` so several quick merges are not overwritten by newer pending runs.

Each successful run:

1. Verifies the requested commit belongs to the first-parent history of `main` and checks out that **exact** SHA.
2. Derives a deterministic pre-1.0 version: `v0.1.N`, where `N` is the number of commits along the first-parent history through that SHA. One completed main-line commit has one stable version, independent of the wall-clock time or of later merges. Existing history means the first release may not be `v0.1.1`.
3. Re-runs Go checks and race tests with the repo-pinned Go toolchain; any failure prevents release publishing.
4. Builds `fleetguard-agent`, `fleetguard-controller` and `fleetguardctl` for Linux AMD64, embeds version and commit metadata, and runs the unprivileged smoke test.
5. Creates deterministic `fleetguard_v0.1.N_linux_amd64.tar.gz` and `fleetguard_v0.1.N_compose.tar.gz` archives with `SHA256SUMS` covering both. Uploads these as run artifacts and as assets of the GitHub prerelease tagged `v0.1.N`.
6. Validates Compose's read-only/non-root/capability-free security contract; builds a Linux AMD64 controller Docker image, runs it with no network, no caps and a read-only filesystem, then publishes the tested image as `ghcr.io/maestroi/fleetguard-controller:v0.1.N` and `:sha-<full-main-commit>`.

**Publish destinations:** [Fleetguard GitHub Releases](https://github.com/maestroi/Fleetguard/releases) and GHCR (`ghcr.io/maestroi/fleetguard-controller`). No external registry credentials or personal access token is required. The release uses repository-scoped `GITHUB_TOKEN` with `contents: write` and `packages: write`. The owner may need to set the GHCR package's visibility to **Public** after its initial publication, or otherwise users must authenticate before pulling.

### Recovering a failed or interrupted release

If the release job fails, fix the cause and rerun the workflow. Its tag is derived from the commit, so a successful rerun uploads to the same version instead of making another version. To backfill a missed main commit, open **Actions → Publish release → Run workflow**, enter its full 40-character SHA, and run. The workflow rejects commits not on `main`'s first-parent history and refuses to overwrite an existing release tag that points elsewhere.

### Release compatibility

The archive is Linux **x86_64/amd64** only, because the controller's SQLite implementation uses CGO. The controller is dynamically linked to system SQLite and must run on a compatible Linux distribution. The matching Debian-based controller container includes a compatible `libsqlite3-0`, runs as UID 65532, and supports linux/amd64 only. The Compose example is [documented here](container-deployment.md). There is no ARM release yet and no claim of static controller binaries.

### Trust boundaries

- PR CI runs untrusted code with `contents: read` only.
- The privileged merge job does **not** execute code from a pull request; it validates author, repository, base, draft status and current SHA from GitHub's API before merging.
- The release job builds from **main-only** SHA after the merge, not from arbitrary event or PR input; it still re-runs the tests before uploading.
- This does not replace protected branches, dependency pinning, code reviews or security audits. Do not auto-merge from untrusted authors.
