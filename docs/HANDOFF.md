# Engineering handoff

Read this, then ROADMAP.md, IMPLEMENTATION_STATUS.md and SECURITY_GATES.md.
Verify against `git log origin/main`, `gh pr list`, `gh issue list` and
`gh run list` before trusting any of it.

## Session 2026-11-28 (summary)

- PR #46 (#41 never-ban) had failed CI at `fmt-check` and also had two unused
  imports that `vet` would have caught. Both were fixed. The agent side was
  then completed: retrieval, persistence, enforcement and metrics. The
  controller gained the publication gate, audit, bulk import and dry-run.
  Grafana and alert rules were added. #46 merged as `d8fccb4` through the
  owner auto-merge workflow after green CI.
- The automated commit security review found a fail-open: a retained,
  unverified list (after signer rotation) was still treated as fresh. Fixed
  with a regression test (`147b789`).
- Created #47, the watchdog and independent TTL recovery issue (P0), and
  implemented it in draft PR #49. That covers bounded D-Bus calls, a watchdog
  pinged only after a successful reconcile, ExecStopPost `cleanup-owned`, and
  research showing firewalld timeout ipsets can't be used (entries are
  untracked and not removable).
- Added these persistent docs.

## Working-tree notes

- The main checkout `~/Documents/projects/Fleetguard` is on
  `feat/issue-42-chain-profiles` with **uncommitted owner work** (#42 chain
  profiles, `deploy/ansible/`, `examples/exposure/chains.json`,
  `internal/exposure/simulate*.go`). Do not stash, reset or commit it without
  the owner.
- Agent work happens in a separate worktree, `~/Documents/projects/Fleetguard-41`
  (`git worktree list`).

## Repo conventions learned

- Go 1.27, `GOTOOLCHAIN=local`. CI runs `make fmt-check tidy-check vet`,
  targeted package tests, `go test -race ./...`, `make build smoke`, compose
  security checks and a release-version test.
- Controller store needs cgo plus libsqlite3 (`//go:build linux && cgo`).
- **Auto-merge:** any non-draft, same-repo PR by `maestroi` is squash-merged
  when Go CI passes at the current head, and a release is published. Keep PRs
  as drafts until they are truly complete.
- Commit style: conventional commits with an `(#issue)` suffix.
- The local `staticcheck` binary is too old for Go 1.27 (export data v4).
  Do not rely on it locally.

## Design facts worth knowing (not obvious from code)

- Agent enforcement runs only in a disposable-VM lab: it needs `mode=enforce`,
  a root-owned config, `lab_confirm=disposable-vm-console-ready` and an INPUT
  attestation.
- Snapshot TTL is at most 300s, and `max_offline_age` (1–300s) bounds central
  bans when the controller is down. Operator ban lifetime (Decision.ExpiresAt)
  is separate from lease validity (Snapshot.ExpiresAt).
- Never-ban on the agent: protections only withhold bans. With
  `never_ban_required`, a stale list refuses new bans, and existing bans lapse
  at list expiry plus `max_offline_age`. See docs/never-ban.md.
- Every new ban-publication path on the controller must call
  `DB.CheckNeverBan` inside its transaction (see `PublishApprovedDecision`).
- Local-safety violations reject a whole snapshot. Fleet-protection overlaps
  are withheld per entry (`partially_applied` ack). #44 should extend per-entry
  rejection to local protections for bulk policies.

## Next steps (in order)

1. **#47 watchdog**: DONE in draft PR #49. The owner must review it (it changes
   unit semantics) and run `scripts/lab/watchdog-fault-injection.sh` on a
   disposable VM. Original plan, for reference: Real hung-agent risk; G5 is unmet. Plan:
   - systemd notify plus `WatchdogSec`, pinged only after a successful reconcile
   - per-call D-Bus deadlines in `internal/firewall/firewalld`
   - a `fleetguard-agent cleanup` oneshot via `OnFailure=` and `ExecStopPost=`
   - crash-loop limits
   - fault-injection tests (fake backend that blocks; process-level tests
     with SIGSTOP on a helper binary)
   - research firewalld ipset `timeout` on the nftables backend
2. **#44 bulk ban/unban.** Needs a protocol design note first: shared group
   policy, chunked atomic generations, ≥5,000 entries, short leases separate
   from ban TTL.
3. **#16 scale harness.**

## Blockers requiring a human

- Privileged disposable-VM lab access (#11, #12, #41 lab criterion, #47 lab
  acceptance).
