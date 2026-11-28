# Fleet-wide never-ban protection: protocol foundation (#41)

The signed protocol, controller management, authenticated distribution, agent
retrieval/persistence/enforcement and the controller publication gate are
implemented. Everything is opt-in; agents without a never-ban anchor behave
as before.

## Contract

A separate Ed25519 signature domain identifies a fleet-wide protection document.
The canonical JSON payload includes schema, monotonic revision, UTC issuance and
expiry, signer ID and sorted entries. Every entry has a canonical IPv4 or IPv6
CIDR and one of infrastructure, peers, partners or edge. There are at most
4,096 entries, a 512 KiB payload and a 24-hour validity period. Host bits,
IPv4-mapped IPv6, /0, duplicate entries and unknown categories are rejected.
These bounds are initial design choices, not measured capacity limits.

The list does not open ports, replace local safety configuration, or authorize
enforcement. A source prefix overlapping any protected prefix is ineligible for
new bans. Local management protections must always be checked independently.

VerifyNeverBanUpdate combines strict signature and freshness checks with the
add-only transition check. An expired previous revision is still authoritative
for membership: no previously accepted (CIDR, category) pair may be removed by
remote updates. Renewal may preserve identical entries. A missing or expired
current list must prevent new bans. Remote removal is intentionally not supported;
a future separately reviewed, local recovery procedure may manage legitimate
retirement of protections. The protection list should use an independently
provisioned signing trust anchor rather than treating every ban signer as a
protection signer.

## Agent integration

Opt in with two runtime config fields:

```json
{
  "never_ban_trusted_keys_file": "/etc/fleetguard/never-ban-keys.json",
  "never_ban_required": true
}
```

The keys file has the same format as `trusted_keys_file` but must be a
different file, and no key ID or key material may be shared with the policy
signers (checked at startup). In enforce mode it must be root-owned.

**Retrieval.** Each poll first fetches `GET /v1/never-ban` (no query; same
pinned-TLS transport and per-node token), then the snapshot. The agent
verifies the signature against its own anchor regardless of HTTPS. An ETag is
sent only after the matching document was verified and persisted, so a 304
can never stand in for an unverified document. A protection fetch failure
never blocks the snapshot poll: unbans and expiry keep flowing.

**Persistence.** The accepted envelope, revision and acceptance time are
written to `<state_dir>/never-ban-v1.json` with the same atomic
temp+fsync+rename, 0600, no-symlink, single-link and root-owner checks as the
policy state. Identical repeats are idempotent (no rewrite). Replays, older
revisions, removals, expired, forged or policy-signed lists are rejected and
leave prior protections untouched. On restart the list is re-verified at its
acceptance time; if the anchor was rotated away, the entries are **retained**
(they can only withhold bans) but reported `protection_unverified` and never
counted as fresh. A rotated signer can only add to the retained entries.

**Merging.** Root-owned local protections (protected CIDRs, controller IPs,
management interfaces; see local-safety.md) are checked as before. Fleet
entries are indexed (`protocol.ProtectionIndex`: a set lookup per distinct
prefix length plus one binary search; about 45 ns per lookup at 4,096 entries
on the development machine) and checked on every reconcile. Remote lists
can only add protection.

**Partial enforcement.** A valid snapshot whose decisions partly overlap fleet
protections is accepted; the overlapping decisions are withheld individually,
the rest are applied, and the ack is `partially_applied` with reason
`protected_source`, never `applied`. (Local safety violations still reject
the whole snapshot; per-entry local rejection is part of #44.)

**Active ban removal.** Accepting a list triggers an immediate reconcile.
Decisions overlapping a protection are dropped from desired state (locals are
deleted outright), the backend is reconciled, and the backend readback is
checked: a protected source still reported installed increments
`protection_cleanup_failures_total` and fails the reconcile. Because
protection is add-only and filtering runs on every reconcile, a removed ban
cannot be restored by the same or a later snapshot.

**Offline / stale behavior** (`never_ban_required: true`):

| Situation | New central/local bans | Existing bans |
| --- | --- | --- |
| Fresh list | accepted (minus protected entries) | kept |
| Never received a list | refused (`protection_stale`) | none can exist |
| List expired (controller down, not renewed) | refused; snapshots that only repeat or remove existing decisions are still accepted | kept until list expiry + `max_offline_age`, then all lapse |
| Retained after signer rotation | refused until a fresh list from a trusted signer | same as expired |

Protections are retained in all cases. With `never_ban_required: false` the
fleet list still withholds overlapping bans when present, but its absence does
not block bans; this is explicit local-only operation, never a silent fallback.

**Controller.** `PublishApprovedDecision`, the only current publication path,
checks the fleet list inside its SQLite transaction. It fails closed when the
anchor is configured but the list is missing, expired or unverifiable, or when
history exists without a configured anchor. Refusals are audited as
`decision_refused`. Every never-ban write also adds a `never_ban_updated`
audit row. Future paths (#44 manual bans, automation, feeds) must call
`DB.CheckNeverBan` in the same way.

**Metrics** (bounded labels only, no addresses). Agent:
`fleetguard_agent_protection_{required,revision,entries,fresh,unverified,withheld_decisions}`,
`..._protection_expires_timestamp_seconds`, `..._protection_last_update_timestamp_seconds`,
`..._protection_updates_total{result}`, `..._decisions_rejected_total{reason=protected_source|protection_stale}`,
`..._protection_conflict_removals_total`, `..._protection_cleanup_failures_total`.
Controller: `fleetguard_controller_never_ban_revision` and
`..._never_ban_expires_timestamp_seconds`. Alerts in
`deploy/monitoring/alerts.yml` cover stale lists, upcoming expiry, revision
mismatch, cleanup failure and rejected updates.

### Remaining gates

- Disposable-VM validation of removal of a real firewalld IP-set entry on
  protection update (rootless tests use a fake backend). Tracked with #11/#12.
- The watchdog gap (a hung agent cannot remove bans) is unaffected by this
  feature; see the watchdog issue.
- Signer rotation on the controller side (overlapping anchors) is not
  implemented; the agent tolerates it by retaining entries.

## Local controller management

Generate a distinct protection key (not the policy signer):

```sh
fleetguardctl generate-signing-key -private /private/fleet.key -public /private/fleet.pub
fleetguard-controller never-ban add -config /private/server.json \
  -key-id fleet-protection -public-key /private/fleet.pub -private-key /private/fleet.key \
  -category peers -cidr 192.0.2.0/24 -cidr 2001:db8::/48 -reason 'approved peer inventory'
fleetguard-controller never-ban list -config /private/server.json \
  -key-id fleet-protection -public-key /private/fleet.pub
fleetguard-controller never-ban diff -config /private/server.json \
  -key-id fleet-protection -public-key /private/fleet.pub -from 1
# Bulk import (one canonical CIDR per line, # comments), validated first:
fleetguard-controller never-ban add -dry-run -config /private/server.json \
  -key-id fleet-protection -public-key /private/fleet.pub \
  -category partners -file partners.txt -reason 'partner import'
fleetguard-controller never-ban add -config /private/server.json \
  -key-id fleet-protection -public-key /private/fleet.pub -private-key /private/fleet.key \
  -category partners -file partners.txt -reason 'partner import'
fleetguard-controller never-ban renew -config /private/server.json \
  -key-id fleet-protection -public-key /private/fleet.pub -private-key /private/fleet.key \
  -reason 'scheduled refresh'
```

`-dry-run` needs no private key, opens the database read-only and reports new, duplicate-in-request, already-protected and invalid entries plus the resulting count; it exits non-zero if the real add would be refused, so it can gate automation.

Each write uses BEGIN IMMEDIATE and appends a complete verified signed revision,
the local process UID, issuance timestamp and reason to the private controller
SQLite database. It never replaces or deletes a previous revision; the existing
evidence/audit retention purge does not touch this history. Lists and diffs use
a read-only SQLite handle and require only the protection public key. Use
list -revision N to inspect the operator and reason for an older revision. Diffs
report newly added (CIDR, category) pairs, with revision zero representing an
empty baseline. Add rejects a duplicate-only batch; renew keeps membership.
Expired lists are retained and can be renewed, but are not fresh authorization.
An explicit signer is required; key rotation is intentionally not implemented
in this slice. The CLI rejects use of the controller policy key for protection
writes. The local UID identifies the process account, not an independently
authenticated human; use separate OS accounts and external sudo logs where
individual attribution is required.

Complete signed history grows with revisions; monitor database size and back up
the private DB. Compaction or external audit archival and key rotation need a
separate reviewed design before production. These commands do not change any existing enforcement path.

## Authenticated distribution

Opt in by adding both fields to the existing private controller server JSON:

```json
{
  "never_ban_key_id": "fleet-protection",
  "never_ban_public_key_file": "/private/fleet.pub"
}
```

These are additional fields, not a complete server config. The server loads
only the independent protection public key at startup, and refuses to reuse
the decision signing key or ID. Local CLI writes must match the configured
signer when distribution is enabled. Restart the controller to change this
trust configuration; signer rotation remains a separate design task.

Authenticated non-revoked agents can request GET /v1/never-ban over the existing
HTTPS transport. The endpoint is fleet-wide, with no query parameters or HTTP
mutation commands. It returns the exact signed envelope without operator
identity or reason, with X-Fleetguard-Revision, X-Fleetguard-Expires-At and a
content-hash ETag. An exact If-None-Match receives 304 only if the current list
is still verified and fresh. Responses remain no-store; clients must independently
verify and persist signed state before using conditional retrieval. Missing,
expired, future-dated or unverifiable data returns 503; disabled returns 404.
Authentication/revocation applies even to conditional requests.

Each request reads and verifies the current durable revision (no stale fallback
or in-memory cache). This avoids sending a superseded revision after a committed
update but still incurs SQLite and signature verification cost; benchmark at
fleet scale before optimizing.
