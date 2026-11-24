# Fleet-wide never-ban protection: protocol foundation (#41)

The signed protocol and local controller management are implemented. They do
**not** change the running controller API, agent, firewall or lab approvals.

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

## Remaining integration gates

- Authenticated distribution endpoint for the durable controller state.
- Agent atomic persistent revision and signed state, separate trust configuration,
  idempotent polling, expiry and fail-safe behavior after restart.
- Before activating a new list, remove conflicting existing temporary bans and
  recheck both central and local decision paths. Retain last known protections
  even when expired; block new bans until a fresh list is validated. Never silently
  fall back to local-only protection in an enforcement configuration requiring
  fleet protection.
- Controller-side overlap checks for every publication path, including the lab
  path, and per-entry decisions for future bulk bans.
- Bounded metrics and audit, including revision and rejection categories.
- Negative and real disposable-VM tests; no production rollout before #11/#12
  safety gates and watchdog gap are addressed.

The protocol package tests cover signing, canonical order, domain separation,
tampering, revision replay, expiry, future issuance, additive transitions after
expiry, IPv4/IPv6 overlap and malformed input.

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
fleetguard-controller never-ban renew -config /private/server.json \
  -key-id fleet-protection -public-key /private/fleet.pub -private-key /private/fleet.key \
  -reason 'scheduled refresh'
```

Each write uses BEGIN IMMEDIATE and appends a complete verified signed revision,
the local process UID, issuance timestamp and reason to the private controller
SQLite database. It never replaces or deletes a previous revision; the existing
evidence/audit retention purge does not touch this history. Lists and diffs use
a read-only SQLite handle and require only the protection public key. Diffs
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
separate reviewed design before production. These commands do not yet distribute
lists or change any existing enforcement path.
