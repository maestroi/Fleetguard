# Fleet-wide never-ban protection: protocol foundation (#41)

This is the first implementation slice. It does **not** change the running
controller, agent, firewall or any existing lab approval behavior.

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

- Controller durable append-only state, operator identity and reason audit, CLI
  add/list/diff and an authenticated distribution endpoint.
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
