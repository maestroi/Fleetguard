# Protocol v1: evidence and signed policy snapshots

**Status:** experimental schema for issue #3. No transport, authentication service, correlation engine, state persistence, or privileged enforcement is implemented here. This document defines interoperable **data**, not remote execution capabilities. The APIs reside in `pkg/protocol`.

## Safety boundaries

- Agent events are **untrusted claims**. The controller must authenticate the submitting connection (e.g. mTLS) and require `Evidence.node_id` to match that established identity. A `node_id` within JSON is not authentication.
- Proof level is a classification asserted by a sensor, **not a credential**. Raw firewalld logs, observed SYN sources, and spoofable UDP sources are `unverified_network_log` and must never independently trigger fleet enforcement. Even `application_verified` evidence needs a known, credible sensor and an independently authenticated node before it can count toward policy promotion.
- A signed snapshot is not authorization to bypass local policy. Before enforcing anything, agents must check local protected addresses/networks, management paths, service/port allowlists, backend capabilities and strict mode. These checks are delivered in issue #7. Until implemented, all binaries remain **observe-only**.
- No generic commands, shell snippets, arbitrary action targets or script fields exist. Unknown JSON fields are rejected.

## Evidence (agent → controller)

See `pkg/protocol/testdata/evidence_unverified.json`, `evidence_udp_unverified.json`, `evidence_established.json` and `evidence_verified.json` for complete examples. All addresses use documentation ranges.

| Field | Description |
|---|---|
| `schema` | Exactly `1` |
| `event_id`, `dedup_key` | Bounded identifier strings; dedup is enforced by the future controller |
| `node_id` | Reported identity, **must match** authenticated connection identity |
| `observed_at`, `window_seconds` | RFC3339 timestamp and bounded aggregation window |
| `source_ip` | Canonical single IPv4 or IPv6 source address, not a CIDR |
| `service`, `transport`, `destination_ports` | Scoped service, `tcp`/`udp`, sorted unique ports |
| `observation`, `attempts`, `proof_level` | Bounded observational metadata and an explicit evidence class |

Proof levels: `unverified_network_log`, `established_connection` (TCP only), `application_verified`. No proof tier promotes evidence to a ban by itself. `DecodeEvidence` checks authenticated node binding, freshness and data validity; correlation and dedup are intentionally deferred to issues #5–#6.

## Signed full snapshots (controller signer → agents)

A snapshot is a complete desired-state replacement for its **explicit audience**, not an imperative command. It contains `schema`, strictly increasing `revision`, `issued_at`, `expires_at`, `audience` (`service_group`, optional `node_id`), an explicit `decisions` array, and `key_id`. Every decision has `id`, `source`, `action`, `service`, `transport`, `destination_ports`, `expires_at` and `reason_code`.

Only `drop` with a **canonical single IPv4 `/32` source**, scoped service and 1–16 explicit sorted unique destination ports is defined for v1. Broad CIDRs, implicit all-port/all-service drops and IPv6 enforcement are invalid. Empty `decisions: []` is valid (revocation/clear). A snapshot always expires and each decision expires no later than the snapshot. Future protocol changes require an explicit new schema version.

Example unsigned *authoring input*: `pkg/protocol/testdata/snapshot_unsigned.json`. This is **not** a trusted policy. Never enforce unsigned JSON.

### Signature and byte encoding

The wire format is this two-field JSON object:

```json
{
  "payload_b64": "<unpadded RFC4648 standard base64 of canonical UTF-8 JSON snapshot>",
  "signature_b64": "<unpadded RFC4648 standard base64 of 64-byte Ed25519 signature>"
}
```

`SignSnapshot` first validates the structured v1 snapshot, normalizes all timestamps to UTC, then serializes it through Go `encoding/json` using the **declared field order** of the fixed structs. The payload contains no maps or floating-point numbers; optional `audience.node_id` is omitted if empty, and explicit decisions always serialize as `[]`, never `null`. All timestamps use Go's RFC3339Nano UTC representation; ports must already be ordered. The exact resulting UTF-8 bytes are the canonical payload. The signer computes:

```text
Ed25519.Sign(private_key, UTF8("Fleetguard/signed-snapshot/v1") || 0x00 || payload_bytes)
```

`key_id` is **inside** `payload_bytes` and is therefore authenticated. Do not sign a re-encoded JSON object, a hash supplied by the network, or the envelope itself. The canonical payload format is frozen for schema v1; changing struct fields/field order requires a new schema version and test vectors.

`VerifySignedSnapshot` base64-decodes the opaque payload, rejects unknown/duplicate JSON fields, decodes into the fixed v1 structure, re-encodes to compare **byte for byte** against the original payload, fetches the trusted Ed25519 verification key using the *signed* `key_id`, then verifies the domain-separated signature over the **original exact bytes**. Tampered bytes and alternate whitespace/number/time representations are rejected; there is no ambiguity about what was signed. The committed `snapshot_signed_valid.json` is a deterministic test vector made from a public **test-only** signing seed and must never be used as a real trust anchor.

The caller must supply trusted public keys provisioned **locally**, not received from the controller response; a local expected node/group audience; the last **durably accepted revision for that audience**; and an injected clock. Checks reject future-issued policies beyond skew, expired policies or decisions, wrong audience, and revisions <= last accepted. Update durable revision and accepted state atomically in issue #9. Keep the last valid state on failed verification. Per-audience revisions prevent replay **only with persisted monotonic state**; signature verification alone is insufficient.

### Bounds (hard-coded v1 ceilings)

| Limit | Value |
|---|---:|
| Evidence JSON | 16 KiB |
| Signed snapshot payload | 128 KiB |
| JSON envelope | 180 KiB |
| Decisions per snapshot | 256 |
| Ports per decision / evidence event | 16 / 32 |
| Maximum snapshot lifetime | 5 minutes |
| Clock skew allowance | 30 seconds |
| Evidence maximum age | 10 minutes |
| Evidence window | 5 minutes |
| Evidence attempts per window | 1,000,000 |

Operational policy must use **equal or stricter** local limits, including destination service/port permissions, protected management paths and maximum concurrent bans. These are upper bounds for parsing only, not safe defaults for real hosts.

## Acknowledgments and errors

`Acknowledgement` carries schema, node, revision, state and (for rejection/error) a machine-readable reason. States: `received`, `validated`, `applied`, `rejected`, `error`. Reasons: `malformed`, `oversized`, `invalid_schema`, `invalid_evidence`, `invalid_decision`, `unknown_signer`, `invalid_signature`, `not_canonical`, `expired`, `clock_skew`, `replay`, `scope_mismatch`. State is a report and cannot be trusted without authenticated transport; the protocol package itself never claims a firewall operation succeeded.

## Validation and fixtures

```sh
go test -count=1 ./pkg/protocol
go test -race ./...
make check
```

Tests use a fixed clock and an explicitly **non-production** deterministic key. They exercise signed test vector interoperability, byte-by-byte mutation of every signed byte, signature mutation, malformed and duplicate JSON, oversized payloads, unknown signers, stale/replayed revisions, wrong node/group, future/expired snapshots and decisions, broad CIDRs, bad ports/actions, unverified SYN/UDP classification and event spoofing. No root, firewalld, controller, Tailscale, or network access is needed.
