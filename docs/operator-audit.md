# Fleetguard operator audit, readback and retention (issue #14)

**Status: experimental, read-only inspection; no API to enable enforcement.** The controller still publishes signed **empty** policies. [Prometheus exporters, /metrics, alert rules and Grafana dashboards are separate issue #35](https://github.com/maestroi/Fleetguard/issues/35).

## Agent: signed desired vs accepted vs runtime readback

On the agent VM, with the *existing* installed runtime configuration:

```sh
fleetguardctl status -runtime-config /etc/fleetguard/agent-runtime.json
fleetguardctl decisions -runtime-config /etc/fleetguard/agent-runtime.json
fleetguardctl inspect 203.0.113.42 -runtime-config /etc/fleetguard/agent-runtime.json
```

These commands **do not** poll the controller, submit evidence or touch firewall rules. The same CLI also supports `inspect -runtime-config FILE 203.0.113.42`. It reads the private agent state, validates the Ed25519 snapshot signature against locally trusted keys at the original acceptance timestamp, checks current TTL and offline age, and independently evaluates local safety restrictions. Invalid signatures or state ownership fail closed.

The JSON separates:
- `signed_desired`: authentic, persisted signed policy *including expired historical decisions* (not necessarily active).
- `accepted_effective`: locally acceptable, unexpired central decisions after current TTL/offline/safety checks.
- `backend_observed`: agent-owned entries found through **read-only** backend inspection. A backend entry that is no longer in an accepted snapshot is visibly unmatched.
- `acceptance`: `none`, `current`, `expired`, or `unsafe`.
- `enforcement`: `simulated_only`, `backend_inspected`, or `unavailable`; `backend_readback_verified` is distinct from `kernel_verified`.

**A D-Bus runtime readback is not independent proof that a real packet was dropped on the wire.** `kernel_verified` deliberately remains false until a separate isolated network test (#11/#12). In observe mode, the agent does not invent live mock-backend state from an offline process. If firewalld D-Bus is unavailable, results say `unavailable`, never `no bans`.

`fleetguard-agent -run` status includes counters for invalid signed snapshots (including invalid/replayed), rejected policy scopes, reconcile errors, last acceptance, central decision count and existing denied-log sensor queue/drop metrics. Agent process restart resets ephemeral counters; they are not durable fleet telemetry. Local non-persisted decisions can be identified from real backend readback, but not reconstructed from a previous process's private memory.

For emergency cleanup, `fleetguardctl emergency-disable -runtime-config FILE -state-dir DIR` remains the **only** local privileged mutation, and it removes only Fleetguard-owned runtime rules. Audit commands never call it.

## Controller: authenticated node-local audit API

The HTTPS controller provides `GET /v1/audit?group=<authorized-group>&limit=16` on its **existing private TLS 1.3 listener**. There is no new listener or administrative token. The normal per-node bearer token and `X-Fleetguard-Node-ID` header are mandatory. The handler binds the request to the authenticated node ID and authorized group, and limits evidence to 1–32 records.

The response provides the reporting node, proof level (including unverified network logs), event/time/service/port metadata, stored signed snapshot *payload* with signer key ID/revision/TTL/reason, and recent acknowledgements. The API does not export signing private keys, bearer credentials, packet payloads or a cross-node fleet listing. **Acknowledgements are self-reported by agents, not independently verified enforcement.**

`GET /v1/health?group=<authorized-group>` remains authenticated and returns mode, node, bounded queue depth and explicit `enforcement_enabled=false` / `applied_state_verified=false`. Neither endpoint permits firewall commands, policy signing, changes to local protections or configuration edits.

For an operator who has access to the controller's private local files (including historical, revoked nodes in their authorized historical groups), use the controller process **offline**:

```sh
fleetguard-controller -inspect-node -config /etc/fleetguard/server.json -node lab-node-a -group lab-ssh
```

This uses a **read-only SQLite connection**; it cannot create a database, change PRAGMAs or modify rows. It displays at most 32 recent evidence items plus 16 recent ack claims, and only for the specified node/group.

## Evidence and source IP retention

Set `evidence_retention_hours` in the private controller server JSON, from **1 to 24** (omission defaults to 24). This restricts evidence and general audit-log retention, including audit messages that can contain source IPs, when new evidence arrives. The controller also offers an explicit local-only purge:

```sh
fleetguard-controller -purge-sensitive -config /etc/fleetguard/server.json
```

The purge reports the cutoff time and how many evidence/audit rows were deleted. Run it periodically even when no evidence is arriving (for example with a scheduled systemd timer); the process does **not** start an unrequested background cleanup job. It never deletes current signed policy revision watermarks, acknowledgement history, local agent state or SQLite backup copies. **If future snapshots include source IPs, signed snapshot retention requires a separate safety-preserving design:** deleting the snapshot watermark would break monotonic anti-replay protection. Do not treat this feature as a blanket compliance/erasure solution.

SQLite parent directories remain private (0700), DB files private (0600). Avoid exposing JSON outputs with source IPs to unauthorized users or centralized logs without appropriate retention policy. There is no arbitrary source-IP lookup via controller HTTP endpoints; the operator can only view scoped data from its own node identity.

## Tests and open follow-ups

```sh
go test -race ./internal/agent ./internal/controller/api ./internal/controller/auth ./internal/controller/store
```

CI covers tampered signed state rejection, TTL expiry, simulated vs backend semantics, invalid IPv4 lookup, invalid snapshots/scopes, failed reconciliation, node/group isolation, unauthorized API access, private SQLite read-only behavior, expired evidence purge, retention bounds and safe health responses.

Remaining work: controlled packet-path verification in #11/#12, fleet-wide authenticated **operator role** and protected administrative access (not a node bearer token), continuous production-grade metrics in #35, persistent agent decision provenance across crashes, and formal signer/key rotation in #15.
