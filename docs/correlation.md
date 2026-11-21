# Rootless cross-node correlation (issue #6)

**Experimental, observe-only.** This release does not automatically publish, sign or apply correlation candidates. The existing controller `/v1/snapshot` continues serving **signed empty snapshots**; no firewall rules are modified, and no new HTTP admin endpoint is exposed.

## Workflow

1. Start the authenticated HTTPS controller as described in [controller-api.md](controller-api.md) and ingest test evidence from two different, independently enrolled lab nodes.
2. Configure **different token credentials** for each node in a locally protected registry. A reporting `node_id` is authenticated by the controller when evidence is ingested; the evaluator only reads those persisted records.
3. Create a private (`chmod 600`) local correlation policy from [`examples/correlation/lab-policy.example.json`](../examples/correlation/lab-policy.example.json) and ensure its `group`, node domains and service scopes match the server's operator-owned registry.
4. On the controller host, run a **manual** evaluation with the controller's existing `server.json` and SQLite file:

```sh
./dist/fleetguard-controller \
  -evaluate \
  -config /private/lab/server.json \
  -correlation /private/lab/correlation.json \
  -group public-rpc
```

No signing key or TLS private-key access is required by the offline evaluation command. All candidate reports are written to standard output as JSON and an audit record is appended to the local SQLite database. **Candidate JSON must not be fed directly to a firewall or treated as proof of abuse.** It is a bounded advisory result only, pending independent operator verification and future host-local safety checks.

## Promotion rules

A candidate requires *all* of the following:

- At least `min_nodes >= 2` distinct, non-revoked nodes with independently authenticated evidence stored in the **same** controller-owned group and authorized for the service.
- At least `min_domains >= 2` different **operator-provisioned** node trust domains. Put nodes sharing a trust boundary, backend identity or telemetry source in the same domain; a second token alone is not independent proof.
- `proof_level == application_verified`, received and observed within the configured time window, with no future timestamps. This remains a node's reported proof label; it is **not** cryptographic proof of user abuse.
- A canonical, public IPv4 source address, exactly allowlisted service, `observation` (e.g. `application_abuse`), transport and destination port. No default SSH/validator port allowlists or global source drops.
- No match against the locally configured `protected_sources`. These sources are suppressed even when multiple nodes agree.

A source in the explicitly configured `shared_nat_sources` is labeled `manual_review` with reason `shared_nat_review` and **no proposed Decision**; a shared IP may represent innocent users. A regular eligible candidate carries `verified_multi_node_abuse` and an advisory IPv4 `/32` `drop` Decision limited to the exact service, transport and one port, with a short bounded TTL. A proposed Decision is **not** a policy snapshot and is **never** automatically published.

Only application-level abuse evidence qualifies. An `established_connection` proves no malicious activity, while unverified firewalld/SYN/UDP log-only observations are spoofable or insufficient and **never contribute** to candidates. Mixed proof levels are not combined to reach the threshold.

## Limits and failure handling

Policies must explicitly specify the group, allowed scopes and domain mapping; omitted values do not enable auto-enforcement. `window_seconds` is 10–300, `decision_ttl_seconds` is 5–120, and thresholds are at least two. Each node contributes only one vote to a source/service/observation/port grouping, with attempts capped at 100 per node. Candidates are deterministically sorted by source and scope, and candidate identifiers are stable across input ordering. The database read is bounded by `max_evidence <= 4096`, and output by `max_candidates <= 64`. **Overflow returns an error** rather than silently using partial evidence.

The evaluator applies the strict protocol freshness limits again and skips invalid, stale, unauthorized or future evidence. A compromised node cannot increase its vote by flooding attempts, replaying different IDs or claiming a second domain. Unauthorized/expired reports have no impact; source overlap with protected prefixes is suppressed. Database and successful/failed evaluation events are audited. The initial read path is appropriate for a small homelab, not thousands of agents; evaluation is an explicit manual operator action.

## Verification

Run:

```sh
go test -count=1 ./internal/controller/correlation ./internal/controller/store ./cmd/fleetguard-controller
go test -race ./internal/controller/correlation ./internal/controller/store ./cmd/fleetguard-controller
```

Tests cover independent reporters, same-domain reporters, noisy single nodes, spoofable proof, shared NAT, protected prefixes, service/port/observation mismatches, duplicates and ordering, expired/future data, rate/candidate caps, SQLite group isolation, restart and audit retention. No root, firewalld, Proxmox or Tailscale is required.

## Next safety gates

Issue #7 will introduce local protected management paths and enforcement allowlists. Issue #8 provides an independently audited firewalld D-Bus backend and issue #9 adds signed desired-state reconciliation with anti-replay. **No candidate should become an enforceable policy before those gates have passed and lab tests validate all traffic paths.**
