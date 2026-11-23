# Rootless cross-node correlation (issue #6)

**Experimental.** Evaluation produces advisory candidates. The controller serves signed empty snapshots by default. A local operator can explicitly approve a candidate for an isolated lab using the workflow below.

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


## Approve a scoped decision in the isolated lab

Run evaluation with `-lab-source-cidr 172.29.50.0/24` first and inspect the candidate's source, service, transport, port, and reporting nodes. On the controller VM, rerun it with the candidate ID and the intended lab source subnet:

```sh
fleetguard-controller -evaluate -config /opt/fg-issue11/server.json \
  -correlation /opt/fg-issue11/correlation.json -group lab-ssh \
  -approve-lab-candidate "$CANDIDATE_ID" -lab-source-cidr 172.29.50.0/24
```

The command reevaluates evidence using the current registry and correlation policy. Lab evaluation accepts sources only within the specified private IPv4 subnet of /24 or narrower. Approval requires a fresh eligible candidate. It excludes the controller listener address. It uses the configured signing key to atomically publish a new node-specific snapshot for each reporting node. A reporting node with an active approval causes the entire new publication to be rejected. The decision and snapshot share the same expiry. Subsequent fetches after expiry receive empty desired state.

Keep the agents in observe mode for the first run. Before verifying the packet path, follow the [disposable VM firewalld setup](agent-reconciliation.md#disposable-vm-only-firewalld-experiment). Record the baseline reachability of the selected service and a second lab port. After approving the candidate, check the agent's applied revision and probe both ports from the generator. Repeat the probes after expiry, and use Grafana to compare the desired and enforced counters.

### Packet-path check on pve05

The generator uses `172.29.50.13` and the two agents use `172.29.50.11` and `172.29.50.12`. Use `172.29.50.13/32` as the lab source subnet for this check. With QEMU guest-agent recovery available, use the pre-provisioned Fleetguard sets in the `public` INPUT zone and verify the zone contains only the lab NIC. Use TCP 22 as the scoped service and a temporary listener on TCP 2222 as the comparison port. Probe both from the generator, and probe TCP 22 from the controller as a second source.

When firewalld is active, permit TCP 9464 from the controller's lab IP only on each agent so Prometheus can scrape the enforcement metric:

```sh
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="172.29.50.10/32" port port="9464" protocol="tcp" accept'
```

Reapply this runtime allow rule after a firewalld reload. With a 60-second approval, expect TCP 22 to time out from the generator during enforcement while TCP 2222 and the controller's TCP 22 probes succeed. Expect TCP 22 from the generator to recover after expiry. In Grafana, query `fleetguard_agent_enforced_decisions` over the test window. The packet probes verify the scope and the metric reports backend readback.
