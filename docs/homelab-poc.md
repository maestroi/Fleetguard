# Homelab POC: deployment and acceptance plan

**All tests must run against isolated, disposable test VMs, not Proxmox hosts or production systems.** At the beginning, the real enforcement backend is disabled and simulated.

## Topology

| VM | Role | Notes |
|---|---|---|
| `fg-control` | Go controller + SQLite | HTTPS API, signed decisions, audit |
| `fg-agent-a` | Go agent + firewalld | IPv4 test network, observe-only first |
| `fg-agent-b` | Go agent + firewalld | Separate independent reporting identity |
| `fg-generator` | Controlled traffic/event generator | Limited to explicitly owned lab IP ranges |

Use a dedicated Proxmox bridge/VLAN or other isolated network. Snapshot VMs before enabling firewall enforcement. Add optional Tailscale connectivity only **after** basic HTTPS operation is verified; ensure a console path remains available. Do not publish an unauthenticated controller port to the public internet.

The controller host and the operator jump host addresses must be in each agent's local protected policy. Do not count the traffic generator's public IP if it could affect real users. Use documentation addresses (e.g., `203.0.113.42`) for offline synthetic events only; use real *assigned lab subnet* IPs for packet-path experiments.

## Reproducible phases

### Phase 0 — interfaces and synthetic events

- Implement a mock firewall and synthetic sensor. All decisions default to observation-only.
- Start controller and two agents with distinct authenticated identities.
- Inject event fixtures at both agents and verify bounded batching, provenance, deduplication, and controller audit logs.
- No actual network drops at this stage.

### Phase 1 — signed desired state

- Implement canonical policy serialization, key enrollment, signing, key rotation tests, revision/expiry validation, poll/ack loop.
- Controller emits an isolated short-lived decision targeting a test source /32 and one allowed lab service port.
- Confirm both agents accept the same revision and reject an altered payload.
- Simulate controller disconnection and ensure expiry still occurs locally.

### Phase 2 — firewalld enforcement

- On disposable VMs, enable enforcement intentionally; initialize agent-owned runtime ipsets/rules using D-Bus.
- Validate actual packet outcomes to host INPUT and (only if present) Docker DNAT/FORWARD paths.
- Confirm no unrelated firewalld zones/policies/rules are changed.
- Run `firewall-cmd --reload`, restart firewalld, and restart the agent; verify eventual state convergence and no lockout.
- Use console access to verify emergency-disable removes only Fleetguard state.

### Phase 3 — correlation and safety

- Simulate multiple independent verified events and a one-node-only event. Only sufficient verified, independent evidence can promote an auto-ban.
- Simulate forged/spoofable low-confidence packets and ensure they never alone cause fleet-wide enforcement.
- Test protected addresses, malformed CIDRs, wrong service scopes, expired policies, replay, signature failures, and oversized event streams.
- Verify automatic removal on TTL expiration and no accidental reactivation after reboot.

## MVP acceptance matrix

| Test | Expected result |
|---|---|
| Controller + two agents start in observe mode | No changes to live firewall |
| Two independently authenticated nodes report verified abuse | Correlation produces auditable candidate; signed block when explicit threshold met |
| One node reports only raw SYN/UDP logs | No global auto-block |
| Valid signed short-lived /32 for permitted service | Correct firewalld enforcement on intended port only |
| Signature tampered / unknown key | Reject, emit reason and metric |
| Replay old revision / already expired snapshot | Reject, leave valid state intact |
| Protected management IP or overlapping prefix | Reject locally even if signature valid |
| Broad `0.0.0.0/0` or IPv6 `::/0` | Reject |
| Wrong node group / protocol port | Reject |
| Agent process restart | Recover, preserve valid bans, don't restore expired ones |
| Firewalld reload/restart | Restore only agent-owned runtime objects, preserve existing zones |
| Controller disconnect | Existing bans expire; no loss of baseline access |
| Manual emergency-disable | No Fleetguard drops remain, unrelated rules unchanged |
| Docker published port (optional if installed) | Explicitly verify that intended rule applies to forwarded traffic; mark unsupported otherwise |
| High event-cardinality stress fixture | Bounded memory and queues; count dropped/sampled events |
| 1,000 simulated agents (later) | Controller handles snapshots/acks without correctness degradation |

For repeatable dashboard setup and access on the `pve05` lab, see the [Proxmox monitoring runbook](observability.md#four-vm-proxmox-lab).

## Measurements to record

- `event_to_policy_seconds`: from last qualifying verified observation to signed policy availability.
- `policy_to_apply_seconds`: from policy fetch to confirmed firewall enforcement.
- False-positive rate by service and independent-node count, plus rejected-policy reasons.
- Number of active decisions, current policy revision, time since last contact, reconciling errors.
- Controller CPU/RAM/SQLite growth, agent RSS/CPU and dropped evidence counters.

**Targets are hypotheses:** aim for a few seconds in a four-VM lab; do not state production SLOs without measurements.

## Security test constraints

- Use controlled small traffic volumes and locally assigned test IPs.
- Do not attack third-party systems or real public services.
- If the generator produces traffic, rate-limit it and never send it beyond the isolated lab.
- Always test with console access and a disposable VM snapshot before toggling enforcement.
- Maintain an explicit operator-controlled allowlist and an out-of-band recovery path.

## Definition of done for POC

An independent contributor can follow a short README, start the lab, produce a reproducible correlation, watch a signed decision appear in both agents' firewalld state, and see it expire. Every negative and failure test above either passes or is clearly documented as unsupported. No production-readiness claim is made.

## Results: pve05 packet-path run (2026-11-23)

Both agents ran in `enforce` mode on firewalld 2.x with nftables, using pre-provisioned Fleetguard ipsets in `public` and TCP 22 as the scoped service. The comparison listener was TCP 2222. The generator was `172.29.50.13`. Each agent posted one fresh `application_verified` evidence event. The approval command was `-approve-lab-candidate … -lab-source-cidr 172.29.50.13/32` with a 60-second TTL.

| Test | Result |
|---|---|
| Observe-mode baseline | Pass. Generator and controller reached TCP 22 and TCP 2222 on both agents. No ipset entries or drop rules were present. |
| Two-node verified evidence → candidate | Pass. The candidate used two nodes and two domains with `verified_multi_node_abuse`, a /32 source and TCP 22 only. |
| Approval → enforced drop | Pass. The drop was enforced 1.6 s after approval on agent A and within 3.2 s on agent B, an upper bound from sequential polling. |
| Scope during block | Pass. Generator TCP 22 was dropped on both agents. Generator TCP 2222 and controller TCP 22 stayed open. |
| TTL expiry | Pass. The entry and rich rule were removed within 1 s of `expires_at`, and generator TCP 22 reopened. |
| Expiry with controller stopped | Pass. Agent B removed the drop on time while the controller was stopped. |
| Agent restart after expiry, controller down | Pass. The agent reported `offline_expired: true` and did not reapply the drop. |
| Graceful agent restart during block | Pass. The drop was cleared on stop and restored within 0.5 s of restart. |
| `firewall-cmd --reload` during block | Pass after a setup fix. The drop was restored within 1 s. See finding 1. |
| Second approval while one is active | Pass. The command was rejected with `already has an active approval`. |
| `fleetguardctl emergency-disable` during block | Pass. Only the Fleetguard rich rule was removed, as confirmed by a zone diff. The latch persisted across agent restart. |
| Controller-signed block on a locally protected IP (`172.29.50.254`) | Pass. Both agents rejected it with `protected_source` and `rejected_scopes=1`, and applied no entry. |
| Snapshot signed by an untrusted key | Pass after fix. The agent stays up, restores no decisions (`invalid_snapshots=1`) and keeps its revision watermark. See finding 2. |
| SIGKILL during block | Pass with `deploy/systemd/fleetguard-agent.service`. systemd restarted the agent within 1 s, it restored the still-valid drop, and the drop expired on time. Without the unit, the drop stays until a manual restart. |
| Agent crash loop during block | Pass. After the restart limit, `OnFailure` ran emergency-disable, which removed only the Fleetguard drop and set the latch. |

The broad-CIDR, replay and tampered-payload cases are covered by unit tests only. The lab approval path cannot sign a non-/32 source.

### Findings

1. **Permanent interface binding is required.** On agent A, `enp6s18` was bound to `public` at runtime only. A reload left no active zone, so the backend refused all writes, including cleanup, with `zone or source-based routing mismatch`. This fail-closed behaviour also dropped the active ban. Fix: `firewall-cmd --permanent --zone=public --add-interface=<nic>` on each agent before enforcement. A reload also removes runtime-only allow rules, such as the TCP 9464 metrics rule.
2. **Fixed: trusted-key rotation stopped the agent from starting.** When the stored snapshot's key was no longer trusted, the agent exited at startup. It now starts without restoring decisions, keeps the revision watermark so older snapshots remain rejected, and waits for a fresh snapshot.
3. **Fixed for crashes: a dead agent left drops in place.** The pre-provisioned ipsets have no kernel timeouts. Run the agent with `deploy/systemd/fleetguard-agent.service`, which uses `Restart=always` and `RestartMode=direct` and requires systemd 254 or later. Without `RestartMode=direct`, `OnFailure` fires on the first crash. Repeated failures trigger `fleetguard-agent-emergency.service`. Runtime ipset entries do not survive a reboot. The remaining gap is an agent that hangs without exiting; a systemd watchdog would cover that case.
