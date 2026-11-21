# Fleetguard threat model (draft)

**Scope:** POC agent, controller, transport, firewalld enforcement, local protection policy, telemetry. Revisit before a production pilot.

## Security objectives

1. Remote policies must **never** be able to remove required management access or modify unrelated firewall state.
2. A single malicious/compromised node, forged observation, or unauthenticated API caller must not trigger fleet-wide blocks.
3. Decisions must be authentic, scoped, bounded, replay-resistant, revocable, and automatically expire.
4. Loss of the control plane, transport, or process must not disable the baseline host firewall.
5. A local operator needs a documented, out-of-band recovery path.

## Assets and trust boundaries

- **Local root-owned safety config:** protected networks/interfaces, service roles, maximum bans/TTLs, trusted signer keys. Highest priority; not remotely mutable.
- **Agent host and firewalld D-Bus:** privileged enforcement boundary; compromised root can disable the agent (cannot be fully mitigated locally).
- **Controller API:** ingests untrusted events and serves signed policies. HTTP/Tailscale transport is **not** policy authority.
- **Signing authority:** private policy key; compromise impacts all connected nodes, subject to independent local hard limits.
- **Detection stream:** spoofable, adversarial, potentially inaccurate; observations are not commands.
- **Operator / CI:** repository and release pipeline can introduce malicious code; releases need signed artifacts and review before production.

## Attacker capabilities

Assume external attackers can send arbitrary internet traffic, probe many nodes, forge UDP packets or some raw TCP SYNs, control hosts behind NAT/cloud proxies, and exploit internet-facing applications. Also assume *one* agent's telemetry may be malicious or compromised. Consider a controller breach, expired/stolen credentials, and an operator accidentally deploying an unsafe policy.

Do not assume Fleetguard can prevent an attacker who already has root on the target Linux server from changing firewall rules.

## Abuse cases and mitigations

| Scenario | Potential impact | Required mitigation / validation |
|---|---|---|
| Spoofed source packets framed as port scanning | Block a victim's IP | Log-only SYN/UDP evidence cannot trigger global ban; require verified connection/application signals; cap weight per node |
| One agent reports fabricated huge volume | Poison controller decisions | Authenticate node, independently corroborate, cap its contribution, anomaly / quarantine telemetry |
| Shared NAT / CDN / legitimate scanner | Many innocent users lose access | Short TTL, service scope, explicit exceptions, confidence thresholds, review/appeal, hit-rate metrics |
| Controller emits `0.0.0.0/0` or management IP | Fleet lockout | Agent rejects broad prefixes and any overlap with local protected list; strict allowlist of permitted ports/services |
| Controller/API compromise | Unauthorized block waves | Offline/local hard limits, signed payloads, separate signing identity, operator approval for exceptional scopes, blast-radius staging |
| MITM, replay, stale state | Old bans reapplied | HTTPS authentication, signed exact bytes, monotonic revisions, issued/expiry windows, nonce or snapshot replacement semantics |
| Lost heartbeat or controller outage | Uncontrolled stale bans | Max offline lease, bounded TTL, expiration enforced locally; baseline firewall stays intact |
| Crash/reload during a rule update | Partial/inconsistent filters | Idempotent reconciliation, backend health, explicit applied-state acknowledgments, restore/rollback tests |
| Firewall chain ordering bypass | No effective block, or management lockout | Verify actual packet paths and firewalld priority behavior; integration tests in INPUT and FORWARD |
| Docker/container port publishing | Unexpected exposure or bypass | Test DNAT/FORWARD path and Docker policy semantics; no default claim of container protection |
| SSRF / arbitrary code via policy payload | Code execution | Strict structured schema, bounded size, no command interpolation, no remote scripts, safe logging |
| Disk/memory/network telemetry flood | Agent or controller DoS | Rate limits, sampling, bounded queues, per-IP cardinality limits, disk retention caps |
| Malicious build/release | Host root compromise | CI least privilege, pinned dependencies, release provenance/signatures, code review |
| Signing key leaked | Mass unauthorized decisions | Key rotation/revocation, scoped keys where possible, hard local limits and fast local disable |

## Protected management access

A remote blocklist is **not** an authoritative management allowlist. Keep a root-managed local protection policy for:
- Explicit management jump hosts and operator CIDRs (both IPv4 and IPv6).
- Required Tailscale interface and controller communication paths, validated by interface and policy where appropriate.
- Recovery access through hypervisor/provider console; do not rely solely on a network allow rule.
- Node-specific protocol-critical peers when verified and stable; avoid blindly exempting broad networks.

A local exception is only useful if its effective rule priority is correct. Enforce local checks against proposed source CIDRs **and test live packet forwarding outcomes**. `ACCEPT` in one nftables base chain does not necessarily override `DROP` in a later base chain.

Never allow remote policy updates to edit these local protections. Document an offline disable/recovery procedure that does not call the controller.

## Confidence and decision promotion

The system needs explicit, evidence-based semantics—not a generic single score that can be manipulated by traffic volume.

| Evidence | Fleet-wide auto-enforcement (initial policy) |
|---|---|
| Dropped packets, raw TCP SYN, UDP scan or unmatched ports | **No**; observe/report only |
| Validated failed SSH auth tied to established connections | Candidate with corroboration and limits |
| Trusted app-level abuse from a known endpoint | Candidate with corroboration and per-service scope |
| Multiple independent nodes corroborate verified abuse | Eligible for short temporary block, subject to limits |
| Manual operator decision | May be broader only with explicit approval and local safety limits |

Limit per-node observation votes, require independent network placement where possible (same shared logging pipeline does **not** count as independent), and verify source identity when practical. An alert should explain *which proof* supports its decision.

Local bans may be shorter and narrower than fleet-wide bans. Never promote one local ban automatically as verified evidence for a global ban.

## Privilege and separation

- Agent process should not require arbitrary root shell execution. Bind only to firewalld D-Bus operations it needs; assess practical D-Bus/polkit hardening on target distributions.
- Controller's event-ingest endpoint must not possess signing authority by default if the deployment can separate them.
- Node enrollment keys and controller signing keys have distinct roles.
- Linux service runs with filesystem and syscall hardening where compatible; never store unnecessary secrets in logs.

## Privacy and observability

Source IP addresses can be personal data. Collect minimal metadata, document retention, access controls, and deletion policy. Suggested POC: configurable short retention with an explicit purge test. Produce audit trails for manual overrides and policy promotion, but no packet payload collection.

## Mandatory adversarial tests

- Signed block targeting the controller or operator's protected management IP.
- Signed `0.0.0.0/0`, `::/0`, and an overly broad /24; overlapping protected subnet.
- Forged signature and previously valid but replayed/expired revision.
- A compromised reporter flooding fake events.
- Firewalld restart/reload, Docker forwarded flow, and Tailscale connectivity.
- Controller partition and simultaneous restart; verify expiry and rollback.
- Burst of >10,000 unique simulated IPs; verify bounded agent/controller memory.
- Legitimate clients behind a shared NAT; measure false positives.

See [architecture](architecture.md) and [homelab POC](homelab-poc.md).
