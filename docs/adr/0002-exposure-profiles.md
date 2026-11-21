# ADR 0002 — Role-based network exposure profiles and drift detection

- **Status:** Proposed
- **Date:** 2026-11-21
- **Scope:** Follow-on capability; no automatic exposure changes in initial POC.

## Problem

Fleetguard's threat decisions explain *who should be temporarily denied*. Operators also need to know *which services, ports and ingress paths should exist at all*. A central rule such as "allow 443 everywhere" is unsafe: port 443 may be public on a reverse proxy, internal-only on a validator, or unnecessary on a database.

Node network exposure differs by purpose, protocol, network, environment, deployed role and local configuration. Firewalld zones and policies, listeners, Docker-published ports, NAT, cloud firewalls and service-specific flags all affect effective reachability.

## Decision

Introduce an **ExposureProfile** as a separate, signed/versioned policy concept from temporary **ThreatDecision**. Profiles describe intended exposure, not imperative firewall commands.

- Profiles are reusable, composable and scoped to trusted node identities/tags: e.g. `baseline-linux`, `web-edge`, `solana-validator`, `solana-rpc`, `sui-validator`, `sui-fullnode`.
- Node role/assignment comes from authenticated inventory or root-owned local config; never trust a node's self-reported role to raise its privileges or public exposure.
- Each entry expresses **direction** (ingress/egress), protocol (TCP/UDP), destination port/range, allowed network source or interface (public, private CIDR, tailnet, localhost), purpose and intent:
  - `required`: must be reachable from listed sources to function.
  - `permitted`: may be reachable if that service is enabled.
  - `forbidden`: must not be reachable from listed sources.
- Profiles may take deploy-time parameters such as the node's configured Solana `dynamic-port-range` and RPC port; do not blindly hard-code defaults.
- Explicitly track exceptions/overrides with identity, reason and expiry.
- **Observe-only initially:** report drift; do not automatically open or close baseline ports from a remote profile. Later enforcement needs a separate, explicitly enabled approval workflow, canary scope and rollback.
- Dynamic threat bans are a separate overlay constrained by local hard safety requirements and protocol-critical traffic protections. A signed exposure profile cannot override the local emergency management protection.
- Document precedence and conflicts deterministically: locally protected management paths > validated operator-managed exposure baseline > scoped temporary threat bans; disallowed or contradictory combinations must produce a visible conflict rather than a silent wider allow.

## Example profile (illustrative YAML, not a parser contract)

```yaml
apiVersion: fleetguard.io/v1alpha1
kind: ExposureProfile
metadata:
  name: sui-fullnode
spec:
  assignments: {nodeRoles: [sui-fullnode]}
  mode: audit
  entries:
    - name: p2p-state-sync
      direction: ingress
      protocol: udp
      port: 8084
      sources: [internet]
      intent: required
    - name: public-api-tls-proxy
      direction: ingress
      protocol: tcp
      port: 443
      sources: [internet]
      intent: permitted
      condition: public_api_enabled
    - name: internal-grpc
      direction: ingress
      protocol: tcp
      port: 9000
      sources: [private-network]
      intent: permitted
    - name: metrics
      direction: ingress
      protocol: tcp
      port: 9184
      sources: [internet]
      intent: forbidden
    - name: admin
      direction: ingress
      protocol: tcp
      port: 1337
      sources: [internet]
      intent: forbidden
```

This is a *starting example*, not a complete definition of Sui node exposure. Verify actual release config and local network architecture before use. Source: https://docs.sui.io/operators/full-node/sui-full-node

Example `solana-validator` profile should derive a configured `--dynamic-port-range` from a local trusted deployment manifest (not assume every node uses the same ports). Public RPC access must be a separate explicit `solana-rpc` role/profile. See https://github.com/solana-labs/solana/blob/master/docs/src/operations/requirements.md

For generic `web-edge`, a required or permitted public ingress `80/tcp` / `443/tcp` profile applies only to nodes assigned that role, not the entire fleet.

## Observed state: what can an agent actually know?

Combine at least the following, clearly reporting confidence and coverage:

1. **Configured firewall**: firewalld zone, policy, interface and runtime/permanent rules, plus recognized alternative firewall controls.
2. **Socket listeners**: local sockets bound to `0.0.0.0`, `::`, loopback and interface IPs, including process metadata when permissions allow.
3. **Container/published ports**: Docker or other runtime NAT / forwarding maps. A missing host listener does not prove a container is unreachable.
4. **Effective network path**: service ingress vs forwarded traffic, cloud/provider firewalls, external load balancers, NAT and proxies, when inventory evidence is available.
5. **Optional authorized external reachability probe**: only from controlled test identities and narrowly scoped addresses/ports; never let the controller become a generic internet scanner.

Report `expected_and_observed`, `required_missing`, `unexpected_listener`, `unexpected_public_exposure`, `forbidden_exposure`, `unknown_path`, and `insufficient_evidence`. **Do not equate a local listening socket with internet accessibility, or a firewalld allow rule with a working service.**

## Interaction with threat detection

- Traffic to an intentionally closed management port is an interesting signal, but not by itself proof that an attacker owns the claimed source IP (raw TCP SYN and UDP spoofing).
- A public P2P port being heavily contacted is often normal for blockchain nodes. Never ban solely because traffic volume exceeds a generic HTTP/SSH threshold.
- Dynamic blocks must be evaluated against both local protected paths and the effective exposure scope. Never block an IP on all services as a side effect of one port's abuse.
- Policy drift is an alertable **configuration issue** distinct from a threat event. Do not turn evidence of unexpected exposure into an automatic attack reputation score.

## Architecture and interfaces

Expose optional `ExposureAuditor` capabilities independent of enforcement `Backend`:

```go
type ExposureAuditor interface {
    Observe(ctx context.Context) (ObservedNetworkState, error)
    Evaluate(ctx context.Context, profile ExposureProfile, observed ObservedNetworkState) ([]ExposureFinding, error)
}
```

This is a conceptual interface. Keep OS observers and comparison/evaluation logic separate for rootless tests. Later: policy-as-code, secure canary rollout of desired host configuration, protocol-specific profile packs with versioned release notes.

## Risks and required safety gates

- Generic protocol defaults can drift across versions and configurations; require operator-reviewed variables and release-specific profile versions.
- Never use remotely supplied profiles to remove/rewrite existing firewalld permanent rules by default.
- A compromised controller must not be able to push an `allow internet everywhere` rule. Any eventual apply mode requires independent local opt-in, signed scope, approval/canary and rollback.
- Overlapping profiles and exceptions need deterministic evaluation and explicit conflict output.
- Preexisting management/Tailscale recovery remains a *local* protected invariant.
- Verify that a status of `forbidden_exposure` refers to actual reachable service paths, not speculative results from insufficient visibility.

## First deliverable (after mock sensor / safety foundations)

Implement an **audit-only profile evaluator** in rootless unit tests:
- `web-edge`, `sui-fullnode`, `solana-validator`, `solana-rpc` fixture profiles.
- Synthetic listeners/firewalld/NAT inventory.
- Findings for unexpected public ports, forbidden management exposure, missing required protocol port, and ambiguous/unobserved ingress.
- No remote firewall mutations and no network scans.

References:
- https://firewalld.org/documentation/concepts.html
- https://www.docs.sui.io/operators/validator/validator-config
- https://docs.sui.io/operators/full-node/sui-full-node
- https://github.com/solana-labs/solana/blob/master/docs/src/operations/requirements.md
