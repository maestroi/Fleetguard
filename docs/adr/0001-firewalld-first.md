# ADR 0001 — Firewalld-first, pluggable enforcement

- **Status:** Proposed
- **Date:** 2026-11-21

## Context

The initial target fleet already uses firewalld to manage exceptions for blockchain protocol ports and to coexist with Docker. Firewalld commonly uses nftables underneath, but `FirewallBackend` remains configurable. Calling Ansible or repeatedly launching `firewall-cmd` per IP is not suitable for fast response.

## Decision

Build the first working adapter using **firewalld D-Bus**, without directly owning nftables tables, editing external firewall policy, or issuing shell commands. Keep the backend contract expressed as **desired enforcement decisions** rather than generic arbitrary command strings.

Use a dedicated agent-owned firewall object namespace and a local reconciler. Future adapters may target nftables, UFW, or application firewalls, but the POC must not ship adapters that aren't actually tested.

## Candidate interface

```go
type Capability struct {
    IPv4, IPv6 bool
    ScopedPorts bool
    ForwardedTraffic bool
    KernelExpiry bool
}

type Backend interface {
    Capabilities(ctx context.Context) (Capability, error)
    Reconcile(ctx context.Context, desired []Decision) (AppliedState, error)
    Inspect(ctx context.Context) (AppliedState, error)
    RemoveOwned(ctx context.Context) error // emergency disable only
}
```

The `Decision` schema is validated by the core agent before the backend sees it. The backend independently revalidates it (defense in depth). Make all operations idempotent and test concurrency/reloads.

## Proposed rules of ownership

- Runtime only for temporary bans; no changes to existing permanent base policy.
- Dedicated named objects; never modify unrelated sets/rules.
- Explicit management bypass constraints in local config, never inferred from remote messages.
- **Default to port/protocol-scoped bans**, not full-host source drops.
- Automatically reject non-single-host prefixes initially: IPv4 /32, IPv6 /128 when supported.
- Maintain canonical decision/expiry state in the agent; firewalld's ipset timeout entries may not be retrievable through its usual API.
- D-Bus operation failures must be visible and must not silently claim successful enforcement.

## Critical validation required before implementation claims

Firewalld rich rules, policies, zones, source binding, and nftables chain ordering affect whether drops apply to INPUT vs FORWARD. Docker publishes ports through forwarding/NAT paths which can bypass a naive host INPUT rule. Evaluate representative firewalld configurations and write integration tests proving enforcement on intended paths without interfering with known-good access.

Do not assume `ACCEPT` in a chain immunizes packets against `DROP` in a separately evaluated nftables base chain.

## Alternatives considered

| Alternative | Decision |
|---|---|
| Direct nftables management | Attractive for advanced performance and atomic updates, but risks conflicts with an existing firewalld owner; deferred to a separate adapter |
| UFW command-line | Easy to prototype but repeated per-IP commands are not ideal for large dynamic sets; deferred |
| iptables + ipset | Useful on legacy hosts but avoid adding another policy owner in the first release |
| firewalld CLI loop | Acceptable for manual diagnostics, not the main runtime API |
| Firewall-only static Ansible deployments | Useful for installing/upgrading the agent, too slow for per-incident response |

## Follow-up

Prototype firewalld D-Bus set/rule creation and deletion on disposable lab VMs. Measure time to reconcile 1, 100, and 10,000 decisions. Record exact firewalld/backend versions and Docker settings. If port-scoped rules with protected management bypass cannot be proven safe, keep the entire prototype in observe mode rather than silently falling back to broad drops.

## References

- https://firewalld.org/documentation/man-pages/firewalld.dbus
- https://firewalld.org/documentation/man-pages/firewalld.policy
- https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html
- https://firewalld.org/documentation/man-pages/firewalld.conf.html
