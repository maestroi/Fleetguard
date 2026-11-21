# Fleetguard

**Fleet-wide threat detection and safe, distributed firewall enforcement.**

> **Status: design / proof of concept.** No production-ready agent or controller exists yet. Do not deploy to critical systems.

Fleetguard is an open-source Go project exploring a hybrid approach to host network defense:

- **Local agents** observe suspicious activity, optionally take narrowly scoped, short-lived action, and report summarized evidence.
- A **control plane** correlates independent observations across nodes and issues signed, time-limited enforcement decisions.
- **Firewall backends** implement decisions without replacing existing host firewall policy. The first target is **firewalld via D-Bus**; other backends may follow.
- **Transport** is authenticated HTTPS and can run across **Tailscale**; Tailscale is not required by the software.

## Design principles

1. **Observe-only by default.** Enabling enforcement is an explicit opt-in.
2. **No accidental lockouts.** Protected management paths and networks are local-only configuration that remote decisions cannot supersede.
3. **Do not trust one observation.** Correlate independent, credible evidence; raw packets can be spoofed.
4. **Do not trust the control plane blindly.** Enforce signatures, anti-replay, policy scope, expiry, and hard local safety limits.
5. **Fail safely.** Preserve existing firewall configuration, expire temporary bans, and allow local recovery when connectivity is lost.
6. **Protect the right traffic.** Service/port-scoped policies first; special caution around peer-to-peer and consensus networking.
7. **No arbitrary command execution.** Agents accept structured policies only, not shell commands.

## Proposed components

| Component | Responsibility |
|---|---|
| `fleetguard-agent` | Sensors, safe local decisions, signed-policy validation, firewall reconciler, metrics |
| `fleetguard-controller` | Node authentication, event ingestion, correlation, policy issuance, auditing |
| `firewalld` backend | Agent-owned runtime IP sets / rules via D-Bus, careful interoperability with existing zones and Docker |
| `simulated` sensor/backend | Deterministic tests without modifying host firewall rules |

## First demonstration

In an isolated VM lab: one controller + two firewalld agents + a controlled traffic/event generator. Demonstrate cross-node corroboration, signed temporary blocks, expiration, restart/reload recovery, and protection against malicious policy. Use **observe-only** mode first.

## Roadmap

See [GitHub Issues](https://github.com/maestroi/Fleetguard/issues) for the implementation backlog. Architecture, threat model, and lab test plans will be proposed in a design pull request.

## Implementation status

This repository is currently bootstrapped with a design-only README. Do not assume any of the components described above have been implemented.

## License and contributions

License and contribution guidelines will be added during repository setup. Until a license file is present, **no open-source usage license is granted by default**.
