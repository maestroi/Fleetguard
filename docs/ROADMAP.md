# Fleetguard roadmap

Persistent project plan. Status detail is in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md);
resume instructions in [HANDOFF.md](HANDOFF.md). Reconcile both against GitHub
and `main` at the start of every session; stale docs are not proof of state.

Target: 1,000–5,000 Linux (firewalld/nftables) nodes, mostly blockchain
infrastructure. Pillars: reactive fleet incident response, proactive threat
detection, protocol-aware exposure auditing, drift detection, lockout
prevention, observability.

## Milestone order

| # | Milestone | Issue | Priority | State |
|---|-----------|-------|----------|-------|
| 1 | Stabilize PR #46 / CI | #46 | P0 | done |
| 2 | Fleet-wide never-ban protection | #41 | P0 | merged; lab test pending |
| 3 | Agent watchdog + independent TTL recovery | #47 | P0 | next |
| 4 | Manual bulk fleet-wide ban/unban | #44 | P0 | not started |
| 5 | 1,000+ agent scale testing | #16 (raised to P0) | P0 | not started |
| 6 | Policy distribution from benchmark results | (from #16) | P0 | blocked on 5 |
| 7 | Fleet inventory and targeting | new issue needed | P1 | not started |
| 8 | Secure enrollment and key rotation | #15 | P1 | not started |
| 9 | Docker/Tailscale/blockchain packet-path validation | #11, #12 | P0/P1 | needs privileged lab |
| 10 | Blockchain exposure profiles | #42 | P1 | local WIP on `feat/issue-42-chain-profiles` (uncommitted, owner's) |
| 11 | Continuous exposure auditing | #21 | P1 | audit-only base merged (#36) |
| 12 | Distributed threat detection | #43 | P1 | correlation base merged (#27) |
| 13 | Local high-confidence responder | #13 | P1 | engine hook exists; adapters not started |
| 14 | Strict exposure enforcement | #22 | P2 | not started |
| 15 | Observability and dashboards | #35 (closed), continuous | P1 | base merged (#38) |
| 16 | Operator web interface | new issue needed | P1 | after APIs/authz stable |
| 17 | External threat intelligence | new issue needed | P2 | not started |
| 18 | Controller HA evaluation (ADR) | new issue needed | P2 | after scale data |
| 19 | Additional firewall backends | new issue needed | P3 | not started |
| 20 | Release and production readiness | continuous | P1 | release automation exists |

Tests, docs, observability and security review accompany every milestone;
none are deferred to the end.

## Non-negotiable invariants
See [SECURITY_GATES.md](SECURITY_GATES.md). Summary: local protection is
authoritative; observe-only by default; signed, bounded, replay-safe policies;
independent expiry; spoofable evidence never auto-blocks; Fleetguard only
touches its own firewall objects; unsupported paths are reported, never
claimed.

## Infrastructure stance
SQLite + single controller until measurements say otherwise. No Redis, Kafka,
NATS, PostgreSQL or Kubernetes dependency without an ADR backed by measured
need (see `docs/adr/`).
