# Fleetguard

**Fleet-wide threat detection and safe, distributed firewall enforcement.**

> **Status: experimental proof of concept.** A private, opt-in HTTPS controller now accepts authenticated lab evidence and serves signed **empty** policies. Synthetic sensors and mock firewalls remain test-only. No automatic threat promotion or real firewall enforcement exists. Do not deploy to critical systems.

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

See [GitHub Issues](https://github.com/maestroi/Fleetguard/issues) for the implementation backlog. The design is documented in:
- [Architecture and protocol sketch](docs/architecture.md)
- [Threat model and safety requirements](docs/threat-model.md)
- [Isolated homelab POC test plan](docs/homelab-poc.md)
- [Observability: Prometheus metrics, alerts and Grafana](docs/observability.md)
- [ADR 0001: firewalld-first backend](docs/adr/0001-firewalld-first.md)
- [ADR 0002: role-based exposure profiles](docs/adr/0002-exposure-profiles.md)

## Implementation status

The Go monorepo contains buildable command-line entry points and a simulated, observe-only startup path. It does **not** yet detect attacks, correlate evidence into bans, or manage firewall rules. A separate, explicitly enabled **observe-only HTTPS controller API** now handles authenticated lab-node evidence and signed *empty* snapshots. A separate deterministic synthetic sensor and in-memory mock backend are available for rootless testing.

The versioned **data-only** event and Ed25519-signed policy contract lives in [`pkg/protocol`](pkg/protocol) and is documented in [Protocol v1](docs/protocol-v1.md). This library does not enable enforcement, implement controller authentication, or replace local safety checks.

## Developer quickstart (safe simulation only)

Requirements: **Go 1.27+**, `make`, and Linux for the built binaries. Dependencies are standard-library-only.

```sh
git clone https://github.com/maestroi/Fleetguard.git
cd Fleetguard
make check                     # gofmt, tidy, vet, unit tests
make build                     # Linux amd64 binaries in dist/ (controller uses SQLite)
make smoke                     # agent, controller and CLI; no privileges
```

Run individual entry points (one-shot status output, not long-running daemons):

```sh
go run ./cmd/fleetguard-agent -config examples/agent.json
go run ./cmd/fleetguard-controller -config examples/controller.json
go run ./cmd/fleetguardctl check-config -kind agent -config examples/agent.json
go run ./cmd/fleetguardctl version
```

Configurations are strict, local JSON files. The agent accepts **only** `mode: "observe"` and `firewall_backend: "simulated"`; a different mode or backend is rejected. The controller accepts only `mode: "observe"`. No example contains real credentials or production defaults. The simulator does not create firewall rules, listen on sockets, send telemetry or issue policies. For the complete intended architecture, see [docs/architecture.md](docs/architecture.md).

Build metadata defaults to `VERSION=dev`, `COMMIT=<git short SHA>` and `BUILD_DATE=unknown`. To label a build reproducibly:

```sh
make build VERSION=v0.0.0-dev COMMIT=local-test BUILD_DATE=unknown
```

## Rootless synthetic demo (issue #4)

Run `make simulate` (or `make build && ./dist/fleetguardctl simulate`) for a two-node fixture demo with a simulated partition and a manually seeded mock-only drop that expires under a virtual clock. No sockets, firewalld, root access or real packet filtering are involved. The demo is *not* automatic correlation or signed-policy enforcement. See [simulation documentation](docs/simulation.md) and the bounded fixture files under `examples/synthetic/`.

## Authenticated controller (issue #5)

The controller can now run an **opt-in** private HTTPS 1.3 listener with distinct per-node bearer-token authentication, local credential revocation, server-controlled service groups, bounded evidence ingestion, SQLite persistence, idempotent signed empty policy snapshots and acknowledgement auditing. The normal `fleetguard-controller -config examples/controller.json` command remains a no-network simulation.

Build requirements for the controller are Go 1.27+, a C compiler, and system `libsqlite3-dev` (Linux AMD64). The agent and CLI remain pure Go. No real firewall access is involved. Setup requires generating your own certificates, keys and tokens; **no valid credentials are committed**. See [controller API and lab setup](docs/controller-api.md).

```sh
make build
./dist/fleetguardctl generate-signing-key -private /private/lab/signing.key -public /private/lab/signing.pub
./dist/fleetguard-controller -serve -config /private/lab/server.json
```

The server rejects wildcard/public bind addresses, non-TLS requests, unknown or revoked nodes, evidence identity spoofing, unauthorized service groups and stale/oversized evidence. **It never promotes events into enforcement decisions**; that is separate, security-gated work in issues #6–#9.

## Automated merging and releases

**Go CI** runs on every pull request. After CI passes, only your non-draft, same-repository PRs authored by `maestroi` are automatically squash-merged into `main`; everyone else's PRs still need a manual merge. Owner auto-merge never bypasses GitHub's required checks and validates the exact tested PR SHA.

Every successful `main` update (including bot-performed merges) builds a fresh experimental `v0.1.N` prerelease and uploads Linux AMD64 binaries, a Compose bundle and `SHA256SUMS` to [GitHub Releases](https://github.com/maestroi/Fleetguard/releases), and publishes a version-matched GHCR controller image. The controller requires system `libsqlite3`; no build is production-ready by virtue of being released. See [automation and release details](docs/automation.md). The first workflow PR must be merged manually to activate it; configuring GitHub branch protection is recommended.

## Manual cross-node correlation (issue #6)

A new **offline, observe-only** `fleetguard-controller -evaluate` mode correlates persisted, authenticated evidence into scoped advisory candidates. It requires at least two distinct reporters from independently configured trust domains, application-verified proof, and an operator-controlled service/observation/transport/port allowlist. Raw SYN/UDP logs cannot trigger a candidate, and known shared NAT addresses require explicit manual review. Output is audited locally but **never published to agent snapshots or applied by a firewall**.

Read [the correlation guide](docs/correlation.md) and [example local policy](examples/correlation/lab-policy.example.json). The controller still serves signed **empty** policies.

## Docker controller and Compose

A versioned, **non-root** Linux AMD64 controller image is published to the GitHub Container Registry at `ghcr.io/maestroi/fleetguard-controller:v0.1.N` for each new main release. The matching GitHub Release also includes a Compose bundle and checksums. See [Docker deployment and permissions](docs/container-deployment.md) and [the runnable Compose example](deploy/controller/README.md).

The Compose deployment uses UID/GID 65532, **drops all Linux capabilities**, disables privilege escalation, uses a **read-only root filesystem**, mounts only private read-only credentials plus writable SQLite state, enforces resource limits and exposes HTTPS **only on host loopback**. It does **not** require `NET_ADMIN`, privileged mode, host networking, Docker socket or host firewalld access. No live blocking is implemented. Use an explicit published version tag, not a floating `latest`. The container's GHCR package may need a one-time change to **Public** for anonymous pulls.

## Local safety authorization and recovery (issue #7)

The root-managed local safety policy and offline emergency latch are documented in [local safety and recovery](docs/local-safety.md). These safety gates validate protected source networks, service/port scopes, decision limits, management interface state and backend verification independently of signed central policy. The current controller and agent remain observe-only: **there is still no live firewalld adapter or automatic enforcement.** The latch is preparatory until the adapter and reconciler are integrated.

```sh
go run ./cmd/fleetguardctl check-safety -config examples/safety-policy.json
# On a prepared disposable Linux VM only:
# sudo fleetguardctl emergency-disable -state-dir /run/fleetguard
```

## Optional firewalld denied-log sensor (issue #10)

The opt-in agent daemon can tail *new* kernel journal entries that firewalld has already configured to log. A strict IPv4 INPUT parser aggregates bounded, sampled source/service/port counters and sends unverified evidence to the existing authenticated HTTPS controller. The sensor **never enables firewalld LogDenied, opens a network port, or initiates a ban**. A controller outage drops telemetry rather than delaying expiry and safety reconciliation. See [denied-traffic sensor setup, limits and test fixtures](docs/firewalld-sensor.md).

## Audit-only exposure profiles (issue #21)

The [role-based exposure auditor](docs/exposure-profiles.md) introduces versioned local profiles, inheritance, trusted range parameters, expiring overrides and a read-only evaluator for unexpected listening ports and firewall configuration drift. Example profiles cover web edges, Solana validators and RPC, and Sui validators/fullnodes. Run `fleetguardctl audit-exposure -config FILE -observed FILE` for rootless fixtures, or `-live -watch` for read-only D-Bus and socket monitoring. **The feature never modifies baseline firewall rules or claims an open socket is internet reachable.**

## Operator audit and health (issue #14)

The [read-only operator audit](docs/operator-audit.md) adds `fleetguardctl status`, `decisions` and `inspect <ip>` for signed desired vs accepted vs backend-observed temporary bans, without touching the firewall. It also adds scoped authenticated `GET /v1/audit` on the controller's existing TLS listener, a local read-only `fleetguard-controller -inspect-node` command, and configurable evidence retention with a local `-purge-sensitive` command. An agent acknowledgement or D-Bus readback is **not** packet-path proof. Prometheus /metrics and dashboards remain in [#35](https://github.com/maestroi/Fleetguard/issues/35).

## Opt-in signed-policy agent daemon (issue #9)

The [agent reconciler and offline recovery](docs/agent-reconciliation.md) add authenticated outbound HTTPS polling, Ed25519 verification, monotonic durable state, short-lived local decisions and automatic TTL/offline cleanup. The original `fleetguard-agent -config` remains a harmless one-shot simulator; the daemon is enabled only with `fleetguard-agent -run -runtime-config /absolute/path`. The observe-only runtime uses mock firewall state; live firewalld requires **explicit disposable VM-only opt-in** and independent management-path testing. Do not deploy on production hosts.

## Experimental firewalld D-Bus adapter (issue #8)

The [firewalld D-Bus backend](internal/firewall/firewalld) is implemented as a **separate, not-yet-wired library** with a real D-Bus client, pre-provisioned host/IPSet ownership checks, port-scoped runtime rules, minimal-change reconciliation, exact owned-object cleanup and mock-based tests. It deliberately refuses unsupported backends and zone topology; it does not enable blocking in the current agent. Read [isolated VM prerequisites, limits and test plan](docs/firewalld-backend.md). In particular, real packet-path tests and expiry/restart integration (#9 and #11) are still required before live use.

## License and contributions

Licensed under [Apache-2.0](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) for the PR and testing workflow and [SECURITY.md](SECURITY.md) for private vulnerability reporting.
