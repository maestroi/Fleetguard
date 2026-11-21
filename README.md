# Fleetguard

**Fleet-wide threat detection and safe, distributed firewall enforcement.**

> **Status: experimental bootstrap / proof of concept.** The binaries currently validate local configuration and print simulated state only. No network services, real sensors, policy issuance or firewall enforcement exist yet. Do not deploy to critical systems.

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

The Go monorepo contains buildable command-line entry points and a simulated, observe-only startup path. It does **not** yet detect attacks, correlate evidence into bans, or manage firewall rules. A separate, explicitly enabled **observe-only HTTPS controller API** now handles authenticated lab-node evidence and signed *empty* snapshots. A separate deterministic synthetic sensor and in-memory mock backend are available for rootless testing.

The versioned **data-only** event and Ed25519-signed policy contract lives in [`pkg/protocol`](pkg/protocol) and is documented in [Protocol v1](docs/protocol-v1.md). This library does not enable enforcement, implement controller authentication, or replace local safety checks.

## Developer quickstart (safe simulation only)

Requirements: **Go 1.27+**, `make`, and Linux for the built binaries. Dependencies are standard-library-only.

```sh
git clone https://github.com/maestroi/Fleetguard.git
cd Fleetguard
make check                     # gofmt, tidy, vet, unit tests
make build                     # static Linux amd64 binaries in dist/
make smoke                     # agent, controller and CLI; no privileges
```

Run individual entry points (one-shot status output, not long-running daemons):

```sh
go run ./cmd/fleetguard-agent -config examples/agent.json
go run ./cmd/fleetguard-controller -config examples/controller.json
go run ./cmd/fleetguardctl check-config -kind agent -config examples/agent.json
go run ./cmd/fleetguardctl version
```

Configurations are strict, local JSON files. The agent accepts **only** `mode: "observe"` and `firewall_backend: "simulated"`; a different mode or backend is rejected. The controller accepts only `mode: "observe"`. No example contains real credentials or production defaults. The simulator does not create firewall rules, listen on sockets, send telemetry or issue policies. For the complete intended architecture, see design PR #1.

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

## License and contributions

Licensed under [Apache-2.0](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) for the PR and testing workflow and [SECURITY.md](SECURITY.md) for private vulnerability reporting.
