# Rootless deterministic simulation (issue #4)

**Status:** test harness, not a production agent, controller, IDS, firewall or signed policy client. No root privileges, firewalld, Proxmox, Tailscale, sockets or real network traffic are used.

## Run it

```sh
make check
make build
./dist/fleetguardctl simulate
# or: make simulate
```

The demo uses two local fixture files, `examples/synthetic/node-a.json` and `node-b.json`, and a **fixed, injected clock** (`2026-11-21T12:00:00Z`) to make the output reproducible. The date is deliberately pinned to the fixture timestamps; it is not the real-time current date.

The output JSON reports that A's events were delivered while B was partitioned, that B's events arrived after the partition healed, and that a **manually authored mock-only** service/port-scoped decision expired after advancing the virtual clock. `real_firewall_writes` and `network_listeners` remain zero. The demo **does not correlate events into policy**, verify remote signatures, or enforce packet filtering; those capabilities are separate issues (#5–#9).

```sh
./dist/fleetguardctl simulate \
  -a examples/synthetic/node-a.json \
  -b examples/synthetic/node-b.json \
  -at 2026-11-21T12:00:00Z
```

## Components and safety bounds

| Component | What it does | Explicit limits |
|---|---|---|
| `internal/firewall.Backend` | Narrow capabilities/reconcile/inspect/remove-owned contract | Only structured `protocol.Decision`, no shell/command or raw firewall access |
| `internal/firewall/mock` | Owns an in-memory set of validated service/transport/port-scoped IPv4 `/32` decisions; lazy expiration | Maximum 256 entries; maximum 5-minute remaining TTL; returns `simulated: true`; no real firewall operations |
| `internal/sensor/synthetic` | Reads and validates per-node fixture events via protocol v1; injected clock and rate window | 128 KiB fixture, 128 events, 16 events per batch, 32 events per one-second virtual window; stale or impersonating events rejected |
| `internal/lab` | Holds up to 16 distinct fixture-backed node identities; toggles synthetic partitions and keeps bounded audit history | Maximum 2,048 delivered events; no sockets, TLS or host networking |

All reported events are **claims**. `ProofLevel` is not evidence authentication. Even app-verified fixtures should never trigger automatic fleet bans on their own; these packages deliberately do not issue signed snapshots or decisions from sensor input. Cross-node correlation belongs to issue #6, and immutable local safety checks belong to issue #7.

The mock reuses `protocol.ValidateSnapshot` for v1 structural checks, but validation in a mock is not authorization to enforce on a real host. The future firewalld backend must *independently* check trust, protected management ranges, service scopes, backend capabilities, and maximum TTL. A mock adapter may report effective **simulated** decisions only, never kernel state.

## Rootless tests

```sh
go test ./internal/firewall/mock ./internal/sensor/synthetic ./internal/lab
go test -race ./...
go vet ./...
make smoke
```

Tests cover virtual time advancement, expiration, idempotent desired-state replacement, atomic rejection of bad rules, defensive copies, concurrency, cancellation, spoofed node identity, duplicated events, oversized fixtures, rate limiting, partitions, and zero real enforcement. CI runs the same package tests and the simulate smoke command.
