# Role-based exposure profiles and read-only drift auditing (issue #21)

**Audit only.** This feature never changes firewalld, nftables, iptables, Docker, cloud rules or listeners. It does **not** add a new enforcement policy, bypass local protected networks or submit evidence to attacker reputation/correlation. A signed temporary IP ban is separate from this locally assigned, versioned baseline.

## Quickstart

The project includes example local assignments for `web-edge`, `solana-validator`, `solana-rpc`, `sui-validator` and `sui-fullnode`, all inheriting `baseline-linux`. They are **illustrative**, not defaults to deploy on production validators. Verify protocol ports with your deployed release and Ansible flags.

Check a deterministic synthetic fixture:

```sh
go run ./cmd/fleetguardctl audit-exposure \\
  -config examples/exposure/sui-fullnode.json \\
  -observed examples/exposure/sui-fullnode-observed.json
```

Read-only inspection of the machine where the CLI runs:

```sh
go run ./cmd/fleetguardctl audit-exposure \\
  -config /etc/fleetguard/exposure.json -live
```

For continuous local warnings and periodic state output (no listener or network connection from Fleetguard itself):

```sh
go run ./cmd/fleetguardctl audit-exposure \\
  -config /etc/fleetguard/exposure.json -live -watch \\
  -interval 5s -grace 2s
```

`-watch` listens for common firewalld D-Bus reload, zone, port, rule and service change signals and debounces for 750ms. A read-only socket and firewalld scan also runs every 5 seconds by default, with a 60-second full-scan fallback. Run the CLI as a systemd service and ship its JSON output to an **operator-controlled alert pipeline** if needed. It emits `new` and `resolved` alerts using stable finding IDs with configurable 0–5-minute grace. These cadences are POC choices, **not measured delivery-time SLOs**. Docker publishes, OS socket changes and external routing are not event-subscribed by this reader; they are only partially visible.

## Schema and precedence

The local `schema: 1` JSON document declares a node ID, role, service group, assigned named profiles, inheritance, conditional flags and trusted `port_parameters`. Profile entries specify `id`, `direction` (ingress or egress), `transport`, `ports: {from,to}` **or** `port_parameter`, `source`, optional `zone`/`interface`, `intent` (required, permitted, forbidden), and optional `condition`. Source classes are `public`, `private`, `tailnet`, `loopback`, `any`, or a canonical `cidr:192.0.2.0/24`. These are conceptual source categories for auditing, not automatically discoverable internet ACLs.

Entries with a missing condition flag or missing port parameter **fail compilation**. A false condition omits the associated entry. Explicitly assigned role/group must agree with every inherited profile's stated role/group. Duplicate profile IDs, inherited cycles, unsupported port ranges, unknown overrides and contradictory overlapping source/port/interface/zone intentions fail compilation. Reusable base profiles can leave role/group unspecified. CIDRs overlapping broad source classes are conservatively regarded as potential conflict, rather than silently permitted.

`overrides` live in the **local** document, refer to qualified `profile/entry` IDs, and require a named operator, reason, and expiry no more than seven days away. Expired overrides automatically stop changing intent. `protected` entries are local unconditional `forbidden` invariants; an inherited profile or override cannot negate them without causing an explicit compilation conflict. For example, protect public access to the out-of-band admin socket, independently of the firewall's existing management protection. The compiler never receives profile data from the controller.

For Solana, supply your **actual** `--dynamic-port-range` through the trusted `solana_dynamic_ports` port parameter. The `solana-validator` profile does not implicitly grant HTTP RPC port 8899; `solana-rpc` is a separate explicit role. Sui fullnode's 8084/UDP, metrics 9184/TCP and admin 1337/TCP illustrate distinct required/forbidden intents. Validate real Sui listen interfaces, proxy ports and chain version before adjusting production monitoring.

## How to interpret findings

A local listening socket does **not** mean a public internet connection can reach that service. Kernel socket tables are read from `/proc/net/{tcp,tcp6,udp,udp6}` with bounded reads; non-loopback listeners can trigger `unexpected_listener`, but only with `local_only` confidence.

Firewalld is queried through read-only D-Bus methods `getActiveZones`, `getPorts`, `getServices`, `getRichRules` and `getForwardPorts`. Simple runtime port allowances can be shown as `configured_allow` but firewalld service expansions, rich rule ordering, policy objects, direct nftables/iptables, cloud ACLs, proxies, source zones and Docker forwarding are **not fully modeled**. Those appear in `coverage.notes`. A configured allowance is reported with `configured_only` confidence, *not* `verified_external`. Missing permissions never change host firewall state or falsely imply traffic is blocked.

The rootless fixture format supports `listeners`, `coverage` and `paths`. A path with `provenance: external_probe` and `state: verified_reachable` or `verified_blocked` is accepted only with explicit `coverage.external: true`; this is **input reported by the operator's controlled lab probe**, not independently verified by Fleetguard. Valid `firewall_runtime` and `container_publish` paths are configuration-only evidence and never prove end-to-end reachability. Coverage gaps produce `unknown_path`; absence of a required host listener is only called `required_port_unavailable` when listener and forwarding inventories are both complete or an external probe explicitly found it blocked.

Finding types include `unexpected_public_exposure`, `forbidden_exposure`, `unexpected_listener`, `required_port_unavailable` and `unknown_path`, each with severity, confidence, profile provenance, port/transport and stable dedup ID. Conflict resolution is strict compilation failure, not a silent policy override. No attacker source address or unsanctioned network scan is used.

## Remaining acceptance gates

The evaluator, CLI, tests and live read-only observer can be validated without Proxmox privileges. Your isolated VM agent should separately validate firewalld D-Bus permissions, real socket table interpretation, IPv6/firewall coverage gaps, container DNAT/FORWARD inventory, controlled external probes and actual alert lag. Authenticated controller drift ingestion and independent inventory/probing are not included in this initial audit-only PR; the JSON event stream is the operator alert sink. The security of a profile/role assignment depends on the **local filesystem deployment**: for privileged systemd installations, operator-manage `/etc/fleetguard/exposure.json` as root-owned, not world-writable, and do not accept remote profile updates.

See [ADR 0002](adr/0002-exposure-profiles.md), [homelab POC](homelab-poc.md), and [issue #22](https://github.com/maestroi/Fleetguard/issues/22) for the future **separately approved** strict-enforcement mode.
