# Firewalld D-Bus adapter — isolated-VM prototype (issue #8)

**Not production-ready. Do not point at a validator, Proxmox host, or any critical machine.** The current `fleetguard-agent` remains observe-only. This package is a library with a real system D-Bus client and a fully mocked/rootless test suite, **not** an enabled agent. The agent transport, durable signed state, expiry daemon, and locally latched emergency integration are issue #9.

## Why pre-provision IP sets?

The upstream firewalld D-Bus runtime API exposes `org.fedoraproject.FirewallD1.ipset.addEntry/removeEntry/getEntries`, but **creating an IP set is a permanent-configuration operation** (`org.fedoraproject.FirewallD1.config.addIPSet`). The adapter deliberately never calls that permanent method, never invokes `firewall-cmd`, reloads firewalld, or installs direct/iptables/nftables commands. A *local operator* may provision one labeled empty `hash:ip` set per enabled service/protocol/port before running disposable-VM tests.

Each set is named `fg1_<first 16 hex digits of SHA256(zone + NUL + node + NUL + group + NUL + service + NUL + transport + NUL + decimal port)>`; description must equal `Fleetguard runtime entries v1 <set name>`. The set MUST have `hash:ip`, `family=inet`, **no timeout** and an initially empty entries list. Runtime entries can then be reconciled and enumerated for verification. A timeout-enabled kernel set is explicitly refused because firewalld's D-Bus API cannot enumerate its timed entries.

```sh
# All commands below are for an isolated disposable VM only.
# Use scripts/plan-firewalld-set.py or inspect the SetName/SetDescription helpers to
# calculate the exact name for your chosen zone/group/service/transport/port.
# Example conceptual parameters:
#   zone=public node=lab-a group=rpc service=web transport=tcp port=8899
#
# Operator: provision /etc/firewalld/ipsets/<derived-name>.xml with
# type=hash:ip, option family=inet, the EXACT generated description and
# no entries. Then reload firewalld during a scheduled local setup window.
# The Fleetguard adapter itself never executes these operations.
```

Generate a proposed set definition locally (prints to stdout; no host changes):

```sh
python3 scripts/plan-firewalld-set.py --zone public --node lab-a \\
  --group rpc --service web --protocol tcp --port 8899
```

Copy the emitted XML into a root-managed `/etc/firewalld/ipsets/<set-name>.xml` on the disposable VM, and perform a one-time operator-controlled firewalld reload. This manual provisioning is not part of the Fleetguard agent's runtime operations.

After provisioning, verify it with `firewall-cmd --info-ipset=<derived-name>` (operator diagnostics only), then run the adapter read-only `Capabilities` check. The adapter doesn't mutate permanent sets; `RemoveOwned` clears their **runtime entries** and the exact generated runtime rich rules without removing the set definitions.

## Safety gates

The `New` constructor requires local `safety.Policy`, a node/service-group audience, one explicit runtime INPUT zone, a small list of explicit locally permitted bindings, and an injected D-Bus client. It does not accept controller-provided rule strings or set names. The `HostINPUTVerified` bit is a **local manual attestation**, never a remote field and never derived just from a successful D-Bus method response. It must remain false until the specific VM's packet-path test below succeeds.

Before every write, including removal, `probe` verifies:
- firewalld state RUNNING, compatible version 2.x, `FirewallBackend=nftables`, IPv4 + `hash:ip` support.
- exactly one active zone with interface bindings and no source-based zone overrides. Docker FORWARD, DNAT and alternative zones are explicitly unsupported.
- every expected set exists with the deterministic name, exact ownership description, `hash:ip`, `family=inet`, no timeout.
- local mode `enforce` and strict local safety authorization for every live decision before applying bans. Expired decisions are skipped; all unknown/protected/wide source prefixes, unauthorized services/ports and excessive counts/TTLs fail.
- no global source drop, no permanent changes, no mutation of non-Fleetguard rich rules.

The generated rich rule is:
```
rule priority="-100" family="ipv4" source ipset="<derived-name>" port port="8899" protocol="tcp" drop
```

The negative priority runs before ordinary firewalld primitives within the selected zone. **This does not prove INPUT or other-chain order, and is not a substitute for packet captures/counters or management-path tests.** Multiple active zones and source-based zone mappings are refused for this narrow prototype, not silently treated as protected.

## Reconciliation and failure behavior

`Reconcile` groups decision IPv4 hosts by bound port/protocol set, reads live runtime rules and entries, diffs only those sets, applies minimal D-Bus writes, then re-reads everything. A second equivalent reconcile produces **zero mutation calls** in the mock tests. Partial D-Bus failures return an error; they never claim desired rules were fully applied. `Inspect` queries live entries/rules; after a process restart it refuses to invent decision IDs, signatures or expiration metadata from unknown existing entries. A subsequent fully authorized `Reconcile` can safely replace stale entries.

`RemoveOwned` removes all entries from exactly the fingerprinted named sets and their exact rules, leaving foreign zones, rules, other sets and permanent objects untouched; it requires no controller connectivity. This method must be wired to issue #7's local emergency latch by the privileged agent in issue #9.

**Expiry limitation:** IP-set entries have no kernel timeouts for inspectability. If a future agent is killed without cleanup, they may remain until the next reconcile or local recovery. Thus no live enforcement may be enabled until issue #9 implements persistent signed state, a short reconcile/expiry loop, crash/restart recovery, and an out-of-band cleanup test.

## Disposable VM integration checklist (manual, pending)

Use 4 isolated Proxmox VMs with host console/snapshots; no production networks. Record `firewall-cmd --version`, `firewall-cmd --get-active-zones`, `firewall-cmd --get-backend` (or firewalld.conf), `nft --version`, kernel and Docker versions. First test observe-only, then explicitly authorize INPUT with locally verified policy.

1. Pre-provision two empty labeled sets, ensure exact descriptions and only the intended zone is active; assert `Capabilities` reports `ForwardedTraffic=false`.
2. Send known lab source traffic to one authorized local TCP port. Reconcile one short signed/locally authorized /32 decision via the future agent harness. Confirm packet counters/pcap show this source blocked **only on that port**, while other source and an unrelated port still work.
3. Verify independent management/Tailscale access (SSH/jump host/controller paths) before and during a short-lived ban. Force an attempted protected-IP and /24 block; no traffic may be disrupted.
4. Repeat with 100 decisions, then 10,000 *proposed* decisions. The latter must be refused by the v1 snapshot limit of 256 before any writes; do not silently lift the cap to satisfy a benchmark.
5. Partition the controller, restart firewalld, restart the agent and exercise the emergency command. Verify only owned runtime state is removed and unexpired authorized decisions return only after valid signed state is recovered.
6. Repeat with iptables backend, absent sets, source-based zone mapping, extra active zone and Docker-published forwarding; each must refuse to claim support, with no new D-Bus writes. Document exact tested firewalld/nftables packet-path behavior.

A build-tagged destructive integration harness performs live, single-set D-Bus
reconcile/inspect/owned cleanup and checks that unrelated rich rules remain
unchanged. It is **not** run by ordinary CI. To run it after local policy,
pre-provisioned set and console recovery are verified on a disposable VM:

```sh
sudo env FLEETGUARD_LAB_CONFIRM=disposable-vm-console-ready \\
  FLEETGUARD_TEST_POLICY=/etc/fleetguard/safety.json \\
  FLEETGUARD_TEST_ZONE=public FLEETGUARD_TEST_NODE=lab-a \\
  FLEETGUARD_TEST_GROUP=rpc FLEETGUARD_TEST_SERVICE=web \\
  FLEETGUARD_TEST_SOURCE=192.0.2.42/32 FLEETGUARD_TEST_PORT=8899 \\
  go test -tags=firewalld_integration -run '^TestDisposableVMReconcile ./internal/firewall/firewalld -run '^$' -bench BenchmarkReconcile -benchmem`. These are **mock D-Bus call-plan/validation** timings, not kernel or bus throughput numbers. 10,000 is a deliberate early rejection measurement. Real D-Bus latency and the four-VM packet-path tests are outstanding acceptance gates for #8/#11.

## References
- [Upstream firewalld D-Bus API](https://firewalld.org/documentation/man-pages/firewalld.dbus)
- [Rich rule ordering](https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html)
- [Local safety and emergency recovery](local-safety.md)
- [Firewalld ADR](adr/0001-firewalld-first.md)
 -count=1 -v ./internal/firewall/firewalld
```

Replace documentation addresses and service names with the isolated VM's
approved source/port and configured locally protected policy; also prove with
external traffic captures that **only** that host INPUT port drops. The harness
must not be mistaken for the broader four-VM packet-path acceptance test.

Rootless benchmarks: `go test ./internal/firewall/firewalld -run '^$' -bench BenchmarkReconcile -benchmem`.

Measured on GitHub Actions Ubuntu 24.04 using Go 1.27, `-benchtime=20x -benchmem`
([CI run](https://github.com/maestroi/Fleetguard/actions/runs/44941481884)):

| Mock D-Bus scenario | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| 1 decision | 21,554 | 5,282 | 126 |
| 100 decisions | 190,834 | 86,875 | 1,034 |
| 10,000 proposed decisions | 95.10 | 16 | 1 |

The 10,000 case **does no firewall mutation**: it is an early size-cap
rejection benchmark. Timings are illustrative, not firewalld/kernel throughput. These are **mock D-Bus call-plan/validation** timings, not kernel or bus throughput numbers. 10,000 is a deliberate early rejection measurement. Real D-Bus latency and the four-VM packet-path tests are outstanding acceptance gates for #8/#11.

## References
- [Upstream firewalld D-Bus API](https://firewalld.org/documentation/man-pages/firewalld.dbus)
- [Rich rule ordering](https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html)
- [Local safety and emergency recovery](local-safety.md)
- [Firewalld ADR](adr/0001-firewalld-first.md)
