# Optional firewalld denied-traffic sensor (issue #10)

**Status: opt-in, observe-only telemetry. No firewall changes and no automatic bans.** Configure this only on a test agent whose existing firewalld and journal already expose denied kernel packet logs. The normal one-shot `fleetguard-agent -config examples/agent.json` remains fully inert.

## Data source and privileges

The optional collector uses one bounded child process, with fixed arguments:

```sh
journalctl --quiet --no-pager --follow --lines=0 --output=cat _TRANSPORT=kernel
```

It follows kernel journal messages only; *not* `journalctl -u firewalld` service messages and not historical boot logs. It never invokes `firewall-cmd`, `nft`, root-only packet export, arbitrary shell commands, or automatically enables `LogDenied`. It has no inbound listener. The existing host should explicitly configure any firewall logging and **apply a kernel/iptables/nftables rate limit** before enabling the collector; source-side rate limiting is essential because user-space sampling cannot prevent log floods.

If `LogDenied=off` (often the default) or journal access is denied, the sensor produces no events, records optional-reader restart failures, and does not affect controller polling, expiry or firewall reconciliation. Grant only read access to the kernel journal as appropriate to the guest OS, not full root privileges solely for telemetry.

The parser recognizes only `FINAL_REJECT:`, `FINAL_DROP:`, and `filter_IN_<zone>_REJECT/DROP:` log prefixes with a host `IN=` interface, empty `OUT=`, IPv4 `SRC`/`DST`, TCP/UDP and canonical destination port. It rejects ambiguous or malformed messages, IPv6 (unsupported by this sensor), other programs' log prefixes, forwarded/Docker traffic and packets on unmapped ports. It handles optional kernel fields and repeated UDP length metadata. **No general internet reachability claim is made.**

## Configuration

Put this in the *opt-in* `fleetguard-agent -run -runtime-config /absolute/agent-runtime.json` config, or use [the explicitly enabled sensor example](../examples/agent-runtime.sensor.json). The standard [observe example](../examples/agent-runtime.observe.json) leaves the sensor disabled:

```json
"denied_traffic": {
  "enabled": true,
  "window_seconds": 10,
  "max_sources": 256,
  "max_packets_per_window": 5000,
  "max_reports_per_window": 32,
  "bindings": [
    { "service": "ssh", "transport": "tcp", "port": 2222 },
    { "service": "solana-rpc", "transport": "tcp", "port": 8899 }
  ]
}
```

`denied_traffic` is **absent by default**, which disables journal access. To disable an existing configuration, remove the field entirely. Bindings are an explicit local mapping from a protocol/port to a service already allowed by the controller's node/group registry; no blanket catchall services, protocol inference, port scanning or inferred application identity. This mapping is observational, not a firewall allowlist or ban scope.

Bounds: `window_seconds` 1–60; `max_sources` 1–2048 (source/service/protocol buckets); `max_packets_per_window` 1–100,000; `max_reports_per_window` 1–128; at most 64 bindings; at most 32 distinct ports per summary. One bounded 64-entry outgoing evidence queue and an independent HTTPS sender rate-limited to 8 requests/second. Saturation causes visible drops rather than unbounded growth or blocking agent safety checks. Journal input lines longer than 2048 bytes are drained and counted, not retained.

`fleetguard-agent` JSON status includes `denied_traffic` counters such as `parsed`, `malformed`, `ignored`, `oversized`, `unmapped`, `dropped_packets`, `dropped_sources`, `dropped_reports`, `queue_dropped`, `submit_failed`, `journal_failures` and `active_sources`; it prints a sensor status snapshot at least every ~10 seconds while enabled. No raw log lines or packet payloads are persisted.

## Evidence provenance and security

All emitted events have `proof_level: unverified_network_log`, `observation: firewalld_denied_packets`, locally authenticated `node_id` and bounded `attempts`, `window_seconds` and sorted unique `destination_ports`. They use a random process-specific ID prefix and a monotonic counter for deduplication. The packet `SRC` and `DST` values are untrusted kernel-reported fields; in particular, denied SYNs and UDP packets can have **spoofed sources**. Even repeated hits or several servers observing them **do not prove independent, established attackers**.

This sensor never invokes `Engine.AddLocal`; the controller's current correlation policy requires independently trustworthy evidence and explicitly disallows promoting these log-only observations into fleet-wide drops. Lost uploads are counted and discarded, not replayed after controller recovery. The attacker-controlled source IP is not used to construct file paths, commands, logging text, credentials or host configuration.

## Test and next steps

```sh
go test -race ./internal/sensor/firewalld ./internal/agent
go test -run '^$' -bench '^BenchmarkCardinalityCapped$' -benchtime=2x -benchmem ./internal/sensor/firewalld
```

CI validates valid TCP/UDP/zone prefixes, forwarded and unrelated logs, malformed and oversized entries, bounded cardinality, per-source aggregation, local config rejection, proper unverified proof label, and authenticated HTTPS evidence submission. Benchmarks are rootless synthetic parser/aggregation measurements, **not** real journal performance.

Issue #11 must test real journal access and actual firewalld logging under deliberately rate-limited conditions on a disposable isolated VM, capture CPU/RSS, verify errors/counters, and separately validate packet-path enforcement with management access protected. See upstream [firewalld LogDenied configuration](https://firewalld.org/documentation/man-pages/firewalld.conf).
