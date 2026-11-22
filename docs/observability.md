# Observability: Prometheus metrics, alerts and Grafana (issue #35)

The agent daemon (`fleetguard-agent -run`) and the HTTPS controller (`fleetguard-controller -serve`) can each expose a read-only Prometheus `GET /metrics` endpoint. It works in observe and simulated mode. It needs no root, no firewalld and no Tailscale.

Reference files live in [`deploy/monitoring/`](../deploy/monitoring):

| File | Purpose |
|---|---|
| `prometheus.yml` | Scrape jobs for one controller and two lab agents (placeholder Tailscale IPs) |
| `alerts.yml` | 12 reference alert rules (checked with `promtool`) |
| `grafana-dashboard.json` | Dashboard: fleet overview, agent health, policy propagation, enforcement state, threat telemetry, controller ingest and errors |

## Enabling

Metrics are **off by default**. Add `metrics_listen` to the config:

```jsonc
// agent runtime config (examples/agent-runtime.observe.json)
"metrics_listen": "127.0.0.1:9464"
// controller server config (examples/controller-server/server.example.json)
"metrics_listen": "127.0.0.1:9465"
```

## Security model

- Bind addresses must be an explicit loopback, private (RFC 1918/ULA) or Tailscale CGNAT IP, using the same rule as the controller API. Wildcard, hostname and public binds are rejected at config load. The controller also rejects a `metrics_listen` equal to its API `listen`.
- The listener is a **separate** plain-HTTP server that serves only `GET /metrics`. Every other path returns 404 and other methods return 405. It has no administrative surface, takes no request input and sets no secrets in URLs. For TLS or authentication, put a private reverse proxy in front, or scrape over the tailnet with restrictive ACLs.
- Labels are fixed enums only: route patterns, HTTP codes, protocol reason codes and ack states. Source and destination IPs, node IDs, groups, decision or event IDs, tokens and error text **never** become labels. Tests assert this (`internal/agent/metrics_test.go`, `internal/controller/api/metrics_test.go`). Per-IP or per-decision attribution stays in the authenticated audit view and the operator CLI.
- A scrape reads cached in-memory state. It never triggers D-Bus or firewalld work. A failing metrics listener is logged and never stops reconcile, expiry or ingest.

## Metric contract

Unix timestamps are exported as `*_timestamp_seconds`, so compute ages in PromQL (`time() - x`). A timestamp is **absent** (rather than 0) until the event first happens.

### Agent (`fleetguard_agent_*`)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `info` | gauge | `version`, `backend`, `mode` | Always 1 |
| `controller_connected` | gauge | | 1 if a controller fetch succeeded within 3 poll intervals |
| `last_controller_contact_timestamp_seconds` | gauge | | Last successful fetch |
| `policy_revision` / `policy_applied_revision` | gauge | | Accepted vs last reconciled signed revision |
| `policy_accepted_timestamp_seconds` | gauge | | When the current revision was accepted |
| `policy_updates_total` | counter | `result=accepted\|invalid\|scope_denied` | `invalid` covers signature, replay, expiry and audience failures |
| `active_decisions` | gauge | `origin=central\|local` | **Desired** live decisions |
| `enforced_decisions` | gauge | | Decisions the backend **reported applied** on the last reconcile (readback) |
| `enforcement_healthy` | gauge | | 1 only in enforce mode, not simulated, not disabled, no last error and reconciled within 3 intervals. **Observe mode is always 0.** |
| `simulated`, `emergency_disabled`, `offline_expired`, `last_error` | gauge | | 0/1 safety flags |
| `firewall_reconcile_errors_total` | counter | | Failed reconciles |
| `last_reconcile_timestamp_seconds` | gauge | | Last successful reconcile |
| `sensor_lines_total` | counter | `result=parsed\|ignored\|malformed\|oversized\|unmapped` | Denied-traffic sensor only |
| `sensor_events_dropped_total` | counter | `reason=packet_cap\|source_cap\|port_cap\|report_cap\|queue_full\|submit_failed` | Data lost to bounds |
| `sensor_reports_emitted_total`, `sensor_journal_failures_total`, `sensor_active_sources` | | | Sensor throughput and health |

The process target being up (`up == 1`) only proves the HTTP listener answers. Check `controller_connected`, `offline_expired` and `enforcement_healthy` before concluding anything about firewall state.

### Controller (`fleetguard_controller_*`)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `info` | gauge | `version`, `mode` | Always 1 |
| `http_requests_total` | counter | `route` (mux pattern or `unmatched`), `code` | All API traffic, including 401/403 |
| `events_rejected_total` | counter | `reason` (protocol reason or fixed code) | Evidence refused after authentication |
| `agent_ack_total` | counter | `state` | **Client-reported** acknowledgements; not proof of enforcement |
| `storage_errors_total` | counter | `operation=ingest\|snapshot\|ack\|audit` | SQLite failures (pre-created at 0) |
| `ingest_queue_depth` / `ingest_queue_capacity` | gauge | | Single-writer evidence queue |
| `registered_nodes` | gauge | | Non-revoked registry nodes |
| `enforcement_enabled` | gauge | | Always 0 in this release |

Go runtime (`go_*`) and process (`process_*`) collectors are included on both endpoints.

## Verified in a local lab

On one host, with the real binaries, I ran a controller and two observe-mode agents on loopback, scraped by Prometheus v3.5 and shown in Grafana 12.1:

- All three targets scraped. All 12 rules evaluated cleanly.
- Killing the controller made both agents report `controller_connected=0` while their own `up` stayed 1. `FleetguardTargetDown` and `FleetguardAgentControllerDisconnected` went to pending.
- After restart, the agents reconnected within one backoff window (about 60s) and `offline_expired` cleared.

## Known gaps

- No reconcile-duration or policy-delivery-lag histograms yet. Use the `last_*_timestamp_seconds` gauges. An end-to-end latency metric needs trustworthy cross-host clocks.
- No controller-side "nodes seen recently" gauge (that would need a SQLite query per scrape). Use the agents' `controller_connected` instead.
- Exposure-drift metrics will come once the drift auditor runs inside the agent daemon (#21).
- `/healthz` and `/readyz` are not part of this endpoint (see #14).
- Alert thresholds are starting points and need tuning in the four-VM lab (#11).

## Four-VM Proxmox lab

### Prerequisites and deployment

| Guest on `pve05` | VM ID | Lab address | Role |
|---|---:|---|---|
| `fg-control` | 102 | `172.29.50.10` | Fleetguard API, Prometheus, Grafana |
| `fg-agent-a` | 111 | `172.29.50.11` | Observe-only agent |
| `fg-agent-b` | 112 | `172.29.50.12` | Observe-only agent |
| `fg-generator` | 113 | `172.29.50.13` | Lab traffic source |

The script upgrades an existing observe-only deployment. For fresh guests, first follow the [lab topology](homelab-poc.md), [controller setup](controller-api.md#build-and-private-lab-setup), and [agent setup](agent-reconciliation.md#rootless-observe-mode-lab-setup). Keep all four guests on the isolated `vmbr50` bridge. Start the guests with QEMU Guest Agent enabled and verify out-of-band access and baseline snapshots. Use `/opt/fg-issue11/server.json` on the controller and `/opt/fg-issue11/runtime.json` on each agent. Set the controller HTTPS address to `172.29.50.10:9443`, include that IP in the TLS certificate SAN, and use a separate credential and node identity per agent. Keep the agent backend simulated.

From the repository root on a Linux AMD64 workstation with Go, Docker, and working root SSH access to `pve05`, run:

```sh
docker pull prom/prometheus:v3.5.0
docker pull grafana/grafana:12.1.0
./deploy/monitoring/proxmox-lab.sh
```

The script builds Fleetguard from the checked-out revision, temporarily serves the install archives on the lab network, and restarts the three services. It preserves the Fleetguard database and credentials. Prometheus and Grafana run on `fg-control`, and Docker is used on the workstation to extract their pinned distributions. For an alternate SSH destination, set `FG_PROXMOX_HOST` and use the same destination in the relay command below.

### Dashboard access

To open the dashboard, run this command on your workstation and keep it running. It requires `socat` on the workstation and `nc` on `pve05`.

```sh
socat TCP-LISTEN:3300,bind=127.0.0.1,reuseaddr,fork \
  EXEC:'ssh -T -o BatchMode=yes root@192.168.50.171 ip netns exec fg-issue11 nc 172.29.50.10 3000'
```

Open <http://127.0.0.1:3300/d/fleetguard-overview/>. The dashboard has anonymous Viewer access within the isolated network. The SSH relay binds only to workstation loopback. The Proxmox access namespace has a single interface on `vmbr50` and no default route. Prometheus listens on controller loopback and scrapes the three Fleetguard targets over the lab network.


### Verify and repeat

With the relay running, query the provisioned datasource from the workstation:

```sh
curl -fsS 'http://127.0.0.1:3300/api/datasources/proxy/uid/prometheus/api/v1/query?query=up'
```

Allow at least one 15-second scrape interval. Expect three samples with value `1`, one for each Fleetguard service. Query `fleetguard_agent_controller_connected` the same way and expect two values of `1`. Both agents should be in observe mode. Zero active and enforced decisions are expected in this baseline.

After a guest or host reboot, start the four guests as needed and rerun the deployment script. It restores the service bindings and temporary IPs for the controller and agents. For generator tests, restore its address separately with `qm guest exec 113 -- ip addr replace 172.29.50.13/24 dev enp6s18` on `pve05`. Restart the workstation relay if it has exited. Use the baseline snapshots for VM recovery, then repeat the observe-only bootstrap if the restored disks predate it.

If the dashboard loads but targets are missing, check the controller's Prometheus target details with `qm guest exec 102 -- curl -fsS http://127.0.0.1:9090/api/v1/targets` on `pve05`. Check the affected guest's journal using `journalctl -u fg-issue11-agent` or `journalctl -u fg-issue11-controller`. If the dashboard itself fails to load, check `fg-issue11-grafana` on the controller and verify the local relay is still running.
