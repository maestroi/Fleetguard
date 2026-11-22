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
