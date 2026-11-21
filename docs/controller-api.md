# Controller API: authenticated, observe-only lab service (issue #5)

**Experimental**. This is an opt-in HTTPS **control-plane transport** for lab nodes. It authenticates and stores bounded evidence, provides **empty** signed desired-state snapshots, and records *client-reported* acknowledgement states. It neither correlates events into bans (#6) nor validates a host's protected paths (#7), nor manages a firewall (#8–#9). Do **not** expose it to the public internet or deploy it on production validators.

## Safety and trust model

- Existing `fleetguard-controller -config examples/controller.json` remains a no-network, one-shot bootstrap. The HTTPS server starts **only** with `-serve -config /absolute/path/server.json`.
- Only explicit loopback/private IPs and Tailscale CGNAT (`100.64.0.0/10`) are accepted as bind addresses. Wildcard, hostname and public binds are rejected. HTTPS uses TLS 1.3 or later. **Tailscale is not authentication**; restrict its ACLs independently.
- The operator keeps the local JSON registry (`chmod 600`) with a distinct SHA-256 digest for each independently generated, high-entropy bearer token. The plaintext token is not stored by Fleetguard. Credentials are bound to an exact `X-Fleetguard-Node-ID` and **cannot** be changed over HTTP.
- Registry owns group membership and allowed service names. `node_id` and `service` inside evidence are untrusted claims and must match their independently authenticated identity/scope. A removed/revoked node cannot submit evidence, retrieve snapshots, or acknowledge policy. Edit the registry and `kill -HUP <controller-pid>` to reload and audit changes (or restart).
- The controller's private Ed25519 signer stays on the controller host as a mode `0600` file. Public verification key provisioning and agent replay persistence remain future work (#9). HTTP TLS is not a replacement for policy signatures.
- Every snapshot is **complete, node-specific and empty**, with a finite 2-minute TTL. Its revision is monotonic in SQLite per node/group; retry before expiry returns the same exact signed envelope. No event ever causes a drop decision in this release.
- No administrative API, arbitrary shell command, dynamic firewall capability, unsigned policy promotion, or live enforcement exists. Acknowledgement states are **client reports**, not proof that firewalld applied a rule.

## Build and private lab setup

Requirements: Go 1.27+, C toolchain and `libsqlite3-dev` (Ubuntu: `sudo apt-get install libsqlite3-dev`). The controller links to the system SQLite C library. Agent and CLI remain pure Go. Linux AMD64 is the supported bootstrap platform.

```sh
make check && make build
LAB="$HOME/.local/share/fleetguard-lab"
mkdir -p "$LAB" && chmod 700 "$LAB"
./dist/fleetguardctl generate-signing-key -private "$LAB/signing.key" -public "$LAB/signing.pub"
# Local, short-lived TLS certificate for loopback testing ONLY.
openssl req -x509 -newkey ed25519 -nodes -days 7 \
  -keyout "$LAB/tls.key" -out "$LAB/tls.crt" \
  -subj '/CN=fleetguard-lab' -addext 'subjectAltName=IP:127.0.0.1'
chmod 600 "$LAB/tls.key"
# Never reuse a token across nodes. The random token is NOT checked into Git.
TOKEN="$(openssl rand -hex 32)"
printf '%s' "$TOKEN" | ./dist/fleetguardctl hash-token
# Paste the hash (not $TOKEN) into one node entry in a copy of registry.example.json.
```

Copy `examples/controller-server/server.example.json` and `registry.example.json` to `$LAB/server.json` / `$LAB/registry.json`; substitute all `/replace/...` paths in the server config with absolute `$LAB` paths and the displayed hash into the registry. Set registry permissions `chmod 600 "$LAB/registry.json"`. No example contains a real token, key, or production IP. Note: shell history, environment variables and `curl -H` arguments can leak tokens; use a local secret manager or protected client configuration for any longer-lived test.

Run (no root required):

```sh
./dist/fleetguard-controller -serve -config "$LAB/server.json"
```

The service listens only on the explicitly configured private address (the example is `127.0.0.1:9443`). No listener is opened by the ordinary simulator. To test using curl, pin the lab cert with `--cacert "$LAB/tls.crt"`, and send headers `X-Fleetguard-Node-ID: lab-node-a` and `Authorization: Bearer <your-generated-token>` with the selected `group=lab-ssh` query parameter. Do not disable TLS verification using `-k`.

## API contract

All endpoints require a verified TLS connection and a valid, non-revoked node credential. `Content-Type: application/json` is mandatory for POST. No endpoint allows remote configuration or credentials changes.

| Method | Path | Body / response | Restriction |
|---|---|---|---|
| `GET` | `/v1/health` | `{ "status":"ok", "mode":"observe", "enforcement_enabled":false }` | Authenticated only |
| `POST` | `/v1/evidence?group=lab-ssh` | One strict `protocol.Evidence` JSON → `{ "accepted":true, "duplicate":false }` | Authenticated node identity, registry group, service scope, freshness and dedup |
| `GET` | `/v1/snapshot?group=lab-ssh` | `protocol.SignedSnapshot` envelope with `payload_b64`, `signature_b64` | Unique signed empty snapshot for **this** node and group |
| `POST` | `/v1/ack?group=lab-ssh` | Strict `protocol.Acknowledgement` JSON → `accepted/duplicate` | Must reference latest published revision for this node/group |

The response includes `Cache-Control: no-store`. Policy responses also include `X-Fleetguard-Revision`. Errors carry a machine-readable `error` code. Critical distinctions: `401` unknown/mismatched/revoked identity, `403` unauthorized group/service, `409` conflicting dedup key or unknown revision, `413` too large, `422` invalid protocol payload, `429` rate/capacity reached, `503` full queue or storage failure.

Limits: 256 nodes, 32 groups, 16 groups per node, 32 services per group; evidence max 16 KiB, per-node 32 evidence requests per second, in-process write queue 64, max 4,096 stored events per node with 24-hour age pruning. SQLite writes and audits are transactions. `node_id/event_id` and `node_id/dedup_key` uniqueness persist across restarts; a conflicting retried payload returns `409` instead of silently replacing evidence. Read and write timeouts and header size bounds protect the HTTP server. Client-reported applied acknowledgements **do not prove** actual firewall state.

For a local integration test without creating a certificate or root permissions:

```sh
go test -race ./internal/controller/...
```

The test suite uses ephemeral `httptest.NewTLSServer` (loopback), temporary mode-0600 files and an injected clock. Tests verify wrong/revoked identities, cross-node impersonation, unapproved services, token rotation/reload, malformed JSON, duplicate acknowledgements and evidence, replay-stable revisions and restart recovery. No Proxmox, firewalld, Tailscale, privilege escalation or real firewall writes are required.
