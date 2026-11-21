# Minimal-permission controller container

**Experimental / observe-only.** This Compose deployment runs only the HTTPS
**controller**. It does not monitor host packets, perform correlation on live
requests, apply firewall rules, or run a privileged agent. The agent's future
firewalld D-Bus integration belongs on a host or in a separately designed
sandbox; **do not** add `privileged`, `NET_ADMIN`, `network_mode: host`,
`/var/run/docker.sock`, host D-Bus or host firewall mounts to this deployment.

## Prepare the private lab directory

Requirements: Docker Engine with Compose v2, OpenSSL and a `fleetguardctl`
Linux AMD64 binary from the matching [GitHub Release](https://github.com/maestroi/Fleetguard/releases)
(or built locally). On a system with another subnet using `172.30.240.0/24`,
choose a free RFC1918 /24 in `.env` **and** update the private `server.json`
`listen` address to match the selected static container IP.

From this directory (`deploy/controller`):

```sh
cp .env.example .env
# Set FLEETGUARD_TAG to a published v0.1.N release, not a floating tag.
mkdir -p private state
chmod 700 private state
cp server.example.json private/server.json
cp registry.example.json private/registry.json

# Invoke the matching fleetguardctl executable (from the release archive):
/path/to/fleetguardctl generate-signing-key \
  -private private/signing.key -public private/signing.pub

# Example cert: ONLY for local 127.0.0.1 test traffic.
openssl req -x509 -newkey ed25519 -nodes -days 7 \
  -keyout private/tls.key -out private/tls.crt \
  -subj '/CN=fleetguard-lab' -addext 'subjectAltName=IP:127.0.0.1'

# Each node must have a unique high-entropy bearer token. Never commit it.
TOKEN="$(openssl rand -hex 32)"
printf '%s' "$TOKEN" | /path/to/fleetguardctl hash-token
# Copy the resulting hash into private/registry.json token_sha256.
# Transfer the plaintext token securely to that lab agent, then clear it.
unset TOKEN

chmod 600 private/server.json private/registry.json private/signing.key private/tls.key
# The container never starts as root. Prepare host bind mounts for UID 65532.
sudo chown -R 65532:65532 private state
sudo chmod 700 private state

docker compose config --quiet
docker compose pull
docker compose up -d
```

The private server JSON uses **container** paths, not host paths. If you change
any of the Compose network variables, keep `private/server.json` in sync. The
SQLite parent directory must be owned by the container UID and must have mode
`0700`. Credential files (`registry.json`, `signing.key`, `tls.key`) must be
regular files inaccessible to group/other (`0600`). Host root is able to manage
these files even when a normal user cannot. Docker Desktop / rootless Docker
may need different ownership mapping; inspect UID mappings rather than granting
world read access.

Verify that the server is reachable only from the Docker **host's** loopback
address, using your trusted local cert (no `curl -k`). For example, use a
non-revoked node token and its exact node ID:

```sh
curl --cacert private/tls.crt \
  -H 'X-Fleetguard-Node-ID: lab-node-a' \
  -H 'Authorization: Bearer REPLACE_WITH_NODE_TOKEN' \
  https://127.0.0.1:9443/v1/health
```

This uses the Docker host loopback, **not** a listener bound to container
loopback. To allow other private hosts, use a separately secured tailnet/private
reverse proxy with TLS verification and ACLs; do not change the Compose host
publish address to `0.0.0.0` merely for convenience. Older Docker releases
(before 28.0) may expose localhost-published ports to L2 peers: upgrade Docker
and test your host firewall/port exposure. No unauthenticated health endpoint
is added solely for Docker health checks.

## Container security envelope

| Setting | Value | Reason |
|---|---|---|
| UID/GID | `65532:65532` | Controller runs as non-root |
| Linux capabilities | **ALL dropped** | No `NET_ADMIN`, `NET_RAW`, bind-service or other caps |
| Privileges | `privileged: false`, `no-new-privileges` | No escalation |
| Network | Dedicated bridge, static private IP, loopback host publish | No host namespace or public bind |
| Filesystem | Read-only root, read-only private config, writable SQLite data only | No unrelated host filesystem access |
| Temporary files | 16 MiB `noexec,nosuid,nodev` tmpfs | Bound temporary storage |
| Resources | 256 MiB memory, 1 CPU, 64 PIDs | Prevent accidental runaway use |
| Mounts | No Docker socket, D-Bus, `/proc`/`/sys` host mounts, host firewall config | No host firewall control |

The container still has the **application privileges** granted by its private
signing key and node registry. Run it only on trusted infrastructure. It cannot
authenticate agents without valid per-node tokens and always serves
**empty, signed policies**; the offline correlation CLI is not started by the
container entrypoint.

## Updates

Select a newer tested `v0.1.N` tag in `.env`, then `docker compose pull && docker
compose up -d`. A published image tag is versioned, not `latest`; for stronger
pinning, replace the tag with the SHA256 image digest obtained from GHCR. The
SQLite state mount persists across restarts. GitHub Releases also include a
versioned Compose archive containing this file and examples, never secrets.

The first GHCR publication may be private by default: the repository owner must
make the **fleetguard-controller** GHCR package **Public** in its package
settings for unauthenticated `docker pull` by others. Publishing uses the
repository-scoped GitHub Actions token; no long-lived PAT is required.
