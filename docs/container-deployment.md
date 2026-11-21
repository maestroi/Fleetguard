# Controller image and least-privilege Docker Compose

**Release artifact:** `ghcr.io/maestroi/fleetguard-controller:v0.1.N`
(replace `v0.1.N` with a published release version). A `sha-<40-character
main commit>` image tag is published for each version as well. Supported
platform for the first image: **linux/amd64**. Corresponding GitHub Releases
contain `fleetguard_v0.1.N_compose.tar.gz` and `SHA256SUMS` alongside the
Linux binary archive.

This image contains **only** the observe-only HTTPS **controller**. It is not a
firewall agent. It intentionally contains no Linux firewall or host-namespace
integration and cannot apply deny rules. `-evaluate` remains an optional,
manual, offline host operator operation and is never triggered by the container
entrypoint. The API still returns signed **empty** decisions.

## Run

Use [the Compose deployment](../deploy/controller/README.md). It contains a
self-contained guide for generating TLS keys, registering per-node tokens,
preparing private directories, and running an experimental controller with
non-root UID/GID `65532:65532`. Never add real keys or plaintext tokens to the
repository, image, Dockerfile, or Compose environment variables.

Required filesystem mounts, and **nothing else**:

- Private `server.json`, `registry.json`, TLS keypair and Ed25519 key in a
  **read-only** bind mount at `/etc/fleetguard`. Private material must be regular
  files with `0600` permissions, accessible only to UID 65532 inside the image.
- Writable SQLite state directory at `/var/lib/fleetguard`, owned by the same
  UID and mode `0700`; data persists across container restarts.

The image starts on TCP 9443 and the private bridge's explicitly assigned IP;
Docker only publishes `127.0.0.1:9443` on the host by default. The server
rejects `0.0.0.0` and all public/wildcard binds, so the Compose static private
IP must match its `listen` config. To expose the endpoint to remote lab nodes,
use a separate authenticated private proxy or Tailscale service with strict
ACLs and certificate verification. Do not publish port 9443 publicly or use
`network_mode: host`.

## Runtime permissions

| Requirement | Granted inside container |
|---|---|
| Root | No; numeric UID/GID 65532 |
| Additional Linux capabilities | **None** (all dropped) |
| Elevated privileges | No; `privileged: false`, `no-new-privileges` |
| Host network namespace | No; dedicated private bridge |
| Writable host paths | **Only** the SQLite data directory |
| Writable root filesystem | No; read-only with a small `noexec` `/tmp` tmpfs |
| Docker socket, host D-Bus, `/sys`/`/proc` host mounts | **None** |
| Required network | Only inbound private HTTPS to TCP 9443 |
| CPU/memory/process budgets | 1 CPU, 256 MiB RAM, 64 PIDs (change only with lab testing) |

No `CAP_NET_ADMIN`, `CAP_NET_RAW`, root, privileged mode, host iptables/nftables,
firewalld D-Bus, host network, container runtime socket, or rootless Docker
daemon access is required. Running the image does **not** configure Docker
firewall rules beyond Docker's own bridge/port publication; it does not manage
host firewalld. Docker itself has administrative access to its host network
configuration, so run Compose on a disposable homelab VM before expanding.

## Release publishing

On every successful `main` update, the trusted release workflow checks the
exact merged SHA, reruns CI/smoke tests, then builds the same controller source
into a versioned Docker image. A deliberately unprivileged smoke command runs
inside the image with **no network and no Linux capabilities** before GHCR
publication. No fork PR can publish an image, and the PR CI token is read-only.

The image is pushed with both the version tag and a main-commit SHA tag; the
matching GitHub prerelease contains the Compose archive and checksums. The
release workflow uses `GITHUB_TOKEN` with `packages: write` and `contents:
write`, not an external personal token. The GHCR package may initially be
private: the repository owner must change its visibility to **Public** in
GitHub Packages if anonymous downloads are desired. Use a version/sha tag or
pin an image digest rather than a floating `latest`.

The controller dynamically links to Debian's `libsqlite3-0` and the runtime
image contains its own compatible SQLite library and CA certificates, unlike
the standalone Linux binary archive, which requires SQLite on the host.

## Limits

This is a secure-by-default Compose *example*, not production certification.
The controller holds a signing private key and distinct node credentials, so a
compromised container may misuse the controller's application-level authority
even without Linux capabilities. Keep the host and Docker updated, verify
certificate SANs, run the container only in a private VLAN/tailnet, and rotate
credentials after compromise. Host-side agent enforcement will require a
separate, narrow permission design and is intentionally out of scope.
