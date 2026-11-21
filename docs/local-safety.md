# Local host safety and offline emergency disable (issue #7)

**No real firewall enforcement ships in this release.** The protocol, controller and current agent are still observe-only. This change adds the independent local authorization boundary and a persistent emergency latch for future firewalld support. Do not use it as a replacement for existing firewalld/Tailscale policy. The backend in issue #8 and agent reconciler in issue #9 must integrate these gates before any live blocks.

## Root-managed policy

Copy `examples/safety-policy.json` to `/etc/fleetguard/safety.json`, substitute real management IPs and local interfaces, and create it root-owned with mode `0600` in a root-owned, non-writable-to-other-users directory. The example uses documentation-only IPs.

```sh
sudo install -d -o root -g root -m 0700 /etc/fleetguard /run/fleetguard
sudo install -o root -g root -m 0600 examples/safety-policy.json /etc/fleetguard/safety.json
fleetguardctl check-safety -config /etc/fleetguard/safety.json
```

The privileged loader rejects symbolic links, writable or non-root-owned ancestor directories, and group/world-readable policy files. `check-safety` is a **syntax-only** operator check; it intentionally works without root for test fixtures and cannot enable enforcement.

A valid local policy specifies explicit source exclusions (IPv4 and IPv6), controller IPs, management interfaces (e.g. `tailscale0`), service-group/service/protocol/port scopes, a decision-count cap and maximum remaining TTL. Allowed services are **not** broad firewall allow rules: the policy authorizes only whether a signed drop proposal may proceed to backend verification.

The safety gate verifies a signed snapshot's signature, revision, audience and timestamps before local authorization, then rejects the *entire* snapshot on any protected source overlap, non-host prefix, excessive TTL/entry count, unlisted destination port, unavailable management interface or unknown backend. An accepted snapshot is **not** proof of kernel enforcement. The adapter must prove actual INPUT rule ordering and supported backend version separately; Docker/FORWARD and untested packet paths remain unsupported. No remote field can edit this file.

**Conservative defaults:** `mode: observe` never enforces. To test local policy matching without a real backend, use unit tests. Setting `mode: enforce` in this file **does not** activate the current simulated agent or controller. The real firewalld adapter must be installed, verified and explicitly wired first.

## Offline disable and recovery

```sh
sudo fleetguardctl emergency-disable -state-dir /run/fleetguard
```

The command needs no controller or network. It creates an on-disk root-owned `/run/fleetguard/emergency-disabled` latch, refuses unsafe paths, and is idempotent. The future agent must refuse new enforcement whenever the latch exists (or its state cannot be checked). It must also remove **only** adapter-owned runtime objects through `Backend.RemoveOwned` — never reload firewalld, flush system-wide tables, or edit permanent/foreign rules. The mock backend has an offline unit test proving only its own entries are removed. **At present there is no live backend to remove**, and the CLI reports that limitation instead of asserting firewall cleanup.

For an actual lockout, access the disposable VM through Proxmox/provider console; stop the agent service, check the emergency marker, inspect firewalld ownership and rule ordering, then remove only confirmed Fleetguard-owned runtime objects. Do not rely on remote SSH/Tailscale as the sole recovery path. Confirm Tailscale access and controller reachability from independent hosts *before* and *after* the first firewalld VM test; a matching allow rule in one nftables chain may not override a drop in another.

The marker is deliberately **not** automatically removed on restart. Only a local operator should remove it after investigating the cause and checking backend health. `/run` is often tmpfs and does not persist across reboot: systemd integration in #9 must use persistent agent state (e.g. `/var/lib/fleetguard`) or explicitly propagate this latch so emergency disable survives reboot. Do not opt into enforcement until that is implemented and tested.

## Remaining gates for live enforcement

- Issue #8: a separate D-Bus adapter now implements runtime owned-state cleanup with strict capability/zone checks. **Real INPUT packet-path attestation and VM integration tests remain pending**; see [the backend guide](firewalld-backend.md).
- Issue #9: connect the signed snapshot validator and persistent emergency latch to polling, apply state and offline/TTL reconciliation.
- Issue #11: test management/Tailscale connectivity, malicious signed policy and offline recovery on isolated disposable VMs. No production/Proxmox-host deployment.
