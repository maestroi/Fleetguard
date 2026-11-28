# Security gates

A capability may be described as production-ready only when every applicable
gate below is satisfied **with recorded evidence** (test name, lab log or PR).
"Code exists" is not evidence.

| Gate | Applies to | Status | Evidence |
|---|---|---|---|
| G1 Local protection authoritative: controller cannot remove/override protected networks, management interfaces, controller IPs | all enforcement | rootless unit only | `internal/safety`, `TestFleetListNeverRemovesLocalProtection` |
| G2 Observe-only default; remote config cannot elevate to enforce/strict | all | rootless unit | config validation tests; enforce needs root-owned config + lab ack |
| G3 Signed, bounded policies: signature, signer, audience, group, node, revision, expiry, skew, scope, size, count | snapshots, never-ban | rootless unit + fuzz (never-ban) | `pkg/protocol` tests |
| G4 Replay/rollback safe across restarts | snapshots, never-ban | rootless unit | persisted watermark tests |
| G5 Independent expiry: bans lapse with controller down, agent crashed, **hung**, firewalld reload, restart, key change | enforcement | **NOT MET**: mechanism in draft #49 (watchdog + ExecStopPost cleanup), lab run pending | #47, docs/watchdog.md |
| G6 Spoofable evidence never auto-blocks legitimate traffic | correlation, local responder | design + unit | `AddLocal` proof-level gate; correlation observe-only |
| G7 Firewall ownership: only Fleetguard objects touched | firewalld backend | rootless unit | lab confirmation pending (#11) |
| G8 Unsupported packet paths reported, never claimed (Docker FORWARD, IPv6, Tailscale) | enforcement, strict | **NOT MET** | #12 |
| G9 Fleet never-ban: add-only, separate anchor, stale ⇒ no new bans | never-ban | rootless unit + e2e | #46; lab pending |
| G10 No management lockout in safety tests | enforcement | **NOT MET** (no lab run recorded) | #11 |

## Current verdict
Enforcement is **not production-ready**: G5, G8 and G10 are unmet. Real
firewalld enforcement stays behind the disposable-VM lab opt-in
(`lab_confirm`).
