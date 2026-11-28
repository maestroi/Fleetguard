# Implementation status

Last reconciled: 2026-11-28 against `main` @ d8fccb4 and GitHub issues.
"Merged" means code is on `main` with rootless tests. It does **not** mean the
issue's acceptance criteria are verified. As of this date **no issue has any
acceptance checkbox ticked**, and no privileged lab validation has been
recorded for enforcement paths. Issues therefore stay open.

| Issue | Pri | Title | Depends on | State | PRs | Tests | Known limitations / remaining |
|---|---|---|---|---|---|---|---|
| #7 | P0 | Local safety: protected paths, scopes, emergency disable | – | merged, unverified | #31 | unit | lab verification of lockout protection |
| #8 | P0 | firewalld D-Bus backend, owned sets/rules | #7 | merged, unverified | #32 | unit, opt-in integration tag | real D-Bus lab run; per-call D-Bus deadlines (#47) |
| #9 | P0 | Agent signed reconcile, TTL, offline recovery | #7 #8 | merged, unverified | #33 | unit | hung-agent expiry gap → #47 |
| #10 | P1 | Bounded denied-traffic sensor | – | merged, unverified | #34 | unit, bench | lab journal volume |
| #11 | P0 | Four-VM homelab E2E | #7–#10 | partial (lab approval path) | #40 | – | needs disposable VMs; no packet evidence recorded in repo yet beyond #40 notes |
| #12 | P1 | Docker/Tailscale/blockchain packet paths | #11 | not started | – | – | privileged lab required |
| #13 | P1 | Local high-confidence responder | #9 | engine `AddLocal` hook only | #33 | unit | adapters, rate limits, opt-in config |
| #14 | P1 | Operator CLI, health, audit metrics | – | merged, unverified | #37 | unit | – |
| #15 | P1 | Tailscale deployment, credential rotation | – | not started | – | – | enrollment, key rotation |
| #16 | P0 (raised from P2) | Scale test 1,000+ nodes | – | not started | – | – | see PERFORMANCE_RESULTS.md |
| #17 | epic | Homelab POC | – | tracking | – | – | – |
| #21 | P1 | Exposure profiles, audit-only drift | – | merged (audit-only base) | #36 | unit | continuous daemon integration, events |
| #22 | P2 | Strict exposure mode | #21 #12 | not started | – | – | – |
| #41 | P0 | Fleet never-ban set | #7 #9 | merged; lab criterion open | #46 | unit, e2e HTTPS, property, fuzz | lab: peer-IP ban rejected fleet-wide on real firewalld; controller signer rotation workflow |
| #42 | P1 | Chain/client exposure profiles | #21 | owner WIP (uncommitted, not touched) | – | – | upstream port verification |
| #43 | P1 | Fleet port-scan detection | #10 | correlation base merged | #27 | unit | trust domains, rollout stages |
| #44 | P0 | Manual fleet-wide incident ban | #41 | not started | – | – | bulk protocol design (≥5,000 entries) |
| #45 | epic | Proactive fleet defense | – | tracking | – | – | – |
| #47 | P0 | Watchdog + independent TTL recovery | #9 | code complete in draft PR #49; lab pending | #49 | unit (hung backend, ping logic, sd_notify) | lab fault-injection run; firewalld fully wedged is uncovered; ~1–2 s gap after crash |

## #41 detail (2026-11-28)
Acceptance:
- [x] Signed allowlist with revision, expiry, audit; agents verify it independently.
- [x] Removing a fleet entry never removes a local protection (unit: `TestFleetListNeverRemovesLocalProtection`). Lab part open.
- [x] Ban on a protected IP rejected on controller (publication gate, `protected_source`, audited) and agent (`protected_source`, metric). The controller lab path is a one-shot CLI, so it audits rather than exporting a metric.
- [x] CLI list/add/diff/renew, bulk file, dry-run; audited who/when/why (local UID).
- [x] Grafana: revision per agent, rejected bans by category.
- [ ] Lab: peer IP ban rejected fleet-wide (needs #11 lab).
