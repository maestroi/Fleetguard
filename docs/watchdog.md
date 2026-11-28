# Agent watchdog and independent TTL recovery (#47)

Runtime firewalld IP-set entries are removed only by reconciliation, so
expiry depends on a live, *working* agent. This document says what covers
each failure and what does not.

| Failure | Mechanism | Bans removed by | Verified |
|---|---|---|---|
| Controller down / partition | snapshot lease + `max_offline_age` (≤300 s) | agent reconcile | rootless unit |
| Clean stop | agent `RemoveOwned` on exit, then `ExecStopPost` | agent, then cleanup command | rootless unit (cleanup no-op path) |
| Crash / SIGKILL | `ExecStopPost` cleanup, restart re-applies still-valid signed state | `fleetguardctl cleanup-owned` | lab pending |
| Blocked D-Bus call | 15 s `ReconcileTimeout` on every backend call (godbus honours context cancellation) | next reconcile; watchdog if it persists | rootless unit (`TestReconcileTimeoutBoundsHungBackend`) |
| Hang / deadlock / SIGSTOP | `WatchdogSec=60`; `WATCHDOG=1` only after a **successful** reconcile → SIGABRT, SIGKILL after `TimeoutStopSec` | `ExecStopPost` cleanup | rootless unit (ping logic); lab pending |
| Reconcile failing repeatedly | no pings → watchdog kill → restart | `ExecStopPost` cleanup | rootless unit |
| Crash loop | `StartLimitBurst=5` / 120 s → `OnFailure` emergency latch | emergency-disable D-Bus cleanup | existing |
| firewalld wedged entirely | nothing can remove entries via firewalld | **not covered**; documented limitation | – |
| Clock jump | leases use wall-clock expiry; restored state rejects acceptance timestamps in the future | – | existing unit tests |

**Trade-off.** Because cleanup runs after *every* stop, a SIGKILL'd agent's
still-valid bans disappear for roughly `RestartSec` plus startup time (about
1–2 s) before the restarted agent re-applies them. Failing open briefly is
preferred over leaving unbounded stale bans.

**Configuration constraint.** The agent refuses to start when
`WatchdogSec < 3 × reconcile_interval_seconds + 15 s`, so transient slowness
cannot trigger kills. Watchdog health is exported as
`fleetguard_agent_watchdog_enabled` and
`fleetguard_agent_watchdog_last_ping_timestamp_seconds`.

**systemd compatibility.** Uses `Type=notify`, `NotifyAccess=main`,
`WatchdogSec`, `ExecStopPost`, `OnFailure` and `StartLimit*`, all available
since systemd 209 (EL8 ships 239). `RestartMode=direct` needs systemd 254 or
later. On older versions `OnFailure` fires on the first crash, which latches
emergency disable (fail-safe). sd_notify is implemented with the standard
library; there is no libsystemd dependency.

## Kernel-enforced expiry: investigated, not usable through firewalld

firewalld supports a set-level `timeout` option. Per
`src/firewall/core/fw_ipset.py` (main branch, read 2026-11-28), `add_entry` on
a timeout set passes the entry to the kernel but does **not** record it. As a
result:
- `getEntries` cannot read it back;
- `removeEntry` raises NOT_ENABLED, so an operator unban cannot remove it before expiry;
- duplicate and overlap checks are skipped.

That breaks readback-verified enforcement and fast unban. Writing to the
kernel set directly with nft would bypass firewalld ownership, which this
project forbids. Lab confirmation on the target firewalld versions is still
outstanding.

**Conclusion:** expiry is not *guaranteed* independent of the host. It is
guaranteed only while systemd and firewalld themselves work. Enforcement must
not be called production-ready on the basis of this mechanism alone (gate G5
stays open until the lab run below passes).

## Lab acceptance (disposable VM only)

`scripts/lab/watchdog-fault-injection.sh` installs a ban, then for each of
SIGKILL, SIGSTOP and a blocked firewalld (`SIGSTOP` to firewalld) requires
the `ExecStopPost` cleanup confirmation in the journal within
`WatchdogSec + TimeoutStopSec + 10 s`. The restarted agent legitimately
re-applies still-valid signed bans afterwards. It
refuses to run without the lab marker file and never touches non-Fleetguard
objects.
