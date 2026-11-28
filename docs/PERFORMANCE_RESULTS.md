# Performance results

Only measured numbers with hardware and command. No extrapolation to fleet
scale. Targets (not achieved) are listed separately.

## Targets (from mission; unverified)
≥1,000 polling agents; fleet-ban convergence P95 ≤5s, P99 ≤10s; 5,000-entry
bulk operations; 10,000 active decisions per group; idle agent RSS <30 MB and
CPU <1% of a core; bounded resources under overload; zero lockouts.

## Measurements

| Date | What | Result | Command | Hardware |
|---|---|---|---|---|
| 2026-11-28 | `ProtectionIndex.Overlaps`, 4,096 /24 protections, miss | ~45–51 ns/op | `go test -run '^$' -bench ProtectionIndex ./pkg/protocol` | dev workstation, 32 logical CPUs, Go 1.27.0, linux/amd64 (shared, not isolated) |

Existing CI benchmarks (`BenchmarkReconcile`, `BenchmarkCardinalityCapped`)
run with tiny `-benchtime` as smoke checks; their numbers are not recorded as
results.

## Not yet measured
Everything in #16: multi-agent controller load, SQLite contention, signature
cost at fleet scale, convergence latency, firewalld reconcile at
1/100/1k/5k/10k entries.
