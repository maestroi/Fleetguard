# Contributing to Fleetguard

Thanks for helping build a security-sensitive, open-source prototype. Read the [README](README.md), [security policy](SECURITY.md), and design documents (once merged) before making changes.

## Development workflow

1. Discuss substantial changes in an issue, especially anything touching enrollment, trust, detection or firewall enforcement.
2. Create a short-lived feature branch from `main` and open a focused pull request. Link the related issue and describe operational risks and rollback.
3. Install Go 1.27 or later. Run `make check`, `make build`, and `make smoke` locally. CI runs formatting, module tidy, vet, race-enabled unit tests, Linux amd64 builds, and unprivileged simulated smoke tests.
4. Keep tests deterministic and unprivileged. No test should require root, Docker, Tailscale, firewalld, a live controller, or a real network service. Put future privileged tests behind an explicit opt-in integration-test boundary.
5. Prefer stdlib and small `internal/` packages. Introduce exported `pkg/` APIs only when callers and compatibility requirements are established. Avoid external dependencies without an explanation.
6. Do not add real credentials, private addresses, customer data, or production policy. Use documentation IPs and simulated fixtures only.

## Safety and review

Observe-only is the default. A pull request must not silently introduce firewall mutations, public listeners, network access, automatic blocking or insecure fallback behavior. Changes to those boundaries need threat-model review, negative tests, rollback guidance and explicit opt-in before merge.

Use `gofmt` for formatting. Tests should exercise both successful behavior and rejection of unsafe input. Update user-facing documentation when behavior changes.

## Dependency updates and releases

Dependabot opens weekly PRs for Go modules and GitHub Actions. Review changes and the CI results before merging; do not blindly auto-merge security-sensitive dependencies. Go dependencies are currently stdlib-only. Builds use a single Go module and link metadata (`VERSION`, `COMMIT`, `BUILD_DATE`) via `make build`. `BUILD_DATE=unknown` by default to avoid non-reproducible timestamps. Signed releases and artifact provenance are separate future work.

## Reporting vulnerabilities

Follow [SECURITY.md](SECURITY.md) for private disclosure, not a public issue.
