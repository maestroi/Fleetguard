## Summary

What changed and why?

## Validation

- [ ] `make check` (gofmt, module tidy, vet, unit tests)
- [ ] `make build && make smoke` (Linux amd64, simulated mode)
- [ ] Tests and examples require no root, firewalld, Tailscale or credentials
- [ ] No secrets, private IPs, or production infrastructure details added

## Safety review

- [ ] Change is observe-only or its enforcement impact and rollback are explicitly documented
- [ ] No new privileged operations or production defaults without explicit review

Closes #
