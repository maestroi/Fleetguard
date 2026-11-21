# Security policy

Fleetguard is **experimental and not production-ready**. The bootstrap currently has no network listeners or firewall enforcement. Do not deploy it to protect production infrastructure.

## Report a vulnerability privately

**Do not create a public issue, discussion, or pull request for an undisclosed vulnerability.**

Use [GitHub's private vulnerability reporting](https://github.com/maestroi/Fleetguard/security/advisories/new) if the repository has that feature enabled. If the link is unavailable, contact the maintainer through an existing private channel first and request a secure way to share details. Do not send exploit payloads or secrets through public GitHub issues.

**Maintainer setup required:** enable *Private vulnerability reporting* under the repository's Settings → Code security and analysis. A public `SECURITY.md` alone does not turn this feature on.

Please include the affected commit/version, impact, minimal reproduction on disposable test systems, and proposed mitigations. Avoid using real-world targets or private infrastructure data.

No response or remediation SLA is promised at this early stage. We will coordinate disclosure with reporters before publishing technical details.

## Supported versions

There are no supported production releases. Only the current development branch receives security fixes on a best-effort basis.
