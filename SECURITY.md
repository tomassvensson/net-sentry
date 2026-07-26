# Security Policy

## Supported Versions

Only the latest release on the `main` branch receives security fixes.

| Version | Supported |
| ------- | --------- |
| latest (`main`) | ✓ |
| older releases  | ✗ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a security vulnerability, open a
[GitHub Security Advisory](https://github.com/tomassvensson/net-sentry/security/advisories/new)
(click *"Report a vulnerability"* on the *Security* tab of the repository).

Include as much detail as possible:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept (redacted for safety if needed).
- Affected component(s) and version/commit hash.
- Any suggested mitigations you may have.

### What to expect

| Step | Timeline |
| ---- | -------- |
| Acknowledgement of your report | within 5 business days |
| Status update (confirmed / not confirmed) | within 10 business days |
| Patch release (for confirmed issues) | within 90 days, sooner if possible |

We will keep you informed of progress and credit you in the release notes
(unless you prefer to remain anonymous).

## Scope

This project runs as a **local network scanner** on a private LAN.
Nevertheless, the following classes of issues are in scope:

- Remote code execution or privilege escalation via the FastAPI service.
- SQL injection or other database-layer attacks.
- Information disclosure (e.g., device data exposed without authentication).
- Dependency vulnerabilities with a CVSS score ≥ 7.0.
- Insecure default configuration that would expose a production deployment.

The following are **out of scope**:

- Denial-of-service issues that require physical LAN access and are
  non-exploitable remotely.
- Issues in third-party libraries that are already tracked by Dependabot.
- Theoretical vulnerabilities without a practical attack scenario.

## Security Measures in Place

- **SAST:** Medium/high Bandit findings fail CI.
- **Dependency scanning:** Dependabot, blocking `pip-audit`, and Trivy.
- **Reproducible dependencies:** A universal `uv.lock` is checked in CI and
  consumed by CI and the production image without re-resolution.
- **Container scanning:** Trivy Docker image scan in CI.
- **DAST:** OWASP ZAP baseline scan against the running API in CI.
- **Code scanning:** GitHub's default CodeQL setup analyzes the default branch
  and pull requests without a competing advanced workflow.
- **Authentication:** API, dashboard, media, metrics, and API docs share one
  bearer/cookie JWT policy. Authenticated startup rejects weak secrets, users,
  wildcard hosts, and wildcard CORS.
- **Browser security:** CSRF checks, login-origin validation, HttpOnly
  same-site cookies, trusted-host validation, and nonce-based CSP.
- **HTTP security headers:** frame denial, MIME sniffing protection, CSP,
  HSTS on HTTPS, referrer/permissions policy, COOP, and CORP are centralized.
- **Container isolation:** The application is non-root/read-only with no Linux
  capabilities; the non-root Caddy edge keeps only `NET_BIND_SERVICE`.
- **Production edge:** The tested Compose profile provides automatic HTTPS,
  file-backed credentials, exact hosts/origins, and CIDR-scoped forwarded
  header trust.
- **Rate limiting:** API endpoints are rate-limited via `slowapi`.
- **Static analysis:** `ruff` and `mypy` run on every push.
- **Pre-commit hooks:** `ruff`, `mypy`, and `bandit` run before each commit.

For the threat model, resolved findings, verification contract, and explicitly
accepted residual risks, see
[docs/production-readiness.md](docs/production-readiness.md).

## Preferred Languages

Reports may be submitted in English or Swedish.
