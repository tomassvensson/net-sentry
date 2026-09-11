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
[GitHub Security Advisory](https://github.com/tomassvensson/btwf/security/advisories/new)
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

- **SAST:** Bandit runs on every push via GitHub Actions.
- **Dependency scanning:** Dependabot + Trivy + OWASP Dependency-Check.
- **Container scanning:** Trivy Docker image scan in CI.
- **DAST:** OWASP ZAP baseline scan against the running API in CI.
- **Code scanning:** GitHub CodeQL analysis on every push.
- **HTTP security headers:** `X-Frame-Options`, `X-Content-Type-Options`,
  `Content-Security-Policy`, `X-XSS-Protection`, and `Referrer-Policy`
  are set by `SecurityHeadersMiddleware` in `src/api.py`.
- **Rate limiting:** API endpoints are rate-limited via `slowapi`.
- **Static analysis:** `ruff` and `mypy` run on every push.
- **Pre-commit hooks:** `ruff`, `mypy`, and `bandit` run before each commit.

## Preferred Languages

Reports may be submitted in English or Swedish.
