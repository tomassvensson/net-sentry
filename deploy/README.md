# Production HTTPS deployment

The production Compose override places Caddy in front of Net Sentry, enables
authentication and secure cookies, mounts credentials as files, and trusts
forwarded headers only from a dedicated internal Docker subnet. The direct
application port remains bound to host loopback by the base Compose file.

## Prepare

1. Point the public DNS name at the host and allow inbound TCP 80/443. Caddy
   obtains and renews the certificate automatically.
2. Copy `.env.production.example` to `.env.production` and set the public host,
   exact HTTPS origin, and ACME contact address.
3. Copy `config.yaml.example` to `config.yaml` and configure only the scanners
   and integrations needed on this host. Authentication, hosts, origins,
   cookies, proxy trust, and credentials are forced by the production override.
4. Create `secrets/net_sentry_jwt_secret.txt` with a stable random signing
   secret of at least 32 bytes:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

5. Create a bcrypt password hash:

   ```bash
   python -c "import bcrypt; print(bcrypt.hashpw(b'replace-this-password', bcrypt.gensalt(rounds=12)).decode())"
   ```

   Save the user map as `secrets/net_sentry_api_users.json`:

   ```json
   {"admin": "$2b$12$replace-with-the-generated-hash"}
   ```

Restrict both secret files to the deployment account where the host supports
POSIX permissions (`chmod 600 secrets/*`).

## Start

```bash
docker compose --env-file .env.production \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  --profile production up -d --build
```

Verify the public health endpoint:

```bash
curl https://net-sentry.example.com/api/v1/health
```

All dashboard, API, metrics, media, schema, and interactive-documentation
routes except the minimal health endpoint require authentication. Rotating the
JWT secret intentionally invalidates every active session.

For internet-facing or multi-user deployments, put an OIDC-aware identity
proxy in front of Caddy (or replace Caddy with that ingress) to add MFA,
central revocation, and organizational access policy. Do not expose the
loopback application listener through an additional public port mapping.
