# Production Runbook

This document describes the current operational baseline for PrivacyLink. Validate deployment-specific settings and procedures in the target environment.

## Configuration and secrets

- Set `ASPNETCORE_ENVIRONMENT=Production`.
- For a host that does not use Compose, provide `ConnectionStrings__PrivacyLink` and `Security__PasswordPepper` as environment variables; do not put these values in the repository. GitHub Actions can pass GitHub Secrets as environment variables through the `env` section. With Compose, the host provides `POSTGRES_PASSWORD` and `PRIVACYLINK_PASSWORD_PEPPER` to Compose; Compose mounts them as secret files and passes only the file paths to the API.
- Set `Security__SecretStore__Provider=Environment`. The API reads the pepper from ASP.NET Environment configuration; with Compose, it first reads the pepper from the mounted secret file. There is no Azure Key Vault or Kubernetes integration. In Development, production validation is disabled and `appsettings.Development.json` provides the local development pepper.
- Configure a random Base64 secret for `Security__AuditHashKey` (at least 32 bytes); do not reuse the password pepper. With Compose, set `PRIVACYLINK_AUDIT_HASH_KEY`; it is mounted as a secret file. Product statistics collection has been retired. Startup migration 6 drops the legacy `stats_daily` and `stats_visitors_daily` tables and their data; `/api/v1/stats` returns HTTP 410.
- Use an absolute `Storage__BlobPath` on durable storage that the service account can write to.
- Compose accepts HTTP by default so local testing and a Caddy upstream over HTTP work. The published host port binds to `127.0.0.1` by default; route public access through Caddy and configure trusted proxies only with your own proxy IP addresses. Set `PRIVACYLINK_REQUIRE_HTTPS=true` if the application itself must enforce HTTPS.
- Restrict `AllowedHosts` to the public hostnames.

## Health checks and incident triage

- `/health` is a fast liveness probe with no dependency information.
- `/health/ready` returns HTTP 200 with `{"status":"ready"}` when startup initialization has completed and PostgreSQL and the blob root are reachable. Otherwise, the probe returns HTTP 503 with `not_ready`; it does not expose dependency details. The checks run in parallel and have a two-second timeout.
- In production, both health endpoints may be called over HTTP only from loopback. The Compose health check uses the Native AOT binary itself as the probe, without a shell or `curl` in the chiseled image. When `PRIVACYLINK_REQUIRE_HTTPS=true`, other HTTP requests are rejected; behind a TLS proxy, only a trusted proxy should supply `X-Forwarded-Proto`.
- Application audit logs contain the operation, status, duration, and trace ID. When a valid `Security:AuditHashKey` is configured (required in Production), they also contain a truncated HMAC-SHA-256 of the client IP; without a valid key, the client field is `unavailable`. Request bodies, URL identifiers, keys, and passwords are not logged by the application.
- For database problems, first check the connection string, network, and migration lock. Do not manually delete records or blobs.

## Database and blobs

- At startup, transactional schema migrations run under an advisory lock and are recorded in `schema_migrations`; migrations are idempotent.
- Migration 6 drops the legacy statistics tables. Stop every old API instance before starting the new version; do not run old and new API versions side by side during this transition. Active secrets and blobs are unaffected.
- The PostgreSQL image reads the database password from `POSTGRES_PASSWORD_FILE`; the API builds the Npgsql connection string using the mounted password secret. The Compose secret source `environment` is intended for Docker Compose, not `docker stack deploy`.
- Cleanup deletes expired blobs before metadata and can be safely repeated. Temporary `.tmp-*` blobs are safely removed at startup.
- Production backups must include both the production PostgreSQL database and production `Storage__BlobPath`. Restoring only one can break references. Do not include staging volumes in production backups.
- After a restore, always run `scripts/reconcile-blobs.ps1`. It is a dry run by default; delete candidates only after separate operational approval.

## Release gates

```powershell
dotnet restore PrivacyLink.slnx
dotnet build PrivacyLink.slnx --no-restore
dotnet test PrivacyLink.slnx --no-restore
dotnet publish src/PrivacyLink.Api/PrivacyLink.Api.csproj -c Release -r win-x64 --self-contained true -p:PublishAot=true -p:PublishAotUsingRuntimePack=true
pwsh -File scripts/verify-linux-container.ps1
Push-Location src/PrivacyLink.Web
npm ci
npm test -- --no-watch --no-progress
npm run build
Pop-Location
```

On Windows systems where the Angular CLI crashes natively, use `npm run build:container`. This build runs the same production configuration in a temporary Linux container and writes the output to `.container-dist`.

Run the local persistence smoke test with `powershell -File scripts/verify-persistence.ps1`. It starts a temporary PostgreSQL container, runs the actual API migrations and create flow, creates a PostgreSQL custom-format backup, restores it to a second database, and compares the blob backup using SHA-256. The test uses only temporary data and removes the container when finished.

## Remaining blockers

- This repository has no production PostgreSQL/blob environment or production backup/restore exercise with measured RPO/RTO; the local persistence smoke test is not a substitute for one.
- The feature VPS environment is configured: its root-owned Compose file/environment, isolated PostgreSQL volume, deployment-helper support, Caddy route, DNS, and TLS are ready. The app is not running until the dedicated workflow and public `privacylink-feature` GHCR package are activated. See [`deploy/vps/README.md`](../deploy/vps/README.md).
- The `staging` environment and its deployment secrets are configured. Create the `feature` GitHub environment and add its own deployment secrets; create and make the `privacylink-feature` GHCR package public before deploying the preview. Configure required reviewers and deployment secrets for `production`; the repository is public, so GitHub supports this approval gate. Confirm the `main` ruleset still requires both CI checks.
- `public/_headers` is a provider profile; the deployment environment must test the final reverse-proxy/CDN configuration.
- No external load test or disaster-recovery evidence has been produced.

## CI and release validation

- `scripts/verify-release.ps1` runs restore, backend build and tests, Native AOT publishing, static-hosting validation, frontend tests, and the containerized production build. The script does not deploy anything.
- `scripts/verify-linux-container.ps1` builds the Dockerfile for `linux-x64`, starts the production image with the in-memory development configuration, and waits for `/health`. The GitHub Actions workflow `.github/workflows/linux-aot-container.yml` runs this artifact check on pushes to `main` and pull requests targeting `main`; it then starts a disposable Compose stack with temporary CI credentials and isolated volumes. `docker compose up --wait` waits for PostgreSQL health and API readiness through the built-in health check. The workflow removes its temporary containers and volumes afterwards.
- `.github/workflows/deploy.yml` is a manual workflow started from `main`. It reruns backend and frontend tests, publishes an immutable image to GHCR, deploys it to staging, runs `scripts/verify-prototype.mjs`, and records the tested digest. After staging succeeds, the same run waits at the `production` environment's required-reviewer gate. Approval deploys that exact staged digest without rebuilding; rejection fails the run. GitHub automatically fails an approval still pending after 30 days. The rollback input also passes through staging and this same production gate. `scripts/deploy-vps.sh` connects over SSH using environment-scoped secrets; `deploy/vps/privacylink-deploy` performs the fixed host-side Compose update. Neither workflow rebuilds images on the VPS.
- `.github/workflows/deploy-feature.yml` is a separate manual workflow that must be started from `main`, with the feature branch supplied as input. It builds the selected branch and deploys it only to `feature.privacylink.nl`, using the separate `feature` GitHub environment and GHCR package. It checks readiness and runs the protocol smoke check. It does not touch staging or production.
- GitHub branch rules must require both `Backend and frontend tests` and `Build and verify production Linux container` before merging to `main`. Workflow files cannot enable this repository setting by themselves.
- The PostgreSQL/blob smoke test remains a local, temporary check; schedule a periodic restore exercise in the production environment and measure RPO/RTO.
- `/health` is a liveness probe; `/health/ready` checks dependency readiness. Audit logging is privacy-preserving; monitor status codes, latency, and readiness failures through the host logging/metrics layer, and alert on sustained 5xx responses, 429 spikes, readiness 503 responses, and backup failures.
- TLS termination must forward the original HTTPS scheme only through explicitly trusted proxy IP addresses. Validate HSTS, `X-Forwarded-*`, host allowlisting, and end-to-end HTTPS in the deployment environment.

