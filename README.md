# PrivacyLink

A local PrivacyLink prototype for sharing text and files without accounts through encrypted links. The interface supports Dutch and English.

Messages are encrypted in the browser using AES-256-GCM and an HKDF-derived key. The client key stays in the link fragment (`#...`) and is never sent to the API. Recipients open a message through an explicit action. Links can be opened repeatedly until they expire.

**Storage:** without database configuration, development mode uses temporary in-memory storage. With `ConnectionStrings:PrivacyLink` configured, the API uses PostgreSQL for metadata and the existing blob abstraction for ciphertext on the local filesystem (`Storage:BlobPath`). A message can contain optional text and up to 10 encrypted files (25 MiB total). PIN and password protection add a server-side encryption envelope whose key is derived with Argon2id.

## Requirements

- .NET SDK 10.0.400 (see `global.json`).
- Node.js 24.18 or a compatible Node 24 release, and npm.
- Network access to NuGet and npm for the initial dependency installation.

PostgreSQL and Docker are not required for the temporary development setup. The persistent setup uses PostgreSQL and a durable blob root; transactional startup migrations record applied changes in `schema_migrations`. See the [production runbook](docs/runbook.md) for secret management, health probes, backups, and release gates.

Example environment variable configuration for a persistent production deployment (replace every placeholder with a real value):

```powershell
$env:ASPNETCORE_ENVIRONMENT = "Production"
$env:ConnectionStrings__PrivacyLink = "Host=localhost;Port=5432;Database=privacylink;Username=privacylink;Password=<database-password>"
# Use an absolute blob path on the server; for Linux, for example, use /srv/privacylink/blobs.
$env:Storage__BlobPath = "C:\privacylink-data\blobs"
$env:Security__PasswordPepper = "<long-random-password-pepper>"
$env:Security__AuditHashKey = "<unique-base64-random-key-at-least-32-bytes>"
$env:Analytics__Key = "<different-unique-base64-random-key-at-least-32-bytes>"
$env:Security__SecretStore__Provider = "Environment"
$env:Security__RequirePasswordPepper = "true"
$env:Security__RequireHttps = "true"
$env:AllowedHosts = "privacylink.example.com"
# Set this only when TLS terminates at a reverse proxy; use its exact IP as seen by the API.
# $env:Security__TrustedProxies__0 = "10.0.0.10"
```

Generate separate random values for the password pepper, audit hash key, and analytics key. The audit hash key and analytics key must each be Base64-encoded random values of at least 32 bytes; do not reuse either as the password pepper.

## Docker Compose

The image contains both the Angular build and the .NET API. PostgreSQL runs as a separate Compose service, so its hostname in the connection string is `postgres`. Compose mounts four secret values as files: the database password, password pepper, audit hash key, and analytics key. The API uses all four; PostgreSQL uses only the database password. By default, the API binds to a host port on loopback only. The database and encrypted blobs are stored in separate volumes named per Compose project.

```powershell
Copy-Item .env.example .env
# Set all four secrets: use long, independent values for the database password and password pepper.
# Generate a unique 32-byte Base64 value for each of the audit hash key and analytics key.
docker compose up --build -d
```

The local `.env` file is ignored by Git and Docker builds. Compose mounts the values as secret files only in the API and PostgreSQL services; they are not passed to the containers as environment variables. The supported secret-store provider is `Environment`: when running the API directly, supply secrets through ASP.NET environment configuration; Compose reads host environment values and mounts them as secret files. This applies to secrets, not to every application setting or configuration source. In Development, the local development pepper from `appsettings.Development.json` remains available. The Compose stack expects HTTPS to terminate at a reverse proxy or load balancer in front of the API. Set `PRIVACYLINK_ALLOWED_HOSTS` to the public hostname and set `PRIVACYLINK_TRUSTED_PROXY_0` to the exact IP address of the proxy as seen by the API container. A proxy on the same host can reach the API through the loopback port; a proxy in Docker must share the Compose network and can reach the API at `privacylinkslim:8080`.

The GitHub Actions workflow builds and checks the image on pull requests and pushes to `main`. The separate deployment workflow is started manually from `main`; it publishes one GHCR image, deploys its digest to staging, runs protocol smoke checks there, and waits for production environment approval before deploying that same digest to production. See the [Contabo VPS setup guide](deploy/vps/README.md) for host and GitHub configuration. Keep production and staging Compose volumes separate. Back up both production PostgreSQL and production blobs together; staging data is excluded. If you have an existing installation using the old fixed volume names `privacylink-postgres-data` or `privacylink-blobs`, set the corresponding name in `PRIVACYLINK_POSTGRES_VOLUME` or `PRIVACYLINK_BLOBS_VOLUME` in `.env` before the first startup after this change, so the existing data remains attached.

## Run locally

Run these commands from the repository root:

```powershell
dotnet restore PrivacyLink.slnx
dotnet run --project src/PrivacyLink.Api --urls http://localhost:5080
```

The Development environment is recommended for local work (`$env:ASPNETCORE_ENVIRONMENT="Development"`); the API uses in-memory storage and the local development pepper by default in that environment. In production, the API requires a PostgreSQL connection string, an absolute blob root, `Security:PasswordPepper` from Environment configuration, `Security:AuditHashKey`, `Analytics:Key`, `Security:RequirePasswordPepper=true`, an explicit `Security:RequireHttps` value, and explicit `AllowedHosts`. Configure `Security:TrustedProxies` with the proxy's exact IP address when TLS terminates at a proxy. Do not trust `X-Forwarded-*` headers without an explicit proxy IP.

Application privacy audit records include the operation, status, trace ID, and duration. When a valid `Security:AuditHashKey` is configured (required in production), the record also includes a truncated HMAC-SHA-256 of the client IP; without a valid key, the client field is `unavailable`. The application does not log request bodies, passwords, keys, or secret IDs. Product analytics also records daily keyed HMACs of client IPs for aggregate unique-visitor counts; it does not put raw IP addresses in the statistics tables. These visitor HMAC rows are retained indefinitely. Matching HMACs can be linked across days even without the key; the key also allows a holder to check a candidate IP against stored HMACs. The application uses client IPs for in-memory rate limiting as well. This does not describe logs produced by the hosting platform, proxy, or infrastructure. Default limits for request body size, files, Argon2, and rate limiting are security limits and should only be changed deliberately.

Start the frontend in a second terminal:

```powershell
cd src/PrivacyLink.Web
npm ci
npm start
```

Open the local Angular URL printed in the terminal (by default, `http://localhost:4200`). The development proxy forwards API requests to port 5080. Use the frontend URL to create and open links. Web Crypto requires a secure context; localhost is supported. A shared deployment requires HTTPS and a same-origin API.

## Checks

```powershell
dotnet test PrivacyLink.slnx
```

From `src/PrivacyLink.Web`:

```powershell
npm test -- --watch=false
npm run build
```

With the API running, execute this from the repository root:

```powershell
node scripts/verify-prototype.mjs http://localhost:5080
```

The independent protocol check uses Node Web Crypto, creates temporary test messages, and checks decryption, repeated opens, metadata, invalid requests, and headers, among other things. Test data and keys are not logged.

## Repository layout

| Path | Contents |
| --- | --- |
| `src/PrivacyLink.Api` | Minimal API, validation, limits, PostgreSQL metadata, and blob storage |
| `src/PrivacyLink.Contracts` | Shared C# API contracts |
| `src/PrivacyLink.Web` | Angular SPA and browser cryptography |
| `tests/PrivacyLink.Api.Tests` | Backend unit tests |
| `tests/PrivacyLink.IntegrationTests` | Backend integration tests |
| `scripts/verify-prototype.mjs` | Independent Web Crypto and HTTP check |
| `scripts/build-web-container.ps1` | Reproducible Angular production build in a Linux container |
| `scripts/verify-linux-container.ps1` | Builds the production image for Linux and checks that the container starts and responds at `/health` |
| `scripts/verify-persistence.ps1` | Temporary PostgreSQL and blob backup/restore smoke test |

The solution contains the .NET projects. Angular has its own npm build and tests.

## Copyright and use

Copyright © 2026 Softable. All rights reserved. This source code is public for inspection and transparency; no license for reuse is granted.

Message and file contents are encrypted in the browser; the API receives ciphertext, not plaintext. With password protection enabled, the browser computes an HMAC-SHA-256 token using the entered password as the HMAC key and the client key as the message. At creation and unlock, it sends this derived token to the API, not the entered password or client key. During creation, the API combines the token with its server-side pepper and uses Argon2id to derive a key that wraps the already client-encrypted content in an additional AES-256-GCM envelope. For password-protected content, the API persists the salt, outer nonces, and enveloped ciphertext; it does not persist the entered password, HMAC token, or derived key. At unlock, the API uses the token to open that outer envelope and returns the still client-encrypted content; the browser then decrypts it with the client key from the link fragment.

Separately, sender history stores the entered password, full share link (including its client key), and revoke token in this browser's `localStorage`. Expired history entries are removed by browser-history cleanup when the app runs; anyone with access to this browser profile can access entries that remain stored there. A compromised frontend could still serve malicious JavaScript, and the prototype does not protect against a compromised device.

