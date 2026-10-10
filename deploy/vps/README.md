# Contabo VPS setup

This setup guide prepares the existing Contabo Softable VPS for the manual GitHub Actions deployments. Staging, feature, and production use separate Compose projects, environment files, databases, and blob volumes. Caddy remains installed and managed on the VPS.

## 1. Prepare the host

Use a dedicated SSH deployment account. Install Docker Engine with the Compose plugin and `curl`. Keep the deployment account out of the `docker` group; Docker access is effectively root access.

Create root-owned directories and install the versioned Compose file and deploy command as root:

```sh
sudo install -d -o root -g root -m 0755 /opt/privacylink/staging /opt/privacylink/feature /opt/privacylink/production
sudo install -d -o root -g root -m 0755 /etc/privacylink
sudo install -o root -g root -m 0644 compose.yaml /opt/privacylink/staging/compose.yaml
sudo install -o root -g root -m 0644 compose.yaml /opt/privacylink/feature/compose.yaml
sudo install -o root -g root -m 0644 compose.yaml /opt/privacylink/production/compose.yaml
sudo install -o root -g root -m 0750 deploy/vps/privacylink-deploy /usr/local/sbin/privacylink-deploy
```

The deployment account needs read access to the Compose files and access to `sudo` for only `/usr/local/sbin/privacylink-deploy`. Do not let it edit the root-owned Compose files or join the Docker group. The deployment script accepts `staging` and `production` digests for `ghcr.io/janouwehand/privacylink`, or a `feature` digest for `ghcr.io/janouwehand/privacylink-feature`.

Whenever `compose.yaml` or the server deploy command changes, install the reviewed version on the VPS before deploying an image that relies on it. The server deploy command removes unused PrivacyLink images after a healthy deployment. Docker keeps any PrivacyLink image still used by staging, feature, or production containers.

## 2. Create environment files

Create `/etc/privacylink/staging.env`, `/etc/privacylink/feature.env`, and `/etc/privacylink/production.env` as root-owned files with mode `0600`. Each file must define:

- Independent values for `POSTGRES_PASSWORD`, `PRIVACYLINK_PASSWORD_PEPPER`, and `PRIVACYLINK_AUDIT_HASH_KEY`. Generate unique values per environment. The audit hash key must be a Base64-encoded random value of at least 32 bytes.
- `ASPNETCORE_ENVIRONMENT=Production`.
- `PRIVACYLINK_ALLOWED_HOSTS=plstaging.softable.nl` for staging, `PRIVACYLINK_ALLOWED_HOSTS=feature.privacylink.nl` for feature, and `PRIVACYLINK_ALLOWED_HOSTS=privacylink.nl` for production.
- `PRIVACYLINK_REQUIRE_HTTPS=false`, because Caddy terminates HTTPS and forwards to the loopback-only HTTP port.
- `PRIVACYLINK_BIND_ADDRESS=127.0.0.1` and a distinct `PRIVACYLINK_HTTP_PORT`: `8081` for staging, `8082` for feature, and `8080` for production.
- `PRIVACYLINK_TRUSTED_PROXY_0` set to the exact proxy address the API container sees. Determine this for each Compose network on the VPS; do not guess or trust a whole subnet.

Use separate project names `privacylink-staging`, `privacylink-feature`, and `privacylink-production`. The deploy command supplies the project name and image digest when running Compose. Never copy production or staging environment values into feature.

## 3. Configure Caddy

Review `deploy/Caddyfile` and merge its site blocks into the existing Caddy configuration. Verify the loopback ports match each environment file. Validate and reload the existing Caddy service using the VPS's service manager. Caddy should serve staging, feature, and `privacylink.nl`, and permanently redirect `privacylink.eu` to the matching path on `privacylink.nl`.

The DNS A and AAAA records for `plstaging.softable.nl` and `feature.privacylink.nl` point to this VPS. Confirm production records for `privacylink.nl` and `privacylink.eu` point to this VPS before enabling those Caddy sites.

## 4. Configure GitHub

In repository settings:

1. Add `staging`, `feature`, and `production` environments, each restricted to the `main` branch. A production required reviewer is an additional safeguard when the repository plan supports it. Production promotion remains in the existing deployment workflow after staging succeeds.
2. Add independent `VPS_HOST`, `VPS_USER`, `VPS_SSH_PRIVATE_KEY`, and `VPS_SSH_KNOWN_HOSTS` secrets to each environment. Verify the host key fingerprint independently before storing it. Keep deployment secrets out of repository-level secrets.
3. Run `PrivacyLink deployment` once with `publish_only=true` to create the main GHCR package without attempting a deployment. Set `ghcr.io/janouwehand/privacylink` to public. In Actions, run `PrivacyLink feature branch deployment`, choose the desired `feature/...` branch in `Use workflow from`, and set `publish_only=true` to create `ghcr.io/janouwehand/privacylink-feature` without deploying it. The trusted `PrivacyLink feature deployment` run publishes the package; then set it to public. The VPS pulls both packages by digest without registry credentials. Public packages are publicly downloadable and cannot be made private again; make that visibility decision deliberately.
4. Add a ruleset for `main` that requires pull requests and both successful status checks: `Backend and frontend tests` and `Build and verify production Linux container`.

The `PrivacyLink deployment` workflow is started manually from `main` and keeps the existing main → staging → approved production promotion. For a preview, run `PrivacyLink feature branch deployment` and select a `feature/...` branch in `Use workflow from`. That branch-selected workflow has no deployment secrets; on success, `PrivacyLink feature deployment` runs from `main`, builds and publishes the image, and deploys only to `feature.privacylink.nl`. It uses the separate GHCR package and `feature` environment secrets, database, and blob volume. It never deploys feature code to shared staging or production. The trusted deployment uses an immutable digest and retains the newest 20 feature package versions after successful deployment. The server deploy command removes unused images while preserving images used by any of the three installations.

## 5. Production data backups

Back up production PostgreSQL and the production blob volume together. Exclude staging and feature volumes from production backup and restore jobs. Store backups outside the live VPS storage and verify a paired database/blob restore before relying on the service. Configure the backup destination, encryption, schedule, and retention before enabling automated backups; those operational choices are intentionally not guessed here.
