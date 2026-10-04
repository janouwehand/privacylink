# Contabo VPS setup

This setup guide prepares the existing Contabo Softable VPS for the manual GitHub Actions deployment. Staging and production use separate Compose projects, environment files, databases, and blob volumes. Caddy remains installed and managed on the VPS.

## 1. Prepare the host

Use a dedicated SSH deployment account. Install Docker Engine with the Compose plugin and `curl`. Keep the deployment account out of the `docker` group; Docker access is effectively root access.

Create root-owned directories and install the versioned Compose file and deploy command as root:

```sh
sudo install -d -o root -g root -m 0755 /opt/privacylink/staging /opt/privacylink/production
sudo install -d -o root -g root -m 0755 /etc/privacylink
sudo install -o root -g root -m 0644 compose.yaml /opt/privacylink/staging/compose.yaml
sudo install -o root -g root -m 0644 compose.yaml /opt/privacylink/production/compose.yaml
sudo install -o root -g root -m 0750 deploy/vps/privacylink-deploy /usr/local/sbin/privacylink-deploy
```

The deployment account needs read access to the Compose files and access to `sudo` for only `/usr/local/sbin/privacylink-deploy`. Do not let it edit the root-owned Compose files or join the Docker group. The deployment script accepts only `staging` or `production` and a digest for `ghcr.io/janouwehand/privacylink`.

Whenever `compose.yaml` or the server deploy command changes, install the reviewed version on the VPS before deploying an image that relies on it.

## 2. Create environment files

Create `/etc/privacylink/staging.env` and `/etc/privacylink/production.env` as root-owned files with mode `0600`. Each file must define:

- Independent values for `POSTGRES_PASSWORD`, `PRIVACYLINK_PASSWORD_PEPPER`, `PRIVACYLINK_AUDIT_HASH_KEY`, and `PRIVACYLINK_ANALYTICS_KEY`. Generate unique values per environment. The audit and analytics values must each be Base64-encoded random values of at least 32 bytes.
- `ASPNETCORE_ENVIRONMENT=Production`.
- `PRIVACYLINK_ALLOWED_HOSTS=plstaging.softable.nl` for staging and `PRIVACYLINK_ALLOWED_HOSTS=privacylink.nl` for production.
- `PRIVACYLINK_REQUIRE_HTTPS=false`, because Caddy terminates HTTPS and forwards to the loopback-only HTTP port.
- `PRIVACYLINK_BIND_ADDRESS=127.0.0.1` and a distinct `PRIVACYLINK_HTTP_PORT`: `8081` for staging and `8080` for production.
- `PRIVACYLINK_TRUSTED_PROXY_0` set to the exact proxy address the API container sees. Determine this for each Compose network on the VPS; do not guess or trust a whole subnet.

Use separate project names `privacylink-staging` and `privacylink-production`. The deploy command supplies the project name and image digest when running Compose. Never copy production environment values into staging.

## 3. Configure Caddy

Review `deploy/Caddyfile` and merge its site blocks into the existing Caddy configuration. Verify the loopback ports match each environment file. Validate and reload the existing Caddy service using the VPS's service manager. Caddy should serve staging and `privacylink.nl`, and permanently redirect `privacylink.eu` to the matching path on `privacylink.nl`.

The DNS A and AAAA records for `plstaging.softable.nl` are already configured. Confirm production records for `privacylink.nl` and `privacylink.eu` point to this VPS before enabling those Caddy sites.

## 4. Configure GitHub

In repository settings:

1. Add `staging` and `production` environments, both restricted to the `main` branch. A production required reviewer is an additional safeguard when the repository plan supports it. Production promotion is always a separate, manually started workflow after staging succeeds.
2. In each environment, add `VPS_HOST`, `VPS_USER`, `VPS_SSH_PRIVATE_KEY`, and `VPS_SSH_KNOWN_HOSTS`. Verify the host key fingerprint independently before storing it. Keep deployment secrets out of repository-level secrets.
3. Run `PrivacyLink deployment` once with `publish_only=true` to create the GHCR package without attempting a deployment. Then set `ghcr.io/janouwehand/privacylink` to public so the VPS can pull by digest without registry credentials. This makes the container image publicly downloadable; GitHub does not let you change a public package back to private. The source repository is public; make the package-visibility decision deliberately.
4. Add a ruleset for `main` that requires pull requests and both successful status checks: `Backend and frontend tests` and `Build and verify production Linux container`.

The `PrivacyLink deployment` workflow is started manually from `main`. It reruns backend and frontend tests, publishes one image, deploys its digest to staging, and runs the protocol smoke check. On success, it stores the tested digest as a run artifact for 30 days. To promote, start `PrivacyLink production promotion` manually from `main` and provide the successful staging workflow's run ID. The promotion workflow verifies that the run came from this deployment workflow on `main`, that its staging job succeeded, then deploys the exact tested digest. Its manual start is the human production gate. The optional `image_digest` input on `PrivacyLink deployment` redeploys an existing digest to staging for verification; use its new successful run ID to promote that rollback digest. Set `publish_only=true` only for the one-time package setup described above.

## 5. Production data backups

Back up production PostgreSQL and the production blob volume together. Exclude both staging volumes from production backup and restore jobs. Store backups outside the live VPS storage and verify a paired database/blob restore before relying on the service. Configure the backup destination, encryption, schedule, and retention before enabling automated backups; those operational choices are intentionally not guessed here.

