# Linux/Docker office deployment candidate

This is the agreed first deployment platform. These files are a deployment candidate, not a verified production release. Docker is unavailable on the development machine, so image build, Compose startup and TLS integration must be tested on the Linux host before a pilot. Existing `compose.yaml` at the repository root remains the synthetic demonstration setup.

The API image does not train or include a model. Supply a verified model directory containing `bundle.joblib` and `manifest.json`. Startup refuses a missing or synthetic-trained artifact. A real-data provenance flag alone does not establish model quality: independent evaluation and site calibration remain release gates.

## Host preparation

1. Install Docker Engine and the Compose plugin on the chosen Linux host.
2. Create the absolute directories referenced in `.env.example`. Keep the approved model admin-owned, readable by UID 10001, and mounted read-only. Copy a reviewed detection configuration based on `config/detection.example.json` to the configured file.
3. Configure the authorized Zeek sensor to produce uncompressed JSON `conn*.log` files, with retained rotated logs in the mounted directory. Grant UID 10001 read/traverse access. Review [collector recovery requirements](../docs/COLLECTOR.md). The container does not capture traffic or install Zeek.
4. Provision DNS and a TLS certificate for the selected hostname. Put `fullchain.pem` and `privkey.pem` in the configured certificate directory. Clients must trust the issuing CA. Caddy uses these certificates; this configuration does not automatically request or renew them.
5. Copy `.env.example` to `.env` in this directory, set the actual paths/hostname, and generate distinct high-entropy role tokens of at least 24 characters. Protect the file with restrictive permissions. Container administrators can inspect environment credentials; restrict Docker access accordingly.

From the repository root:

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml config --quiet
docker compose --env-file deploy/.env -f deploy/compose.yaml up --build -d
docker compose --env-file deploy/.env -f deploy/compose.yaml ps
docker compose --env-file deploy/.env -f deploy/compose.yaml logs --tail=100 api collector proxy
```

The proxy publishes HTTPS on port 443; the API has no directly published port. The collector shares the API network namespace and submits over loopback with the analyst token. API and collector data live in separate persistent volumes. Do not use `down --volumes` when preserving evidence or pending telemetry. Restart the stack together after API replacement because the collector shares its network namespace.

`AEGISWEAVE_PUBLIC_ORIGIN` is set to the exact external HTTPS origin. Browser mutations are checked against that trusted configuration; forwarded headers do not change the trusted origin. Changing hostname or externally visible port requires updating that origin and the proxy consistently.

## Required host verification

- Build and start with the approved artifact; confirm missing/synthetic artifacts fail startup.
- Check the HTTPS certificate and browser login; confirm cross-origin mutations and missing tokens are rejected.
- Verify the collector drains logs, survives API unavailability and restart, and reports source errors/backpressure. Its Docker healthcheck reads the atomic local status file and detects stale status, errors and aging backlog. Configure operator notifications before the pilot; an unhealthy Docker status alone does not send alerts or automatically restart the container.
- Restart containers and verify evidence, spool offsets, and pending telemetry persist.
- Exercise database [backup and restore](../docs/BACKUP.md) against the persistent volume, then document a complete restore including model, config, and credentials.
- Measure CPU, memory, storage growth, capture loss, backlog, and latency under the site's expected peak. Current CPU/memory limits are initial settings, not demonstrated capacity.
- Record image digests and dependency/security review for the release; current base-image tags are not immutable pins.

The Compose network is internal, certificates are supplied locally, and neither the API nor collector requires internet egress during serving. Restrict inbound HTTPS to the intended office/admin network using the host's network policy. No host firewall changes are made by these files.

Configuration references: [Docker Compose services](https://docs.docker.com/reference/compose-file/services/), [Caddy TLS](https://caddyserver.com/docs/caddyfile/directives/tls), [Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).
