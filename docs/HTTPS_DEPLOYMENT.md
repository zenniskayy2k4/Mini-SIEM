# Local HTTPS deployment

Start the isolated reverse-proxy profile:

```bash
docker compose -f docker-compose.yml -f docker-compose.https.yml up -d
```

Open `https://localhost`. Port 80 returns a permanent redirect, Caddy terminates TLS and rejects bodies larger than 2 MiB, and the dashboard is reachable only through the Compose proxy network. Flask trusts exactly one forwarded-header hop, accepts only `localhost`, and emits secure session cookies in this profile.

Caddy stores the local CA root certificate at `/data/caddy/pki/authorities/local/root.crt` inside the `proxy` container. Export only that public certificate when the browser does not trust it:

```bash
docker compose -f docker-compose.yml -f docker-compose.https.yml cp \
  proxy:/data/caddy/pki/authorities/local/root.crt data/caddy-local-root.crt
```

Trust `data/caddy-local-root.crt` only on local development devices. Never copy or expose the CA private key under `/data/caddy/pki/authorities/local/`. Public deployments should use a real DNS name and publicly trusted certificate instead of this local-CA profile.
