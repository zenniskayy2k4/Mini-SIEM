# Security operations runbook

Mini-SIEM is a single-node blue-team platform, not a hardened multi-tenant boundary. Treat its
alerts, raw telemetry, credentials, audit records, reports, backups, and collector state as
sensitive security data.

## Production minimum

Before exposure outside an isolated lab:

- Set `DEPLOYMENT_ENV=production`, an HTTPS `DASHBOARD_PUBLIC_URL`, secure cookies, explicit trusted
  proxy/host values, and `FLASK_DEBUG=false`.
- Put the dashboard behind a firewall and TLS reverse proxy; do not expose its direct Flask port.
- Configure unique session, metrics, and collector secrets of at least 32 characters through a
  protected secret store or `*_FILE` mount.
- Require authenticated individual accounts, least-privilege roles, and at least one recoverable
  administrator account.
- Keep `RESPONSE_MODE=simulation` unless a separately reviewed least-privilege executor is
  explicitly authorized. The repository does not execute arbitrary AI-generated commands.
- Protect `data/`, `logs/`, `secrets/`, collector state, reports, and backups with host access
  controls and encrypted storage where available.
- Run `tools.validate_config`, `tools.doctor`, and the health check before opening ingress.

The bundled Caddy profile uses a local development CA. Follow
[HTTPS deployment](HTTPS_DEPLOYMENT.md) for local use; use a real DNS name, publicly trusted or
organization-managed certificate, expiry monitoring, and an explicit proxy trust boundary in
production.

## Secret inventory

| Purpose | Variables | Rotation impact |
|---|---|---|
| Dashboard sessions | `DASHBOARD_SESSION_SECRET` or `_FILE` | Invalidates existing sessions |
| Metrics access | `METRICS_BEARER_TOKEN` or `_FILE` | Scrapers must change with dashboard |
| Windows ingestion | `WINDOWS_COLLECTOR_SECRET` or `_FILE` | Dashboard and every collector must match |
| Ollama Cloud | `OLLAMA_API_KEY` or `_FILE` | AI enrichment degrades until restarted |
| Threat intelligence | `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `TAXII_BEARER_TOKEN` or `_FILE` | Affected provider becomes unavailable |
| Case export | `THEHIVE_API_KEY`, `JIRA_API_TOKEN` or `_FILE` | Manual export fails until restarted |
| Notifications | `NOTIFICATION_WEBHOOK_URL` | Notification delivery pauses |

Direct and `_FILE` forms are mutually exclusive. File requirements and supported names are in
[File-based secrets](FILE_SECRETS.md). Never store real values in source, `.env.example`, fixtures,
documentation, shell history, screenshots, tickets, or Git history.

## Secret rotation

The application accepts one active value for each secret, so use a short maintenance window rather
than trying to overlap old and new credentials.

1. Create the replacement in the owning secret manager and restrict read access to the affected
   service account.
2. Stop the component that sends or consumes the credential. For collector rotation, stop Windows
   collectors first; they retain their cursors and source logs continue to collect events.
3. Update both ends where required: dashboard and collectors, dashboard and metrics scraper, or
   Mini-SIEM and the external provider.
4. Revoke the old credential at the provider after the replacement is stored.
5. Recreate affected containers so environment/file values are reloaded:

   ```powershell
   docker compose up -d --force-recreate dashboard agent
   ```

6. Start collectors, validate configuration, require health HTTP 200, and confirm the affected
   integration in admin diagnostics.
7. Review provider and Mini-SIEM audit logs for use of the revoked credential.

Rotate the dashboard session secret only when forced sign-out is acceptable. If a credential may
have entered Git history, revoke it immediately; removing the current line or rewriting Git history
does not make the exposed value safe.

## Access and trust boundaries

- The browser is untrusted. Server-side RBAC and CSRF enforcement, not hidden controls, protect
  mutations.
- Viewer is read-only; analysts manage incident workflow; administrators manage users, rules,
  diagnostics, and maintenance-sensitive settings.
- The collector shared secret authenticates ingestion but does not encrypt transport. Use TLS over
  untrusted networks and limit source networks at the firewall.
- YAML, Sigma, STIX/TAXII, Windows events, alert payloads, and AI text are untrusted input. Keep
  source directories read-only and review import failures before enabling a rule or feed.
- AI and threat intelligence are advisory context. Deterministic evidence and risk factors remain
  distinct, and external provider failure must not block alert storage.
- Prometheus labels are bounded and exclude raw IP, username, secret, and payload data. Still
  authenticate or network-restrict `/metrics` outside an isolated lab.

## Security incident handling

1. Contain network exposure at the firewall or proxy without deleting containers or evidence.
2. Stop `agent` and `dashboard` if continued writes threaten integrity; preserve collector buffers.
3. Record UTC time and acquire protected copies of SQLite/WAL/SHM, logs, analyst audit chain,
   configuration names, collector diagnostics, image digest, and relevant provider audit records.
4. Revoke suspected credentials and sessions using the rotation procedure.
5. Verify SQLite integrity, the analyst audit chain, rule sources, Compose configuration, image/SBOM
   provenance, and account roles from a trusted host.
6. Recover from known-good artifacts, validate, and monitor before restoring ingress.
7. Document scope and lessons without including secrets or raw sensitive telemetry.

Do not use response automation as an incident-containment shortcut. Keep simulation mode unless the
specific executor and target were separately authorized.

## Disaster recovery

Maintain protected off-host copies of:

- integrity-checked SQLite backups and required JSON compatibility state;
- analyst audit log and dashboard user store;
- `.env` variable mapping plus secrets in a separate secret manager;
- native/Sigma rules and rule state overrides;
- collector deployment configuration and identity/state where host recovery requires it;
- the reviewed Git release/tag, container image digest, SBOM, and release checksums.

Recovery order:

1. Provision a trusted host with the required Docker/Compose version and restricted storage.
2. Restore the reviewed source release and protected configuration; do not start ingress.
3. Restore data by following [Retention, backup and restore](RETENTION_BACKUP.md).
4. Run configuration validation, database migration dry-run, doctor, and the restore drill.
5. Start dashboard then agent, require health HTTP 200, and verify users, audit chain, rules,
   incidents, assets, and integration state.
6. Restore TLS/firewall ingress, then collectors in controlled groups while monitoring queue and
   parser health.

Test the restore drill at least monthly and after a storage/schema change. A successful backup job
without a tested restore is not a disaster-recovery proof.
