# Mini-SIEM Release History

Archived release notes for versions older than the current standalone release. See [v0.5.0](RELEASE_v0.5.0.md) for the latest release.

## Mini-SIEM v0.4.0 Release Checklist

`v0.4.0` adds CI-backed detection engineering and normalized threat intelligence to the single-node Blue Team lab. Native detections remain authoritative; Sigma and external intelligence add provenance and context without silently rewriting severity.

### Upgrade from v0.3.0

- No alert-database migration is required; SQLite and JSON compatibility remain unchanged.
- Rebuild the image so the Sigma and threat-intelligence modules are included, then restart the stack.
- Copy new optional settings from `.env.example`. Empty AbuseIPDB, VirusTotal, and TAXII credentials keep those providers disabled.
- Existing native rules, dashboard users, alerts, models, and audit data under mounted directories remain compatible.
- Review the supported Sigma subset in [Sigma rule support](SIGMA_RULES.md) before adding third-party rules.

### Clean-clone setup

Clone and select the release:

```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
git checkout v0.4.0
```

Create the local environment file on PowerShell:

```powershell
Copy-Item .env.example .env
```

Or on a POSIX shell:

```bash
cp .env.example .env
```

Build, train, and start:

```bash
docker compose build
docker compose --profile train run --rm train
docker compose up -d
docker compose exec dashboard python tools/manage_dashboard_user.py admin admin
```

The user command prompts for a password. Open <http://localhost:5000> and verify:

```bash
docker compose ps
curl http://localhost:5000/health
```

Rules, local ML, storage, dashboard, offline STIX, and GeoIP handling work without paid-provider keys. Keep `RESPONSE_MODE=simulation` for the lab.

### Optional threat-intelligence setup

Configure only providers you intend to use:

```dotenv
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
STIX_BUNDLE_FILE=
TAXII_COLLECTION_URL=
TAXII_BEARER_TOKEN=
TAXII_FEED_SOURCE=taxii
TAXII_PULL_INTERVAL_SECONDS=3600
```

Place offline bundles under a mounted path such as `data/`, then import manually when needed:

```bash
docker compose exec agent python tools/import_stix.py /app/data/feed.json --source lab-feed
```

Only exact STIX equality indicators for IPv4, domain, SHA-256, and MD5 are active in this release. VirusTotal performs hash metadata lookups only and never uploads files.

### Regression command

Run all executable modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

### Release verification record

| Check | Result |
|---|---|
| Semantic version | `v0.4.0` selected for Detection Engineering and Threat Intelligence |
| Regression | 25/25 executable test modules passed, including the responsive dashboard contract |
| Sigma | Parser, mapping, lifecycle, provenance, coverage, and offline corpus passed |
| Threat intelligence | Provider, GeoIP, AbuseIPDB, VirusTotal, dashboard, STIX/TAXII, expiry, and failure paths passed |
| GitHub Actions | Responsive stabilization run `32123583216` passed baseline, Docker smoke, security, and release gate |
| Clean clone | Required release files, Compose configuration, syntax, and the original 24/24 release-snapshot regression modules passed |
| Secret review | No active Gitleaks exception; `.env`, `data/`, and `logs/` remain untracked |
| Runtime | Existing agent/dashboard stack and public `/health` are healthy |

The clean-clone verification reuses the existing local image to avoid a duplicate multi-gigabyte build. GitHub Actions independently performs the clean Docker build and smoke test.

### Known limitations

- This remains an educational single-node lab, not a production SIEM, EDR, firewall, or high-availability service.
- The supported Sigma grammar is deliberately limited; unsupported modifiers, aggregations, wildcards, and complex conditions are disabled with a reason.
- GeoIP is context, not a maliciousness decision. AbuseIPDB and VirusTotal depend on external quotas and credentials.
- STIX phase 1 accepts exact IPv4/domain/hash equality patterns only. TAXII expects a collection objects URL and supports bearer-token authentication, not every discovery/authentication profile.
- Threat-intelligence caches and stores are local. Concurrent multi-process writers and distributed feed coordination are out of scope.
- VirusTotal never uploads, rescans, or downloads files; domain/IP VirusTotal lookups are not enabled.
- Ollama Cloud uses one shared worker with no durable AI queue or local fallback. AI output remains advisory.
- Response actions remain allowlisted workflow simulations; no production executor is bundled.
- Dashboard identity is local-file based with no SSO, MFA, password recovery, or user-administration UI.
- TLS/reverse-proxy configuration is not bundled. Protect collector and dashboard traffic before crossing untrusted networks.
- Windows collection remains polling-based and NIDS visibility remains Linux-oriented.

### Tag and publish

The annotated tag was created after the release commit's GitHub Actions `release-gate` passed:

```bash
git status --short
git tag -a v0.4.0 -m "Mini-SIEM v0.4.0"
git push origin feature/blue-team-baseline
git push origin v0.4.0
```

Published tag `v0.4.0` points to verified commit `1c41462`.

---

## Mini-SIEM v0.3.0 Release Checklist

`v0.3.0` is the first versioned Blue Team portfolio release. The minor version reflects substantial new detection, incident, storage, response, Windows, and reliability capabilities while the project remains pre-1.0 and lab-focused.

### Clean-clone setup

Clone and select the release:

```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
git checkout v0.3.0
```

Create the local environment file on PowerShell:

```powershell
Copy-Item .env.example .env
```

Or on a POSIX shell:

```bash
cp .env.example .env
```

Add `OLLAMA_API_KEY` to `.env` if AI triage is required. Rules, local ML, storage, and the dashboard continue to work without it. Keep `RESPONSE_MODE=simulation` for the lab.

Build, train, and start:

```bash
docker compose build
docker compose --profile train run --rm train
docker compose up -d
docker compose exec dashboard python tools/manage_dashboard_user.py admin admin
```

The user command prompts for a password. Open <http://localhost:5000> and verify:

```bash
docker compose ps
curl http://localhost:5000/health
```

Expected public health state is `healthy` for the dashboard, agent, alert store, and database.

### Regression command

The tests are executable modules rather than `unittest.TestCase` classes. Run all modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

### Release verification record

| Check | Result |
|---|---|
| Semantic version | `v0.3.0` selected; no earlier repository tag existed |
| Regression | 14/14 executable test modules passed |
| Live demo | SSH threshold, one Ollama analysis, analyst lifecycle, response simulation, and audit passed |
| Storage | Final demo alert matched between SQLite and JSON |
| Audit | Hash chain returned `(True, 'Audit chain is valid')` |
| Clean clone | Required files present and `docker compose --profile train config --quiet` passed |
| Secret review | Latest 30 commits: no known token/private-key pattern; `.env`, `data/`, and `logs/` are untracked |
| Runtime | Agent/dashboard and `/health` healthy |

The clean-clone check intentionally validated configuration without rebuilding a second image on the release machine. The commands above document the full first-time build path.

### Known limitations

- This is an educational single-node lab, not a production SIEM, EDR, firewall, or high-availability service.
- Response modes record allowlisted workflow actions; `simulation` makes no host change, and no production executor is bundled.
- Ollama Cloud uses one shared worker. Alerts arriving while it is busy are marked `busy`; there is no durable AI queue or local Ollama fallback.
- AI wording and confidence are nondeterministic. Analysts must validate evidence, and system severity remains authoritative.
- Coordination locks, login throttling, AI state, and some runtime settings are process-local and are not designed for multi-worker scaling.
- SQLite and JSON are local storage paths without clustering, multi-tenancy, or remote disaster recovery.
- Dashboard accounts use a local file store; SSO, MFA, password recovery, and a full user-administration UI are not included.
- TLS/reverse-proxy configuration is not bundled. Windows collector traffic must be placed behind HTTPS on untrusted networks.
- Windows collection is polling-based and covers a selected Sysmon/Security/Defender subset, not every channel or event ID.
- NIDS packet visibility is Linux-oriented. Docker Desktop normally cannot observe all physical Windows host traffic.
- Detection and local ML models are lab baselines and may produce false positives or miss attacks outside their training/rule coverage.
- Webhooks are best-effort generic/Discord notifications, not a durable case-management integration.

### Release operation

The release commit is tagged locally with annotated tag `v0.3.0`. Publishing the branch and tag remains an explicit repository-owner action:

```bash
git push origin feature/blue-team-baseline
git push origin v0.3.0
```
