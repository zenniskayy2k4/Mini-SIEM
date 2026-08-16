# Mini-SIEM v0.3.0 Release Checklist

`v0.3.0` is the first versioned Blue Team portfolio release. The minor version reflects substantial new detection, incident, storage, response, Windows, and reliability capabilities while the project remains pre-1.0 and lab-focused.

## Clean-clone setup

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

## Regression command

The tests are executable modules rather than `unittest.TestCase` classes. Run all modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

## Release verification record

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

## Known limitations

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

## Release operation

The release commit is tagged locally with annotated tag `v0.3.0`. Publishing the branch and tag remains an explicit repository-owner action:

```bash
git push origin feature/blue-team-baseline
git push origin v0.3.0
```
