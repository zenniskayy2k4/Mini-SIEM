# Mini-SIEM Pro — AI-Assisted Blue Team Lab

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-Dashboard-black?style=flat-square&logo=flask)
![Ollama](https://img.shields.io/badge/Ollama-Cloud_AI-white?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![Release](https://img.shields.io/badge/release-v0.4.0-2ea44f?style=flat-square)
[![CI](https://github.com/zenniskayy2k4/Mini-SIEM/actions/workflows/ci.yml/badge.svg)](https://github.com/zenniskayy2k4/Mini-SIEM/actions/workflows/ci.yml)

A compact, explainable SIEM lab for learning blue-team workflows. It combines YAML signatures, local anomaly models, event correlation, an optional Ollama Cloud analyst, an authenticated incident dashboard, and safe response simulation.

> **Educational use only.** Run it only on systems and networks you own or are authorized to monitor. It is not a production EDR, firewall, or replacement for a staffed SOC.

Current release: **v0.4.0** — see the [changelog](CHANGELOG.md) and [release checklist](docs/RELEASE_v0.4.0.md).

## What is implemented

- Native YAML and supported Sigma detection rules with MITRE ATT&CK mappings and reloadable rule state.
- CI-backed baseline, Docker smoke, security, and release gates.
- HIDS log monitoring, Linux-oriented packet capture, honeypot events, and multi-event correlation.
- Offline Windows/Sysmon import plus authenticated collector ingestion.
- TF-IDF/Isolation Forest and autoencoder anomaly signals alongside deterministic rules.
- Ollama Cloud triage through one shared worker; detection continues while the worker is busy or AI is unavailable.
- SQLite as the primary alert store, with JSON dual-write/fallback during migration.
- Admin-only asset inventory with validated CRUD, hostname/IP lookup, filters, criticality, ownership, tags, and immutable audit events.
- Incident lifecycle, notes, assignee, timeline, audit trail, role-based access, and CSRF protection.
- Proposed response actions, approvals, simulation, rollback metadata, and optional webhook notifications.
- Normalized GeoIP, optional AbuseIPDB/VirusTotal metadata, and offline STIX/TAXII indicator matching.
- Health/status diagnostics, retention, SQLite backup, and log rotation tooling.

## Architecture

```mermaid
flowchart LR
    Linux[Linux logs] --> Agent[Mini-SIEM agent]
    Windows[Windows/Sysmon collector] -->|shared-secret ingest| Ingest[Windows ingest API]
    Ingest --> WinFile[(windows_events.jsonl)]
    WinFile --> Agent
    NIDS[NIDS packet capture] --> Agent
    Honey[Honeypot events] --> Agent

    Agent --> Rules[YAML rules]
    Agent --> NLP[TF-IDF + Isolation Forest]
    Agent --> AE[Autoencoder]
    Rules --> Pipeline[Alert pipeline]
    NLP --> Pipeline
    AE --> Pipeline

    Pipeline --> Correlation[Correlation + incident lifecycle]
    Correlation --> TI["Threat intelligence<br/>GeoIP + reputation + STIX/TAXII"]
    TI --> SQLite[(SQLite)]
    TI --> JSON[(JSON fallback)]
    Correlation --> AI["Ollama Cloud<br/>shared 1-worker analyst"]
    Correlation --> Response[Safe response workflow]
    Correlation --> Webhook[Optional webhook]

    SQLite --> UI[Authenticated Flask dashboard]
    Agent -->|heartbeat| Health[Health diagnostics]
    UI --> Health
```

The dashboard and agent share mounted `data/`, `logs/`, `models/`, and read-only rule files when run with Docker Compose.

## Detection and severity model

The local detector remains authoritative. AI enrichment never silently rewrites the alert's `severity`.

| Local evidence | System decision |
|---|---|
| YAML rule plus both local ML signals | `CRITICAL` |
| YAML rule plus one local ML signal | Keep the rule severity and annotate the supporting signal |
| No rule, both local ML signals, confidence at least 40 | `CRITICAL` |
| No rule, one local ML signal | `HIGH` |

Ollama adds separate decision-support fields:

- `ai_recommended_severity` and `ai_disposition`, without changing `severity`.
- `escalate_to_human=true` recommends `CRITICAL` and human review.
- A high-confidence false-positive assessment (`fp_confidence >= 80`) recommends `LOW` with `FALSE_POSITIVE_SUSPECTED`; an analyst still makes the final decision.

## Quick start with Docker

Requirements: Docker Desktop with Compose, Git, and enough resources to run the local models. Ollama Cloud is optional.

```bash
git clone <repository-url>
cd Mini-SIEM
cp .env.example .env
docker compose --profile train run --rm train
docker compose up -d
```

Create the first dashboard administrator. The command prompts securely when `DASHBOARD_USER_PASSWORD` is not set:

```bash
docker compose exec dashboard python tools/manage_dashboard_user.py admin admin
```

Open <http://localhost:5000>, then sign in. Check service state with:

```bash
docker compose ps
curl http://localhost:5000/health
```

The local rule/ML pipeline works without an Ollama key. Training only needs to be rerun when models or training data change.

## Ollama Cloud setup

Copy `.env.example` to `.env` and set:

```dotenv
AI_PROVIDER=ollama_cloud
OLLAMA_API_KEY=your_ollama_cloud_key
OLLAMA_BASE_URL=https://ollama.com/api
OLLAMA_MODEL=gemma4:cloud
```

The analyst uses one shared worker because the configured Ollama service accepts one request at a time. If it is occupied, new eligible alerts are marked `busy` instead of building an unbounded queue. AI failures do not block alert creation.

The validated AI payload contains:

```text
is_false_positive, fp_confidence, threat_confidence,
mitre_tactic, mitre_technique, threat_summary,
observed_facts, analyst_inferences, recommended_playbook,
ioc_tags, escalate_to_human
```

Provider, model, analysis time, cache state, and the separate severity recommendation are added by the application. The dashboard system-status view reports AI availability and recent outcomes without making a probe call that would occupy the worker.

## Threat intelligence

Threat intelligence is contextual evidence only and never rewrites detector severity. Public IPs can receive GeoIP context; AbuseIPDB and VirusTotal remain disabled until their API keys are configured. VirusTotal performs hash metadata lookups only and never uploads, rescans, or downloads files.

STIX 2.1 bundles can be imported manually from a path visible inside the agent container:

```bash
docker compose exec agent python tools/import_stix.py /app/data/feed.json --source lab-feed
```

For TAXII 2.1, configure `TAXII_COLLECTION_URL`, optional `TAXII_BEARER_TOKEN`, feed source, and pull interval in `.env`. A one-off pull uses the same normalized store:

```bash
docker compose exec agent python tools/import_stix.py --taxii-url https://taxii.example/collections/lab/objects/ --source lab-taxii
```

The phase-1 STIX parser supports exact equality indicators for IPv4, domains, SHA-256, and MD5. It deduplicates per feed, ignores expired indicators, preserves source/confidence/labels, and bounds TAXII responses to 5 MiB and 10 pages.

## Dashboard roles

| Role | Access |
|---|---|
| `viewer` | View alerts, incidents, graphs, logs, and diagnostics |
| `analyst` | Viewer access plus incident status, assignee, notes, and response workflow |
| `admin` | Analyst access plus settings, rule administration, diagnostics, and maintenance-sensitive controls |

Sessions use HTTP-only cookies, server-side role checks, CSRF protection for mutations, and an append-only analyst audit log. Set `DASHBOARD_SESSION_SECRET` explicitly for stable deployments and enable `DASHBOARD_COOKIE_SECURE=true` only behind HTTPS.

## Response safety

`RESPONSE_MODE=simulation` is the default. Actions such as `BLOCK_IP`, `DISABLE_USER`, and `QUARANTINE_FILE` are proposed and audited but do not alter the host. Protected targets, approval expiry, execution records, and rollback metadata remain enforced by the workflow.

This repository does not execute arbitrary AI-generated commands. Treat manual or automatic modes as workflow labels for the lab until a separately reviewed, least-privilege executor is integrated.

Optional high-risk notifications can be sent to a generic or Discord webhook. Leave `NOTIFICATION_WEBHOOK_URL` empty to disable them.

## Windows and Sysmon collection

Offline exports (`.json`, `.jsonl`, `.ndjson`, `.xml`, or `.evtx`) can be normalized with:

```bash
python tools/import_windows_events.py evidence.evtx --output data/windows_events.jsonl
```

For continuous collection, run `tools/windows_event_collector.ps1` on the Windows host and configure the same random `WINDOWS_COLLECTOR_SECRET` on the collector and dashboard. The current mappings focus on selected Sysmon process, network, image-load, access, file, and registry events plus selected Security/Defender events.

Limitations:

- The collector is polling-based and intentionally covers a blue-team lab subset, not every Windows event channel or Sysmon event ID.
- Event access depends on Windows privileges, channel availability, and the local Sysmon configuration.
- Transport should be placed behind HTTPS before it crosses an untrusted network; a shared secret alone does not encrypt traffic.

## NIDS limitations on Windows and Docker Desktop

The Compose agent uses host networking and privileged packet capture, which is primarily a Linux configuration. On native Windows, packet capture generally requires Npcap and an elevated process. Under Docker Desktop, the agent normally observes networking visible inside its Linux VM/container environment, not every packet on the physical Windows host.

For meaningful NIDS testing, prefer a Linux host/VM with an explicitly selected interface or feed mirrored traffic to a dedicated sensor. Keep HIDS and Windows event collection enabled when full host packet visibility is unavailable.

## Operations and testing

- `GET /health` provides an unauthenticated liveness/readiness summary; authenticated admins can use `/api/system/status` for richer diagnostics.
- Retention, backup, restore verification, and log rotation are documented in [Retention and backup](docs/RETENTION_BACKUP.md).
- The supported Sigma subset, import flow, provenance, and debugging steps are in [Sigma rule support](docs/SIGMA_RULES.md).
- Detection coverage and manual checks are tracked in [Detection checklist](DETECTION_CHECKLIST.md).
- The portfolio-ready workflow is in [End-to-end Blue Team demo](docs/DEMO_SCENARIO.md).
- Release changes and verification are in the [changelog](CHANGELOG.md) and [v0.4.0 checklist](docs/RELEASE_v0.4.0.md).
- Every future tag must pass the [CI-backed release checklist](docs/RELEASE_CHECKLIST.md).
- The completed v0.3 history is in the [Blue-team development plan](docs/MINI_SIEM_BLUE_TEAM_DEVELOPMENT_PLAN.md); active work continues in the [v0.4–v0.6 roadmap](docs/MINI_SIEM_CONTINUATION_ROADMAP_v0.4_to_v0.6.md).

Useful commands:

```bash
# Run every executable regression module in the existing image
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'

# Generate authorized lab traffic/events
docker compose exec agent python tools/attack_sim.py

# Back up SQLite or apply retention offline
docker compose run --rm dashboard python -m tools.maintenance backup
docker compose run --rm dashboard python -m tools.maintenance retention --days 90
```

## Project layout

```text
Mini-SIEM/
├── config/rules/                 # Native YAML detections and MITRE metadata
├── config/sigma/                 # Supported Sigma rule subset
├── docs/                         # Operational runbooks
├── models/                       # Trained local anomaly models
├── src/                          # Detection, storage, AI, response, and health modules
├── static/ and templates/        # Authenticated Flask dashboard
├── tests/                        # Regression and workflow tests
├── tools/                        # Training, import, users, rules, maintenance, simulation
├── dashboard.py                  # Dashboard/API entry point
├── main.py                       # Sensor/agent entry point
└── docker-compose.yml
```

## Dashboard

![Authenticated dashboard overview](assets/Dashboard.jpeg)

## Near-term roadmap

- Asset inventory and deterministic, explainable risk context.
- SOC metrics, incident reporting, and AI provider resilience.
- TLS/reverse-proxy deployment guidance and stronger secret management.
- Production-grade response integrations, after explicit approval and least-privilege design.

Contributions should keep detections explainable, failure modes observable, and response actions safe by default.
