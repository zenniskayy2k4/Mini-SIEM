# End-to-End Blue Team Demo

This scenario demonstrates detection, correlation, Ollama Cloud triage, analyst workflow, safe response simulation, and immutable audit evidence. It uses only the tools and UI already in the repository.

> Run the scenario only in an authorized lab. Keep `RESPONSE_MODE=simulation`; no host firewall rule is created.

## Evidence map

| Artifact | Location |
|---|---|
| Authenticated dashboard screenshot | [Dashboard overview](../assets/Dashboard.jpeg) |
| Architecture diagram | [README architecture](../README.md#architecture) |
| Sample alert and AI analysis | Reference-run JSON below |
| Incident timeline | Reference-run JSON below |
| Response evidence | `data/incident_responses.log` and sample below |
| Analyst audit | `data/analyst_audit.jsonl` and verification command below |

Runtime files under `data/` are intentionally not committed. The samples below were captured from a live run on 2026-08-15 and shortened to stable, useful fields.

## 1. Prepare the lab

Confirm these `.env` values:

```dotenv
AI_PROVIDER=ollama_cloud
OLLAMA_API_KEY=your_ollama_cloud_key
OLLAMA_BASE_URL=https://ollama.com/api
OLLAMA_MODEL=gemma4:cloud
RESPONSE_MODE=simulation
```

Start and verify the existing stack:

```bash
docker compose up -d
docker compose ps
curl http://localhost:5000/health
```

Use an existing `analyst` or `admin` account. To create a dedicated demo analyst, run the following command and enter a unique password when prompted:

```bash
docker compose exec dashboard python tools/manage_dashboard_user.py demo-analyst analyst
```

## 2. Inject an SSH failed-login campaign

Run the repository simulator:

```bash
docker compose exec agent python tools/attack_sim.py
```

Select mode `1`, note the source IP printed by the simulator, then select `q`. The simulator writes repeated failed SSH logins to the watched log; it sends no network packets in this mode.

Expected detector result with the bundled configuration:

- Rule `DET-SSH-001` triggers at 5 failures in 60 seconds.
- The alert is `HIGH`, maps to `T1110.001`, and contains an `event_count` campaign total.
- Later failures from the same active campaign update that alert instead of occupying the Ollama worker again.

Watch the agent until the single Ollama call finishes:

```bash
docker compose logs --since 5m agent
```

Look for an entry similar to:

```text
[AIAnalyst] SSH Brute Force Attempt → FP=False (fp_conf=20%) threat_conf=80%
```

If the alert says `ai_analysis.skipped=busy`, let the current call finish and repeat mode `1`. The shared analyst intentionally has no backlog.

## 3. Investigate and respond

Open <http://localhost:5000/logs>, sign in as an analyst, and filter by the source IP printed by the simulator.

Verify the evidence before changing the incident:

1. Alert name is `SSH Brute Force Attempt` and rule is `DET-SSH-001`.
2. `severity` remains the detector decision. With the bundled models in the reference run it remained `HIGH`.
3. Ollama places its separate decision in `ai_recommended_severity` and `ai_disposition`.
4. The raw log, event count, target users, first/last seen values, and MITRE mapping support the conclusion.

Then perform the analyst workflow in the incident panel:

1. Add a note describing the validated failed-login evidence.
2. Change status from `NEW` to `INVESTIGATING`.
3. Select `BLOCK_IP`, retain the detected source IP as target, and choose **Request action**.
4. Confirm the result is `SIMULATED` and says it *would* block the IP.
5. Change the incident to `RESOLVED`.

The response request is allowlisted and target-validated. It records intent and result but executes no shell command or firewall change.

## 4. Verify audit and response evidence

Verify the append-only audit hash chain:

```bash
docker compose exec dashboard python -c "from src.audit import verify_audit_log; print(verify_audit_log())"
```

Expected result:

```text
(True, 'Audit chain is valid')
```

Review the most recent response records:

```bash
docker compose exec dashboard sh -c 'tail -n 5 /app/data/incident_responses.log'
```

The analyst audit should contain `NOTE_ADDED`, both `STATUS_CHANGED` transitions, `RESPONSE_REQUESTED`, and `RESPONSE_EXECUTED` with outcome `SIMULATED`. Audit records store event metadata, not note text or the response target.

## Reference run artifacts

### Alert and AI analysis

```json
{
  "alert_name": "SSH Brute Force Attempt",
  "severity": "HIGH",
  "source_type": "HIDS_LOG",
  "rule_id": "DET-SSH-001",
  "mitre_attck_id": "T1110.001",
  "ip_address": "192.0.2.240",
  "event_count": 5,
  "incident_status": "NEW",
  "ai_recommended_severity": "CRITICAL",
  "ai_disposition": "REQUIRES_HUMAN_REVIEW",
  "ai_analysis": {
    "is_false_positive": false,
    "fp_confidence": 20,
    "threat_confidence": 80,
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110.001 - Password Guessing",
    "observed_facts": [
      "Source IP 192.0.2.240 attempted 5 SSH logins within 60 seconds",
      "Target user 'demo' is identified as an invalid user"
    ],
    "analyst_inferences": [
      "The invalid username pattern is consistent with automated guessing."
    ],
    "recommended_playbook": [
      "Block the source IP at the network firewall.",
      "Review SSH logs for successful logins from the same source."
    ],
    "ioc_tags": ["192.0.2.240"],
    "escalate_to_human": true,
    "provider": "ollama_cloud",
    "model": "gemma4:cloud",
    "cached": false
  }
}
```

AI wording and confidence can vary between runs. Pass criteria are that its output follows the validated contract, cites observed evidence, and remains separate from authoritative system severity.

### Incident timeline and response

```json
{
  "incident_status": "RESOLVED",
  "timeline": [
    {"event_type": "NOTE_ADDED", "author": "demo-analyst"},
    {"event_type": "STATUS_CHANGED", "from_status": "NEW", "to_status": "INVESTIGATING"},
    {
      "event_type": "RESPONSE_ACTION_SIMULATED",
      "action_type": "BLOCK_IP",
      "target": "192.0.2.240",
      "status": "SIMULATED"
    },
    {"event_type": "STATUS_CHANGED", "from_status": "INVESTIGATING", "to_status": "RESOLVED"}
  ],
  "response_action": {
    "action_type": "BLOCK_IP",
    "target": "192.0.2.240",
    "mode": "simulation",
    "status": "SIMULATED",
    "result": "would execute BLOCK_IP on 192.0.2.240"
  }
}
```

### Audit summary

```json
[
  {"event_type": "NOTE_ADDED", "actor": "demo-analyst", "outcome": "SUCCESS"},
  {"event_type": "STATUS_CHANGED", "details": {"from": "NEW", "to": "INVESTIGATING"}},
  {"event_type": "RESPONSE_REQUESTED", "details": {"action_type": "BLOCK_IP"}},
  {"event_type": "RESPONSE_EXECUTED", "outcome": "SIMULATED"},
  {"event_type": "STATUS_CHANGED", "details": {"from": "INVESTIGATING", "to": "RESOLVED"}}
]
```

## Pass criteria

- One correlated SSH incident is visible for the simulator source IP.
- Local severity and the separate AI recommendation are both visible.
- Ollama performs one analysis for the campaign; the worker backlog remains zero.
- Note and status changes persist in SQLite and the JSON fallback.
- `BLOCK_IP` finishes as `SIMULATED`; the host network is unchanged.
- The incident reaches `RESOLVED` and the audit chain verifies successfully.
