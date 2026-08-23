# Manual Detection Checklist

Run the simulator with `python tools/attack_sim.py`, then confirm the expected alert in the dashboard coverage table or `/api/detection-coverage`.

| Mode | Scenario | Expected rule ID | Pass criteria |
|---|---|---|---|
| 1 | SSH brute force | `DET-SSH-001` | One HIGH alert after the configured threshold; hit count increases. |
| 2 | Sudo privilege escalation | `DET-LNX-001` | One MEDIUM alert; hit count increases. |
| 3 | ML/NLP anomaly | None | An AI anomaly may appear; YAML rule coverage is unchanged. |
| 4 | Mixed SSH + sudo | `DET-SSH-001`, `DET-LNX-001` | Both rule hit counts increase. |
| 5 | TCP SYN scan | `DET-NET-001` | One HIGH NIDS alert; runtime hit count increases. |
| Manual | Account creation log containing `new user: name=` | `DET-LNX-002` | One LOW alert; hit count increases. |

Also verify:

- Every configured rule appears, including rules with `0` hits as `NEVER HIT`.
- The MITRE summary counts unique configured techniques and techniques with at least one hit.
- Each rule-generated alert contains the expected `rule_id`.

Runtime hit counts prove that a rule fired in this installation; they do not prove deterministic behavior. The offline positive/negative corpus and its latest results are tracked separately in the generated [validation coverage matrix](docs/DETECTION_VALIDATION_COVERAGE.md).
