# Sigma rule support

Mini-SIEM loads a deliberately small, offline subset of Sigma rules. Native rules in `config/rules/` remain supported; Sigma rules live separately in `config/sigma/` and use their Sigma UUID as both `rule_id` and `sigma_rule_id`.

## Import and lifecycle

1. Copy a `.yml` or `.yaml` Sigma rule into `config/sigma/`. The loader also accepts multiple YAML documents in one file.
2. Restart the agent and dashboard after adding, removing, or editing Sigma source files:

   ```bash
   docker compose restart agent dashboard
   ```

3. Sign in as an administrator and open **Settings → Detection Rules**. The table shows Native/Sigma source, validation status, last load time, hit count, never-hit state, and the enable/disable action.

Supported Sigma rules are enabled by default. Enable/disable overrides are written atomically to `data/sigma_rule_states.json`; the agent detects that file change and reloads its active rules. Sigma source files remain read-only inside the containers.

## Supported phase-1 subset

Only `logsource.product: windows` is translated. These field mappings are supported:

| Sigma field | Normalized Mini-SIEM field |
|---|---|
| `EventID` | `event_id` |
| `Image`, `NewProcessName`, `ProcessName` | `process_image` |
| `CommandLine`, `ProcessCommandLine` | `command_line` |
| `ParentImage`, `ParentProcessName` | `parent_image` |
| `TargetImage` | `target_image` |
| `GrantedAccess` | `granted_access` |
| `User`, `UserName`, `TargetUserName`, `SubjectUserName` | `user` |
| `TaskName` | `task_name` |
| `TaskContent` | `task_content` |
| `NewValue` | `defender_setting` |

Supported value and condition forms:

- A field without a modifier performs exact matching.
- `contains`, `startswith`, `endswith`, and `contains|all`.
- Scalar values and flat lists of scalar values. A normal list is OR; `contains|all` requires every listed value.
- Keyword selections as one string or a flat string list.
- `selection`.
- `selection and filter` and `selection and not filter`.
- `selection1 or selection2`.

Matching is case-insensitive because the translated rule uses the existing Mini-SIEM regex engine.

## Unsupported syntax

Unsupported rules are retained in the admin catalog as disabled with `validation_status: unsupported` and an explicit `skip_reason`; they never enter the active detector. Phase 1 rejects:

- non-Windows logsources;
- unknown fields;
- modifiers other than the supported list, including `re`;
- wildcard values containing `*` or `?`;
- null, empty, or nested selection values;
- condition lists, parentheses, aggregation, correlation, `1 of ...`, `all of ...`, or more complex boolean expressions;
- `or not` conditions;
- rules whose Sigma status is `deprecated` or `unsupported`.

Malformed YAML, invalid UUIDs, missing required metadata, and duplicate Sigma UUIDs are skipped individually and reported in the service logs instead of stopping the agent.

## Example

```yaml
title: Suspicious PowerShell Execution
id: 7c4f8f2e-1e7b-4d95-9f76-8c731fef60a3
status: experimental
description: Detects PowerShell launched with an encoded command option.
author: Mini-SIEM
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -encodedcommand '
  condition: selection
level: high
```

The complete sample is [config/sigma/suspicious_powershell.yml](../config/sigma/suspicious_powershell.yml). Raw Sigma `detection` metadata is preserved after translation.

## Alert provenance

An alert created by a translated Sigma rule includes:

```json
{
  "rule_id": "7c4f8f2e-1e7b-4d95-9f76-8c731fef60a3",
  "rule_source": "sigma",
  "sigma_rule_id": "7c4f8f2e-1e7b-4d95-9f76-8c731fef60a3"
}
```

Native alerts use `rule_source: native` and `sigma_rule_id: null`. Sigma title, author, references, tags, logsource, level, raw detection, and source filename remain available in the loaded rule catalog.

## Debug procedure

1. Validate the loader and inspect every rule state without starting the stack:

   ```bash
   docker compose run --rm -v "${PWD}:/app" dashboard python -c "from config import config; from src.sigma import load_sigma_rules; rules, errors = load_sigma_rules(config.SIGMA_RULES_DIR); print([(r['id'], r['enabled'], r['validation_status'], r['skip_reason']) for r in rules]); print(errors)"
   ```

2. Inspect loader warnings:

   ```bash
   docker compose logs agent dashboard
   ```

   Search for `Sigma rule disabled`, `Sigma rule skipped`, or `Duplicate Sigma id`.

3. Run the offline Sigma regression corpus against the current source tree:

   ```bash
   docker compose run --rm -v "${PWD}:/app" dashboard python -m tests.test_sigma_corpus
   ```

4. In **Settings → Detection Rules**, confirm `validation_status`, hover the row to read `skip_reason`, and verify the expected hit count. `GET /api/detection-rules` exposes the same catalog to an authenticated administrator.

5. If a newly imported rule is absent, confirm its extension, UUID, required `logsource`/`detection` fields, and restart both services. If a supported rule is present but does not match, compare its fields with the normalized text produced by `src.windows_events.windows_event_text`.

## Known limitations

- This is not a complete Sigma implementation and does not use pySigma pipelines or backends.
- Only normalized Windows events are supported in phase 1.
- Source-file changes require an agent/dashboard restart; enable/disable overrides reload live.
- The detector returns the first matching rule, not every matching rule.
- Lifecycle overrides are shared through one local `data/` mount; multi-node coordination is not implemented.
- Malformed rules are logged but do not appear in the lifecycle table because they cannot produce a valid catalog record.
