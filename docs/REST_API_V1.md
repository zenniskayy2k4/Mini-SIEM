# REST API v1

Mini-SIEM's supported REST contract is rooted at `/api/v1`. The original
unversioned paths remain temporary compatibility aliases and return
`Deprecation: true` plus a `Link` header pointing to the v1 successor.

All v1 routes reuse the existing handlers, authentication, role checks, CSRF
protection, request limits, status codes, and response bodies. M28.2 versions
the alert payload itself; see [Alert Schema v1](ALERT_SCHEMA.md). The
[OpenAPI 3.1 contract](openapi-v1.yaml) is the machine-readable source for
supported paths and methods, session/CSRF requirements, roles, errors,
pagination, field bounds, and request-body limits. CI rejects drift between
that contract and the registered Flask v1 routes.

## Supported v1 routes

| Resource | Methods and paths | Access |
|---|---|---|
| Alerts | `GET /api/v1/alerts`, `GET /api/v1/alerts/search` | Authenticated |
| Incident workflow | `PATCH /api/v1/alerts/{alert_id}/status`, `PATCH .../assignee`, `POST .../notes`, `POST .../feedback` | Analyst |
| Response actions | `POST /api/v1/alerts/{alert_id}/response-actions`, `POST .../{action_id}/approve`, `POST .../{action_id}/rollback` | Analyst |
| Reports and export | `GET /api/v1/alerts/{alert_id}/report.pdf`, `POST .../external-case` | Authenticated / analyst |
| Assets | `GET, POST /api/v1/assets`, `GET, PATCH, DELETE /api/v1/assets/{asset_id}` | Admin |
| Detection rules | `GET /api/v1/detection-rules`, `PATCH /api/v1/detection-rules/{rule_id}` | Admin |
| Detection policy | `GET, POST /api/v1/detection-exceptions`, `DELETE .../{exception_id}` | Admin |
| Suppression policy | `GET, POST /api/v1/alert-suppression-policies`, `DELETE .../{policy_id}` | Admin |
| Detection coverage | `GET /api/v1/detection-coverage` | Authenticated |
| SOC analytics | `GET /api/v1/analytics/kpis` | Authenticated |
| System status | `GET /api/v1/system/status` | Admin |

Path parameters are URL path segments. Search, filtering, pagination, request
limits, and error behavior are unchanged from the corresponding compatibility
alias. JSON errors use `{"error": "message"}`. Authentication failures return
401, authorization failures 403, invalid input 400/413, missing resources 404,
conflicts 409, and unavailable dependencies 5xx as appropriate.

## Endpoint inventory and classification

| Existing surface | Classification | v1 status |
|---|---|---|
| Alert, incident workflow, response, report, and external-case routes | Supported REST API | Versioned |
| Asset, detection-rule, exception, and suppression-policy routes | Supported REST API | Versioned |
| `/api/analytics/kpis`, `/api/detection-coverage`, `/api/system/status` | Supported REST API | Versioned |
| `/api/stats`, `/api/graph`, `/api/detection-tuning` | Dashboard-internal read model | Unversioned internal |
| `/api/settings`, `/api/settings/update`, `/api/admin/workspace`, `/api/admin/users/...` | Dashboard-internal administration | Unversioned internal |
| `/api/windows-events` | Collector machine API | Separately versioned by [COLLECTOR_PROTOCOL.md](COLLECTOR_PROTOCOL.md) |
| `/health`, `/metrics` | Operational endpoints | Outside the REST API namespace |

Internal endpoints may change with the bundled dashboard and are not part of
the v1 compatibility promise.

## Compatibility and deprecation

- New API clients should use `/api/v1/...`.
- Existing `/api/...` aliases remain available during the v1.0 transition.
- Alias responses advertise their v1 successor; v1 responses do not carry a
  deprecation header.
- Removing aliases requires a separately announced release and migration note.
