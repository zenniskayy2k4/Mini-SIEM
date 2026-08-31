# SQLite Query Plan Audit

M26.1 measures representative plans on SQLite with 5,000 alerts, incidents,
events, and feedback records plus 10,000 assets. Dashboard analytics use the
default 24-hour range. Timings are local medians per completed query and are
evidence for index selection, not a cross-machine benchmark.

| Query path | Before | After | Local ms before → after | Decision |
|---|---|---|---:|---|
| Alert list | Timestamp index plus temporary order | `idx_alerts_timestamp_id`, no temporary order | 0.046 → 0.026 | Replace single-column timestamp index |
| Time range | Ordered index scan | Bounded range search on `idx_alerts_timestamp_id` | 0.057 → 0.027 | Compare normalized ISO timestamps directly |
| Severity | Ordered scan | Search and order on `idx_alerts_severity_timestamp_id` | 0.049 → 0.028 | Replace single-column severity index |
| Incident status | Ordered alert scan plus indexed incident join | Same ordered path | 0.496 → 0.358 | Keep fallback semantics; status-first index was slower |
| Rule coverage | Search using `idx_alerts_rule_id` | Unchanged | 0.358 → 0.384 | Existing expression index is sufficient |
| KPI range | Range search using `idx_alerts_created_at` | Unchanged | 0.066 → 0.067 | Existing index is sufficient |
| Analytics top rules | Created-at range plus bounded group/order temp trees | Unchanged | 0.159 → 0.162 | Grouping work is expected; no speculative index |
| False-positive trend | Timestamp range then event filter | Event-type and timestamp range search | 0.048 → 0.016 | Add `idx_incident_events_type_timestamp` |
| Assets | Ordered hostname index scan | Unchanged | 3.050 → 3.259 candidate | Reject enabled composite index; it was slower |
| Feedback/rule quality | Materialize and scan all feedback | Created-at scope plus indexed latest-feedback lookup | 5.438 → 0.317 | Rewrite query; reuse existing indexes |

`EXPLAIN QUERY PLAN` regression checks require the selected index names, reject
temporary ordering for alert lists, and prevent a full feedback-table scan.
Migration 2 replaces the two superseded alert indexes and adds the event index;
operators apply it with the existing backup-first migration command.
