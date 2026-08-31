# Large-history Benchmark

M26.3 exercises the retained-alert storage and serialization paths against one
isolated SQLite database grown from 10k to 50k and 100k alerts. Retention runs
on a temporary database copy; no live data, network, AI, or JSON mirror is used.

Run it with:

```text
python tools/benchmark_large_history.py
```

### Local results — 2026-08-31

| Path | 10k | 50k | 100k |
|---|---:|---:|---:|
| Alert API storage + JSON serialization | 2.688 ms | 9.550 ms | 18.928 ms |
| Filtered search | 7.137 ms | 23.533 ms | 47.741 ms |
| SOC KPI + analytics | 249.202 ms | 1362.291 ms | 2733.217 ms |
| Rule coverage | 33.878 ms | 164.115 ms | 332.495 ms |
| Open-incident workspace | 40.623 ms | 180.851 ms | 373.895 ms |
| Incident PDF report | 0.451 ms | 0.414 ms | 0.434 ms |
| Backup, archive, retention delete, and vacuum | 454.012 ms | 2187.567 ms | 4586.949 ms |

The 100k database occupied about 149 MiB. All paths returned valid results;
retention archived 47,500 old terminal/non-incident alerts and preserved 2,500
old open incidents. Analytics is the measured ceiling at 2.73 seconds. Keep the
current implementation until an operator SLA requires a lower ceiling, then
profile its JSON aggregate scans before adding more indexes or summary tables.
