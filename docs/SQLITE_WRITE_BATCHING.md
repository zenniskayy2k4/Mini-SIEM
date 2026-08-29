# SQLite Write Batching

M26.2 measured 300 alert writes on the isolated Docker runtime. Each result is
the median of three runs against a new temporary database and JSON mirror.

| Workload | Single transaction per alert | Batch 10 | Improvement |
|---|---:|---:|---:|
| SQLite telemetry | 716.394 ms | 79.178 ms | 88.9% |
| SQLite incidents | 656.656 ms | 80.011 ms | 87.8% |
| Dual-write telemetry | 1647.538 ms | 916.059 ms | 44.4% |
| Dual-write incidents | 1621.251 ms | 1026.301 ms | 36.7% |

The runtime therefore batches SQLite writes in FIFO groups of 10 or after a
50 ms maximum delay. The queue is bounded by the existing ingestion capacity.
Reads flush pending work for read-after-write consistency, and shutdown drains
the queue. Async batching is used only while the durable JSON mirror is enabled;
SQLite-only mode remains synchronous.

The defaults can be calibrated with `SQLITE_WRITE_BATCH_SIZE` and
`SQLITE_WRITE_FLUSH_SECONDS` without adding a dependency or external service.
