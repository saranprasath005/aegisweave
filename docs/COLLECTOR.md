# Durable Zeek JSON collector

The `collect` command reads existing Zeek JSON connection logs, queues normalized events in a local SQLite spool, and forwards them to AegisWeave. It does not install Zeek, configure network mirroring, or capture packets.

From the project root, with a configured API credential in `AEGISWEAVE_TOKEN`:

```powershell
.\.venv\Scripts\python.exe -m aegisweave collect --source "C:\ZeekLogs\conn*.log" --sensor office-gateway --spool var/office-collector.db --url https://nids.example.org
```

Replace the source path and API origin with the actual deployment values. For local lab use, `--url http://127.0.0.1:8765` supports the loopback demo session. Add `--simulated` for constructed fixtures; that choice is persisted with the spool so it cannot change silently after restart. Tokens are read from the environment, not command arguments or logs.

Zeek must write JSON, for example using `redef LogAscii::use_json = T;` in the site configuration. This is documented in the [Zeek logging framework](https://docs.zeek.org/en/master/frameworks/logging.html). This command does not accept TSV; existing `replay --format zeek-tsv` remains available for recorded TSV input.

## Recovery contract

- A committed source byte offset and its queued event are written in the same transaction with SQLite full synchronous durability. Restart resumes from that offset.
- Only complete newline-terminated records are consumed. Malformed or unrepresentable records advance the cursor with a rejection counter and bounded error history. Original logs must be retained for investigation.
- Delivery is at least once. The same sensor/Zeek UID/timestamp produces the same event ID; an API duplicate response acknowledges a previously stored event. API event retention therefore bounds deduplication across very long outages.
- Pending events are removed only after a matching success or duplicate acknowledgment. Network errors and unsuccessful HTTP responses retain them. Retry delay grows up to 60 seconds; numeric server Retry-After values are honored up to 300 seconds.
- `--max-pending` defaults to 100,000 records. Intake pauses when full; delivery continues. This is a record-count bound, not a byte-capacity guarantee. Size disk storage and source retention from measured traffic.
- One process owns a spool. The source glob, sensor name, and simulated flag must match on restart. Give separate sensors separate spool files.
- Rename/create rotation is supported when all unread rotated files remain uncompressed and match the source glob. Do not delete, move out of the glob, compress, copy/truncate, or modify source logs while unread bytes remain. Prefix/size checks report detected rewrites; they cannot establish that an arbitrary rewrite or deleted unread file never lost data.
- Files are visited by modification time and path, and records within a file retain arrival order. This is not a globally ordered merge across independently written files. The existing behavior engine handles bounded event-time lateness.

The command prints JSON status: cumulative queued, delivered, duplicate and rejected counts; pending backlog; recent parse failures; source/delivery errors; and backpressure. A permanent API rejection stops the front batch from draining and requires operator attention rather than silently discarding events. Oversized lines stop intake visibly. SQLite/disk failures exit the process, retaining committed work for restart.

Each cycle also atomically publishes `<spool>.status.json`, including its update time and oldest pending-event age. `python -m aegisweave collector-health --spool var/office-collector.db` exits nonzero for missing/stale status, source or delivery errors, backpressure, current-cycle rejections, or a backlog older than the configured limit. Defaults are 120 seconds for status freshness and 300 seconds for pending age; adjust `--max-age` and `--max-backlog-age` to the validated operational target. Legacy queued rows without timestamps are treated as old until delivered. Docker uses this check for collector health; it does not itself send operator notifications.

`--once` performs one bounded intake/delivery cycle for diagnostics. It is not a complete backlog-drain command. Continuous mode requires a process supervisor for automatic restart; an OS service installation and sustained site load test are still pending. Source and spool directories should be writable only by their respective trusted service accounts.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_ingest.py -q
.\.venv\Scripts\python.exe scripts/verify_collector.py
```

The latter starts a separate API with a temporary database and explicitly simulated input. It checks offline spooling, restart delivery, rename rotation, duplicate acknowledgments, and event counts over real HTTP. It does not touch the running dashboard database.
