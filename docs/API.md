# AegisWeave API and backend operations

AegisWeave serves its dashboard and JSON API from one FastAPI process, normally at `http://127.0.0.1:8765`. Its only response adapter is a simulation ledger. Blocking, isolation and notification records never invoke a shell, alter a firewall, modify a host or send an external message.

## Authentication and roles

Set one or more environment variables before starting the server: `AEGISWEAVE_ADMIN_TOKEN`, `AEGISWEAVE_ANALYST_TOKEN`, `AEGISWEAVE_VIEWER_TOKEN`. Use distinct randomly generated secrets of at least 24 characters. The server rejects short, duplicate or invalid role configurations. Send a configured secret as `Authorization: Bearer <secret>`; do not place secrets in URLs. Viewer can read dashboards and evidence. Analyst can ingest telemetry, investigate audits, propose responses, approve responses and roll back responses. Admin additionally changes policy and reloads the verified model. Tokens identify a role; this prototype does not implement per-person accounts, SSO or token revocation without restarting.

When **no role tokens are configured**, the server generates an unpredictable session token in memory and exposes it through `GET /api/session`. This convenience mode grants local demo administration and rejects every request unless the peer address and Host header are loopback/localhost. It also rejects Forwarded and X-Forwarded-* headers. A browser from another origin cannot obtain the session or make mutations. The token changes on each server creation. Configured authentication disables this session endpoint; an authenticated `GET /api/identity` returns the current role.

Requests with an Origin header must match the server origin for session acquisition and unsafe methods. Cross-site Fetch Metadata is rejected for these operations. No CORS allowance is configured. Error responses omit raw malicious inputs. All responses include content-type protection, frame denial, no-store caching, a same-origin content-security policy and a restrictive permissions policy. The default service is loopback HTTP. For any deployment beyond a trusted local machine, provision TLS and operating-system access controls; a shared role token is not a production identity service.

## Routes

| Method and path | Minimum role | Behavior |
| --- | --- | --- |
| `GET /api/health` | Public within the perimeter | Minimal healthy/degraded status and simulation mode. |
| `GET /api/session` | Local demo only | Returns the ephemeral demo token, role and mode; 404 with configured tokens. |
| `GET /api/identity` | Viewer | Authenticated role and authentication mode. |
| `GET /api/openapi.json` | Viewer | Generated request schemas and route specification. |
| `GET /api/overview` | Viewer | Counts, decision trend, classes, confidence distribution and detailed health. |
| `GET /api/events` | Viewer | `limit` 1–500, optional `decision` and literal `search` filter. |
| `GET /api/events/{id}` | Viewer | Full intelligence, normalized telemetry and retained raw request evidence. |
| `GET /api/incidents`, `GET /api/incidents/{id}` | Viewer | Evidence groups with event-time timelines and correlation explanations. |
| `GET /api/models` | Viewer | Model registry plus active architecture version, fit ID/fingerprint and artifact digest. |
| `GET /api/behavior`, `GET /api/drift` | Viewer | Bounded host observations and drift state. |
| `GET /api/metrics` | Viewer | Detailed health, measured rates, latency, failures and process resources. |
| `GET /api/policies`, `GET /api/responses` | Viewer | Current response policy and simulation ledger. |
| `GET /api/audit` | Analyst | Structured audit entries; `limit` 1–500. |
| `POST /api/telemetry` | Analyst | Validate one normalized flow, process and persist it; return intelligence. |
| `POST /api/telemetry/batch` | Analyst | Process `{"events":[...]}` with 1–200 flows. |
| `POST /api/demo` | Analyst | Generate and process `{"count":120,"seed":42}` synthetic flows; count 1–200. |
| `POST /api/responses` | Analyst | Propose a simulated action against an existing event. |
| `POST /api/responses/{id}/approve` | Analyst | Recheck the current policy and approve a pending proposal. |
| `POST /api/responses/{id}/rollback` | Analyst | Clear an active simulation or cancel a pending proposal. |
| `PUT /api/policies` | Admin | Validate and persist the response policy, with audit. |
| `POST /api/models/reload` | Admin | Verify and load the configured local artifact, reset behavior/drift, and record lineage. |

List endpoints return `{"items":[...]}` except policy and metrics objects. The dashboard is `/`; its assets are `/static/*`. These static paths do not bypass the global demo perimeter.

## Ingestion contract and backpressure

Telemetry uses `schema.Flow`. IP addresses are validated and canonicalized. Timestamps require a timezone. Integers, counts, ports, rates and identifier lengths are bounded. Extra fields, attack labels and asset-criticality inputs are rejected. NaN/infinite values fail validation. The online API rejects timestamps more than five minutes beyond server time to limit future-watermark poisoning; historical replay and offline model evaluation remain supported. The original JSON request and normalized telemetry are retained separately. Labels, addresses, IDs, timestamps and simulation flags are not classifier features.

The process has one dedicated inference worker and a bounded FIFO of 1,024 events. This preserves causal processing order and protects the event loop from CPU-bound inference. Requests wait asynchronously for their event results. A full queue rejects a whole submission with 429 before enqueuing anything. Global API traffic is limited to 600 requests per peer per minute, with additional actor limits of 120 individual ingestions, 30 batches and 10 demo replays per minute. The bounded limiter keeps up to 4,096 client/actor buckets in memory. Deploy one application worker; separate worker processes would have separate temporal history and rate limits.

Event IDs are unique while retained. A duplicate is rejected **before inference**, avoiding a second behavior update. Duplicate requests return 409. Batches validate and reserve capacity together, but their inference/persistence is per event: a failure can follow successful commits. A 409/503 batch response reports `accepted`, the committed `event_ids`, and errors keyed by event ID. Retry only failed IDs. Once retention removes an event, its old ID is no longer protected against replay. The queue is memory-resident, so an abrupt process termination can lose accepted but uncommitted work; a client should reconcile IDs when a connection fails.

Statuses are 401 for missing/invalid tokens, 403 for role/perimeter/origin denial, 404 for missing evidence or disabled sessions, 409 for duplicate events or invalid response transitions, 413 for bodies over 2 MiB, 422 for invalid input, 429 for rate/queue limits, and 503 for unavailable inference or failed service operations. Request-size enforcement counts streamed bytes and does not trust Content-Length. Unexpected errors return a generic message and log the exception type; model paths and secrets are not returned.

## Response policy and safety

The policy defaults to `simulation=true`, `kill_switch=false`, allowlisted `127.0.0.0/8` and `::1/128`, five executions per minute, minimum risk 70, minimum confidence 0.8, and a 300-second maximum lease. `simulation` is a strict literal true: false, strings and numeric substitutes are rejected. IPv4-mapped IPv6 addresses cannot bypass IPv4 allowlists. Network actions are constrained to `block_source`, `isolate_host` and `notify`.

Containment needs a malicious decision, sufficient risk and confidence, an unprotected source, an available retained event, no kill switch, available execution-rate capacity and human approval. It enters `pending_approval` first. `notify` records a simulated notification directly after applicable checks; it sends nothing. Denied proposals are also recorded. Pending proposals are bounded by a separate proposal rate of twice the configured execution limit.

Example request: `{"event_id":"existing-event-id","action":"block_source","reason":"Reviewed correlated flow evidence","ttl_seconds":300}`. Approval and rollback requests are `{"reason":"Analyst review completed"}`. Reasons are printable text, 3–1,000 characters. The same analyst may propose and approve; this is human approval, not a two-person separation-of-duties system.

Approval checks the **current** allowlist, evidence, kill switch, thresholds and execution rate. A shorter current TTL shortens the remaining lease; approval never extends proposal expiry. Missing retained evidence or an expired proposal cannot execute. The background sweeper checks expiry every second, and response reads/actions also expire leases. Activating the kill switch rolls back active simulations and denies pending proposals. Rollback is available even when the kill switch is on. Every response transition and its global audit record commit atomically in SQLite; an audit-write failure prevents a transition. Policy mutation and its audit also commit together. Audit storage is an operational ledger, not cryptographically tamper-evident storage.

## Database, correlation and retention

SQLite uses WAL, foreign keys, a five-second busy timeout, parameterized SQL and a process lock. Schema migrations use `PRAGMA user_version`; current schema is **2**. Version 2 separates model-fit identity from architecture version so distinct trained artifacts do not overwrite one another. Existing version 1 registries migrate transactionally. Back up the database before upgrading an existing deployment.

Tables store raw/normalized/full intelligence (`events`), groups and event links (`incidents`, `incident_events`), response records (`responses`), structured actions (`audit`), policy (`settings`) and model metadata (`models`). Indexes support time, source/time, decision/time, correlation, expiry and audit queries. Event insert and incident correlation share one transaction. Response/audit records survive source-event retention.

Non-normal events correlate only when they share source IP, sensor and simulation status within connected 300-second event-time intervals. Late events may bridge and merge intervals. This is evidence grouping, not proof of a campaign or attack progression. Incident detail reports the complete retained count and up to 200 recent timeline events, with `timeline_truncated` if necessary. Retention refreshes interval bounds and removes empty groups.

Default retention is 100,000 events or 30 days by ingestion time, whichever limit is reached first. It runs during event writes and once per minute while idle. Audit rows are capped at 100,000; completed response records share a 100,000-row retention threshold while active leases remain available until expiry. No packet payloads are captured. SQLite does not encrypt evidence and deletion is not a guarantee of physical secure erasure from disks or backups. Apply file permissions and an appropriate backup/retention policy for real telemetry.

## Model lifecycle and observability

The API loads only the configured local model directory, normally `var/models/active`. It offers no upload, arbitrary model path or shell execution endpoint. Reload verifies the manifest and exact artifact bytes through `ModelBundle.load`, then replaces the model under the detection lock and resets its temporal/drift state. Models use executable joblib serialization, so administrator ownership of both artifact and manifest is the trust boundary; a hash detects corruption but does not authenticate a file an attacker can replace together with its manifest.

Health reports collector readiness, actual model availability, SQLite status, queue occupancy/capacity, worker state, last failure and uptime. `/api/metrics` reports ingestion events per second over the trailing 60 seconds, average retained inference latency, latest queue wait, retained decision/anomaly/alert proportions, active simulated response count, process-lifetime inference errors and error proportion. Duplicate conflicts count as rejected telemetry and do not mark the service degraded. CPU percentage uses successive samples from the same process handle and includes the measured sample interval; missing optional resource support is marked unavailable. These are operational measurements, not model evaluation accuracy. Full offline evaluation results are separate model metadata/artifacts.

Use the root README for installation, training, serving, Docker and replay commands. Backend tests are in `tests/test_api_security.py` and `tests/test_response_safety.py`; they cover authentication boundaries, malformed evidence, queue and partial-failure behavior, persistence/migrations/correlation, policy gates, approval rechecks, expiry, rollback, kill switch and atomic audit failure.
