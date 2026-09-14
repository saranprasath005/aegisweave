# AegisWeave implementation contracts

Root owns `aegisweave/schema.py`, `aegisweave/detection.py`, root config, docs, integration.
ML agent owns `aegisweave/ml.py`, `aegisweave/features.py`, `aegisweave/behavior.py`, `aegisweave/demo.py`, `aegisweave/datasets.py`, `experiments/`, ML tests.
Backend agent owns `aegisweave/api.py`, `aegisweave/storage.py`, `aegisweave/response.py`, API/security tests.
Frontend agent owns `frontend/` only (vanilla HTML/CSS/JS, served by FastAPI).

## Telemetry (schema.Flow Pydantic model)
event_id: str (UUID default), timestamp: timezone-aware datetime, source: IP string, destination: IP string,
source_port: int (0..65535), destination_port: int, protocol: TCP|UDP|ICMP|OTHER,
duration: float seconds >= 0, packets: int >= 0, bytes: int >= 0,
reverse_packets: int >= 0 = 0, reverse_bytes: int >= 0 = 0, with packets + reverse_packets >= 1 (responder-only records are valid; packetless records are not),
failed: bool = False, syn_ratio: float [0,1] = 0,
sensor_id: safe str = local, simulated: bool = False.
packets/bytes are FORWARD counters, reverse_* are additional responder counters.
missing_features: list of syn_ratio|failed|reverse_packets|reverse_bytes, default auto records omitted optional measurements; frozen training-median imputation plus reliability discount.
No labels accepted by telemetry. IPs/timestamps/IDs/simulation flags never enter classifier features.

## Collectors
`zeek_to_flow(record, sensor_id)` accepts Zeek conn records from JSON or `read_zeek_tsv` (Zeek's default ASCII log, including IoT-23's
space-joined label columns). Unset fields are omitted, then: duration unset only for single-packet connections -> 0; unset payload bytes ->
0 for zero packets or a single TCP packet, or UDP/ICMP IP length minus fixed IPv4/IPv6 + 8-byte headers; anything else is refused.
Label columns are never read into telemetry. `replay --format normalized|zeek|zeek-tsv [--batch-size 1..200]` skips and reports
unrepresentable records, honors 429 Retry-After, and summarizes {accepted, rejected, already_ingested}.

## BehaviorEngine
`observe(flow: Flow) -> dict` event-time prior context (flows that started no later than this one) + current flow, bounded windows [5,30,60,300] seconds. Does not learn baseline from untrusted inference.
`max_lateness` (default 300 s, Zeek's TCP inactivity timeout): sensors emit connections when they end, so flows up to this far behind the stream watermark
are inserted in event-time order (`reordered: true`); older flows are isolated (`late_event: true`, no history) and never alter history.
In-order streams produce identical context for any tolerance unless a host reaches the per-host event cap.
`snapshot() -> list[dict]` host observations for dashboard.
`reset()` clears history.
Context includes numeric `connections_5s`, `connections_30s`, `unique_destinations_30s`, `unique_ports_30s`, `failed_ratio_30s`, `bytes_30s`, `destination_entropy`, `new_edge`, `history_count`, `temporal_consistency` (recent elevated events if supported; otherwise explain definition), plus explanation evidence.

## ML ModelBundle
`train_demo(path: Path, seed: int = 42) -> ModelBundle` explicitly synthetic fallback.
`fit_bundle(parts, seed, dataset=None, isolation=None)`: default = synthetic episodes with the strict disjoint-episode check; real corpora pass
dataset provenance ({id_prefix,name,simulated,status,implementation_files,provenance}) and their protocol-specific leakage report.
`aegisweave.corpus` (IoT-23): `load_capture` streams labeled Zeek logs through the serving collector + BehaviorEngine in arrival order;
`build_split(captures, "temporal_blocks"|"leave_capture_out", held_out=, withheld_classes=)` -> CorpusSplit{parts, unseen_test, decision_sample, report}.
Unmapped labels are refused; unrepresentable records, boundary purges, rare classes and duplicate flow vectors are reported.
`ModelBundle.load(path: Path)` trusted local artifact only; validate manifest hash before deserialize.
`bundle.predict(flow: Flow, context: dict) -> dict`:
prediction: {class, confidence, probabilities, entropy}, anomaly: {score, is_anomalous, contributions: list},
attribution: {model_class, support_percentile, class_support: {class: percentile}, method} (optional for older artifacts),
behavior: {deviation, temporal_consistency, available}, fusion: {score, reliability, contributions: dict},
explanation: list[str], model: {id, version, dataset, simulated_training, feature_schema}.
`support_percentile` = rank of the flow's 5-NN distance to training flows of the predicted class among held-out
calibration flows of that class (1.0 = beyond all). `reliability` = calibration x host history x measurement completeness
(class entropy excluded; attribution confidence is gated separately). Contributions carry `attack_log_odds_delta`.
`evaluate_decisions(bundle, matrix)` measures analyst-facing decisions through this exact path.
`bundle.metadata` dict including metrics, feature_importance, training time, versions, dataset provenance.
`bundle.drift_snapshot()` optional; root handles drift otherwise.
`generate_demo(count=120, seed=42, start=None) -> list[Flow]` simulated only.

## DetectionEngine (root)
`DetectionEngine(model, store=None)`; `process(flow: Flow) -> dict` intelligence event (JSON serializable).
`behavior.snapshot()`; `health() -> dict`; `drift_snapshot() -> dict`.
Output contains event_id,timestamp,source,destination,source_port,destination_port,protocol,simulated,sensor_id,telemetry,
prediction,anomaly,attribution,behavior,fusion:{score,decision,reliability,...},risk:{score,severity,reasoning,recommended_response},explanation,model,inference_ms.
Decisions: normal | suspicious | anomalous | malicious | unknown.
- malicious: fused >= malicious_threshold, confidence >= minimum_confidence, flow inside predicted class support.
- anomalous: anomaly >= anomaly_threshold AND (outside predicted class support, or classifier says normal without support data). "Attack type uncertain".
- unknown: reliability < minimum_reliability, low-confidence attack evidence, or contradicting layers (explicit abstention).
- suspicious: detected/deviating below the known-attack bar; an unsupported class is never malicious.
- A model with class-support estimates but none for the predicted attack class (no held-out calibration flows) cannot verify
  the attribution: it is treated as unsupported (never malicious; statement says it cannot be verified). Artifacts without any
  class-support layer keep the pre-support behaviour.
- normal: no corroborated evidence; class confidence is not required.
attribution (engine output) adds {status: attributed|tentative|withheld_novel|withheld_no_supported_class|withheld_uncertain|not_applicable,
label: class|unattributed|uncertain|normal, statement, support_threshold, nearest_supported_class (null unless some class supports the flow), outside_all_known_classes}.
attribution.label is the stored/searchable class and drives the risk impact prior; the raw model class stays in prediction.
Risk caps: normal 24, unknown 59, suspicious 69, anomalous 69, malicious 100.
Root engine computes decisions/risk; store/API persists and correlates. Never let untrusted source set asset importance.

## HTTP API, all same origin
Bearer token `Authorization: Bearer ...`; roles from env tokens; missing env tokens = loopback-only demo session via GET /api/session (returns {token,role,mode}), never available when configured auth is used or remote client. Demo mode must reject non-loopback requests globally and enforce same-origin unsafe browser requests.
GET /api/health public minimal; GET /api/overview, /api/events?limit=100&decision=&search=, /api/events/{id}, /api/incidents, /api/incidents/{id}, /api/models, /api/behavior, /api/metrics, /api/policies, /api/responses, /api/audit (role restricted), /api/drift.
POST /api/telemetry body Flow -> event (analyst/admin); POST /api/telemetry/batch body {events:[Flow]} max 200 -> {accepted,events}.
POST /api/demo body {count:120,seed:42} -> {accepted} (analyst/admin); generates and processes only synthetic telemetry.
POST /api/responses body {event_id,action:'block_source'|'isolate_host'|'notify',reason,ttl_seconds:300} -> response record (analyst/admin).
POST /api/responses/{id}/approve, /rollback body {reason} (analyst/admin).
PUT /api/policies (admin) validated policy: {simulation:true,kill_switch:false,allowlist:['127.0.0.0/8','::1/128'],max_actions_per_minute:5,min_risk:70,min_confidence:0.8,ttl_seconds:300}; no live command adapter exists. Simulation cannot be disabled.
POST /api/models/reload (admin) verified local active model only.
GET list endpoints returns {items:[...]}. /api/models returns {items:[metadata],active_version:...}.
/api/overview returns {total_events,detected_threats,anomalies,suspicious_activity (suspicious+anomalous+unknown),anomalous_unattributed,uncertain,decisions:{normal,suspicious,anomalous,malicious,unknown},critical_incidents,response_actions,events_per_second,inference_latency_ms,trend:[{timestamp,normal,suspicious,anomalous,malicious,unknown}],attack_classes:[{name,count}] (attribution labels),confidence_distribution:[{name,count}],mode:'simulation',health:{...}}.
GET /api/events decision filter accepts normal|suspicious|anomalous|malicious|unknown. Containment (block_source/isolate_host) is denied first for any non-malicious decision.
/api/behavior returns {items: [...host contexts...]}; /api/drift contains {status,window_size,...}.
Incidents: {id,source,title,status,severity,risk_score,event_count,first_seen,last_seen,classes,events:[event_id],timeline:[{event_id,timestamp,decision,class,risk}],explanation}.
Response: {id,event_id,action,target,status,simulated:true,created_at,expires_at,reason,approval_required,audit:[...]}; statuses pending_approval/simulated/rolled_back/expired/denied.

## Runtime
`python -m aegisweave` CLI root handles train-demo/serve/demo/generate-demo/replay. Default localhost:8765, data in `var/` (ignored),
active model `var/models/active` (override with `AEGISWEAVE_MODEL`); archived artifacts in `var/models/archive/<version>`.
Static dashboard served on `/` from frontend; API relative paths; no separate node server needed.
