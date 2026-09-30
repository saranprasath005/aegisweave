# Continuation review — 14 September 2026

The existing AegisWeave architecture, source, datasets, model artifacts, experiments, dashboard, databases, and generated reports were preserved. This review continues the work; it does not replace the original project assessment or retrospectively regenerate its results.

## Verified starting state

The first resumed inspection found a running FastAPI service, a connected seven-view dashboard, trained synthetic models, a real UNSW-NB15 benchmark, and working SQLite incident/response storage. The initial suite passed 96 tests, and the real-process verification passed all 85 checks. Subsequent saved work also includes IoT-23 corpus training, Zeek TSV replay, causal out-of-order handling, and capture-held-out evaluation. These modules were inspected and their tests were included in the final run.

## Targeted changes

- Drift now uses bounded independent windows for each `(sensor_id, simulated)` population. A demonstration cannot populate a real sensor's normal-reference window or make a sparse sensor appear fully observed. The API identifies the displayed stream and returns every stream's status.
- Missing optional flow measurements are imputed from frozen training values; affected temporal coordinates are declared and discounted. Zeek payload fallback assumptions are explicitly attached to normalized events and explanations. Fixed-header subtraction is an estimate when IP options or extensions exist; a single TCP packet does not prove zero payload.
- Model fitting and artifact identity are separate from architecture version. Training fingerprints, verified artifact digests, atomic artifact writes, and SQLite registry migration retain distinct fits. Every event also records the applied decision and risk severity thresholds.
- Saturated anomaly scores can choose an all-negative validation operating point instead of silently returning an FPR-violating threshold.
- The API rejects far-future telemetry before queueing, preserves role enforcement, handles absent models and inference errors visibly, protects OpenAPI access, and samples process CPU over an actual interval.
- Dashboard changes preserve metric precision, prevent stale query results from replacing current filters, display observed drift counts, enforce role-based controls, and surface policy-denial reasons. The dependency-free frontend regression suite covers these paths.
- End-to-end test fixtures and constructed Zeek logs are labeled simulated. The verification runs actual HTTP servers, ML models, SQLite, collectors and response policies; it does not capture or attack any network.

## Research interpretation

The synthetic fusion experiments, fresh-generator confirmation, UNSW-NB15 benchmark, and IoT-23 capture experiments are separate evidence. Do not pool their scores or present a synthetic-trained model as validated for deployment.

The UNSW reduced-feature test contains repeated vectors across the designated files. Its non-overlapping-vector subset is the more conservative result. The IoT-23 capture-held-out experiment exposes substantial benign alerting and wrong attack attribution despite strong binary detection. Class-support distance can reject geometrically novel examples; it does not establish the identity of an unseen attack that resembles an existing class.

An additional limitation is now reported by `corpus.build_split`: behavior features are constructed over complete captures before interleaved partition assignment. The historical 60-second purge is shorter than the 300-second behavior window, so it does not establish independent temporal context between those partitions. Whole held-out captures isolate test context, while internal fitting/calibration partitions still share capture history. Existing result files remain historical measured outputs; their `passed` leakage-check field is not proof that every form of leakage has been excluded. Use capture-separated fitting/calibration or partition-specific behavior construction for stronger future claims.

The profile layer did not improve the synthetic full-fusion result over its ablation. Its contribution differs in the IoT-23 capture-transfer experiment. This is evidence for a conditional experimental component, not a universally beneficial innovation.

## Operation and remaining boundaries

Final validation: 137 Python tests passed, the frontend regression and JavaScript syntax checks passed, and `pip check` found no broken dependencies. The live verification covers 88 checks over actual application processes; detailed run reports are saved under `var/verify/` with synthetic-fixture provenance.

Run from the project root:

```powershell
.\.venv\Scripts\python.exe -m aegisweave serve
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider
node frontend/check-ui.cjs
.\.venv\Scripts\python.exe scripts/verify_pipeline.py
```

The default dashboard is `http://127.0.0.1:8765`. Use `demo --count 200` for a safe synthetic replay, or `replay --format zeek-tsv` for recorded sensor telemetry. Add `--simulated` for constructed sensor fixtures. Response execution is a simulated ledger with approval, rollback, expiry, allowlists, rate limits and a kill switch. There is no live firewall or host-isolation adapter.

Docker configuration is present but build/run remains unverified because Docker is not installed here. The deployed models need representative local calibration and additional independent evaluation before any operational security claim. Existing Word/PDF reports are preserved snapshots; this review and the latest verification JSON describe subsequent changes.


## Evaluation separation correction — 16 September 2026

`corpus.build_split` now rebuilds behavior features from verified source logs after partition assignment, boundary purging, and class exclusions. State (including watermarks) resets at each contiguous partition transition. Purged records, excluded rare classes, and withheld attack classes in fitting partitions cannot populate context. Serving-path decision samples are regenerated from the same isolated contexts, including for held-out captures selected at split time. Original `load_capture` arrays remain whole-capture replay diagnostics and are not used as fitting behavior inputs.

Context-isolation metadata is version 2. Existing result files and model artifacts have not been regenerated or promoted. New IoT-23 CLI runs default to `experiments/results/iot23-context-v2.json`; the experiment explicitly records that this correction follows the original results. A new training/evaluation run is required before quoting revised model metrics.

The 60-second purge is retained as an additional boundary exclusion, not as the isolation guarantee. Isolation comes from rebuilding eligible context separately. Interleaved temporal blocks still share hosts and capture environments, may contain repeated vectors, and are not a forward-only evaluation. Resets introduce cold starts. Whole-capture holdouts remain the stronger test of transfer; the revised split alone does not establish production readiness.

Regression checks perturb test records and withheld-class records, compare all partition behavior matrices and serving samples against independent partition replay, exercise both protocols and purging, and reject changed source files.

Validation after this correction: all 142 Python tests passed, including 16 corpus tests. Existing dependency deprecation warnings remain. No full-corpus retraining was performed in this change.
