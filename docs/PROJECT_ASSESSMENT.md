# AegisWeave — inherited project assessment (2026-09-14)

Written before any modification. Every claim below was checked by reading the code
and/or running it. Anything that could not be verified is marked **UNVERIFIED**.

## 1. What the project is

A single-process Python ML-NIDS ("AegisWeave") with a vanilla-JS dashboard served by FastAPI.
It was built by several coordinated agents following `CONTRACT.md`, which lists the module owners.
There is no README, no git history and no ML test suite.

```
Flow JSON / Zeek conn.log JSONL / synthetic generator
   │  schema.Flow (pydantic, strict; labels and asset priority rejected)
   ▼
InferenceWorker (bounded queue, one ordered worker thread)      api.py
   ▼
DetectionEngine.process                                          detection.py
   ├─ BehaviorEngine.observe  (causal 5/30/60/300 s host windows) behavior.py
   ├─ ModelBundle.predict                                        ml.py
   │    GradientBoosting multiclass (flow features) + temperature scaling
   │    IsolationForest (benign-only) → calibrated anomaly percentile
   │    HistGradientBoosting temporal model (behaviour features)
   │    benign behaviour-profile distance
   │    logistic-regression stacking fusion + validated FPR-budget threshold
   │    one-feature-replacement sensitivity explanation
   ├─ decide()      normal | suspicious | malicious | unknown
   ├─ assess_risk() 0-100, decision-capped, asset importance from trusted config
   └─ DriftMonitor  PSI / total-variation, observation only
   ▼
Store (SQLite WAL): events, incidents (source/sensor/time correlation), responses, audit, models
   ▼
ResponseEngine: policy, allowlist, rate limit, TTL expiry, approval, rollback, kill switch — simulation only
   ▼
REST API (role tokens or loopback demo session) → static dashboard
```

## 2. Verified state

| Question | Finding |
|---|---|
| Technologies | Python 3.12, FastAPI/Starlette/uvicorn, pydantic 2, scikit-learn 1.9.1, numpy, pandas, scipy, SQLite, vanilla HTML/CSS/JS. Docker + compose files. |
| ML models | GradientBoostingClassifier (5 classes), IsolationForest, HistGradientBoostingClassifier (temporal), robust profile distance, LogisticRegression stacking (5 ablation variants). Saved at `var/models/active` (hash verified). |
| Datasets | The deployable model is trained on **synthetic** episodes only (`demo.generate_episodes`), and it is labelled `demo-only`. UNSW-NB15 CSVs are downloaded in `var/datasets/`. `experiments/public.py` benchmarks them on reduced counters, but it had **never been run** (no result file). |
| Features | 17 flow features (log counters, rates, directional shares, protocol one-hot, log dst port, failed, syn_ratio) and 16 causal behaviour features. IPs, timestamps, IDs and labels are excluded. |
| Ingestion | `POST /api/telemetry[/batch]` of normalized flows; `python -m aegisweave replay` forwards JSONL or Zeek `conn.log` JSON. No packet capture. |
| Prediction path | API → queue → worker → DetectionEngine → ModelBundle.predict → decide/risk → Store. **Verified working** with the real model (~7.6 ms/flow). |
| Alerts/incidents | Every non-normal event is correlated into incidents by source + sensor + simulation flag within 300 s event-time windows. Verified working. |
| Risk engine | Present: weighted evidence plus asset importance, capped by decision. |
| Anomaly detection | Present (benign-only IsolationForest). |
| Behavioural / temporal | Present (BehaviorEngine windows, temporal model, profile distance). |
| Explainability | Present: class probabilities, entropy, fusion log-odds terms, one-feature sensitivity, behaviour evidence. |
| Automated response | **Simulated only**, by design. No live adapter exists. Policy, allowlist, TTL, rate limit, approval, rollback, kill switch and audit are all implemented and tested. |
| APIs | health, session, identity, overview, events, incidents, models, behavior, drift, metrics, telemetry, telemetry/batch, demo, policies, responses (+approve/rollback), audit, models/reload. All verified to return 200. |
| Storage | SQLite with schema versioning, retention, parameterized SQL. |
| Dashboard | 7 views written (overview, events, analytics, behaviour, incidents, response, system), but **broken at runtime** (see below). |
| Tests | 72 tests, **all pass**. They cover schema validation, decision rules, risk caps, API authz/perimeter/CSRF, bounds, storage, response safety and collectors. The API tests use a `FakeEngine`, so **no test exercises the real ML model, the CLI or the dashboard**. |

## 3. What is broken or wrong (verified)

1. **Dashboard does not load.** `index.html` requests `/app.js` and `/styles.css`, but FastAPI mounts the frontend at `/static`. Both return 404 and the page renders a giant unstyled logo.
2. **Default model path mismatch.** The CLI and API default to `var/model`, but the trained artifact lives in `var/models/active`. `python -m aegisweave serve` starts with no model (degraded), and the Docker image has no model at all.
3. **Benign traffic mostly abstains.** On the held-out synthetic test set, 377 of 586 benign flows (64%) are `unknown` (see `baseline_decisions` below). `decide()` requires multiclass argmax confidence ≥ 0.70 even to call a flow *normal*, and benign per-flow confidence averages ~0.66, although the validated fused detector scores these flows ~0.02. This is severe alert fatigue: unknowns are counted as "suspicious activity" on the dashboard.
4. **Novel attacks receive an invented known-attack label.** All 337 flows of the withheld `unknown_beacon` family are classified `scan` with confidence 1.00: 26 are *malicious scan* and 311 are *suspicious scan*. The only novelty model is benign-relative, so the system cannot tell "unlike benign" from "unlike every known attack class".
5. **Explanation sensitivity saturates.** Probability deltas are reported for only the 3 largest-deviation features, e.g. "changes attack probability by -0.000". The features are selected by deviation, not by effect.
6. **Inconsistent anomaly flag.** The model's `is_anomalous` uses 0.98, but decisions use a configured 0.95, so dashboard "anomaly" counts disagree with the decision logic.
7. **Configured-token dashboard sessions have an unknown role.** The frontend asks `/api/session` (404 in token mode) instead of `/api/identity`. The server still enforces roles, so this is UI-only.
8. **Drift panel fields that the API never returns** (`anomaly_rate`, `mean_confidence`) always show "—".

Baseline decision distribution of the inherited model plus `decide()` (fixed seeds):

| true label | normal | suspicious | malicious | unknown |
|---|---|---|---|---|
| benign (test) | 208 | 1 | 0 | **377** |
| dos (test) | 1 | 10 | 64 | 37 |
| withheld `unknown_beacon` | 0 | 311 (as "scan") | **26 (as "scan")** | 0 |

## 4. Claims checked

| Claim | Status |
|---|---|
| Synthetic full-fusion F1 0.995 / FPR 0.34 % (`experiments/results/synthetic.json`, manifest) | Reproduced from the saved artifact. It is **synthetic only**, and the artifact says so. |
| "Automated response implemented" | Simulation ledger only. No device is ever touched (verified in code). |
| UNSW-NB15 public benchmark | Not previously run. Measured now (reduced 10 counters): hybrid F1 0.904 / FPR 8.5 % on all official test rows; F1 0.775 / FPR 10.1 % on the 45,816 test rows whose feature vector never appears in training. |
| Docker deployment works | **UNVERIFIED** (Docker not exercised). Also structurally incomplete: no model in the image. |

## 5. Gap analysis

| Component | Status | Evidence | Problem | Next action |
|---|---|---|---|---|
| Telemetry schema/ingestion | Implemented | schema.py, api.py, collectors.py | none found | keep |
| Feature engineering | Implemented | features.py | no fitted transforms (good) | keep |
| Behaviour/temporal context | Implemented | behavior.py | — | keep |
| Supervised classifier | Implemented (synthetic-trained) | ml.py | demo-only training data | keep; document; real-data benchmark |
| Anomaly detection | Implemented | ml.py IsolationForest | benign-relative only | add class-support (open-set) layer |
| Open-set attribution | **Missing** | none | novel flows get invented class | design + implement |
| Decision fusion | Partial / defective | detection.decide | benign abstention; no ANOMALOUS category | fix; add `anomalous` |
| Explainability | Partial | ml.predict | saturated, top-3 by deviation | log-odds sensitivity across all features; attribution evidence |
| Risk engine | Implemented | detection.assess_risk | uses raw class prior | use attributed label; handle `anomalous` |
| Incidents/alerts | Implemented | storage.py | — | include new decision |
| Response engine | Implemented (simulated) | response.py | — | keep; add tests for new decision |
| API | Implemented | api.py | wrong default model path; no anomalous filter | fix |
| Dashboard | **Broken** | frontend/ | asset 404; role detection; drift fields | fix paths; add attribution UI |
| Model lifecycle/drift | Implemented | detection.DriftMonitor, /api/models/reload | missing summary fields | small additions |
| ML tests | **Missing** | tests/ | real model never tested | add ML, attribution and end-to-end tests |
| Deployment | Partial, UNVERIFIED | Dockerfile | no model in image | bake demo model at build |
| Documentation | **Missing** | only CONTRACT.md | no README | write README and update contract |

## 6. Resolution status (after this work)

| # | Finding | Resolution | Verified by |
|---|---|---|---|
| 1 | Dashboard assets 404 | `index.html` loads `/static/*`; stray CSP-blocked `@import` removed | `test_dashboard_page_and_its_assets_are_served`; browser |
| 2 | Default model path | CLI/API default `var/models/active` (`AEGISWEAVE_MODEL`); Docker image bakes a root-owned demo model | CLI runs; Docker **UNVERIFIED** |
| 3 | Benign abstention 64 % | `decide()` separates detection from attribution; class entropy removed from evidence reliability (chosen on tuning splits across 4 seeds) | test split: benign→normal 89.1 %, abstain 9.6 % |
| 4 | Invented attack types | `ClassSupport` open-set layer, new `anomalous` decision, `attribution` block | withheld family 337/337 anomalous; ablation reproduces the defect |
| 5 | Saturated explanations | log-odds sensitivity over all measured features + anomaly sensitivity + fusion terms | `test_sensitivity_explanation_is_recomputable_from_the_model` |
| 6 | Inconsistent anomaly flag | engine sets `is_anomalous` from the configured threshold | code |
| 7 | Token-mode role unknown | dashboard uses `/api/identity`; demo tabs recover after server restart | browser |
| 8 | Drift panel fields | `DriftMonitor.snapshot` returns `anomaly_rate`, `mean_confidence`, `message` | browser |
| — | UNSW benchmark never run | run; open-set leave-families-out test added | `experiments/results/unsw.json` |
