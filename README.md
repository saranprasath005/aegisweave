# AegisWeave — ML-first network intrusion detection (research system)

AegisWeave scores network **flows** with several complementary ML layers. It separates
*detecting* an attack from *attributing* an attack type, explains every decision with measured
evidence, correlates alerts into incidents, and routes any response through a policy engine
that **only simulates** actions.

> **Status: demo / research.** The deployable model is trained on *synthetic* traffic, and it says
> so in every event (`model.simulated_training: true`). The real-data results below come from an
> offline UNSW-NB15 benchmark on reduced counters. No result here establishes real-world
> detection performance. No live containment adapter exists.

## Architecture

```
Zeek conn.log JSON ─┐
normalized JSONL ───┼─► POST /api/telemetry[/batch]  (pydantic Flow: strict, no labels, no asset priority)
synthetic replay ───┘            │
                                 ▼
                  bounded queue ─► single ordered inference worker            api.py
                                 ▼
DetectionEngine.process                                                       detection.py
 ├─ BehaviorEngine: causal 5/30/60/300 s host windows (never learns from live data)  behavior.py
 ├─ ModelBundle.predict                                                       ml.py
 │   ├─ supervised   GradientBoosting, 5 classes, temperature-scaled
 │   ├─ anomaly      benign-only IsolationForest → percentile vs held-out benign
 │   ├─ temporal     HistGradientBoosting on behaviour windows
 │   ├─ profile      robust distance to benign behaviour windows
 │   ├─ class support 5-NN distance to each class's training flows (open-set attribution)
 │   ├─ fusion       stacked logistic regression over the layers' evidence
 │   └─ explanation  one-feature sensitivity (log-odds, isolation score), fusion terms
 ├─ decide()     normal | suspicious | anomalous | malicious | unknown
 ├─ attribute()  analyst-facing attack type, or an explicit "unattributed" / "uncertain"
 ├─ assess_risk() 0–100, capped by decision, trusted asset importance from local config
 └─ DriftMonitor  PSI / total-variation between live windows (review signal, never retrains)
                                 ▼
Store (SQLite WAL): events · incidents (source+sensor+time correlation) · responses · audit · models
                                 ▼
ResponseEngine: policy → allowlist → risk/confidence gates → approval → TTL expiry → rollback → kill switch
                (simulation ledger only)
                                 ▼
REST API (role tokens, or loopback-only demo session) ─► dashboard (served at /)
```

### Decisions: known attack vs. anomalous vs. uncertain

| Decision | Meaning | Attack type shown |
|---|---|---|
| `malicious` | Fused detector ≥ 0.78, class confidence ≥ 0.70, and the flow lies **inside** that class's training support | the class, e.g. `dos` |
| `suspicious` | Detected or deviating, but below the known-attack bar | tentative class, or `unattributed` |
| `anomalous` | Unlike benign traffic **and** no supported known class: *"Anomalous behavior detected, attack type uncertain"* | `unattributed` |
| `unknown` | Abstention: evidence reliability < 0.5, or evidence layers contradict each other | `uncertain` |
| `normal` | No corroborated evidence. Class confidence is **not** required to call benign traffic normal | `normal` |

The raw classifier output is always kept in `prediction` for transparency. The analyst-facing label is in
`attribution.label`, and a withheld raw class never drives search, incident titles, risk priors or containment.

## Quick start (Windows or Linux, Python 3.12)

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.lock      # Linux/macOS: .venv/bin/python
```

The trained demo model is expected at `var/models/active`. Recreate it at any time; training is deterministic and takes about 15 s:

```bash
.venv/Scripts/python -m aegisweave train-demo --model var/models/active
```

Start the dashboard with 200 replayed synthetic flows (loopback demo session, no tokens needed):

```bash
.venv/Scripts/python -m aegisweave demo --count 200
```

Open http://127.0.0.1:8765. Run all commands from the repository root.

Other commands:

| Command | Purpose |
|---|---|
| `python -m aegisweave serve [--host --port --model --db --config]` | API + dashboard, no replay |
| `python -m aegisweave generate-demo out.jsonl --count 500` | write simulated normalized flows |
| `python -m aegisweave replay out.jsonl` | forward normalized JSONL to the API |
| `python -m aegisweave replay conn.json --format zeek --sensor lab1` | forward Zeek `conn.log` (JSON) |
| `python -m experiments.run --model var/models/active` | full synthetic evaluation and retrain (~40 s) |
| `python -m experiments.public --train var/datasets/UNSW_NB15_training-set.csv --test var/datasets/UNSW_NB15_testing-set.csv` | UNSW-NB15 benchmark + open-set test (~35 s) |

Environment variables: `AEGISWEAVE_ADMIN_TOKEN`, `AEGISWEAVE_ANALYST_TOKEN`, `AEGISWEAVE_VIEWER_TOKEN`
(≥ 24 chars, distinct; setting any enables token auth), `AEGISWEAVE_TOKEN` (for `replay` to a
token-protected server), `AEGISWEAVE_MODEL` (default model path), `AEGISWEAVE_LOG_LEVEL`.
Detection thresholds and asset importance: copy `config/detection.example.json` and pass `--config`.

## Demonstration procedure

1. `python -m aegisweave demo --count 200` and open http://127.0.0.1:8765.
2. **Overview**: decisions over time. *Novel behavior* counts `anomalous` events; *Detected threats* counts `malicious`.
3. **Live events**: filter *Decision = Anomalous*. The UDP/5353 beacon flows come from an attack family that was
   **never in training**. Open one. *Attack attribution* shows the raw classifier said "Scan 100%", but the flow is
   outside every known class's training support, so the type is withheld.
4. Filter *Malicious* and open a high-risk DoS event. It shows an attributed type, support percentile, sensitivity table,
   fusion terms and risk reasoning.
5. In that drawer choose **Block source** → justify → submit. The request is *pending approval*. Go to **Response**,
   **Approve** (recorded as *simulated*; nothing on the network changes), then **Rollback**.
6. Try **Isolate host** on an anomalous event. Policy **denies** it, because containment requires an attributed malicious decision.
7. **System health**: the audit trail shows every step. Toggle the kill switch (admin) and watch active simulations roll back.
8. **ML analytics**: held-out decision matrix, per-class metrics, provenance (synthetic training is flagged).

## Tests

```bash
.venv/Scripts/python -m pytest -p no:cacheprovider
```

The run takes about 16 s. **96 tests** cover schema and injection rejection, decision/attribution/risk rules, a real
trained model (manifest tamper detection, output contract, identity-field invariance, recomputable explanations, missing
measurements, split leakage, class-support behaviour, withheld attack family never given a known type, held-out
decision quality), API authz/CSRF/perimeter/bounds, storage retention and correlation, response safety (allowlist,
IPv4-mapped bypass, kill switch, rate limits, expiry, approval re-checks), collectors, and a full end-to-end pipeline
through the API, including dashboard asset serving and verified model reload.

Live end-to-end verification against real server processes (85 checks across 19 stages: validation, every ML layer,
behaviour windows, novel-traffic attribution, batch/API/CLI/Zeek ingestion, storage, incidents, risk invariants, response
policy with approval/allowlist/kill switch/lease expiry, audit, drift, model reload, dashboard, restart persistence,
token RBAC, fail-closed startup), about 1 minute:

```bash
.venv/Scripts/python scripts/verify_pipeline.py
```

## Measured results

All numbers come from the committed result files (`experiments/results/*.json`) and are reproducible with the commands above.

### Synthetic episodes (`experiments/results/synthetic.json`, seed 42; independent host episodes)

Split: train / calibration / fusion / threshold-tuning / test, disjoint by episode, with exact feature-hash leakage checks.
Test set: 1,348 flows (586 benign, 762 attack).

| Binary detector (test) | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|
| logistic baseline | 0.978 | 0.765 | 0.859 | 2.2 % | 0.939 |
| supervised only | 0.978 | 0.867 | 0.919 | 2.6 % | 0.952 |
| anomaly only | 0.893 | 0.660 | 0.759 | 10.2 % | 0.842 |
| full fusion | 0.997 | 0.992 | 0.995 | 0.34 % | 0.9998 |

Episode-bootstrap 95 % CI for F1(full) − F1(supervised): [0.023, 0.144].

**Analyst-facing decisions** (every test flow through `predict → decide → attribute`):

| | Inherited v1.0.0 logic | Current v1.1.0 | v1.1.0 without class-support layer |
|---|---|---|---|
| benign → normal | 35.5 % | **89.1 %** | 86.5 % |
| benign → unknown (abstain) | 64.3 % | 9.6 % | 8.7 % |
| benign → alert (suspicious/anomalous/malicious) | 0.2 % | 1.4 % | 4.8 % |
| attacks flagged (any non-normal) | — | 99.6 % | 99.6 % |
| attacks given the correct type | — | 87.4 % | 87.8 % |
| attacks given a wrong known type | — | 0.26 % | 0.26 % |
| **withheld `unknown_beacon` family (337 flows)** | 26 malicious + 311 suspicious, all "scan" | **337 anomalous, 0 invented types** | 26 malicious + 311 suspicious, all "scan" |

Latency: 6.8 ms p50 / 7.5 ms p95 per event including explanation (one thread, Intel desktop CPU); RSS ≈ 195 MB.

### UNSW-NB15 (`experiments/results/unsw.json`; real lab traffic, reduced to 10 generic counters)

Official train/test files preserved, 60,000-row stratified training sample, no temporal context available.
36,516 of 82,332 test rows share an exact feature vector with training, so both views are reported.

| Reduced hybrid | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|
| all official test rows | 0.927 | 0.881 | 0.904 | 8.5 % | 0.968 |
| 45,816 rows unseen in training | 0.819 | 0.736 | 0.775 | 10.1 % | 0.921 |

Multiclass on reduced counters is weak (macro F1 0.46). **Open-set test** (analysis, backdoor, shellcode and worms
removed from training): 6.2 % of their test flows get a confident wrong known type, **with or without** the class-support
check. These families overlap known ones in these features, so the support check gave **no measurable benefit on this
dataset**; the confidence gate withholds 91 %. The support check's cost on known families was negligible (0.03 % of
correct types withheld). On benign rows 15 % receive a confident attack type: a classifier false-positive problem on
reduced counters.

## Security model

- Telemetry is untrusted. Strict schema, canonical IPs, timezone-aware timestamps, 2 MiB body cap, batch ≤ 200,
  rate limits. Labels and asset importance are rejected in telemetry.
- Auth: role tokens (viewer < analyst < admin), constant-time comparison. Without tokens, a random per-process admin session is
  served **only** to loopback clients with a local Host header and no forwarding headers. Unsafe requests require same-origin.
- Headers: strict CSP (`script-src 'self'`), `frame-ancestors 'none'`, `nosniff`, `no-store`. The dashboard escapes all dynamic values.
- Models: SHA-256 manifest, sklearn-version and feature-schema checks before joblib deserialization. Joblib is executable,
  so the model directory must be admin-owned (the Docker image makes it root-owned).
- Response: simulation cannot be disabled (schema-enforced). Containment needs a malicious, attributed decision,
  risk ≥ 70, confidence ≥ 0.8, a target outside the allowlist (IPv4-mapped IPv6 handled), rate limit, human approval, TTL.
  The kill switch rolls back active and denies pending actions. Every transition is audited in the same transaction.
- SQL is fully parameterized. LIKE search escapes metacharacters.

## Deployment

```bash
AEGISWEAVE_ADMIN_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))") docker compose up --build
```

The image trains the synthetic demo model at build time into a root-owned `/app/models/active`, runs as UID 10001 with a
read-only root filesystem, no capabilities, and binds to 127.0.0.1. Put a TLS reverse proxy in front for remote access.
**Docker build/run has not been verified in this environment (Docker was not installed).**

## Known limitations and TODOs

- The deployable model is synthetic-trained. Real deployment needs labeled, representative flows from the target network
  with the same schema (including causal host history), then retraining, `experiments`-style evaluation, and `/api/models/reload`.
- The public benchmark covers per-flow layers only. No public CSV provides the validated host identity and chronology the temporal layers need.
- About 10 % of benign synthetic flows still abstain (`unknown`), mostly behaviour-profile deviation (`behavior_threshold` 0.85,
  about 7.5 % of benign windows by construction) and low evidence reliability on a host's first flows.
- The class-support check helps only when novel traffic is geometrically distinct from known classes (see UNSW result).
- Host behaviour windows live in memory only (bounded; last 300 s). After a restart the Behaviour page is empty and each
  host's first flows get discounted temporal evidence until new history accumulates. Stored events are unaffected.
- Single-process design: one inference worker and SQLite. Horizontal scaling would need an external queue and database.
- No live response adapters, SIEM/notification integrations, packet capture, or TLS termination.
- `docs/PROJECT_ASSESSMENT.md` records the inherited state before this work. `CONTRACT.md` is the module/API contract.
