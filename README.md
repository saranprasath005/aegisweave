# AegisWeave — ML-first network intrusion detection (research system)

AegisWeave scores network **flows** with several complementary ML layers. It separates
*detecting* an attack from *attributing* an attack type, explains every decision with measured
evidence, correlates alerts into incidents, and routes any response through a policy engine
that **only simulates** actions.

> **Status: research.** Two kinds of model artifact exist, and every event says which one scored it
> (`model.simulated_training`, `model.dataset`). The default demo model (`var/models/active`) is trained on
> *synthetic* traffic. The IoT-23 models (`var/models/iot23`, `var/models/iot23-lco`) are trained on *real*
> labeled Zeek traffic from a 2018–2019 lab network. They transfer poorly to an unseen network (see results).
> No result here establishes performance on your network. No live containment adapter exists.

## Architecture

```
Zeek conn.log (TSV or JSON) ─┐   collectors.py: exact handling of unset fields, bad records skipped and reported
normalized JSONL ────────────┼─► POST /api/telemetry[/batch]  (pydantic Flow: strict, no labels, no asset priority)
synthetic replay ────────────┘            │
                                 ▼
                  bounded queue ─► single ordered inference worker            api.py
                                 ▼
DetectionEngine.process                                                       detection.py
 ├─ BehaviorEngine: event-time 5/30/60/300 s host windows; flows up to 300 s out of order are
 │                  re-sequenced (Zeek emits connections when they end); never learns from live data   behavior.py
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
| `python -m aegisweave replay conn.log --format zeek-tsv --sensor lab1 --batch-size 200` | forward Zeek's default TSV `conn.log` in batches (honors rate limits, skips unrepresentable records) |
| `python -m aegisweave replay conn.json --format zeek --sensor lab1` | forward Zeek `conn.log` (JSON) |
| `python -m experiments.run --model var/models/active` | full synthetic evaluation and retrain (~40 s) |
| `python -m experiments.confirm` | frozen synthetic model on fresh synthetic draws, no refitting |
| `python -m experiments.iot23 --model var/models/iot23 --model-lco var/models/iot23-lco` | real IoT-23 training + evaluation, 3 protocols (~8 min first run) |
| `python -m experiments.public --train var/datasets/UNSW_NB15_training-set.csv --test var/datasets/UNSW_NB15_testing-set.csv` | UNSW-NB15 benchmark + open-set test (~35 s) |

API reference and backend operations: [docs/API.md](docs/API.md).

### Real traffic: IoT-23

IoT-23 (S. Garcia, A. Parmisano, M. J. Erquiaga, Stratosphere Laboratory, 2020, https://www.stratosphereips.org/datasets-iot23)
provides labeled Zeek `conn.log` files. The experiment reads every `*.conn.log.labeled` file in `var/datasets/iot23/`
(git-ignored). The results below used these eight files from
`https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/<capture>/bro/conn.log.labeled`, saved as
`<capture>.conn.log.labeled`; SHA-256 hashes are recorded in the results file:
CTU-IoT-Malware-Capture-1-1, 3-1, 8-1, 34-1, 42-1, 44-1 and CTU-Honeypot-Capture-4-1, 5-1 (≈178 MB).

Replay the two captures the leave-capture-out model never saw through the live API:

```bash
.venv/Scripts/python -m aegisweave serve --port 8791 --model var/models/iot23-lco --db var/iot23-unseen-demo.db
```

```bash
.venv/Scripts/python -m aegisweave replay var/datasets/iot23/CTU-Honeypot-Capture-5-1.conn.log.labeled --format zeek-tsv --sensor honeypot-5-1 --batch-size 200 --url http://127.0.0.1:8791
```

```bash
.venv/Scripts/python -m aegisweave replay var/datasets/iot23/CTU-IoT-Malware-Capture-8-1.conn.log.labeled --format zeek-tsv --sensor capture-8-1 --batch-size 200 --url http://127.0.0.1:8791
```

The label columns in these research logs are ignored by the collector; only measured counters reach the model.

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

The run takes about 20 s. **136 tests** cover:
- schema and injection rejection; decision, attribution and risk rules
- a real trained model: manifest tamper detection, output contract, identity-field invariance, recomputable explanations,
  missing measurements, split leakage, class-support behaviour, a withheld attack family never given a known type,
  held-out decision quality, model lineage
- API authz/CSRF/perimeter/bounds, OpenAPI auth, future-timestamp rejection; storage retention, migrations, correlation and incremental incident bounds
- response safety: allowlist, IPv4-mapped bypass, kill switch, rate limits, expiry, approval re-checks, atomic audit
- per-sensor drift isolation; Zeek TSV parsing and exact unset-field handling; event-time reordering of out-of-order flows
- the IoT-23 corpus pipeline on an IoT-23-format fixture (label mapping, exclusion accounting, split guarantees, real-data provenance)
- a full end-to-end pipeline through the API, including dashboard asset serving and verified model reload

Frontend rendering and refresh-race regressions (Node, no dependencies):

```bash
node frontend/check-ui.cjs
```

Live end-to-end verification against real server processes: 88 checks across 19 stages, including Zeek TSV batch replay
with an unrepresentable record. It takes about 1 minute; all input flows are constructed fixtures:

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

Latency: 7.7 ms p50 / 8.5 ms p95 per event including explanation (one thread, Intel desktop CPU); RSS ≈ 198 MB.

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

### IoT-23 (`experiments/results/iot23.json`; real labeled Zeek traffic through the live pipeline)

**Corpus.** 8 captures, 1,204,888 conn records, processed with the serving collector and behaviour engine in sensor
arrival order.
- **Exclusions:** 14,260 records are excluded and reported. They are one capture-34-1 flood labelled DDoS, logged by Zeek
  with bad checksums and **zero counted packets**; learning "empty counters = DoS" would be a label artifact.
- **Reordering:** 452,276 flows (38%) arrived out of event order and were re-sequenced within the 300 s tolerance; 952 were
  later than that and received no host history.
- **Classes:** normal, scan, command_and_control, attack_attempt and dos. Only 135 DoS flows remain, with no
  validation-partition coverage, so DoS attributions can never be verified and are never `malicious`.
- **Excluded class:** file_download (3 flows).

Protocols were fixed before results were seen. One logic fix, unverifiable attributions never becoming `malicious`, was made
after inspecting protocol C; it changed decisions only, never scores.

| Protocol (binary, all test rows) | Test rows | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| A. temporal blocks within captures | 107,306 | 0.995 | 0.988 | 0.992 | 0.70 % | 0.999 |
| A, only the 7,136 test rows whose flow vector never occurs in fitting data | 7,136 | 0.877 | 0.740 | **0.803** | **6.90 %** | 0.913 |
| B. attack_attempt withheld from all fitting partitions | 107,306 | 0.999 | 0.967 | 0.983 | 0.18 % | 0.999 |
| C. **captures 8-1 (Hakai botnet) and honeypot 5-1 never used for fitting** | 11,777 | 0.957 | 1.000 | 0.978 | **10.27 %** | 0.906 |

**Analyst-facing decisions** (serving path `predict → decide → attribute`, sampled test flows):

| | A | B | C |
|---|---|---|---|
| benign → normal | 92.1 % | 92.0 % | 45.4 % |
| benign → alert / → malicious | 3.2 % / 0.8 % | 3.2 % / 0.4 % | 30.9 % / 0.0 % |
| attacks flagged | 99.8 % | 99.8 % | 100 % |
| attacks given the correct type | 99.2 % | 73.0 % (withheld class cannot be named) | **0 %** |
| attacks given a wrong known type | 0 % | 0 % | **100 %** (all C&C shown as `scan`) |

What this shows, and does not show:
- **Within known captures (A) the headline is optimistic.** 93 % of test rows repeat a fitting flow vector; on genuinely new
  vectors F1 is 0.80. Destination port is the most important supervised feature, so the classifier partly learns capture-specific ports.
- **Novel attack type (B): 935 of 936 withheld attack_attempt flows → `anomalous`, zero invented attack types.** The fused
  score alone missed most of them on unseen vectors (recall 0.30). The anomaly-driven decision rule caught them. An ablation without the
  class-support layer gives the same 935, so the benefit comes from the benign-novelty layer and decision rule, not class support.
- **New network and malware family (C): detection transfers, attribution and benign precision do not.** The supervised layer
  alone scores F1 0.0; detection comes from the anomaly and behaviour-profile layers (removing the profile layer drops fused F1 to
  0.53). All Hakai C&C is typed `scan`. The unseen honeypot's benign IoT devices mostly look anomalous. The C fusion partition
  contained no C&C rows, because 34-1's C&C is concentrated in time.

**Live replay of the unseen captures** (C model served, `replay --format zeek-tsv`). Labels were joined back only for scoring:

| True traffic (every flow) | Flows | Decisions | Analyst-facing type |
|---|---|---|---|
| Hakai botnet C&C (8-1) | 8,222 | 75.0 % suspicious, 25.0 % malicious | `scan` (wrong) |
| benign, capture 8-1 | 2,181 | 67.1 % normal, 32.8 % uncertain | — |
| benign, unseen honeypot 5-1 | 1,374 | 24.7 % normal, 61.5 % anomalous, 13.8 % uncertain | unattributed |

The live distribution matches the offline evaluation (C&C 74.8 % / 25.2 % offline). No benign flow reached `malicious`, so none
was containment-eligible. A block request for a real botnet host went to human approval; isolation of an anomalous benign smart
device was denied. Serving latency was 7–9 ms per flow including explanation; replay throughput was about 85 flows/s on one
inference worker.

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

- **Cross-network generalization is weak (IoT-23 protocol C).** A model trained on some lab captures raised alerts on 31 %
  of an unseen network's benign flows and gave every flow from a new malware family the wrong type. A new site needs
  locally collected benign traffic for calibration and retraining, then `experiments`-style evaluation and `/api/models/reload`.
- IoT-23 is a small lab corpus (a few devices and malware samples, 2018–2019). DoS has 135 usable flows and no
  validation coverage. The supervised layer leans on destination port.
- The default demo model is synthetic-trained. UNSW-NB15 covers per-flow layers only, because its CSVs lack host identity and chronology.
- About 10 % of benign synthetic flows still abstain (`unknown`), mostly behaviour-profile deviation (`behavior_threshold` 0.85,
  about 7.5 % of benign windows by construction) and low evidence reliability on a host's first flows.
- The class-support check helps only when novel traffic is geometrically distinct from known classes (see UNSW result).
- Host behaviour windows live in memory only (bounded; last 300 s). After a restart the Behaviour page is empty and each
  host's first flows get discounted temporal evidence until new history accumulates. Stored events are unaffected.
- Single-process design: one inference worker and SQLite. Horizontal scaling would need an external queue and database.
- No live response adapters, SIEM/notification integrations, packet capture, or TLS termination.
- `docs/PROJECT_ASSESSMENT.md` records the inherited state before this work. `CONTRACT.md` is the module/API contract.
