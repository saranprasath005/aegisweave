# AegisWeave — Project Knowledge Base

**The central technical reference for the AegisWeave ML-NIDS project team.**

> **How to read this document.** Every major claim carries a status tag and, where possible, an evidence pointer to a file in the repository.
>
> | Tag | Meaning |
> |---|---|
> | **[IMPLEMENTED]** | Confirmed in the current source code and exercised by tests or runs |
> | **[PARTIALLY IMPLEMENTED]** | Code exists but is incomplete, unverified on its target platform, or not integrated |
> | **[PLANNED]** | Written in project plans or documents, not implemented |
> | **[PROPOSED]** | A reasonable idea raised in this document, not part of any plan yet |
> | **[EXTERNAL BACKGROUND]** | From research literature or general knowledge, not from our code |
> | **[UNKNOWN]** | Cannot be verified from the project material |
>
> Where it matters, **FACT** (what the files show), **INTERPRETATION** (what that suggests) and **RECOMMENDATION** (what we should do) are kept separate.

---

# PART 0 — DOCUMENT CONTROL

| Item | Value |
|---|---|
| Project title | **AegisWeave** — Evidence-aware machine-learning network intrusion detection system |
| Project type | Final-year / Prototype Development Lab project; research prototype with a working web application |
| Domain | Network security; network intrusion detection (NIDS); applied machine learning |
| Report purpose | Onboarding and single source of truth for all team members, the supervisor and viva preparation |
| Analysis date | 1 October 2026 |
| Code version | Git commit `401f186` on branch `main` (8 commits in total; working tree clean at analysis time). Package version `0.1.0` (`pyproject.toml`); model architecture version `1.1.0` (`aegisweave/ml.py: MODEL_VERSION`); feature schema `aegisweave.flow.v1` |
| Verification status | Source code, configuration, tests, experiment result files and documentation were inspected directly. On 1 Oct 2026: the full test suite passed (**164/164**), the end-to-end pipeline check passed (**88/88** checks) and the collector recovery check passed (**8/8**) |

### Files and material inspected

- **Source:** `aegisweave/` — all 17 modules, including `schema.py`, `features.py`, `behavior.py`, `ml.py`, `detection.py`, `collectors.py`, `ingest.py`, `corpus.py`, `datasets.py`, `storage.py`, `response.py`, `api.py`, `auth.py`, `backup.py`, `demo.py` and `__main__.py`.
- **Frontend:** `frontend/index.html`, `app.js`, `styles.css`, `check-ui.cjs`.
- **Experiments:** `experiments/run.py`, `confirm.py`, `public.py`, `iot23.py`, `prepare_cic.py`, `cic_baseline.py`.
- **Result files:** all 7 JSON files in `experiments/results/`.
- **Tests:** all 14 files in `tests/` (164 tests).
- **Scripts:** `scripts/verify_pipeline.py`, `verify_collector.py`, `start_prototype.py`, `acquire_cic2017.py`.
- **Configuration:** `pyproject.toml`, `requirements.lock`, root `Dockerfile`, `deploy/` (Compose, Dockerfile, Caddyfile, `.env.example`), `config/detection.example.json`.
- **Documentation:** `README.md`, `CONTRACT.md`, and in `docs/`: `API.md`, `BACKUP.md`, `COLLECTOR.md`, `CONTINUATION_REVIEW.md`, `CIC2017_BASELINE_REVIEW.md`, `MODEL_REVIEW_CONTEXT_V2.md`, `PRODUCTION_TARGET.md`, `LAB_VALIDATION.md`, `PROTOTYPE_DEMO.md`, `WORK_CHECKPOINT.md`, `PROJECT_ASSESSMENT.md`, and the generated report `docs/report/`.

### Important assumptions and gaps

1. **Research papers.** The brief mentions *uploaded* research papers (historical IDS, misuse vs. anomaly detection, Random Forest NIDS, data-breach concepts). **None were available to this analysis.** No NIDS papers were found in the repository or the recent download folders. The literature sections therefore use the 12 papers the project already cites (`docs/report/generator/content.js` and the Week 2 activity file), and are tagged [EXTERNAL BACKGROUND]. Any paper-specific numbers are deliberately left out rather than guessed. **Add the uploaded papers to Parts 4–5 when they are available.**
2. **Team.** Team members, their names and their actual role split are **[UNKNOWN]**. The work breakdown in the Week 3 activity file assigns *suggested* roles M1–M4.
3. **Development history.** The code was developed with AI assistance (Claude Code, and an earlier GPT/Codex session), as declared in the project report. This document describes the code as it exists, not who wrote which part.

---

# PART 1 — EXECUTIVE SUMMARY

### What are we building?

AegisWeave is a **passive network intrusion detection system**. It reads **network flow records** — one summary per network connection, as produced by the open-source sensor **Zeek** — and decides whether each connection looks normal or like an attack. It does this with a **multi-layer machine-learning engine**, and it explains every decision.

It stores results in a local database and groups related alerts into incidents. It shows everything on a web dashboard, and lets an analyst request a **simulated** response (block or isolate a host) that must pass safety policy and human approval. [IMPLEMENTED]

### What problem does it solve?

Classic signature IDS (Snort, Suricata) miss attacks they have no rule for. Many ML-based IDS in the literature report near-perfect accuracy on a single dataset but fail in practice, for three reasons:

- they force every input into a known class, so a new attack gets a wrong label;
- they raise too many false alarms;
- their evaluations leak test data into training.

AegisWeave targets exactly these weaknesses. It separates *"this is a known attack of type X"* from *"this is unusual but we cannot say what it is"* and from *"we are not sure"*. It never lets an ML score trigger an action by itself. And it evaluates itself on real public data with leakage checks.

### Who is it for?

The agreed first target (`docs/PRODUCTION_TARGET.md`) is a **small office LAN of about 25–100 devices**, run by one part-time administrator, with passive monitoring and human-reviewed alerts. [PLANNED — not yet deployed or piloted]

### Core technical approach

1. **Input.** Zeek connection records are normalised into a strict `Flow` object: addresses, ports, protocol, duration, packets and bytes in each direction, and connection state.
2. **Two feature groups.** 17 per-flow features plus 16 per-host behaviour features, computed over sliding windows of 5, 30, 60 and 300 seconds.
3. **Five evidence layers.**
   - a supervised gradient-boosted classifier (which known class?)
   - a benign-only Isolation Forest (is this unlike normal traffic?)
   - a temporal classifier over the behaviour windows
   - a robust behaviour-profile distance
   - a nearest-neighbour **class-support** check (is this flow actually close to training examples of the predicted class?)
4. **Fusion.** A stacked logistic regression combines the layers into one fused attack score.
5. **Decision.** An explicit rule produces one of five decisions: `normal`, `suspicious`, `anomalous`, `malicious` or `unknown`.
6. **After the decision.** An attribution step names the attack type only when it is supported. A risk score (0–100) is capped by the decision. A response engine is simulation-only.

### What has been implemented?

- The complete software pipeline, from log ingestion to dashboard. [IMPLEMENTED]
- Model training and evaluation on synthetic data, **UNSW-NB15**, **IoT-23** (1,204,888 real Zeek records) and a separate **CICIDS2017** (corrected) baseline. [IMPLEMENTED]
- A REST API with role-based tokens, a 7-view dashboard, and a durable log collector. [IMPLEMENTED]
- Backup and restore, and a test suite of 164 tests plus an 88-check end-to-end verification. [IMPLEMENTED]
- A Linux/Docker deployment configuration. [PARTIALLY IMPLEMENTED — written, never run]

### Current status

The **software is a complete, working, tested prototype**. The **models are research-grade, not deployment-grade**:

- On captures never seen in training (IoT-23 protocol C), 10.27 % of benign flows cross the binary threshold.
- All command-and-control traffic is given the wrong attack type (`scan`).
- A day-separated CICIDS2017 baseline detected 0 of 736 botnet flows.

The dashboard's default model is a **synthetic-data demo model**. No real-data model has been promoted to it.

### What remains?

- Per-site calibration and representative benign office traffic.
- Validation with a real Zeek sensor.
- A first run of the Docker deployment.
- An authorised office observation pilot.
- Measured load testing.
- Resolving the known model failures (cross-network false alerts, command-and-control attribution, botnet coverage).

### PROJECT IN ONE PARAGRAPH

AegisWeave is a passive, machine-learning network intrusion detection prototype. It ingests Zeek connection logs, turns each connection into 17 flow features and 16 host-behaviour features, and scores them with five complementary models (supervised gradient boosting, benign-only Isolation Forest, temporal gradient boosting, behaviour-profile distance and a nearest-neighbour class-support check) combined by a stacked logistic regression. A transparent rule then decides whether the flow is normal, suspicious, anomalous (unlike normal but of unknown type), malicious (a supported known attack) or unknown (not enough reliable evidence). Each decision comes with an explanation, a capped risk score and incident grouping. Everything is shown on a role-protected web dashboard, where analysts can request only simulated, policy-gated, human-approved responses. The software is complete and heavily tested. The models have been evaluated honestly on synthetic data, UNSW-NB15, IoT-23 and CICIDS2017, and they still show significant weaknesses on unseen networks, so the system is a validated research prototype, not a production IDS.

### PROJECT IN 10 BULLET POINTS

1. **Input:** Zeek `conn.log` records (TSV or JSON), normalised JSONL, or JSON over REST. No raw packet capture is performed by our code. [IMPLEMENTED]
2. **Representation:** each connection becomes 17 flow features plus 16 behaviour-window features. IP addresses and labels are never model inputs. [IMPLEMENTED]
3. **Models:** five scikit-learn evidence layers plus stacked fusion, trained on disjoint train / calibration / fusion / tuning / test partitions. [IMPLEMENTED]
4. **Decisions:** five analyst-facing outcomes, including `anomalous` ("attack type uncertain") and `unknown` (abstain). [IMPLEMENTED]
5. **Explainability:** one-feature log-odds sensitivity, fusion terms and a plain-language attribution statement on every event. [IMPLEMENTED]
6. **Risk:** a 0–100 score from weighted evidence plus trusted asset importance, capped by decision (only `malicious` can exceed 69). [IMPLEMENTED]
7. **Response:** simulation only, behind a decision gate, allowlist, risk and confidence gates, human approval, expiry, rollback, rate limit and kill switch, all audited. [IMPLEMENTED]
8. **Platform:** FastAPI backend, SQLite storage, vanilla-JavaScript 7-view dashboard, durable Zeek collector, backup/restore; 164 tests and an 88-check end-to-end run. [IMPLEMENTED]
9. **Evidence:** real-data evaluation on IoT-23 (1.2 M flows, three protocols), UNSW-NB15 and a CICIDS2017 baseline, with unseen-vector and held-out-capture results reported next to headline scores. [IMPLEMENTED]
10. **Not done:** live Zeek sensor, Docker run on Linux, office pilot, per-site calibration, production-quality cross-network accuracy. [PLANNED]

---

# PART 2 — PROBLEM DEFINITION

### 2.1 Cybersecurity perspective

Attackers who get onto a network have to *communicate*. They scan for targets, guess passwords, flood services, receive commands from a controller (command-and-control, "C&C"), or copy data out. Much of this is visible in **how hosts talk to each other**, even when the content is encrypted.

An IDS watches that communication and raises alerts. The hard part is not raising alerts. It is raising **few, correct and understandable** alerts, because every false alarm costs an analyst's time. Too many false alarms train people to ignore the system.

### 2.2 Networking perspective

A network carries **packets**. A sensor such as Zeek reassembles packets into **connections** and writes one log line per connection when it ends: who talked to whom, on which port and protocol, for how long, and how many packets and bytes went each way.

This **flow-level** view is cheap to store, privacy-friendly (no payload), and still works when traffic is encrypted. It is also lossy. Many attacks look identical to normal traffic at flow level, and some flow fields are left empty by the sensor (Zeek writes `-` for unset values).

### 2.3 Machine-learning perspective

The ML task looks like classification (normal vs. attack types), but it has properties that break naive ML:

- **Class imbalance.** Attacks can be rare or overwhelming depending on the dataset: IoT-23 has more scan flows than normal flows.
- **Open set.** New attack types appear that were never in training. A normal classifier must still pick one of its known classes, so it will mislabel them.
- **Distribution shift.** A new network has different "normal" traffic.
- **Leakage.** Public datasets contain many exact duplicate rows, so random splits put the same row in both training and test and inflate scores.
- **Cost asymmetry.** False positives consume human attention; false negatives miss attacks.

### 2.4 Software-engineering perspective

A detector is only useful inside a system. That system must:

- reliably ingest logs without losing or duplicating records;
- validate untrusted input;
- keep results;
- present them;
- protect itself (authentication, rate limits);
- never let a model error turn into a harmful action.

### 2.5 Academic / research perspective

Sommer & Paxson (2010) argue that ML-based intrusion detection often fails outside the lab: its "closed world" assumptions, costly errors and weak evaluation don't survive real networks. Arp et al. (2022) catalogue common pitfalls in ML security research, such as data snooping and spurious correlations. [EXTERNAL BACKGROUND]

Our project uses these critiques as design requirements rather than just citing them.

### 2.6 Motivation, users and operating scenario

- **Motivation.** Build an IDS that is honest about uncertainty, explains itself, is safe by construction, and is evaluated without self-deception.
- **Target users** (from `docs/PRODUCTION_TARGET.md`) [PLANNED]:
  - a part-time office administrator (few, clear alerts);
  - an analyst (evidence, search, incidents);
  - a researcher (reproducible metrics).
- **Operating scenario** [PLANNED]:
  1. A Zeek sensor on a switch mirror (SPAN) port writes JSON logs.
  2. `aegisweave collect` reads them and posts them to the API over HTTPS.
  3. The analyst reviews alerts on the dashboard behind a TLS proxy.
  4. No automatic blocking happens.

  Today the same flow is exercised with **recorded** Zeek logs from IoT-23, not a live sensor.

### 2.7 Threat model (summary — full version in Part 20)

- **Attackers we want to detect:** hosts performing scanning, brute force, flooding / DoS, C&C beaconing and data exfiltration that shows up in flow metadata.
- **Attackers against the NIDS itself:** unauthenticated API users, flooding of the ingest API, forged telemetry, evasion by mimicking normal flows, tampering with model files.

### 2.8 Constraints

- ₹0 budget; one Windows laptop (Intel i7-13650HX, 24 GB RAM).
- No office network access and no mirror port.
- Docker and Zeek are not installed on the development machine.
- One semester.
- Ethical rule: no scanning or attacking of real networks.
- Safety rule: *an ML prediction must never execute a command*.

### 2.9 Assumptions

- Flow metadata carries enough signal for the attack types in scope.
- Zeek-style connection records are the sensor interface.
- Asset importance comes from trusted local configuration, never from telemetry.
- Public datasets are only proxies for a real office network.

---

# PART 3 — NIDS FUNDAMENTALS

Each concept is explained simply first, then technically, then in terms of our project.

### Intrusion detection

- **IDS (Intrusion Detection System).** Software that watches activity and reports signs of attack. It *detects*; it does not necessarily *block* (a system that blocks is an **IPS**, Intrusion Prevention System). **Ours is an IDS**: response is simulated only.
- **NIDS vs. HIDS.** A **network** IDS watches traffic on the wire. A **host** IDS watches one computer's logs, files and processes. **Ours is a NIDS.** It sees only flow metadata, so it cannot see what happens inside a host.

### Detection approaches

- **Signature / misuse detection.** Matches known attack patterns (rules). Precise for known attacks, blind to new ones. *We do not use rules.* Our supervised layer is the ML analogue: it learns patterns of *known* attack classes from labelled data.
- **Anomaly detection.** Learns what normal looks like and flags deviations. It can catch new attacks, but also flags unusual-but-harmless traffic. Our **Isolation Forest (benign-only)** and **behaviour-profile distance** layers are anomaly detectors.
- **Hybrid detection.** Combines both. **AegisWeave is a hybrid**, combined through a learned fusion layer and an explicit decision rule.

### The confusion matrix and its terms

For a binary attack-vs-benign decision:

| | Predicted attack | Predicted benign |
|---|---|---|
| **Actually attack** | True positive (TP) | False negative (FN) — missed attack |
| **Actually benign** | False positive (FP) — false alarm | True negative (TN) |

`metrics()` in `aegisweave/ml.py` computes all of these and stores the confusion matrix in each result file.

### Metrics

| Metric | Formula | Plain meaning | Why it matters for a NIDS |
|---|---|---|---|
| Accuracy | (TP+TN)/all | Share of correct calls | Misleading under imbalance (see Part 15) |
| Precision | TP/(TP+FP) | Of the alerts, how many were real | Low precision means analysts drown in noise |
| Recall / detection rate | TP/(TP+FN) | Of the attacks, how many were caught | Low recall means missed intrusions |
| F1 | 2PR/(P+R) | Balance of precision and recall | A common single summary |
| False-positive rate (FPR) | FP/(FP+TN) | Share of benign traffic that raises an alarm | Drives operator workload. We pick thresholds for FPR ≤ 5 % on a tuning split |
| ROC-AUC | Area under TPR-vs-FPR curve | Ranking quality across all thresholds | Independent of the chosen threshold |
| PR-AUC | Area under precision-recall curve | Ranking quality focused on the attack class | More informative than ROC under heavy imbalance |

### Attack classification and novel attacks

- **Attack classification** means naming the attack type, not just saying "attack". We call this **attribution** and treat it as a separate step from detection.
- **Zero-day / novel attacks** are attacks absent from training. **We do not claim zero-day detection.** We measure behaviour on *withheld* attack classes: an attack class removed from training on purpose, then tested. Unfamiliar traffic is designed to be labelled `anomalous` (type uncertain) instead of being given a wrong known type.

### Traffic representation

- **Packet vs. flow.** A packet is one unit on the wire. A **flow** (connection) groups packets sharing source/destination address, ports and protocol. **Our unit of analysis is the flow.**
- **Flow features** are numbers derived from a flow: duration, packet and byte counts, rates, direction ratios, protocol, destination port, whether the connection failed. Ours are listed in Part 11.

---

# PART 4 — HISTORICAL AND RESEARCH BACKGROUND

> All content in this part is **[EXTERNAL BACKGROUND]**, drawn from the papers the project cites. Specific numeric results from papers are omitted unless central and well established. The uploaded literature mentioned in the brief was not available (Part 0).

### Research timeline

```
1987  Denning — statistical intrusion-detection model (profiles of normal behaviour)
1999  Paxson — Bro (now Zeek): real-time network monitoring into connection logs
2008  Liu, Ting & Zhou — Isolation Forest (efficient unsupervised anomaly detection)
2010  Sommer & Paxson — why ML-based intrusion detection struggles in real networks
2013  Scheirer et al. — open-set recognition (classifiers must reject the unknown)
2015  Moustafa & Slay — UNSW-NB15 dataset
2017  Guo et al. — temperature scaling for calibrated probabilities
2018  Sharafaldin, Lashkari & Ghorbani — CICIDS2017 dataset
2018  Mirsky et al. — Kitsune: online ensemble of autoencoders for NIDS
2020  Garcia, Parmisano & Erquiaga — IoT-23 labelled Zeek IoT dataset
2021  Engelen, Rimmer & Joosen — errors found in CICIDS2017 flow construction and labels
2022  Arp et al. — "Dos and don'ts" of ML in security (pitfalls in evaluation)
2022  Liu et al. (CNS) — error prevalence in NIDS datasets; corrected CICIDS2017 release
```

### Evolution of the field

| Era | Problem with what came before | New idea | Advantage | Limitation | Relevance to AegisWeave |
|---|---|---|---|---|---|
| **Early IDS** (1980s) | Manual audit-log review does not scale | Automated statistical profiles of normal behaviour (Denning) | Can flag unknown misuse | Normal behaviour drifts; many false alarms | Our behaviour-profile layer is a modern descendant |
| **Host-based IDS** | Attacks visible only in host logs | Monitor processes, files and logs per host | Deep visibility on one host | Must be installed everywhere | Out of scope: we are network-only |
| **Network-based IDS** | Host agents are hard to deploy | Watch traffic centrally (Bro/Zeek, Snort) | One sensor covers many hosts | No view inside encrypted content or hosts | We are a NIDS and consume Zeek logs |
| **Signature / rule IDS** | Anomaly systems too noisy | Match known attack signatures | Precise, explainable | Blind to new attacks; rule upkeep | Our supervised layer is the learned analogue; we add anomaly layers for what it cannot see |
| **Anomaly detection** | Signatures miss novel attacks | Model "normal" and flag deviations | Can catch the unknown | False positives on unusual-but-benign traffic | Isolation Forest (benign-only) and profile layers |
| **Statistical approaches** | Hand-set thresholds | Distributions, percentiles, divergences | Principled | Assumes stable distributions | Percentile calibration of anomaly scores; PSI drift monitor |
| **Data mining** | Manual feature design | Mine patterns from labelled logs | Scales to large data | Label quality; overfitting | Our training on labelled corpora |
| **Machine learning** | Rigid rules | Learn classifiers from features (trees, SVMs) | Strong on tabular flow data | Leakage, imbalance, closed-world assumption | Gradient boosting and stacking |
| **Deep learning** | Manual features | Learn representations (CNN, LSTM, autoencoders) | Can learn from raw inputs | Data-hungry, opaque, costly | **Not used**. Kitsune is our comparison point |
| **Modern intelligent NIDS** | Accuracy-only evaluation | Calibration, open-set handling, explainability, human-in-the-loop, honest evaluation | Trustworthy operations | Still an active research area | **Our main design focus** |

---

# PART 5 — EXISTING SYSTEMS AND RELATED WORK

> [EXTERNAL BACKGROUND]. Per-paper results are described qualitatively; this document reproduces no numbers that we have not verified.

**Denning (1987), "An intrusion-detection model", IEEE TSE 13(2).**
Problem: automating misuse detection. Method: statistical profiles of subjects' behaviour; alarms when behaviour deviates. Strength: foundational anomaly concept. Limitation: normal behaviour changes; threshold setting. **Relevance:** the ancestor of our behaviour-profile layer.

**Paxson (1999), "Bro: a system for detecting network intruders in real-time", Computer Networks 31.**
Problem: high-speed, robust network monitoring. Method: an event engine plus a policy language, producing connection-level logs. Strength: rich, efficient network telemetry. Limitation: detection logic is hand-written. **Relevance:** Bro is now Zeek, and its `conn.log` is our input format.

**Liu, Ting & Zhou (2008), "Isolation Forest", IEEE ICDM.**
Method: random trees isolate anomalies in fewer splits than normal points. Strength: fast, unsupervised, scales well. Limitation: struggles with anomalies hidden inside dense normal regions. **Relevance:** our anomaly layer, trained on benign traffic only.

**Sommer & Paxson (2010), "Outside the closed world", IEEE S&P.**
Problem: why ML-based NIDS rarely succeeds in practice. Key points: errors are expensive, there is a semantic gap between an "anomaly" and an "attack", training data is scarce, and evaluation is weak. **Relevance:** it motivated our explanations, our human-in-the-loop response and our evaluation design.

**Scheirer et al. (2013), "Toward open set recognition", IEEE TPAMI 35(7).**
Problem: classifiers assume every test input belongs to a known class. Idea: bound the "open space" and reject unknown inputs. **Relevance:** our class-support layer and the `anomalous` / "unattributed" outcome.

**Moustafa & Slay (2015), UNSW-NB15, MilCIS.**
A modern labelled dataset: synthetic mixed traffic from a cyber-range, 9 attack families, designated training and testing files. Limitation: synthetic generation; many duplicate rows. **Relevance:** our benchmark 1.

**Guo et al. (2017), "On calibration of modern neural networks", ICML.**
Problem: over-confident predicted probabilities. Method: temperature scaling. **Relevance:** we temperature-scale the supervised classifier's probabilities.

**Sharafaldin, Lashkari & Ghorbani (2018), CICIDS2017, ICISSP.**
Five days of benign and attack traffic with CICFlowMeter flow features. Limitation: later work found flow-construction and labelling errors. **Relevance:** benchmark 3, used in its corrected version.

**Mirsky et al. (2018), "Kitsune", NDSS.**
Online, unsupervised ensemble of autoencoders over packet statistics. Strength: lightweight, learns online. Limitation: reports anomalies only, with no attack type and no response workflow. **Relevance:** the closest comparison for an "anomaly-first" design; we add attribution and safety.

**Garcia, Parmisano & Erquiaga (2020), IoT-23, Stratosphere Laboratory.**
Real IoT malware and benign captures (20 malware and 3 benign scenarios), provided as labelled Zeek connection logs. **Relevance:** our main real-traffic dataset, processed through our own collector.

**Engelen, Rimmer & Joosen (2021), "Troubleshooting an intrusion detection dataset: the CICIDS2017 case study", IEEE SPW.**
Found flow-construction and labelling problems. **Relevance:** it is why we use a corrected CICIDS2017 release.

**Arp et al. (2022), "Dos and don'ts of machine learning in computer security", USENIX Security.**
Identifies ten common pitfalls, including data snooping, spurious correlations, inappropriate baselines and lab-only evaluation. **Relevance:** it guided our split-isolation checks, unseen-vector reporting and held-out-capture protocol.

**Liu et al. (2022), "Error prevalence in NIDS datasets" (IEEE CNS).**
Source of the corrected CICIDS2017 files and of the recommendation to map "attempted" attacks to benign. **Relevance:** our CICIDS2017 preparation follows it (`docs/CIC2017_BASELINE_REVIEW.md`).

### Comparison table

| Paper | Dataset | Model | Task | Metrics | Limitations | Relevance |
|---|---|---|---|---|---|---|
| Denning 1987 | Audit records | Statistical profiles | Anomaly detection | — | Drift; thresholds | Profile layer |
| Paxson 1999 | Live traffic | Event engine + policy scripts | Network monitoring | — | Hand-written policy | Zeek input |
| Liu 2008 | Benchmark data | Isolation Forest | Unsupervised anomaly | AUC | Local/dense anomalies | Anomaly layer |
| Sommer & Paxson 2010 | — (position paper) | — | Critique | — | — | Design principles |
| Scheirer 2013 | Vision benchmarks | 1-vs-set machine | Open-set recognition | — | Domain differs | Class-support layer |
| Moustafa & Slay 2015 | UNSW-NB15 | — (dataset) | Dataset creation | — | Synthetic; duplicates | Benchmark 1 |
| Guo 2017 | Image data | Temperature scaling | Calibration | ECE, NLL | Global recalibration only | Probability calibration |
| Sharafaldin 2018 | CICIDS2017 | Several ML baselines | Dataset creation | Precision, recall, F1 | Later-found errors | Benchmark 3 |
| Mirsky 2018 | Own IoT / camera traces | Autoencoder ensemble | Online anomaly detection | AUC, EER | No attribution | Comparison |
| Garcia 2020 | IoT-23 | — (dataset) | Dataset creation | — | Lab IoT; label granularity | Main real data |
| Engelen 2021 | CICIDS2017 | — | Dataset audit | — | — | Use corrected data |
| Arp 2022 | Surveyed papers | — | Methodology | — | — | Evaluation discipline |


---

# PART 6 — PROJECT REQUIREMENTS

**Sources:** the Week 1 activity file (frozen requirements), `docs/PRODUCTION_TARGET.md`, `CONTRACT.md` and the source code. The **Status** column states what the code actually does.

### Functional requirements

| ID | Requirement | Status | Evidence |
|---|---|---|---|
| FR1 | Ingest flows from Zeek conn.log (TSV/JSON), normalised JSONL and REST (single or batch ≤ 200) | [IMPLEMENTED] | `collectors.py`, `api.py` (`/api/telemetry`, `/batch`), `tests/test_collectors.py` |
| FR2 | Reject malformed, injected or labelled telemetry | [IMPLEMENTED] | `schema.py` (`extra="forbid"`, strict types), `tests/test_api_security.py` |
| FR3 | Multi-layer detection with fusion | [IMPLEMENTED] | `ml.py: fit_bundle, ModelBundle.components` |
| FR4 | Five analyst-facing decisions | [IMPLEMENTED] | `detection.py: decide` |
| FR5 | Per-event explanation | [IMPLEMENTED] | `ml.py: predict` (contributions, fusion terms), `detection.py: attribute` |
| FR6 | Risk 0–100 with severity; asset importance only from trusted config | [IMPLEMENTED] | `detection.py: assess_risk`; `--config` option in `__main__.py` |
| FR7 | Correlate alerts into incidents | [IMPLEMENTED] | `storage.py: _correlate` (source + sensor + simulated flag, 300 s linked windows) |
| FR8 | Response workflow with safety controls | [IMPLEMENTED] (simulation only) | `response.py`, `tests/test_response_safety.py` |
| FR9 | Web dashboard | [IMPLEMENTED] | `frontend/` (7 views) |
| FR10 | Drift monitoring per sensor | [IMPLEMENTED] | `detection.py: DriftMonitor, DriftRegistry` |
| FR11 | Model registry, integrity manifest, backup/restore | [IMPLEMENTED] | `ml.py: save/load`, `storage.py` models table, `backup.py` |
| FR12 | Continuous collection from a live Zeek sensor | [PARTIALLY IMPLEMENTED] | `ingest.py` works on files; never run against a live Zeek process |
| FR13 | Live containment on real devices | **Not implemented, by design** | `response.py`: `simulation: Literal[True]` |

### Non-functional requirements

| ID | Requirement | Status | Evidence |
|---|---|---|---|
| NFR1 | < 50 ms per flow including explanation | Met on the dev laptop: 7.7 ms p50 / 8.5 ms p95 (synthetic model) | `experiments/results/synthetic.json → performance` |
| NFR2 | Throughput adequate for a small office | [UNKNOWN] for the office. About 85 flows/s measured in replay with one worker | Report / README live replay; office peak not measured |
| NFR3 | Security of the NIDS itself | [IMPLEMENTED] | Part 19 |
| NFR4 | No silent telemetry loss; no duplicates on retry | [IMPLEMENTED] in the lab | `ingest.py`, `scripts/verify_collector.py` (8/8) |
| NFR5 | Reproducible, leakage-checked evaluation | [IMPLEMENTED] | `check_split_isolation`, `corpus.build_split`, seeds |
| NFR6 | Operator workload ≤ 5–10 actionable incidents per day | [PLANNED] — unmeasured | `docs/PRODUCTION_TARGET.md` |
| NFR7 | Portability (Windows / Linux / Docker) | Windows verified; Docker [PARTIALLY IMPLEMENTED] | `Dockerfile`, `deploy/` |

### ML requirements

- Train, calibrate, fuse, tune and test on **disjoint** partitions. [IMPLEMENTED]
- Handle class imbalance **without** synthetic oversampling (balanced sample weights). [IMPLEMENTED]
- Operating threshold chosen on a tuning partition under FPR ≤ 0.05. [IMPLEMENTED]
- Unknown attack types must not receive a known label (open set). [IMPLEMENTED — measured, not guaranteed]
- Missing measurements are declared, imputed from frozen training medians and discounted. [IMPLEMENTED]
- The model never retrains from live data. [IMPLEMENTED — no online learning code exists]

### Security requirements

Role tokens; a loopback-only demo mode; same-origin checks on state changes; CSP headers; body-size cap; rate limits; model integrity checks; simulated responses only; an audit log. All are [IMPLEMENTED] — details in Part 19.

### Networking requirements

- Consume Zeek connection records.
- Handle Zeek's unset fields and out-of-order emission.
- Support IPv4 and IPv6.
- Use HTTPS between collector and API in deployment ([PARTIALLY IMPLEMENTED]: configured in `deploy/`, never run).

### UI requirements

Seven views, role-aware controls, explanation drill-down, filters and search, export, and visible simulation labelling. [IMPLEMENTED]

### Backend requirements

REST/JSON API, a bounded inference queue with back-pressure (HTTP 429), health reporting, and OpenAPI access only when authenticated. [IMPLEMENTED]

### Data requirements

- Labels never enter telemetry.
- Source hashes are recorded for every dataset.
- Exclusions are counted and reported.
- Datasets live in `var/`, **outside Git**.

[IMPLEMENTED]

### Deployment requirements

- Linux + Docker Compose, Caddy TLS proxy, read-only containers, a required non-synthetic model, backups. [PARTIALLY IMPLEMENTED — `deploy/` exists, unverified]
- Office pilot of at least 14 days. [PLANNED]

---

# PART 7 — COMPLETE SYSTEM ARCHITECTURE

**The actual architecture.** Every box exists in code unless marked otherwise.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ TRAFFIC SOURCES                                                              │
│  • Zeek conn.log (TSV / JSON)  — recorded IoT-23 logs today   [IMPLEMENTED]  │
│  • Live Zeek on a mirror port                                  [PLANNED]     │
│  • Normalised JSONL files / synthetic demo generator           [IMPLEMENTED] │
└───────────────┬──────────────────────────────────────────────────────────────┘
                ↓   (no packet capture is done by our code)
┌──────────────────────────────────────────────────────────────────────────────┐
│ COLLECTION   collectors.py (replay)  ·  ingest.py (durable `collect`)        │
│  parse TSV/JSON → handle unset '-' fields → Flow → HTTP POST (batch ≤200)    │
│  SQLite spool, offsets + payload in one transaction, retry, 429 back-off     │
└───────────────┬──────────────────────────────────────────────────────────────┘
                ↓  HTTPS (deploy) / loopback HTTP (demo), Bearer token
┌──────────────────────────────────────────────────────────────────────────────┐
│ API  api.py + auth.py (FastAPI/Uvicorn)                                      │
│  body cap 2 MiB → auth/role → rate limit → pydantic Flow validation          │
│  → bounded queue (1024) → ONE ordered inference worker thread                │
└───────────────┬──────────────────────────────────────────────────────────────┘
                ↓
┌──────────────────────────────────────────────────────────────────────────────┐
│ DETECTION ENGINE  detection.py: DetectionEngine.process                      │
│  1 BehaviorEngine.observe  (host windows 5/30/60/300 s, re-ordering ≤300 s)  │
│  2 ModelBundle.predict     (17 flow + 16 behaviour features → 5 layers       │
│                             → stacked fusion → explanations)   ml.py         │
│  3 decide()      → normal | suspicious | anomalous | malicious | unknown     │
│  4 attribute()   → known type, or "unattributed" / "uncertain"               │
│  5 assess_risk() → 0–100, severity, capped by decision                       │
│  6 DriftRegistry.observe (PSI / total variation per sensor; never retrains)  │
└───────────────┬──────────────────────────────────────────────────────────────┘
                ↓
┌──────────────────────────────────────────────────────────────────────────────┐
│ STORAGE  storage.py (SQLite WAL, schema v2)                                  │
│  events · incidents · incident_events · responses · audit · settings · models│
│  retention: 100,000 events / 30 days; incident correlation 300 s             │
└───────┬──────────────────────────────────────┬───────────────────────────────┘
        ↓                                      ↓
┌─────────────────────────────┐   ┌───────────────────────────────────────────┐
│ DASHBOARD frontend/ (7 views│   │ RESPONSE ENGINE response.py               │
│ vanilla JS, polls REST API) │──▶│ decision gate → allowlist → risk ≥70 →    │
│ analyst requests/approves   │   │ confidence ≥0.8 → approval → TTL → audit  │
└─────────────────────────────┘   │ SIMULATION LEDGER ONLY — no live adapter  │
                                  └───────────────────────────────────────────┘
OFFLINE (not in the serving path):
  experiments/*.py  → train / evaluate → experiments/results/*.json, var/models/*
  corpus.py         → IoT-23 split protocols A/B/C with context isolation v2
  backup.py         → SQLite snapshot + verified restore
```

### Component notes

- **Collection** turns sensor output into validated `Flow` objects. The *replay* path (`collectors.forward`) is for recorded files; the *collect* path (`ingest.py`) is durable, continuous tailing.
- **The API** is the only way into the engine. There is exactly **one inference worker**, so flows are processed in arrival order. That order matters for the behaviour windows.
- **The detection engine** is the heart of the system. It is deliberately split into *score → decide → attribute → risk*, so that each step can be tested and audited separately.
- **Storage** is a single-process SQLite database with write-ahead logging (WAL). Events and incident updates are written atomically.
- **The response engine** can only ever write to a *simulation ledger*: `Policy.simulation` is typed `Literal[True]`, so any other value is a validation error.
- **The dashboard** is static HTML/JS served by the API. It polls the REST endpoints and renders them.

### Key design decisions

**DECISION:** Flow-level (Zeek conn.log) input rather than raw packets.
**WHY:** Privacy (no payload), low cost, works on encrypted traffic, and matches the IoT-23 format.
**ALTERNATIVES:** packet capture with deep inspection; NetFlow/IPFIX.
**TRADE-OFF:** payload-based attacks are invisible, and some Zeek fields are unset.
**EVIDENCE:** `collectors.py`, `schema.py`.
**CURRENT STATUS:** [IMPLEMENTED] with recorded logs; live sensor [PLANNED].

**DECISION:** A single ordered inference worker.
**WHY:** Behaviour windows depend on event order; a single SQLite writer is simpler and safe.
**ALTERNATIVES:** a worker pool; a message broker such as Kafka.
**TRADE-OFF:** throughput is bounded (about 85 flows/s measured in replay).
**EVIDENCE:** `api.py: InferenceWorker`.
**CURRENT STATUS:** [IMPLEMENTED].

**DECISION:** Separate detection, attribution, risk and response.
**WHY:** A model score must never directly cause an action; uncertainty must stay visible.
**ALTERNATIVES:** a single classifier plus an automatic block.
**TRADE-OFF:** more logic to maintain and explain.
**EVIDENCE:** `detection.py`, `response.py`.
**CURRENT STATUS:** [IMPLEMENTED].

---

# PART 8 — END-TO-END DATA FLOW

### 8.1 Inference data flow — following one connection

1. **Origin.** A device opens a TCP connection. A Zeek sensor observes it and, *when the connection ends*, writes one line to `conn.log` with the connection's **start** timestamp. (Today, that line comes from a recorded IoT-23 file.)

2. **Entry.** `python -m aegisweave replay FILE --format zeek-tsv --batch-size 200` (or the durable `collect` command for JSON logs) reads the line.
   - `read_zeek_tsv` parses the `#fields` header and handles the IoT-23 quirk of space-joined label columns.
   - `zeek_to_flow` builds a `Flow`:
     - `orig_pkts/orig_bytes` → `packets/bytes`; `resp_*` → `reverse_*`.
     - `conn_state` in {S0, REJ, RSTOS0} → `failed=True`.
     - `syn_ratio` is always declared **missing**, because Zeek's history string cannot give a measured SYN ratio.
     - Unset payload bytes are handled by explicit rules. Zero packets means zero bytes. A single TCP packet is assumed to carry zero payload. UDP/ICMP payload is estimated as IP bytes minus fixed header sizes. Each assumption is **recorded** on the flow (`measurement_assumptions`). Anything else is rejected.
   - Label columns are ignored.
   - The event ID is a UUID5 of sensor, Zeek `uid` and timestamp, so a replay produces the same ID and the server drops duplicates.

3. **Transport.** The flows are POSTed in batches of up to 200 to `/api/telemetry/batch` with an analyst token. If the queue is full the API returns 429 with `Retry-After`, and the collector backs off.

4. **Validation.** Pydantic rejects:
   - unknown fields (e.g. a smuggled `label`);
   - non-canonical or scoped IPs;
   - timestamps without a timezone;
   - negative or absurd counters;
   - flows with no packets in either direction.

   Missing optional fields are added to `missing_features`.

5. **Behaviour context.** `BehaviorEngine.observe` looks up the source host's history for this (sensor, simulated) stream.
   - If the flow started up to 300 s *earlier* than the newest flow already seen, it is **re-ordered** into place (Zeek emits connections when they end).
   - If it is later than that, it is *isolated*: it gets no history and cannot alter trusted history.
   - The engine computes connection counts in 5/30/60/300 s windows, unique destinations and ports, failure ratio, bytes, entropies, edge novelty and frequency, rate change, temporal consistency and packet-rate statistics.

6. **Features.** `flow_features` produces 17 numbers and `behavior_features` produces 16. Features whose inputs are missing are replaced with **frozen benign medians** from training, and the reliability score is reduced accordingly.

7. **Prediction** (`ModelBundle.predict`):
   - **Supervised.** Temperature-scaled class probabilities; attack score = 1 − P(normal).
   - **Anomaly.** The Isolation Forest raw score is ranked against held-out benign flows and mapped to [0, 1]. Only the top half of benign-like ranks gives positive evidence.
   - **Temporal.** P(attack) from the behaviour-window classifier.
   - **Profile.** Robust distance of the behaviour vector from the benign medians, ranked against held-out benign flows.
   - **Class support.** For each class, the percentile of this flow's 5-nearest-neighbour distance among held-out flows of that class.
   - **Fusion.** A 7-number evidence vector goes through StandardScaler and logistic regression to give the fused attack score.
   - **Explanation.** Each measured flow feature is reset to its benign median one at a time, and the change in attack log-odds and anomaly score is recorded; fusion terms are listed.

8. **Interpretation.** `decide()` applies the rule ladder (Part 12.9) to produce one of five decisions. `attribute()` gives the analyst-facing type: a class, `unattributed` or `uncertain`. `assess_risk()` gives the score, severity and recommended response.

9. **Storage and alerting.** `Store.add_event` inserts the event atomically. If the decision is not `normal`, `_correlate` attaches it to an open incident with the same source, sensor and simulated flag within 300 s, or creates one. The drift registry records summary statistics. There is **no push notification** (email/SMS/webhook) [not implemented]. An "alert" means a non-normal event visible on the dashboard and in incidents.

10. **To the user.** The dashboard polls `/api/overview`, `/api/events` and `/api/incidents` about every 5 s. The analyst opens an event to see the explanation and can request a response. Anything other than `notify` needs a `malicious` decision, and then policy gates, then approval. The result is a simulated ledger entry with an expiry time, and every step is audited.

### 8.2 Training data flow

```
Synthetic: demo.generate_episodes ──┐
IoT-23: corpus.load_capture ────────┼─► same collector + BehaviorEngine as serving
UNSW / CIC CSV: datasets.py ────────┘   (UNSW/CIC: 10 common counters only, no behaviour context)
                 ↓
Partitioning (disjoint): train | calibration | fusion | tuning | test
   synthetic: whole host episodes per partition, checked by check_split_isolation
   IoT-23:    20 arrival-order blocks per capture (protocols A/B) or whole captures held out (C),
              60 s boundary purge, behaviour rebuilt per partition (context isolation v2)
                 ↓
fit_bundle:
   train       → GradientBoosting (flow), IsolationForest (benign flows), HistGB (behaviour),
                 benign medians/IQR, class-support references
   calibration → temperature, benign anomaly/profile reference distributions, layer reliabilities,
                 class-support percentiles
   fusion      → logistic-regression stacker (6 variants)
   tuning      → decision threshold at FPR ≤ 0.05
                 ↓
evaluate on test (binary metrics, unseen-vector subset, decision-level outcomes)
                 ↓
ModelBundle.save → bundle.joblib + manifest.json (SHA-256, feature schema, sklearn version, metadata)
```

**Important:** the serving and training paths share `collectors.py`, `behavior.py` and `features.py`. This avoids **training/serving skew**, where features are computed differently in training and in production.

---

# PART 9 — DATASETS

> Datasets live under `var/datasets/` (about 2 GB), which is **git-ignored**. A teammate who clones the repository does **not** get the data, and must re-download it (Part 27). Results are committed in `experiments/results/`.

### 9.1 Synthetic episodes — `aegisweave/demo.py` [IMPLEMENTED]

- **Purpose:** implementation testing, the dashboard demo, and controlled stress tests. **Not evidence of real-world performance.** Every synthetic flow is marked `simulated=True`.
- **Generation:**
  - Each *episode* is one simulated source host with 22–44 flows. The first 4 flows are normal warm-up; the rest have the episode's class.
  - Class probabilities per episode: normal 0.38, scan 0.17, brute_force 0.15, dos 0.16, exfiltration 0.14.
  - Every third episode is "subtle": its per-flow values overlap with normal, so only the behaviour context distinguishes it.
  - An `unknown_beacon` family exists for open-set stress tests and is never in training.
- **Splits** (`ml.create_splits`): 80 / 24 / 24 / 24 / 40 episodes for train / calibration / fusion / tuning / test, drawn with different seeds. The test set has **1,348 flows: 586 benign and 762 attack**.
- **Limitations:**
  - hand-designed, so easy for behaviour features (a temporal-only model reaches F1 0.986);
  - the seed-42 test was inspected during development, so it is exploratory;
  - `experiments/confirm.py` re-tests the frozen model on fresh draws, but from the same generator.

### 9.2 UNSW-NB15 [IMPLEMENTED; present locally]

- **Source:** UNSW Canberra ([EXTERNAL BACKGROUND]: generated with the IXIA PerfectStorm tool in a cyber-range; 9 attack families).
- **⚠ Download provenance:** according to `experiments/results/unsw.json`, the official download timed out and the files were obtained from a **GitHub mirror** (`Nir-J/ML-Projects`). The bytes are SHA-256 hashed but **not authenticated by the dataset authors**. (`aegisweave/datasets.py` still names the official page as `UNSW_SOURCE`; the result file records the mirror.)
- **Files:** `UNSW_NB15_training-set.csv` (175,341 rows) and `UNSW_NB15_testing-set.csv` (82,332 rows), both CSV.
- **Target:** `attack_cat` — 10 classes: normal, analysis, backdoor, dos, exploits, fuzzers, generic, reconnaissance, shellcode, worms. The binary `label` is cross-checked against it.
- **Class distribution** (official test): normal 37,000; generic 18,871; exploits 11,132; fuzzers 6,062; dos 4,089; backdoor 583; analysis 677; and others.
- **What we use:** only 5 raw counters (`dur, spkts, sbytes, dpkts, dbytes`), turned into the **10 common features** (Part 11). Dataset-specific `ct_*` features, ports, IPs and timestamps are deliberately excluded, so the model cannot learn dataset artefacts.
- **Duplicates:** 93,383 duplicate feature rows within the training file and 39,083 within the test file. **36,516 of 82,332 test rows** exactly match a training vector, so results are reported on all rows *and* on the 45,816 rows never seen in training.
- **Limitations:**
  - synthetic lab traffic from 2015;
  - no host identity or chronology, so no behaviour features;
  - reduced counters make multiclass classification weak (macro F1 0.46).

### 9.3 IoT-23 [IMPLEMENTED; present locally, 8 of 23 captures, ~520 MB]

- **Source:** Stratosphere Laboratory, CTU Prague (Garcia et al. 2020). Labelled Zeek `conn.log.labeled` files. Source hashes are recorded per file.
- **Captures used and labels (as mapped by `corpus.IOT23_CLASSES`):**

| Capture | Records | Labels |
|---|---:|---|
| CTU-IoT-Malware-Capture-1-1 | 1,008,748 | scan 539,465 · normal 469,275 · C&C 8 |
| CTU-IoT-Malware-Capture-3-1 | 156,103 | scan 145,597 · attack_attempt 5,962 · normal 4,536 · C&C 8 |
| CTU-IoT-Malware-Capture-34-1 | 23,145 | dos 14,394 · C&C 6,706 · normal 1,923 · scan 122 |
| CTU-IoT-Malware-Capture-8-1 (Hakai) | 10,403 | C&C 8,222 · normal 2,181 |
| CTU-IoT-Malware-Capture-42-1 | 4,426 | normal 4,420 · C&C 3 · file_download 3 |
| CTU-Honeypot-Capture-5-1 | 1,374 | normal 1,374 |
| CTU-Honeypot-Capture-4-1 | 452 | normal 452 |
| CTU-IoT-Malware-Capture-44-1 | 237 | normal 211 · C&C 25 · dos 1 |
| **Total** | **1,204,888** | normal 484,372 · scan 685,184 · C&C 14,972 · dos 14,395 · attack_attempt 5,962 · file_download 3 |

- **Label mapping:**
  - Benign → `normal`
  - PartOfAHorizontalPortScan → `scan`
  - DDoS → `dos`
  - C&C variants → `command_and_control`
  - Attack → `attack_attempt`
  - FileDownload → `file_download`
- **Exclusions:**
  - **14,260** capture-34-1 "DDoS" records with **zero measured packets** (bad checksums). Learning "empty counters = DoS" would be a label artefact, so they are excluded and reported.
  - `file_download` (3 flows) is too rare to train on.
  - Only 135 DoS flows remain usable.
- **Reordering:** 452,276 flows (38 %) arrived out of event order and were re-sequenced within the 300 s tolerance.
- **Limitations:**
  - 2018–2019 lab IoT networks;
  - two captures dominate the corpus;
  - class balance varies wildly by capture;
  - repeated flow vectors are common (93 % of protocol A test rows repeat a fitting vector);
  - destination port carries capture-specific signal.

### 9.4 CICIDS2017 (corrected release) [IMPLEMENTED as an offline baseline; present locally, ~1.5 GB]

- **Source:** the corrected files from Liu et al. (CNS 2022), downloaded from KU Leuven DistriNet. The archive SHA-256 is recorded in `var/datasets/cicids2017-improved/acquisition.json`.
- **Size:** 5 day files, **2,099,976 records**. "Attempted" attack flows (11,979) were mapped to **benign**, following the correcting authors' recommendation.
- **Protocol:**
  - fit on Tuesday + Wednesday (capped at 200,000 per binary class; 378,578 rows);
  - calibrate the threshold on Thursday benign flows not seen in fitting (237,246 rows): threshold = 99th percentile;
  - test on Friday (547,557 rows) and Monday (371,624 benign rows).
- **Features:** 5 counters → 10 common features.
- **Limitations:**
  - CICFlowMeter byte counters are **not shown to equal** Zeek payload counters;
  - no deployable model is produced;
  - Friday contains botnet traffic that the fitting days do not.

### 9.5 Dataset selection rationale

| Dataset | Why used | Main risk |
|---|---|---|
| Synthetic | Tests the whole pipeline, including behaviour windows and open-set stress, safely | Not real traffic |
| UNSW-NB15 | A widely used public benchmark; comparability | Synthetic generation, duplicates, no chronology |
| IoT-23 | **Real Zeek logs**, so it goes through our real collector; supports behaviour windows | IoT lab networks, not office networks |
| CICIDS2017 (corrected) | A different network and different attack types; day-separated test | Different flow meter; no behaviour context |

**Not used:** KDD Cup 99 and NSL-KDD. They are outdated and have well-known problems. [EXTERNAL BACKGROUND]

---

# PART 10 — DATA PREPROCESSING

Only operations that are actually implemented are listed. The last table covers techniques we do **not** use.

| Operation | Input → output | Purpose | Implementation | Risk / leakage |
|---|---|---|---|---|
| Schema validation | Raw JSON/Zeek row → `Flow` or rejection | Untrusted-input safety | `schema.py` (pydantic strict, `extra="forbid"`) | Over-strict rules reject odd but real flows (e.g. packetless records) — counted and reported |
| Zeek unset-field handling | `-` fields → exact values, disclosed estimates, or rejection | Avoid silently inventing measurements | `collectors._payload_bytes`, `zeek_to_flow` | Estimates (single TCP packet = 0 payload; fixed headers) are disclosed on the event |
| Missing-value handling | Missing measurement → frozen **benign training median**; reliability discounted | Keep the model defined without guessing | `ml.predict` (`flow_center`, `profile_center`) | The median comes from **training** only, so no test leakage |
| Label isolation | Label columns → ignored in telemetry | Prevent label leakage | `zeek_to_flow`; schema forbids extra fields | — |
| Log transforms | Counts and rates → `log1p(x)` | Compress heavy-tailed counters | `features.py` (fixed, not fitted) | None: not fitted on data |
| Rate floors | Duration → max(duration, 1 ms) | Avoid division by zero | `features.py` | Documented approximation |
| One-hot protocol | TCP/UDP/ICMP/OTHER → 4 binary features | Categorical encoding | `features.py` | — |
| Robust scaling (for distances) | Features → (x − median)/IQR (IQR floor 0.15) | Distance layers | `ClassSupport`, profile distance | Fitted on **train** only |
| Standard scaling (fusion input) | Evidence vector → z-scores | Logistic-regression stability | `make_pipeline(StandardScaler(), LogisticRegression)` | Fitted on the **fusion** partition only |
| Duplicate handling | Duplicate vectors → **kept**, but reported; unseen-vector subset evaluated | Honest measurement | `datasets.feature_hashes`, `corpus.build_split` | Duplicates inflate headline scores, which is why both views are shown |
| Exclusions | Unrepresentable / rare-class records → excluded and counted | Avoid label artefacts | `corpus.load_capture`, `build_split` | Changes class distribution, so it is reported |
| Splitting | Data → train / calibration / fusion / tuning / test | Separate each fitting role | `ml.create_splits`, `corpus.build_split`, `public.py` (GroupShuffleSplit by feature hash) | See Part 14 |
| Class balancing | Imbalanced labels → **balanced sample weights** | Stop the majority class dominating | `compute_sample_weight("balanced", …)` | No synthetic samples created |
| Capping | Very large classes → per-(capture, label) caps (train 15,000; calibration/fusion/tuning 3,000; test uncapped) | Tractable training; stop one capture dominating | `corpus.DEFAULT_CAPS` | Seeded reservoir sampling |

**Not used:** SMOTE, random over/undersampling, general outlier removal, PCA and learned feature selection. The feature set is **fixed by design** (`features.py`). Any "feature selection" is the manual exclusion of identifiers, labels and dataset-specific fields. These techniques could be explored as [PROPOSED] work, but must be fitted on training partitions only.

---

# PART 11 — FEATURES

**Source:** `aegisweave/features.py` (`FEATURE_SCHEMA = "aegisweave.flow.v1"`). IP addresses, event IDs, timestamps and labels are **never** model features.

### 11.1 Flow features (17) — per connection

| # | Feature | Type | Definition | Why it matters | Notes |
|---|---|---|---|---|---|
| 1 | `log_duration` | float | log1p(duration in s) | Floods are short; exfiltration and beacons are long | |
| 2 | `log_packets` | float | log1p(forward packets) | Volume from the originator | |
| 3 | `log_bytes` | float | log1p(forward payload bytes) | Data sent | Zeek unset → disclosed estimate |
| 4 | `log_reverse_packets` | float | log1p(response packets) | Whether the server answered | Missing → benign median |
| 5 | `log_reverse_bytes` | float | log1p(response bytes) | Data returned | Missing → benign median |
| 6 | `log_packet_rate` | float | log1p(total packets / max(duration, 1 ms)) | Flooding intensity | |
| 7 | `log_byte_rate` | float | log1p(total bytes / max(duration, 1 ms)) | Bandwidth use | |
| 8 | `log_mean_packet_size` | float | log1p(total bytes / max(total packets, 1)) | Probes are tiny; bulk transfers are large | |
| 9 | `reverse_packet_share` | float [0,1] | response packets / total | One-sided traffic suggests scans or floods | |
| 10 | `reverse_byte_share` | float [0,1] | response bytes / total | Upload-heavy traffic suggests exfiltration | |
| 11–14 | `tcp`, `udp`, `icmp`, `other_protocol` | 0/1 | One-hot protocol | Protocol context | |
| 15 | `log_destination_port` | float | log1p(port) | Service targeted | **Leakage-like risk:** strongest supervised feature on IoT-23; partly learns capture-specific ports |
| 16 | `failed` | 0/1 | Zeek conn_state ∈ {S0, REJ, RSTOS0} | Scans and brute force fail often | Missing → benign median |
| 17 | `syn_ratio` | float [0,1] | Share of SYN packets | SYN floods and scans | **Always missing for Zeek input** → benign median |

Features 1–10 are the **common features** (`COMMON_FEATURES`). They are the only ones available for UNSW-NB15 and CICIDS2017, which is why those benchmarks use a reduced model.

### 11.2 Behaviour features (16) — per source host, event-time windows (`behavior.py`)

| Feature | Definition | Detects |
|---|---|---|
| `log_connections_5s/30s/60s/300s` | log1p(flows from this host in the window) | Bursts, sustained activity |
| `log_unique_destinations_30s` | Distinct destination IPs in 30 s | Horizontal scanning |
| `log_unique_ports_30s` | Distinct destination ports in 30 s | Vertical scanning |
| `failed_ratio_30s` | Failed flows / flows in 30 s | Scans, brute force |
| `log_bytes_30s` | Total bytes in 30 s | Exfiltration, floods |
| `destination_entropy` | Shannon entropy of destinations (30 s) | Spread vs. focus |
| `protocol_entropy` | Entropy of protocols (30 s) | Mixed behaviour |
| `new_edge` | 1 if (destination, port, protocol) is not in the prior window | Novel contacts |
| `edge_frequency` | Prior occurrences of this edge / prior flows | Repetition such as beaconing |
| `rate_change` | (5 s rate) / (rate over the previous 25 s), capped at 20 | Sudden bursts |
| `temporal_consistency` | Share of 5 s bins with activity | Persistence |
| `log_mean_packet_rate`, `log_packet_rate_std` | Packet-rate statistics over 30 s | Regular vs. erratic traffic |

**History reliability** = `available` × min(1, prior flows/8) × (1 − incomplete behaviour features/16). It scales the temporal and profile evidence down when a host has little history.

### 11.3 Feature importance (measured)

The supervised model stores impurity-based global importances in `metadata["feature_importance"]` (see the manifest of each model). **On IoT-23, destination port is the most important supervised feature** (README, `docs/MODEL_REVIEW_CONTEXT_V2.md`). Per-event importance is the one-feature sensitivity described in Part 12.8, which is **not causal and not SHAP**.

---

# PART 12 — MACHINE-LEARNING PIPELINE

```
DATA ─► VALIDATION/NORMALISATION ─► FLOW FEATURES (17) + BEHAVIOUR FEATURES (16)
     ─► PARTITION (train | calibration | fusion | tuning | test)
     ─► TRAIN layers (train) ─► CALIBRATE (calibration) ─► FIT FUSION (fusion)
     ─► CHOOSE THRESHOLD (tuning, FPR ≤ 5 %) ─► TEST (test + unseen subset + decisions)
     ─► SERIALISE (joblib + SHA-256 manifest) ─► LOAD/VERIFY ─► INFERENCE
```

No separate "feature selection" stage exists (Part 10). All code is in `aegisweave/ml.py` unless noted.

### 12.1 Supervised layer — Gradient Boosting

- **Level 1.** Learns which *known* class a flow resembles: normal, scan, dos, and so on.
- **Level 2.** Gradient boosting builds many shallow decision trees in sequence. Each new tree corrects the errors of the previous ones by fitting the gradient of the log-loss (Friedman 2001). Its probabilities are over-confident, so they are divided in log space by a **temperature** *T* chosen to minimise log-loss on the calibration partition: p ∝ exp(log p_raw / T), with T in [0.4, 4].
- **Level 3.** `GradientBoostingClassifier(n_estimators=65, learning_rate=0.075, max_depth=2, min_samples_leaf=12)`, balanced sample weights, trained on the 17 flow features of the **train** partition. Attack evidence = 1 − P(normal), passed to fusion as a logit.
- **Level 4.** Tree ensembles are strong baselines on tabular data. Temperature scaling follows Guo et al. (2017).
- **Why chosen:** handles mixed features and non-linearity, fast on a CPU, supports feature importance.
- **Alternatives:** Random Forest, XGBoost/LightGBM, neural networks (Part 36).
- **Weakness:** a closed-set model — it must choose a known class.

### 12.2 Anomaly layer — Isolation Forest (benign-only)

- **Level 1.** Learns only what *normal* looks like and scores how unusual a flow is.
- **Level 2.** Random trees split the data at random. Unusual points are isolated in fewer splits, which gives a higher anomaly score (Liu et al. 2008).
- **Level 3.** `IsolationForest(n_estimators=80, max_samples=min(256, n))`, fitted on **benign train flows** only. The raw score is converted to its percentile among **held-out benign calibration flows**, then mapped to max(0, 2·percentile − 1). So a flow more unusual than every held-out benign flow scores 1, and a median-normal flow scores 0.
- **Why:** gives evidence for attacks that were never in training.
- **Weakness:** unusual-but-harmless traffic (such as a new IoT device) also scores high. This is the main cause of cross-network false alerts.

### 12.3 Temporal layer — HistGradientBoosting on behaviour windows

`HistGradientBoostingClassifier(max_iter=65, max_leaf_nodes=12, learning_rate=0.075, min_samples_leaf=16, l2_regularization=1.0)`, trained as a binary model (attack vs. normal) on the 16 behaviour features. Its evidence is multiplied by history reliability, so hosts with little history count less.

### 12.4 Behaviour-profile layer

A robust distance: the mean of min(|b − benign median| / IQR, 20) over the behaviour features. It is ranked against held-out benign distances and mapped like the anomaly score. This is an unsupervised "how unlike normal host behaviour" signal, in the tradition of Denning (1987).

### 12.5 Class-support layer (open-set attribution)

- **Level 1.** Asks: "the classifier says *scan* — but is this flow actually close to the scan flows we trained on?"
- **Level 2.** Scales features robustly (fitted on train). For each class, it computes the mean distance to the 5 nearest training flows of that class (up to 2,500 references per class). It ranks that distance against the same distance for **held-out calibration flows of that class**. A percentile above **0.99** means the flow is farther from the class than 99 % of genuine held-out examples: *unsupported*.
- **Level 3.** `ClassSupport(k=5, max_reference=2500, min_calibration=10)`. Classes with fewer than 10 calibration flows have **no support estimate**. Since fix `fc48844`, an attribution to such a class counts as *unverifiable* and can never become `malicious`.
- **Level 4.** A practical open-set rejection mechanism, inspired by open-set recognition (Scheirer et al. 2013). It is not a probability.

### 12.6 Stacked fusion

- **Evidence vector** (7 values; `META_FEATURES`):
  1. supervised logit × reliability
  2. anomaly × reliability
  3. temporal logit × history × reliability
  4. profile × history × reliability
  5. class entropy
  6. disagreement between layers (standard deviation)
  7. history reliability

  Layer reliabilities = max(0.1, 1 − Brier score) on the calibration partition.
- **Model:** StandardScaler + `LogisticRegression(C=0.5)`, fitted on the **fusion** partition only. This is stacked generalisation (Wolpert 1992).
- **Variants** for ablation: `full`, `hybrid` (supervised + anomaly + entropy), `without_anomaly`, `without_temporal`, `without_profile`.

### 12.7 Threshold selection

`choose_threshold`: on the **tuning** partition only, try candidate thresholds and keep the one with the best F1 subject to **FPR ≤ 0.05**. An explicit all-negative threshold is always available. The threshold is stored in `bundle.thresholds` and used for the binary metrics.

### 12.8 Explanation

For each of the 17 flow features (except imputed ones), `predict` resets that one feature to its benign training median and records:

- the change in supervised attack log-odds;
- the change in raw anomaly score.

It reports the top three by class effect and the top two by anomaly effect, plus the standardised fusion terms. This is **one-feature replacement sensitivity**: explicitly **not causal and not SHAP**. The counterfactual vector may not be a realistic flow.

### 12.9 Decision, attribution and risk (`detection.py`)

**Default thresholds** (`DetectionConfig`):

| Setting | Default |
|---|---|
| malicious | 0.78 |
| suspicious | 0.42 |
| minimum confidence | 0.70 |
| minimum reliability | 0.50 |
| anomaly | 0.95 |
| behaviour deviation | 0.85 |
| attribution percentile | 0.99 |

**`decide()` rule ladder** (first match wins):

1. The label is unknown, or reliability < 0.50 → **unknown**.
2. Novel (anomaly ≥ 0.95) AND (unsupported class, OR predicted normal with no support estimate) → **anomalous**.
3. Predicted normal:
   - behaviour deviation ≥ 0.85 → **unknown**;
   - else fused score ≥ 0.42 → **suspicious**;
   - otherwise → **normal**.
4. Fused score < 0.42 with no novelty or deviation:
   - low confidence or unsupported → **normal**;
   - otherwise → **unknown** (the layers disagree).
5. Confidence < 0.70 → **unknown**.
6. Class unsupported or unverifiable → **suspicious**.
7. Fused score ≥ 0.78 → **malicious**; otherwise → **suspicious**.

**`attribute()`** names the class only for supported decisions. Otherwise it says `unattributed` (anomalous) or `uncertain` (unknown), with a plain-language statement.

**`assess_risk()`**:

- Score = 42 × fused score + 14 × anomaly + 13 × behaviour deviation + 12 × persistence × deviation + 9 × class impact prior + 10 × asset importance.
- **Caps:** normal 24, unknown 59, suspicious 69, anomalous 69, malicious 100.
- **Severity:** medium ≥ 40, high ≥ 70, critical ≥ 85.
- The impact priors (for example dos 0.8, scan 0.45) are configured analyst policy, not learned.

### 12.10 Serialisation and loading

`ModelBundle.save` writes `bundle.joblib` (compressed) and `manifest.json` atomically. The manifest holds the SHA-256, feature schema, scikit-learn version and full metadata: training fingerprint, implementation-file hashes, hyperparameters, thresholds and leakage report.

`load` refuses to proceed on any schema, version, hash or metadata mismatch. **Joblib is executable serialisation**, so the model directory must be admin-owned: the SHA-256 detects corruption, not a deliberate attacker who replaces both files.

### 12.11 Model artifacts present (`var/models/`, git-ignored)

| Artifact | Trained on | Status |
|---|---|---|
| `active` | Synthetic episodes (seed 42) | **The dashboard default.** Demo-only |
| `iot23` | IoT-23 protocol A (historical context v1) | Research candidate, not promoted |
| `iot23-lco` | IoT-23 protocol C, captures 8-1 and 5-1 held out (v1) | Used for the live-replay experiment |
| `iot23-context-v2`, `iot23-lco-context-v2` | Corrected context-isolation runs | Research candidates, **not promoted** (`docs/MODEL_REVIEW_CONTEXT_V2.md`) |
| `archive`, `smoke` | Earlier / test artifacts | Not for use |


---

# PART 13 — MODEL COMPARISON

All numbers are copied from committed result files. A dash (—) means *not measured*. Binary metrics use each model's tuning-partition threshold.

### 13.1 Synthetic test (1,348 flows; `experiments/results/synthetic.json`)

| Model / variant | Precision | Recall | F1 | FPR | ROC-AUC | Note |
|---|---|---|---|---|---|---|
| Logistic baseline (flow features) | 0.978 | 0.765 | 0.859 | 2.22 % | 0.939 | Simple baseline |
| Supervised GB only | 0.978 | 0.867 | 0.919 | 2.56 % | 0.952 | |
| Anomaly (IF) only | 0.893 | 0.660 | 0.759 | 10.24 % | 0.842 | |
| Temporal only | 0.974 | 0.999 | 0.986 | 3.41 % | 0.9997 | Synthetic behaviour is easy |
| Hybrid (supervised + anomaly) | 0.985 | 0.864 | 0.920 | 1.71 % | 0.939 | |
| Without temporal | 0.939 | 0.945 | 0.942 | 8.02 % | 0.987 | |
| Without anomaly | 0.981 | 0.999 | 0.990 | 2.56 % | 0.9998 | |
| **Full fusion** | **0.997** | **0.992** | **0.995** | **0.34 %** | **0.9998** | |
| Without profile | 0.999 | 0.992 | 0.995 | 0.17 % | 0.9999 | **The profile layer adds nothing here** |

- Paired episode bootstrap (250 resamples): F1(full) − F1(supervised) = 0.075, 95 % interval [0.023, 0.144].
- Model training time: 3.4 s (shown in the dashboard's model card).
- Latency: 7.7 ms p50 / 8.5 ms p95 per event, including explanation.

### 13.2 IoT-23, corrected context isolation v2 (`experiments/results/iot23-context-v2.json`)

| Protocol / subset | Rows | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---:|---|---|---|---|---|
| A — time blocks, all test rows | 107,306 | 0.995 | 0.988 | 0.991 | 0.72 % | 0.999 |
| A — unseen flow vectors only | 7,136 | 0.874 | 0.741 | 0.802 | 7.06 % | 0.915 |
| B — attack_attempt withheld, all rows | 107,306 | 0.999 | 0.967 | 0.983 | 0.21 % | 0.999 |
| B — unseen flow vectors only | 7,136 | 0.914 | 0.303 | 0.455 | 1.89 % | 0.820 |
| C — 2 captures held out entirely | 11,777 | 0.957 | 1.000 | 0.978 | 10.27 % | 0.905 |

**Layer comparison on protocol C** (the new-network test):

| Model | Precision | Recall | F1 |
|---|---|---|---|
| Supervised only | 0 | 0 | 0.0 |
| Anomaly only | 0.903 | 1.0 | 0.949 |
| Temporal only | 0.111 | 0.0001 | 0.0002 |
| Full fusion | 0.957 | 1.0 | 0.978 |
| Without profile | 0.894 | 0.375 | 0.529 |

**Interpretation:** on a new network, the anomaly and profile layers do the detecting; the supervised layer alone fails completely.

**Decision-level results** (serving path, sampled test flows):

- **A:** 2.45 % of benign flows alert; 0.70 % are `malicious`.
- **B:** 939 of 940 withheld flows → `anomalous`, with no invented type.
- **C:** 24.70 % of benign flows alert and a further 8.20 % abstain. All sampled attacks are typed `scan` (**wrong**); 24.20 % reach `malicious`.

Full run time: 1,685 s over 1,204,888 records.

### 13.3 UNSW-NB15 (reduced 10-feature hybrid; `experiments/results/unsw.json`)

| Subset | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|
| All official test rows (82,332) | 0.927 | 0.881 | 0.904 | 8.5 % | 0.968 |
| Rows never seen in training (45,816) | 0.819 | 0.736 | 0.775 | 10.1 % | 0.921 |

- Multiclass macro F1 is 0.46. For example, per-class F1 is 0.06 for `analysis` and 0.98 for `generic`.
- **Open-set test** (4 families withheld): 6.2 % of their flows get a confident wrong type, **with or without** the class-support check. The support check gives **no measurable benefit** on this dataset.

### 13.4 CICIDS2017 corrected — offline counter baseline (`cic2017-baseline-v1*.json`)

| Model | Friday attack recall | Friday benign FPR | Monday benign FPR |
|---|---|---|---|
| Logistic regression | 37.35 % | 0.83 % | 0.69 % |
| **Boosted trees** | **99.15 %** | 1.21 % | 1.72 % |
| Benign Isolation Forest | 0.013 % | 0.74 % | 0.77 % |

Boosted trees per label on Friday: DDoS 99.98 %, PortScan 99.12 %, **Botnet 0 of 736 (0 %)**.

### 13.5 What these metrics mean for a NIDS

- **Headline F1 ≈ 0.99 is not the story.** On IoT-23, 93 % of test rows repeat a training vector. The unseen-vector F1 (0.80) is the more honest figure within known captures.
- **FPR drives workload.** 10 % FPR on 100,000 benign flows per day would be 10,000 false alerts, which is unusable without calibration and incident grouping.
- **Recall per attack type matters.** An aggregate 99 % can hide a complete miss (botnet 0/736).

---

# PART 14 — EXPERIMENTAL METHODOLOGY

| Aspect | What is done | Evidence |
|---|---|---|
| **Objectives** | (1) Does fusion beat single layers? (2) Does the open-set logic stop invented attack types? (3) How does the system transfer to unseen data and networks? (4) Is the serving path consistent with offline evaluation? | `experiments/*.py`, README |
| **Hypotheses** (implicit) | Fusion improves F1/FPR; the class-support check reduces wrong attribution; anomaly layers help on unseen networks | Result files test each one; outcomes are mixed (Part 29) |
| **Splits** | Synthetic: disjoint host episodes with 5 partitions. UNSW: designated train/test preserved, and validation groups formed by feature hash. IoT-23: A = 20 arrival-order blocks per capture in an interleaved pattern with a 60 s purge; B = A with `attack_attempt` removed from all fitting partitions; C = captures 8-1 and honeypot 5-1 held out entirely. CIC: day-separated | `ml.create_splits`, `public.py`, `corpus.py`, `cic_baseline.py` |
| **Leakage controls** | Episode/event-ID disjointness; exact feature-hash checks; withheld-class assertions; behaviour context rebuilt per partition (**isolation v2**, added after the original results); labels excluded from telemetry | `check_split_isolation`, `corpus.build_split` → `context_isolation` |
| **Seeds** | 42 throughout; `confirm.py` uses fresh seed 381947 | Result files |
| **Environment** | Windows 11, Intel i7-13650HX, Python 3.12.10, scikit-learn 1.9.1, single thread | `performance` blocks in the result files |
| **Baselines** | Logistic regression, single layers, unweighted supervised, fusion variants | `synthetic.json`, `iot23*.json` |
| **Ablations** | Fusion without anomaly / temporal / profile; with and without class support | Same |
| **Decision-level evaluation** | Every test flow passed through `predict → decide → attribute` | `ml.evaluate_decisions` |

### Methodological weaknesses (be open about these)

1. **Synthetic tests were inspected during development.** They are exploratory, not confirmatory. The confirmation run uses the same generator.
2. **IoT-23 protocol A is interleaved, not forward-in-time.** Blocks alternate between train and test within a capture, so it is optimistic.
3. **Context isolation was corrected afterwards.** The original IoT-23 results (`iot23.json`) predate the context-isolation fix. The corrected run (`iot23-context-v2.json`) is now the README's primary table; the historical tables are kept and labelled.
4. **The held-out captures have been seen.** After inspection, captures 8-1 and 5-1 are development data. A new untouched test set is needed for final claims.
5. **No hyperparameter search** was performed. Parameters were fixed by hand, which avoids overfitting to the test set but may leave performance unexplored.
6. **One seed** for most experiments; seed variance was not systematically reported.
7. **No cross-dataset training.** Each dataset is evaluated separately. Scores must not be pooled.

---

# PART 15 — MODEL EVALUATION CONCEPTS (APPLIED TO OUR RESULTS)

- **Confusion matrix.** Stored in every result file. For example, the synthetic full-fusion test has TN = 584, FP = 2, FN = 6, TP = 756 (from FPR 0.34 % of 586 and recall 0.992 of 762).
- **Specificity** = 1 − FPR.
- **False-negative rate** = 1 − recall. Both are stored (`false_positive_rate`, `false_negative_rate`).
- **PR-AUC.** Stored as `pr_auc` (average precision).
- **Brier score.** Stored. Used to measure calibration and to weight layers.
- **Per-class metrics.** `classification_report` output is stored in `per_class` / `multiclass` / `supervised_multiclass_official_test`.
- **Macro / weighted averages.** Included in the classification reports. Macro F1 treats every class equally, which exposes weak rare classes (UNSW macro F1 0.46).

### Why accuracy misleads

- In IoT-23 capture 1-1, **53 %** of flows are scans. A model that calls everything "scan" is right on 53 % of that capture while detecting nothing useful about the rest.
- In CICIDS2017 Friday, a model that ignores the 736 botnet flows loses only about 0.13 % of accuracy.

That is why we report precision, recall, FPR, per-class recall, unseen-vector subsets and decision-level outcomes, and not accuracy alone.

### Decision-level metrics (specific to our system)

| Metric | Meaning |
|---|---|
| benign → normal / alert / malicious | Operator workload |
| benign → unknown | Abstention cost |
| attacks flagged | Detection |
| attacks with correct type | Attribution quality |
| attacks with a wrong known type | Misleading attribution — the error our design most wants to avoid |

---

# PART 16 — REAL-TIME DETECTION

| Mode | Supported? | How |
|---|---|---|
| Offline / batch | **Yes** [IMPLEMENTED] | `experiments/*.py` score whole datasets |
| Streaming near-real-time | **Yes** [IMPLEMENTED] | Each flow is scored on arrival: 7–9 ms per flow; queue ≤ 1024; one ordered worker |
| Continuous ingestion from log files | **Yes** [IMPLEMENTED] | `collect` tails Zeek JSON logs, including rotated files |
| Live capture from a network interface | **No** | Requires a Zeek sensor [PLANNED] |
| Packet-level, in-line real-time | **No** | Out of scope |

### How inference timing works

1. A flow becomes visible **only when Zeek finishes the connection**. Long connections are therefore detected late — up to Zeek's inactivity timeout (300 s for TCP by default [EXTERNAL BACKGROUND]).
2. Once the flow arrives, API validation, queueing and inference take milliseconds. Measured throughput was about **85 flows/s** in replay, with a single worker, on a laptop.

**Verdict:** *near-real-time at flow granularity*, not packet-level real-time.

### What full real-time operation would need [PROPOSED]

- A Zeek sensor on a mirror port or TAP.
- Measured peak flow rates for the site.
- Horizontal scaling if the peak exceeds one worker (sharding by source host keeps the behaviour-window ordering).
- Load and soak tests (`docs/PRODUCTION_TARGET.md` capacity gate: sustain 2× measured peak for 60 minutes).
- Alert delivery beyond the dashboard (email or webhook).

---

# PART 17 — BACKEND

- **Framework:** FastAPI 0.141.1 on Uvicorn 0.52.4; Pydantic 2.13.5 for validation. App factory: `api.create_app()`; entry point: `python -m aegisweave serve` (`__main__.py`).
- **Middleware** (`api.py`):
  - request bodies capped at **2 MiB**;
  - security headers: `Content-Security-Policy` (script-src 'self', frame-ancestors 'none'), `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`.
- **Inference worker:** `InferenceWorker` — a bounded `queue.Queue(1024)` and one background thread. A full queue returns **429 with `Retry-After: 2`**.
- **Model loading:** at start-up from `--model` (default `var/models/active`, or the `AEGISWEAVE_MODEL` environment variable) via `ModelBundle.load` (hash-verified). If no model is present, the server starts in a degraded state and inference returns errors. `serve --require-real-model` refuses synthetic-trained models. Admins can hot-reload with `POST /api/models/reload`.
- **Error handling:**
  - inference failures raise `ModelUnavailableError`, and **no detection or response is produced**;
  - health reports `degraded`;
  - duplicate events return 409 with per-event detail.
- **Storage:** SQLite (`journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`); schema version 2 with migrations; retention of 100,000 events / 30 days; audit capped at 100,000 entries.
- **Logging:** Python `logging` (level from `AEGISWEAVE_LOG_LEVEL`); a `service_started` log line records model identity and auth mode.
- **Configuration:**
  - CLI flags: `--host --port --model --db --config`;
  - a detection config JSON (thresholds and asset importance; template `config/detection.example.json`).
- **Environment variables:**
  - `AEGISWEAVE_ADMIN_TOKEN`, `AEGISWEAVE_ANALYST_TOKEN`, `AEGISWEAVE_VIEWER_TOKEN` (role tokens);
  - `AEGISWEAVE_MODEL`;
  - `AEGISWEAVE_PUBLIC_ORIGIN` (HTTPS origin behind a proxy; requires tokens);
  - `AEGISWEAVE_TOKEN` (used by the collector);
  - `AEGISWEAVE_LOG_LEVEL`.

### API table (24 endpoints under `/api` plus `/` for the dashboard; source `aegisweave/api.py`, documentation `docs/API.md`)

| Endpoint | Method | Input | Output | Purpose | Min. role | Status |
|---|---|---|---|---|---|---|
| `/api/health` | GET | — | status, inference, database, queue, auth mode | Liveness / health | public | [IMPLEMENTED] |
| `/api/session` | GET | — | demo token | Loopback demo session only (404 when tokens are configured) | loopback | [IMPLEMENTED] |
| `/api/identity` | GET | token | role, mode | Who am I | viewer | [IMPLEMENTED] |
| `/api/openapi.json` | GET | token | OpenAPI schema | API schema (not public) | viewer | [IMPLEMENTED] |
| `/api/overview` | GET | — | totals, decisions, trend, latency | Dashboard KPIs | viewer | [IMPLEMENTED] |
| `/api/events` | GET | limit ≤ 500, decision, search | event list | Event stream | viewer | [IMPLEMENTED] |
| `/api/events/{id}` | GET | id | full event incl. explanation | Drill-down | viewer | [IMPLEMENTED] |
| `/api/incidents`, `/api/incidents/{id}` | GET | — / id | incidents, timeline | Investigations | viewer | [IMPLEMENTED] |
| `/api/behavior` | GET | — | host snapshots, graph edges | Behaviour view | viewer | [IMPLEMENTED] |
| `/api/drift` | GET | — | PSI / TV signals per stream | Drift view | viewer | [IMPLEMENTED] |
| `/api/metrics` | GET | — | process and runtime metrics | Operations | viewer | [IMPLEMENTED] |
| `/api/models` | GET | — | model registry and metadata | Model provenance | viewer | [IMPLEMENTED] |
| `/api/telemetry` | POST | one `Flow` JSON | scored event (201) | Ingest one flow | analyst (120/min) | [IMPLEMENTED] |
| `/api/telemetry/batch` | POST | `{"events":[Flow…]}` ≤ 200 | accepted events (201) or 409 duplicates | Ingest a batch | analyst (30/min) | [IMPLEMENTED] |
| `/api/demo` | POST | count, seed | generated simulated flows | Demo replay | analyst (10/min) | [IMPLEMENTED] |
| `/api/policies` | GET / PUT | `Policy` JSON | current policy | Read / change response policy, kill switch | viewer / **admin** | [IMPLEMENTED] |
| `/api/responses` | GET / POST | `ResponseRequest` (event_id, action, reason, ttl) | response record | List / propose an action | viewer / analyst | [IMPLEMENTED] |
| `/api/responses/{id}/approve` | POST | reason | updated record | Approve (re-checks policy) | analyst | [IMPLEMENTED] |
| `/api/responses/{id}/rollback` | POST | reason | updated record | Roll back | analyst | [IMPLEMENTED] |
| `/api/audit` | GET | limit | audit entries | Audit trail | analyst | [IMPLEMENTED] |
| `/api/models/reload` | POST | — | new model metadata | Load a verified artifact | **admin** | [IMPLEMENTED] |
| `/` | GET | — | dashboard HTML | UI | — | [IMPLEMENTED] |

Rate limits are per actor in 60-second windows (`auth.rate_limit`). **Note:** `approve` requires only the *analyst* role. A two-person rule (proposer ≠ approver) is **not verified** from the code and should be treated as absent [RECOMMENDATION: add one].

### Backend security concerns

- The demo mode issues an admin session to any **loopback** client. It is safe on a personal machine but must never be exposed; the server refuses a remote bind without tokens.
- Joblib model files are executable; protect `var/models/` with filesystem permissions.
- There is a single process, so no high availability.

---

# PART 18 — FRONTEND / DASHBOARD

- **Framework:** none. Plain **HTML + CSS + vanilla JavaScript** (`frontend/index.html`, `app.js` 285 lines, `styles.css`), served by the API at `/` with assets under `/static/`. No build step; compatible with the strict CSP.
- **State:** a single `state` object in `app.js` (current page, token, role, filters, cached data, errors). Navigation uses URL hashes (`#overview`, `#events`, …). Data refreshes by polling about every 5 s, with protection against stale responses overwriting newer filters.
- **Auth:** a token is taken from the configured session, or from `/api/session` in loopback demo mode, with automatic demo-session recovery after a server restart. `/api/identity` sets role-aware controls: viewers cannot see admin actions.

### What a user sees (seven views) [IMPLEMENTED]

| View | Content |
|---|---|
| **Overview** | KPI cards: total events, detected threats (= malicious), novel behaviour (= anomalous), investigation signals (suspicious + anomalous + uncertain), critical incidents, response actions. A detection-activity chart by decision, a classification-mix donut, and "inside the engine" averages (confidence, anomaly, deviation) |
| **Live events** | Searchable, filterable, sortable table (time, source → destination, attribution, decision, confidence, anomaly, risk, severity), with JSON export. An event drawer shows the explanation, attribution statement, feature-sensitivity table and response request |
| **ML analytics** | Held-out metrics of the active model (clearly labelled *Simulated* for the demo model), model identity and version, and analyst-facing decision rates. For real-data models it shows provenance (protocol, held-out captures, cross-capture F1/FPR) |
| **Behaviour** | Communication map of recent endpoints, drift "distribution monitor", and per-host activity windows |
| **Incidents** | Correlated incidents per source host with severity, event count, risk and last-seen time |
| **Response** | Approval boundary (pending / active / kill switch), guardrail summary and the simulation ledger. Denials show their reason |
| **System health** | Component status (telemetry intake, inference, storage, queue), response-policy form (kill switch, risk and confidence gates, rate, TTL, allowlist), operational measurements JSON, model lifecycle and reload |

- **Testing:** `node frontend/check-ui.cjs` checks metric precision, drift counts, role controls, health, stale refresh, response reasons and safe (escaped) rendering. [IMPLEMENTED]
- **Known UI issue:** the "Simulation workspace. Replay generates synthetic telemetry" banner is **static HTML** (`frontend/index.html`, line 31), so it is always shown, even when the displayed events are real recorded IoT-23 flows. [RECOMMENDATION: drive the banner from the events' `simulated` flag.]
- **Not implemented:** user accounts or login pages (tokens only), push notifications, report export beyond JSON, mobile-specific layout testing.

---

# PART 19 — SECURITY ARCHITECTURE (SECURITY OF THE NIDS ITSELF)

| Concern | How it could hurt us | What exists | Status |
|---|---|---|---|
| **Unauthorised access** | Reading sensitive traffic metadata; changing policy | Role tokens (viewer < analyst < admin), constant-time comparison (`hmac.compare_digest`); demo session loopback-only with Host and forwarding-header checks; remote bind without tokens refused | [IMPLEMENTED] |
| **CSRF / cross-origin** | A web page tricks the browser into acting | Same-origin check on unsafe methods; `AEGISWEAVE_PUBLIC_ORIGIN` behind a proxy (HTTPS only) | [IMPLEMENTED] |
| **XSS in the dashboard** | Injected hostnames or strings run script | Strict CSP (`script-src 'self'`); all dynamic values escaped (tested) | [IMPLEMENTED] |
| **API abuse / flooding** | Resource exhaustion | 2 MiB body cap; per-actor rate limits; bounded queue with 429; batch ≤ 200 | [IMPLEMENTED] |
| **Forged / poisoned telemetry** | Fake flows create false alerts or hide real ones | Schema validation; labels and asset priority rejected; a `simulated` flag separates demo streams; an analyst token is required to ingest | [PARTIALLY IMPLEMENTED]: an attacker holding an analyst token can still inject plausible fake flows |
| **Data / model poisoning** | Corrupting training data | **No online learning**: live data never updates the model; retraining is offline and manual | [IMPLEMENTED] by design |
| **Model tampering** | Replacing the model with malicious code (joblib is executable) | SHA-256 manifest, schema and version checks; tampered model refused at start-up (verified); admin-owned directory | [PARTIALLY IMPLEMENTED]: the hash does not stop someone who can replace both files |
| **Evasion / adversarial traffic** | An attacker shapes flows to look benign (slow scans, mimicked sizes and ports) | Anomaly and behaviour layers make pure mimicry harder; nothing specifically adversarial | **Not addressed** [PROPOSED: adversarial evaluation] |
| **Feature manipulation** | Spoofed ports or protocols | The supervised model relies on destination port, which is easy to change | **Known weakness** |
| **Alert flooding** | Drowning analysts | Incident correlation; risk caps; `unknown` abstention | [PARTIALLY IMPLEMENTED]: no alert suppression or rate-based summarisation |
| **Model extraction** | Querying the API to copy the model | Authentication plus rate limits make it costly | [PARTIALLY IMPLEMENTED] |
| **Harmful automated response** | A model error blocks a legitimate server | Simulation only; decision gate; allowlist; risk ≥ 70; confidence ≥ 0.8; approval; TTL; rollback; kill switch; rate limit; audit in the same transaction | [IMPLEMENTED] |
| **Privacy** | Flow metadata reveals who talks to whom | No payload stored; local only, no cloud; retention 30 days / 100,000 events | [IMPLEMENTED] |
| **Logging risks** | Logs leak tokens | Tokens are never logged (`service_started` records only the auth mode); `.env` is git-ignored | [IMPLEMENTED] as far as inspected |
| **Transport** | Sniffing tokens on the LAN | TLS via Caddy in `deploy/` | [PARTIALLY IMPLEMENTED] (never run) |

---

# PART 20 — THREAT MODEL

**Assets:**

- captured flow metadata;
- detection results and incidents;
- response policy and ledger;
- audit log;
- model artifacts;
- role tokens;
- availability of the service;
- analysts' attention.

**Attackers:**

- **A1** — an external attacker on the monitored network, who wants to avoid detection;
- **A2** — a malicious or compromised insider holding a token;
- **A3** — someone with local file-system access to the server;
- **A4** — a web attacker targeting the analyst's browser;
- **A5** — a noisy but harmless device (not malicious, but it causes false alerts).

**Trust boundaries:**

1. The network, then the sensor, then the collector (untrusted telemetry).
2. The collector, then the API (token-authenticated).
3. The API, then storage and the model (trusted process).
4. The browser, then the API (tokens plus same-origin).
5. Administrator-owned files (models and config).

| Asset | Threat | Attack vector | Impact | Mitigation | Status |
|---|---|---|---|---|---|
| Detection quality | Evasion | A1 shapes slow / low / port-mimicking traffic | Missed attack | Multi-layer evidence; behaviour windows | Partial; untested adversarially |
| Analyst attention | False-alert flood | A5 new devices; A1 deliberate noise | Alert fatigue | Correlation; risk caps; abstention | Partial; 10 % cross-network FPR unresolved |
| Integrity of results | Telemetry injection | A2 with an analyst token | Fake incidents / hidden activity | Token roles; schema validation; audit | Partial |
| Model artifact | Replacement with a malicious pickle | A3 file access | Code execution | SHA-256 manifest; admin-owned directory; `--require-real-model` | Partial |
| Response policy | Unauthorised change or kill-switch abuse | A2 stealing an admin token | Disabled safeguards | Admin-only PUT; audited | Implemented |
| Network availability | Harmful containment | Model error | Business disruption | Simulation-only; gates; approval; TTL | Implemented |
| Dashboard users | XSS / CSRF | A4 | Token theft, forged actions | CSP; escaping; same-origin | Implemented |
| Service availability | Request flooding | A1/A2 | Missed telemetry | Body cap; rate limits; bounded queue; 429 back-pressure; durable collector spool | Implemented (single node) |
| Flow metadata | Disclosure | Unauthorised read; plain HTTP | Privacy breach | Tokens; TLS (deploy); retention | Partial (TLS unverified) |


---

# PART 21 — PROJECT DIRECTORY AND CODEBASE ANALYSIS

```
nids project/
├── aegisweave/            application package (≈3,700 lines of Python)
├── frontend/              dashboard (HTML/CSS/JS) + UI regression script
├── tests/                 14 pytest files, 164 tests
├── experiments/           training/evaluation scripts + results/*.json (committed)
├── scripts/               verification, dataset acquisition, demo launcher
├── config/                detection.example.json
├── deploy/                Linux office deployment candidate (Compose, Caddy, Dockerfile)
├── docs/                  reviews, API, collector, backup, plans, report/
├── Dockerfile             demo container (bakes a synthetic model)
├── START_PROTOTYPE.cmd    one-click Windows demo (port 8775)
├── README.md, CONTRACT.md, pyproject.toml, requirements.lock
└── var/  (git-ignored)    datasets/, models/, databases, verification reports, prototype runs
```

| Path | Purpose | Important functions / classes | Depends on | Status |
|---|---|---|---|---|
| `aegisweave/__main__.py` | CLI entry point | `parser()`, `main()` — commands `serve`, `demo`, `train-demo`, `replay`, `collect`, `collector-health`, `backup`, `restore`, `generate-demo` | everything | [IMPLEMENTED] |
| `aegisweave/schema.py` | Telemetry contract | `Flow` (validators: canonical IP, aware time, ≥ 1 packet, missing-feature declaration) | pydantic | [IMPLEMENTED] |
| `aegisweave/features.py` | Feature definitions | `flow_features`, `behavior_features`, `FLOW_FEATURES`, `BEHAVIOR_FEATURES` | numpy | [IMPLEMENTED] |
| `aegisweave/behavior.py` | Host context | `BehaviorEngine.observe` (windows, re-ordering, caps), `snapshot` | — | [IMPLEMENTED] |
| `aegisweave/ml.py` | Models | `ClassSupport`, `ModelBundle` (`components`, `predict`, `save`, `load`), `fit_bundle`, `choose_threshold`, `metrics`, `evaluate_decisions`, `check_split_isolation`, `train_demo` | scikit-learn, scipy, joblib | [IMPLEMENTED] |
| `aegisweave/detection.py` | Decisions and engine | `DetectionConfig`, `decide`, `attribute`, `assess_risk`, `DriftMonitor`, `DriftRegistry`, `DetectionEngine.process` | ml, behavior | [IMPLEMENTED] |
| `aegisweave/collectors.py` | Zeek parsing and replay | `read_zeek_tsv`, `zeek_to_flow`, `_payload_bytes`, `forward` (batch, back-off, skip/report) | httpx | [IMPLEMENTED] |
| `aegisweave/ingest.py` | Durable collector | `Spool` (poll, deliver), `run`, `collector_health` | collectors, sqlite3 | [IMPLEMENTED] (file-based) |
| `aegisweave/corpus.py` | IoT-23 corpus and splits | `iot23_label`, `load_capture`, `assign`, `purge_mask`, `build_split`, `_isolated_capture` | collectors, behavior | [IMPLEMENTED] |
| `aegisweave/datasets.py` | UNSW / CIC CSV adapters | `load_unsw`, `load_cic`, `normalize_cic_columns`, `feature_hashes` | pandas | [IMPLEMENTED] |
| `aegisweave/storage.py` | SQLite store | `Store` (`add_event`, `_correlate`, `_prune`, `overview`, `events`, `incidents`, `audit`, `record_response`, model registry) | sqlite3 | [IMPLEMENTED] |
| `aegisweave/response.py` | Response policy | `Policy`, `ResponseRequest`, `ResponseEngine` (`propose`, `approve`, `rollback`, `expire`, `update_policy`) | storage | [IMPLEMENTED] (simulation) |
| `aegisweave/api.py` | REST API | `create_app`, `InferenceWorker`, security-header / body-size middleware, all routes | fastapi | [IMPLEMENTED] |
| `aegisweave/auth.py` | Authentication | `Auth` (tokens, demo session, `perimeter`, `rate_limit`, public origin) | — | [IMPLEMENTED] |
| `aegisweave/backup.py` | Backup / restore | `snapshot`, `restore` (integrity check, SHA-256 manifest, restore to an unused path only) | sqlite3 | [IMPLEMENTED] |
| `aegisweave/demo.py` | Synthetic generator | `generate_episodes`, `generate_demo` | schema | [IMPLEMENTED] |
| `experiments/run.py` | Synthetic experiment | variants, ablations, stress, decisions, bootstrap → `synthetic.json` | ml | [IMPLEMENTED] |
| `experiments/confirm.py` | Frozen-model fresh draws | → `confirmation.json` | ml | [IMPLEMENTED] |
| `experiments/public.py` | UNSW benchmark and open-set test | → `unsw.json` | datasets | [IMPLEMENTED] |
| `experiments/iot23.py` | IoT-23 protocols A/B/C, model export | → `iot23.json` (v1), `iot23-context-v2.json` | corpus, ml | [IMPLEMENTED] |
| `experiments/prepare_cic.py`, `cic_baseline.py` | CIC staging and baseline | → `cic2017-baseline-v1*.json` | datasets | [IMPLEMENTED] |
| `scripts/verify_pipeline.py` | 88-check end-to-end run with real processes | — | all | [IMPLEMENTED] |
| `scripts/verify_collector.py` | 8-check collector recovery | — | ingest | [IMPLEMENTED] |
| `scripts/start_prototype.py` | Demo launcher | — | CLI | [IMPLEMENTED] |
| `scripts/acquire_cic2017.py` | Downloads corrected CIC | — | — | [IMPLEMENTED] |
| `deploy/` | Office deployment | compose.yaml, Caddyfile, Dockerfile | Docker | [PARTIALLY IMPLEMENTED] (never run) |

### Tracing one call through the code

```
__main__.main("serve") → api.create_app() → ModelBundle.load()  [ml.py]
POST /api/telemetry/batch → Auth.perimeter/role → BatchRequest(Flow…) → InferenceWorker.submit
InferenceWorker thread → DetectionEngine.process(flow)                         [detection.py]
   → BehaviorEngine.observe(flow)                                              [behavior.py]
   → ModelBundle.predict(flow, context) → flow_features/behavior_features      [ml.py, features.py]
        → components() → fusers["full"] → contributions/explanations
   → decide() → attribute() → assess_risk() → DriftRegistry.observe()
→ Store.add_event(event) → _correlate() → _prune()                             [storage.py]
Dashboard GET /api/events → Store.events() → JSON → app.js render
```

---

# PART 22 — DEPENDENCIES AND TECHNOLOGY STACK

Versions are from `requirements.lock` and `pyproject.toml`; the tools on the development PC were checked directly.

| Technology | Version | Purpose | Where used | Status |
|---|---|---|---|---|
| Python | 3.12.10 | Language | everywhere | [IMPLEMENTED] |
| scikit-learn | 1.9.1 (pinned; model load fails on mismatch) | All ML models | `ml.py`, experiments | [IMPLEMENTED] |
| NumPy / SciPy | 2.5.3 / 1.18.1 | Arrays; temperature optimisation, softmax | `ml.py`, `features.py` | [IMPLEMENTED] |
| pandas | 3.0.5 | CSV datasets | `datasets.py`, CIC prep | [IMPLEMENTED] |
| joblib | 1.6.0 | Model serialisation | `ml.py` | [IMPLEMENTED] (executable-pickle risk) |
| threadpoolctl | 3.6.0 | Single-thread determinism | `ml.py` | [IMPLEMENTED] |
| FastAPI / Starlette | 0.141.1 / 1.6.0 | REST API | `api.py` | [IMPLEMENTED] |
| Uvicorn | 0.52.4 | ASGI server | `__main__.py` | [IMPLEMENTED] |
| Pydantic | 2.13.5 | Validation | `schema.py`, `response.py`, `api.py` | [IMPLEMENTED] |
| httpx | 0.28.1 | HTTP client (collector, replay) | `collectors.py`, `ingest.py` | [IMPLEMENTED] |
| psutil | 7.2.2 | Process metrics | `api.py`, experiments | [IMPLEMENTED] |
| SQLite | bundled with Python | Storage, collector spool | `storage.py`, `ingest.py` | [IMPLEMENTED] |
| pytest | 9.1.1 | Tests | `tests/` | [IMPLEMENTED] |
| Node.js | v24.18.1 (dev PC) | UI regression script | `frontend/check-ui.cjs` | [IMPLEMENTED] |
| HTML/CSS/JavaScript | — | Dashboard | `frontend/` | [IMPLEMENTED] |
| Zeek | — | Network sensor | input format only | [PLANNED] (not installed) |
| Docker / Compose, Caddy | — | Deployment, TLS proxy | `Dockerfile`, `deploy/` | [PARTIALLY IMPLEMENTED] (not installed / never run) |
| Git | 2.55 | Version control | — | [IMPLEMENTED] |
| VS Code | 1.139.1 | IDE | — | In use |

### Observations

- **No deep-learning framework** (TensorFlow or PyTorch) is present. Deep learning is not used.
- **Deprecation warnings** from Starlette's test client (the `httpx` usage and the anyio `BlockingPortal` alias) appear during tests. They are harmless now but should be tracked.
- **Everything is pinned exactly** — good for reproducibility, but security updates must be applied deliberately.
- **Joblib/pickle** is the riskiest dependency choice (Part 19). [PROPOSED: sign artifacts, or store parameters in a non-executable format.]
- There are no unused or duplicated heavy dependencies visible.

---

# PART 23 — CURRENT PROJECT STATUS MATRIX

| Feature | Status | Evidence | Missing work | Priority |
|---|---|---|---|---|
| Zeek TSV/JSON parsing | COMPLETED | `collectors.py`; 19 collector tests | Validate against live Zeek output | High |
| Durable continuous collector | COMPLETED (lab) | `ingest.py`; `verify_collector` 8/8 | Live sensor; sustained load | High |
| Strict telemetry schema | COMPLETED | `schema.py`; API security tests | — | — |
| Behaviour windows and re-ordering | COMPLETED | `behavior.py`; reordering tests | — | — |
| Five ML layers and fusion | COMPLETED | `ml.py`; ML tests | Better cross-network generalisation | Critical |
| Five-way decisions and attribution | COMPLETED | `detection.py`; 35 detection tests | C&C attribution failure | Critical |
| Explanations | COMPLETED | `ml.predict`; recomputable-explanation test | User study of usefulness | Low |
| Risk scoring | COMPLETED | `assess_risk` | Calibrate weights with real incidents | Medium |
| Incident correlation | COMPLETED | `storage._correlate` | Alert suppression / summarisation | Medium |
| Simulated response workflow | COMPLETED | `response.py`; 16 safety tests | Two-person approval; live adapter (only if ever wanted) | Medium |
| Drift monitoring | COMPLETED (observational) | `DriftRegistry` | Evaluate against real drift | Low |
| REST API and auth | COMPLETED | `api.py`, `auth.py`; 31 security tests | — | — |
| Dashboard (7 views) | COMPLETED | `frontend/`; UI checks | Fix the simulated banner; accessibility check | Low |
| Backup / restore | COMPLETED | `backup.py`; tests | Scheduled backups | Medium |
| Synthetic evaluation | COMPLETED | `synthetic.json`, `confirmation.json` | — | — |
| UNSW-NB15 benchmark | COMPLETED | `unsw.json` | Authenticated original download | Low |
| IoT-23 evaluation (v2) | COMPLETED | `iot23-context-v2.json` | New untouched captures | High |
| CICIDS2017 baseline | COMPLETED (offline only) | `cic2017-baseline-v1*.json` | Botnet coverage; Zeek feature equivalence | High |
| Real-data model in the dashboard | NOT IMPLEMENTED | `var/models/active` is synthetic | A model that passes release gates | Critical |
| Per-site calibration | NOT IMPLEMENTED | `docs/PRODUCTION_TARGET.md` | Design and implement | Critical |
| Live Zeek sensor | PLANNED | `docs/LAB_VALIDATION.md` | Install Zeek; process known PCAPs | High |
| Docker deployment | PARTIAL | `deploy/`; the Docker image was never built | Build and run on Linux; TLS test | High |
| Load / soak test | NOT IMPLEMENTED | — | Measure the 2× peak for 60 min gate | High |
| Office pilot (≥ 14 days) | PLANNED | `docs/PRODUCTION_TARGET.md` | Authorisation, site data | High |
| Alert notifications (email/webhook) | NOT IMPLEMENTED | — | Design | Medium |
| Adversarial / evasion testing | NOT IMPLEMENTED | — | Design experiments | Medium |
| README and report up to date | PARTIAL | README updated 7 Oct 2026 (164 tests, v2 IoT-23 and CIC tables); the generated report still says 136 tests | Regenerate the report | Medium |

---

# PART 24 — WHAT WE HAVE ACTUALLY BUILT

**If someone asks what our project does *today*, this is the answer.**

We have built a working, locally running network intrusion detection application.

1. You give it Zeek connection logs, which it can replay from files or follow continuously as they grow. It can also generate clearly labelled synthetic traffic.
2. It checks every record, rejects bad ones and turns each connection into numbers describing that connection and the recent behaviour of the host that made it.
3. Five machine-learning models, trained offline, score the connection. A sixth model combines their evidence into one attack score.
4. A fixed rule turns the evidence into one of five decisions. It names an attack type only when the connection genuinely resembles the training examples of that type; otherwise it says "anomalous – type uncertain" or "uncertain".
5. It attaches a written explanation and a risk score, stores the result in a local database, and groups related alerts from the same host into incidents.
6. A web dashboard with seven pages shows all of this to users with viewer, analyst or admin tokens.
7. An analyst can ask for a host to be "blocked" or "isolated". Nothing is ever blocked: the request is checked against safety rules, needs approval, expires automatically, can be rolled back, and is recorded in an audit log as a simulation.

On the research side:

- We trained and evaluated these models on synthetic data, UNSW-NB15, 1.2 million real IoT-23 Zeek records and a separate CICIDS2017 baseline.
- We wrote down both the good results and the failures.
- 164 automated tests and an 88-check end-to-end script verify the software.

**What it is not, today:**

- It is not connected to a live network sensor.
- It has not been deployed with Docker.
- It has not been used on an office network.
- Its default dashboard model was trained on synthetic data.
- Its real-data models make too many false alerts on unfamiliar networks for operational use.

---

# PART 25 — WHAT IS STILL MISSING

### CRITICAL

1. **A model fit for real use.**
   - *Why it matters:* cross-network FPR is 10.27 %; C&C traffic is always typed `scan`; the CIC botnet recall is 0 %.
   - *What is needed:* representative benign office traffic, per-site calibration, and more diverse C&C/botnet training data.
2. **Per-site calibration procedure.**
   - *Why it matters:* "normal" differs per network, and the anomaly layers otherwise flag every new device.
3. **An untouched final test set.**
   - *Why it matters:* every held-out capture has already been inspected, so no clean final claim is currently possible.

### HIGH

4. **Live Zeek sensor integration and feature-equivalence check.** Process known PCAPs with the sensor we intend to deploy (`docs/LAB_VALIDATION.md`).
5. **Docker build, TLS and restart verification** on Linux.
6. **Load and soak testing** against measured site traffic.
7. **Remove port reliance / improve generalisation.** Destination port dominates the supervised layer.

### MEDIUM

8. **Two-person approval** for containment requests.
9. **Alert notification channel** and alert suppression / summarisation.
10. **Adversarial and evasion evaluation.**
11. **Regenerate the project report** (`docs/report/`) with the v2 results and current test counts. The README was refreshed on 7 Oct 2026.
12. **Scheduled backups** and retention sized from measured volume.

### LOW

13. Fix the dashboard simulation banner.
14. Authenticated UNSW download (replace the mirror).
15. Accessibility review of the dashboard.
16. Clear dependency deprecation warnings.

---

# PART 26 — TECHNICAL RISKS AND EDGE CASES

| Problem | Cause | Effect | Detection | Mitigation (existing / needed) |
|---|---|---|---|---|
| Data leakage | Duplicate vectors, shared host context, random splits | Inflated scores | Feature-hash checks; unseen-vector subsets; `context_isolation` report | Implemented checks; keep partitions separate |
| Overfitting | Training and testing on the same capture environment | Good scores, poor transfer | Protocol C held-out captures | Need more diverse data; per-site calibration |
| Class imbalance | Scans dominate IoT-23; botnet rare in CIC | Rare classes ignored | Per-class recall | Balanced weights (implemented); more minority data |
| Concept drift | Network changes over time | Rising false alerts / misses | `DriftRegistry` PSI / TV signals | Offline retraining with review (process only) |
| Unseen attacks | New malware families | Wrong type or a miss | Class-support and anomaly layers; protocol B | `anomalous` decision; but B unseen-vector recall is only 0.30 |
| False positives | Unusual benign devices | Alert fatigue | Benign alert rate | Calibration; incident grouping; risk caps |
| False negatives | Attacks that mimic normal flows | Missed intrusions | Per-attack recall | More behaviour features; payload-free limits accepted |
| Dataset bias | Lab IoT / synthetic traffic | Not representative of offices | Cross-dataset tests | Collect local benign data |
| Feature instability | Port numbers, sensor differences | Brittle models | Importance analysis | Reduce port reliance |
| Preprocessing mismatch | CICFlowMeter vs. Zeek counters | Invalid transfer | Documented as unproven | Validate with PCAP → Zeek |
| Training/serving skew | Different feature code | Silent errors | Shared `features.py` / `behavior.py`; implementation hashes in the manifest | Implemented |
| Model-loading failure | Missing file, version mismatch, tampering | No inference | Health "degraded"; start-up refusal | Implemented fail-closed |
| API failure / outage | Crash, overload | Lost telemetry | Collector health; 429 | Durable spool with retry (implemented) |
| Malformed traffic | Broken Zeek lines, missing fields | Crashes or garbage | Schema; rejected counts | Implemented skip-and-report |
| Missing values | Zeek unset fields | Undefined features | `missing_features`, `measurement_assumptions` | Benign-median imputation plus reliability discount |
| Extreme volumes | Floods, busy networks | Queue saturation, latency | Queue depth, 429s | Bounded queue; needs load tests and scaling |
| Out-of-order events | Zeek emits at connection end | Wrong host history | `reordered` / `late_event` flags | Re-ordering ≤ 300 s (implemented) |
| Adversarial behaviour | Attacker shapes traffic | Evasion | — | Not addressed |
| Deployment issues | Docker, TLS, permissions untested | Failed rollout | — | Run the `deploy/` validation plan |

---

# PART 27 — REPRODUCIBILITY

All commands below come from `README.md`, `docs/report` Appendix A and the verified runs. Use Windows paths; on Linux use `.venv/bin/python`.

**1. Prerequisites.** Python 3.12, Git, Node.js (only for the UI check), about 3 GB of disk for datasets. No GPU is needed.

**2–3. Installation and dependencies**

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.lock
```

**4. Dataset setup** (none of these are in Git):

- **IoT-23:** download the 8 `conn.log.labeled` files listed in Part 9.3 from `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/` into `var/datasets/iot23/`. Source hashes are checked against those recorded in the result files.
- **UNSW-NB15:** `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` into `var/datasets/`. Prefer the official site; the project copy came from a mirror (Part 9.2).
- **CICIDS2017 corrected:** `.venv/Scripts/python scripts/acquire_cic2017.py`, then `experiments.prepare_cic` for each day (see `docs/CIC2017_BASELINE_REVIEW.md` for the exact command).

**5–8. Preprocessing, training, evaluation and model saving** (preprocessing is part of each script):

```bash
.venv/Scripts/python -m aegisweave train-demo
.venv/Scripts/python -m experiments.run --model var/models/active
.venv/Scripts/python -m experiments.confirm
.venv/Scripts/python -m experiments.public --train var/datasets/UNSW_NB15_training-set.csv --test var/datasets/UNSW_NB15_testing-set.csv
.venv/Scripts/python -m experiments.iot23 --model var/models/iot23-context-v2 --model-lco var/models/iot23-lco-context-v2
```

The IoT-23 run took about 28 minutes on the dev laptop. Results are written to `experiments/results/*.json`; models to `var/models/<name>/` (`bundle.joblib` + `manifest.json`).

**9–10. Backend and frontend** (the frontend is served by the backend):

```bash
.venv/Scripts/python -m aegisweave demo --count 200
```

Then open `http://127.0.0.1:8765`. Alternatively, double-click `START_PROTOTYPE.cmd`, which opens port 8775.

To replay real, held-out IoT-23 traffic, start a server with the capture-held-out model, then replay a capture into it:

```bash
.venv/Scripts/python -m aegisweave serve --port 8791 --model var/models/iot23-lco --db var/iot23-unseen-demo.db
```

```bash
.venv/Scripts/python -m aegisweave replay var/datasets/iot23/CTU-Honeypot-Capture-5-1.conn.log.labeled --format zeek-tsv --sensor honeypot-5-1 --batch-size 200 --url http://127.0.0.1:8791
```

**11. Testing**

```bash
.venv/Scripts/python -m pytest -p no:cacheprovider
node frontend/check-ui.cjs
.venv/Scripts/python scripts/verify_pipeline.py
.venv/Scripts/python scripts/verify_collector.py
```

**12. Expected outputs** (1 Oct 2026):

- `164 passed`
- `Frontend regressions passed: …`
- `88/88 checks passed` (about 54 s)
- collector report `"passed": true` with 8 checks

Retrained metrics should match the committed JSON when versions are pinned and seeds are unchanged. Exact equality across machines is not verified.

---

# PART 28 — TESTING STRATEGY

| Test type | What exists | Count / evidence | Missing |
|---|---|---|---|
| Unit | Decisions, risk, attribution, schema, features, parsers, policy logic | `test_detection.py` (35), `test_response_safety.py` (16), `test_collectors.py` (19) | — |
| Integration | API via the FastAPI test client; storage; pipeline | `test_api_security.py` (31), `test_pipeline_e2e.py` (4), `test_ingest.py` (8), `test_backup.py` (2), `test_deployment.py` (7) | — |
| ML tests | Manifest tamper detection, output contract, identity-field invariance, recomputable explanations, missing measurements, split leakage, class support, withheld family never given a known type | `test_ml.py` (13), `test_corpus.py` (16), `test_behavior_reordering.py` (5), `test_drift_isolation.py` (3), `test_cic_*` (5) | Seed-variance and regression thresholds on real data |
| Data validation | Schema, Zeek unset fields, CIC counter checks, IoT-23 exclusions | Collector and CIC staging tests | Automatic checks on newly downloaded datasets |
| API tests | Auth, roles, origin, body cap, rate limits, headers, error handling | `test_api_security.py` | Fuzzing |
| Frontend | Logic regression without a browser | `frontend/check-ui.cjs` | Browser end-to-end tests (e.g. Playwright); accessibility |
| End-to-end | 88 checks over 19 stages with real processes | `scripts/verify_pipeline.py` | — |
| Recovery | Collector outage / restart / rotation | `scripts/verify_collector.py` (8) | Server crash mid-write |
| Security | Header, auth, injection and CSP-escaping tests | as above | Penetration test; dependency scanning |
| Performance | Latency measured in experiments | `performance` blocks | **Load and soak tests** |

**Rule for contributors:** every change must keep `pytest`, `check-ui.cjs` and `verify_pipeline.py` green. ML changes must re-run the relevant experiment and report *both* the headline and the unseen / held-out numbers.

---

# PART 29 — RESEARCH CONTRIBUTION

### Actual contribution (supported by our evidence)

1. **An engineering integration** of hybrid detection with an explicit **open-set decision layer**: known attack vs. anomalous-unattributed vs. uncertain, kept separate from risk and from a simulation-only response workflow. Measured behaviour:
   - IoT-23 B: 939 of 940 withheld-class flows became `anomalous` with 0 invented types;
   - synthetic: 337 of 337 withheld beacon flows.

   **Caveat:** on UNSW-NB15 the class-support check gave no benefit.
2. **Leakage-aware evaluation built into the tool:** unseen-vector subsets, held-out captures, withheld classes, context isolation, and decision-level (not just score-level) metrics. This shows how headline scores shrink (F1 0.99 → 0.80 on unseen vectors; FPR 0.7 % → 10.3 % on a new network).
3. **A causal Zeek re-ordering fix:** Zeek emits connections when they end, which scrambled host history for 38 % of IoT-23 flows. The fix's effect on host-history availability was measured during development but is **not recorded in a committed result file**, so re-measure it before quoting any figure. What is recorded: 452,276 flows re-sequenced within tolerance (`iot23-context-v2.json → corpus`).

### Potential contribution (needs more evidence)

- That anomaly and profile layers carry detection across networks where supervised learning fails (protocol C) — a single experiment with two held-out captures.
- That decision-level open-set evaluation is a better way to report NIDS results than aggregate F1.

### Future research opportunity

- Per-site calibration with small reviewed benign samples.
- Port-invariant features.
- Evaluation of analyst workload in a real pilot.
- Adversarial robustness of the fusion design.

### Not a contribution (do not claim)

- New ML algorithms: every model is standard scikit-learn.
- Zero-day detection.
- State-of-the-art accuracy.

---

# PART 30 — LIMITATIONS (UNSOFTENED)

- **Datasets.**
  - No office traffic at all.
  - The synthetic data is hand-designed.
  - UNSW-NB15 is synthetic 2015 traffic from a mirror download.
  - IoT-23 is 2018–19 lab IoT, dominated by two captures.
  - CIC uses a different flow meter.
  - Only 135 usable DoS flows in IoT-23.
- **Models.**
  - The supervised layer relies on destination port.
  - C&C is misattributed as scan on a new network.
  - Botnet traffic is missed in the CIC baseline.
  - The anomaly layer flags benign-but-new devices.
  - No hyperparameter search; mostly a single seed.
- **Implementation.**
  - One process, one inference worker.
  - SQLite only.
  - No live sensor, no notifications, no two-person approval.
  - Joblib artifacts are executable.
- **Evaluation.**
  - Protocol A is interleaved (optimistic).
  - The context-isolation correction came after the original results.
  - All held-out captures have been inspected.
  - No confirmatory untouched test.
  - The generated project report still shows historical figures.
- **Deployment.**
  - Docker and TLS never run.
  - No load test.
  - No pilot.
  - The dashboard's default model is synthetic.
- **Real world.**
  - Flow metadata cannot see payload-based attacks.
  - Encrypted-traffic behaviour only.
  - Detection latency is bounded by Zeek's connection-end logging.
  - Evasion has not been studied.
- **Research.**
  - Contributions are engineering and methodology, not algorithmic.
  - Evidence for the class-support benefit is mixed across datasets.


---

# PART 31 — FUTURE WORK

Only improvements that address a measured problem are listed. All are [PROPOSED] unless marked [PLANNED].

| Improvement | Problem solved | Technical approach | Difficulty | Expected benefit | Dependencies | Priority |
|---|---|---|---|---|---|---|
| Per-site calibration [PLANNED] | 10 % FPR on unseen networks | Collect a reviewed benign observation window at the site; refit anomaly / profile references and thresholds only; keep the supervised model frozen | Medium | Large FPR reduction expected — must be measured | Site data, authorisation | Critical |
| Port-robust supervised layer | Capture-specific port learning | Ablate `log_destination_port`, or replace it with service-category buckets; re-run protocols A/C | Low–Medium | Better transfer; honest importance | None | High |
| C&C / botnet coverage | C&C typed `scan`; CIC botnet 0/736 | Add more IoT-23 C&C captures and periodicity features (inter-arrival regularity per edge) | Medium | Better attribution | Data download | High |
| Untouched final test set | No clean final claim possible | Reserve new IoT-23 captures now; never inspect them until release | Low | Credible final numbers | Discipline | Critical |
| Live Zeek validation [PLANNED] | Feature semantics unproven on the real sensor | Run Zeek on known PCAPs; compare with `collectors.py` output | Medium | Confidence in live input | Linux + Zeek | High |
| Docker / TLS run [PLANNED] | Deployment untested | Follow `deploy/README.md` on Ubuntu | Low–Medium | Deployable candidate | Linux host | High |
| Load / soak test [PLANNED] | Unknown capacity | Replay at 2× measured peak for 60 min; watch queue, latency, RAM | Medium | Capacity evidence | Site measurements | High |
| Two-person approval | A single analyst can approve their own proposal | Store the proposer; reject approval by the same actor | Low | Safer workflow | None | Medium |
| Alert notifications | Alerts visible only in the dashboard | Webhook / email on incident creation, rate-limited | Low | Faster response | SMTP / webhook target | Medium |
| Adversarial evaluation | Evasion unknown | Perturb attack flows (timing, sizes, ports) within realistic bounds; measure recall | Medium | Robustness evidence | None | Medium |
| Safer model format | Joblib code-execution risk | Sign artifacts, or export parameters to a non-executable format | Medium | Integrity | None | Medium |
| Seed-variance reporting | Single-seed results | Repeat key experiments over 5 seeds; report the spread | Low | Statistical credibility | Compute time | Medium |

**Not recommended:** adding deep learning, a bigger dashboard or more datasets *just* to look impressive. None of these fixes the measured failures above.

---

# PART 32 — PROJECT ROADMAP

| Phase | Goal | Concrete tasks | Exit criterion |
|---|---|---|---|
| **1 — Stabilise** | Everyone can run it | Regenerate the report (README already refreshed); fix the simulation banner; document dataset download; each member runs all tests | Every member reproduces 164 / 88 / 8 |
| **2 — Complete implementation** | Close platform gaps | Two-person approval; notification webhook; scheduled backups | New tests pass |
| **3 — Improve ML** | Fix measured failures | Port ablation; C&C periodicity features; seed variance; reserve an untouched test set | Improvement on the v2 protocols **without** tuning on the reserved set |
| **4 — Improve detection operations** | Site readiness | Per-site calibration procedure; alert summarisation | Benign alert rate target met on a lab / site sample |
| **5 — Dashboard** | Usability | Simulation banner from data; calibration status view; accessibility pass | UI checks plus a user walkthrough |
| **6 — Security hardening** | Trust the NIDS | Artifact signing; dependency scan; fuzz the API; TLS verification | No high findings |
| **7 — Evaluation** | Credible claims | Final run on the untouched set; adversarial perturbation study; load test | Predeclared release gates evaluated |
| **8 — Documentation** | Hand-over | Update this document, the report and the activity files | Reviewed by the supervisor |
| **9 — Final demonstration** | Viva | Live dashboard demo, real IoT-23 replay, safety demo (denied containment, kill switch), honest results slide | Rehearsed Q&A (Parts 35–36) |

---

# PART 33 — TEAM KNOWLEDGE TRANSFER

### What you must know before touching the code

1. **Architecture in one line:**

   collector → `Flow` schema → behaviour windows → five ML layers → fusion → `decide` → `attribute` → `assess_risk` → SQLite → dashboard / simulated response.

2. **The golden safety rule.** An ML output must **never** execute or trigger a real action. `Policy.simulation` is `Literal[True]`. Do not add a live adapter without a design review.

3. **Features are a contract.**
   - Changing `features.py` or `behavior.py` changes `FEATURE_SCHEMA` semantics.
   - Every model must then be retrained.
   - Old artifacts will refuse to load, or will behave wrongly. Bump the schema name if meanings change.

4. **Pinned scikit-learn.** Models load only with the exact scikit-learn version (1.9.1). Upgrading means retraining every artifact.

5. **Never let labels into telemetry.** The schema forbids extra fields. Do not add a `label` field "for convenience".

6. **Partitions are sacred.** Train, calibration, fusion, tuning and test each have one job. Never tune thresholds on test. Never fit scalers on test. Keep `check_split_isolation` and `build_split` checks passing.

7. **Report both numbers.** Any new result must show the headline *and* the unseen-vector / held-out figure.

8. **Data and models are not in Git.** `var/` is ignored. Share datasets through their official sources and models through a trusted channel. Never commit tokens or `.env`.

### Important commands

- `python -m pytest -p no:cacheprovider` — run all tests.
- `python scripts/verify_pipeline.py` — full end-to-end check.
- `python -m aegisweave demo --count 200` — run the dashboard with simulated data.
- `python -m aegisweave train-demo` — rebuild the synthetic model.

### Dangerous changes (require review and full re-verification)

- `decide()` thresholds or rule order;
- `assess_risk` caps;
- `response.py` gates;
- `auth.py` perimeter logic;
- the CSP headers;
- the feature definitions;
- the corpus split logic.

### Common mistakes

- Comparing numbers from `iot23.json` (historical) with `iot23-context-v2.json` (corrected) as if they came from the same protocol.
- Quoting the synthetic 0.995 F1 as real-world performance.
- Treating anomaly as attack: `anomalous` means *unusual*, not *malicious*.
- Running two servers on port 8765. The CLI checks the port first; use `--port`.
- Forgetting that the dashboard's model is synthetic.

### Git practice

- Work on branches.
- Small commits with meaningful messages.
- Run tests before committing.
- Do not rewrite `main` history.
- Result JSON files are committed deliberately as evidence: regenerate them, never hand-edit them.

---

# PART 34 — TEAM MEMBER LEARNING PATH

| Level | What to learn | Why it matters | Files to inspect | Practical exercise |
|---|---|---|---|---|
| 1 Networking | IP, ports, TCP handshake, UDP, flows vs. packets | Our input *is* flows | `schema.py`, `collectors.py` | Open an IoT-23 `conn.log.labeled`; explain 5 lines field by field |
| 2 Cybersecurity | Scans, brute force, DoS, C&C, exfiltration; CIA triad | What we try to detect | `demo.py` (how each attack is simulated) | Match each synthetic attack to its flow signature |
| 3 IDS / NIDS | Signature vs. anomaly, false alarms, Zeek | Design rationale | Parts 3–5; `docs/PROJECT_ASSESSMENT.md` | Write one paragraph: why hybrid? |
| 4 Machine learning | Decision trees, gradient boosting, Isolation Forest, logistic regression, calibration | Our models | `ml.py` (`fit_bundle`) | Train the demo model; read its `manifest.json` |
| 5 Dataset processing | Splits, leakage, duplicates, imbalance | Why our numbers are honest | `corpus.py`, `datasets.py`, `check_split_isolation` | Count duplicate vectors in UNSW with `feature_hashes` |
| 6 Model evaluation | Confusion matrix, precision/recall, FPR, ROC/PR-AUC, per-class | Reading results correctly | `experiments/results/*.json`, Part 13 | Recompute F1 from a stored confusion matrix |
| 7 Architecture | Data flow, decision ladder, risk, response | Changing code safely | `detection.py`, `response.py`, Part 7 | Trace one event with the dashboard drawer open |
| 8 Codebase | API, storage, frontend | Contributing | `api.py`, `storage.py`, `frontend/app.js` | Add a harmless field to `/api/health` plus a test |
| 9 Deployment | Docker, TLS, tokens, backups | Real use | `deploy/`, `docs/BACKUP.md`, `docs/COLLECTOR.md` | Take a backup and restore it to a new file |
| 10 Research methodology | Pitfalls (Arp et al.), open set, honest reporting | Viva and report | Parts 14, 29, 30 | Criticise one of our own experiments in half a page |

---

# PART 35 — QUESTIONS THE TEAM MAY BE ASKED

### Basic

- **What is your project?** A passive, ML-based network intrusion detection prototype. It scores Zeek connection logs with five models plus fusion, explains each decision, separates known attacks from unknown ones, and only simulates responses.
- **Is it an IDS or an IPS?** An IDS. Response is simulated and needs human approval.

### Networking

- **What is a flow?** One connection's summary: endpoints, ports, protocol, duration, packets and bytes each way.
- **Why flows, not packets?** Cheaper, privacy-preserving, and work on encrypted traffic. The cost: payload-based attacks are invisible.
- **Why re-order flows?** Zeek writes a connection when it ends but timestamps its start. 38 % of IoT-23 flows arrived out of order, so host windows would otherwise be wrong.

### Cybersecurity

- **What attacks can it see?** Those with flow-level signatures: scanning, brute force, flooding / DoS, some C&C and exfiltration patterns — within the limits measured in Part 13.
- **What happens when an attack is detected?** A stored event with an explanation and risk score, grouped into an incident, shown on the dashboard. Containment can only be *requested*, and is simulated after gates and approval.

### Machine learning

- **Which models?** Gradient Boosting (supervised), Isolation Forest (benign-only anomaly), HistGradientBoosting (temporal), a robust profile distance, 5-NN class support, and a logistic-regression stacker.
- **What is the output?** A fused attack score in [0, 1], class probabilities, anomaly, temporal and profile evidence, and class-support percentiles. These are then turned into one of 5 decisions.
- **How is imbalance handled?** Balanced sample weights, per-(capture, label) caps, and metrics that do not depend on accuracy. No SMOTE.

### Datasets

- **Which datasets?** Synthetic episodes; UNSW-NB15; IoT-23 (8 captures, 1,204,888 records); corrected CICIDS2017 (offline baseline).
- **Why not KDD'99 / NSL-KDD?** Outdated, with well-known flaws. [EXTERNAL BACKGROUND]

### Architecture and implementation

- **Stack?** Python 3.12, scikit-learn, FastAPI, SQLite, vanilla-JS dashboard.
- **How does the backend talk to the ML?** In-process. The API enqueues flows; one worker thread calls `DetectionEngine.process`, which calls `ModelBundle.predict`.
- **How is the model protected?** SHA-256 manifest, schema and version checks, admin-owned files; a tampered model is refused.

### Evaluation

- **Your best result?** Synthetic F1 0.995 — but that is synthetic. The honest real-data picture:
  - IoT-23 within captures: F1 0.991 overall, **0.802 on unseen vectors**;
  - on new captures: **FPR 10.27 %**.

### Research, limitations and future work

See Parts 29–31. Lead with the open-set results and the honest evaluation. State the cross-network failure plainly.

---

# PART 36 — VIVA DEFENCE (HARD QUESTIONS, PROJECT-SPECIFIC ANSWERS)

**Why did you choose these datasets?**
IoT-23 is real Zeek output, so it exercises our actual collector and behaviour engine. UNSW-NB15 is a common benchmark for comparability. Corrected CICIDS2017 tests a different network and attack mix, with day-separated evaluation. Synthetic data tests the whole pipeline safely. We avoided KDD'99 and NSL-KDD because they are outdated.

**Why this model?**
Tabular flow features suit tree ensembles. Gradient boosting trains in seconds on a CPU and is inspectable. We combine it with anomaly layers because a supervised model alone scored **F1 0.0** on the unseen captures (protocol C). The anomaly and profile layers carried detection there.

**Why not deep learning (CNN / LSTM)?**
Our inputs are 33 engineered numbers per flow, not images or long raw sequences. The behaviour windows already give temporal context. Deep models need more data, are harder to explain, and would not fix our measured failures (port reliance, cross-network calibration). We have **not** experimentally compared against deep learning, so we don't claim it would be worse — only that it was not needed to answer our research questions.

**Why not Random Forest or XGBoost?**
Either is a reasonable alternative. We used scikit-learn's GradientBoosting and HistGradientBoosting to avoid extra dependencies. **We did not benchmark RF or XGBoost** — that is a fair gap to acknowledge. Our design goal was the decision and open-set logic around the classifier, not the choice of classifier.

**How do you detect zero-day attacks?**
We don't claim zero-day detection. We test *withheld* classes. In IoT-23 protocol B, 939 of 940 withheld attack flows were marked `anomalous – type uncertain`, with no invented type. But on previously unseen flow vectors, the fused-score recall for that protocol was only 0.30. Withheld-class evidence is suggestive, not proof of zero-day capability.

**How do you handle class imbalance?**
Balanced sample weights (no synthetic samples), per-capture and per-label caps, threshold selection under an FPR budget, and per-class reporting.

**How do you avoid data leakage?**
- Disjoint episodes and event IDs; exact feature-hash checks.
- Designated UNSW split preserved; duplicates reported, with a separate unseen-vector evaluation.
- IoT-23: block partitions with a boundary purge, behaviour context rebuilt per partition (isolation v2), whole-capture hold-out, and withheld-class assertions.
- Labels are forbidden in telemetry.

We also admit residual weaknesses: interleaved blocks, and captures that have now been inspected.

**Why is accuracy insufficient?**
Imbalance. IoT-23 capture 1-1 is 53 % scans, and the 736 CIC botnet flows are about 0.13 % of Friday. Accuracy hides both. We report FPR, recall per class and decision outcomes.

**How does it work in real time?**
Near-real-time at flow granularity: each flow is scored on arrival in about 8 ms, at about 85 flows/s with one worker. Flows only exist once Zeek closes the connection. There is no live sensor integration yet.

**What happens with unseen traffic?**
- If it is unlike benign traffic **and** unlike every known class: `anomalous`, "type uncertain".
- If the evidence is unreliable or contradictory: `unknown`.
- On a new network, the honest result is **many benign flows become anomalous** (24.7 % of sampled benign flows alerted in protocol C). That is why per-site calibration is our top priority.

**What if an attacker deliberately evades the detector?**
Flow-level mimicry (normal sizes, ports and timing) could evade the supervised layer, which also relies on ports. The behaviour and anomaly layers make it harder, but **we have not tested adversarial evasion**. It is listed as future work.

**How is your system different from existing NIDS?**
Snort/Suricata use signatures; Kitsune reports anomalies only; commercial tools act autonomously. Ours combines supervised and anomaly evidence with an explicit open-set decision, per-event explanations, and a response path where the ML can never act alone — all evaluated with leakage-aware protocols.

**What is actually novel?**
The *combination* and the *evaluation discipline*, not the algorithms (Part 29). Our patent search of 7 patent abstracts found no description of an explicit "attack type uncertain" outcome combined with a human-gated simulated response. That is not a patentability opinion.

**Biggest limitations?**
- 10.27 % false positives on unseen networks;
- wrong C&C attribution;
- botnet flows missed in the CIC baseline;
- no live sensor or office data;
- deployment untested.

---

# PART 37 — GLOSSARY

| Term | Beginner definition | Technical definition | Relevance to us |
|---|---|---|---|
| Flow / connection | A summary of one conversation between two computers | Aggregate of packets sharing a 5-tuple over a time span | Our unit of analysis |
| Zeek | A tool that writes network logs | Open-source network security monitor (formerly Bro) | Our input format |
| conn.log | Zeek's connection log | Per-connection record (uid, endpoints, proto, duration, bytes, pkts, conn_state) | Parsed by `collectors.py` |
| 5-tuple | The connection's "address" | src IP, dst IP, src port, dst port, protocol | Identity fields (not model features) |
| IDS / IPS | Alarm vs. alarm-plus-block | Detection vs. prevention system | We are an IDS |
| Signature detection | Matching known patterns | Rule/pattern matching | Not used; the supervised layer is the ML analogue |
| Anomaly detection | Spotting the unusual | Modelling normality, scoring deviation | Isolation Forest, profile layer |
| Open-set recognition | Saying "I don't know this class" | Rejecting inputs outside the known classes' support | Class-support layer, `anomalous` decision |
| Isolation Forest | Finds odd points quickly | Random-partition trees; short path = anomaly | Anomaly layer |
| Gradient boosting | Many small trees fixing each other | Additive trees fitting loss gradients | Supervised and temporal layers |
| Temperature scaling | Making confidence honest | Dividing logits by T fitted on calibration data | Supervised calibration |
| Stacking / fusion | Combining several opinions | A meta-model on base-model outputs | Logistic-regression fuser |
| Calibration partition | Data for tuning scores | Held-out data for probability and reference fitting | Temperature, benign references |
| Threshold tuning | Choosing the alarm cut-off | Maximise F1 subject to FPR ≤ 5 % on a tuning set | `choose_threshold` |
| Data leakage | Test answers seen in training | Information from evaluation data influencing training | Guarded by several checks |
| Unseen vectors | Test rows never seen in training | Exact feature-hash not in the fitting data | Honest subset metrics |
| Class imbalance | Some classes are rare | Skewed label distribution | Balanced weights |
| Concept drift | "Normal" changes over time | Shift in P(x) or P(y\|x) | `DriftRegistry` (PSI / TV) |
| PSI | A number for distribution change | Population Stability Index | Drift signal threshold 0.25 |
| Brier score | Error of probabilities | Mean squared error of predicted probability | Layer reliability |
| ROC-AUC / PR-AUC | Ranking quality | Area under ROC / precision-recall curves | Stored in results |
| FPR | The false-alarm share | FP / (FP + TN) | Workload driver |
| Attribution | Naming the attack type | Analyst-facing class label, or unattributed / uncertain | `attribute()` |
| Abstention (`unknown`) | Refusing to guess | Low reliability or contradictory evidence | A decision class |
| Risk cap | A ceiling on the score | Maximum risk per decision | Stops non-malicious flows reaching high severity |
| Allowlist | Protected addresses | Networks that can never be contained | Response gate |
| Kill switch | Emergency stop | Denies pending actions and rolls back active ones | Response policy |
| TTL | Automatic expiry | Lease duration of a simulated action | ≤ 3600 s |
| WAL | Safe database writes | SQLite write-ahead logging | Storage |
| CSP | Browser security rule | Content-Security-Policy header | Blocks injected scripts |
| Joblib | A model file format | Python object serialisation (pickle-based, executable) | Model artifacts |
| SPAN / mirror port | A copy of switch traffic | Port mirroring for passive monitoring | Planned sensor placement |
| Context isolation v2 | Keeping host history separate per split | Rebuilding behaviour features per partition after assignment | Corrected IoT-23 evaluation |

---

# PART 38 — MASTER PROJECT SUMMARY

### PROJECT IN 60 SECONDS

AegisWeave is a passive network intrusion detection prototype. It reads Zeek connection logs, describes each connection and its host's recent behaviour with 33 numbers, and scores them with five machine-learning evidence layers combined by a learned fuser. A transparent rule then says *normal, suspicious, anomalous (unknown type), malicious (known type) or uncertain*, with an explanation and a capped risk score. Results appear on a secure 7-page dashboard, where any response is simulated and needs human approval. It is fully built and tested as software. It has been evaluated honestly on real data, and it still produces too many false alarms on unfamiliar networks for real deployment.

### PROJECT IN 5 MINUTES

1. **Problem.** Signature IDS miss new attacks. ML IDS often overclaim because of leakage, mislabel new attacks, and are unsafe when they block automatically.
2. **Our answer:**
   - a hybrid detector (supervised + anomaly + behaviour);
   - an open-set decision that refuses to name unsupported attack types;
   - explanations;
   - a simulation-only, policy-gated response.
3. **Pipeline:** Zeek log → validated flow → behaviour windows → five layers → fusion → decide / attribute / risk → SQLite incidents → dashboard.
4. **Evidence:**
   - synthetic F1 0.995;
   - IoT-23 within captures F1 0.991 (0.802 on unseen vectors);
   - withheld attack class 939/940 → anomalous;
   - new captures FPR 10.27 %, and C&C mislabelled;
   - CIC botnet 0/736.
5. **Status:** software complete (164 tests, 88/88 end-to-end); deployment and pilot pending; the model needs per-site calibration.

### PROJECT IN 15 MINUTES

Walk through, in order:

1. Parts 1–2 (problem);
2. Part 7 (architecture diagram);
3. Part 8 (one flow end to end);
4. Part 11 (features);
5. Part 12.1–12.9 (layers and the decision ladder);
6. Part 13 (results — show the headline *and* the honest tables);
7. Part 19 (safety);
8. Part 24 (what exists);
9. Part 25 (what is missing).

Close with the roadmap (Part 32).

### COMPLETE TECHNICAL SUMMARY

Python 3.12 / scikit-learn 1.9.1 / FastAPI / SQLite / vanilla-JS application.

- **Features:** 17 flow features (log counters, rates, direction shares, protocol one-hot, log port, failure, SYN ratio) and 16 causal host-behaviour features (5/30/60/300 s windows, re-ordering ≤ 300 s).
- **Layers:**
  - GradientBoosting (65 trees, depth 2, balanced weights, temperature-scaled);
  - IsolationForest (80 trees, benign-only, percentile-calibrated);
  - HistGradientBoosting temporal model;
  - robust profile distance;
  - 5-NN class support (0.99 percentile gate);
  - 7-feature stacked logistic regression (C = 0.5).
- **Training:** threshold at FPR ≤ 0.05 on a tuning partition; disjoint partitions with leakage checks.
- **Decisions and risk:** a 7-step decision ladder; risk = weighted evidence capped per decision.
- **Response:** simulation-only with 8 safeguards.
- **Platform:** token-based roles, CSP, rate limits, bounded queue, durable collector, SHA-256 model manifest, backup and restore.
- **Evaluated on:** synthetic, UNSW-NB15, IoT-23 (A/B/C, context isolation v2) and CICIDS2017 (day-separated baseline).

### CURRENT STATUS

- **Software:** COMPLETE and verified (1 Oct 2026: 164/164, 88/88, 8/8).
- **Models:** RESEARCH CANDIDATES — none promoted; the dashboard uses the synthetic demo model.
- **Deployment:** PARTIAL — configuration only.
- **Pilot:** PLANNED.

### TOP 10 THINGS THE TEAM MUST KNOW

1. The dashboard's default model is **synthetic**. Say so whenever you demo it.
2. `anomalous` means *unusual, type unknown* — not "attack confirmed".
3. The ML can never trigger a real action; responses are simulated.
4. Always quote unseen-vector and held-out numbers next to headline scores.
5. `iot23-context-v2.json` is the corrected evaluation; `iot23.json` is historical.
6. Datasets and models live in `var/` and are **not in Git**.
7. Features are a versioned contract; changing them means retraining.
8. scikit-learn is pinned; models won't load on another version.
9. Run `pytest`, `check-ui.cjs` and `verify_pipeline.py` before every commit.
10. The biggest open problem is **false alerts on new networks** (per-site calibration).

### TOP 10 THINGS THAT MUST NOT BE CLAIMED WITHOUT EVIDENCE

1. "Detects zero-day attacks."
2. "99 % accuracy" (synthetic, or duplicate-inflated) as real-world performance.
3. "Real-time packet-level detection."
4. "Production-ready" or "deployed".
5. "Works on any network." (Protocol C shows otherwise.)
6. "Automatically blocks attackers."
7. "Deep learning based."
8. "Detects botnets." (CIC botnet 0/736; C&C mislabelled.)
9. "The class-support layer always reduces misattribution." (No benefit on UNSW.)
10. "Validated on live office traffic" or "live Zeek integration".

---

## APPENDIX — SELF-AUDIT

| Check | Result |
|---|---|
| Inspected the actual project? | Yes: all source modules, tests, experiments, result JSON files, config, docs; test runs on 1 Oct 2026 |
| Distinguished implemented vs. planned? | Yes: status tags throughout; Part 23 matrix |
| Avoided invented metrics? | Yes: every number traces to a result file or a verification run. One unrecorded reordering figure was removed |
| Avoided invented datasets or architecture? | Yes |
| Separated literature from implementation? | Yes: Parts 4–5 are tagged [EXTERNAL BACKGROUND]. The uploaded papers were unavailable (Part 0) |
| Identified contradictions? | Yes, see below |
| Identified missing information? | Team roles, the uploaded papers, office traffic figures, load capacity |

### Contradictions found

| # | Claim A | Claim B | More current | Conclusion |
|---|---|---|---|---|
| 1 | `README.md`: "137 tests" | Test run on 1 Oct 2026: 164 tests | The run | Fixed in the README on 7 Oct 2026 |
| 2 | README IoT-23 tables (e.g. withheld 935/936, A FPR 0.70 %) | `docs/MODEL_REVIEW_CONTEXT_V2.md` / `iot23-context-v2.json` (939/940, 0.72 %) | v2 (16 Sep 2026, corrected protocol) | Use v2. The README now leads with v2 and labels the old tables historical (7 Oct 2026) |
| 3 | `datasets.py`: `UNSW_SOURCE` = official UNSW page | `unsw.json`: downloaded from a GitHub mirror | The result file records the actual download | Data came from a mirror, hashed but not authenticated |
| 4 | Project report (`docs/report`): 136 tests; collector byte counts "exact" | Continuation review: estimates are disclosed; 164 tests | Continuation review and code | The report is a snapshot from 14 Sep 2026 |
| 5 | Dashboard banner: "Replay generates synthetic telemetry" | Real IoT-23 replays shown in the same UI | The code: the banner is static text in `frontend/index.html` | The UI message is inaccurate for real replays |
| 6 | Week 4 activity file (1 Oct): UNSW source "UNSW Canberra" | Contradiction 3 | The result file | Corrected in the Week 4 and Week 6 activity files on 1 Oct 2026 |

