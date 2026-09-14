// Report content: single source for the Word and web versions. Every number comes from report_data.json.
'use strict';
const D = require('./report_data.json');

const pct = (x, d = 1) => `${(x * 100).toFixed(d)} %`;
const f3 = x => (x === null || x === undefined ? '—' : Number(x).toFixed(3));
const n = x => Number(x).toLocaleString('en-US');
const share = (a, b, d = 1) => pct(a / b, d);

const syn = D.synthetic, conf = D.confirmation, unsw = D.unsw, iot = D.iot23, live = D.live_replay;
const A = iot.experiments.A_temporal_blocks, B = iot.experiments.B_open_set_withheld_attack_attempt, C = iot.experiments.C_leave_capture_out;
const corpusTotal = Object.values(iot.corpus).reduce((s, v) => s + v.records, 0);
const corpusRepresented = Object.values(iot.corpus).reduce((s, v) => s + v.represented, 0);
const corpusReordered = Object.values(iot.corpus).reduce((s, v) => s + v.reordered_within_tolerance, 0);
const corpusIsolated = Object.values(iot.corpus).reduce((s, v) => s + v.isolated_beyond_tolerance, 0);
const ddosExcluded = iot.corpus['CTU-IoT-Malware-Capture-34-1'].excluded['dos: no measured packets'];
const inh = D.inherited;
const after = live.after_fix, before = live.before_fix;
const lc = key => after.counts[key];
const lcTotal = key => Object.values(lc(key)).reduce((s, v) => s + v, 0);
const benignLive = ['capture-8-1|normal', 'honeypot-5-1|normal'].reduce((acc, k) => { for (const [d, v] of Object.entries(lc(k))) acc[d] = (acc[d] || 0) + v; return acc; }, {});
const benignLiveN = Object.values(benignLive).reduce((s, v) => s + v, 0);
const cc = 'capture-8-1|command_and_control';
const replaySeconds = Math.round(after.span_8_1_s), replayBeforeSeconds = Math.round(before.span_8_1_s);
const throughput = Math.round(lcTotal(cc) + lcTotal('capture-8-1|normal')) / after.span_8_1_s;
const bin = m => [f3(m.precision), f3(m.recall), f3(m.f1), pct(m.false_positive_rate, 2), f3(m.roc_auc)];
const layerRow = (name, e) => [name, f3(e.single_layers.supervised.f1), pct(e.single_layers.supervised.false_positive_rate, 2),
  f3(e.single_layers.anomaly_only.f1), pct(e.single_layers.anomaly_only.false_positive_rate, 2),
  f3(e.single_layers.temporal_only.f1), pct(e.single_layers.temporal_only.false_positive_rate, 2), f3(e.fusion_variants.full.f1)];
const labelCount = labels => Object.entries(labels).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${n(v)}`).join('; ');
const lateRows = Object.entries(D.lateness).sort((a, b) => b[1].records - a[1].records)
  .map(([k, v]) => [k.replace('CTU-IoT-Malware-Capture-', 'Malware ').replace('CTU-Honeypot-Capture-', 'Honeypot '), n(v.records), pct(v.late), pct(v.beyond_300s, 2)]);

const meta = {
  title: 'AegisWeave: An Evidence-Aware, ML-First Network Intrusion Detection System',
  subtitle: 'Open-set attack attribution, event-time behavioural analysis and controlled simulated response, evaluated on synthetic and real network traffic',
  date: 'September 2026',
  placeholders: ['[Student name]', '[Register / roll number]', '[Degree programme and department]', '[Institution]', '[Supervisor name and designation]'],
};

const blocks = [];
const h1 = t => blocks.push({ type: 'h1', text: t });
const h2 = t => blocks.push({ type: 'h2', text: t });
const h3 = t => blocks.push({ type: 'h3', text: t });
const p = t => blocks.push({ type: 'p', text: t });
const list = items => blocks.push({ type: 'bullets', items });
const numbered = items => blocks.push({ type: 'numbers', items });
const table = (caption, header, rows, widths, note) => blocks.push({ type: 'table', caption, header, rows, widths, note });
const code = (caption, lines) => blocks.push({ type: 'code', caption, lines });
const callout = t => blocks.push({ type: 'callout', text: t });

// ------------------------------------------------------------------------------------------------
blocks.push({ type: 'frontmatter' });

h1('Abstract');
p(`Machine-learning network intrusion detection systems are frequently reported with near-perfect accuracy on benchmark datasets, yet they often fail silently on new networks and present unfamiliar attacks as confidently labelled known ones. This project designed, implemented and evaluated **AegisWeave**, a flow-based intrusion detection system in which machine learning is the central intelligence but every decision is separated from any response action. Network flows from Zeek logs or a JSON API pass through validated telemetry, 17 flow features and 16 causal host-behaviour features, and five complementary layers: a temperature-calibrated gradient-boosting classifier, a benign-only Isolation Forest, a temporal model, a behavioural profile and a class-support check for open-set attribution. A stacked fusion model combines them. A decision procedure distinguishes known attacks, suspicious activity, anomalous behaviour of uncertain type and explicit abstention; risk scoring, explanations, incident correlation and a policy-gated, simulation-only response engine follow.`);
p(`The system was evaluated at the level an analyst actually sees, not only by binary scores. On synthetic host episodes, fusion reached F1 ${f3(syn.variants.full.f1)}; correcting the inherited decision logic raised the share of benign flows called normal from ${share(inh.benign.normal, inh.benign.n)} to ${pct(syn.decisions.benign_normal_rate)}, and all ${n(syn.withheld.anomalous)} flows of an attack family withheld from training were reported as anomalous with no invented attack type. On ${n(corpusTotal)} real IoT-23 Zeek records, within-capture F1 was ${f3(A.binary.f1)} but fell to ${f3(A.unseen_binary.f1)} on flow vectors never seen in training; ${n(B.decision_counts.attack_attempt.anomalous)} of ${n(Object.values(B.decision_counts.attack_attempt).reduce((s, v) => s + v, 0))} flows of a withheld attack class were reported as anomalous. On captures from an unseen network and malware family, every command-and-control flow was detected (recall ${f3(C.binary.recall)}), but all were given the wrong attack type, the fused detector's false-positive rate rose to ${pct(C.binary.false_positive_rate)}, and ${pct(C.decisions.benign_alert_rate)} of sampled benign flows raised alerts. A live replay of those captures through the running system reproduced the offline results. The findings show that open-set decision logic prevents invented labels, but cross-network generalization remains the principal limitation and requires per-site calibration.`);
p(`**Keywords:** network intrusion detection, machine learning, open-set recognition, anomaly detection, Zeek, IoT-23, UNSW-NB15, explainability, evaluation methodology.`);

h1('Declaration and Acknowledgement of Assistance');
p('I declare that this report describes the AegisWeave project and that all experimental results reported here were produced by the project code and data referenced in the text, and can be regenerated with the commands in Appendix A.');
p('Parts of the design, implementation, debugging and evaluation were carried out with the assistance of AI coding assistants (OpenAI Codex/GPT and Anthropic Claude). Their outputs were executed, tested and verified against measured data before inclusion.');
callout('Edit this declaration to match your institution\'s academic-integrity policy on AI assistance, and add acknowledgements (supervisor, department, dataset authors) as required.');

blocks.push({ type: 'toc' });

// ------------------------------------------------------------------------------------------------
h1('1  Introduction');
h2('1.1  Motivation');
p('Network intrusion detection systems (NIDS) watch network traffic for signs of attack. Signature-based systems recognise known attack patterns reliably but cannot recognise what they have not been told about. Machine-learning (ML) approaches promise to generalise from examples, and published work routinely reports detection accuracy above 99 % on public datasets. In operational use, however, ML-based NIDS are known to suffer from high false-alarm rates, poor transfer to networks that differ from the training data, and a tendency to assign confident but wrong labels to traffic unlike anything seen before [1], [2]. An analyst who is told "port scan, 100 % confidence" about a novel beaconing implant is worse off than one who is told "anomalous behaviour, attack type uncertain".');
p('This project therefore treats ML as the core intelligence of an intrusion detection system while making three commitments: decisions must say what the evidence does and does not support, every result must be measured rather than asserted, and no model output may directly execute a network action.');

h2('1.2  Problem Statement');
p('Build a complete, working, flow-based NIDS in which machine learning performs detection, anomaly and behavioural analysis, and attack attribution; in which uncertain and novel traffic is explicitly distinguished from known attacks; in which detection, risk and response are separated by policy and safety controls; and evaluate it honestly on synthetic and real traffic, including traffic from a network the models never saw.');

h2('1.3  Objectives');
numbered([
  'Ingest network flow telemetry from a validated API and from Zeek connection logs.',
  'Engineer per-flow and causal host-behaviour features without using addresses, identifiers or labels as model inputs.',
  'Combine supervised classification, anomaly detection, temporal and behavioural analysis through calibrated fusion.',
  'Distinguish known attacks, suspicious activity, anomalous behaviour of uncertain type, and explicit uncertainty.',
  'Explain every decision with measured evidence and compute a separate, policy-relevant risk score.',
  'Correlate alerts into incidents and route any response through a policy engine with approval, allowlists, expiry, rollback, rate limits, a kill switch and an audit trail, in simulation only.',
  'Provide an authenticated API and an analyst dashboard backed exclusively by real application data.',
  'Evaluate with leakage controls and decision-level metrics on synthetic data, UNSW-NB15 and real IoT-23 Zeek traffic, including cross-network generalization and a live replay.',
]);

h2('1.4  Scope and Safety Constraints');
list([
  '**Response is simulated by design.** No firewall, host or device is ever modified; the only response adapter records simulated actions in an audited ledger, and simulation cannot be disabled through the API.',
  '**No live packet capture or probing.** Telemetry comes from existing flow logs, public research datasets and explicitly labelled synthetic generators.',
  '**Research, not production certification.** Results describe the datasets and protocols reported here and do not establish performance on any other network.',
]);

h2('1.5  Contributions');
numbered([
  '**An end-to-end, tested ML-NIDS** from telemetry to dashboard, with five complementary ML layers, stacked fusion and a simulation-only response engine behind explicit safety policy.',
  '**Open-set decision logic** that separates detection from attribution: attack types are shown only when a flow lies inside the training support of that class, and unverifiable attributions are never treated as known attacks.',
  '**Decision-level evaluation** through the exact serving path, measuring abstention, unattributed novelty and invented attack types that binary metrics cannot show.',
  '**Real-traffic engineering for Zeek:** exact handling of unset fields, bounded event-time reordering (Zeek emits connections when they end), and exclusion of unrepresentable records.',
  '**A real-data evaluation on IoT-23** with three protocols (temporal blocks, withheld attack class, leave-capture-out), duplicate-vector reporting and a live replay of never-seen captures scored against ground truth.',
  '**Honest reporting of failures:** inflated within-capture results, poor cross-network transfer, a dataset labelling artifact and a scaling defect found and fixed during evaluation.',
]);

h2('1.6  Report Organisation');
p('Chapter 2 reviews background and related work. Chapter 3 states requirements and the system design, and Chapter 4 describes the implementation. Chapter 5 sets out the evaluation methodology and Chapter 6 reports results. Chapter 7 discusses their meaning, limitations and threats to validity, and Chapter 8 concludes with future work. Appendices give reproduction commands, test coverage, the API surface and the development history.');

// ------------------------------------------------------------------------------------------------
h1('2  Background and Related Work');
h2('2.1  Intrusion Detection and Flow Monitoring');
p('Intrusion detection systems are commonly divided into misuse (signature) detection, which matches known attack patterns, and anomaly detection, which models normal behaviour and reports deviations. Network monitors such as Bro/Zeek [3] summarise traffic into connection records containing endpoints, ports, protocol, duration, packet and byte counters and connection state. Flow records are compact, avoid storing payloads and remain usable when traffic is encrypted, which makes them a practical basis for ML-based detection at the cost of losing payload-level evidence.');

h2('2.2  Machine Learning for NIDS and Its Pitfalls');
p('Sommer and Paxson [1] argued that intrusion detection differs from classic ML applications: attacks are rare and diverse, errors are expensive, network traffic is highly variable, and evaluation on closed datasets rarely reflects deployment. Arp et al. [2] later catalogued recurring pitfalls in ML security research, including data snooping, spurious correlations, sampling bias, inappropriate baselines, lab-only evaluation and inappropriate metrics. This project adopts several of their recommendations directly: disjoint and time-ordered splits, reporting results on test rows whose feature vectors never occur in training, ablations, decision-level metrics, and an explicit threats-to-validity analysis.');

h2('2.3  Open-Set Recognition');
p('A conventional classifier assigns every input to one of the classes it was trained on, even when the input belongs to none of them. Open-set recognition [4] studies classifiers that can instead reject inputs outside the known classes. In intrusion detection this matters because new malware families and attack techniques appear continually; a system that maps them onto the nearest known label produces confident but misleading alerts. AegisWeave approaches the problem with two signals: novelty relative to benign training traffic (Isolation Forest [5]) and support relative to each known attack class (a class-conditional nearest-neighbour distance calibrated on held-out flows).');

h2('2.4  Models, Calibration and Fusion');
p('Gradient boosting [6] builds an additive ensemble of shallow trees and performs strongly on tabular features. Isolation Forest [5] isolates anomalies with random partitioning trees and needs no attack labels. Classifier probabilities are often poorly calibrated; temperature scaling [7] rescales logits with one parameter fitted on held-out data. Stacked generalization [8] trains a second-level model on the outputs of first-level models, allowing heterogeneous evidence to be combined. All models were implemented with scikit-learn [9].');

h2('2.5  Datasets');
p(`**UNSW-NB15** [10] was generated at the UNSW Canberra Cyber Range, combining real normal traffic with synthetic attacks from nine families. Its designated training and testing files (${n(unsw.rows.train)} and ${n(unsw.rows.test)} records) do not contain host addresses or timestamps. **IoT-23** [11], published by the Stratosphere Laboratory, provides labelled Zeek connection logs from real IoT devices infected with malware and from benign honeypot devices, with addresses and timestamps intact. It therefore supports evaluation of host-behaviour and temporal features, which UNSW-NB15's CSV files cannot.`);

// ------------------------------------------------------------------------------------------------
h1('3  Requirements and System Design');
h2('3.1  Functional Requirements');
table('Functional requirements', ['ID', 'Requirement'], [
  ['F1', 'Accept normalized flow telemetry (single and batch) and Zeek connection logs (tab-separated and JSON).'],
  ['F2', 'Reject malformed or hostile telemetry, including injected labels or asset priorities, before inference.'],
  ['F3', 'Compute flow and causal host-behaviour features; never use addresses, identifiers, timestamps or labels as model inputs.'],
  ['F4', 'Produce supervised, anomaly, temporal and behavioural evidence and a fused attack score for every flow.'],
  ['F5', 'Decide normal, suspicious, anomalous, malicious or unknown, and attribute an attack type only when supported.'],
  ['F6', 'Explain each decision and compute a separate risk score using trusted asset context.'],
  ['F7', 'Persist events, correlate non-normal events into incidents and expose them through an API and dashboard.'],
  ['F8', 'Propose, approve, expire and roll back responses under policy, in simulation only, with a complete audit trail.'],
  ['F9', 'Verify, version and reload model artifacts; monitor distribution drift without retraining automatically.'],
], [0.08, 0.92]);

h2('3.2  Non-Functional Requirements');
list([
  '**Security:** role-based access, same-origin enforcement, bounded request sizes and rates, strict content security policy, parameterized SQL, and integrity checks before loading executable model artifacts.',
  '**Safety:** no path from model output to command execution; high-impact actions require a malicious, attributed decision, policy gates and human approval.',
  '**Honesty and explainability:** outputs state uncertainty and provenance, including whether a model was trained on synthetic or real data.',
  '**Reproducibility:** seeded experiments, recorded dataset hashes, model fingerprints and committed result files.',
  '**Performance:** per-flow inference with explanation in single-digit milliseconds on commodity hardware, with storage costs that do not grow with incident size.',
]);

h2('3.3  Architecture');
p('Figure 1 shows the processing pipeline. Telemetry enters through collectors or the API, is validated, queued and processed in arrival order by a single inference worker, and flows through behaviour analysis, the ML layers, decision and attribution logic, risk scoring and storage. Responses are a separate path that operators invoke explicitly and that the policy engine gates.');
code('Figure 1: AegisWeave processing pipeline', [
  'Zeek conn.log (TSV/JSON) ─┐   collectors.py: unset-field rules, bad records skipped',
  'normalized JSON flows ─────┼─► POST /api/telemetry[/batch] → strict Flow schema',
  'synthetic replay ──────────┘      (labels and asset priority rejected)',
  '                                            │',
  '                         bounded queue ─► single ordered inference worker',
  '                                            ▼',
  'DetectionEngine.process',
  ' ├─ BehaviorEngine    event-time 5/30/60/300 s host windows, 300 s reordering tolerance',
  ' ├─ ModelBundle       supervised · anomaly · temporal · profile · class support → stacked fusion',
  ' ├─ decide()          normal | suspicious | anomalous | malicious | unknown',
  ' ├─ attribute()       attack type, or explicit "unattributed" / "uncertain"',
  ' ├─ assess_risk()     0–100, capped by decision, trusted asset importance',
  ' └─ DriftMonitor      per-sensor PSI / total variation (review signal only)',
  '                                            ▼',
  'SQLite store: events · incidents · responses · audit · model registry',
  '                                            ▼',
  'ResponseEngine (operator-initiated): policy → allowlist → gates → approval → expiry/rollback → kill switch',
  '                                            ▼',
  'REST API (role tokens) ─► analyst dashboard',
]);

h2('3.4  Telemetry Schema and Trust Boundaries');
p('Every flow is validated by a strict schema before any processing: canonical IP addresses, timezone-aware timestamps no more than five minutes in the future, bounded non-negative counters, a closed protocol vocabulary and at least one measured packet in either direction. Unknown fields are rejected, so a sender cannot supply a label, a risk score or an asset priority. Optional measurements that a sensor cannot provide (SYN ratio, connection failure, reverse counters) are recorded as missing; the model substitutes frozen benign medians and reduces evidence reliability rather than inventing values.');

h2('3.5  Separation of Detection and Response');
p('Detection output is evidence, not a command. The response engine accepts only operator requests (block source, isolate host, notify) tied to a stored event and re-evaluates policy at proposal and approval. Containment requires a malicious decision with an attributed attack type, a risk score of at least 70, class confidence of at least 0.8, a target outside the allowlist and headroom under the action rate limit, followed by human approval. Every action carries an expiry, can be rolled back and is written to the audit trail in the same database transaction as its state change. An emergency kill switch rolls back active simulations and denies pending ones.');

// ------------------------------------------------------------------------------------------------
h1('4  Implementation');
h2('4.1  Technology Stack');
table('Technology stack', ['Concern', 'Choice'], [
  ['Language and runtime', `Python ${D.environment.python}`],
  ['Web API and server', 'FastAPI, Starlette, Uvicorn; pydantic 2 for validation'],
  ['Machine learning', 'scikit-learn 1.9.1, NumPy, SciPy'],
  ['Storage', 'SQLite in WAL mode with schema migrations and bounded retention'],
  ['Dashboard', 'Dependency-free HTML, CSS and JavaScript served by the API'],
  ['Testing', 'pytest; a Node-based frontend regression script; a live multi-process verification script'],
  ['Deployment', 'Dockerfile and Compose file with a read-only, unprivileged container (not verified in this environment)'],
], [0.3, 0.7]);

h2('4.2  Telemetry Collection');
p('Flows arrive as normalized JSON or from Zeek connection logs. Zeek\'s default output is tab-separated with typed header lines; the collector parses both that format and Zeek JSON into the same typed records, including the IoT-23 variant whose label columns are joined by spaces. Label columns in research logs are never read into telemetry. Evaluation on real logs exposed two collector defects that were corrected:');
list([
  '**Unset fields.** Zeek leaves duration and payload bytes unset for single-packet connections, which are exactly the probe and scanning traffic of interest. The original collector rejected them. Table 3 lists the exact rules now applied.',
  '**Brittle replay.** One unrepresentable record stopped an entire replay. Invalid records are now reported and skipped, requests are batched (up to 200 flows) and rate-limit responses are honoured with backoff.',
]);
table('Rules for unset Zeek measurements', ['Situation', 'Value used', 'Justification'], [
  ['Duration unset, at most one packet', '0 s', 'Zeek leaves duration unset when first and last packet coincide; verified on all IoT-23 captures.'],
  ['Payload bytes unset, zero packets', '0', 'No packets carry no payload.'],
  ['Payload bytes unset, one TCP packet', '0', 'A lone SYN or RST probe carries no sequence-tracked payload.'],
  ['Payload bytes unset, UDP/ICMP', 'IP bytes − packets × (IP + 8-byte header)', 'Exact for fixed-length headers (IPv4 20 B, IPv6 40 B).'],
  ['Any other unset required value', 'Record rejected and reported', 'Values are never guessed.'],
], [0.3, 0.27, 0.43]);

h2('4.3  Behaviour Engine and Event-Time Reordering');
p('The behaviour engine keeps a bounded history per (sensor, simulation flag, source host) and computes causal windows of 5, 30, 60 and 300 seconds: connection counts, distinct destinations and ports, failure ratio, byte volume, destination and protocol entropy, new communication edges, rate change, activity persistence and packet-rate statistics. Inference never updates a learned baseline, so an attacker cannot gradually teach the system that attacks are normal.');
p('Zeek writes a connection record when the connection ends but stamps it with the time it started, so records arrive out of event order. The original engine treated any record older than the newest timestamp seen as late and gave it no host history. Table 4 shows how common this is in IoT-23: up to about half of all records arrive out of order, but almost all within five minutes.');
table('Out-of-order arrival in IoT-23 Zeek logs', ['Capture', 'Records', 'Arrive out of order', 'Later than 300 s'], lateRows, [0.34, 0.2, 0.25, 0.21]);
p(`The engine now accepts records up to 300 seconds behind the stream watermark (Zeek's TCP inactivity timeout) and inserts them in event-time order; each record sees only flows that started no later than itself, and records beyond the tolerance are isolated and cannot alter history. On capture 34-1 the share of flows with usable host history rose from ${pct(D.reordering['CTU-IoT-Malware-Capture-34-1']['0'].available)} to ${pct(D.reordering['CTU-IoT-Malware-Capture-34-1']['300'].available)}, and on honeypot 5-1 from ${pct(D.reordering['CTU-Honeypot-Capture-5-1']['0'].available)} to ${pct(D.reordering['CTU-Honeypot-Capture-5-1']['300'].available)}. For streams that arrive in order the output is unchanged, which a regression test checks by comparing features with and without the tolerance, and the synthetic confirmation results were identical before and after the change.`);

h2('4.4  Feature Engineering');
p('Features are fixed transformations with no fitted state, so training and serving compute identical values. Addresses, ports other than the destination port, identifiers, timestamps, sensor names and simulation flags are excluded.');
table('Model features', ['Group', 'Features'], [
  ['Flow (17)', 'log duration, packets, bytes, reverse packets, reverse bytes; log packet rate, byte rate, mean packet size; reverse packet and byte shares; protocol one-hot (TCP, UDP, ICMP, other); log destination port; connection failed; SYN ratio'],
  ['Behaviour (16)', 'log connections in 5, 30, 60 and 300 s; log distinct destinations and ports in 30 s; failure ratio in 30 s; log bytes in 30 s; destination entropy; protocol entropy; new edge; edge frequency; rate change; temporal consistency; log mean and standard deviation of packet rate'],
], [0.18, 0.82]);

h2('4.5  ML Intelligence Layers');
table('ML layers and their training data', ['Layer', 'Model', 'Fitted on', 'Evidence produced'], [
  ['Supervised', 'Gradient boosting (65 depth-2 trees, balanced class weights) + temperature scaling', 'Training partition; temperature on calibration', 'Class probabilities, entropy, attack probability'],
  ['Anomaly', 'Isolation Forest (80 trees)', 'Benign training flows only', 'Percentile of isolation score against held-out benign flows'],
  ['Temporal', 'Histogram gradient boosting (65 iterations)', 'Behaviour features, training partition', 'Attack probability from host context'],
  ['Profile', 'Robust (median/IQR) distance', 'Benign behaviour windows', 'Percentile deviation from benign host behaviour'],
  ['Class support', '5-nearest-neighbour distance per class', 'Training flows per class; percentiles from held-out calibration flows', 'How typical a flow is of the class it was assigned'],
  ['Fusion', 'Logistic regression on 7 standardized evidence terms', 'Separate fusion partition', 'Fused attack score; threshold chosen on a tuning partition at ≤ 5 % FPR'],
], [0.13, 0.32, 0.29, 0.26]);
p('Each layer is fitted on a different partition than the one used to calibrate or combine it, so no layer\'s calibration or fusion weight is learned from its own training data. Evidence reliability combines the supervised layer\'s calibration quality, the amount of available host history and measurement completeness; class entropy is deliberately excluded because it describes which attack type, not whether the evidence is trustworthy.');

h2('4.6  Decision Logic and Open-Set Attribution');
p('Detection (is this an attack?) and attribution (which known attack?) are separated. Table 7 summarises the five decisions with their default thresholds.');
table('Decisions', ['Decision', 'Condition (defaults)', 'Attack type shown'], [
  ['malicious', 'Fused score ≥ 0.78, class confidence ≥ 0.70, reliability ≥ 0.50, and the flow inside the assigned class\'s training support', 'The class'],
  ['suspicious', 'Detected or behaviourally deviating, but below the known-attack bar, or the class is unsupported or unverifiable', 'Tentative class or unattributed'],
  ['anomalous', 'Anomaly percentile ≥ 0.95 and no supported known class: "Anomalous behaviour detected, attack type uncertain"', 'Unattributed'],
  ['unknown', 'Reliability < 0.50, low-confidence attack evidence, or contradictory layers (explicit abstention)', 'Uncertain'],
  ['normal', 'No corroborated evidence; class confidence is not required to call benign traffic normal', 'Normal'],
], [0.14, 0.62, 0.24]);
p('A flow counts as outside a class\'s support when its mean distance to the five nearest training flows of that class exceeds 99 % of held-out calibration flows of the same class. Evaluation on IoT-23 revealed that a rare class (DoS) had no held-out calibration flows, so no support estimate existed; the original rule treated that absence as "supported". The corrected rule treats such attributions as unverifiable: they are never malicious, and the explanation states that the label cannot be verified.');

h2('4.7  Risk Scoring');
p('Risk (0–100) is computed after the decision from fused evidence (42 %), anomaly evidence (14 %), behavioural deviation (13 %), persistent deviation (12 %), an analyst-configured class impact prior (9 %) and trusted asset importance (10 %). Scores are capped by decision (normal 24, unknown 59, suspicious and anomalous 69, malicious 100), so uncertain or unattributed evidence can never reach the high-risk band that policy uses for containment. Severity is low below 40, medium from 40, high from 70 and critical from 85.');

h2('4.8  Explainability');
list([
  '**Feature sensitivity:** each measured feature is reset to its benign training median and the model is re-run; the largest changes in attack log-odds and in isolation score are reported, explicitly labelled as sensitivity rather than causation.',
  '**Fusion terms:** the standardized log-odds contribution of each evidence layer to the fused score.',
  '**Attribution statement:** why an attack type is or is not shown, including class-support percentiles.',
  '**Behavioural evidence:** window counts and activity persistence, with notes when measurements were missing or history was truncated.',
  '**Provenance:** model identifier, version, training fingerprint, artifact hash and whether training data were synthetic.',
]);

h2('4.9  Incidents and Storage');
p(`Non-normal events are correlated into incidents by source, sensor and simulation flag within 300-second event-time windows; an event that bridges two incidents merges them. The original implementation recomputed an incident's first and last timestamps by scanning all its events on every insert. During the live replay of a botnet capture (Section 6.4) one incident grew to ${n(before.largest_incident)} events and per-event storage time rose from ${before.ms_per_event.start.toFixed(1)} ms to ${before.ms_per_event.end.toFixed(1)} ms. Bounds are now maintained incrementally, with a randomized test confirming they always equal a full recomputation, including merges and retention deletions.`);

h2('4.10  API, Authentication and Dashboard');
p('The REST API exposes health, overview, events, incidents, models, behaviour, drift, metrics, policies, responses and audit, plus telemetry ingestion, synthetic replay, response actions, policy updates and model reload (Appendix C). Configured bearer tokens map to viewer, analyst and admin roles and are compared in constant time. Without configured tokens the server issues an ephemeral demonstration session only to loopback clients with a local host header. Mutating browser requests must be same-origin, request bodies are limited to 2 MiB, batches to 200 flows, and responses carry a strict content security policy.');
p('The dashboard has seven views: overview, live events, ML analytics, behaviour, incidents, response and system health. Every value is loaded from the API, and all dynamic content is HTML-escaped. The event drawer shows attribution, raw classifier output, class-support percentiles, sensitivity tables, fusion terms, risk reasoning and response controls. The analytics view shows a model\'s own provenance warning, evaluation protocol and cross-capture results.');

h2('4.11  Model Lifecycle and Drift Monitoring');
p('Model artifacts are saved atomically with a manifest recording the SHA-256 of the serialized bundle, the feature schema, the scikit-learn version and full metadata. Loading verifies all of these and deserializes exactly the verified bytes. Each training run records a fingerprint over code hashes, data and seed. Drift is monitored per sensor and simulation stream using population stability index and total-variation distance between a reference window and the latest window; a shift requests human review and never triggers retraining.');

// ------------------------------------------------------------------------------------------------
h1('5  Evaluation Methodology');
h2('5.1  Research Questions');
numbered([
  '**RQ1:** How accurately do the individual layers and their fusion detect attacks, and how optimistic are headline scores once repeated feature vectors are excluded?',
  '**RQ2:** Does the decision logic avoid alert fatigue on benign traffic while still flagging attacks?',
  '**RQ3:** When an attack type is absent from training, does the system report anomalous behaviour instead of inventing a known attack type?',
  '**RQ4:** How well do models trained on some networks transfer to an unseen network and malware family?',
  '**RQ5:** Does the running system reproduce offline results on real traffic, at acceptable latency and throughput?',
]);

h2('5.2  Datasets and Preparation');
p(`**Synthetic host episodes.** A generator produces independent host episodes (22–43 flows, the first four benign) of normal, scan, brute-force, DoS and exfiltration traffic, with a third of attack episodes deliberately subtle at flow level and periodic benign bursts. A further "unknown beacon" family is never used in training. Partitions are drawn from disjoint seeds: 80 training, 24 calibration, 24 fusion, 24 tuning and 40 test episodes (${n(syn.test_samples)} test flows).`);
p(`**UNSW-NB15.** The designated training and testing files are preserved; a stratified ${n(unsw.training_sample)}-row sample of the training file is used for fitting, reduced to ten generic counters shared with the live schema. ${n(unsw.overlap)} of ${n(unsw.rows.test)} test rows repeat a training feature vector, so results are reported on all rows and on the ${n(unsw.unseen)} unseen rows.`);
p(`**IoT-23.** Eight labelled Zeek captures (${n(corpusTotal)} records) were processed through the same collector and behaviour engine used in serving, in sensor arrival order. Research labels were mapped with a documented table (benign → normal, PartOfAHorizontalPortScan → scan, C&C variants → command_and_control, Attack → attack_attempt, DDoS → dos); unmapped labels are refused. ${n(ddosExcluded)} records are excluded: all belong to one DDoS flood in capture 34-1 that Zeek logged with bad checksums and zero counted packets, so they contain no traffic measurements and would teach the model an artifact. ${n(corpusReordered)} records were re-sequenced within the reordering tolerance and ${n(corpusIsolated)} were isolated.`);
table('IoT-23 captures used', ['Capture', 'Records', 'Represented', 'Labels'], Object.entries(iot.corpus).map(([k, v]) => [k.replace('CTU-IoT-Malware-Capture-', 'Malware ').replace('CTU-Honeypot-Capture-', 'Honeypot '), n(v.records), n(v.represented), labelCount(v.labels)]), [0.2, 0.14, 0.15, 0.51]);

h2('5.3  Leakage Controls and Split Protocols');
list([
  '**Synthetic:** episodes and exact feature vectors may not cross partitions (checked in code); thresholds are chosen on the tuning partition only. The seed-42 test set was inspected during development, so it is labelled exploratory; a frozen model was additionally evaluated on fresh draws (seed 381947) without refitting.',
  '**UNSW-NB15:** duplicate feature vectors share a validation group; test results are reported with and without rows whose vectors occur in training. An open-set test removes the four smallest families (analysis, backdoor, shellcode, worms) from training.',
  '**IoT-23 protocol A (temporal blocks):** each capture is cut into 20 contiguous arrival-order blocks mapped to partitions by a fixed interleaved pattern, with a 60-second event-time purge at partition boundaries. Bursty attack phases stay testable without shuffling rows.',
  '**IoT-23 protocol B (withheld class):** as A, with attack_attempt removed from every fitting partition.',
  '**IoT-23 protocol C (leave-capture-out):** captures 8-1 (Hakai botnet) and honeypot 5-1 (benign IoT devices) are never used for fitting; the remaining captures supply all fitting partitions.',
]);
p('IoT-23 protocols were fixed before any IoT-23 result was observed. Partition coverage gaps are reported rather than hidden: DoS has no calibration, fusion or tuning rows in any protocol, and in protocol C the fusion partition contains no command-and-control rows because capture 34-1\'s C&C traffic is concentrated in time.');

h2('5.4  Metrics');
list([
  '**Binary detection:** precision, recall, F1, false-positive rate (FPR), ROC-AUC and PR-AUC of the fused score at the tuning-selected threshold.',
  '**Decision-level outcomes:** every sampled test flow is passed through the exact serving path (prediction, decision, attribution). Reported: benign flows called normal, abstaining, alerting and malicious; attacks flagged; attacks given the correct type; attacks given a wrong known type; and for each true label, which analyst-facing label it received.',
  '**Performance:** per-flow latency including explanation, replay throughput and storage cost per event.',
]);

h2('5.5  Reproducibility');
p('All experiments are seeded and write complete JSON result files, including dataset hashes, partition sizes, leakage reports and model hyperparameters. Model artifacts record training fingerprints. Appendix A lists the exact commands.');

// ------------------------------------------------------------------------------------------------
h1('6  Results');
h2('6.1  Synthetic Episodes');
table('Synthetic test set: binary detection by layer', ['Detector', 'Precision', 'Recall', 'F1', 'FPR', 'ROC-AUC'], [
  ['Logistic regression baseline', ...bin(syn.variants.baseline_logistic)],
  ['Supervised layer only', ...bin(syn.variants.supervised)],
  ['Anomaly layer only', ...bin(syn.variants.anomaly_only)],
  ['Temporal layer only', ...bin(syn.variants.temporal_only)],
  ['Fusion without temporal evidence', ...bin(syn.variants.without_temporal)],
  ['Full fusion', ...bin(syn.variants.full)],
], [0.34, 0.13, 0.13, 0.13, 0.13, 0.14], `${n(syn.test_samples)} test flows. Episode-bootstrap 95 % interval for F1(full) − F1(supervised): [${f3(syn.bootstrap.percentile_95_interval[0])}, ${f3(syn.bootstrap.percentile_95_interval[1])}].`);
p(`Fusion clearly outperforms every single layer, and removing temporal evidence raises FPR from ${pct(syn.variants.full.false_positive_rate, 2)} to ${pct(syn.variants.without_temporal.false_positive_rate, 2)}, showing that host context contributes information unavailable per flow. These are synthetic results and validate the implementation rather than real-world effectiveness.`);
table('Synthetic test set: analyst-facing decisions', ['Outcome', 'Inherited logic', 'Final system', 'Without class support'], [
  ['Benign → normal', share(inh.benign.normal, inh.benign.n), pct(syn.decisions.benign_normal_rate), pct(syn.ablation_test.benign_normal_rate)],
  ['Benign → unknown (abstain)', share(inh.benign.unknown, inh.benign.n), pct(syn.decisions.benign_abstention_rate), pct(syn.ablation_test.benign_abstention_rate)],
  ['Benign → alert', share(inh.benign.suspicious, inh.benign.n), pct(syn.decisions.benign_alert_rate), pct(syn.ablation_test.benign_alert_rate)],
  ['Attacks flagged', 'not measured', pct(syn.decisions.attack_flagged_rate), pct(syn.ablation_test.attack_flagged_rate)],
  ['Attacks given the correct type', 'not measured', pct(syn.decisions.attack_correct_attribution_rate), pct(syn.ablation_test.attack_correct_attribution_rate)],
  ['Withheld beacon family (337 flows)', `${inh.beacon.malicious} malicious + ${inh.beacon.suspicious} suspicious, all "scan"`, `${syn.withheld.anomalous} anomalous, 0 invented types`, `${syn.withheld_ablation.malicious} malicious + ${syn.withheld_ablation.suspicious} suspicious, all "scan"`],
], [0.3, 0.25, 0.22, 0.23]);
p(`The inherited decision logic required high class confidence even to call traffic normal, so ${share(inh.benign.unknown, inh.benign.n)} of benign flows abstained, and it mapped every flow of the withheld beacon family onto "scan". Separating detection from attribution and adding the class-support check reduced abstention to ${pct(syn.decisions.benign_abstention_rate)} and reported every beacon flow as anomalous. The ablation shows that on this data the class-support layer is what prevents the invented labels.`);
p(`A frozen model evaluated on fresh synthetic draws without refitting gave F1 ${f3(conf.binary.f1)}, benign normal rate ${pct(conf.decisions.benign_normal_rate)}, wrong attack type ${pct(conf.decisions.attack_wrong_attribution_rate)}, and ${n(conf.withheld.anomalous)} of ${n(Object.values(conf.withheld).reduce((s, v) => s + v, 0))} withheld-family flows reported as anomalous. Stress tests on the fused score alone showed that covariate shift reduced F1 only to ${f3(syn.stress.covariate_shift.f1)}, while on episodes containing the withheld family fused-score recall was ${f3(syn.stress.heldout_unknown.recall)}; decision-level evaluation is what reveals that those flows are still reported as anomalous.`);

h2('6.2  UNSW-NB15');
table('UNSW-NB15 official test set, reduced generic counters', ['Detector / rows', 'Precision', 'Recall', 'F1', 'FPR', 'ROC-AUC'], [
  ['Logistic baseline, all rows', ...bin(unsw.all.baseline_logistic)],
  ['Supervised, all rows', ...bin(unsw.all.supervised)],
  ['Anomaly only, all rows', ...bin(unsw.all.anomaly_only)],
  ['Reduced hybrid, all rows', ...bin(unsw.all.reduced_hybrid)],
  ['Supervised, unseen rows', ...bin(unsw.unseen_metrics.supervised)],
  ['Reduced hybrid, unseen rows', ...bin(unsw.unseen_metrics.reduced_hybrid)],
], [0.34, 0.13, 0.13, 0.13, 0.13, 0.14], `All rows: ${n(unsw.rows.test)}; unseen rows (feature vector absent from training): ${n(unsw.unseen)}.`);
p(`On UNSW-NB15's ten generic counters the hybrid detector reached F1 ${f3(unsw.all.reduced_hybrid.f1)} at ${pct(unsw.all.reduced_hybrid.false_positive_rate)} FPR, falling to F1 ${f3(unsw.unseen_metrics.reduced_hybrid.f1)} at ${pct(unsw.unseen_metrics.reduced_hybrid.false_positive_rate)} FPR on unseen vectors. Attack-family classification was weak (macro F1 ${f3(unsw.macro_f1)}). In the open-set test, ${pct(unsw.open_set.withheld_family_test_rows.attributed_wrong_type)} of withheld-family flows received a confident wrong type both with and without the class-support check: these families overlap known ones in the reduced feature space, so the check gave no measurable benefit here; the confidence gate withheld ${pct(unsw.open_set.withheld_family_test_rows.withheld_low_confidence)} of them.`);

h2('6.3  IoT-23 Real Traffic');
table('IoT-23 binary detection by protocol', ['Protocol / rows', 'Precision', 'Recall', 'F1', 'FPR', 'ROC-AUC'], [
  [`A temporal blocks, all ${n(A.binary.samples)} rows`, ...bin(A.binary)],
  [`A, ${n(A.unseen_binary.samples)} unseen-vector rows`, ...bin(A.unseen_binary)],
  [`B attack_attempt withheld, all rows`, ...bin(B.binary)],
  [`B, unseen-vector rows`, ...bin(B.unseen_binary)],
  [`C leave-capture-out, all ${n(C.binary.samples)} rows`, ...bin(C.binary)],
  [`C, ${n(C.unseen_binary.samples)} unseen-vector rows`, ...bin(C.unseen_binary)],
], [0.34, 0.13, 0.13, 0.13, 0.13, 0.14], `In protocol A, ${n(A.seen)} of ${n(A.binary.samples)} test rows (${share(A.seen, A.binary.samples, 0)}) repeat a feature vector seen in fitting data.`);
table('IoT-23 single layers (F1 and FPR at tuning-selected thresholds)', ['Protocol', 'Supervised F1', 'FPR', 'Anomaly F1', 'FPR', 'Temporal F1', 'FPR', 'Fusion F1'], [
  layerRow('A', A), layerRow('B', B), layerRow('C', C),
], [0.1, 0.13, 0.12, 0.13, 0.12, 0.13, 0.12, 0.15]);
table('IoT-23 analyst-facing decisions (sampled test flows)', ['Outcome', 'A', 'B', 'C'], [
  ['Benign flows sampled', n(A.decisions.benign_flows), n(B.decisions.benign_flows), n(C.decisions.benign_flows)],
  ['Benign → normal', pct(A.decisions.benign_normal_rate), pct(B.decisions.benign_normal_rate), pct(C.decisions.benign_normal_rate)],
  ['Benign → alert', pct(A.decisions.benign_alert_rate), pct(B.decisions.benign_alert_rate), pct(C.decisions.benign_alert_rate)],
  ['Benign → malicious', pct(A.decisions.benign_malicious_rate), pct(B.decisions.benign_malicious_rate), pct(C.decisions.benign_malicious_rate)],
  ['Attack flows sampled', n(A.decisions.attack_flows), n(B.decisions.attack_flows), n(C.decisions.attack_flows)],
  ['Attacks flagged', pct(A.decisions.attack_flagged_rate), pct(B.decisions.attack_flagged_rate), pct(C.decisions.attack_flagged_rate)],
  ['Attacks given the correct type', pct(A.decisions.attack_correct_attribution_rate), pct(B.decisions.attack_correct_attribution_rate), pct(C.decisions.attack_correct_attribution_rate)],
  ['Attacks given a wrong known type', pct(A.decisions.attack_wrong_attribution_rate), pct(B.decisions.attack_wrong_attribution_rate), pct(C.decisions.attack_wrong_attribution_rate)],
], [0.4, 0.2, 0.2, 0.2]);
p(`**Protocol A.** Within known captures the system performs strongly (F1 ${f3(A.binary.f1)}), but ${share(A.seen, A.binary.samples, 0)} of test rows repeat fitting vectors, and on genuinely new vectors F1 falls to ${f3(A.unseen_binary.f1)} with FPR ${pct(A.unseen_binary.false_positive_rate)}. Destination port is the most important supervised feature (${pct(iot.feature_importance_A[0].importance, 0)} of impurity importance), so the classifier partly learns capture-specific ports.`);
p(`**Protocol B.** ${n(B.decision_counts.attack_attempt.anomalous)} of ${n(Object.values(B.decision_counts.attack_attempt).reduce((s, v) => s + v, 0))} flows of the withheld attack_attempt class were reported as anomalous, and none received an invented known type. The fused score alone detected unseen-vector attacks with recall of only ${f3(B.unseen_binary.recall)}; the anomaly-driven decision rule caught them. An ablation without the class-support layer produced the same ${n(B.ablation.attack_attempt.anomalous)} anomalous decisions, so on this data the benefit comes from benign-relative novelty and the decision rule rather than class support.`);
p(`**Protocol C.** On an unseen network and malware family, detection transferred but attribution and benign precision did not. Every Hakai command-and-control flow was detected (recall ${f3(C.binary.recall)}), yet the supervised layer alone scored F1 ${f3(C.single_layers.supervised.f1)}; detection came from the anomaly and behavioural-profile layers (fusion without the profile scored F1 ${f3(C.fusion_variants.without_profile.f1)}). All ${n(C.attributed_as.command_and_control.scan)} sampled C&C flows were typed as scan. Per capture, benign FPR was ${pct(C.per_capture['CTU-Honeypot-Capture-5-1'].false_positive_rate)} on the unseen honeypot's devices and ${pct(C.per_capture['CTU-IoT-Malware-Capture-8-1'].false_positive_rate)} on capture 8-1's benign traffic. After the unverifiable-attribution correction (Section 4.6), no benign flow was decided malicious; before it, ${n(iot.prefix_C.benign_malicious)} sampled benign flows had been labelled DoS with malicious decisions (commit ${iot.prefix_C.commit}).`);

h2('6.4  Live Replay of Unseen Captures');
p(`The protocol C model was served by the running system, and both held-out captures were replayed through the command-line collector and the authenticated API exactly as a sensor would deliver them. Ground-truth labels were joined back to stored events afterwards, for scoring only. All ${n(after.events)} events matched a labelled record.`);
table('Live replay decisions on never-seen real traffic', ['True traffic', 'Flows', 'Decisions', 'Analyst-facing type'], [
  ['Hakai botnet C&C (8-1)', n(lcTotal(cc)), `${share(lc(cc).suspicious, lcTotal(cc))} suspicious, ${share(lc(cc).malicious, lcTotal(cc))} malicious`, 'scan (wrong)'],
  ['Benign, capture 8-1', n(lcTotal('capture-8-1|normal')), `${share(lc('capture-8-1|normal').normal, lcTotal('capture-8-1|normal'))} normal, ${share(lc('capture-8-1|normal').unknown, lcTotal('capture-8-1|normal'))} uncertain`, '—'],
  ['Benign, unseen honeypot 5-1', n(lcTotal('honeypot-5-1|normal')), `${share(lc('honeypot-5-1|normal').anomalous, lcTotal('honeypot-5-1|normal'))} anomalous, ${share(lc('honeypot-5-1|normal').normal, lcTotal('honeypot-5-1|normal'))} normal, ${share(lc('honeypot-5-1|normal').unknown, lcTotal('honeypot-5-1|normal'))} uncertain`, 'Unattributed'],
], [0.27, 0.11, 0.42, 0.2], `All benign: ${share(benignLive.normal, benignLiveN)} normal, ${share((benignLive.anomalous || 0) + (benignLive.suspicious || 0) + (benignLive.malicious || 0), benignLiveN)} alerting, ${share(benignLive.malicious || 0, benignLiveN)} malicious.`);
p(`The live decision distribution for C&C traffic (${share(lc(cc).suspicious, lcTotal(cc))} suspicious, ${share(lc(cc).malicious, lcTotal(cc))} malicious) agrees with the offline evaluation of the same protocol (${share(C.decision_counts.command_and_control.suspicious, Object.values(C.decision_counts.command_and_control).reduce((s, v) => s + v, 0))} and ${share(C.decision_counts.command_and_control.malicious, Object.values(C.decision_counts.command_and_control).reduce((s, v) => s + v, 0))}), confirming that the serving path and the evaluation path compute the same results. No benign flow reached a malicious decision, so none became eligible for containment. Operating the response workflow on these events, a block request for a genuinely infected host was held for human approval, while isolation of a benign smart-home device flagged as anomalous was denied because containment requires an attributed malicious decision.`);

h2('6.5  Performance');
table('Performance measurements', ['Measurement', 'Value'], [
  ['Synthetic per-flow inference with explanation', `p50 ${syn.latency.p50.toFixed(1)} ms, p95 ${syn.latency.p95.toFixed(1)} ms`],
  ['IoT-23 per-flow serving path (protocol A sample)', `p50 ${A.latency.p50.toFixed(1)} ms, p95 ${A.latency.p95.toFixed(1)} ms`],
  ['Live replay mean inference per flow', `${after.mean_inference_ms.toFixed(1)} ms`],
  ['Live replay of capture 8-1 (10,403 flows), storage defect present', `${replayBeforeSeconds} s; storage ${before.ms_per_event.start.toFixed(1)} → ${before.ms_per_event.end.toFixed(1)} ms per event`],
  ['Same replay after incremental incident bounds', `${replaySeconds} s; ${after.ms_per_event.start.toFixed(1)} → ${after.ms_per_event.end.toFixed(1)} ms per event`],
  ['Replay throughput, one inference worker', `≈ ${Math.round(throughput)} flows per second`],
  ['IoT-23 training time per protocol', `${Math.round(Math.min(A.fit_seconds, B.fit_seconds, C.fit_seconds))}–${Math.round(Math.max(A.fit_seconds, B.fit_seconds, C.fit_seconds))} s`],
], [0.52, 0.48], `Measured on ${D.environment.platform}, single-threaded model execution.`);

h2('6.6  Software Verification');
p(`The automated test suite contains ${D.tests.collected} tests across ${D.tests.files.length} files, covering schema and injection rejection, decision, attribution and risk rules, a genuinely trained model (manifest tampering, output contract, identity invariance, recomputable explanations), API authorization and perimeter controls, storage migrations and correlation, response safety, collectors and reordering, the IoT-23 corpus pipeline and an end-to-end API pipeline. A dependency-free Node script checks dashboard rendering and refresh races. A live verification script starts real server processes and runs ${D.verification.checks} checks across ${D.verification.stages.length} stages; all passed (${D.verification.failed} failures).`);

// ------------------------------------------------------------------------------------------------
h1('7  Discussion');
h2('7.1  Answers to the Research Questions');
list([
  `**RQ1.** Fusion outperforms individual layers on synthetic data, and host context adds measurable value. Headline scores are optimistic whenever test rows repeat training vectors: F1 fell from ${f3(A.binary.f1)} to ${f3(A.unseen_binary.f1)} on IoT-23 and from ${f3(unsw.all.reduced_hybrid.f1)} to ${f3(unsw.unseen_metrics.reduced_hybrid.f1)} on UNSW-NB15.`,
  `**RQ2.** Separating detection from attribution removed most benign abstention (${share(inh.benign.unknown, inh.benign.n)} → ${pct(syn.decisions.benign_abstention_rate)} synthetic) while flagging ${pct(syn.decisions.attack_flagged_rate)} of attacks. On known IoT-23 captures ${pct(A.decisions.benign_normal_rate)} of benign flows were called normal.`,
  `**RQ3.** Yes on synthetic data and IoT-23: withheld attack types were reported as anomalous with no invented labels. Not on UNSW-NB15's reduced counters, where withheld families resemble known ones in feature space.`,
  `**RQ4.** Poorly. Detection of a new malware family relied on anomaly and behavioural layers and attribution failed completely; the fused false-positive rate was ${pct(C.binary.false_positive_rate)}, ${pct(C.decisions.benign_alert_rate)} of sampled benign flows raised alerts, and most flows from the unseen benign devices were reported as anomalous.`,
  `**RQ5.** Yes. Live replay reproduced offline decisions on ${n(after.events)} real flows at single-digit millisecond inference, once a quadratic storage defect found during the replay was fixed.`,
]);

h2('7.2  What the Headline Numbers Mean');
p('A detection F1 above 0.99 was obtained twice in this project, and in both cases it overstates what the system would achieve on new traffic: on synthetic data because the generator is hand-designed, and on IoT-23 because most test rows repeat vectors seen during fitting. Reporting only these numbers would reproduce the evaluation problems described by Arp et al. [2]. The unseen-vector results, decision-level outcomes and the leave-capture-out protocol are the more informative evidence.');

h2('7.3  Where Open-Set Logic Helped and Where It Did Not');
p('The combination of benign-relative novelty and class support prevented invented attack types when novel traffic was genuinely different from training traffic (the synthetic beacon family; IoT-23 attack attempts). It did not help when novel classes lay close to known ones (UNSW-NB15 families in ten counters; Hakai command-and-control, which was typed as scan because it lay inside the scan class\'s support). Distance-based support can only flag what the feature space separates; the confidence gate and the anomaly layer carried most of the protective effect in the real-data experiments.');

h2('7.4  Why Cross-Network Transfer Failed');
list([
  '**Feature reliance:** destination port dominates supervised importance, and ports are largely deployment- and malware-specific.',
  '**Benign diversity:** the unseen honeypot\'s smart-home devices used protocols and ports absent from other captures\' benign traffic, so the benign-only anomaly model reported most of them as novel.',
  '**Small corpus:** IoT-23 contains few devices and malware samples; DoS contributes only 135 usable flows, and temporal concentration left validation partitions without some classes.',
]);
p('The practical implication is that a deployment should collect benign traffic from its own network to calibrate the anomaly and profile layers before the system is trusted, and should retrain and re-evaluate on locally labelled data.');

h2('7.5  Data-Quality Lessons');
list([
  `Labelled public data can contain artifacts: ${n(ddosExcluded)} IoT-23 "DDoS" records had zero counted packets and would have taught the model that empty counters indicate an attack.`,
  'Sensor semantics matter: Zeek\'s end-of-connection output order and unset single-packet fields silently degraded behavioural features and broke ingestion until handled explicitly.',
  'Evaluation at scale finds engineering defects that unit tests miss: the storage slowdown appeared only when a real botnet produced an incident of thousands of events.',
]);

h2('7.6  Threats to Validity');
list([
  '**Post-hoc correction:** the unverifiable-attribution rule was added after inspecting protocol C results. It changed decisions only, not scores, and both before and after figures are reported.',
  '**Exploratory synthetic test:** the seed-42 synthetic test set was inspected during development; fresh-draw confirmation mitigates but does not remove this.',
  '**Single seed and sampling:** IoT-23 results use one seed; decision-level figures use bounded per-label samples whose composition differs from the full population (visible in the live replay comparison).',
  '**Dataset scope:** synthetic data are hand-designed; UNSW-NB15 and IoT-23 are laboratory captures from 2015 and 2018–2019.',
  '**Deployment:** Docker packaging was not executed in this environment, and the system runs as a single process.',
]);

h2('7.7  Ethics and Safety');
p('The project never captured third-party traffic, never probed networks and never executed containment. Public datasets were used under their published terms, with sources cited. Response actions are simulated, policy-gated and audited, and the design prevents unattributed or uncertain evidence from reaching containment. A production deployment would additionally require legal authorization for monitoring, data-protection review, TLS, per-user identity and independent security review.');

// ------------------------------------------------------------------------------------------------
h1('8  Conclusion and Future Work');
p('AegisWeave demonstrates a complete, tested ML-first intrusion detection system in which detection, attribution, risk and response are deliberately separated, uncertainty is stated rather than hidden, and every reported number is reproducible from committed code and data. Its open-set decision logic prevented invented attack labels on synthetic data and on a withheld class of real IoT attacks, and a live replay reproduced offline results on real traffic.');
p('The evaluation also shows clearly what the system cannot yet do: models trained on some laboratory networks do not transfer reliably to a new network or malware family. That conclusion, reached with leakage-aware, decision-level evaluation, is itself a central result of the project.');
p('**Future work:**');
numbered([
  'Per-site calibration of the anomaly and behavioural profile layers on locally collected benign traffic, followed by re-measurement of cross-network false positives.',
  'Reduced dependence on destination port through feature ablation and port-group abstractions.',
  'Larger and more diverse corpora (additional IoT-23 captures, CIC-IDS2017 flows with timestamps, locally recorded traffic) and multiple seeds with confidence intervals.',
  'Density- or representation-based open-set methods that separate classes overlapping in counter space.',
  'Horizontal scaling with an external queue and database, verified container deployment and TLS.',
  'Controlled live response adapters behind the existing policy engine, tested in an isolated laboratory network.',
]);

// ------------------------------------------------------------------------------------------------
h1('References');
blocks.push({ type: 'references', items: [
  'R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," in Proc. IEEE Symposium on Security and Privacy, 2010, pp. 305–316.',
  'D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro and K. Rieck, "Dos and don\'ts of machine learning in computer security," in Proc. USENIX Security Symposium, 2022.',
  'V. Paxson, "Bro: A system for detecting network intruders in real-time," Computer Networks, vol. 31, no. 23–24, pp. 2435–2463, 1999.',
  'W. J. Scheirer, A. de Rezende Rocha, A. Sapkota and T. E. Boult, "Toward open set recognition," IEEE Transactions on Pattern Analysis and Machine Intelligence, vol. 35, no. 7, pp. 1757–1772, 2013.',
  'F. T. Liu, K. M. Ting and Z.-H. Zhou, "Isolation forest," in Proc. IEEE International Conference on Data Mining, 2008, pp. 413–422.',
  'J. H. Friedman, "Greedy function approximation: A gradient boosting machine," Annals of Statistics, vol. 29, no. 5, pp. 1189–1232, 2001.',
  'C. Guo, G. Pleiss, Y. Sun and K. Q. Weinberger, "On calibration of modern neural networks," in Proc. International Conference on Machine Learning, 2017.',
  'D. H. Wolpert, "Stacked generalization," Neural Networks, vol. 5, no. 2, pp. 241–259, 1992.',
  'F. Pedregosa et al., "Scikit-learn: Machine learning in Python," Journal of Machine Learning Research, vol. 12, pp. 2825–2830, 2011.',
  'N. Moustafa and J. Slay, "UNSW-NB15: A comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)," in Proc. Military Communications and Information Systems Conference (MilCIS), 2015.',
  'S. Garcia, A. Parmisano and M. J. Erquiaga, "IoT-23: A labeled dataset with malicious and benign IoT network traffic," Stratosphere Laboratory, 2020. [Online]. Available: https://www.stratosphereips.org/datasets-iot23',
] });

// ------------------------------------------------------------------------------------------------
h1('Appendix A  Reproduction Commands');
p('All commands run from the repository root with the project virtual environment. Windows paths are shown; on Linux or macOS use .venv/bin/python. Indented lines continue the command above them and must be typed on the same line.');
code('Environment and tests', [
  'python -m venv .venv',
  '.venv/Scripts/python -m pip install -r requirements.lock',
  '.venv/Scripts/python -m pytest -p no:cacheprovider',
  'node frontend/check-ui.cjs',
  '.venv/Scripts/python scripts/verify_pipeline.py',
]);
code('Experiments', [
  '.venv/Scripts/python -m experiments.run --model var/models/active',
  '.venv/Scripts/python -m experiments.confirm',
  '.venv/Scripts/python -m experiments.public',
  '    --train var/datasets/UNSW_NB15_training-set.csv',
  '    --test var/datasets/UNSW_NB15_testing-set.csv',
  '.venv/Scripts/python -m experiments.iot23',
  '    --model var/models/iot23 --model-lco var/models/iot23-lco',
]);
code('Demonstrations', [
  '.venv/Scripts/python -m aegisweave demo --count 200',
  '.venv/Scripts/python -m aegisweave serve --port 8791',
  '    --model var/models/iot23-lco --db var/iot23-unseen.db',
  '.venv/Scripts/python -m aegisweave replay',
  '    var/datasets/iot23/CTU-Honeypot-Capture-5-1.conn.log.labeled',
  '    --format zeek-tsv --sensor honeypot-5-1 --batch-size 200',
  '    --url http://127.0.0.1:8791',
  '.venv/Scripts/python -m aegisweave replay',
  '    var/datasets/iot23/CTU-IoT-Malware-Capture-8-1.conn.log.labeled',
  '    --format zeek-tsv --sensor capture-8-1 --batch-size 200',
  '    --url http://127.0.0.1:8791',
]);
p('The synthetic demonstration dashboard opens at http://127.0.0.1:8765 and the real-traffic replay dashboard at http://127.0.0.1:8791. IoT-23 files are downloaded from https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/<capture>/bro/conn.log.labeled and saved as var/datasets/iot23/<capture>.conn.log.labeled; their SHA-256 hashes are recorded in experiments/results/iot23.json.');

h1('Appendix B  Test and Verification Coverage');
table('Automated test files', ['File'], D.tests.files.map(f => [f]), [1]);
table('Live verification stages', ['Stage'], D.verification.stages.map(s => [s]), [1], `${D.verification.checks} checks, ${D.verification.failed} failures, ${D.verification.seconds} s.`);

h1('Appendix C  API Surface');
table('API endpoints', ['Method and path', 'Minimum role', 'Purpose'], [
  ['GET /api/health', 'None (perimeter applies)', 'Minimal health and response mode'],
  ['GET /api/session', 'Loopback demo only', 'Ephemeral demonstration token'],
  ['GET /api/identity', 'Viewer', 'Authenticated role'],
  ['GET /api/overview, /api/metrics', 'Viewer', 'Counts, decision trend, latency, health, resources'],
  ['GET /api/events, /api/events/{id}', 'Viewer', 'Filtered events and full intelligence records'],
  ['GET /api/incidents, /api/incidents/{id}', 'Viewer', 'Correlated incidents and timelines'],
  ['GET /api/models, /api/behavior, /api/drift', 'Viewer', 'Model registry, host windows, drift state'],
  ['GET /api/policies, /api/responses', 'Viewer', 'Response policy and simulation ledger'],
  ['GET /api/audit', 'Analyst', 'Audit trail'],
  ['POST /api/telemetry, /api/telemetry/batch', 'Analyst', 'Ingest one or up to 200 flows'],
  ['POST /api/demo', 'Analyst', 'Generate and process synthetic flows'],
  ['POST /api/responses, …/approve, …/rollback', 'Analyst', 'Propose, approve or roll back simulated actions'],
  ['PUT /api/policies', 'Admin', 'Update the validated response policy'],
  ['POST /api/models/reload', 'Admin', 'Verify and reload the configured model artifact'],
], [0.42, 0.22, 0.36]);

h1('Appendix D  Development History');
p('The project is under version control. Its commit history records the main development stages:');
table('Commits (newest first)', ['Commit', 'Summary'], D.git.map(line => [line.slice(0, 7), line.slice(8)]), [0.15, 0.85]);

module.exports = { meta, blocks, D };
