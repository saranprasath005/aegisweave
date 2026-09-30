# AegisWeave work checkpoint

Updated 16 September 2026. Continue existing work; no restart or model promotion without evaluation.

## Latest checkpoint: Windows presentation, 17 September

User needs to present a working prototype tomorrow and explicitly defers Linux installation until after the presentation. Preserve the presentation environment; do not initiate OS changes or model promotion. Added START_PROTOTYPE.cmd and scripts/start_prototype.py: a loopback-only synthetic presentation on port 8775, a fresh database per server start under var/prototype, existing running presentation reused. It uses the existing active model and leaves the research database untouched. No dependencies or Linux installation required on this prepared PC.

Current presentation run: var/prototype/20260917-003004-987753. Dashboard verified in browser: connected, 200 events, 35 malicious and 64 anomalous decisions. Launcher startup and repeat invocation verified. Frontend regression script passed. Full HTTP pipeline verification passed 88/88 in 57.9 seconds; report var/verify/20260917-002940/report.json. All demonstration input and response actions are explicitly simulated. docs/PROTOTYPE_DEMO.md contains the walkthrough, startup/recovery instructions and research limitations/Q&A.

Linux migration and lab validation remain deferred as requested. Keep this presentation stable through the meeting; resume the earlier lab plan afterward when the user is ready. Latest usage check at task start: 95% five-hour and 26% weekly remaining.

## Previous checkpoint: local lab direction, 16 September

This section supersedes the host-input assumptions below. The user has no separate Linux machine and no office network access, and intends to keep Windows alongside Ubuntu on this PC. Do not keep asking for an existing office/Linux host. Ubuntu installation is not yet confirmed. No partition or OS changes are authorized by the continuation heartbeat alone.

At this heartbeat usage was available: 97% five-hour and 28% weekly remaining. Updated PRODUCTION_TARGET.md and added LAB_VALIDATION.md to make the immediate milestone a deployable, lab-validated candidate; actual office validation remains a later gate. No training was rerun, no model promoted, and no runtime verification is claimed by these documentation changes.

Next concrete work follows LAB_VALIDATION.md: preserve and independently back up existing work before OS installation; once Linux is available validate offline PCAP-to-Zeek feature semantics, container startup/TLS, durable ingestion/recovery and measured replay throughput. No office access is required for these steps. Linux availability and an external backup destination remain inputs for migration; do not invent either. Existing corrected model failures remain release blockers. Preserve the usage-aware heartbeat and stay quiet on unchanged dependencies rather than repeating host questions.

## Previous checkpoint: morning continuation, 16 September

This section supersedes the previous execution notes below. Usage recovered and work resumed; latest check showed 24% five-hour and 31% weekly allowance remaining. This milestone stops for deployment-host input, not a claim that allowance is exhausted.

### Completed and verified

- The context-v2 IoT-23 run finished in 1,685 seconds. Both candidate artifacts load with verified hashes and context-isolation version 2. No training process remains running and neither model was promoted. Review: docs/MODEL_REVIEW_CONTEXT_V2.md. Whole-capture binary FPR remains 10.27%; sampled benign alerting is 24.7%, with wrong attack attribution on all sampled attacks. These captures are now development evidence for future changes.
- Acquired the corrected CICIDS2017 dataset directly from the correction authors over HTTPS. Five raw CSVs, archive, acquisition hashes, and staged captures are in var/datasets/cicids2017-improved. 2,099,976 records retained; 11,979 attempted flows explicitly mapped to benign following the authors' documented recommendation. Original files preserved. The primary university registration-form failure is no longer blocking this corrected-version acquisition.
- Added scripts/acquire_cic2017.py and experiments/prepare_cic.py, strict staging/provenance/exclusion accounting, explicit attempted-flow policy, and tests. Fixed the inherited pandas read-only-array failure in load_cic duration conversion.
- Added experiments/cic_baseline.py: fit Tuesday/Wednesday, calibrate independent Thursday benign vectors, test Friday/Monday with frozen thresholds. Reports: experiments/results/cic2017-baseline-v1.json and cic2017-baseline-v1-details.json. The details run has identical thresholds and adds per-label reporting. Boosted-tree Friday recall 99.15% masks 0/736 botnet detections. Friday FPR 1.21%, Monday FPR 1.72%. These are offline counter baselines, not live Zeek model artifacts. Review: docs/CIC2017_BASELINE_REVIEW.md.
- Collector now records oldest pending age and atomically publishes status. New collector-health command checks missing/stale status, delivery/source errors, backpressure, current-cycle rejects and aged pending events. deploy/compose.yaml now uses this healthcheck. There is still no external operator notification integration.
- Full suite: 164 tests passed in 24.76 seconds. Four warnings: two existing dependency deprecations and two benign small-fixture IsolationForest max_samples warnings. Updated real-process collector verification: 8/8 checks passed, var/verify/20260916-082210/collector-report.json. The previous 88-check full HTTP verification remains historical evidence; no API code was changed in this continuation.

### Next actions / input dependencies

1. Obtain access details for the user's Linux machine/VM with Docker. An asynchronous question is pending asking whether it is available, without requesting passwords or private keys. Local checks confirm Docker is absent and WSL reports not installed. Do not claim container/TLS/Zeek validation happened or silently install a host OS.
2. On that host, validate deploy/ Compose build/start, supplied certificates, proxy Origin behavior, required-real-model rejection, persistent volumes, collector health/restart and backup/restore. A real-data flag does not authorize promotion of a poor candidate.
3. Validate common feature semantics by processing known PCAPs with the intended Zeek sensor; CICFlowMeter byte counters have not been shown equivalent to the deployed payload measurements. A reduced counter benchmark is not a replacement for the full live bundle.
4. Obtain representative authorized office telemetry and additional botnet/C&C evidence. Use new held-out data for final claims; do not tune against the already inspected IoT or CIC test captures and then call them untouched.
5. Measure actual site load and run the agreed observation pilot. Site network visibility, hardware, traffic, permission and operational acceptance values remain needed.

Do not rerun completed acquisitions/training or make arbitrary feature additions while waiting for host access. Check whether the pending input has arrived, and continue concrete independent validation if available. Stay quiet on unchanged blocked/paused state as requested. Preserve the six-hour usage-aware heartbeat and the 10% pause rule.

## User direction

Continue the production plan for a passive small-office LAN NIDS. Pause development when either Codex allowance has 10% or less remaining and resume after capacity restores. A six-hour thread heartbeat named Resume AegisWeave development (id resume-aegisweave-development) checks usage and resumes work. Do not redeem credits or purchase anything. Ordinary allowance was available at the start (76% five-hour, 54% weekly remaining).

## Previous checkpoint (retained as history)

Usage checkpoint: five-hour allowance 11% remaining, weekly 44% remaining at the latest check. Finish the current validation/checkpoint and pause agent implementation near the 10% threshold. The already-started local training process may finish without further agent usage. Resume via the configured six-hour heartbeat when both usage windows have more than 10% remaining.

The user explicitly chose Linux machine/VM with Docker. Files are in deploy/ (separate from root demo Compose). Docker is not installed here, so build/run/TLS integration are unverified. The new image requires an explicit non-synthetic model; it does not train a demo model. Trusted AEGISWEAVE_PUBLIC_ORIGIN enables proxy HTTPS Origin checks without trusting forwarded headers.

Completed this continuation:
- Added durable Zeek JSON collect command, persistent spool/cursor transactions, retry and duplicate acknowledgments, rename rotation, bounded pending records, local configuration validation, and simulated-fixture mode. See docs/COLLECTOR.md.
- Seven collector unit tests pass. Real HTTP collector verification passed six checks, report var/verify/20260916-004848/collector-report.json.
- Added SQLite online backup and verified restore to unused paths. Unit tests pass. Actual dashboard DB backup is var/backups/20260916-readiness; separately restored DB is var/verify/20260916-restored.db. Running dashboard DB was not replaced.
- Full existing HTTP verification passed 88 checks, var/verify/20260916-005359/report.json, before the public-origin addition. Public-origin/deployment plus API-security focused tests subsequently passed 38 checks. Final full pytest run completed: 158 passed, two existing dependency deprecation warnings, in 28.20 seconds.
- CICIDS2017 official download link https://cicresearch.ca/CICDataset/CIC-IDS-2017/ returned a server error and registration form. No registration identity was supplied, no submission was made, and no new dataset was downloaded. Alternate corrected-dataset page also timed out. This remains an acquisition dependency, not a successful integration.

Corrected IoT-23 full-corpus run launched in exec session 60716:

`.venv/Scripts/python.exe -m experiments.iot23 --output experiments/results/iot23-context-v2.json --model var/models/iot23-context-v2 --model-lco var/models/iot23-lco-context-v2`

Inspect running processes and output files before launching another run. Preserve existing active model and historical experiments/results/iot23.json. The corrected code passed 142 tests before this run.

Training process IDs at launch: venv launcher 2888, Python worker 34556. Last output: A fitted and evaluated; B/C still pending. Whole-corpus loading covered 1,204,888 records. The script saves final results and candidate artifacts only after all protocols finish. Do not duplicate or stop the existing process unnecessarily; inspect session 60716 or final files on resumption. These candidate models have NOT been promoted to the dashboard.

## Previous next-work list (superseded above)

1. Finish and inspect context-v2 evaluation; report both repeated/unseen vectors, false alerts and attribution. Do not promote a poor model.
2. Audit and integrate CICIDS2017 as a separate, provenance-tracked dataset with clean capture-separated evaluation. Do not claim offline reduced counters are the live Zeek model.
3. Collector core is complete and tested; remaining work includes sustained load, health/alert integration, and validation with actual Zeek output on the Linux deployment host.
4. Verify deploy/ Compose and Dockerfile on Linux with Docker. Docker and Zeek executables are currently unavailable here. Site-specific traffic, hardware, permission and pilot remain external inputs. Do not call deployment or model quality production-ready based on unit tests.

See PRODUCTION_TARGET.md for acceptance criteria and CONTINUATION_REVIEW.md for historical and corrected evaluation limitations.
