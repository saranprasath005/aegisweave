# First production target: small office LAN

Decision recorded: 16 September 2026. The user accepted the recommendation to target a single-site small office LAN. Continue the existing AegisWeave application and preserve its models, datasets, and historical results.

Deployment platform confirmed by the user: Linux machine or VM with Docker. See [the deployment candidate](../deploy/README.md); host build/run verification is pending.

Updated user constraints (16 September): no separate Linux machine and no access to office network traffic. The user intends to install Ubuntu alongside Windows on this PC, retaining Windows. Installation has not been performed or verified. The immediate milestone is a deployable, lab-validated candidate using recorded traffic and an isolated lab; office capacity, alert workload, and the observation pilot remain unverified future gates. Office access is not a prerequisite for continuing lab development. See [lab validation plan](LAB_VALIDATION.md).

## Release scope

- Approximately 25–100 devices at one site: workstations, servers, printers, and ordinary office appliances.
- Passive detection and incident review by one part-time administrator. Automated blocking and isolation are outside this first release.
- Zeek flow telemetry from a gateway traffic mirror, with additional internal segment mirrors where available. Gateway visibility alone does not establish coverage of internal device-to-device traffic.
- Existing API, dashboard, incident storage, audit trail, model registry, and explanation pipeline remain the foundation.
- Initial validation in a controlled lab, followed by an authorized office-network observation pilot.

This is an agreed product direction, not a claim of demonstrated capacity or detection reliability. No live capture or network configuration is initiated by this document.

## Sizing and operator targets

Measure average, p95, and peak flows/second, mirrored bandwidth, burst duration, daily event volume, and sensor packet loss at the candidate site. Device count is not a substitute for these measurements. Record capture hardware and application hardware separately.

Provisional engineering acceptance targets, to be refined from site measurements:

| Area | Proposed criterion | Evidence required |
|---|---|---|
| Capacity | Sustain twice the measured peak flow arrival rate for 60 minutes | Load report on the intended hardware, including latency, CPU, RAM, queue growth, and storage growth |
| Visibility | State which segments and traffic directions are covered | Sensor placement map and capture-loss measurements |
| Delivery | No unexplained loss of accepted telemetry; retries must not create duplicate stored events | Reconciliation of input, accepted, rejected, queued, and stored records through restart and outage tests |
| Operator workload | Aim for at most 5–10 actionable incidents/day and roughly 30 minutes/day of routine triage | Pilot incident counts, reviewed usefulness, false alerts, and measured triage time; retain recall evidence so suppression cannot conceal regressions |
| Pilot | At least 14 consecutive days including ordinary work, idle periods, and scheduled maintenance | Daily health, ingestion, incident-review, and resource reports; extend if traffic is not representative |

Flow-level false-positive rates and incident-level workload must be reported separately. Attack recall, wrong-type attribution, abstention, and uncertainty must also be reported. Set numerical detection release gates before examining the final test set, using the site's threat scope and acceptable miss rate; these gates are still pending.

## Delivery sequence and release gates

1. **Independent evaluation pipeline.** Fix the documented temporal-context overlap. Separate fitting, calibration, tuning, and final evaluation by capture/network or construct behavior state independently per partition. Audit duplicate feature vectors and preserve an untouched final test set. Existing published results remain historical.
2. **Representative training data.** Inventory existing corpora, license terms, labels, feature definitions, and provenance. Add compatible office-relevant traffic and independently reviewed local benign samples. Keep synthetic fixtures distinct. Evaluate dataset additions for improvements on held-out environments rather than row-count growth.
3. **Model selection.** Compare existing fusion and simpler baselines under the same protocol. Measure false alerts, per-attack recall, wrong attack attribution, calibration, abstention, and serving cost. Investigate port dependence. Promote only artifacts that meet predeclared gates; preserve the previous model for rollback.
4. **Continuous ingestion.** Extend recorded-log replay into a supervised Zeek collector with checkpointing, rotation handling, durable buffering, bounded retries, duplicate prevention, and visible failure/overflow status. Validate restart and network-outage recovery.
5. **Deployment verification.** Verify container build/run, persistent volumes, service restart, authenticated TLS access, secrets configuration, backup/restore, model rollback, disk exhaustion behavior, and sustained load on the chosen host. Select retention and disk capacity from measured event volume. Replace the synthetic demo artifact for the pilot only after the real-data model passes its release gates.
6. **Observation pilot and release decision.** Run on the authorized target network and review alerts. Use separately authorized controlled exercises for detection validation. Freeze and version evaluation data; do not automatically treat incoming traffic as benign or retrain on it. Record unresolved coverage and reliability limits before release.

## Current evidence and outstanding site inputs

The 14 September continuation review records historical evidence. By 16 September, 164 Python tests and eight collector recovery checks passed; a durable continuous log collector and deployment candidate were implemented. Actual Zeek capture and Linux container execution remain unverified. Corrected evaluations still show substantial cross-network false alerting and incorrect attack attribution, and the separate CIC counter baseline missed all 736 tested botnet flows. These software checks do not establish office-network detection performance. See WORK_CHECKPOINT.md for artifact paths and current evidence.

Before live deployment, obtain the actual gateway/switch mirroring capability, network segments, sensor and server hardware, deployment operating system, measured traffic profile, retention needs, and permission to collect the site's telemetry. Local pipeline and deployment implementation can proceed before those site details are available.

See [continuation review](CONTINUATION_REVIEW.md) for the measured starting state and research limitations.
