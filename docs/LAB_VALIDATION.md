# Local lab validation milestone

Recorded 16 September 2026. Preserve the existing application, data, models, and historical results. The user has no office traffic access and plans Ubuntu alongside Windows on the same PC. No OS installation, partition changes, or live capture has been performed by this plan.

## What the milestone establishes

A reproducible Linux installation and evidence that recorded packets can reach Zeek, the durable collector, the API, and the dashboard. Report model detection quality separately from delivery correctness. Passing the lab milestone permits describing a lab-validated deployment candidate; it does not establish office readiness or authorize model promotion.

## Ordered work

1. Preserve the Windows project before installation: source including uncommitted files, config, documentation, experiment reports, datasets and their manifests, model bundles, and an online SQLite backup. Keep an independently verified copy on external storage. The existing backup on the same disk is not protection against repartitioning. Recreate the Python environment on Linux rather than copying the Windows virtual environment. Check hardware, free space, disk layout, encryption/recovery availability, and backup destination before preparing any installation instructions that change partitions.
2. After Ubuntu is available, record OS, Docker/Compose and Zeek versions and hardware. Use separate lab data directories, database, collector spool, credentials, and model paths. Keep the Windows demo and historical artifacts intact. Inspect deploy/README.md before using its deployment candidate; it publishes HTTPS on the host, so restrict the lab endpoint to the intended local interface/network before startup.
3. Select a small legally usable recorded PCAP with documented origin, SHA-256, capture boundaries, labels if available, and expected traffic. Keep it separate from final evaluation data. Process the recording offline with Zeek; this requires no office access and no packet injection. Preserve the exact sensor configuration, output logs, and command/version record. A capture's existence is not evidence that its labels are reliable.
4. Reconcile actual Zeek fields with collectors.py: duration, packet/byte counters, direction, missing values, protocol and connection state. Compare representative records against source packets and record discrepancies. Do not equate CICFlowMeter counters with Zeek payload counters without evidence. Fix confirmed mapping defects before larger replay experiments.
5. Feed those logs through the collector into a separate lab API. Record inputs, parsing exclusions, queued events, acknowledgments, duplicates and stored events. Exercise restart, API outage, retained-log rotation, stale health and backup/restore using the existing verification tools plus actual Zeek output. Constructed fixtures remain simulated. Recorded real traffic retains its provenance and is identified as replay evidence in the report, never as an office pilot.
6. Validate deploy/ container build, model startup guards, TLS/authentication, persistence and recovery. An existing unapproved real-data candidate may be used only in an isolated engineering test, clearly identified as unsuitable for operational detection. Do not promote it to the active dashboard or relax the synthetic-model guard to claim readiness.
7. Measure a declared replay-rate sweep on this hardware, recording input rate, accepted/stored rate, latency, queue growth, CPU, RAM and disk growth. State the achieved rate and duration; without site measurements do not claim twice an office's peak capacity. Repeat traffic can test transport throughput but is not independent detection evidence; stable event IDs may also make naive repeated-log runs deduplication tests.
8. Investigate false alerts and botnet/C&C misses using development data. Predeclare per-attack, false-alert, abstention and attribution gates before selecting a new final holdout. Keep fitting, calibration and final captures separate and audit duplicate vectors. Additional home-device captures are optional and require actual permission and visibility; never assume all collected traffic is benign.

## Evidence to retain

For each run save software/model/data hashes, configuration without secrets, commands, hardware, timestamps, counts, exclusions, measured resource use, failures and limitations. Preserve original packets/logs according to their access and retention constraints. Keep synthetic fixtures, recorded captures and future live observations identifiable.

## Deferred office acceptance

Network segment coverage, mirror configuration, packet loss under real site load, representative benign activity, actionable incidents per day, analyst review time and the 14-day pilot require an authorized deployment later. Lab results must not be substituted for these gates. Dual boot also means monitoring stops when Ubuntu is not running.
