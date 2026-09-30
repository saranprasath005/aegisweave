# AegisWeave: five-minute prototype demonstration

## Start on this Windows PC

Double-click START_PROTOTYPE.cmd in the project folder. Wait for the browser to open at http://127.0.0.1:8775. No Linux, Docker, internet access or office traffic is required for this prepared demonstration. The existing Python environment and model must remain in the project folder.

The launcher creates a separate database with 200 synthetic flows under var/prototype, leaving the research database and models intact. Opening it again reuses the running presentation. After a reboot, launch it again to create a fresh demonstration. The server runs in the background; closing the browser does not stop it. Do not move or delete the project before the demonstration.

## Opening statement — 30 seconds

“AegisWeave is a working research prototype for machine-learning-based network intrusion detection. It combines flow classification, anomaly detection and behavioral analysis to help an analyst investigate suspicious activity. Today I am demonstrating the complete application using synthetic network-flow records. Response actions are simulated; this is not a live office deployment.”

## Demonstration — four minutes

1. **Overview:** explain the decision counts and risk summary. These are results for the displayed demonstration records, not a real network's threat statistics.
2. **Live events:** open a malicious event, preferably DoS. Show measured flow properties, the decision, risk reasoning and ML explanation. Explain that evidence comes from several models rather than one class label.
3. **Uncertainty:** filter for anomalous events and open one. Explain that unusual behavior can be flagged without claiming a known attack type. If that category is empty, use Replay demo once and select an available example; do not describe an absent result.
4. **Incidents:** show how related events are grouped for investigation instead of requiring review of every flow independently.
5. **Response:** optionally request Block source on an attributed malicious event and provide “Presentation: simulated response workflow”. Show pending approval, approve if offered, then roll back. Policy can deny actions based on evidence; do not promise every selected event is eligible. No network blocking occurs.
6. **System health / ML analytics:** show model provenance, audit evidence and system status. Explain that this dashboard's active model was trained on synthetic data.

Use the on-screen Replay demo button if you want to demonstrate new events entering the system. It generates synthetic input. Pause automatic refresh while explaining a particular screen if it helps.

## Closing statement — 30 seconds

“The working contribution is the integrated detection and investigation pipeline: telemetry ingestion, multiple ML signals, explanations, incident grouping and an auditable response workflow. We have also evaluated real research datasets separately. The next milestones are improving cross-network detection and false alarms, verifying Linux/Docker deployment, and testing recorded packet captures through Zeek. Office effectiveness still requires a future authorized pilot.”

## Questions you may receive

**Is this just a screen mockup?** No. The Python backend runs inference, stores events and incidents, serves the dashboard, and enforces simulated-response policy. The demonstration input is synthetic.

**What is the accuracy?** There is no single validated production accuracy. The corrected CICIDS2017 reduced-counter baseline reached 99.15% aggregate attack recall on Friday but missed all 736 botnet flows; it is not the live dashboard model. Corrected IoT-23 evaluations also showed transfer and false-alert problems. These findings are why no real-data candidate was promoted.

**Have you used real data?** Yes: the corrected IoT-23 run processed approximately 1.2 million records and the corrected CICIDS2017 corpus contains approximately 2.1 million staged records. They are separate experiments, not evidence that one deployed model learned all those records or generalizes to an office.

**Does it stop attacks?** It currently simulates response requests, approval, expiry and rollback. It does not alter firewalls or isolate devices.

**Is it production-ready?** No. It is a working prototype with tested software behavior; model quality, deployment, live capture and operational acceptance remain open.

**What is novel?** Describe the proposed combination of evidence, explicit uncertain attribution and controlled response. Do not claim a globally novel algorithm or superiority without a literature comparison and independent benchmarks.

## Before the meeting

- Start and rehearse once on the actual presentation PC, then keep it awake and plugged in.
- Open the dashboard before screen sharing; keep logs, credentials and unrelated applications off screen.
- Keep this guide available. If the browser disconnects, rerun START_PROTOTYPE.cmd; if startup fails, inspect the newest var/prototype directory's server.log.
- Historical test counts are software checks, not detection accuracy. See MODEL_REVIEW_CONTEXT_V2.md and CIC2017_BASELINE_REVIEW.md for measured research results.
