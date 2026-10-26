# Sample telemetry

`sample_telemetry.jsonl` holds twelve synthetic flow records in the exact shape the
API accepts (`aegisweave.schema.Flow`), one JSON object per line. Every record is
marked `"simulated": true`. Nothing here was captured from a real network.

The set is small on purpose — enough to exercise the pipeline end to end and to show
what the evidence model looks like, not a training corpus. For benchmark data see
`aegisweave/datasets.py` and the dataset sources it points at.

## What is in it

| Records | Pattern |
|---|---|
| 0001–0003, 0009, 0011, 0012 | Ordinary client traffic — web, DNS, ICMP |
| 0004–0008 | One host touching five hosts and four ports in ~2 s, every connection failed, SYN ratio 1.0 — a horizontal scan |
| 0010 | A long outbound session sending ~3 MB up against ~41 KB down — an exfiltration-shaped transfer |

Records 0004–0008 are what the behaviour windows are for: no single failed connection
is interesting, and the pattern only exists across them.

## Running it

Start the API (see the README's quick start), then post the batch:

```bash
python - <<'PY'
import json, httpx
flows = [json.loads(line) for line in open("examples/sample_telemetry.jsonl")]
r = httpx.post("http://127.0.0.1:8000/api/telemetry/batch", json=flows, timeout=30)
print(r.status_code, r.text[:400])
PY
```

Then open the dashboard at `http://127.0.0.1:8000/` to see the decisions, the
attribution, and the per-flow explanation for each record.

Validation only, no server needed:

```bash
python -c "
import json
from aegisweave.schema import Flow
for line in open('examples/sample_telemetry.jsonl'):
    Flow.model_validate_json(line)
print('all sample records valid')
"
```
