"""Extract every number the project report cites from committed results, databases and raw data."""
import collections, glob, json, os, re, sqlite3, statistics, subprocess, sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]  # docs/report/generator -> repository root
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
from aegisweave.behavior import BehaviorEngine
from aegisweave.collectors import read_zeek_tsv, zeek_to_flow
from aegisweave.corpus import iot23_label

R = lambda name: json.load(open(ROOT / "experiments" / "results" / name, encoding="utf-8"))
out = {}

# Synthetic ------------------------------------------------------------------------------------
s = R("synthetic.json")
keep = ("precision", "recall", "f1", "false_positive_rate", "roc_auc", "pr_auc", "samples")
out["synthetic"] = {
    "seed": s["seed"], "test_samples": s["variants"]["full"]["samples"],
    "variants": {k: {m: s["variants"][k][m] for m in keep} for k in ("baseline_logistic", "supervised", "anomaly_only", "temporal_only", "full", "without_temporal", "without_anomaly", "without_profile")},
    "bootstrap": s["paired_episode_bootstrap"],
    "decisions": s["decisions"]["test"]["summary"], "decision_counts": s["decisions"]["test"]["decision_counts"],
    "withheld": s["decisions"]["withheld_unknown"]["decision_counts"]["unknown_beacon"],
    "withheld_ablation": s["decisions"]["ablation_without_class_support"]["withheld_unknown"]["decision_counts"]["unknown_beacon"],
    "ablation_test": s["decisions"]["ablation_without_class_support"]["test"],
    "stress": {k: {m: v[m] for m in ("f1", "recall", "false_positive_rate")} for k, v in s["stress"].items()},
    "latency": {"p50": s["performance"]["single_event_model_and_local_explanation_ms_p50"], "p95": s["performance"]["single_event_model_and_local_explanation_ms_p95"]},
    "protocol_note": s["protocol"]["baseline_selection"],
    "leakage": s["leakage"]["checks"],
}
# Inherited-logic baseline measured before any change (docs/PROJECT_ASSESSMENT.md table)
assessment = (ROOT / "docs" / "PROJECT_ASSESSMENT.md").read_text(encoding="utf-8")
out["inherited"] = {"benign": {"normal": 208, "suspicious": 1, "malicious": 0, "unknown": 377, "n": 586},
                    "beacon": {"suspicious": 311, "malicious": 26, "n": 337},
                    "source": "docs/PROJECT_ASSESSMENT.md", "verified_in_doc": "| benign (test) | 208 | 1 | 0 | **377** |" in assessment}

c = R("confirmation.json")
out["confirmation"] = {"seed": c["seed"], "binary": {m: c["binary_score"][m] for m in keep}, "decisions": c["decisions"]["summary"],
                       "withheld": c["withheld_unknown"]["decision_counts"]["unknown_beacon"], "warning": c["warning"]}

# UNSW-NB15 ------------------------------------------------------------------------------------
u = R("unsw.json")
out["unsw"] = {
    "rows": {"train": u["provenance"]["train"]["rows"], "test": u["provenance"]["test"]["rows"]},
    "training_sample": u["protocol"]["seeded_training_sample"], "features": u["protocol"]["features"],
    "overlap": u["leakage"]["test_rows_matching_any_designated_train_normalized_vector"], "unseen": u["leakage"]["test_rows_without_train_feature_overlap"],
    "all": {k: {m: u["official_test_all_rows"][k][m] for m in keep} for k in u["official_test_all_rows"]},
    "unseen_metrics": {k: {m: u["test_without_train_feature_overlap"][k][m] for m in keep} for k in u["test_without_train_feature_overlap"]},
    "macro_f1": u["supervised_multiclass_official_test"]["macro avg"]["f1-score"], "weighted_f1": u["supervised_multiclass_official_test"]["weighted avg"]["f1-score"],
    "open_set": {k: u["open_set_attribution"][k] for k in ("withheld_families", "withheld_family_test_rows", "known_attack_family_test_rows", "benign_test_rows")},
}

# IoT-23 ----------------------------------------------------------------------------------------
d = R("iot23.json")
out["iot23"] = {"corpus": d["corpus"], "protocol": d["protocol"], "warning": d["warning"], "dataset": d["dataset"], "experiments": {}}
for name, e in d["experiments"].items():
    out["iot23"]["experiments"][name] = {
        "partitions": {p: v["class_counts"] for p, v in e["split"]["partitions"].items()},
        "seen": e["split"]["test_rows_with_flow_vector_seen_in_fitting_partitions"], "unseen": e["split"]["test_rows_unseen"],
        "coverage_gaps": e["split"]["coverage_gaps"], "excluded_rare": e["split"]["excluded_rare_classes"],
        "binary": {m: e["binary_all_test_rows"][m] for m in keep}, "confusion": e["binary_all_test_rows"]["confusion_matrix"],
        "unseen_binary": {m: e["binary_unseen_flow_vectors"][m] for m in keep} if "binary_unseen_flow_vectors" in e else None,
        "single_layers": {k: {m: v[m] for m in ("f1", "false_positive_rate")} for k, v in e["single_layers"].items()},
        "fusion_variants": {k: {m: v[m] for m in ("f1", "false_positive_rate")} for k, v in e["fusion_variants"].items()},
        "per_capture": e["per_capture"], "decisions": e["decisions"]["summary"], "decision_counts": e["decisions"]["decision_counts"],
        "attributed_as": {k: v["attributed_as"] for k, v in e["decisions"]["per_label"].items()},
        "latency": e["decisions"]["latency_ms"], "fit_seconds": e["fit_seconds"],
        "ablation": e["ablation_without_class_support"]["decision_counts"] if "ablation_without_class_support" in e else None,
    }
# Decisions before the unverifiable-attribution fix, from the committed pre-fix result file.
prefix = json.loads(subprocess.run(["git", "show", "fc48844:experiments/results/iot23.json"], capture_output=True, text=True, cwd=ROOT, encoding="utf-8").stdout)
pc = prefix["experiments"]["C_leave_capture_out"]["decisions"]
out["iot23"]["prefix_C"] = {"commit": "fc48844", "benign_malicious": pc["decision_counts"]["normal"]["malicious"],
                            "benign_dos_label": pc["per_label"]["normal"]["attributed_as"].get("dos", 0)}
model = json.load(open(ROOT / "var" / "models" / "iot23" / "manifest.json", encoding="utf-8"))["metadata"]
out["iot23"]["feature_importance_A"] = model["feature_importance"][:5]

# Out-of-order arrival per capture (raw logs) and reordering effect --------------------------------
lateness = {}
for path in sorted(glob.glob(str(ROOT / "var/datasets/iot23/*.labeled")), key=os.path.getsize):
    watermark, n, late, beyond = float("-inf"), 0, 0, 0
    for record in read_zeek_tsv(path):
        n += 1
        lag = watermark - record["ts"]
        late += lag > 0
        beyond += lag > 300
        watermark = max(watermark, record["ts"])
    lateness[Path(path).name.split(".")[0]] = {"records": n, "late": late / n, "beyond_300s": beyond / n}
out["lateness"] = lateness
reorder = {}
for name in ("CTU-IoT-Malware-Capture-34-1", "CTU-Honeypot-Capture-5-1"):
    flows = []
    for record in read_zeek_tsv(ROOT / f"var/datasets/iot23/{name}.conn.log.labeled"):
        try:
            flows.append(zeek_to_flow(record, name))
        except ValueError:
            pass
    reorder[name] = {}
    for tolerance in (0, 300):
        engine = BehaviorEngine(max_lateness=tolerance)
        contexts = [engine.observe(f) for f in flows]
        reorder[name][str(tolerance)] = {"available": sum(c["available"] for c in contexts) / len(contexts),
                                         "isolated": sum(c["late_event"] for c in contexts) / len(contexts), "flows": len(flows)}
out["reordering"] = reorder

# Live replay scoring (labels joined back only for evaluation) -----------------------------------
truth = {}
for capture, sensor in (("CTU-Honeypot-Capture-5-1", "honeypot-5-1"), ("CTU-IoT-Malware-Capture-8-1", "capture-8-1")):
    for record in read_zeek_tsv(ROOT / f"var/datasets/iot23/{capture}.conn.log.labeled"):
        truth[zeek_to_flow(record, sensor).event_id] = (sensor, iot23_label(record))

def replay(db_path):
    db = sqlite3.connect(db_path)
    counts = collections.defaultdict(collections.Counter)
    labels = collections.defaultdict(collections.Counter)
    for event_id, decision, label in db.execute("SELECT id, decision, class FROM events"):
        sensor, true = truth[event_id]
        counts[f"{sensor}|{true}"][decision] += 1
        labels[f"{sensor}|{true}"][label] += 1
    rows = db.execute("SELECT received_at, inference_ms FROM events WHERE sensor_id='capture-8-1' ORDER BY received_at").fetchall()
    t = [datetime.fromisoformat(r[0]).timestamp() for r in rows]
    inf = [r[1] for r in rows]
    def rate(q):
        i = int(q * (len(t) - 1)); j = min(len(t) - 1, i + 200)
        return (t[j] - t[i]) / (j - i) * 1000
    incident = db.execute("SELECT MAX(n) FROM (SELECT COUNT(*) n FROM incident_events GROUP BY incident_id)").fetchone()[0]
    return {"counts": {k: dict(v) for k, v in counts.items()}, "labels": {k: dict(v) for k, v in labels.items()},
            "events": sum(sum(v.values()) for v in counts.values()), "span_8_1_s": t[-1] - t[0], "inference_total_s": sum(inf) / 1000,
            "ms_per_event": {"start": rate(0), "middle": rate(.5), "end": rate(.98)}, "mean_inference_ms": statistics.mean(inf),
            "largest_incident": incident}
out["live_replay"] = {"after_fix": replay(ROOT / "var/iot23-unseen.db"), "before_fix": replay(ROOT / "var/iot23-unseen-demo.db")}

# Verification and tests --------------------------------------------------------------------------
latest = sorted(glob.glob(str(ROOT / "var/verify/*/report.json")))[-1]
report = json.load(open(latest, encoding="utf-8"))
out["verification"] = {"checks": report["checks"], "failed": report["failed"], "seconds": report["seconds"],
                       "stages": sorted({r["stage"] for r in report["results"]}, key=lambda s: int(s.split()[0]))}
collected = subprocess.run([str(ROOT / ".venv/Scripts/python.exe"), "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "-o", "addopts="],
                           capture_output=True, text=True, cwd=ROOT).stdout
out["tests"] = {"collected": int(re.search(r"(\d+) tests? collected", collected).group(1)),
                "files": sorted({line.split("::")[0] for line in collected.splitlines() if "::" in line})}
out["git"] = subprocess.run(["git", "log", "--oneline"], capture_output=True, text=True, cwd=ROOT).stdout.strip().splitlines()
out["environment"] = {"python": sys.version.split()[0], "platform": d["performance"]["platform"]}

target = Path(__file__).with_name("report_data.json")
target.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
print("wrote", target, "| tests", out["tests"]["collected"], "| verification", out["verification"]["checks"], "failed", out["verification"]["failed"],
      "| replay events", out["live_replay"]["after_fix"]["events"], "| inherited doc verified", out["inherited"]["verified_in_doc"])
