"""Evaluate a frozen saved model on fresh synthetic draws without refitting/tuning."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from threadpoolctl import threadpool_limits

from aegisweave.demo import generate_episodes
from aegisweave.ml import (ModelBundle, check_split_isolation, create_splits,
                           episodes_to_matrix, evaluate_bundle, evaluate_decisions)


@threadpool_limits.wrap(limits=1)
def run_confirmation(model_path: Path, output: Path, seed=381947):
    model = ModelBundle.load(model_path)
    # Identity and thresholds are captured BEFORE drawing any confirmation rows.
    frozen = {"id": model.metadata["id"], "version": model.metadata["version"],
              "training_fingerprint": model.metadata.get("training_fingerprint"),
              "artifact_sha256": model.artifact_sha256, "thresholds": dict(model.thresholds)}
    confirmation = episodes_to_matrix(generate_episodes(80, seed=seed))
    unknown = episodes_to_matrix(generate_episodes(40, seed=seed + 1, unknown=True))
    prior = create_splits(seed=model.metadata["provenance"]["seed"])
    isolation = check_split_isolation({**prior, "confirmation": confirmation, "confirmation_unknown": unknown})
    report = {"experiment": "Frozen-model fresh synthetic draws", "simulated": True,
              "generated_at": datetime.now(timezone.utc).isoformat(), "seed": seed,
              "frozen_model": frozen, "refitting": False, "threshold_selection": False,
              "warning": "Fresh draws from the same hand-designed generator after implementation fixes. This is not independent public or real-world validation, and was not preregistered.",
              "leakage": isolation, "binary_score": evaluate_bundle(model, confirmation),
              "decisions": evaluate_decisions(model, confirmation),
              "withheld_unknown": evaluate_decisions(model, unknown)}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=Path("var/models/active"))
    parser.add_argument("--output", type=Path, default=Path("experiments/results/confirmation.json"))
    parser.add_argument("--seed", type=int, default=381947)
    args = parser.parse_args()
    result = run_confirmation(args.model, args.output, args.seed)
    print(json.dumps({"output": str(args.output), "frozen_model": result["frozen_model"],
                      "binary_score": {key: result["binary_score"][key] for key in ("f1", "false_positive_rate", "recall")},
                      "decisions": result["decisions"]["summary"],
                      "withheld_unknown": result["withheld_unknown"]["per_label"].get("unknown_beacon")}, indent=2))


if __name__ == "__main__":
    main()
