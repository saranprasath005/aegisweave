# Corrected CICIDS2017 integration and baseline review

16 September 2026. The corrected dataset was acquired directly from the authors of Liu et al., *Error Prevalence in NIDS datasets*, CNS 2022. It is a separate dataset version from the original CICIDS2017 release.

- Documentation: https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html
- Archive: https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip
- Local acquisition record: `var/datasets/cicids2017-improved/acquisition.json`
- SHA-256: `97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883`
- Five day-specific raw CSV files and separate staging manifests are retained. No source files were overwritten.

## Data preparation

2,099,976 records were staged. No rows failed the required numeric-counter checks in these files. Following the correction authors' documented recommendation, flows with an `Attempted Category` other than -1 were explicitly mapped to benign. This affected 11,979 retained records. Their original label counts and mapping counts remain in each manifest.

The streaming preparation command validates duration/packet/byte counters, records exclusions, keeps capture identities and local hashes, and never invents host chronology. It omits unused columns. It defaults to refusing attempted flows until a policy is explicitly chosen.

```powershell
.\.venv\Scripts\python.exe scripts/acquire_cic2017.py
.\.venv\Scripts\python.exe -m experiments.prepare_cic var/datasets/cicids2017-improved/raw/tuesday.csv --output var/datasets/cicids2017-improved/staged/tuesday --capture-id cic2017-improved-tuesday --download-url https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip --attempted-policy benign
```

Repeat staging for each day, using a new output directory. Existing completed staging folders are never overwritten. Acquisition verifies existing files against the archive on repeat runs. Input and output hashes are local integrity evidence, not independently published author checksums.

## Frozen evaluation protocol

Fit Tuesday and Wednesday only, capped at 200,000 examples per binary class (378,578 fitting rows). Calibrate thresholds strictly above the 99th percentile of Thursday benign scores after excluding vectors present in fitting captures (237,246 calibration rows). Evaluate Friday and Monday without threshold tuning on either test capture.

Models: balanced logistic regression, balanced boosted trees, and benign-only IsolationForest. Fixed ten generic counter transformations are used; no ports, identities, timestamps, or behavior windows are classifier inputs. This is an offline binary benchmark and creates no deployable model artifact.

## Results and decision

Friday has 547,557 rows. Monday has 371,624 benign rows.

| Model | Friday attack recall | Friday benign false-positive rate | Monday benign false-positive rate |
|---|---:|---:|---:|
| Logistic regression | 37.35% | 0.83% | 0.69% |
| Boosted trees | 99.15% | 1.21% | 1.72% |
| Benign IsolationForest | 0.013% | 0.74% | 0.77% |

The boosted model's per-attack results reveal its limitation:

| Friday label | Rows | Flagged | Detection rate |
|---|---:|---:|---:|
| Botnet | 736 | 0 | 0% |
| DDoS | 95,144 | 95,121 | 99.98% |
| Portscan | 159,066 | 157,665 | 99.12% |
| Benign | 292,611 | 3,540 | 1.21% false positives |

Friday also contains 219,532 vectors present in fitting/calibration captures; Monday contains 66,092. Separately reported unseen-vector metrics prevent the aggregate from hiding this overlap. For boosted trees, Friday unseen-vector recall is 97.96% with 1.21% FPR. Monday unseen-vector FPR is 2.04%. The subset changes class composition and is not a matched comparison to all rows.

Decision: retain this as a measured baseline, not an approved detector. Botnet coverage fails, and benign false alert counts are too high to establish office suitability. Zero attack recall/F1 values on Monday mean no attacks were present; false-positive counts/rates are the meaningful measures there.

Reports: `experiments/results/cic2017-baseline-v1.json` and `experiments/results/cic2017-baseline-v1-details.json`. The second run adds per-label reporting with unchanged models, seed and thresholds; threshold equality was checked. Neither report is a live Zeek evaluation, a cross-network office pilot, or evidence that CICFlowMeter byte counters equal Zeek payload counters. These observed test days are development evidence for any future modifications.

The next ML work needs representative benign office traffic, botnet/C&C diversity, and validated feature extraction on the deployment sensor. Adding rows without addressing this coverage gap would not establish production readiness.
