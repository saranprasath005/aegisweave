# Context-isolated IoT-23 candidate review

Reviewed 16 September 2026. Decision: retain both new artifacts as research candidates; do not promote them to the dashboard or office deployment.

The completed run used 1,204,888 source records across eight captures and took 1,685 seconds (about 28 minutes). Source hashes, exclusions, split details, and full metrics are recorded in `experiments/results/iot23-context-v2.json`. New artifacts are `var/models/iot23-context-v2` and `var/models/iot23-lco-context-v2`. Historical results and the active dashboard artifact remain unchanged.

## Measurements

| Evaluation | Test rows | Binary recall | Binary F1 | Binary false-positive rate |
|---|---:|---:|---:|---:|
| A: interleaved temporal blocks | 107,306 | 98.80% | 0.9915 | 0.72% |
| A: previously unseen flow vectors only | 7,136 | 74.06% | 0.8019 | 7.06% |
| B: attack_attempt withheld from fitting | 107,306 | 96.72% | 0.9826 | 0.21% |
| B: previously unseen flow vectors only | 7,136 | 30.30% | 0.4551 | 1.89% |
| C: whole held-out captures | 11,777 | 100% | 0.9783 | 10.27% |
| C: previously unseen flow vectors only | 9,992 | 100% | 0.9783 | 20.62% |

These binary measurements use tuning-partition thresholds. They are not equivalent to the analyst-facing decision rules or incident workload.

In the serving-path decision sample:

- A: 2.45% of sampled benign flows alerted; 0.70% were classified malicious.
- B: 939 of 940 withheld attack_attempt flows were anomalous, with no invented known attack type; one was normal. This does not rescue the weak unseen-vector binary recall reported separately.
- C: 24.70% of 2,000 sampled benign flows alerted and another 8.20% abstained. All 2,000 sampled attacks were given the wrong known type (`scan`); 24.20% reached malicious.

Reservoir samples were regenerated after eligibility filtering under the corrected pipeline. Sample composition differs from historical runs, so changes in sampled rates must not be attributed solely to isolation or presented as a controlled improvement.

## Interpretation and next work

Partition-local history, watermarks, purged-record exclusions and withheld-class exclusions are now enforced. This fixes the identified context contamination. It does not make interleaved blocks a forward-only or cross-network evaluation. Repeated vectors still dominate protocol A; C exposes substantial transfer and attribution failures.

The existing held-out captures have now been inspected and are development evidence for any subsequent changes. Do not repeatedly tune against them and then claim an untouched final test. Additional independent captures and representative office benign traffic are required for final validation. Dataset-specific port dependence, coverage gaps, and unsupported attack identities need investigation using fitting/calibration data and separately reserved evaluation data.

Software readiness and model readiness remain separate. The new collector and deployment work does not establish acceptable real-network false-alert rates. Neither candidate meets the evidence needed for office deployment.
