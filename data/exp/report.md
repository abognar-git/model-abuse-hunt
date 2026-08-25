# label-cost research run
Population: **400 accounts**, **8 actors** (prevalence 2.0%), **2095 sessions**.
Classifier agreement with ground-truth topic: **1567/2095 (74.8%)**. Lead threshold: 0.25.

## Scored on the real classifier's labels (what a platform sees)

| metric | value |
|---|---|
| leads (queued) | 65 |
| true positives (actors caught) | 5/8 (recall 62%) |
| false accusations (innocents queued) | 60/392 |
| false-accusation rate | 15.31% (95% CI 12.08-19.21%) |
| queue precision (PPV) | 8% |

## Scored on oracle labels (what the fixture assumed)

| metric | value |
|---|---|
| leads (queued) | 98 |
| true positives (actors caught) | 7/8 (recall 88%) |
| false accusations (innocents queued) | 91/392 |
| false-accusation rate | 23.21% (95% CI 19.31-27.64%) |
| queue precision (PPV) | 7% |

## The cost of an imperfect classifier
- Recall: oracle 88% -> predicted 62% (-25 pts)
- False-accusation rate: oracle 23.21% -> predicted 15.31% (-7.91 pts)
- Queue precision: oracle 7% -> predicted 8%

## Where the errors live (predicted labels, threshold 0.25)

| archetype | count | false accusations | actors missed |
|---|---|---|---|
| actor | 5 | 0 | 0 |
| actor_evasive | 3 | 0 | 3 |
| benign | 224 | 2 | 0 |
| dual_use | 31 | 24 | 0 |
| hn_automation | 34 | 34 | 0 |
| hn_mobile | 34 | 0 | 0 |
| hn_researcher | 35 | 0 | 0 |
| hn_traveler | 34 | 0 | 0 |

## Threshold sweep (predicted labels)

| threshold | leads | actors caught | innocents queued | FPR |
|---|---|---|---|---|
| 0.15 | 137 | 5/8 | 132/392 | 33.67% |
| 0.20 | 110 | 5/8 | 105/392 | 26.79% |
| 0.25 | 65 | 5/8 | 60/392 | 15.31% |
| 0.30 | 51 | 5/8 | 46/392 | 11.73% |
| 0.35 | 32 | 5/8 | 27/392 | 6.89% |
| 0.40 | 30 | 5/8 | 25/392 | 6.38% |
| 0.45 | 6 | 5/8 | 1/392 | 0.26% |
| 0.50 | 5 | 5/8 | 0/392 | 0.00% |
| 0.55 | 5 | 5/8 | 0/392 | 0.00% |
| 0.60 | 5 | 5/8 | 0/392 | 0.00% |
