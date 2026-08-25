# Seed sweep: oracle vs predicted labels across seeds

Same knobs as the study (n=400, prevalence=0.02, hard-fraction=0.35), threshold 0.25; only the seed varies. Populations are regenerated in memory; the committed seed-7 dataset is untouched.

| seed | predicted recall | predicted FA rate | oracle recall | oracle FA rate | classifier cost (actors) |
|---|---|---|---|---|---|
| 0 | 62% (5/8) | 14.80% | 88% (7/8) | 23.21% | 2 |
| 1 | 62% (5/8) | 15.82% | 75% (6/8) | 23.72% | 1 |
| 2 | 62% (5/8) | 15.31% | 75% (6/8) | 24.23% | 1 |
| 3 | 62% (5/8) | 15.05% | 75% (6/8) | 23.98% | 1 |
| 4 | 62% (5/8) | 14.54% | 88% (7/8) | 23.21% | 2 |
| 5 | 62% (5/8) | 15.56% | 75% (6/8) | 24.23% | 1 |
| 6 | 62% (5/8) | 15.05% | 88% (7/8) | 22.96% | 2 |
| 7 | 62% (5/8) | 15.31% | 88% (7/8) | 23.21% | 2 |
| 8 | 62% (5/8) | 14.29% | 88% (7/8) | 22.96% | 2 |
| 9 | 62% (5/8) | 15.82% | 75% (6/8) | 24.23% | 1 |
| 10 | 62% (5/8) | 14.80% | 88% (7/8) | 23.47% | 2 |
| 11 | 62% (5/8) | 16.58% | 62% (5/8) | 23.21% | 0 |
| 12 | 62% (5/8) | 14.54% | 62% (5/8) | 22.70% | 0 |

Predicted recall takes values [62] across 13 seeds; predicted FA rate spans 14.3-16.6%; oracle recall takes values [62, 75, 88]; the classifier's cost is 0-2 actors.
