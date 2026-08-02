# What the false-accusation number licenses

Operating point, recomputed from the committed artifacts: **9/9** malicious accounts reached an enforce decision, **0/14** benign accounts did (8 of them content-overlapping hard negatives). Dataset prevalence **39%**.

| Rate | Observed | 95% interval | Read as |
|---|---|---|---|
| Enforce given malicious (recall) | 9/9 = 1.00 | [0.70, 1.00] | as low as 70% |
| **Enforce given benign (false accusation)** | **0/14 = 0.00** | **[0.00, 0.22]** | **as high as 22%** |

Rule of three cross-check on the zero: 3/14 = **0.214**, against Wilson's 0.215. Two derivations, same answer - the zero is compatible with a true rate near one in five.

## Precision of the enforce queue, per 1,000,000 accounts

At the point estimate the queue is perfect, because the point estimate of the false-accusation rate is exactly zero and zero times any population is zero. At the upper bound of the same measurement it is almost entirely innocent people. Both columns come from the identical 23-account run; the span between them is the width of what was actually established.

| Platform prevalence | Precision at point estimate | Precision at interval bound | Wrongly enforced at bound | FPR needed for a half-innocent queue |
|---|---|---|---|---|
| 39.00% (this dataset) | 100.0% | 67.54% | 131,340 | 63.9344% |
| 10.00% | 100.0% | 26.56% | 193,780 | 11.1111% |
| 1.00% | 100.0% | 3.18% | 213,158 | 1.0101% |
| 0.10% | 100.0% | 0.32% | 215,095 | 0.1001% |
| 0.01% | 100.0% | 0.03% | 215,289 | 0.0100% |

The row to read is **0.1% prevalence**. To keep the enforcement queue merely half-innocent there, the false-accusation rate must sit below **0.1001%** - roughly 215 times tighter than 14 benign accounts can bound it.

## What would license the claim

To bound the false-accusation rate below 0.01% at 95% confidence, the rule of three requires **30,000 benign accounts** to be correctly cleared with zero enforcements. This dataset has 14 - about **2,143x** short. That is not a flaw in the pipeline; it is the sample size the sentence needs, and it is why the sentence now carries an interval.

## Why this strengthens the design rather than the numbers

The arithmetic above is the case for the policy layer's first rule. If abuse were common and detection nearly perfect, an automatic enforcement path would be defensible on the numbers. Under a realistic base rate it is not, and no achievable improvement in the model makes it so: the false-positive term is multiplied by a population three orders of magnitude larger than the true-positive term, so the queue's composition is set by the benign population's error rate, not by recall. **A human gate is not a courtesy the design extends. It is what the base rate requires** - and the property worth quoting from this repo is the enumerated one (no automatic adverse action, none on content alone), not the sampled one.
