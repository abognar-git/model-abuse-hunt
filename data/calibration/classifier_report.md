# Classifier calibration on ToxicChat

Generated 2026-08-08T17:33:45Z from `lmsys/toxic-chat` (`toxicchat0124`,
revision `latest`), 10165 of 10165
rows. The toxic and jailbreak positives are human-verified, so the prevalences
below reflect the dataset's real distribution rather than an uncertainty-sampled
subset.

The gateway's regex classifier ([`src/classify.py`](../../src/classify.py)) is a
keyword matcher over security-abuse **topics**. ToxicChat labels general
**toxicity** and **jailbreaking**, which are different constructs — so the
overlap below is a characterisation of real behaviour, not an accuracy grade.

## Headline: jailbreak under-read

Of the **204** prompts humans labelled as jailbreak attempts, the
regex reads **191** as benign — a **93.6%
under-read**. Real adversarial prompts routinely phrase around a keyword
classifier: this is the measured, real-world version of the `actor_evasive`
archetype, and it is the number the synthetic population is calibrated to.

## Real prevalence (for base-rate context)

- toxic: **7.3%**
- jailbreak: **2.0%**

The regex fires "offensive" on **1.9%** of real prompts.

## Overlap with human labels (loose characterisation)

Treat these as a lower bound: the regex was never built to catch hate/sexual
toxicity, so its recall against the broad `toxicity` label is expected to be low.

| target | precision | recall | f1 | tp | fp | fn | tn |
|---|---|---|---|---|---|---|---|
| toxicity | 0.1122 | 0.0295 | 0.0467 | 22 | 174 | 724 | 9245 |

(In ToxicChat, jailbreak is a labelled subset of toxicity, so a "toxicity OR
jailbreak" target is identical to toxicity — omitted rather than duplicated.)

## What the regex fires as, on real prompts

| category | count |
|---|---|
| `benign_code` | 9684 |
| `creative_writing` | 225 |
| `exploit_help` | 139 |
| `translation` | 60 |
| `malware_dev` | 33 |
| `recon` | 17 |
| `phishing_content` | 7 |

<sub>Dataset: ToxicChat (Lin et al., 2023), CC-BY-NC. Raw cached under
`data/calibration/raw/` (gitignored); only this report and `confusion.json` are
committed.</sub>
