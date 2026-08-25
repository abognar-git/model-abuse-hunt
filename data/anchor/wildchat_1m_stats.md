# WildChat behavioural anchor

Generated 2026-08-08T07:11:30Z from `allenai/WildChat-1M` (revision `latest`),
first **40,000** conversations -> **9,698**
pseudo-accounts grouped on `hashed_ip` (**2,883** with
>= 3 sessions).

This anchors the synthetic archetypes' *behavioural* shapes to real ChatGPT
traffic. It does **not** anchor the abuse base rate: the public WildChat release
is toxicity-filtered (toxic fraction here is
**0.0%**), so prevalence comes from ToxicChat, not
this. WildChat also has no payment/phone/ASN and no account-abuse labels, so it
validates input distributions only - never the detector's recall or precision.

## Sessions per account (how much history a real account carries)

mean **4.125**, median **1**, p90 **7**,
p99 **44**, max **795**. The synthetic archetypes draw
2-16 sessions, which sits inside this range.

## Cadence regularity (CV of inter-arrival gaps)

Over 2,883 multi-session accounts: p10 **0.395**, median
**1.024**, p90 **2.107**. A near-machine cadence (CV < 0.25) shows
up in **6.0%** of accounts - the real
counterpart of the `hn_automation` CI/cron archetype, and evidence that regular
cadence alone is common and benign.

## Topic breadth and country switching

- Multi-topic accounts: **20.1%** (mean breadth
  1.247 topics) - real accounts routinely span topics, so topic breadth
  is a weak abuse signal on its own.
- Country switching mid-history: **0.0%** of
  multi-session accounts. Grouping on `hashed_ip` makes this near-zero by
  construction (GeoIP is essentially one country per IP), so the
  `hn_traveler` archetype is *not* validated by this linkage and remains a
  synthetic hypothesis about stolen-key drift.

## Refusal baseline

Any-refusal accounts: **3.3%** (mean per-account
refusal rate **0.5%**) - a real baseline for `refusal_farming`,
so an occasional refusal is not itself suspicious.

## What the regex reads real prompts as

| category | conversations |
|---|---|
| `benign_code` | 37762 |
| `exploit_help` | 909 |
| `creative_writing` | 494 |
| `translation` | 370 |
| `malware_dev` | 235 |
| `recon` | 223 |
| `phishing_content` | 4 |
| `spam_content` | 3 |

<sub>Dataset: [WildChat](https://huggingface.co/datasets/allenai/WildChat-1M)
(Zhao et al., 2024), AI2 ImpACT licence. Raw streamed into `data/anchor/raw/`
(gitignored); only this report and `wildchat_stats.json` are committed.</sub>
