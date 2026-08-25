# WildChat behavioural anchor

Generated 2026-08-08T07:18:05Z from `allenai/WildChat-4.8M` (revision `latest`),
first **40,000** conversations -> **10,293**
pseudo-accounts grouped on `hashed_ip` (**2,993** with
>= 3 sessions).

This anchors the synthetic archetypes' *behavioural* shapes to real ChatGPT
traffic. It does **not** anchor the abuse base rate: the public WildChat release
is toxicity-filtered (toxic fraction here is
**0.0%**), so prevalence comes from ToxicChat, not
this. WildChat also has no payment/phone/ASN and no account-abuse labels, so it
validates input distributions only - never the detector's recall or precision.

## Sessions per account (how much history a real account carries)

mean **3.886**, median **1**, p90 **7**,
p99 **41**, max **781**. The synthetic archetypes draw
2-16 sessions, which sits inside this range.

## Cadence regularity (CV of inter-arrival gaps)

Over 2,993 multi-session accounts: p10 **0.398**, median
**1.012**, p90 **2.06**. A near-machine cadence (CV < 0.25) shows
up in **5.9%** of accounts - the real
counterpart of the `hn_automation` CI/cron archetype, and evidence that regular
cadence alone is common and benign.

## Topic breadth and country switching

- Multi-topic accounts: **18.7%** (mean breadth
  1.23 topics) - real accounts routinely span topics, so topic breadth
  is a weak abuse signal on its own.
- Country switching mid-history: **0.3%** of
  multi-session accounts. Grouping on `hashed_ip` makes this near-zero by
  construction (GeoIP is essentially one country per IP), so the
  `hn_traveler` archetype is *not* validated by this linkage and remains a
  synthetic hypothesis about stolen-key drift.

## Refusal baseline

Any-refusal accounts: **2.9%** (mean per-account
refusal rate **0.5%**) - a real baseline for `refusal_farming`,
so an occasional refusal is not itself suspicious.

## What the regex reads real prompts as

| category | conversations |
|---|---|
| `benign_code` | 38015 |
| `exploit_help` | 860 |
| `translation` | 364 |
| `creative_writing` | 337 |
| `malware_dev` | 232 |
| `recon` | 186 |
| `phishing_content` | 3 |
| `spam_content` | 3 |

<sub>Dataset: [WildChat-4.8M](https://huggingface.co/datasets/allenai/WildChat-4.8M)
(Zhao et al., 2024), AI2 ImpACT licence. Raw streamed into `data/anchor/raw/`
(gitignored); only this report and `wildchat_stats.json` are committed.</sub>
