# Provenance: where the actor archetypes come from

The telemetry in this project is **synthetic**. The *archetypes* are not — each
planted actor is modelled on activity OpenAI has publicly documented in its own
threat reporting, and each design decision in the pipeline has a published
counterpart.

This document exists because "synthetic dataset authored by the person who wrote
the labels" is the weakest claim in the project, and the honest fix is not to
pretend otherwise but to show what the archetypes are grounded in.

**What is grounded:** the behavioral and infrastructure signatures — multi-account
operation, proxy/hosting infrastructure, iterative development across sessions,
workflow automation, VPN access, multilingual generation.

**What is not:** every account id, IP, timestamp and prompt string is invented.
No real account, person, or organisation is represented. Prompt excerpts describe
intent and are deliberately non-operational.

## Sources

| # | Report | Date | URL |
|---|---|---|---|
| S1 | *Disrupting malicious uses of AI: October 2025* — Nimmo, Bumanglag, Flossman, Hartley, Stubbs, Zhang | 2025-10-07 | [page](https://openai.com/global-affairs/disrupting-malicious-uses-of-ai-october-2025/) · [PDF](https://cdn.openai.com/threat-intelligence-reports/7d662b68-952f-4dfd-a2f2-fe55b041cc4a/disrupting-malicious-uses-of-ai-october-2025.pdf) |
| S2 | *PRC-linked influence operations are targeting AI debates in the US* (June 2026 Threat Report) | 2026-06 | [PDF](https://cdn.openai.com/pdf/96b559fa-c165-4575-805d-e636909e2f78/June-2026-Threat-Report.pdf) |
| S3 | *Disrupting malicious uses of AI by state-affiliated threat actors* (first public report) | 2024-02 | [page](https://openai.com/index/disrupting-malicious-uses-of-ai-by-state-affiliated-threat-actors/) |
| S4 | *Disrupting malicious uses of AI: June 2025* | 2025-06 | [page](https://openai.com/global-affairs/disrupting-malicious-uses-of-ai-june-2025/) |

Per S1, OpenAI has disrupted and reported **over 40 networks** since public
threat reporting began in February 2024.

## Datasets used for calibration (finding #27)

The label-cost study anchors two of its synthetic population's inputs to real,
public traffic. These are established resources, used to **calibrate rather than
to train**, and neither is redistributed — raw downloads cache under gitignored
`data/{calibration,anchor}/raw/` directories and only derived statistics are
committed.

| # | Dataset | What it anchors | Licence |
|---|---|---|---|
| D1 | [ToxicChat](https://huggingface.co/datasets/lmsys/toxic-chat) (Lin et al., [EMNLP Findings 2023](https://aclanthology.org/2023.findings-emnlp.311/)) — 10,165 real Vicuna-demo prompts with human toxicity and jailbreak labels | The regex classifier's error rate (93.6% jailbreak under-read) and the real ~2% jailbreak base rate | CC-BY-NC |
| D2 | [WildChat-4.8M](https://huggingface.co/datasets/allenai/WildChat-4.8M) (Zhao et al., [2024](https://arxiv.org/abs/2405.01470)), with [WildChat-1M](https://huggingface.co/datasets/allenai/WildChat-1M) as a cross-check — real ChatGPT conversations with hashed-IP and geo metadata | Behavioural base rates behind the signals: near-machine cadence, topic breadth, refusals | AI2 ImpACT |

What they cannot do is also part of the record: WildChat's public release is
toxicity-filtered, so it cannot anchor the abuse base rate, and it carries no
payment, phone or ASN labels, so it cannot measure the detector's recall or
precision. It validates input distributions only. ToxicChat labels general
toxicity, a broader construct than the security-abuse topics the regex targets,
which is why the study leads with the well-posed jailbreak under-read rather
than recall against the full toxicity label.

## Archetype → published activity

### `capability_dev` — iterative offensive-tooling development
**Grounded in:** S1, case study *"Cyber Operation: Russian-speaking malware
tooling development"* (pp. 6–9).

The published case describes banned accounts developing and refining a
remote-access trojan, credential stealers and detection-evasion features,
attributed to an operator *"managing multiple accounts"* using *"proxy and
ephemeral hosting infrastructure"* (S1 p. 6).

Three specifics drove this project's design directly:

1. **The pattern, not the single request, is the signature.** S1 observes the
   operator *"iterated on the same code across conversations"* — a pattern the
   report calls consistent with ongoing development rather than occasional
   testing (p. 7). That observation is what motivated
   `signals._capability_trajectory`, and it is worth being exact about the gap
   between the motivation and the implementation: **the signal does not measure
   iteration over time.** It reads no timestamp and imposes no order. What it
   actually counts is breadth across distinct offensive stages, which is a
   weaker proxy for the same idea and is topic-derived rather than behavioural.
   That gap is finding #20 in the README, the ordered version that would earn
   the name is `_capability_arc`, and the comparison between them is measured
   and published. This entry therefore grounds the *design intent* in S1, not
   the implementation.
2. **Refusals push actors toward decomposition.** S1 notes the model refused
   direct malicious requests, so the operator elicited *"building-block code"*
   which was *"likely assembled into malicious workflows"* off-platform (p. 6).
   That is exactly the attack `scripts/stress_decomposition.py` measures.
3. **The outputs are dual-use.** S1 states such outputs are *"not inherently
   malicious"* absent the actor's off-platform use (p. 7) — the premise behind
   weighting content at 0.06.

Mapped to: `acct_CD01`, `acct_CD02` (2 accounts, shared hosting ASN, crypto
payment, escalating arc across sessions).

### `lure_factory` — coordinated multi-account content generation
**Grounded in:** S2, the *"Data Center Bandwagon"* and *"Tech and Tariffs"*
clusters.

S2 describes two banned clusters of accounts likely originating in China,
generating social-media content for covert influence operations. The tradecraft
matches this archetype closely: because access from China is not permitted, the
operators *"used VPNs to access our platform"* (S2 p. 3); they prompted in
Simplified Chinese while requesting English- and Chinese-language output; and
they posed as Americans of varied backgrounds. S2 also records that the actors
uploaded a document describing strategies for creating accounts *"designed to
evade platform detection systems"* (p. 3).

Mapped to: `acct_LF01`–`LF05` (5 burners, two shared VPN egress IPs,
multilingual lure generation, unverified identities).

The `acct_NEG_vpncoincidence` decoy exists *because* of this: if real operators
reach the platform through commercial VPNs, then a shared VPN egress is a
signal that legitimate users also carry — so attribution must not merge on it.

### `recon_automation` — programmatic workflow automation at scale
**Grounded in:** S2 (workflow automation) and S1 (*"Cyber Operation: Phish and
Scripts"*, pp. 13–17).

S2 records the influence operators using the model to automate and scale their
workflow, including requesting code to automate logins and manage interactions
across multiple platforms, plus bulk text processing — username extraction, link
prepending, formatting for worksheets (p. 5). S1's *Phish and Scripts* case
covers a Chinese-language cluster seeking help with phishing and malware
campaigns alongside further automation.

Mapped to: `acct_RA01` (18 near-identical API calls on a fixed ~4-minute
interval — the automation cadence signal).

`acct_NEG_sre` is its deliberate twin: identical cadence, benign content.

### `stolen_key` — a legitimate account turned to abuse
**Partially grounded — stated honestly.** S1's malware case documents
credential theft as an actor *objective*: credential stealers, browser
credential and cookie extraction, app-bound decryption scaffolds (pp. 6–7).

The specific scenario modelled here — a legitimate translation-app API key
exfiltrated and then used for bulk spam generation — is a **reasonable
extension** of that documented objective rather than a case OpenAI has published
in this form. It is included because within-account *baseline drift* is a
signal class the other three archetypes cannot exercise, and it is labelled as
an extension rather than a citation.

Mapped to: `acct_SK01` (steady single-country translation baseline, then abrupt
geography + cadence + intent change).

## Pipeline decisions with published counterparts

| This project | Published counterpart |
|---|---|
| Content weighted 0.06, behavior/infra 0.94 | S1 p. 5: an approach focused on *"patterns of threat actor behavior rather than isolated model interactions"* |
| False-accusation rate as the headline metric; 8 hard negatives | S1 p. 4: a meaningful share of activity falls in a *"gray zone"*, and detection must work *"without disrupting the work of everyday users"* |
| `stress_dual_use.py` — identical content, actor vs legitimate twin | S1 p. 4–5: gray-zone prompts (translating text, modifying code) that indicate innocuous activity or abuse depending on context |
| `stress_decomposition.py` — task split so no session is refusable | S1 p. 6: eliciting *"building-block code"* assembled into workflows off-platform |
| `stress_evasion.py` + adaptive adversary | S1 p. 4: a scam network asked the model to strip em-dashes, a discussed AI-usage tell; S1 p. 5 anticipates further *"adversarial adaptations"* |
| `signals._capability_trajectory` — intent only; it measures topic breadth, not an arc (finding #20) | S1 p. 7: iteration on the same code across conversations |
| `signals._burner_infra` | S1 p. 6: multiple accounts plus proxy and ephemeral hosting |
| Enforcement is human-gated, never automatic | S1: accounts are banned following investigation, with findings shared with partners |

The em-dash case (S1 p. 4) deserves emphasis: it is a *published, real* instance
of an actor adapting specifically to defeat a known detection signal. That is
the premise of `scripts/stress_adaptive.py` — and evidence that treating every
deterministic signal as attacker-adaptive is realism, not paranoia.

## What this does and does not license

It lets the project claim its archetypes reflect documented behaviour, and that
its signal design mirrors the methodology the platform operator has publicly
described.

It does **not** license any claim about detection rates, prevalence, or
effectiveness on real traffic. Every number in the README comes from this
synthetic dataset. A real deployment would face vastly greater diversity, and
S1's own framing — that a meaningful share of activity sits in a gray zone — is
the reason the false-accusation metric, not the detection rate, is the headline.
