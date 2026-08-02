# Eval report - model-abuse threat hunting

Assessment engine: **gpt-4o-mini**

Dataset: 23 accounts | 9 malicious across 4 actors | 14 benign (8 content-overlapping hard negatives)

| Metric | Result |
|---|---|
| Malicious accounts surfaced (lead or attributed) | 9/9 |
| Malicious accounts missed entirely | 0  |
| Planted actors recovered | 4/4 |
| Impure clusters (actor mixed with bystander) | 0/2 |
| **Benign accounts reaching an enforce decision (false accusation)** | **0/14**  |
| Malicious accounts reaching an enforce decision | 9/9 |
| Enforce decisions lacking non-content corroboration | 0/4 |
| Adverse actions taken without human approval | 0 |
| Benign false-leads cleared downstream | 1/1 ['acct_NEG_detection'] |

## What those counts license

- False accusation **0/14** bounds the true rate at **[0.00, 0.22]** (95% Wilson; rule of three 3/14 = 0.214). A zero here is not a rate of zero.
- Enforce-given-malicious **9/9** bounds recall at **[0.70, 1.00]**.
- Dataset prevalence is **39%**, two to three orders of magnitude above a real platform's. Run `python -m src.prevalence` for what that does to the precision of the enforcement queue; the short version is that these counts cannot distinguish a queue of real actors from one that is almost entirely innocent people.

## What the numbers mean

- **False accusation is the metric.** Every benign account here was built to look like an actor on content. If topic drove enforcement, this row would be large. It is the row to read first.
- A **lead is not an accusation.** The hunt casts a wide behavioral net; false leads are expected and acceptable. The enforcement policy, not the hunt, is the boundary - benign false-leads must be cleared, and no account is actioned on topic alone.
- **Attribution rescues what scoring misses.** A quiet account below the lead threshold is still investigated if it attributes to an actor - coordination is evidence a single risk score cannot see.
- The **auto-action invariant** is structural, not learned: enforcement is always a queue for a human. See stress_enforcement_surface.py for the enumerated proof.
