"""What 23 accounts can and cannot license: base rates and intervals.

Every headline number in this repo is a count over a small dataset reported as a
bare fraction - 0/14 false accusations, 9/9 malicious enforced, 36/840 inputs in
the enforce region. Bare fractions invite two errors, and this repo committed
both in its own README before this module existed.

**Error one: a point estimate read as a rate.** "0 of 14" is not a
false-accusation rate of zero. It is an observation consistent with any true rate
small enough to plausibly produce no events in fourteen draws - and with fourteen
draws, that includes rates as high as one in five. The Wilson interval and the
rule of three both put the 95% upper bound near 0.21. The measured 0 and the
unmeasured 0.21 differ by a factor of infinity in the language of rates and by a
factor of two hundred thousand in the language of wrongly-banned people per
million accounts. A number stated without its interval hides that entire span.

**Error two: a rate read outside its base rate.** The dataset is 9 malicious in
23 accounts - a prevalence of 39%. No platform looks like that. Abuse is rare,
and against a rare event the precision of an enforcement queue is governed by the
false-positive rate multiplied by the enormous benign population, not by the
recall everyone quotes. At a prevalence of 1 in 1,000, a false-accusation rate of
0.1% - a hundred times better than this dataset can even bound - still fills half
the queue with innocent people.

So this module takes the pipeline's own committed results and asks what they
actually support:

  1. the operating point, recomputed from `ground_truth.jsonl` + `findings.jsonl`
     rather than transcribed (the lesson this project already learned once, when a
     hand-typed table drifted from its artifact);
  2. Wilson score intervals on every rate, plus the rule of three where the
     numerator is zero;
  3. the precision of the enforce queue projected across plausible platform
     prevalences, evaluated at the point estimate AND at the interval bounds -
     because the gap between those two curves is the honest width of the claim;
  4. how large a clean benign sample would have to be before the README's
     sentence is licensed at all.

Nothing here calls a model and nothing here is sampled. It is arithmetic over
results already in the repo, which is why it can be run by anyone, offline, and
why it cannot drift from the numbers it critiques.

A note on what this does NOT undercut. Finding #7 enumerates the enforcement
policy over its whole input space and shows the enforce region is exactly
`{likely, very likely, almost certain} x recommend_enforcement x corroborated`.
That is a proof about the *policy*, and it stands: no enumeration, no sampling,
no interval. What it does not establish - and what this module measures - is how
often a legitimate account produces an input tuple that lands in that region.
"4.3% of the grid" is a fact about the grid. It is not a false-accusation rate,
and the two must never be read as the same quantity.

Usage:  python -m src.prevalence
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"

Z95 = 1.959963985            # standard normal quantile for a 95% two-sided interval

# Plausible platform-wide prevalences of abusive accounts. The dataset's own 0.39
# is included as the left anchor precisely to show how far outside reality it is.
PREVALENCE_GRID = [0.39, 0.10, 0.01, 0.001, 0.0001]

# The population the projections are stated over. A round million keeps the
# arithmetic legible; nothing depends on the exact figure.
PLATFORM_SCALE = 1_000_000

# The false-accusation rate a reader would probably assume on seeing "0 of 14".
# Used only to report the sample size that would license it.
TARGET_FPR = 0.0001


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Chosen over the textbook normal approximation because that one degenerates
    to the zero-width interval [0, 0] at k=0 - which is exactly the case this
    module exists to talk about, and exactly the case where a zero-width
    interval is the most misleading thing you could print.
    """
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z / denom) * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return (max(0.0, center - half), min(1.0, center + half))


def rule_of_three(n: int) -> float:
    """95% upper bound on an event rate after n trials with zero events.

    The closed form 3/n. Reported alongside Wilson because it is the version a
    reader can check in their head, and because agreement between an exact-ish
    interval and a back-of-envelope one is worth showing rather than asserting.
    """
    return 3.0 / n if n else 1.0


def required_clean_n(target: float = TARGET_FPR) -> int:
    """Benign accounts that must all be correctly cleared before the rule of
    three bounds the false-accusation rate below `target`."""
    return int(-(-3.0 // target)) if target > 0 else 0


def ppv(prevalence: float, tpr: float, fpr: float) -> float:
    """Precision of the enforcement queue: of the accounts recommended for
    enforcement, the fraction that are genuinely abusive.

    This is the number that decides whether a human reviewer is adjudicating or
    rubber-stamping, and it is the number no confusion matrix on a balanced
    dataset ever shows you.
    """
    tp = prevalence * tpr
    fp = (1 - prevalence) * fpr
    return tp / (tp + fp) if (tp + fp) > 0 else float("nan")


def breakeven_fpr(prevalence: float, tpr: float) -> float:
    """The false-accusation rate at which the enforce queue is exactly half
    innocent. Below this the queue is mostly real actors; above it, mostly not."""
    return prevalence * tpr / (1 - prevalence) if prevalence < 1 else float("inf")


def operating_point() -> dict:
    """Recompute the confusion matrix from the committed artifacts.

    Derived, never transcribed. The Phase B table in this repo drifted from its
    artifact once because a human typed it; every count below is read from
    `ground_truth.jsonl` and `findings.jsonl` at run time so the same thing
    cannot happen here.
    """
    gt = {json.loads(l)["account_id"]: json.loads(l)
          for l in open(DATA / "ground_truth.jsonl")}
    findings = [json.loads(l) for l in open(DATA / "findings.jsonl")]

    enforced = set()
    for f in findings:
        if f.get("enforcement_decision") == "enforce":
            enforced.update(f["subject_ids"])

    mal = [a for a in gt if gt[a]["label"] == "malicious"]
    ben = [a for a in gt if gt[a]["label"] == "benign"]
    tp = sum(1 for a in mal if a in enforced)
    fp = sum(1 for a in ben if a in enforced)
    return {
        "n_malicious": len(mal),
        "n_benign": len(ben),
        "n_hard_negatives": sum(1 for a in ben if gt[a].get("persona")),
        "true_positives": tp,
        "false_negatives": len(mal) - tp,
        "false_positives": fp,
        "true_negatives": len(ben) - fp,
        "dataset_prevalence": len(mal) / len(gt),
    }


def analyse() -> dict:
    """The operating point, its intervals, and the projections that follow."""
    op = operating_point()
    tpr_lo, tpr_hi = wilson(op["true_positives"], op["n_malicious"])
    fpr_lo, fpr_hi = wilson(op["false_positives"], op["n_benign"])
    tpr_hat = op["true_positives"] / op["n_malicious"]
    fpr_hat = op["false_positives"] / op["n_benign"]

    projections = []
    for prev in PREVALENCE_GRID:
        benign_pop = (1 - prev) * PLATFORM_SCALE
        projections.append({
            "prevalence": prev,
            "ppv_point": ppv(prev, tpr_hat, fpr_hat),
            "ppv_worst": ppv(prev, tpr_lo, fpr_hi),
            "false_accusations_worst": benign_pop * fpr_hi,
            "breakeven_fpr": breakeven_fpr(prev, tpr_hat),
        })

    return {
        "operating_point": op,
        "tpr": {"point": tpr_hat, "lo": tpr_lo, "hi": tpr_hi},
        "fpr": {"point": fpr_hat, "lo": fpr_lo, "hi": fpr_hi,
                "rule_of_three": rule_of_three(op["n_benign"])},
        "projections": projections,
        "required_clean_n": required_clean_n(),
        "target_fpr": TARGET_FPR,
        "platform_scale": PLATFORM_SCALE,
    }


def render(a: dict) -> str:
    """Markdown, so the result can be read in a terminal or pasted into a doc."""
    op, fpr, tpr = a["operating_point"], a["fpr"], a["tpr"]
    L = []
    add = L.append
    add("# What the false-accusation number licenses\n")
    add(f"Operating point, recomputed from the committed artifacts: "
        f"**{op['true_positives']}/{op['n_malicious']}** malicious accounts "
        f"reached an enforce decision, **{op['false_positives']}/"
        f"{op['n_benign']}** benign accounts did "
        f"({op['n_hard_negatives']} of them content-overlapping hard "
        f"negatives). Dataset prevalence "
        f"**{op['dataset_prevalence']:.0%}**.\n")

    add("| Rate | Observed | 95% interval | Read as |")
    add("|---|---|---|---|")
    add(f"| Enforce given malicious (recall) | {op['true_positives']}/"
        f"{op['n_malicious']} = {tpr['point']:.2f} | "
        f"[{tpr['lo']:.2f}, {tpr['hi']:.2f}] | "
        f"as low as {tpr['lo']:.0%} |")
    add(f"| **Enforce given benign (false accusation)** | "
        f"**{op['false_positives']}/{op['n_benign']} = {fpr['point']:.2f}** | "
        f"**[{fpr['lo']:.2f}, {fpr['hi']:.2f}]** | "
        f"**as high as {fpr['hi']:.0%}** |")
    add(f"\nRule of three cross-check on the zero: 3/{op['n_benign']} = "
        f"**{fpr['rule_of_three']:.3f}**, against Wilson's "
        f"{fpr['hi']:.3f}. Two derivations, same answer - the zero is "
        f"compatible with a true rate near one in five.\n")

    add(f"## Precision of the enforce queue, per {a['platform_scale']:,} "
        f"accounts\n")
    add("At the point estimate the queue is perfect, because the point estimate "
        "of the false-accusation rate is exactly zero and zero times any "
        "population is zero. At the upper bound of the same measurement it is "
        "almost entirely innocent people. Both columns come from the identical "
        "23-account run; the span between them is the width of what was "
        "actually established.\n")
    add("| Platform prevalence | Precision at point estimate | Precision at "
        "interval bound | Wrongly enforced at bound | FPR needed for a "
        "half-innocent queue |")
    add("|---|---|---|---|---|")
    for p in a["projections"]:
        note = " (this dataset)" if abs(p["prevalence"]
                                        - op["dataset_prevalence"]) < 0.02 else ""
        add(f"| {p['prevalence']:.2%}{note} | {p['ppv_point']:.1%} | "
            f"{p['ppv_worst']:.2%} | {p['false_accusations_worst']:,.0f} | "
            f"{p['breakeven_fpr']:.4%} |")

    worst = a["projections"][-2]         # the 0.1% row: the realistic anchor
    add(f"\nThe row to read is **{worst['prevalence']:.1%} prevalence**. To keep "
        f"the enforcement queue merely half-innocent there, the false-accusation "
        f"rate must sit below **{worst['breakeven_fpr']:.4%}** - roughly "
        f"{fpr['hi'] / worst['breakeven_fpr']:.0f} times tighter than "
        f"{op['n_benign']} benign accounts can bound it.\n")

    add(f"## What would license the claim\n")
    add(f"To bound the false-accusation rate below {a['target_fpr']:.2%} at 95% "
        f"confidence, the rule of three requires **{a['required_clean_n']:,} "
        f"benign accounts** to be correctly cleared with zero enforcements. "
        f"This dataset has {op['n_benign']} - about "
        f"**{a['required_clean_n'] / op['n_benign']:,.0f}x** short. That is not "
        f"a flaw in the pipeline; it is the sample size the sentence needs, and "
        f"it is why the sentence now carries an interval.\n")

    add("## Why this strengthens the design rather than the numbers\n")
    add("The arithmetic above is the case for the policy layer's first rule. If "
        "abuse were common and detection nearly perfect, an automatic "
        "enforcement path would be defensible on the numbers. Under a realistic "
        "base rate it is not, and no achievable improvement in the model makes "
        "it so: the false-positive term is multiplied by a population three "
        "orders of magnitude larger than the true-positive term, so the queue's "
        "composition is set by the benign population's error rate, not by "
        "recall. **A human gate is not a courtesy the design extends. It is "
        "what the base rate requires** - and the property worth quoting from "
        "this repo is the enumerated one (no automatic adverse action, none on "
        "content alone), not the sampled one.")
    return "\n".join(L) + "\n"


def readme_table(a: dict) -> str:
    """Emit the README's condensed table from the artifact rather than have a
    human retype it.

    This repo has already paid once for a hand-transcribed table drifting from
    the run it described (see the Phase B note in the limitations). The rule
    that came out of it - emit, do not type - applies here too, so the block
    below is generated and pasted rather than composed by hand.
    """
    rows = ["| Platform prevalence | Precision at the point estimate | "
            "Precision at the interval bound | False-accusation rate needed "
            "for a half-innocent queue |", "|---|---|---|---|"]
    for p in a["projections"]:
        if p["prevalence"] == 0.10:                  # omitted from the README
            continue
        label = f"{p['prevalence']:.0%}" if p["prevalence"] >= 0.01 \
            else f"{p['prevalence']:.2%}".rstrip("%").rstrip("0") + "%"
        if abs(p["prevalence"] - a["operating_point"]["dataset_prevalence"]) < 0.02:
            label += " *(this dataset)*"
        bold = p["prevalence"] == 0.001              # the realistic anchor
        cells = [label, f"{p['ppv_point']:.0%}", f"{p['ppv_worst']:.2%}",
                 f"{p['breakeven_fpr']:.3%}"]
        if bold:
            cells = [f"**{c}**" for c in cells]
        rows.append("| " + " | ".join(cells) + " |")
    return "\n".join(rows) + "\n"


def main(write: bool = True) -> dict:
    a = analyse()
    out = render(a)
    print(out)
    if write:
        (DATA / "prevalence.json").write_text(json.dumps(a, indent=2) + "\n")
        (DATA / "prevalence.md").write_text(out)
        print(f"wrote {DATA / 'prevalence.json'} and {DATA / 'prevalence.md'}")
    return a


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--no-write", action="store_true",
                   help="print the analysis without updating data/")
    p.add_argument("--readme-table", action="store_true",
                   help="emit the README's condensed table from the artifact")
    args = p.parse_args()
    if args.readme_table:
        print(readme_table(analyse()), end="")
    else:
        main(write=not args.no_write)
