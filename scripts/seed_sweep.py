#!/usr/bin/env python3
"""Back the README's seed-variance claims with a committed artifact.

The README states that across seeds the predicted-label numbers are steady
(recall 62%, false-accusation rate ~15%) while oracle recall is the noisy one,
swinging 62-88% on an eight-actor denominator. That claim should be file-backed,
not asserted: this script regenerates the population for each seed IN MEMORY
(never touching the committed data/exp seed-7 files), scores each twice with the
unmodified scorer - predicted labels, then oracle labels - and writes the
per-seed table to data/exp/seed_sweep.md.

Usage:
    python scripts/seed_sweep.py                 # seeds 0-12, same knobs as the study
    python scripts/seed_sweep.py --seeds 0 99    # any range, inclusive
"""
from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.generate_population import assemble  # noqa: E402


def _confusion(scored: dict, truth: dict, thr: float) -> dict:
    tp = fp = tn = fn = 0
    for aid, s in scored.items():
        lead = s["risk_score"] >= thr
        if truth[aid] and lead:
            tp += 1
        elif truth[aid] and not lead:
            fn += 1
        elif not truth[aid] and lead:
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def run_seed(signals, seed: int, *, n: int, prevalence: float,
             dual_use_frac: float, hard_fraction: float) -> dict:
    accounts, sessions, truth_rows = assemble(
        n=n, prevalence=prevalence, dual_use_frac=dual_use_frac,
        hard_fraction=hard_fraction, seed=seed)
    truth = {t["account_id"]: t["is_actor"] for t in truth_rows}
    by: dict[str, list] = {}
    for s in sessions:
        by.setdefault(s["account_id"], []).append(s)

    def score(oracle: bool) -> dict:
        out = {}
        for acc in accounts:
            sess = by.get(acc["account_id"], [])
            if oracle:
                sess = copy.deepcopy(sess)
                for s in sess:
                    s["category"] = s.get("category_true", s["category"])
            out[acc["account_id"]] = signals.score_account(acc, sess)
        return out

    thr = signals.LEAD_THRESHOLD
    cp = _confusion(score(oracle=False), truth, thr)
    co = _confusion(score(oracle=True), truth, thr)
    actors = cp["tp"] + cp["fn"]
    innocents = cp["fp"] + cp["tn"]
    return {
        "seed": seed,
        "pred_recall": cp["tp"] / actors,
        "pred_fpr": cp["fp"] / innocents,
        "orac_recall": co["tp"] / actors,
        "orac_fpr": co["fp"] / innocents,
        "actors": actors,
        "pred_tp": cp["tp"],
        "orac_tp": co["tp"],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--n", type=int, default=400)
    p.add_argument("--prevalence", type=float, default=0.02)
    p.add_argument("--dual-use-frac", type=float, default=0.12)
    p.add_argument("--hard-fraction", type=float, default=0.35)
    p.add_argument("--seeds", type=int, nargs=2, default=[0, 12],
                   metavar=("FIRST", "LAST"), help="inclusive seed range")
    p.add_argument("--out", default=str(ROOT / "data" / "exp" / "seed_sweep.md"))
    args = p.parse_args()

    # The scorer is imported as shipped, never forked;
    # scripts/check_scorer_unmodified.py holds that line.
    from src import signals

    rows = [run_seed(signals, s, n=args.n, prevalence=args.prevalence,
                     dual_use_frac=args.dual_use_frac,
                     hard_fraction=args.hard_fraction)
            for s in range(args.seeds[0], args.seeds[1] + 1)]

    L = ["# Seed sweep: oracle vs predicted labels across seeds\n\n",
         f"Same knobs as the study (n={args.n}, prevalence={args.prevalence}, "
         f"hard-fraction={args.hard_fraction}), threshold "
         f"{signals.LEAD_THRESHOLD}; only the seed varies. Populations are "
         "regenerated in memory; the committed seed-7 dataset is untouched.\n\n",
         "| seed | predicted recall | predicted FA rate | oracle recall | oracle FA rate | classifier cost (actors) |\n",
         "|---|---|---|---|---|---|\n"]
    for r in rows:
        L.append(f"| {r['seed']} | {100*r['pred_recall']:.0f}% "
                 f"({r['pred_tp']}/{r['actors']}) | {100*r['pred_fpr']:.2f}% | "
                 f"{100*r['orac_recall']:.0f}% ({r['orac_tp']}/{r['actors']}) | "
                 f"{100*r['orac_fpr']:.2f}% | {r['orac_tp'] - r['pred_tp']} |\n")

    pr = sorted(set(round(100 * r["pred_recall"]) for r in rows))
    orr = sorted(set(round(100 * r["orac_recall"]) for r in rows))
    pf = [100 * r["pred_fpr"] for r in rows]
    cost = [r["orac_tp"] - r["pred_tp"] for r in rows]
    L.append(f"\nPredicted recall takes values {pr} across "
             f"{len(rows)} seeds; predicted FA rate spans "
             f"{min(pf):.1f}-{max(pf):.1f}%; oracle recall takes values {orr}; "
             f"the classifier's cost is {min(cost)}-{max(cost)} actors.\n")

    out = Path(args.out)
    text = "".join(L)
    out.write_text(text)
    print(text)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
