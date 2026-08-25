#!/usr/bin/env python3
"""Measure two things the static fixture could not: the false-accusation rate
at scale, and the cost of an imperfect topic classifier.

Loads a generated population (scripts/generate_population.py), then scores every
account TWICE with the real scorer:

  predicted  - using the regex classifier's label, src/classify.py (what a
               platform sees)
  oracle     - using the ground-truth intent topic (what the fixture assumed
               for free)

Everything else (infrastructure, cadence, victim fixation, refusals) is
identical between the two runs, so the delta isolates the topic-label channel -
the 0.22 capability + 0.06 content weights this project flagged as its softest
input.

Reports, for each run:
  - confusion matrix at the shipped LEAD_THRESHOLD
  - false-accusation rate (innocents queued) with a Wilson 95% interval
  - recall on actors, precision of the lead queue
  - a threshold sweep (operating-point curve)

Reuses src.prevalence.wilson rather than restating interval maths.

Usage:
    python scripts/experiment.py                     # reads data/exp
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def _confusion(scored: dict, truth: dict, thr: float) -> dict:
    tp = fp = tn = fn = 0
    for aid, s in scored.items():
        lead = s["risk_score"] >= thr
        actor = truth[aid]
        if actor and lead:
            tp += 1
        elif actor and not lead:
            fn += 1
        elif not actor and lead:
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _rates(c: dict, wilson) -> dict:
    innocents = c["fp"] + c["tn"]
    actors = c["tp"] + c["fn"]
    fpr = c["fp"] / innocents if innocents else 0.0
    lo, hi = wilson(c["fp"], innocents) if innocents else (0.0, 0.0)
    recall = c["tp"] / actors if actors else 0.0
    precision = c["tp"] / (c["tp"] + c["fp"]) if (c["tp"] + c["fp"]) else 0.0
    return {"fpr": fpr, "fpr_lo": lo, "fpr_hi": hi, "recall": recall,
            "precision": precision, "innocents": innocents, "actors": actors}


def _score_run(signals, accounts, sessions_by_acct, *, oracle: bool) -> dict:
    out = {}
    for aid, acc in accounts.items():
        sess = sessions_by_acct.get(aid, [])
        if oracle:
            sess = copy.deepcopy(sess)
            for s in sess:
                s["category"] = s.get("category_true", s["category"])
        out[aid] = signals.score_account(acc, sess)
    return out


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exp", default=str(ROOT / "data" / "exp"))
    p.add_argument("--table", action="store_true",
                   help="print the README's finding #27 table from the "
                        "committed population and exit (emitted, not typed)")
    args = p.parse_args()

    # The scorer is imported as shipped, never forked;
    # scripts/check_scorer_unmodified.py holds that line.
    from src import signals
    from src.prevalence import wilson
    thr = signals.LEAD_THRESHOLD

    exp = Path(args.exp)
    missing = [n for n in ("accounts.jsonl", "sessions.jsonl",
                           "ground_truth.jsonl") if not (exp / n).exists()]
    if missing:
        raise SystemExit(f"no population in {exp} (missing {', '.join(missing)}); "
                         "run python -m scripts.generate_population first")
    accounts = {a["account_id"]: a for a in _load(exp / "accounts.jsonl")}
    truth_rows = _load(exp / "ground_truth.jsonl")
    truth = {t["account_id"]: t["is_actor"] for t in truth_rows}
    arch = {t["account_id"]: t["archetype"] for t in truth_rows}
    sessions_by_acct: dict[str, list] = {}
    all_sess = _load(exp / "sessions.jsonl")
    for s in all_sess:
        sessions_by_acct.setdefault(s["account_id"], []).append(s)

    agree = sum(1 for s in all_sess if s["category"] == s.get("category_true"))
    n_actor = sum(1 for v in truth.values() if v)

    pred = _score_run(signals, accounts, sessions_by_acct, oracle=False)
    orac = _score_run(signals, accounts, sessions_by_acct, oracle=True)

    cp = _confusion(pred, truth, thr)
    co = _confusion(orac, truth, thr)
    rp = _rates(cp, wilson)
    ro = _rates(co, wilson)

    if args.table:
        # The README's finding #27 table, derived rather than transcribed —
        # the adaptive table drifted once by being hand-copied
        # (make_figures --table exists for the same reason), and this one is
        # not allowed to repeat that. The caption names the seed the committed
        # population was generated with; the reproduce block pins it.
        print("| (seed 7) | oracle labels | real classifier |")
        print("|---|---|---|")
        print(f"| recall (actors caught) | {100*ro['recall']:.0f}% "
              f"({co['tp']}/{ro['actors']}) | **{100*rp['recall']:.0f}% "
              f"({cp['tp']}/{rp['actors']})** |")
        print(f"| false-accusation rate | {100*ro['fpr']:.0f}% | "
              f"**{100*rp['fpr']:.0f}%** |")
        print(f"| queue precision | {100*ro['precision']:.0f}% | "
              f"**{100*rp['precision']:.0f}%** |")
        return

    L: list[str] = []
    L.append("# label-cost research run\n")
    L.append(f"Population: **{len(accounts)} accounts**, **{n_actor} actors** "
             f"(prevalence {100*n_actor/len(accounts):.1f}%), "
             f"**{len(all_sess)} sessions**.\n")
    L.append(f"Classifier agreement with ground-truth topic: "
             f"**{agree}/{len(all_sess)} ({100*agree/len(all_sess):.1f}%)**. "
             f"Lead threshold: {thr}.\n")

    def block(title, c, r):
        return (f"\n## {title}\n\n"
                f"| metric | value |\n|---|---|\n"
                f"| leads (queued) | {c['tp']+c['fp']} |\n"
                f"| true positives (actors caught) | {c['tp']}/{r['actors']} "
                f"(recall {100*r['recall']:.0f}%) |\n"
                f"| false accusations (innocents queued) | {c['fp']}/{r['innocents']} |\n"
                f"| false-accusation rate | {100*r['fpr']:.2f}% "
                f"(95% CI {100*r['fpr_lo']:.2f}-{100*r['fpr_hi']:.2f}%) |\n"
                f"| queue precision (PPV) | {100*r['precision']:.0f}% |\n")

    L.append(block("Scored on the real classifier's labels (what a platform sees)", cp, rp))
    L.append(block("Scored on oracle labels (what the fixture assumed)", co, ro))

    L.append("\n## The cost of an imperfect classifier\n")
    L.append(f"- Recall: oracle {100*ro['recall']:.0f}% -> predicted {100*rp['recall']:.0f}% "
             f"({100*(rp['recall']-ro['recall']):+.0f} pts)\n")
    L.append(f"- False-accusation rate: oracle {100*ro['fpr']:.2f}% -> "
             f"predicted {100*rp['fpr']:.2f}% ({100*(rp['fpr']-ro['fpr']):+.2f} pts)\n")
    L.append(f"- Queue precision: oracle {100*ro['precision']:.0f}% -> "
             f"predicted {100*rp['precision']:.0f}%\n")

    # Where the errors live, by archetype (predicted-label run, shipped threshold)
    from collections import Counter
    fp_by = Counter(); fn_by = Counter(); total_by = Counter()
    for aid, s in pred.items():
        total_by[arch[aid]] += 1
        lead = s["risk_score"] >= thr
        if truth[aid] and not lead:
            fn_by[arch[aid]] += 1
        elif not truth[aid] and lead:
            fp_by[arch[aid]] += 1
    L.append("\n## Where the errors live (predicted labels, threshold "
             f"{thr})\n\n| archetype | count | false accusations | actors missed |\n"
             "|---|---|---|---|\n")
    for a in sorted(total_by):
        L.append(f"| {a} | {total_by[a]} | {fp_by.get(a,0)} | {fn_by.get(a,0)} |\n")

    L.append("\n## Threshold sweep (predicted labels)\n\n")
    L.append("| threshold | leads | actors caught | innocents queued | FPR |\n|---|---|---|---|---|\n")
    t = 0.15
    while t <= 0.601:
        c = _confusion(pred, truth, round(t, 2))
        r = _rates(c, wilson)
        L.append(f"| {t:.2f} | {c['tp']+c['fp']} | {c['tp']}/{r['actors']} | "
                 f"{c['fp']}/{r['innocents']} | {100*r['fpr']:.2f}% |\n")
        t += 0.05

    report = "".join(L)
    (exp / "report.md").write_text(report)
    print(report)
    print(f"\nwrote {exp/'report.md'}")


if __name__ == "__main__":
    main()
