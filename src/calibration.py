"""Is the confidence honest? Calibration of the ICD-203 bands.

The investigation layer reports confidence in the U.S. intelligence community's
ICD-203 likelihood language - "likely", "very likely", "almost certain" - because
that is the vocabulary an intelligence product is reviewed in. Adopting the
vocabulary invites the standing critique of it: **those words are only
meaningful if they are calibrated.** If everything the model calls "very likely"
turns out to be right 60% of the time, the band is decoration.

Almost no one measures this on their own system, so this module does. For every
account in the dataset it runs a single-account assessment, converts the reported
band into a probability that the subject is malicious, and compares against
ground truth:

  P(malicious) = band_probability              if assessment is malicious_abuse
               = 1 - band_probability          if assessment is likely_benign
               = 0.50                          if insufficient_evidence

Then two standard measures:

  * a RELIABILITY TABLE - per band, the empirical fraction that were truly
    malicious. Perfect calibration means the empirical rate matches the band's
    nominal probability. Systematic excess is overconfidence.
  * the BRIER SCORE - mean squared error of the probability forecasts, which
    rewards being both confident and correct. It is decomposed into
    reliability / resolution / uncertainty so overconfidence and
    non-discrimination can be told apart, because they need different fixes.

Note this deliberately assesses accounts ONE AT A TIME, including the ones the
hunt would never open. That makes it a harder test than the pipeline's real
workload - no coordination evidence, no cluster context - and it is the only way
to get enough labelled points from 23 accounts for a reliability curve to mean
anything.

Caveat stated up front: 23 accounts is a small sample, so per-band cells are
thin. The table reports cell counts so a reader can see which rows are anecdote.

Usage:
    python -m src.calibration --model gpt-4o-mini --reps 3
    python -m src.calibration --models mini --reps 2
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import investigate as inv, ladder
from .hunt import load, score_all

DATA = Path(__file__).resolve().parent.parent / "data"


def p_malicious(assessment: dict) -> float:
    """P(subject is conducting malicious abuse), read straight off the band.

    The band is defined in the system prompt as attaching to exactly that
    proposition, so no inversion by assessment label is needed - and must not be
    applied. An earlier version of this module inverted the band for
    `likely_benign` rows, which produced a spurious 0.38 reliability error that
    was an artifact of an ambiguous schema rather than a miscalibrated model.
    Both the prompt and this function were fixed; see investigate.ICD203.
    """
    return inv.BAND_FLOOR[assessment["confidence_band"]]


def brier_decomposition(forecasts: list[tuple[float, int]]):
    """Brier score plus its reliability / resolution / uncertainty parts.

    reliability  - how far each bucket's forecast sits from its outcome rate
                   (lower is better; this is calibration error)
    resolution   - how much the buckets' outcome rates differ from the base rate
                   (higher is better; this is discriminating power)
    uncertainty  - the base rate's own variance; a property of the dataset
    brier = reliability - resolution + uncertainty
    """
    n = len(forecasts)
    if not n:
        return {}
    base = sum(o for _p, o in forecasts) / n
    brier = sum((p - o) ** 2 for p, o in forecasts) / n
    buckets: dict[float, list[int]] = {}
    for p, o in forecasts:
        buckets.setdefault(round(p, 3), []).append(o)
    reliability = sum(len(os_) * (p - sum(os_) / len(os_)) ** 2
                      for p, os_ in buckets.items()) / n
    resolution = sum(len(os_) * (sum(os_) / len(os_) - base) ** 2
                     for p, os_ in buckets.items()) / n
    return {"brier": brier, "reliability": reliability,
            "resolution": resolution, "uncertainty": base * (1 - base),
            "base_rate": base, "n": n}


def assess_all(model: str, reps: int, rpm: float) -> list[dict]:
    """One single-account assessment per account per rep."""
    gt = {json.loads(l)["account_id"]: json.loads(l)
          for l in open(DATA / "ground_truth.jsonl")}
    accounts, sessions = load()
    scored = score_all(accounts, sessions)
    out = []
    for aid in sorted(accounts):
        packet = inv.build_packet([aid], accounts, sessions, scored, {})
        for rep in range(reps):
            sink = {}
            a = ladder.call_with_retry(
                lambda: (inv.assess_openai(packet, model, rpm, True,
                                           usage_sink=sink), sink),
                model_id=model)
            out.append({
                "account_id": aid, "rep": rep,
                "assessment": a["assessment"],
                "band": a["confidence_band"],
                "p_malicious": p_malicious(a),
                "truth_malicious": int(gt[aid]["label"] == "malicious"),
                "persona": gt[aid].get("persona"),
            })
    return out


def report(rows: list[dict]) -> dict:
    """Reliability table + Brier decomposition + the overconfidence headline."""
    forecasts = [(r["p_malicious"], r["truth_malicious"]) for r in rows]
    decomp = brier_decomposition(forecasts)

    # per-band reliability, ordered weakest -> strongest
    per_band = {}
    for r in rows:
        per_band.setdefault(r["band"], []).append(r)

    lines = ["| band | nominal P | n | empirical P(malicious) | gap |",
             "|---|---|---|---|---|"]
    worst_gap, worst_band = 0.0, None
    for band, _floor in inv.ICD203:
        rs = per_band.get(band)
        if not rs:
            continue
        nominal = inv.BAND_FLOOR[band]
        # empirical rate among rows that USED this band, on the band's own terms:
        # for a malicious_abuse call the band asserts P(malicious)=nominal, so the
        # comparison is against the mean forecast in the cell.
        mean_fc = sum(r["p_malicious"] for r in rs) / len(rs)
        emp = sum(r["truth_malicious"] for r in rs) / len(rs)
        gap = emp - mean_fc
        if abs(gap) > abs(worst_gap):
            worst_gap, worst_band = gap, band
        lines.append(f"| {band} | {nominal:.2f} | {len(rs)} | {emp:.2f} "
                     f"| {gap:+.2f} |")

    return {"table": "\n".join(lines), "decomp": decomp,
            "worst_gap": worst_gap, "worst_band": worst_band}


def run(models_spec, model, reps, rpm):
    models = ladder.resolve(models_spec) if models_spec else [
        ladder.BY_ID.get(model) or ladder.Model(model, model, "unknown", "?")]

    def one(m):
        rows = assess_all(m.id, reps, rpm)
        rep = report(rows)
        return {"rows": rows, "report": rep}

    results = ladder.run_across(models, one) if len(models) > 1 else {
        models[0].id: one(models[0])}

    for mid, res in results.items():
        if "error" in res:
            print(f"\n### {mid}: FAILED - {res['error']}")
            continue
        rep, d = res["report"], res["report"]["decomp"]
        print(f"\n### {mid}  (n={d['n']}, base rate {d['base_rate']:.2f})\n")
        print(rep["table"])
        print(f"\nBrier {d['brier']:.4f} = reliability {d['reliability']:.4f} "
              f"- resolution {d['resolution']:.4f} "
              f"+ uncertainty {d['uncertainty']:.4f}")
        print(f"  reliability (calibration error, lower better): {d['reliability']:.4f}")
        print(f"  resolution  (discrimination, higher better):   {d['resolution']:.4f}")
        if rep["worst_band"]:
            direction = "OVERconfident" if rep["worst_gap"] < 0 else "UNDERconfident"
            print(f"  largest gap: '{rep['worst_band']}' is {direction} "
                  f"by {abs(rep['worst_gap']):.2f}")

    if len(models) > 1:
        rows = {mid: {"brier": f"{r['report']['decomp']['brier']:.3f}",
                      "rel": f"{r['report']['decomp']['reliability']:.3f}",
                      "res": f"{r['report']['decomp']['resolution']:.3f}"}
                for mid, r in results.items() if "error" not in r}
        print("\n" + ladder.results_table(models, rows, [
            ("Brier", "brier"), ("reliability↓", "rel"), ("resolution↑", "res")]))
        print()
        print(ladder.usage_table())

    ladder.save(DATA / "calibration.json",
                {mid: r.get("report", {}).get("decomp", r)
                 for mid, r in results.items()})
    print(f"\nwrote {DATA / 'calibration.json'}")
    return results


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="gpt-4o-mini")
    p.add_argument("--models", default=None, help="ladder spec: all|mini|ids")
    p.add_argument("--reps", type=int, default=1)
    p.add_argument("--rpm", type=float, default=0)
    args = p.parse_args()
    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY not set")
    run(args.models, args.model, args.reps, args.rpm)
