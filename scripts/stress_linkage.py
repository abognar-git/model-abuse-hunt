#!/usr/bin/env python3
"""Can stylometry or timing close attribution's last gap - and what does it cost?

`stress_decomposition` leaves one honest hole: split a development arc across
burners that share infrastructure *and* topic and attribution reassembles them;
let one burner also change its topic and it slips the link. 5 of 6. The two
obvious channels for closing it are stylometry and timing, and this harness
gives both a fair test instead of an argument.

Four experiments, all offline and deterministic:

  CONTROL  Are the "style" features actually topic-independent? Measured, not
           assumed: mean style similarity for same-category pairs versus
           different-category pairs. If same-category pairs score higher, the
           feature set is reading topic under another name and every result
           downstream is an artifact. This runs FIRST because it decides
           whether the rest means anything.

  EXP-1    Does the channel close the gap? Add it to the linker and count how
           many of the six decomposition burners reassemble.

  EXP-2    What does it cost? Run the same linker on the real 23-account
           dataset and count false merges - a benign account pulled into an
           actor, or two unrelated benign accounts fused. The dataset was built
           for this: the SRE's API cadence deliberately mirrors the recon bot's,
           and the detection engineer's hours mirror the lure factory's.

  EXP-3    Is there ANY admissible operating point? Sweep the threshold and ask
           whether some value closes the gap with zero false merges. A channel
           that can do both is worth having. A channel that cannot is not a
           tuning problem.

Usage:
    python -m scripts.stress_linkage
    python -m scripts.stress_linkage --channel style
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import linkage                                     # noqa: E402
from src.attribute import build_actors                      # noqa: E402
from src.hunt import load                                   # noqa: E402
from scripts.stress_decomposition import build as build_decomposition  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"
SWEEP = [round(0.50 + 0.02 * k, 2) for k in range(26)]      # 0.50 .. 1.00


def ground_truth():
    return {json.loads(l)["account_id"]: json.loads(l)
            for l in open(DATA / "ground_truth.jsonl")}


# ------------------------------------------------------------------- control
def control_topic_independence(accounts, sessions) -> dict:
    """Is style similarity higher within a topic than across topics?

    If it is, the feature set encodes topic and 'linking on style' is just
    'linking on content' wearing a lab coat.
    """
    from collections import Counter

    def dominant(aid):
        cats = [s["category"] for s in sessions.get(aid, [])]
        return Counter(cats).most_common(1)[0][0] if cats else None

    sims = linkage.pairwise("style", accounts, sessions)
    same, diff = [], []
    for (a, b), s in sims.items():
        (same if dominant(a) == dominant(b) else diff).append(s)
    m_same = sum(same) / len(same) if same else 0.0
    m_diff = sum(diff) / len(diff) if diff else 0.0
    return {"same_topic_mean": m_same, "diff_topic_mean": m_diff,
            "gap": m_same - m_diff, "n_same": len(same), "n_diff": len(diff)}


def control_text_volume(accounts, sessions) -> dict:
    """How much text per account is there to attribute authorship from?"""
    counts = {aid: linkage.word_count(sessions.get(aid, [])) for aid in accounts}
    vals = sorted(counts.values())
    return {"min": vals[0], "median": vals[len(vals) // 2], "max": vals[-1],
            "floor": linkage.STYLOMETRY_WORD_FLOOR,
            "short_by": linkage.STYLOMETRY_WORD_FLOOR / max(vals[len(vals) // 2], 1)}


# ------------------------------------------------------------------- exp 1/2
def gap_closed(channel: str, threshold: float) -> int:
    """How many of the six decomposition burners reassemble into one cluster."""
    acc, sess, dec_ids = build_decomposition()
    extra = linkage.make_linker(channel, threshold, acc, sess)
    clusters, _ = build_actors(acc, sess, extra=extra)
    best = 0
    for c in clusters:
        best = max(best, len(set(c) & set(dec_ids)))
    return best


def false_merges(channel: str, threshold: float, accounts, sessions, gt):
    """False merges on the real dataset under this channel.

    Counted as PAIRS, not clusters. One cluster that swallows the whole dataset
    is a single cluster but 14 accused people, and a per-cluster count would
    report it as "1" - the same flattening that would let a total collapse look
    tidier than two specific errors. Two kinds, both accusations: a benign
    account fused with a malicious one, and two unrelated benign accounts fused
    with each other.
    """
    extra = linkage.make_linker(channel, threshold, accounts, sessions)
    clusters, log = build_actors(accounts, sessions, extra=extra)
    detail, pairs = [], 0
    for c in clusters:
        labels = {m: gt[m]["label"] for m in c if m in gt}
        actors = {gt[m].get("actor") for m in c
                  if gt.get(m, {}).get("label") == "malicious"}
        benign = sorted(m for m in c if labels.get(m) == "benign")
        mal = sorted(m for m in c if labels.get(m) == "malicious")
        if benign and mal:
            pairs += len(benign) * len(mal)
            detail.append((benign, sorted(a for a in actors if a), sorted(c)))
        elif len(benign) > 1:
            pairs += len(benign) * (len(benign) - 1) // 2
            detail.append((benign, ["<unrelated people fused>"], sorted(c)))
    return detail, pairs, log


def stagger_control(channel: str, threshold: float) -> int:
    """The same six burners, spread across the working day instead of six
    consecutive minutes.

    The fixture creates them one minute apart, which hands a timing linker a
    perfect match for free. An operator who does not run every burner in one
    sitting is the realistic case, so this asks whether the channel's result
    survives it or was an artifact of how the fixture was written.
    """
    acc, sess, dec_ids = build_decomposition()
    for k, aid in enumerate(dec_ids):
        for s in sess[aid]:
            s["ts"] = f"{s['ts'][:11]}{(7 + k * 3) % 24:02d}{s['ts'][13:]}"
    extra = linkage.make_linker(channel, threshold, acc, sess)
    clusters, _ = build_actors(acc, sess, extra=extra)
    return max((len(set(c) & set(dec_ids)) for c in clusters), default=0)


# --------------------------------------------------------------------- report
def run(channels):
    accounts, sessions = load()
    gt = ground_truth()
    results = {}

    print("=" * 74)
    print("CONTROL - is 'style' topic-independent, and is there enough text?")
    print("=" * 74)
    ctrl = control_topic_independence(accounts, sessions)
    vol = control_text_volume(accounts, sessions)
    print(f"\nmean style similarity, same dominant topic : "
          f"{ctrl['same_topic_mean']:.3f}  (n={ctrl['n_same']})")
    print(f"mean style similarity, different topic     : "
          f"{ctrl['diff_topic_mean']:.3f}  (n={ctrl['n_diff']})")
    print(f"topic leakage into the 'style' features    : {ctrl['gap']:+.3f}")
    verdict = ("CONTAMINATED - these features read topic"
               if ctrl["gap"] > 0.02 else
               "clean - similarity does not track topic")
    print(f"  -> {verdict}")
    print(f"\nwords of prompt text per account: min {vol['min']}, "
          f"median {vol['median']}, max {vol['max']}")
    print(f"authorship-attribution floor (order of): {vol['floor']}")
    print(f"  -> the median account is ~{vol['short_by']:.0f}x under the floor")
    results["control"] = {"topic": ctrl, "volume": vol}

    for ch in channels:
        print("\n" + "=" * 74)
        print(f"CHANNEL: {ch}")
        print("=" * 74)

        # Where do this channel's similarities actually live? A channel whose
        # pairwise scores are all crushed into a narrow band has no resolution
        # to threshold, and no sweep over it can mean anything.
        sims = sorted(linkage.pairwise(ch, accounts, sessions).values())
        lo, med, hi = sims[0], sims[len(sims) // 2], sims[-1]
        print(f"\npairwise similarity across the 23 accounts: "
              f"min {lo:.3f}  median {med:.3f}  max {hi:.3f}")
        if hi - lo < 0.10:
            print(f"  -> NO RESOLUTION: every pair scores within "
                  f"{hi - lo:.3f} of every other. There is nothing to "
                  f"separate; the channel is all-or-nothing.")
        results.setdefault(ch, {})["spread"] = {"min": lo, "median": med,
                                                "max": hi}

        print(f"\nEXP-3  threshold sweep "
              f"(gap closed = 6/6 burners; cost = falsely accused pairs)\n")
        print(f"  {'thresh':<9}{'burners':<10}{'false pairs':<14}admissible?")
        admissible, rows, shown = [], [], 0
        for t in SWEEP:
            n = gap_closed(ch, t)
            detail, pairs, _ = false_merges(ch, t, accounts, sessions, gt)
            ok = n == 6 and pairs == 0
            if ok:
                admissible.append(t)
            rows.append({"threshold": t, "burners": n, "false_pairs": pairs})
            # print transitions and the extremes, not all 26 rows
            prev = rows[-2] if len(rows) > 1 else None
            interesting = (prev is None or t == SWEEP[-1] or ok
                           or prev["burners"] != n
                           or prev["false_pairs"] != pairs)
            if interesting and shown < 12:
                shown += 1
                print(f"  {t:<9.2f}{n}/6{'':<7}{pairs:<14}"
                      f"{'YES' if ok else '.'}")
        results[ch].update({"sweep": rows, "admissible": admissible})

        if admissible:
            print(f"\n  -> ADMISSIBLE at {admissible}: closes the gap at no "
                  f"measured cost.")
        else:
            print(f"\n  -> NO ADMISSIBLE THRESHOLD. Every setting that closes "
                  f"the gap also accuses someone innocent.")

        closing = [t for t in SWEEP if gap_closed(ch, t) == 6]
        if closing:
            t = max(closing)
            detail, pairs, _ = false_merges(ch, t, accounts, sessions, gt)
            print(f"\nEXP-1/2  at the tightest gap-closing threshold {t:.2f}: "
                  f"6/6 burners, {pairs} falsely accused pair(s)")
            for benign, actors, cluster in detail:
                shown_b = benign if len(benign) <= 4 else \
                    benign[:4] + [f"...+{len(benign) - 4} more"]
                print(f"    {shown_b}")
                print(f"      fused with {actors}  "
                      f"(cluster of {len(cluster)})")
            # Only meaningful for a channel that reads timestamps; running it
            # on `style` would print a reassuring 6/6 that means nothing.
            if ch == "time":
                stag = stagger_control(ch, t)
                results[ch]["stagger_burners"] = stag
                print(f"\nCONTROL  same six burners spread across the day "
                      f"instead of six consecutive minutes: "
                      f"{stag}/6 reassembled")
                if stag < 6:
                    print(f"  -> the gap closure was an artifact of the "
                          f"fixture's timing, not a property of the channel. "
                          f"An operator who does not run every burner in one "
                          f"sitting is not caught by this.")
        else:
            print(f"\nEXP-1  no threshold closes the gap at all "
                  f"(max {max(gap_closed(ch, t) for t in SWEEP)}/6 burners)")

    (DATA / "linkage.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"\nwrote {DATA / 'linkage.json'}")
    return results


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--channel", default="all", choices=["all", "style", "time"])
    args = p.parse_args()
    chans = ["style", "time"] if args.channel == "all" else [args.channel]
    run(chans)
