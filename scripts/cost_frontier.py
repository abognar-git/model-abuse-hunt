#!/usr/bin/env python3
"""What does it cost to disappear? The detection-vs-spend frontier.

`stress_evasion.py` showed that a determined actor sheds behavioral signals one
countermeasure at a time and the risk score falls. That is a true observation
stated as a weakness. This module states it as **economics**, which is the more
useful frame: detection is not a wall an attacker either clears or does not, it
is a **toll**. The question a defender should ask is not "can this be evaded" -
everything can - but "what does evasion cost, and does the price scale with the
attacker's ambition?"

Method, fully offline and deterministic (no model, no API): enumerate every
subset of available countermeasures, apply it to each planted actor, recompute
the behavioral risk score, and price the basket. Then extract the Pareto
frontier - for each achievable risk level, the cheapest basket that reaches it -
and report the price of crossing below the lead threshold, which is the point at
which the hunt stops opening the account at all.

Three properties fall out of the measurement, and the third was a surprise that
contradicted this module's first draft:

  * Some signals are FREE to shed. Jittering cadence and not probing refusal
    boundaries cost nothing but patience and discipline. Any signal an attacker
    can drop for $0 is not a control, it is a convenience for catching the
    careless.
  * Identity and infrastructure are CHEAP to shed - two figures of dollars per
    account for a clean residential ASN, a verified card and a phone number.
    An actor whose only exposure is infrastructure buys its way out.
  * But some signals cannot be bought off AT ANY PRICE in this action space, and
    they are the ones tied to what the operation *is* rather than how it is
    provisioned:
      - shared VICTIMS plus a shared behavioral profile. The lure factory's five
        accounts stay linked no matter how much separate infrastructure they buy,
        because they keep targeting the same brands in the same way. To break the
        link it would have to stop attacking the same victims - i.e. abandon the
        operation.
      - BASELINE DRIFT. The stolen-key account is betrayed by its own history:
        the divergence is measured against its past, and the past is not for
        sale.
    This is the useful reframing. Money buys anonymity; it does not buy a
    different objective or a different history.

Prices are ILLUSTRATIVE, order-of-magnitude figures for commodity proxy,
virtual-card and SMS-verification services. They are not quotes, and nothing
here depends on their absolute values - the claim is ordinal (which evasions are
cheap, which are dear, and how cost scales with scale).

Usage:
    python -m scripts.cost_frontier
    python -m scripts.cost_frontier --actor lure_factory
"""
from __future__ import annotations

import argparse
import copy
import itertools
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import signals                                        # noqa: E402
from src.attribute import build_actors                          # noqa: E402
from src.hunt import load, score_all                            # noqa: E402
# Prices and mutations are imported so this module and the adaptive adversary can
# never disagree about what a purchase costs or what it buys.
from scripts.stress_adaptive import (PRICES, _apply_purchases,   # noqa: E402
                                     spend_total)

COUNTERMEASURES = list(PRICES)


def _actor_accounts():
    """Map actor id -> its account ids, from ground truth."""
    gt = [json.loads(l) for l in open(
        Path(__file__).resolve().parent.parent / "data" / "ground_truth.jsonl")]
    out: dict[str, list[str]] = {}
    for r in gt:
        if r["label"] == "malicious":
            out.setdefault(r["actor"], []).append(r["account_id"])
    return {k: sorted(v) for k, v in out.items()}


def evaluate_basket(acct_ids, purchases, acc_base, sess_base):
    """Risk + attribution outcome for one actor under one basket of purchases."""
    accounts = [copy.deepcopy(acc_base[a]) for a in acct_ids]
    sessions = []
    for a in acct_ids:
        sessions += copy.deepcopy(sess_base.get(a, []))
    accounts, sessions = _apply_purchases(accounts, sessions, set(purchases))

    acc = dict(acc_base)
    sess = {k: list(v) for k, v in sess_base.items()}
    for a in accounts:
        acc[a["account_id"]] = a
    by: dict[str, list] = {}
    for s in sessions:
        by.setdefault(s["account_id"], []).append(s)
    for aid, sl in by.items():
        sess[aid] = sl

    scored = score_all(acc, sess)
    max_risk = max(scored[a]["risk_score"] for a in acct_ids)
    any_lead = any(scored[a]["is_lead"] for a in acct_ids)
    clusters, _ = build_actors(acc, sess)
    still_clustered = any(len(set(acct_ids) & set(c)) > 1 for c in clusters)
    # The account is opened by the pipeline if it is a lead OR it attributes to a
    # multi-account actor. Evasion means neither.
    surfaced = any_lead or still_clustered
    return {"max_risk": round(max_risk, 4), "any_lead": any_lead,
            "still_clustered": still_clustered, "surfaced": surfaced,
            "spend": spend_total(set(purchases), len(acct_ids))}


def frontier(rows):
    """Pareto frontier: cheapest basket achieving each risk level or better."""
    best = {}
    for r in sorted(rows, key=lambda x: (x["spend"], x["max_risk"])):
        key = r["max_risk"]
        if key not in best or r["spend"] < best[key]["spend"]:
            best[key] = r
    out, cheapest_so_far = [], float("inf")
    for risk in sorted(best):
        r = best[risk]
        if r["spend"] < cheapest_so_far:
            out.append(r)
            cheapest_so_far = r["spend"]
    return sorted(out, key=lambda r: r["spend"])


def run(only_actor=None):
    acc_base, sess_base = load()
    actors = _actor_accounts()
    if only_actor:
        actors = {k: v for k, v in actors.items() if k == only_actor}

    print(f"lead threshold = {signals.LEAD_THRESHOLD}\n")
    print("countermeasure prices (illustrative, USD):")
    for c, p in PRICES.items():
        per = " per account" if c == "split_infrastructure" else ""
        print(f"  {c:<24} ${p:>6.2f}{per}")
    print()

    summary = {}
    for actor, accts in actors.items():
        rows = []
        for n in range(len(COUNTERMEASURES) + 1):
            for combo in itertools.combinations(COUNTERMEASURES, n):
                rows.append({**evaluate_basket(accts, combo, acc_base, sess_base),
                             "purchases": list(combo)})

        base = next(r for r in rows if not r["purchases"])
        escaped = [r for r in rows if not r["surfaced"]]
        cheapest_escape = min(escaped, key=lambda r: r["spend"]) if escaped else None
        free = [r for r in rows if r["spend"] == 0]
        best_free = min(free, key=lambda r: r["max_risk"])

        print(f"### {actor}  ({len(accts)} account(s))")
        print(f"  baseline risk {base['max_risk']:.3f}  "
              f"(lead={base['any_lead']}, clustered={base['still_clustered']})")
        print(f"  best FREE risk reduction: {base['max_risk']:.3f} -> "
              f"{best_free['max_risk']:.3f} using "
              f"{', '.join(best_free['purchases']) or 'nothing'}")
        if cheapest_escape:
            print(f"  cheapest full evasion (never opened): "
                  f"${cheapest_escape['spend']:.2f} via "
                  f"{', '.join(cheapest_escape['purchases'])}")
        else:
            print("  no basket in this action space fully evaded")
        print("  Pareto frontier (spend -> risk):")
        for r in frontier(rows):
            flag = "  <- below lead line" if not r["any_lead"] else ""
            opened = "" if r["surfaced"] else "  <- NEVER OPENED"
            print(f"    ${r['spend']:>8.2f}  risk {r['max_risk']:.3f}"
                  f"{flag}{opened}")
        print()
        # Why an actor could not evade: which signals survived every basket?
        unbuyable = None
        if not cheapest_escape:
            all_bought = min(rows, key=lambda r: r["max_risk"])
            unbuyable = ("still attributed to a cluster (shared victims + shared "
                         "behavior)" if all_bought["still_clustered"]
                         else f"risk floor {all_bought['max_risk']:.3f} stays above "
                              f"the {signals.LEAD_THRESHOLD} lead line")
        summary[actor] = {
            "accounts": len(accts), "baseline_risk": base["max_risk"],
            "cheapest_escape_usd": cheapest_escape["spend"] if cheapest_escape else None,
            "cheapest_escape_via": cheapest_escape["purchases"] if cheapest_escape else None,
            "best_free_risk": best_free["max_risk"],
            "unbuyable_reason": unbuyable,
        }

    print("What money can and cannot buy:")
    buyable = {k: v for k, v in summary.items()
               if v["cheapest_escape_usd"] is not None}
    unbuyable = {k: v for k, v in summary.items()
                 if v["cheapest_escape_usd"] is None}
    for actor, s in sorted(buyable.items(), key=lambda kv: kv[1]["cheapest_escape_usd"]):
        print(f"  BOUGHT OUT   {actor:<20} {s['accounts']} acct(s)  "
              f"${s['cheapest_escape_usd']:>7.2f} via "
              f"{', '.join(s['cheapest_escape_via'])}")
    for actor, s in unbuyable.items():
        print(f"  UNBUYABLE    {actor:<20} {s['accounts']} acct(s)  "
              f"{s['unbuyable_reason']}")

    print("\nRead the split, not the totals. Where an actor's exposure is only its")
    print("infrastructure, evasion costs two figures and the control merely")
    print("inconveniences it. Where the exposure is the operation itself - the same")
    print("victims attacked the same way, or an account diverging from its own")
    print("history - no basket in this action space evades at any price, because")
    print("what would have to change is the objective, not the plumbing.")
    print("\nCaveat: this is an action space of six countermeasures against four")
    print("actors. A countermeasure not modelled here (rotating victims, aging")
    print("accounts before use, splitting one operation across unrelated brands)")
    print("would move these numbers. The frontier bounds what THESE purchases buy.")

    out = Path(__file__).resolve().parent.parent / "data" / "cost_frontier.json"
    out.write_text(json.dumps(summary, indent=2))
    print(f"\nwrote {out}")
    return summary


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--actor", default=None)
    args = p.parse_args()
    run(args.actor)
