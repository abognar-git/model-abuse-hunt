"""Finding #25: the linking rules point both ways.

`scripts/cost_frontier.py` prices what it costs an actor to disappear. Finding
#19 established the other half of the asymmetry: a bystander who has been
falsely merged into an actor's cluster *cannot get out*, because `coordination`
is not a fact you can produce a document against. Both leave a question
unasked, and it is the one an adversary would ask first:

**Can I choose who gets merged?**

Not "will an innocent account be swept up by accident" - `stress_attribution.py`
already measures that, and the VPN decoy survives it. This is deliberate: an
attacker who wants a specific researcher, competitor or journalist taken off the
platform, and who shapes their OWN account until the attribution layer ties the
two together. Every input required is on the attacker's side of the boundary.

The mechanism is `attribute._link_reason`, which merges on either:
  (a) a shared `target:` token plus at least one corroborating weak token, or
  (b) three weak tokens including at least one infrastructure and one behavioral.

A behavioral token is emitted ONLY for a distinctive (offensive/recon) dominant
category - the guard added after `stress_attribution.py` EXP-1 found that
counting `benign_code` merged two strangers behind one VPN. That guard is load
bearing here in a way nobody intended: it means an account is *linkable* exactly
when its dominant activity is offensive or recon.

Which is the finding. The accounts that can be framed under rule (b) are
precisely the accounts this project exists to protect - the penetration tester,
the detection engineer, the security trainer, the CTF player, the journalist
running reconnaissance. Their legitimate work emits the one token that makes
them attachable. The ordinary background user, whose dominant category is
`benign_code` or `translation`, cannot be framed this way at all: there is no
behavioral token to match, so rule (b) can never be satisfied against them.

Protection here is inversely proportional to how much your job looks like the
thing being hunted.

Costs reuse `stress_adaptive.PRICES` rather than inventing a second price list,
so a framing attack and an evasion attack are quoted in the same currency and
can be compared. Fully offline and deterministic; no model is called.

Usage:
    python -m scripts.stress_framing
    python -m scripts.stress_framing --readme-table
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.stress_adaptive import PRICES
from src import signals
from src.attribute import _link_reason, build_actors, tokens
from src.hunt import load, score_all
from src.investigate import assess_mock, build_packet
from src.policy import apply_enforcement_policy

DATA = Path(__file__).resolve().parent.parent / "data"

# What each forged token costs the attacker, in the adaptive harness's currency.
# An attacker shaping their OWN account pays for infrastructure and identity;
# matching a victim's TOPIC is free, because it is just a matter of what you
# choose to ask the model about.
TOKEN_COSTS = {
    "ip": PRICES["split_infrastructure"],   # a proxy on the victim's egress
    "asn": PRICES["clean_asn"],             # a host in the victim's ASN
    "cat": 0.0,                             # free: ask about the same topic
    "pay": PRICES["verified_payment"],
    "target": 0.0,                          # free: name the same org
}


def _cost(toks) -> float:
    return round(sum(TOKEN_COSTS.get(t.split(":", 1)[0], 0.0) for t in toks), 2)


def forgeable_tokens(victim_tokens: set[str]) -> set[str]:
    """Which of a victim's tokens an attacker can reproduce on their own
    account. All of them, in principle - an IP, an ASN, a payment class, a
    topic and a victim-org reference are all things you can choose. That is
    the uncomfortable part: none of the linking evidence is something only the
    real owner could produce."""
    return set(victim_tokens)


def minimal_framing_sets(victim_tokens: set[str]) -> list[dict]:
    """Every minimal token set that would make `_link_reason` merge an attacker
    account into the victim's, priced. Enumerated against the real rule rather
    than reasoned about, so the harness cannot drift from the linker."""
    from itertools import combinations
    forgeable = sorted(forgeable_tokens(victim_tokens))
    out = []
    for size in range(1, min(len(forgeable), 5) + 1):
        for combo in combinations(forgeable, size):
            shared = set(combo)
            reason = _link_reason(shared, strict=True)
            if reason is None:
                continue
            # minimal: no proper subset already works
            if any(set(prev["tokens"]) < shared for prev in out):
                continue
            out.append({"tokens": sorted(shared), "reason": reason,
                        "cost_usd": _cost(shared)})
    return sorted(out, key=lambda x: (x["cost_usd"], len(x["tokens"])))


def analyse() -> dict:
    gt = {json.loads(l)["account_id"]: json.loads(l)
          for l in open(DATA / "ground_truth.jsonl")}
    accounts, sessions = load()
    scored = score_all(accounts, sessions)

    victims = []
    for aid in accounts:
        if gt[aid]["label"] != "benign":
            continue
        vt = tokens(accounts[aid], sessions.get(aid, []))
        sets = minimal_framing_sets(vt)
        dom = None
        cats = [s["category"] for s in sessions.get(aid, [])]
        if cats:
            from collections import Counter
            dom = Counter(cats).most_common(1)[0][0]
        victims.append({
            "account_id": aid,
            "persona": gt[aid].get("persona") or "background",
            "dominant_category": dom,
            "emits_behavioral_token": any(t.startswith("cat:") for t in vt),
            "tokens": sorted(vt),
            "framing_sets": sets,
            "framable": bool(sets),
            "cheapest_usd": sets[0]["cost_usd"] if sets else None,
        })
    victims.sort(key=lambda v: (v["cheapest_usd"] is None,
                                v["cheapest_usd"] or 0))

    # Execute the cheapest framing against each framable victim and check what
    # the pipeline actually does - a link is only an accusation if it survives
    # attribution, investigation and policy.
    executed = []
    for v in victims:
        if not v["framable"]:
            continue
        atk_id = "acct_ATTACKER_frame"
        atk = dict(accounts["acct_LF01"])          # a real actor's profile
        atk["account_id"] = atk_id
        target_ref = None
        for t in v["framing_sets"][0]["tokens"]:
            kind, val = t.split(":", 1)
            if kind == "ip":
                atk["signup_ip"] = val
            elif kind == "asn":
                atk["signup_asn"] = val
            elif kind == "pay":
                atk["payment"] = val
            elif kind == "target":
                target_ref = val
        dom_needed = next((t.split(":", 1)[1]
                           for t in v["framing_sets"][0]["tokens"]
                           if t.startswith("cat:")), None)

        a2 = dict(accounts)
        s2 = {k: list(x) for k, x in sessions.items()}
        a2[atk_id] = atk
        base_sess = [dict(x) for x in sessions["acct_LF01"]]
        for s in base_sess:
            s["account_id"] = atk_id
            if dom_needed:
                s["category"] = dom_needed
            if target_ref:
                s["target_ref"] = target_ref
        s2[atk_id] = base_sess

        clusters, link_log = build_actors(a2, s2)
        merged = [c for c in clusters
                  if v["account_id"] in c and atk_id in c]
        sc2 = score_all(a2, s2)
        decision = None
        if merged:
            packet = build_packet(sorted(merged[0]), a2, s2, sc2, {})
            f = assess_mock(packet)
            f["cluster_size"] = len(merged[0])
            f = apply_enforcement_policy(
                f, [sc2[x]["signals"] for x in merged[0]])
            decision = f["enforcement_decision"]
        executed.append({
            "victim": v["account_id"],
            "persona": v["persona"],
            "cost_usd": v["cheapest_usd"],
            "merged": bool(merged),
            "cluster": sorted(merged[0]) if merged else None,
            "enforcement_decision": decision,
            "victim_enforced": bool(merged) and decision == "enforce",
            "link_reason": next((r for a, b, r in link_log
                                 if atk_id in (a, b)
                                 and v["account_id"] in (a, b)), None),
        })

    framable = [v for v in victims if v["framable"]]
    enforced = [e for e in executed if e["victim_enforced"]]
    return {
        "victims": victims,
        "executed": executed,
        "summary": {
            "benign_accounts": len(victims),
            "framable": len(framable),
            "not_framable": len(victims) - len(framable),
            "successfully_enforced": len(enforced),
            "cheapest_successful_usd": min(
                (e["cost_usd"] for e in enforced), default=None),
            "framable_personas": sorted(
                {v["persona"] for v in framable}),
            "protected_personas": sorted(
                {v["persona"] for v in victims if not v["framable"]}),
        },
        "token_costs": TOKEN_COSTS,
    }


def readme_table(r: dict) -> str:
    L = ["| Victim | Persona | Dominant topic | Framable? | Cheapest | "
         "Pipeline outcome |", "|---|---|---|---|---|---|"]
    ex = {e["victim"]: e for e in r["executed"]}
    for v in r["victims"]:
        e = ex.get(v["account_id"])
        outcome = ("—" if not v["framable"]
                   else (e["enforcement_decision"] or "not merged")
                   if e else "—")
        cost = ("—" if v["cheapest_usd"] is None
                else f"${v['cheapest_usd']:.0f}")
        L.append(f"| `{v['account_id']}` | {v['persona']} | "
                 f"`{v['dominant_category']}` | "
                 f"{'**yes**' if v['framable'] else 'no'} | {cost} | "
                 f"{outcome} |")
    s = r["summary"]
    L.append("")
    L.append(f"{s['framable']} of {s['benign_accounts']} benign accounts are "
             f"framable; {s['successfully_enforced']} reach an `enforce` "
             f"decision, cheapest at "
             f"${s['cheapest_successful_usd']:.0f}."
             if s["cheapest_successful_usd"] is not None else
             f"{s['framable']} of {s['benign_accounts']} benign accounts are "
             f"framable; none reached an enforce decision.")
    return "\n".join(L)


def render(r: dict) -> str:
    L = ["=== who can be framed, and for how much ==="]
    for v in r["victims"]:
        tag = "FRAMABLE" if v["framable"] else "not framable"
        cost = "" if v["cheapest_usd"] is None else f" @ ${v['cheapest_usd']:.0f}"
        L.append(f"  {v['account_id']:26s} {v['persona']:22s} "
                 f"dom={str(v['dominant_category']):18s} {tag}{cost}")
        if v["framable"]:
            best = v["framing_sets"][0]
            L.append(f"      cheapest set: {best['tokens']} -> {best['reason']}")
    L.append("\n=== executing the cheapest framing against each ===")
    for e in r["executed"]:
        L.append(f"  {e['victim']:26s} merged={str(e['merged']):5s} "
                 f"decision={str(e['enforcement_decision']):12s} "
                 f"${e['cost_usd']:.0f}")
        if e["link_reason"]:
            L.append(f"      link: {e['link_reason']}")
    s = r["summary"]
    L.append(f"\n=== summary ===")
    L.append(f"  benign accounts:        {s['benign_accounts']}")
    L.append(f"  framable:               {s['framable']}")
    L.append(f"  not framable:           {s['not_framable']}")
    L.append(f"  reached enforce:        {s['successfully_enforced']}")
    L.append(f"  cheapest successful:    "
             + (f"${s['cheapest_successful_usd']:.0f}"
                if s["cheapest_successful_usd"] is not None else "n/a"))
    L.append(f"  framable personas:      {s['framable_personas']}")
    L.append(f"  structurally protected: {s['protected_personas']}")
    return "\n".join(L)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--readme-table", action="store_true")
    args = p.parse_args()
    r = analyse()
    if args.readme_table:
        print(readme_table(r))
        return
    (DATA / "framing.json").write_text(json.dumps(r, indent=2) + "\n")
    print(render(r))
    print(f"\nwrote {DATA / 'framing.json'}")


if __name__ == "__main__":
    main()
