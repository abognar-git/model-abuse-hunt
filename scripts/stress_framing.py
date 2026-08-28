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

This module reports no costs. It used to price each token from
`stress_adaptive.PRICES` so a framing attack and an evasion attack were quoted
in the same currency; that table was withdrawn (see below) and what is reported
per token now is an access REQUIREMENT - `none` or `network-access`. Fully
offline and deterministic; no model is called.

Usage:
    python -m scripts.stress_framing
    python -m scripts.stress_framing --readme-table
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src import signals
from src.attribute import _link_reason, build_actors, tokens
from src.hunt import load, score_all
from src.investigate import assess_mock, build_packet
from src.policy import apply_enforcement_policy

DATA = Path(__file__).resolve().parent.parent / "data"

# What reproducing each of a victim's tokens actually REQUIRES of an attacker.
#
# This used to be a dollar table built from `stress_adaptive.PRICES`, and that
# was a category error worth recording. Those prices are for *evasion*:
# `clean_asn` ($75) buys **a** clean residential proxy so you look unremarkable,
# and `split_infrastructure` ($100) gives **your own** accounts separate
# infrastructure so they stop correlating. Framing needs neither. It needs you
# to originate from **this specific victim's** ASN and egress IP - which is not
# a product you buy, it is a network you have to already be inside. Three of the
# four accounts in that bracket are on corporate networks.
#
# So the table reports the requirement rather than a price. Quoting a figure
# implied a market that exists for hiding and does not exist for this, and the
# sum it produced ($175) was arithmetically correct and semantically meaningless.
NONE = "none"                    # ask about the same topic, name the same org
NETWORK = "network-access"       # be inside the victim's own network
IDENTITY = "identity-purchase"   # a payment class you can simply buy

TOKEN_ACCESS = {
    "ip": NETWORK,
    "asn": NETWORK,
    "cat": NONE,
    "target": NONE,
    "pay": IDENTITY,
}
# Ordered cheapest-to-hardest, for sorting. Not a currency - a ranking.
_ACCESS_RANK = {NONE: 0, IDENTITY: 1, NETWORK: 2}


def _access(toks) -> str:
    """The hardest requirement in a token set - that is what gates the attack."""
    reqs = {TOKEN_ACCESS.get(t.split(":", 1)[0], NONE) for t in toks}
    return max(reqs, key=lambda r: _ACCESS_RANK[r]) if reqs else NONE


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
                        "requires": _access(shared)})
    return sorted(out, key=lambda x: (_ACCESS_RANK[x["requires"]],
                                      len(x["tokens"])))


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
            "easiest_requirement": sets[0]["requires"] if sets else None,
        })
    victims.sort(key=lambda v: (v["easiest_requirement"] is None,
                                _ACCESS_RANK.get(v["easiest_requirement"], 9)))

    # Execute the framing and see what the pipeline actually does - a link is
    # only an accusation if it survives attribution, investigation and policy.
    #
    # TWO attacker constructions, because conflating them published a wrong
    # number. The original harness built the attacker as a copy of `acct_LF01`
    # and overwrote only the linking tokens, so the attacker kept that actor's
    # infrastructure and the victim was merged into the whole five-account lure
    # factory. The cluster then reached `enforce` because five real actors were
    # sitting in it - the framing supplied the link, the actors supplied the
    # verdict. Reported as "5 of 5 reach an enforcement decision", which is true
    # of that construction and not of the attack it appeared to describe.
    #
    #   standalone   - a purpose-built burner carrying ONLY the tokens needed to
    #                  link. This is the attack as described: attacker plus
    #                  victim, nobody else.
    #   actor_clone  - the original construction, kept as the upper bound. It
    #                  requires the attacker to reproduce a known actor's egress
    #                  infrastructure, which is a far stronger assumption.
    def _run(v, mode):
        atk_id = "acct_ATTACKER_frame"
        best = v["framing_sets"][0]
        if mode == "actor_clone":
            atk = dict(accounts["acct_LF01"])
            base_sess = [dict(x) for x in sessions["acct_LF01"]]
        else:
            atk = {"account_id": atk_id,
                   "created_at": "2026-07-20T09:00:00Z",
                   "email_kind": "freemail",
                   "signup_ip": "198.51.100.200", "signup_asn": "AS64510",
                   "signup_country": "NL", "payment": "card_prepaid",
                   "phone_verified": False, "primary_channel": "chatgpt"}
            base_sess = [{"session_id": f"atk{i}", "account_id": atk_id,
                          "ts": f"2026-07-2{i}T10:00:00Z", "channel": "chatgpt",
                          "category": "phishing_content", "prompt_excerpt": "x",
                          "disposition": "completed",
                          "src_ip": atk["signup_ip"], "asn": atk["signup_asn"],
                          "country": "NL", "target_ref": None}
                         for i in range(3)]
        atk["account_id"] = atk_id
        target_ref = None
        for t in best["tokens"]:
            kind, val = t.split(":", 1)
            if kind == "ip":
                atk["signup_ip"] = val
            elif kind == "asn":
                atk["signup_asn"] = val
            elif kind == "pay":
                atk["payment"] = val
            elif kind == "target":
                target_ref = val
        dom_needed = next((t.split(":", 1)[1] for t in best["tokens"]
                           if t.startswith("cat:")), None)
        a2 = dict(accounts)
        s2 = {k: list(x) for k, x in sessions.items()}
        a2[atk_id] = atk
        for sx in base_sess:
            sx["account_id"] = atk_id
            sx["src_ip"] = atk["signup_ip"]
            sx["asn"] = atk["signup_asn"]
            if dom_needed:
                sx["category"] = dom_needed
            if target_ref:
                sx["target_ref"] = target_ref
        s2[atk_id] = base_sess
        clusters, link_log = build_actors(a2, s2)
        merged = [c for c in clusters if v["account_id"] in c and atk_id in c]
        if not merged:
            return {"merged": False, "cluster": None, "cluster_size": 0,
                    "others_pulled_in": [], "enforcement_decision": None,
                    "victim_enforced": False}
        sc2 = score_all(a2, s2)
        f = assess_mock(build_packet(sorted(merged[0]), a2, s2, sc2, {}))
        f["cluster_size"] = len(merged[0])
        f = apply_enforcement_policy(f, [sc2[x]["signals"] for x in merged[0]])
        others = [x for x in sorted(merged[0])
                  if x not in (v["account_id"], atk_id)]
        return {"merged": True, "cluster": sorted(merged[0]),
                "cluster_size": len(merged[0]), "others_pulled_in": others,
                "enforcement_decision": f["enforcement_decision"],
                "victim_enforced": f["enforcement_decision"] == "enforce"}

    executed = []
    for v in victims:
        if not v["framable"]:
            continue
        executed.append({
            "victim": v["account_id"], "persona": v["persona"],
            "requires": v["easiest_requirement"],
            "tokens": v["framing_sets"][0]["tokens"],
            "link_reason": v["framing_sets"][0]["reason"],
            "standalone": _run(v, "standalone"),
            "actor_clone": _run(v, "actor_clone"),
        })

    framable = [v for v in victims if v["framable"]]
    standalone_enforced = [e for e in executed if e["standalone"]["victim_enforced"]]
    clone_enforced = [e for e in executed if e["actor_clone"]["victim_enforced"]]
    no_barrier = [v for v in framable if v["easiest_requirement"] == NONE]

    return {
        "victims": victims,
        "executed": executed,
        "summary": {
            "benign_accounts": len(victims),
            "framable": len(framable),
            "not_framable": len(victims) - len(framable),
            "framable_with_no_barrier": len(no_barrier),
            "framable_needing_network_access": len(framable) - len(no_barrier),
            "enforced_standalone_attacker": len(standalone_enforced),
            "enforced_actor_clone_attacker": len(clone_enforced),
            "framable_personas": sorted({v["persona"] for v in framable}),
            "protected_personas": sorted(
                {v["persona"] for v in victims if not v["framable"]}),
        },
        "token_access": TOKEN_ACCESS,
    }


def readme_table(r: dict) -> str:
    L = ["| Victim | Persona | Dominant topic | Attachable? | Requires | "
         "Standalone attacker | Attached to a known actor |",
         "|---|---|---|---|---|---|---|"]
    ex = {e["victim"]: e for e in r["executed"]}
    for v in r["victims"]:
        e = ex.get(v["account_id"])
        req = v["easiest_requirement"] or "—"
        sa = e["standalone"]["enforcement_decision"] if e else None
        ac = e["actor_clone"]["enforcement_decision"] if e else None
        L.append(f"| `{v['account_id']}` | {v['persona']} | "
                 f"`{v['dominant_category']}` | "
                 f"{'**yes**' if v['framable'] else 'no'} | `{req}` | "
                 f"{sa or '—'} | {ac or '—'} |")
    s_ = r["summary"]
    L += ["",
          f"{s_['framable']} of {s_['benign_accounts']} benign accounts can be "
          f"attached to an attacker's account: "
          f"{s_['framable_with_no_barrier']} with no barrier at all, "
          f"{s_['framable_needing_network_access']} only from inside the "
          f"victim's own network. A standalone attacker gets "
          f"{s_['enforced_standalone_attacker']} of them enforced against; an "
          f"attacker who can also attach them to a known actor cluster gets "
          f"{s_['enforced_actor_clone_attacker']}."]
    return "\n".join(L)


def render(r: dict) -> str:
    L = ["=== who can be attached to an attacker's account, and what it takes ==="]
    for v in r["victims"]:
        tag = "ATTACHABLE" if v["framable"] else "not attachable"
        req = f" [{v['easiest_requirement']}]" if v["framable"] else ""
        L.append(f"  {v['account_id']:26s} {v['persona']:22s} "
                 f"dom={str(v['dominant_category']):18s} {tag}{req}")
        if v["framable"]:
            best = v["framing_sets"][0]
            L.append(f"      easiest set: {best['tokens']} -> {best['reason']}")
    L.append("\n=== what the pipeline then does, by attacker construction ===")
    L.append(f"  {'victim':26s} {'standalone':>14s}   {'actor-clone':>14s}   pulled in")
    for e in r["executed"]:
        sa, ac = e["standalone"], e["actor_clone"]
        L.append(f"  {e['victim']:26s} {str(sa['enforcement_decision']):>14s}   "
                 f"{str(ac['enforcement_decision']):>14s}   "
                 f"{len(ac['others_pulled_in'])} other account(s)")
    s_ = r["summary"]
    L += ["\n=== summary ===",
          f"  benign accounts:                 {s_['benign_accounts']}",
          f"  attachable:                      {s_['framable']}",
          f"    of those, no barrier at all:   {s_['framable_with_no_barrier']}",
          f"    needing the victim's network:  {s_['framable_needing_network_access']}",
          f"  not attachable:                  {s_['not_framable']}",
          f"  enforced, standalone attacker:   {s_['enforced_standalone_attacker']}",
          f"  enforced, attached to an actor:  {s_['enforced_actor_clone_attacker']}",
          f"  attachable personas:             {s_['framable_personas']}",
          f"  structurally protected:          {s_['protected_personas']}",
          "",
          "  The gap between the two enforcement rows is the finding. Attaching",
          "  yourself to a chosen person is easy; making that stick as an",
          "  enforcement needs a known actor in the cluster, which means",
          "  reproducing that actor's infrastructure - not just the victim's."]
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
