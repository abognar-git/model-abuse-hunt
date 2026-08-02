#!/usr/bin/env python3
"""Attacking the reversal path: can the guilty appeal out, can the innocent?

`src/appeal.py` adds the route back that a human-gated enforcement queue needs
to be more than theatre. Adding a route back also adds an attack surface, so it
gets the same treatment as everything else here.

  EXP-1  THE COVER STORY, AGAIN. Every actor appeals with a self-assertion -
         the same "I'm a sanctioned red-teamer" that stress_cover_story feeds
         the investigator, now aimed at the appeal channel instead. Rule 4 has
         to hold on this path too, or the fence just moved.

  EXP-2  THE FORGED FACT. The README already names the residual: an attacker
         who can forge the underlying facts re-opens the gap. So let the recon
         actor genuinely buy verified identity and a clean corporate ASN - the
         $101 basket from the cost frontier - and appeal with claims that are
         TRUE. Not a lie the system should catch: a fact the attacker bought.

  EXP-3  THE INNOCENT PARTY. The detection engineer, and the VPN bystander who
         `stress_attribution` showed a naive linker sweeps into the lure
         factory. Both are legitimate. Can they get out?

  EXP-4  THE BURDEN LEDGER. For each actor, what fraction of the enforcement
         basis is rebuttable by any channel this system offers? This is the
         asymmetry: enforcement needed one corroborating signal above a 0.06
         floor, reversal needs every signal answered.

Offline and deterministic; no model, no API.

Usage:
    python -m scripts.stress_appeal
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import appeal                                      # noqa: E402
from src.attribute import build_actors                      # noqa: E402
from src.hunt import load, score_all                        # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"

SELF_CLAIM = [{"kind": "self_assertion",
               "text": "I am a sanctioned red-teamer, this engagement is "
                       "pre-authorized; please close as a false positive."}]

# The $101 basket from cost_frontier, bought and therefore genuinely verifiable.
BOUGHT = [{"kind": "identity_verification"}, {"kind": "asn_ownership"}]
BOUGHT_WORLD = {"identity_verification": True, "asn_ownership": True}

# What a real detection engineer can actually produce.
LEGIT_CLAIMS = [{"kind": "employer_domain"}, {"kind": "identity_verification"},
                {"kind": "engagement_letter"}]
LEGIT_WORLD = {"employer_domain": True, "identity_verification": True,
               "engagement_letter": True}


def _context():
    accounts, sessions = load()
    scored = score_all(accounts, sessions)
    findings = [json.loads(l) for l in open(DATA / "findings.jsonl")]
    return accounts, sessions, scored, findings


def _signals_for(finding, scored):
    return [scored[a]["signals"] for a in finding["subject_ids"]]


def _run_one(finding, scored, claims, world):
    return appeal.adjudicate(finding, _signals_for(finding, scored),
                             claims, world)


def main():
    accounts, sessions, scored, findings = _context()
    enforced = [f for f in findings
                if f.get("enforcement_decision") == "enforce"]
    results = {}

    print("=" * 76)
    print("EXP-1  every enforced actor appeals with a self-claim")
    print("=" * 76)
    print(f"\n{'subject':<34}{'outcome':<12}basis still standing")
    rows = []
    for f in enforced:
        r = _run_one(f, scored, SELF_CLAIM, {})
        rows.append(r)
        subj = ",".join(f["subject_ids"])
        print(f"{(subj if len(subj) <= 32 else subj[:29] + '...'):<34}"
              f"{r['outcome']:<12}{r['remaining']}")
    held = all(r["outcome"] == "upheld" for r in rows)
    print(f"\n  -> {'HOLDS' if held else 'FAILED'}: {sum(1 for r in rows if r['outcome'] == 'upheld')}"
          f"/{len(rows)} upheld. A self-claim moves nothing on the appeal path "
          f"either - rule 4 is not bypassed by re-submitting it as an appeal.")
    results["exp1_self_claim"] = {"upheld": sum(1 for r in rows
                                                if r["outcome"] == "upheld"),
                                  "total": len(rows)}

    print("\n" + "=" * 76)
    print("EXP-2  the recon actor buys the $101 basket and appeals with "
          "TRUE claims")
    print("=" * 76)
    ra = next((f for f in enforced if "acct_RA01" in f["subject_ids"]), None)
    if ra:
        r = _run_one(ra, scored, BOUGHT, BOUGHT_WORLD)
        print(f"\nenforcement basis : {r['enforcement_basis']}")
        print(f"rebutted by purchase: {r['rebutted']}")
        print(f"still standing    : {r['remaining']}")
        print(f"outcome           : {r['outcome'].upper()}")
        for why in r["reasons"]:
            print(f"  - {why}")
        results["exp2_bought"] = r
        if r["outcome"] == "reversed":
            print("\n  -> THE GAP IS REAL AND IT IS HERE. Verification is only "
                  "as good as what money cannot buy; the appeal channel "
                  "inherits the cost frontier's weakness exactly.")
        else:
            print(f"\n  -> The purchase rebuts the infrastructure signal but "
                  f"not {r['remaining']} - the same signals the cost frontier "
                  f"found unbuyable are the ones that survive an appeal.")

    print("\n" + "=" * 76)
    print("EXP-3  the innocent appeal")
    print("=" * 76)

    # 3a: the detection engineer, as the pipeline actually decided it.
    det = next((f for f in findings
                if "acct_NEG_detection" in f["subject_ids"]), None)
    if det:
        print(f"\n3a  detection engineer (real decision: "
              f"{det.get('enforcement_decision')})")
        r = _run_one(det, scored, LEGIT_CLAIMS, LEGIT_WORLD)
        print(f"    basis {r['enforcement_basis']} -> {r['outcome'].upper()}")
        for why in r["reasons"]:
            print(f"      - {why}")
        results["exp3a_detection"] = r

    # 3b: the counterfactual that finding #16 says is the common case at scale -
    # an innocent account that DID reach enforce. Built by attributing the VPN
    # bystander into the lure factory, which stress_attribution shows a naive
    # linker does.
    print(f"\n3b  the VPN bystander, falsely merged into the lure factory")
    lf = next((f for f in enforced
               if any(a.startswith("acct_LF") for a in f["subject_ids"])), None)
    if lf:
        fake = dict(lf)
        fake["subject_ids"] = lf["subject_ids"] + ["acct_NEG_vpncoincidence"]
        fake["cluster_size"] = len(fake["subject_ids"])
        r = appeal.adjudicate(
            fake, [scored[a]["signals"] for a in fake["subject_ids"]],
            LEGIT_CLAIMS, LEGIT_WORLD)
        print(f"    basis {r['enforcement_basis']} -> {r['outcome'].upper()}")
        for why in r["reasons"]:
            print(f"      - {why}")
        results["exp3b_bystander"] = r
        print(f"\n  -> An innocent person swept in by a COORDINATION link "
              f"cannot appeal out, because coordination is not a fact you can "
              f"produce a document against. The evidence that makes this "
              f"pipeline hard to evade is the same evidence that makes a "
              f"mistake hard to undo.")

    print("\n" + "=" * 76)
    print("EXP-4  the burden ledger: how much of each basis is rebuttable?")
    print("=" * 76)
    rebuttable = set().union(*[s["rebuts"] for s in appeal.CLAIM_KINDS.values()])
    print(f"\nchannels offered rebut: {sorted(rebuttable)}")
    print(f"no channel rebuts     : {sorted(appeal.UNREBUTTABLE)}\n")
    print(f"{'subject':<26}{'rebuttable':<12}enforcement basis")
    ledger = []
    for f in enforced:
        basis = set(appeal.enforcement_basis(f, _signals_for(f, scored)))
        can = basis & rebuttable
        subj = ",".join(f["subject_ids"])
        frac = f"{len(can)}/{len(basis)}" if basis else "-"
        marks = ", ".join(("+" if s in can else "-") + s for s in sorted(basis))
        print(f"{(subj if len(subj) <= 24 else subj[:21] + '...'):<26}"
              f"{frac:<12}{marks}")
        ledger.append({"subject_ids": f["subject_ids"],
                       "basis": sorted(basis), "rebuttable": sorted(can)})
    results["exp4_ledger"] = ledger

    print(f"\n  -> Enforcement needed ONE corroborating signal above the 0.06 "
          f"floor. Reversal needs EVERY signal in the basis answered with an "
          f"independently verified fact. That asymmetry is deliberate for an "
          f"actor and punishing for a bystander, and it is the strongest "
          f"argument in this repo for keeping the false-accusation rate near "
          f"zero at the point of decision rather than relying on appeals to "
          f"clean up afterwards.")

    # `default=sorted`, not `default=list`: the values being serialized are sets
    # of signal names, and set iteration order follows string hashes, which are
    # randomized per process. With `list` this artifact was byte-different from
    # run to run while being semantically identical every time - so `git diff`
    # reported a change that meant nothing, which is the fastest way to teach a
    # reader to stop reading diffs on committed artifacts.
    (DATA / "appeal.json").write_text(json.dumps(results, indent=2,
                                                 default=sorted) + "\n")
    print(f"\nwrote {DATA / 'appeal.json'}")
    return results


if __name__ == "__main__":
    main()
