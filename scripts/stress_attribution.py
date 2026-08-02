#!/usr/bin/env python3
"""Attacks on the attribution layer - all offline, all deterministic.

Attribution is where a false positive becomes a false *accusation*: link a
bystander to an actor and every downstream layer treats them as the actor.
So the attribution layer is attacked directly, the way stress_correlation.py
attacked the triage project's linker. Three experiments; none touches a model.

  EXP-1  shared-infrastructure false merge
         A bystander behind the same commercial VPN egress (same IP, same ASN)
         as the lure factory - and nothing else. Merging on infrastructure
         alone would attribute them to the actor. The rule must not.

  EXP-2  attribution poisoning via a shared victim
         The strongest link the layer has is a shared named victim. That makes
         it the poisoning target: an ordinary employee of the victim org names
         their own employer, exactly as the recon actor does. Naive victim-
         linking merges them. The guard requires corroboration a bystander
         cannot supply.

  EXP-3  burner fragmentation
         An actor splits one operation across many single-session burners so no
         single account clears the behavioral lead threshold. Per-account
         scoring is designed to be evaded this way. Coordination is not:
         the burners still share victim + infra, so attribution reassembles
         them even though not one of them is individually a lead.

Usage:
    python -m scripts.stress_attribution
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import signals                                   # noqa: E402
from src.attribute import build_actors                    # noqa: E402
from src.hunt import load, score_all                      # noqa: E402


def _actor_of(clusters, aid):
    for i, c in enumerate(clusters, 1):
        if aid in c:
            return i, c
    return None, None


def exp1_shared_infra(accounts, sessions):
    print("EXP-1  shared-infrastructure false merge")
    acc = dict(accounts)
    sess = dict(sessions)
    # bystander sharing ONLY the lure factory's egress IP + ASN
    acc["acct_DECOY_vpn"] = {
        "account_id": "acct_DECOY_vpn", "created_at": "2026-07-20T10:00:00Z",
        "email_kind": "freemail", "signup_ip": "198.51.100.44",
        "signup_asn": "AS64497", "signup_country": "RO",
        "payment": "card_verified", "phone_verified": True,
        "primary_channel": "chatgpt"}
    sess["acct_DECOY_vpn"] = [{
        "session_id": "sx1", "account_id": "acct_DECOY_vpn",
        "ts": "2026-07-20T11:00:00Z", "channel": "chatgpt",
        "category": "benign_code", "prompt_excerpt": "review my python script",
        "disposition": "completed", "src_ip": "198.51.100.44",
        "asn": "AS64497", "country": "RO", "target_ref": None}]
    clusters, _ = build_actors(acc, sess)
    idx, cluster = _actor_of(clusters, "acct_DECOY_vpn")
    merged = idx is not None
    print(f"   decoy shares IP 198.51.100.44 + AS64497 with 5 lure burners")
    print(f"   merged into an actor cluster: {'YES (FALSE MERGE)' if merged else 'no'}")
    print(f"   -> {'FAIL' if merged else 'PASS'}: infrastructure alone does not attribute\n")
    return not merged


def exp2_poisoning(accounts, sessions):
    print("EXP-2  attribution poisoning via a shared victim")
    acc = dict(accounts)
    sess = dict(sessions)
    # an ordinary employee of the recon actor's victim, naming their employer
    acc["acct_DECOY_victim"] = {
        "account_id": "acct_DECOY_victim", "created_at": "2026-07-15T09:00:00Z",
        "email_kind": "corporate", "signup_ip": "198.51.100.30",
        "signup_asn": "AS65538", "signup_country": "DE",
        "payment": "card_verified", "phone_verified": True,
        "primary_channel": "chatgpt"}
    sess["acct_DECOY_victim"] = [{
        "session_id": "sy1", "account_id": "acct_DECOY_victim",
        "ts": "2026-07-15T10:00:00Z", "channel": "chatgpt",
        "category": "benign_code",
        "prompt_excerpt": "help me write an internal onboarding doc for "
                          "acme-logistics new hires",
        "disposition": "completed", "src_ip": "198.51.100.30", "asn": "AS65538",
        "country": "DE", "target_ref": "acme-logistics"}]

    naive, _ = build_actors(acc, sess, strict=False)
    ni, _ = _actor_of(naive, "acct_DECOY_victim")
    strict, _ = build_actors(acc, sess, strict=True)
    si, _ = _actor_of(strict, "acct_DECOY_victim")
    print(f"   employee names own employer 'acme-logistics'; recon actor targets it")
    print(f"   naive victim-linking merges the employee: "
          f"{'YES (FALSE MERGE)' if ni else 'no'}")
    print(f"   guarded linking merges the employee:      "
          f"{'YES (FALSE MERGE)' if si else 'no'}")
    print(f"   -> {'PASS' if (ni and not si) else 'INCONCLUSIVE'}: the guard "
          f"is what prevents the poison; naive linking would swallow it\n")
    return not si


def exp3_fragmentation(accounts, sessions):
    print("EXP-3  burner fragmentation below the lead threshold")
    acc = dict(accounts)
    sess = dict(sessions)
    # 8 single-session burners, same actor: same victim + same egress, one
    # low-grade session each, so none clears the behavioral lead threshold.
    # Distinct infra + victims from the lure factory, so this is provably a
    # NEW actor reassembled by coordination, not a fold-in to an existing one.
    brands = ["westford-credit", "orbit-mobile"]
    for k in range(8):
        aid = f"acct_FRAG{k:02d}"
        acc[aid] = {
            "account_id": aid, "created_at": f"2026-07-22T08:{k:02d}:00Z",
            "email_kind": "freemail", "signup_ip": "192.0.2.10",
            "signup_asn": "AS65539", "signup_country": "RO",
            "payment": "card_verified", "phone_verified": True,
            "primary_channel": "chatgpt"}
        sess[aid] = [{
            "session_id": f"sf{k}", "account_id": aid,
            "ts": f"2026-07-22T09:{k:02d}:00Z", "channel": "chatgpt",
            "category": "phishing_content",
            "prompt_excerpt": f"draft a short verification email for "
                             f"{brands[k % 2]}",
            "disposition": "completed", "src_ip": "192.0.2.10",
            "asn": "AS65539", "country": "RO", "target_ref": brands[k % 2]}]
    scored = score_all(acc, sess)
    frag_ids = [f"acct_FRAG{k:02d}" for k in range(8)]
    any_lead = [a for a in frag_ids if scored[a]["is_lead"]]
    clusters, _ = build_actors(acc, sess)
    idx, cluster = _actor_of(clusters, "acct_FRAG00")
    reassembled = idx is not None and len(cluster) >= 6
    print(f"   8 burners, one session each, individually risk<="
          f"{max(scored[a]['risk_score'] for a in frag_ids):.2f}")
    print(f"   burners that individually became leads: {len(any_lead)}/8")
    print(f"   attribution reassembled them into one actor: "
          f"{'yes, ' + str(len(cluster)) + ' accounts' if reassembled else 'no'}")
    print(f"   -> {'PASS' if (not any_lead and reassembled) else 'PARTIAL'}: "
          f"scoring is evaded, coordination is not\n")
    return reassembled


def run():
    accounts, sessions = load()
    print("Attacking the attribution layer (offline, deterministic)\n")
    r1 = exp1_shared_infra(accounts, sessions)
    r2 = exp2_poisoning(accounts, sessions)
    r3 = exp3_fragmentation(accounts, sessions)
    print("-" * 68)
    print(f"EXP-1 shared-infra guard held: {r1}")
    print(f"EXP-2 poisoning guard held:    {r2}")
    print(f"EXP-3 fragmentation reassembled by coordination: {r3}")
    print("\nThe through-line: link on a REASON, not an overlap. Infrastructure "
          "and\na named victim are each forgeable in isolation; requiring "
          "corroboration\nis what separates an actor's burners from a bystander "
          "who shares one\nattribute with them.")
    return r1 and r2 and r3


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
