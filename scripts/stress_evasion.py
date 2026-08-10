#!/usr/bin/env python3
"""Evasion: an actor who has read the signals and pays to shed them.

Every deterministic signal is a target once the adversary knows it. This
harness takes the recon actor and, one countermeasure at a time, strips the
signals it can buy its way out of - residential/clean ASN instead of
bulletproof hosting, a verified card instead of prepaid, phone verification, a
jittered human-like cadence instead of a fixed interval - and watches the risk
score fall. The honest question a threat-intel team has to answer is not "does
our signal work on the actor who does not evade" but "what is left when a
capable actor evades everything they can".

The result splits the signals into two piles:

  cheap to shed   - infrastructure and payment reputation, cadence. An actor
                    with money and patience removes these, and the risk score
                    collapses toward the benign floor.
  expensive to shed - the behaviors tied to the operation's *purpose*: fixation
                    on a chosen victim, and coordination across accounts. To
                    drop victim fixation is to stop targeting the victim; to
                    drop coordination is to run one account, which caps the
                    operation's scale. These cost the attacker something real.

This is the same shape as the triage project's honest limits: the prefilter is
evadable, so it is not the boundary. Here the per-account score is evadable, so
it is not the boundary either - attribution and victim-centric analysis are,
and even they leave a residual blind spot this harness names rather than hides.

Usage:
    python -m scripts.stress_evasion
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import signals                                   # noqa: E402
from src.hunt import load                                 # noqa: E402


def _score(account, sess_list):
    return signals.score_account(account, sess_list)["risk_score"]


def run():
    accounts, sessions = load()
    acct = copy.deepcopy(accounts["acct_RA01"])
    sess = copy.deepcopy(sessions["acct_RA01"])

    steps = [("baseline actor", lambda a, s: None)]

    def clean_asn(a, s):
        a["signup_asn"] = "AS65537"         # residential broadband (RFC 5398 doc range)
        for x in s:
            x["asn"] = "AS65537"

    def clean_payment(a, s):
        a["payment"] = "card_verified"; a["email_kind"] = "freemail"
        a["phone_verified"] = True

    def jitter_cadence(a, s):
        # spread the calls out irregularly instead of a fixed 4-min beat
        base = 0
        for i, x in enumerate(s):
            base += 7 + (i * 13) % 29
            hh, mm = 2 + base // 60, base % 60
            x["ts"] = f"2026-07-06T{hh:02d}:{mm:02d}:00Z"

    def drop_refusals(a, s):
        for x in s:
            x["disposition"] = "completed"

    steps += [
        ("+ clean ASN (residential)", clean_asn),
        ("+ verified payment + phone", clean_payment),
        ("+ jittered human cadence", jitter_cadence),
        ("+ no boundary-probing refusals", drop_refusals),
    ]

    print(f"{'countermeasure':<34}{'risk':<8}{'fired signals'}")
    print("-" * 78)
    a, s = copy.deepcopy(acct), copy.deepcopy(sess)
    for label, mutate in steps:
        mutate(a, s)
        scored = signals.score_account(a, s)
        fired = ", ".join(sig["signal"] for sig in scored["signals"]) or "none"
        print(f"{label:<34}{scored['risk_score']:<8.2f}{fired}")

    print(f"\nlead threshold is {signals.LEAD_THRESHOLD}. After buying out infra, "
          f"payment and\ncadence, the score is carried by what remains: "
          f"target_fixation on\n'dunmarle-logistics' and the high-risk topic. "
          f"Those do not go away without\nthe actor abandoning the operation's "
          f"purpose.")
    print("\nresidual blind spot, stated plainly: a patient actor who runs ONE "
          "clean\naccount, spreads a low volume, names no reusable victim, and "
          "probes\nnothing looks - on this telemetry - like an ordinary user. "
          "There is no\nbehavioral signal left to fire, and content is dual-use. "
          "That actor is\ncaught, if at all, by evidence this dataset does not "
          "contain (endpoint,\nvendor, downstream victim reports), not by "
          "anything measured here.")


if __name__ == "__main__":
    run()
