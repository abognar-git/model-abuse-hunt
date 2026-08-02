"""Reversal: the path back for an account that was enforced against.

Every other layer in this repo is built around not accusing the wrong person.
This one starts from the assumption that it happened anyway - which
`src/prevalence.py` says is not pessimism but arithmetic. At a realistic base
rate, an enforcement queue with a false-accusation rate anywhere in the interval
this dataset can bound is mostly innocent people. A system that can only ever
add accounts to that queue is not finished.

The design problem is immediate, and it is a genuine collision between two
things this project already believes:

    Policy rule 4 says a subject's self-claim is inert - it cannot lower a
    disposition, at most it raises a manipulation flag. That rule exists
    because cover stories are the cheapest attack on an investigator.

    An appeal IS a self-claim. "You have the wrong person" is exactly the
    utterance rule 4 refuses to credit.

Taken naively, rule 4 means the innocent have no route back, and the whole
human-gate argument collapses into theatre: a human who may only ever confirm is
not a check. Taken the other way - letting appeals move dispositions - every
actor simply appeals, and rule 4 was pointless.

The resolution is that these are different objects. **An appeal does not assert
a conclusion; it nominates a fact for independent verification.** The claim is
still inert. What can move the decision is the *verified fact*, and the
verification is performed by the platform against evidence the subject does not
control - a domain's ownership records, a payment processor, an ASN registry, a
named client contacted directly, an artifact published before the activity
began. So:

  R1  A self-claim alone never reverses anything. (Rule 4, intact.)
  R2  A reversal requires verified facts that rebut the SPECIFIC signals the
      enforcement rested on. Generic good character rebuts nothing - the
      symmetric form of "no enforcement on content alone".
  R3  Verification uses channels the subject does not control. A fact the
      subject can author is not verification; it is the self-claim again in a
      different field. (This is where a forged `change_ticket` came from in the
      sibling project, and where a residential proxy comes from in this one.)
  R4  Reversal is human-gated, exactly as enforcement is. Symmetry matters: an
      automatic un-ban is an attack surface of its own.

The uncomfortable consequence, which `stress_appeal.py` measures rather than
argues: the signals hardest for an actor to *fake* are also the hardest for an
innocent person to *rebut*. Coordination is the clearest case. The cost frontier
found the lure factory cannot buy its way out of a shared-victim link at any
price - and by exactly the same structure, an innocent bystander falsely linked
to that victim cannot rebut it either. Strong evidence is not reversible on
demand, and that property does not check whose side it is on.
"""
from __future__ import annotations

from .policy import CORROBORATING_SIGNALS

# What a subject can assert, and whether the platform can check it against a
# source the subject does not control. `verifiable=False` is the cover-story
# channel: it is not that these claims are always false, it is that believing
# them costs nothing to fake.
CLAIM_KINDS = {
    "self_assertion": {
        "verifiable": False,
        "via": "nothing - the subject's own word",
        "rebuts": set(),
    },
    "identity_verification": {
        "verifiable": True,
        "via": "payment processor + phone carrier, queried directly",
        "rebuts": {"burner_infra"},
    },
    "employer_domain": {
        "verifiable": True,
        "via": "domain registration and MX ownership, queried directly",
        "rebuts": {"burner_infra"},
    },
    "asn_ownership": {
        "verifiable": True,
        "via": "regional registry: does this range belong to the employer",
        "rebuts": {"burner_infra"},
    },
    "engagement_letter": {
        "verifiable": True,
        "via": "named client contacted out of band; scope and dates confirmed",
        "rebuts": {"capability_trajectory", "target_fixation"},
    },
    "published_research": {
        "verifiable": True,
        "via": "public artifact timestamped before the activity began",
        "rebuts": {"capability_trajectory"},
    },
    "service_account_disclosure": {
        "verifiable": True,
        "via": "customer's own infrastructure inventory, provided by the "
               "customer's security contact rather than the account holder",
        "rebuts": {"automation_cadence"},
    },
}

# Signals no appeal channel in CLAIM_KINDS can rebut. Named explicitly rather
# than left as an empty lookup, because this set is the finding: coordination
# across accounts and divergence from an account's own history are not facts a
# subject can produce a document against.
UNREBUTTABLE = {"coordination", "baseline_drift", "refusal_farming"}


def verify(claim: dict, world: dict) -> dict:
    """Check one claim against the platform's own view of the world.

    `world` is what independent verification returns - registry lookups, the
    payment processor, a client contacted out of band. It is deliberately a
    separate argument from the claim: the subject supplies the claim, the
    platform supplies the world, and nothing the subject wrote may appear in
    the second. R3, made structural rather than promised.
    """
    kind = claim.get("kind")
    spec = CLAIM_KINDS.get(kind)
    if spec is None:
        return {"kind": kind, "status": "unknown_claim_kind", "rebuts": set()}
    if not spec["verifiable"]:
        return {"kind": kind, "status": "inert_self_claim", "rebuts": set(),
                "note": "asserted, not checkable - R1"}
    confirmed = world.get(kind)
    if confirmed is None:
        return {"kind": kind, "status": "unverified", "rebuts": set(),
                "note": f"would be checked via {spec['via']}"}
    if confirmed is False:
        return {"kind": kind, "status": "contradicted", "rebuts": set(),
                "note": "independent check refutes the claim"}
    return {"kind": kind, "status": "verified", "rebuts": set(spec["rebuts"]),
            "note": f"confirmed via {spec['via']}"}


def enforcement_basis(finding: dict, member_signals: list) -> set[str]:
    """The specific signals the enforcement decision actually rested on.

    A reversal has to engage with these and nothing else. Reproduces what
    `policy._has_corroboration` credited, so an appeal is answered against the
    real basis rather than a restatement of it.
    """
    basis = set()
    if finding.get("cluster_size", 1) > 1:
        basis.add("coordination")
    from .policy import CORROBORATION_MIN_CONTRIBUTION
    for sigs in member_signals:
        for s in sigs:
            if (s["signal"] in CORROBORATING_SIGNALS
                    and s["contribution"] >= CORROBORATION_MIN_CONTRIBUTION):
                basis.add(s["signal"])
    return basis


def adjudicate(finding: dict, member_signals: list, claims: list,
               world: dict) -> dict:
    """Decide an appeal. Returns the outcome and, always, the reasoning.

    Outcomes: `reversed` (human-gated), `partial` (some basis rebutted, some
    stands), `upheld`. Never automatic - R4.
    """
    basis = enforcement_basis(finding, member_signals)
    checked = [verify(c, world) for c in claims]
    rebutted = set().union(*[c["rebuts"] for c in checked]) if checked else set()
    rebutted &= basis

    remaining = basis - rebutted
    unrebuttable_remaining = remaining & UNREBUTTABLE

    if not basis:
        outcome = "reversed"
        why = ["the enforcement rested on no corroborating signal at all"]
    elif not remaining:
        outcome = "reversed"
        why = [f"every signal the enforcement rested on was rebutted by "
               f"independently verified facts: {sorted(rebutted)}"]
    elif rebutted:
        outcome = "partial"
        why = [f"rebutted {sorted(rebutted)}; still standing "
               f"{sorted(remaining)}"]
    else:
        outcome = "upheld"
        why = [f"nothing verified rebuts the basis {sorted(basis)}"]

    if any(c["status"] == "inert_self_claim" for c in checked):
        why.append("self-claims submitted were recorded and disregarded (R1)")
    if any(c["status"] == "contradicted" for c in checked):
        why.append("an appeal claim was CONTRADICTED by independent check - "
                   "this is itself evidence, and is preserved")
    if unrebuttable_remaining:
        why.append(f"{sorted(unrebuttable_remaining)} cannot be rebutted by "
                   f"any channel this system offers - see UNREBUTTABLE")

    return {
        "subject_ids": finding.get("subject_ids"),
        "enforcement_basis": sorted(basis),
        "claims_checked": checked,
        "rebutted": sorted(rebutted),
        "remaining": sorted(remaining),
        "outcome": outcome,
        "requires_human_approval": True,          # R4: never automatic
        "auto_reversed": False,                   # invariant
        "reasons": why,
    }
