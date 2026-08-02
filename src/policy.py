"""Enforcement policy: the boundary between an assessment and an action.

This is the analogue of the triage project's `apply_policy`, and it exists for
the same reason: the model's judgement, however confident, must not be able to
*act*. Here the stakes are a real person's account. A wrong enforcement bans a
legitimate user - the pentester, the trainer, the detection engineer whose
work looks exactly like the thing we hunt - and there is no undo on the trust
that costs.

So the hard rules, none of which the model can talk its way around:

  1. No adverse action is ever automatic. Every enforcement recommendation
     requires human approval. The automatic-adverse-action region is empty by
     construction; stress_enforcement_surface.py enumerates the whole input
     space to prove it.

  2. No enforcement on content/topic alone. An adverse action requires at
     least one corroborating NON-CONTENT signal - infrastructure, coordination,
     automation, baseline drift, target fixation. "They asked about malware"
     is never, by itself, grounds to action an account, because that is the
     one thing a red-teamer and a malware author have in common.

  3. A confidence floor. Below ICD-203 "likely", no adverse action is
     recommended - the subject is monitored or investigated further.

  4. Self-claimed authorization is inert. A cover story in the subject's own
     prompts cannot *lower* a disposition; at most it raises a manipulation
     flag. (It also never raises enforcement on its own - see rule 2.)

The output disposition is one of: enforce (human-gated), monitor, gather_more,
clear. Enforcement is a queue for a human, never a switch.
"""
from __future__ import annotations

from .investigate import BAND_FLOOR
from .signals import TOPIC_DERIVED_SIGNALS, WEIGHTS

CONFIDENCE_FLOOR_BAND = "likely"          # rule 3
CONFIDENCE_FLOOR = BAND_FLOOR[CONFIDENCE_FLOOR_BAND]

# Signals that count as non-content corroboration (rule 2). capability_trajectory
# and content_category_risk are excluded on purpose: both are topic-derived, and
# topic is dual-use.
#
# DERIVED, not listed. This used to be a literal set of the other five names,
# which meant the repo held the same definition twice - signals.py said which
# signals are topic-derived, and this module independently restated the
# complement. Finding #20 is about exactly that kind of split, and the fix for it
# stopped one module short: adding a signal here, or reclassifying one as
# topic-derived over there, would have silently widened what may action an
# account. The complement is now computed, so the two cannot disagree.
CORROBORATING_SIGNALS = set(WEIGHTS) - TOPIC_DERIVED_SIGNALS

# Presence is not strength. A non-content signal only *corroborates* if it fired
# with real weight - a 0.04 automation blip off three hourly API calls is noise,
# not evidence. Counting mere presence let the real model's over-flag of the
# detection engineer reach an enforce decision; this floor is the same lesson as
# the triage project's corroboration bug (which counted change_ticket=None as
# corroboration), in a new costume.
CORROBORATION_MIN_CONTRIBUTION = 0.06

# Strength is not sample size - the next rung of the same ladder, and finding
# #21. `refusal_farming` is a rate over sessions with no minimum denominator:
# one refusal in one session scores intensity 1.0 and contributes 0.10, which
# clears the strength floor above and supplies the whole of rule 2's
# non-content requirement. But "farming" is a claim about REPETITION, and a
# rate computed from a single observation cannot support it. The median account
# in this dataset has 3 sessions.
#
# This is the argument src/prevalence.py already makes about the project's own
# evaluation metrics - 0 of 14 is not a rate of zero - which had never been
# turned on the scorer that produces them. Enforced here rather than in
# signals.py on purpose: shrinking the score itself would rescale every
# account, including well-sampled ones, and would collide with the mock
# engine's own risk threshold. The defect is specifically that a thin rate can
# ACT, so the fix belongs at the gate that lets it act.
#
# Set to the smallest denominator at which a maximally-refusing account's
# Wilson 95% lower bound clears REFUSAL_FARMING_MIN by more than the interval's
# own half-width - i.e. the point at which the estimate distinguishes "farming"
# from "asked once and was declined". Derived by stress_sensitivity.py, not
# picked.
CORROBORATION_MIN_OBSERVATIONS = 4


def _has_corroboration(finding, member_signals) -> bool:
    """True if the subject is a coordinated multi-account cluster (coordination
    an attacker cannot manufacture by topic alone), OR some member fired a
    non-content signal that is both strong enough and observed often enough.

    `member_signals` is a list (one per member) of that member's signal dicts,
    each carrying `signal`, `contribution` and `n_observations`."""
    if finding.get("cluster_size", 1) > 1:
        return True
    for sigs in member_signals:
        for s in sigs:
            if s["signal"] not in CORROBORATING_SIGNALS:
                continue
            if s["contribution"] < CORROBORATION_MIN_CONTRIBUTION:
                continue
            # A rate-derived signal must also be backed by enough observations.
            # `n_observations` is None for account-level facts (a disposable
            # email is not a rate), and those are exempt by construction.
            n = s.get("n_observations")
            if n is not None and n < CORROBORATION_MIN_OBSERVATIONS:
                continue
            return True
    return False


def apply_enforcement_policy(finding: dict, member_signals: list[set]) -> dict:
    """Map an investigation finding to an enforcement decision under the hard
    rules. `member_signals` is a list of the set of signal names that fired on
    each member account. Returns the finding annotated with the decision.
    """
    result = dict(finding)
    band = finding["confidence_band"]
    conf = BAND_FLOOR[band]
    corroborated = _has_corroboration(finding, member_signals)

    reasons = []
    adverse = finding["recommended_disposition"] == "recommend_enforcement"

    # Rule 3: confidence floor.
    if adverse and conf < CONFIDENCE_FLOOR:
        adverse = False
        reasons.append(f"confidence {band} below floor {CONFIDENCE_FLOOR_BAND}")

    # Rule 2: no enforcement on content alone.
    if adverse and not corroborated:
        adverse = False
        reasons.append("no non-content corroboration - topic alone cannot "
                       "action an account")

    if adverse:
        decision = "enforce"
        reasons.append("confident assessment with behavioral/infra "
                       "corroboration")
    elif finding["assessment"] == "likely_benign" and not corroborated:
        decision = "clear"
        reasons.append("assessed benign, only dual-use topic signals")
    elif finding["recommended_disposition"] == "gather_more":
        decision = "gather_more"
    else:
        decision = "monitor"

    # Rule 1: enforcement is always human-gated. Nothing here flips a switch.
    result["enforcement_decision"] = decision
    result["requires_human_approval"] = decision == "enforce"
    result["auto_actioned"] = False               # invariant: never true
    result["corroborated"] = corroborated
    result["policy_reasons"] = reasons

    # Rule 4: manipulation is recorded, never used to reduce the disposition.
    if finding.get("manipulation_observed"):
        result["policy_reasons"].append(
            "manipulation attempt noted (self-claimed authorization); "
            "disregarded for disposition")
    return result
