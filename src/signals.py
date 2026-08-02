"""Deterministic behavioral/infrastructure signals.

This module is the thesis of the whole project, expressed as numbers.

An abuse request and a legitimate request can be *word-for-word identical*:
"explain reflective DLL loading" is a malware author or a red-teamer; "write a
convincing account-verification email" is a phishing crew or a security-
awareness trainer. Content does not discriminate them. **Behavior and
infrastructure do** - who the account is, how it was created, how it operates,
whether it coordinates with others.

So every signal here scores behavior or infrastructure, and the weight on raw
content-category is deliberately tiny (`WEIGHTS["content_category_risk"]`).
The hunt runs on the 94% that is behavior, not the 6% that is topic. That is
not a tuning choice you could reverse with a better threshold; it is the
design claim, and the hard-negative accounts in the dataset exist to test it.

Nothing here calls a model. Leads are generated deterministically and offline;
the LLM enters later, for *assessment*, never for the accusation itself - the
same "the model is not the safety boundary" discipline the triage project
arrived at, pointed the other way.
"""
from __future__ import annotations

from collections import Counter

# --- category taxonomy (observable TOPIC, never intent) ----------------------
# These are what the platform can see. Intent is exactly what it cannot see
# from the category, which is why detection_eng is not a category: a pasted
# malware sample is `malware_dev` whoever pasted it.
OFFENSIVE_CATEGORIES = {"malware_dev", "exploit_help", "phishing_content",
                        "spam_content"}
RECON_CATEGORIES = {"recon"}
BENIGN_CATEGORIES = {"benign_code", "translation", "creative_writing"}

# --- signal weights ----------------------------------------------------------
# Sum to 1.0. Read them top to bottom: the model-abuse hunt is a behavior-and-
# infrastructure problem. Content is 0.06 of the score on purpose.
WEIGHTS = {
    "capability_trajectory": 0.22,   # sustained offensive-tooling engagement
    "baseline_drift":        0.20,   # account diverges from its own history
    "automation_cadence":    0.16,   # programmatic, high-volume, regular interval
    "burner_infra":          0.16,   # disposable identity + risky payment + bad ASN
    "refusal_farming":       0.10,   # high refusal rate = probing the boundary
    "target_fixation":       0.10,   # repeated focus on one named real org
    "content_category_risk": 0.06,   # the topic itself - weak on purpose
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

# --- thresholds (named, not magic) -------------------------------------------
LEAD_THRESHOLD = 0.25            # risk at/above this becomes a hunting lead
HIGH_VOLUME_SESSIONS = 12        # sessions before "high volume" for automation
CADENCE_TOLERANCE_MIN = 2        # inter-arrival stddev under this = automated
DRIFT_MIN_BASELINE = 4           # need this many prior sessions to call drift
OFFENSIVE_TRAJECTORY_MIN = 3     # offensive sessions before trajectory fires
REFUSAL_FARMING_MIN = 0.20       # refusal fraction that looks like probing
RISKY_PAYMENTS = {"none", "card_prepaid", "crypto"}
RISKY_EMAIL = {"disposable"}
# ASNs a provider would weight as higher-risk hosting (bulletproof/anon egress).
# Illustrative only - a real system uses a maintained reputation feed.
#
# These are deliberately drawn from the RFC 5398 DOCUMENTATION range, and every
# IP in the dataset from the RFC 5737 documentation ranges, because they are
# unassignable: no real operator can ever hold one. An earlier version of this
# file named four real, identifiable companies here - a hosting provider, a
# non-profit ISP association, a privacy host serving journalists, and a cloud
# provider - and one of them was baked into a committed screenshot beside a
# `malicious_abuse` assessment and an `ENFORCE` decision. That is a published
# claim about a real business, sitting in an image no text scan would surface.
# The sibling project caught the identical bug in a different costume (real
# registered domains cast as fraud actors, also baked into screenshots). The
# rule both arrived at: a synthetic fixture names only identifiers that are
# reserved for documentation by standard, because a fixture that casts someone
# as the villain is not made harmless by being fictional everywhere but the name.
HIGHER_RISK_ASNS = {"AS64497", "AS64496", "AS64498", "AS64499"}


def _minutes(ts: str) -> int:
    """Crude timestamp -> minutes-since-epoch-ish, good enough for cadence."""
    # ts like 2026-07-12T09:31:00Z
    day = int(ts[8:10]); hh = int(ts[11:13]); mm = int(ts[14:16])
    return ((day * 24) + hh) * 60 + mm


def _intensity(count: int, full: int) -> float:
    """Saturating ramp: 0 at count 0, 1.0 at count >= full."""
    if full <= 0:
        return 0.0
    return min(1.0, count / full)


def _capability_trajectory(sessions) -> tuple[float, str]:
    """Breadth across distinct offensive stages. Repeating one offensive topic
    (a trainer generating three phishing emails, a student asking twice about
    overflows) is deliberately scored low; breadth is what climbs.

    NAME-VERSUS-BEHAVIOR WARNING, kept here because it is the subject of
    finding #20. This function is *called* a trajectory and its docstring used
    to claim it measured an escalation arc - loader, then obfuscation, then
    evasion, then C2. It does not. It reads no timestamp and imposes no order:
    `distinct` is a set cardinality over categories, so an account that asks
    about malware and then exploitation, one that asks in the reverse order,
    and one that asks both in the same minute all score identically. What it
    actually measures is *topic breadth*, which is why `src/policy.py` refuses
    to accept it as non-content corroboration under rule 2.

    That refusal and this weight (0.22, the largest in the vector) are the two
    halves of the definitional split finding #20 documents. The ordered variant
    that would earn the name is `_capability_arc`; `stress_sensitivity.py`
    measures both, and the README reports what the comparison showed."""
    off = [s for s in sessions if s["category"] in OFFENSIVE_CATEGORIES]
    if not off:
        return 0.0, ""
    distinct = len({s["category"] for s in off})
    base = {1: 0.40, 2: 0.75}.get(distinct, 1.0)   # breadth tier dominates
    vol = _intensity(len(off), OFFENSIVE_TRAJECTORY_MIN)
    inten = min(1.0, base * (0.6 + 0.4 * vol))      # volume modulates within tier
    return inten, (f"{len(off)} offensive-tooling sessions across "
                   f"{distinct} categor{'y' if distinct == 1 else 'ies'}")


# Escalation ordering: the stages a capability-development arc is supposed to
# climb, weakest -> strongest. Named here rather than inline because the whole
# point of the variant is that the ORDER is the claim being tested.
ESCALATION_RANK = {
    "recon": 0,
    "exploit_help": 1,
    "malware_dev": 2,
    "phishing_content": 1,
    "spam_content": 1,
}


def _capability_arc(sessions) -> tuple[float, str]:
    """The ordered variant: an escalation arc that actually reads the clock.

    Scores *upward movement through stages over time*, which is what the
    published threat reporting describes and what `_capability_trajectory`'s
    docstring claimed while measuring topic breadth instead. An account that
    climbs recon -> exploit -> malware scores; one that asks about all three in
    a single sitting, or that walks back down, does not.

    Intensity = (number of strictly-ascending stage transitions) / (stages-1),
    modulated by the same volume ramp so the two variants differ only in
    whether ORDER is required. Measured against the breadth version by
    `stress_sensitivity.py`; not wired into the pipeline unless that
    measurement says it earns its place."""
    off = sorted((s for s in sessions if s["category"] in OFFENSIVE_CATEGORIES
                  | RECON_CATEGORIES), key=lambda s: s["ts"])
    if not off:
        return 0.0, ""
    ranks = [ESCALATION_RANK.get(s["category"], 0) for s in off]
    ascents = sum(1 for a, b in zip(ranks, ranks[1:]) if b > a)
    span = max(ranks) - min(ranks)
    if ascents == 0 or span == 0:
        return 0.0, (f"{len(off)} offensive/recon sessions, no upward stage "
                     f"transition (no arc)")
    max_rank = max(ESCALATION_RANK.values())
    climbed = span / max_rank if max_rank else 0.0
    vol = _intensity(len(off), OFFENSIVE_TRAJECTORY_MIN)
    inten = min(1.0, climbed * (0.6 + 0.4 * vol))
    return inten, (f"{ascents} upward stage transition(s) spanning {span} of "
                   f"{max_rank} escalation levels, in time order")


def _baseline_drift(sessions) -> tuple[float, str]:
    """Within-account divergence: the stolen-key signature. Compares the tail
    of activity against the head on country and category. No cross-account
    data - this is an account turning on its own history."""
    if len(sessions) < DRIFT_MIN_BASELINE + 2:
        return 0.0, ""
    ordered = sorted(sessions, key=lambda s: s["ts"])
    head = ordered[:len(ordered) // 2]
    tail = ordered[len(ordered) // 2:]
    head_countries = {s["country"] for s in head}
    tail_countries = {s["country"] for s in tail}
    head_cats = {s["category"] for s in head}
    tail_cats = {s["category"] for s in tail}
    geo_shift = bool(tail_countries - head_countries)
    cat_shift = bool(tail_cats - head_cats) and not (tail_cats & head_cats)
    if geo_shift and cat_shift:
        return 1.0, (f"usage flipped {sorted(head_countries)}->"
                     f"{sorted(tail_countries)} and "
                     f"{sorted(head_cats)}->{sorted(tail_cats)} mid-history")
    if geo_shift or cat_shift:
        return 0.5, "partial divergence from own baseline"
    return 0.0, ""


def _automation_cadence(account, sessions) -> tuple[float, str]:
    api = [s for s in sessions if s["channel"] == "api"]
    if len(api) < 3:
        return 0.0, ""
    times = sorted(_minutes(s["ts"]) for s in api)
    gaps = [b - a for a, b in zip(times, times[1:])]
    if not gaps:
        return 0.0, ""
    mean = sum(gaps) / len(gaps)
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    std = var ** 0.5
    regular = std <= CADENCE_TOLERANCE_MIN
    vol = _intensity(len(api), HIGH_VOLUME_SESSIONS)
    if not regular:
        return 0.4 * vol, f"{len(api)} API calls, irregular cadence"
    return vol, (f"{len(api)} API calls on a near-fixed "
                 f"~{mean:.0f}min interval (std {std:.1f})")


def _burner_infra(account) -> tuple[float, str]:
    score, why = 0.0, []
    if account["email_kind"] in RISKY_EMAIL:
        score += 0.4; why.append("disposable email")
    if not account["phone_verified"]:
        score += 0.2; why.append("no phone verification")
    if account["payment"] in RISKY_PAYMENTS:
        score += 0.2; why.append(f"{account['payment']} payment")
    if account["signup_asn"] in HIGHER_RISK_ASNS:
        score += 0.3; why.append(f"higher-risk ASN {account['signup_asn']}")
    return min(1.0, score), ", ".join(why)


def _refusal_farming(sessions) -> tuple[float, str]:
    """Fraction of sessions the platform refused, as a proxy for boundary
    probing.

    UNFLOORED-RATIO WARNING (finding #21). This is a bare point estimate with
    no minimum denominator, unlike `_baseline_drift` (needs 6 sessions) and
    `_automation_cadence` (needs 3). One refusal in one session yields frac
    1.0, intensity 1.0 and a 0.10 contribution - which clears
    `policy.CORROBORATION_MIN_CONTRIBUTION`, so a single declined request can
    supply the non-content corroboration that rule 2 requires before an account
    can be actioned. The median account in this dataset has 3 sessions.

    "Farming" is a claim about repetition; a rate from one observation cannot
    support it. This is the argument `src/prevalence.py` already makes about
    the project's own evaluation metrics - a count is not a rate - which had
    never been turned on the scorer. `_refusal_farming_wilson` is the variant
    that applies it; `stress_sensitivity.py` measures the difference."""
    if not sessions:
        return 0.0, ""
    refused = sum(1 for s in sessions if s["disposition"] == "refused")
    frac = refused / len(sessions)
    if frac < REFUSAL_FARMING_MIN:
        return 0.0, ""
    return min(1.0, frac / 0.5), f"{refused}/{len(sessions)} sessions refused"


def _refusal_farming_wilson(sessions) -> tuple[float, str]:
    """As above, but the intensity is the Wilson 95% LOWER bound on the refusal
    rate rather than the point estimate - so a rate measured on one session
    carries the uncertainty of one session instead of being read at face value.

    Reuses `prevalence.wilson` rather than restating the interval arithmetic,
    because a constant that pins a definition does nothing if a call site
    restates it (this repo's recurring bug, now in its fifth costume)."""
    from .prevalence import wilson
    if not sessions:
        return 0.0, ""
    refused = sum(1 for s in sessions if s["disposition"] == "refused")
    lo, _ = wilson(refused, len(sessions))
    if lo < REFUSAL_FARMING_MIN:
        return 0.0, ""
    return min(1.0, lo / 0.5), (f"{refused}/{len(sessions)} sessions refused "
                                f"(Wilson lower bound {lo:.2f})")


def _target_fixation(sessions) -> tuple[float, str]:
    targets = [s["target_ref"] for s in sessions if s.get("target_ref")]
    if not targets:
        return 0.0, ""
    top, n = Counter(targets).most_common(1)[0]
    if n < 2:
        return 0.0, ""
    return min(1.0, n / 6), f"{n} sessions referencing '{top}'"


def _content_category_risk(sessions) -> tuple[float, str]:
    """The weak signal, kept for completeness. High-risk *topic* concentration.
    On its own it fires just as hard for the red-teamer and the trainer as for
    the actor - which is exactly why its weight is 0.06.

    Also an unfloored ratio (see `_refusal_farming`), though the consequence is
    milder: it is excluded from `policy.CORROBORATING_SIGNALS`, so it cannot
    supply corroboration however hard it fires."""
    if not sessions:
        return 0.0, ""
    risky = sum(1 for s in sessions
                if s["category"] in OFFENSIVE_CATEGORIES | RECON_CATEGORIES)
    frac = risky / len(sessions)
    if frac == 0:
        return 0.0, ""
    return frac, f"{risky}/{len(sessions)} sessions in high-risk topics"


def _content_category_risk_wilson(sessions) -> tuple[float, str]:
    """Wilson-lower-bound variant of the topic-concentration ratio."""
    from .prevalence import wilson
    if not sessions:
        return 0.0, ""
    risky = sum(1 for s in sessions
                if s["category"] in OFFENSIVE_CATEGORIES | RECON_CATEGORIES)
    if risky == 0:
        return 0.0, ""
    lo, _ = wilson(risky, len(sessions))
    return lo, (f"{risky}/{len(sessions)} sessions in high-risk topics "
                f"(Wilson lower bound {lo:.2f})")


# Uniform dispatch table: signal name -> (account, sessions) -> (intensity,
# detail). Every implementation takes the same two arguments whether or not it
# uses both, so a harness can substitute one without knowing its shape.
SIGNAL_IMPLS = {
    "capability_trajectory": lambda a, s: _capability_trajectory(s),
    "baseline_drift":        lambda a, s: _baseline_drift(s),
    "automation_cadence":    lambda a, s: _automation_cadence(a, s),
    "burner_infra":          lambda a, s: _burner_infra(a),
    "refusal_farming":       lambda a, s: _refusal_farming(s),
    "target_fixation":       lambda a, s: _target_fixation(s),
    "content_category_risk": lambda a, s: _content_category_risk(s),
}

# Named alternatives a harness can inject. Kept OUT of SIGNAL_IMPLS so that
# importing this module can never silently change what the pipeline scores -
# the same discipline as `attribute.build_actors(extra=...)`: an experimental
# channel is injected by the harness that measures it, never enabled by a flag
# that someone could leave on.
SIGNAL_VARIANTS = {
    "capability_arc":              lambda a, s: _capability_arc(s),
    "refusal_farming_wilson":      lambda a, s: _refusal_farming_wilson(s),
    "content_category_risk_wilson": lambda a, s: _content_category_risk_wilson(s),
}

# Signals whose intensity is a RATE over sessions rather than a fact about the
# account. A rate carries a sample size; a fact does not. `burner_infra` is the
# contrast: an account either has a disposable email or it does not, and one
# observation is the whole truth, so no denominator applies to it.
#
# The distinction exists because `policy.py` gates enforcement on corroborating
# signals, and a rate computed from one session is not evidence of the pattern
# its name claims - "farming" asserts repetition. See finding #21.
RATE_DERIVED_SIGNALS = {"refusal_farming", "content_category_risk"}


def _observations(name: str, sessions) -> int | None:
    """Denominator behind a rate-derived signal; None for account-level facts."""
    return len(sessions) if name in RATE_DERIVED_SIGNALS else None


# Signals that are topic-derived. This is `src/policy.py`'s definition, hoisted
# here so the two modules cannot drift apart again: policy excludes exactly
# these from non-content corroboration because "both are topic-derived, and
# topic is dual-use", while this module's weights assign them 0.28 of the risk
# score and the README's hero chart calls content 0.06. Finding #20 is that
# disagreement. Stating the set once, where the weights live, is what stops a
# call site restating it.
TOPIC_DERIVED_SIGNALS = {"content_category_risk", "capability_trajectory"}


def topic_share(weights: dict | None = None) -> float:
    """Fraction of the risk score that is topic-derived under policy.py's own
    definition. 0.28 as shipped, against the 0.06 the hero chart reports."""
    W = WEIGHTS if weights is None else weights
    return sum(W[t] for t in TOPIC_DERIVED_SIGNALS if t in W)


def score_account(account: dict, sessions: list[dict],
                  weights: dict | None = None,
                  impls: dict | None = None) -> dict:
    """Return the full signal breakdown and weighted risk score for one account.

    The breakdown is the product, not the scalar: a threat-intel analyst needs
    to see *which* behaviors fired, so every downstream layer (lead review,
    investigation prompt, enforcement rationale) is explainable from here.

    `weights` and `impls` are measurement-only overrides, defaulting to the
    shipped values so every existing call site is unchanged. They exist so
    `stress_sensitivity.py` can ablate a signal or substitute a variant without
    mutating module state - an earlier version of that harness monkey-patched
    `WEIGHTS` in place, which works until two measurements run in one process.
    """
    W = WEIGHTS if weights is None else weights
    F = SIGNAL_IMPLS if impls is None else impls
    computed = {name: F[name](account, sessions) for name in W}
    signals = []
    risk = 0.0
    for name, (intensity, detail) in computed.items():
        contribution = W[name] * intensity
        risk += contribution
        if intensity > 0:
            signals.append({
                "signal": name,
                "intensity": round(intensity, 3),
                "weight": W[name],
                "contribution": round(contribution, 4),
                # How many observations back this signal. None for account-level
                # facts, which are not rates. The enforcement gate reads it:
                # strength is not sample size, and a rate from one session
                # cannot corroborate. See policy.CORROBORATION_MIN_OBSERVATIONS.
                "n_observations": _observations(name, sessions),
                "detail": detail,
            })
    signals.sort(key=lambda s: -s["contribution"])
    return {
        "account_id": account["account_id"],
        "risk_score": round(risk, 4),
        "is_lead": risk >= LEAD_THRESHOLD,
        "signals": signals,
        "content_only_score": round(
            W.get("content_category_risk", 0.0)
            * computed.get("content_category_risk", (0.0, ""))[0], 4),
        # The same account's topic-derived total under policy.py's definition.
        # Reported alongside content_only_score precisely because the two
        # disagree; finding #20 is what that disagreement costs.
        "topic_derived_score": round(
            sum(W.get(t, 0.0) * computed.get(t, (0.0, ""))[0]
                for t in TOPIC_DERIVED_SIGNALS), 4),
    }
