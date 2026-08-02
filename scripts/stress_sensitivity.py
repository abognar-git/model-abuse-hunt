"""Finding #20/#21: what the risk score is actually made of, and how hard you
have to push it before it changes its mind.

Every other harness in this repo attacks the pipeline from outside - a cover
story, a purchased proxy, a forged field. This one attacks the *scorer's own
arithmetic*, which nothing had ever done, and it turns up two things.

**#20, the definitional split.** The project's headline claim is that content is
0.06 of the risk score and behavior/infrastructure are 0.94. That is true under
the definition the README's hero chart uses, where "content" means the
`content_category_risk` signal alone. But `src/policy.py` carries a *second*
definition, written down explicitly: it excludes `capability_trajectory` AND
`content_category_risk` from non-content corroboration because "both are
topic-derived, and topic is dual-use". Under that definition - the repo's own,
in the module that guards enforcement - the topic-derived share is 0.06 + 0.22
= **0.28**, and `capability_trajectory` is the single largest weight in the
vector.

It is not a labelling quibble, for two reasons this harness measures:

  1. The implementation backs policy.py. `_capability_trajectory` reads no
     timestamp and imposes no order - `distinct` is a set cardinality over
     categories. It is named for a behavior over time and computes topic
     breadth. `_capability_arc` is the ordered variant that would earn the
     name, and EXPERIMENT C measures whether requiring order keeps the
     detections.

  2. Ablation says it is load-bearing. Zeroing it costs more malicious leads
     than zeroing any behavioral signal except `burner_infra`.

**#21, the unfloored ratios.** `_refusal_farming` is a bare point estimate over
sessions with no minimum denominator, unlike `_baseline_drift` (needs 6) and
`_automation_cadence` (needs 3). One refusal in one session scores intensity
1.0 and contributes 0.10 - which clears `policy.CORROBORATION_MIN_CONTRIBUTION`,
so a single declined request can supply the non-content corroboration rule 2
demands before an account can be actioned. The median account here has 3
sessions. This is the argument `src/prevalence.py` already makes about the
project's evaluation metrics - a count is not a rate - which had never been
turned on the scorer. EXPERIMENT D applies it.

Experiments:
  A  topic share, per account, under both definitions
  B  leave-one-signal-out ablation over the lead layer
  C  weight-perturbation margins + the temporal-arc variant
  D  Wilson-floored ratio variants
  E  lead-threshold sweep (reported as a LIMIT, not a tuning - see below)

A note on E. The sweep shows the shipped 0.25 threshold is dominated by 0.24 on
this dataset: same benign leads, one more malicious. This harness deliberately
does NOT change it. Tuning a threshold on the same 23 accounts you report your
metrics over is overfitting, and the honest reading of a 0.002 margin is that
any threshold choice at this sample size is noise. The number is published as a
limitation.

Fully offline and deterministic. No model is called; no API cost.

Usage:
    python -m scripts.stress_sensitivity
    python -m scripts.stress_sensitivity --readme-table
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src import signals
from src.attribute import build_actors
from src.hunt import load

DATA = Path(__file__).resolve().parent.parent / "data"

# Perturbation grid for EXPERIMENT C, in percent of a weight's shipped value.
PERTURBATION_PCT = range(1, 101)

# Lead-line positions swept in EXPERIMENT E.
THRESHOLD_GRID = [0.18, 0.20, 0.22, 0.24, 0.25, 0.26, 0.28, 0.30, 0.34]


def _truth():
    return {json.loads(l)["account_id"]: json.loads(l)
            for l in open(DATA / "ground_truth.jsonl")}


def _score(accounts, sessions, weights=None, impls=None, thresh=None):
    """Score every account, optionally under overridden weights/impls, and
    apply a threshold without touching module state."""
    t = signals.LEAD_THRESHOLD if thresh is None else thresh
    out = {}
    for aid in accounts:
        r = signals.score_account(accounts[aid], sessions.get(aid, []),
                                  weights=weights, impls=impls)
        r["is_lead"] = r["risk_score"] >= t
        out[aid] = r
    return out


def _confusion(scored, gt, clusters=None):
    """Malicious surfaced / benign surfaced. `surfaced` mirrors evaluate.py:
    a lead OR a member of an attributed cluster, because attribution rescues
    accounts the lead layer misses."""
    clustered = {a for c in (clusters or []) for a in c}
    leads = {a for a, r in scored.items() if r["is_lead"]}
    surfaced = leads | clustered
    mal = [a for a in gt if gt[a]["label"] == "malicious"]
    ben = [a for a in gt if gt[a]["label"] == "benign"]
    return {
        "malicious_leads": sum(1 for a in mal if a in leads),
        "malicious_total": len(mal),
        "benign_leads": sum(1 for a in ben if a in leads),
        "benign_total": len(ben),
        "malicious_surfaced": sum(1 for a in mal if a in surfaced),
    }


# ------------------------------------------------------------------ EXPERIMENT A
def experiment_a(accounts, sessions, gt):
    """Topic share per account under both definitions."""
    scored = _score(accounts, sessions)
    rows = []
    for aid, r in scored.items():
        risk = r["risk_score"]
        rows.append({
            "account_id": aid,
            "label": gt[aid]["label"],
            "risk_score": risk,
            "hero_content_score": r["content_only_score"],
            "policy_topic_score": r["topic_derived_score"],
            "topic_share_of_risk": round(r["topic_derived_score"] / risk, 4)
            if risk else 0.0,
        })
    rows.sort(key=lambda x: -x["risk_score"])
    hard_negs = [r for r in rows
                 if r["label"] == "benign" and r["risk_score"] > 0]
    return {
        "weight_topic_share_policy_definition": signals.topic_share(),
        "weight_topic_share_hero_definition":
            signals.WEIGHTS["content_category_risk"],
        "accounts": rows,
        "hard_negative_topic_shares": {
            r["account_id"]: r["topic_share_of_risk"] for r in hard_negs},
        "max_hard_negative_topic_share": max(
            (r["topic_share_of_risk"] for r in hard_negs), default=0.0),
    }


# ------------------------------------------------------------------ EXPERIMENT B
def experiment_b(accounts, sessions, gt, clusters):
    """Leave-one-signal-out ablation over the lead layer."""
    base = _score(accounts, sessions)
    base_conf = _confusion(base, gt, clusters)
    rows = []
    for name in signals.WEIGHTS:
        w = dict(signals.WEIGHTS)
        w[name] = 0.0
        pert = _score(accounts, sessions, weights=w)
        conf = _confusion(pert, gt, clusters)
        flips = [{"account_id": a, "label": gt[a]["label"],
                  "was_lead": base[a]["is_lead"], "now_lead": pert[a]["is_lead"]}
                 for a in accounts if base[a]["is_lead"] != pert[a]["is_lead"]]
        rows.append({
            "signal": name,
            "weight": signals.WEIGHTS[name],
            "topic_derived": name in signals.TOPIC_DERIVED_SIGNALS,
            "malicious_leads_lost":
                base_conf["malicious_leads"] - conf["malicious_leads"],
            "benign_leads_gained":
                conf["benign_leads"] - base_conf["benign_leads"],
            "total_flips": len(flips),
            "flips": flips,
        })
    rows.sort(key=lambda r: (-r["malicious_leads_lost"], -r["weight"]))
    dead = [r["signal"] for r in rows if r["total_flips"] == 0]
    return {
        "baseline": base_conf,
        "ablations": rows,
        "inert_signals": dead,
        "inert_weight_total": round(
            sum(signals.WEIGHTS[s] for s in dead), 4),
    }


# ------------------------------------------------------------------ EXPERIMENT C
def experiment_c(accounts, sessions, gt, clusters):
    """Weight-perturbation margins, plus the temporal-arc variant."""
    base = _score(accounts, sessions)
    base_conf = _confusion(base, gt, clusters)

    margins = []
    for aid, r in base.items():
        margins.append({
            "account_id": aid, "label": gt[aid]["label"],
            "risk_score": r["risk_score"],
            "distance_to_line": round(r["risk_score"] - signals.LEAD_THRESHOLD, 4),
        })
    margins.sort(key=lambda m: abs(m["distance_to_line"]))

    perturb = []
    for name in signals.WEIGHTS:
        w0 = signals.WEIGHTS[name]
        first = None
        for pct in PERTURBATION_PCT:
            for sgn in (+1, -1):
                w = dict(signals.WEIGHTS)
                w[name] = max(0.0, w0 * (1 + sgn * pct / 100))
                pert = _score(accounts, sessions, weights=w)
                fl = [a for a in accounts
                      if base[a]["is_lead"] != pert[a]["is_lead"]]
                if fl:
                    first = {"pct": sgn * pct,
                             "flipped": [{"account_id": a,
                                          "label": gt[a]["label"]} for a in fl]}
                    break
            if first:
                break
        perturb.append({"signal": name, "weight": w0,
                        "first_flip": first})

    # The arc variant: same weight, ordered implementation.
    impls = dict(signals.SIGNAL_IMPLS)
    impls["capability_trajectory"] = signals.SIGNAL_VARIANTS["capability_arc"]
    arc = _score(accounts, sessions, impls=impls)
    arc_conf = _confusion(arc, gt, clusters)
    arc_rows = []
    for aid in accounts:
        b, a = base[aid], arc[aid]
        if b["risk_score"] != a["risk_score"]:
            arc_rows.append({
                "account_id": aid, "label": gt[aid]["label"],
                "breadth_risk": b["risk_score"], "arc_risk": a["risk_score"],
                "breadth_lead": b["is_lead"], "arc_lead": a["is_lead"],
            })
    arc_rows.sort(key=lambda r: -r["breadth_risk"])
    return {
        "margins": margins,
        "closest_account": margins[0],
        "weight_perturbation": perturb,
        "arc_variant": {
            "baseline": base_conf,
            "arc": arc_conf,
            "changed_accounts": arc_rows,
            "malicious_leads_delta":
                arc_conf["malicious_leads"] - base_conf["malicious_leads"],
            "benign_leads_delta":
                arc_conf["benign_leads"] - base_conf["benign_leads"],
        },
    }


# ------------------------------------------------------------------ EXPERIMENT D
def derive_observation_floor() -> dict:
    """Derive `policy.CORROBORATION_MIN_OBSERVATIONS` rather than pick it.

    A rate-derived signal should only be allowed to corroborate once its
    estimate can actually distinguish the pattern it names from a single
    unlucky draw. Criterion: for a maximally-refusing account (k = n), the
    Wilson 95% lower bound must clear REFUSAL_FARMING_MIN by more than the
    interval's own half-width. Below that point the interval is wider than the
    effect it is being asked to establish.

    The constant in policy.py is asserted against this function, so the two
    cannot drift - restating a definition at a call site is this repo's
    recurring bug, and a "derived" constant that nothing re-derives is the
    same bug with better manners."""
    from src.prevalence import wilson
    rows = []
    chosen = None
    for n in range(1, 13):
        lo, hi = wilson(n, n)
        half = (hi - lo) / 2
        margin = lo - signals.REFUSAL_FARMING_MIN
        ok = margin > half
        rows.append({"n": n, "wilson_low": round(lo, 4),
                     "half_width": round(half, 4),
                     "margin_over_threshold": round(margin, 4),
                     "sufficient": ok})
        if ok and chosen is None:
            chosen = n
    return {"criterion": "wilson_low(n,n) - REFUSAL_FARMING_MIN > half_width",
            "threshold_tested": signals.REFUSAL_FARMING_MIN,
            "derived_floor": chosen, "grid": rows}


def _matched_operating_point(accounts, sessions, gt, clusters, impls,
                             target_benign_leads):
    """Lowest threshold whose benign-lead count does not exceed the shipped
    configuration's. Comparing two scorers at one fixed threshold is unfair
    when one of them systematically rescales every score downward - the Wilson
    variants do, so the fixed-threshold comparison conflates "more honest
    signal" with "everything shrank". This finds the like-for-like point."""
    best = None
    for t in [round(x / 200, 3) for x in range(1, 71)]:      # 0.005 .. 0.35
        conf = _confusion(_score(accounts, sessions, impls=impls, thresh=t),
                          gt, clusters)
        if conf["benign_leads"] <= target_benign_leads:
            if best is None or conf["malicious_leads"] > best["malicious_leads"]:
                best = {"threshold": t, **conf}
    return best


def experiment_d(accounts, sessions, gt, clusters):
    """Wilson-floored ratio variants against the shipped point estimates.

    Three configurations, because the surgical fix and the sweeping one are
    different claims. The soundness bug is specifically that `refusal_farming`
    is a CORROBORATING signal that can clear the corroboration floor off a
    single observation; `content_category_risk` cannot corroborate at all
    (policy excludes it), so flooring that one only rescales the score."""
    from src import policy
    base = _score(accounts, sessions)
    base_conf = _confusion(base, gt, clusters)

    impls_refusal = dict(signals.SIGNAL_IMPLS)
    impls_refusal["refusal_farming"] = \
        signals.SIGNAL_VARIANTS["refusal_farming_wilson"]

    impls_both = dict(impls_refusal)
    impls_both["content_category_risk"] = \
        signals.SIGNAL_VARIANTS["content_category_risk_wilson"]

    wil = _score(accounts, sessions, impls=impls_both)
    wil_conf = _confusion(wil, gt, clusters)
    ref_only = _score(accounts, sessions, impls=impls_refusal)
    ref_only_conf = _confusion(ref_only, gt, clusters)

    def corroborators(scored_row):
        return sorted(s["signal"] for s in scored_row["signals"]
                      if s["signal"] in policy.CORROBORATING_SIGNALS
                      and s["contribution"] >= policy.CORROBORATION_MIN_CONTRIBUTION)

    rows = []
    for aid in accounts:
        b, w = base[aid], wil[aid]
        cb, cw = corroborators(b), corroborators(w)
        if b["risk_score"] != w["risk_score"] or cb != cw:
            rows.append({
                "account_id": aid, "label": gt[aid]["label"],
                "sessions": len(sessions.get(aid, [])),
                "point_risk": b["risk_score"], "wilson_risk": w["risk_score"],
                "point_lead": b["is_lead"], "wilson_lead": w["is_lead"],
                "point_corroborators": cb, "wilson_corroborators": cw,
            })
    rows.sort(key=lambda r: -r["point_risk"])

    # Accounts whose ONLY corroborating signal was refusal_farming: these are
    # the ones where a single declined request was the whole of rule 2's
    # non-content requirement.
    sole_refusal = [
        {"account_id": aid, "label": gt[aid]["label"],
         "sessions": len(sessions.get(aid, [])),
         "refusals": sum(1 for s in sessions.get(aid, [])
                         if s["disposition"] == "refused")}
        for aid in accounts
        if corroborators(base[aid]) == ["refusal_farming"]]

    matched_both = _matched_operating_point(
        accounts, sessions, gt, clusters, impls_both, base_conf["benign_leads"])
    matched_refusal = _matched_operating_point(
        accounts, sessions, gt, clusters, impls_refusal,
        base_conf["benign_leads"])

    floor = derive_observation_floor()
    assert floor["derived_floor"] == policy.CORROBORATION_MIN_OBSERVATIONS, (
        f"policy.CORROBORATION_MIN_OBSERVATIONS is "
        f"{policy.CORROBORATION_MIN_OBSERVATIONS} but the criterion derives "
        f"{floor['derived_floor']} - one of them moved without the other")

    # Which accounts the gate-level floor actually disarms: rate-derived
    # corroborators that clear the strength floor but not the sample floor.
    thin = []
    for aid in accounts:
        for s in base[aid]["signals"]:
            n = s.get("n_observations")
            if (s["signal"] in policy.CORROBORATING_SIGNALS
                    and s["contribution"] >= policy.CORROBORATION_MIN_CONTRIBUTION
                    and n is not None
                    and n < policy.CORROBORATION_MIN_OBSERVATIONS):
                thin.append({"account_id": aid, "label": gt[aid]["label"],
                             "signal": s["signal"], "n_observations": n,
                             "contribution": s["contribution"]})

    # The constructed minimal case: how few sessions can supply corroboration?
    synth = {"account_id": "synthetic_minimal", "signup_ip": "192.0.2.9",
             "signup_asn": "AS64510", "payment": "card",
             "email_kind": "corporate", "phone_verified": True}
    one = [{"ts": "2026-07-12T09:31:00Z", "category": "malware_dev",
            "disposition": "refused", "channel": "web", "country": "DE",
            "target_ref": None}]
    minimal_point = signals.score_account(synth, one)
    minimal_wilson = signals.score_account(synth, one, impls=impls_refusal)
    return {
        "baseline": base_conf,
        "wilson": wil_conf,
        "wilson_refusal_only": ref_only_conf,
        "matched_operating_point": {
            "note": "lowest-threshold configuration whose benign-lead count "
                    "does not exceed the shipped one's; the fair comparison "
                    "when a variant rescales every score",
            "shipped": base_conf,
            "wilson_both": matched_both,
            "wilson_refusal_only": matched_refusal,
        },
        "sole_refusal_corroborated": sole_refusal,
        "observation_floor": floor,
        "thin_corroborators_disarmed": thin,
        "changed_accounts": rows,
        "session_count_median": sorted(
            len(sessions.get(a, [])) for a in accounts)[len(accounts) // 2],
        "minimal_case": {
            "description": "one session, one refusal, clean infrastructure",
            "point_estimate": {
                "risk": minimal_point["risk_score"],
                "refusal_contribution": next(
                    (s["contribution"] for s in minimal_point["signals"]
                     if s["signal"] == "refusal_farming"), 0.0)},
            "wilson": {
                "risk": minimal_wilson["risk_score"],
                "refusal_contribution": next(
                    (s["contribution"] for s in minimal_wilson["signals"]
                     if s["signal"] == "refusal_farming"), 0.0)},
            "corroboration_floor": policy.CORROBORATION_MIN_CONTRIBUTION,
        },
    }


# ------------------------------------------------------------------ EXPERIMENT E
def experiment_e(accounts, sessions, gt, clusters):
    """Lead-threshold sweep. Reported as a limit, never applied."""
    rows = []
    for t in THRESHOLD_GRID:
        conf = _confusion(_score(accounts, sessions, thresh=t), gt, clusters)
        rows.append({"threshold": t, "shipped": t == signals.LEAD_THRESHOLD,
                     **conf})
    shipped = next(r for r in rows if r["shipped"])
    dominating = [r for r in rows
                  if r["malicious_leads"] > shipped["malicious_leads"]
                  and r["benign_leads"] <= shipped["benign_leads"]]
    return {"sweep": rows, "shipped": shipped,
            "dominating_thresholds": [r["threshold"] for r in dominating]}


# ------------------------------------------------------------------ reporting
def analyse() -> dict:
    accounts, sessions = load()
    gt = _truth()
    clusters, _ = build_actors(accounts, sessions)
    return {
        "dataset": {"accounts": len(accounts), "clusters": len(clusters)},
        "a_topic_share": experiment_a(accounts, sessions, gt),
        "b_ablation": experiment_b(accounts, sessions, gt, clusters),
        "c_margins": experiment_c(accounts, sessions, gt, clusters),
        "d_wilson": experiment_d(accounts, sessions, gt, clusters),
        "e_threshold": experiment_e(accounts, sessions, gt, clusters),
    }


def readme_table(r: dict) -> str:
    """Emitted, never hand-transcribed. The Phase B lesson: prose drifts from
    the artifact the moment a human retypes a number."""
    L = []
    a, b, c, d, e = (r["a_topic_share"], r["b_ablation"], r["c_margins"],
                     r["d_wilson"], r["e_threshold"])
    L.append("| Signal | Weight | Topic-derived? | Malicious leads lost if zeroed |")
    L.append("|---|---|---|---|")
    for row in b["ablations"]:
        L.append(f"| `{row['signal']}` | {row['weight']:.2f} | "
                 f"{'**yes**' if row['topic_derived'] else 'no'} | "
                 f"{row['malicious_leads_lost']} |")
    L.append("")
    L.append(f"Topic-derived share of the risk score: "
             f"**{a['weight_topic_share_policy_definition']:.2f}** under "
             f"`policy.py`'s definition, **"
             f"{a['weight_topic_share_hero_definition']:.2f}** under the hero "
             f"chart's.")
    L.append("")
    L.append("| Hard negative | Topic share of its risk score |")
    L.append("|---|---|")
    for aid, share in sorted(a["hard_negative_topic_shares"].items(),
                             key=lambda kv: -kv[1]):
        L.append(f"| `{aid}` | {share:.0%} |")
    L.append("")
    cl = c["closest_account"]
    L.append(f"Closest account to the lead line: `{cl['account_id']}` "
             f"({cl['label']}) at {cl['risk_score']:.3f}, "
             f"**{abs(cl['distance_to_line']):.3f}** from the line.")
    arc = c["arc_variant"]
    L.append(f"Ordered-arc variant: malicious leads "
             f"{arc['baseline']['malicious_leads']} -> "
             f"{arc['arc']['malicious_leads']}, benign leads "
             f"{arc['baseline']['benign_leads']} -> "
             f"{arc['arc']['benign_leads']}.")
    L.append(f"Inert signals (zeroing changes nothing): "
             + (", ".join(f"`{s}`" for s in b["inert_signals"]) or "none")
             + f" - {b['inert_weight_total']:.2f} of the weight vector.")
    m = d["minimal_case"]
    L.append(f"Minimal corroborating account ({m['description']}): "
             f"refusal contributes {m['point_estimate']['refusal_contribution']:.3f} "
             f"as a point estimate against a {m['corroboration_floor']} floor, "
             f"{m['wilson']['refusal_contribution']:.3f} under Wilson.")
    L.append(f"Thresholds dominating the shipped {e['shipped']['threshold']}: "
             + (", ".join(str(t) for t in e["dominating_thresholds"])
                or "none") + " (measured, deliberately not applied).")
    return "\n".join(L)


def render(r: dict) -> str:
    L = []
    a, b, c, d, e = (r["a_topic_share"], r["b_ablation"], r["c_margins"],
                     r["d_wilson"], r["e_threshold"])
    L.append("=== A. topic share: two definitions in one repo ===")
    L.append(f"  policy.py definition (content + capability_trajectory): "
             f"{a['weight_topic_share_policy_definition']:.2f}")
    L.append(f"  hero-chart definition (content only):                   "
             f"{a['weight_topic_share_hero_definition']:.2f}")
    L.append("  hard negatives, share of risk that is topic-derived:")
    for aid, share in sorted(a["hard_negative_topic_shares"].items(),
                             key=lambda kv: -kv[1]):
        L.append(f"    {aid:26s} {share:6.0%}")

    L.append("\n=== B. leave-one-signal-out ablation (lead layer) ===")
    for row in b["ablations"]:
        tag = "TOPIC" if row["topic_derived"] else "     "
        L.append(f"  zero {row['signal']:24s} w={row['weight']:.2f} {tag} "
                 f"-> malicious leads lost {row['malicious_leads_lost']}, "
                 f"benign gained {row['benign_leads_gained']}")
    L.append(f"  inert: {b['inert_signals']} "
             f"({b['inert_weight_total']:.2f} of the weight vector)")

    L.append("\n=== C. margins, perturbation, and the ordered-arc variant ===")
    for m in c["margins"][:4]:
        L.append(f"  {m['account_id']:26s} risk {m['risk_score']:.3f} "
                 f"dist {m['distance_to_line']:+.3f} [{m['label']}]")
    for p in c["weight_perturbation"]:
        f = p["first_flip"]
        L.append(f"  {p['signal']:24s} first flip at "
                 + (f"{f['pct']:+d}% -> "
                    f"{[x['account_id'] for x in f['flipped']]}"
                    if f else "no flip within +/-100%"))
    arc = c["arc_variant"]
    L.append(f"  ARC VARIANT: malicious leads "
             f"{arc['baseline']['malicious_leads']}->"
             f"{arc['arc']['malicious_leads']}, benign leads "
             f"{arc['baseline']['benign_leads']}->{arc['arc']['benign_leads']}")
    for row in arc["changed_accounts"]:
        L.append(f"    {row['account_id']:26s} {row['breadth_risk']:.3f} -> "
                 f"{row['arc_risk']:.3f}  lead {row['breadth_lead']}->"
                 f"{row['arc_lead']} [{row['label']}]")

    L.append("\n=== D. unfloored ratios vs Wilson lower bound ===")
    L.append(f"  median sessions/account: {d['session_count_median']}")
    m = d["minimal_case"]
    L.append(f"  minimal case ({m['description']}):")
    L.append(f"    point estimate: risk {m['point_estimate']['risk']:.3f}, "
             f"refusal contributes "
             f"{m['point_estimate']['refusal_contribution']:.3f} "
             f"(floor {m['corroboration_floor']})")
    L.append(f"    wilson:         risk {m['wilson']['risk']:.3f}, "
             f"refusal contributes {m['wilson']['refusal_contribution']:.3f}")
    L.append(f"  at the SHIPPED threshold (unfair - Wilson rescales "
             f"everything down):")
    L.append(f"    both ratios:   malicious leads "
             f"{d['baseline']['malicious_leads']}->"
             f"{d['wilson']['malicious_leads']}, benign "
             f"{d['baseline']['benign_leads']}->{d['wilson']['benign_leads']}, "
             f"surfaced {d['baseline']['malicious_surfaced']}->"
             f"{d['wilson']['malicious_surfaced']}")
    L.append(f"    refusal only:  malicious leads "
             f"{d['baseline']['malicious_leads']}->"
             f"{d['wilson_refusal_only']['malicious_leads']}, benign "
             f"{d['baseline']['benign_leads']}->"
             f"{d['wilson_refusal_only']['benign_leads']}, surfaced "
             f"{d['baseline']['malicious_surfaced']}->"
             f"{d['wilson_refusal_only']['malicious_surfaced']}")
    mo = d["matched_operating_point"]
    L.append(f"  at a MATCHED operating point (same benign-lead budget):")
    for k in ("wilson_both", "wilson_refusal_only"):
        m = mo[k]
        if m:
            L.append(f"    {k:20s} thresh {m['threshold']:.3f}: malicious "
                     f"leads {m['malicious_leads']}/{m['malicious_total']}, "
                     f"benign {m['benign_leads']}/{m['benign_total']}, "
                     f"surfaced {m['malicious_surfaced']}")
    L.append(f"    {'shipped':20s} thresh "
             f"{signals.LEAD_THRESHOLD:.3f}: malicious leads "
             f"{d['baseline']['malicious_leads']}/"
             f"{d['baseline']['malicious_total']}, benign "
             f"{d['baseline']['benign_leads']}/{d['baseline']['benign_total']}"
             f", surfaced {d['baseline']['malicious_surfaced']}")
    fl = d["observation_floor"]
    L.append(f"  observation floor derived from "
             f"'{fl['criterion']}': n >= {fl['derived_floor']}")
    for g in fl["grid"][:6]:
        L.append(f"    n={g['n']:2d} wilson_low {g['wilson_low']:.3f} "
                 f"half-width {g['half_width']:.3f} margin "
                 f"{g['margin_over_threshold']:+.3f} "
                 f"{'SUFFICIENT' if g['sufficient'] else 'interval wider than effect'}")
    if d["thin_corroborators_disarmed"]:
        L.append("  rate-derived corroborators the gate floor disarms:")
        for t in d["thin_corroborators_disarmed"]:
            L.append(f"    {t['account_id']:26s} {t['signal']} "
                     f"n={t['n_observations']} contrib {t['contribution']:.3f} "
                     f"[{t['label']}]")
    else:
        L.append("  no rate-derived corroborator on this dataset falls below "
                 "the sample floor")
    if d["sole_refusal_corroborated"]:
        L.append("  accounts whose ONLY corroborator was refusal_farming:")
        for s in d["sole_refusal_corroborated"]:
            L.append(f"    {s['account_id']:26s} {s['refusals']}/"
                     f"{s['sessions']} refused [{s['label']}]")
    else:
        L.append("  no account relied on refusal_farming as its sole "
                 "corroborator on this dataset")
    for row in d["changed_accounts"]:
        L.append(f"    {row['account_id']:26s} n={row['sessions']:2d} "
                 f"{row['point_risk']:.3f}->{row['wilson_risk']:.3f} "
                 f"corrob {row['point_corroborators']}->"
                 f"{row['wilson_corroborators']} [{row['label']}]")

    L.append("\n=== E. lead-threshold sweep (a limit, not a tuning) ===")
    for row in e["sweep"]:
        L.append(f"  thresh {row['threshold']:.2f}: malicious leads "
                 f"{row['malicious_leads']}/{row['malicious_total']}  "
                 f"benign leads {row['benign_leads']}/{row['benign_total']}"
                 + ("   <-- shipped" if row["shipped"] else ""))
    L.append(f"  thresholds dominating the shipped one: "
             f"{e['dominating_thresholds'] or 'none'}")
    L.append("  NOT APPLIED: tuning a threshold on the same 23 accounts the "
             "metrics are reported over is overfitting.")
    return "\n".join(L)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--readme-table", action="store_true",
                   help="emit the README table and exit")
    args = p.parse_args()
    r = analyse()
    if args.readme_table:
        print(readme_table(r))
        return
    (DATA / "sensitivity.json").write_text(json.dumps(r, indent=2) + "\n")
    print(render(r))
    print(f"\nwrote {DATA / 'sensitivity.json'}")


if __name__ == "__main__":
    main()
