"""Eval harness: measure what a threat-intel team lives or dies by.

Joins the pipeline's findings against ground truth and reports the metrics that
matter for hunting model-abuse - which are NOT the same as a classifier's
accuracy. The one that dominates is the false-accusation rate: enforcing
against a legitimate user is the expensive, trust-destroying error, and the
whole dataset is built to pressure it (every hard negative's content overlaps
an actor).

Metrics:
  1. Actor recall            - malicious accounts the pipeline surfaced as leads
  2. Attribution recovery    - planted actors reconstructed as clusters
  3. Attribution purity      - clusters that mix an actor with a bystander
  4. False accusation        - BENIGN accounts that reached an enforce decision
                               (must be 0; this is the metric)
  5. Enforcement corroboration - every enforce decision has a non-content signal
  6. Auto-action invariant   - no adverse action taken without human approval

Writes data/eval_report.md.

Usage:  python -m src.evaluate
"""
from __future__ import annotations

import json
from pathlib import Path

from .attribute import build_actors
from .hunt import load, score_all
from .prevalence import rule_of_three, wilson

DATA = Path(__file__).resolve().parent.parent / "data"


def main():
    gt = {json.loads(l)["account_id"]: json.loads(l)
          for l in open(DATA / "ground_truth.jsonl")}
    accounts, sessions = load()
    scored = score_all(accounts, sessions)
    clusters, _ = build_actors(accounts, sessions)
    findings = [json.loads(l) for l in open(DATA / "findings.jsonl")] \
        if (DATA / "findings.jsonl").exists() else []

    mal = [a for a in gt if gt[a]["label"] == "malicious"]
    ben = [a for a in gt if gt[a]["label"] == "benign"]

    # 1. actor recall (behavioral leads) + attribution rescue
    leads = {a for a in gt if scored[a]["is_lead"]}
    clustered = {a for c in clusters for a in c}
    surfaced = leads | clustered           # a subject is investigated if either
    mal_surfaced = [a for a in mal if a in surfaced]
    mal_missed = [a for a in mal if a not in surfaced]

    # 2/3. attribution recovery + purity against planted actor ids
    planted = {}
    for a in mal:
        act = gt[a]["actor"]
        planted.setdefault(act, set()).add(a)
    # single-account actors count as recovered if surfaced at all
    recovered = 0
    for act, members in planted.items():
        if len(members) == 1:
            if next(iter(members)) in surfaced:
                recovered += 1
        elif any(members <= set(c) for c in clusters):
            recovered += 1
    impure = 0
    for c in clusters:
        actors = {gt[m]["actor"] for m in c if gt[m]["label"] == "malicious"}
        has_benign = any(gt[m]["label"] == "benign" for m in c)
        if len(actors) > 1 or has_benign:
            impure += 1

    # 4. false accusation: benign accounts inside an enforce decision
    enforce_ids = set()
    for f in findings:
        if f.get("enforcement_decision") == "enforce":
            enforce_ids.update(f["subject_ids"])
    false_accused = [a for a in ben if a in enforce_ids]
    mal_enforced = [a for a in mal if a in enforce_ids]

    # 5. every enforce decision corroborated by a non-content signal
    enforce_findings = [f for f in findings
                        if f.get("enforcement_decision") == "enforce"]
    uncorroborated = [f for f in enforce_findings if not f.get("corroborated")]

    # 6. auto-action invariant
    auto_actioned = [f for f in findings if f.get("auto_actioned")]
    enforce_ungated = [f for f in enforce_findings
                       if not f.get("requires_human_approval")]

    # false-lead detail (benign surfaced as a lead but correctly not enforced)
    false_leads = [a for a in ben if a in leads]
    cleared = [a for a in false_leads if a not in enforce_ids]

    # Which engine produced the assessments these metrics are computed from.
    # Reported in the artifact rather than assumed, because this repo shipped a
    # mock findings file under a "real-model run" heading and no reader - or
    # author - could have told from the file itself.
    engines = sorted({f.get("engine", "unrecorded") for f in findings})
    engine_label = ", ".join(engines) if engines else "no findings"
    is_mock = engines == ["mock"]

    L = []
    add = L.append
    add("# Eval report - model-abuse threat hunting\n")
    add(f"Assessment engine: **{engine_label}**"
        + ("  <- MOCK: these metrics describe the offline deterministic "
           "engine, not a model." if is_mock else "")
        + ("  <- UNRECORDED: regenerate with `python -m src.investigate` to "
           "stamp provenance." if "unrecorded" in engines else "") + "\n")
    add(f"Dataset: {len(gt)} accounts | {len(mal)} malicious across "
        f"{len(planted)} actors | {len(ben)} benign "
        f"({sum(1 for a in ben if gt[a]['persona'])} content-overlapping hard "
        f"negatives)\n")
    add("| Metric | Result |")
    add("|---|---|")
    add(f"| Malicious accounts surfaced (lead or attributed) | "
        f"{len(mal_surfaced)}/{len(mal)} |")
    add(f"| Malicious accounts missed entirely | {len(mal_missed)} "
        f"{mal_missed or ''} |")
    add(f"| Planted actors recovered | {recovered}/{len(planted)} |")
    add(f"| Impure clusters (actor mixed with bystander) | {impure}/{len(clusters)} |")
    add(f"| **Benign accounts reaching an enforce decision (false accusation)** "
        f"| **{len(false_accused)}/{len(ben)}** {false_accused or ''} |")
    add(f"| Malicious accounts reaching an enforce decision | "
        f"{len(mal_enforced)}/{len(mal)} |")
    add(f"| Enforce decisions lacking non-content corroboration | "
        f"{len(uncorroborated)}/{len(enforce_findings)} |")
    add(f"| Adverse actions taken without human approval | "
        f"{len(auto_actioned) + len(enforce_ungated)} |")
    add(f"| Benign false-leads cleared downstream | "
        f"{len(cleared)}/{len(false_leads)} {false_leads or ''} |")

    # Every row above is a count over a small sample. Printing the headline two
    # with their intervals here - not only in the README - keeps the artifact
    # and the prose making the same claim, and reuses src.prevalence's
    # definitions rather than restating them. (Restating a definition at a call
    # site is the bug this project has now shipped twice.)
    fa_lo, fa_hi = wilson(len(false_accused), len(ben))
    rc_lo, rc_hi = wilson(len(mal_enforced), len(mal))
    add("\n## What those counts license\n")
    add(f"- False accusation **{len(false_accused)}/{len(ben)}** bounds the "
        f"true rate at **[{fa_lo:.2f}, {fa_hi:.2f}]** (95% Wilson; rule of "
        f"three 3/{len(ben)} = {rule_of_three(len(ben)):.3f}). A zero here is "
        f"not a rate of zero.")
    add(f"- Enforce-given-malicious **{len(mal_enforced)}/{len(mal)}** bounds "
        f"recall at **[{rc_lo:.2f}, {rc_hi:.2f}]**.")
    add(f"- Dataset prevalence is **{len(mal) / len(gt):.0%}**, two to three "
        f"orders of magnitude above a real platform's. Run "
        f"`python -m src.prevalence` for what that does to the precision of "
        f"the enforcement queue; the short version is that these counts "
        f"cannot distinguish a queue of real actors from one that is almost "
        f"entirely innocent people.")

    add("\n## What the numbers mean\n")
    add("- **False accusation is the metric.** Every benign account here was "
        "built to look like an actor on content. If topic drove enforcement, "
        "this row would be large. It is the row to read first.")
    add("- A **lead is not an accusation.** The hunt casts a wide behavioral "
        "net; false leads are expected and acceptable. The enforcement policy, "
        "not the hunt, is the boundary - benign false-leads must be cleared, "
        "and no account is actioned on topic alone.")
    add("- **Attribution rescues what scoring misses.** A quiet account below "
        "the lead threshold is still investigated if it attributes to an actor "
        "- coordination is evidence a single risk score cannot see.")
    add("- The **auto-action invariant** is structural, not learned: enforcement "
        "is always a queue for a human. See stress_enforcement_surface.py for "
        "the enumerated proof.")

    if mal_missed:
        add("\n## Missed malicious detail\n")
        for a in mal_missed:
            add(f"- {a} ({gt[a]['actor']}): {gt[a]['notes']}")

    report = "\n".join(L) + "\n"
    (DATA / "eval_report.md").write_text(report)
    print(report)


if __name__ == "__main__":
    main()
