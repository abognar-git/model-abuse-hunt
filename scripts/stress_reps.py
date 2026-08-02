"""Finding #24: the headline numbers came from one sample of a stochastic
decoder.

`investigate.assess_openai` sets no `temperature`, so it runs at the API
default. `data/findings.jsonl` is therefore ONE draw, and it is the file that
`src/evaluate.py` computes 0/14 false accusations and 9/9 recall from - and
that `src/prevalence.py` computes finding #16's Wilson intervals from, which
means the intervals are an uncertainty estimate over a sample that itself has
unmeasured sampling variance.

Finding #18 already established that this repo cannot trust a single-rep model
run: the LLM-as-judge swung +0.75 and +2.0 between single runs, and reps were
made mandatory *for the judge*. That lesson was never applied to the primary
artifact everything else cites. This harness applies it.

The unit of analysis is the SUBJECT, not the account: assessments are written
per attributed actor or standalone lead, exactly as the pipeline does it. For
each subject across R reps it reports the modal decision and the agreement
fraction, and it reports separately whether the two INVARIANTS ever break:

  * a benign account reaching `enforce` in any rep (false accusation)
  * an `enforce` without non-content corroboration in any rep

An invariant that holds on average is not an invariant. What matters here is
the worst rep, not the mean - so the summary reports both, and the pass
condition is stated over the worst.

Does NOT overwrite data/findings.jsonl. That file is the canonical artifact and
this harness is a measurement about it, not a replacement for it.

Usage:
    python -m scripts.stress_reps --reps 10
    python -m scripts.stress_reps --reps 10 --model gpt-4o-mini
    python -m scripts.stress_reps --readme-table
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from src import signals
from src.attribute import build_actors
from src.hunt import load, score_all
from src.investigate import assess_openai, build_packet
from src.policy import apply_enforcement_policy

DATA = Path(__file__).resolve().parent.parent / "data"

DEFAULT_REPS = 10
DEFAULT_MODEL = "gpt-4o-mini"

# Fields whose stability across reps is worth reporting. `enforcement_decision`
# is the one that matters - it is what a human sees in a queue.
TRACKED = ["assessment", "confidence_band", "recommended_disposition",
           "enforcement_decision", "manipulation_observed", "corroborated"]


def subjects_of(accounts, sessions, scored, clusters):
    subs, seen = [], set()
    for c in clusters:
        subs.append(list(c))
        seen.update(c)
    for aid, s in scored.items():
        if s["is_lead"] and aid not in seen:
            subs.append([aid])
            seen.add(aid)
    return subs


def run_reps(reps: int, model: str, rpm: float) -> dict:
    gt = {json.loads(l)["account_id"]: json.loads(l)
          for l in open(DATA / "ground_truth.jsonl")}
    accounts, sessions = load()
    scored = score_all(accounts, sessions)
    clusters, _ = build_actors(accounts, sessions)
    subs = subjects_of(accounts, sessions, scored, clusters)

    per_subject = {}
    per_rep_invariants = []
    for r in range(reps):
        enforce_ids, uncorroborated, ungated = set(), 0, 0
        for ids in subs:
            key = ",".join(sorted(ids))
            packet = build_packet(ids, accounts, sessions, scored, {})
            a = assess_openai(packet, model, rpm)
            a["cluster_size"] = len(ids)
            a = apply_enforcement_policy(
                a, [scored[x]["signals"] for x in ids])
            per_subject.setdefault(key, []).append(
                {k: a.get(k) for k in TRACKED})
            if a["enforcement_decision"] == "enforce":
                enforce_ids.update(ids)
                if not a.get("corroborated"):
                    uncorroborated += 1
                if not a.get("requires_human_approval"):
                    ungated += 1
        ben = [x for x in gt if gt[x]["label"] == "benign"]
        mal = [x for x in gt if gt[x]["label"] == "malicious"]
        per_rep_invariants.append({
            "rep": r,
            "false_accusations": sum(1 for x in ben if x in enforce_ids),
            "malicious_enforced": sum(1 for x in mal if x in enforce_ids),
            "uncorroborated_enforcements": uncorroborated,
            "ungated_enforcements": ungated,
        })
        print(f"  rep {r + 1}/{reps}: "
              f"false_accusations={per_rep_invariants[-1]['false_accusations']} "
              f"malicious_enforced="
              f"{per_rep_invariants[-1]['malicious_enforced']}",
              flush=True)

    stability = {}
    for key, rows in per_subject.items():
        fields = {}
        for f in TRACKED:
            vals = [str(row[f]) for row in rows]
            c = Counter(vals)
            top, n = c.most_common(1)[0]
            fields[f] = {"modal": top, "agreement": round(n / len(vals), 3),
                         "distinct": len(c),
                         "values": dict(c)}
        stability[key] = {
            "label": ("benign" if all(
                json.loads(l)["label"] == "benign"
                for l in open(DATA / "ground_truth.jsonl")
                if json.loads(l)["account_id"] in key.split(","))
                else "mixed/malicious"),
            "fields": fields,
        }

    fa = [p["false_accusations"] for p in per_rep_invariants]
    me = [p["malicious_enforced"] for p in per_rep_invariants]
    return {
        "model": model,
        "reps": reps,
        "temperature": "API default (investigate.assess_openai pins none)",
        "subjects": [",".join(sorted(s)) for s in subs],
        "per_rep": per_rep_invariants,
        "stability": stability,
        "invariants": {
            "false_accusations_worst": max(fa),
            "false_accusations_mean": round(sum(fa) / len(fa), 3),
            "false_accusations_held_every_rep": max(fa) == 0,
            "uncorroborated_worst": max(
                p["uncorroborated_enforcements"] for p in per_rep_invariants),
            "ungated_worst": max(
                p["ungated_enforcements"] for p in per_rep_invariants),
            "malicious_enforced_min": min(me),
            "malicious_enforced_max": max(me),
        },
        "least_stable_field": min(
            ((k, f, v["agreement"])
             for k, s in stability.items() for f, v in s["fields"].items()),
            key=lambda t: t[2], default=None),
    }


def readme_table(r: dict) -> str:
    L = []
    L.append(f"{r['reps']} reps, `{r['model']}`, temperature = "
             f"{r['temperature']}.")
    L.append("")
    L.append("| Subject | Assessment (modal, agreement) | Enforcement decision "
             "(modal, agreement) |")
    L.append("|---|---|---|")
    for key, s in r["stability"].items():
        a = s["fields"]["assessment"]
        e = s["fields"]["enforcement_decision"]
        L.append(f"| `{key}` | {a['modal']} ({a['agreement']:.0%}) | "
                 f"{e['modal']} ({e['agreement']:.0%}) |")
    inv = r["invariants"]
    L.append("")
    L.append(f"False accusations: **worst rep {inv['false_accusations_worst']}"
             f"**, mean {inv['false_accusations_mean']}. "
             f"Enforce-without-corroboration worst rep: "
             f"{inv['uncorroborated_worst']}. "
             f"Ungated enforcements worst rep: {inv['ungated_worst']}. "
             f"Malicious accounts enforced: "
             f"{inv['malicious_enforced_min']}–{inv['malicious_enforced_max']}"
             f" across reps.")
    return "\n".join(L)


def render(r: dict) -> str:
    L = [f"=== {r['reps']} reps of {r['model']} "
         f"(temperature: {r['temperature']}) ==="]
    for key, s in r["stability"].items():
        L.append(f"\n  {key}")
        for f, v in s["fields"].items():
            flag = "" if v["distinct"] == 1 else "   <-- VARIES"
            L.append(f"    {f:26s} {v['modal']:22s} "
                     f"agreement {v['agreement']:.0%}{flag}")
            if v["distinct"] > 1:
                L.append(f"        {v['values']}")
    inv = r["invariants"]
    L.append("\n=== invariants, stated over the WORST rep ===")
    L.append(f"  false accusations       worst {inv['false_accusations_worst']}"
             f"  mean {inv['false_accusations_mean']}  "
             f"{'HELD' if inv['false_accusations_held_every_rep'] else 'BROKE'}")
    L.append(f"  enforce w/o corroboration worst "
             f"{inv['uncorroborated_worst']}")
    L.append(f"  ungated enforcement       worst {inv['ungated_worst']}")
    L.append(f"  malicious enforced        "
             f"{inv['malicious_enforced_min']}..{inv['malicious_enforced_max']}")
    if r["least_stable_field"]:
        k, f, agr = r["least_stable_field"]
        L.append(f"  least stable field: {f} on {k} ({agr:.0%} agreement)")
    return "\n".join(L)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--reps", type=int, default=DEFAULT_REPS)
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--rpm", type=float, default=60)
    p.add_argument("--readme-table", action="store_true")
    args = p.parse_args()

    out = DATA / "reps.json"
    if args.readme_table:
        print(readme_table(json.loads(out.read_text())))
        return
    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY not set - this harness measures the REAL "
                 "model; there is nothing to measure about the mock, which is "
                 "deterministic by construction")
    r = run_reps(args.reps, args.model, args.rpm)
    out.write_text(json.dumps(r, indent=2) + "\n")
    print(render(r))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
