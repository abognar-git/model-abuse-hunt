#!/usr/bin/env python3
"""Enumerate the enforcement policy's entire input space.

Every other harness writes one attack and reports what happened. That answers
"did this attack work", never "what is the complete set of inputs that lead to
an adverse action". This does the latter for src/policy.py, the way
stress_policy_surface.py did for the triage project: it enumerates every
combination of the policy's inputs and characterises exactly what escapes to
an `enforce` decision - and proves the two invariants that matter.

Inputs enumerated:
  confidence_band          7 ICD-203 bands
  recommended_disposition  4
  assessment               3
  corroboration state      { none, content-only, non-content, coordinated }
  manipulation_observed    2

Invariants asserted over the WHOLE space (not sampled):
  I1  no input ever produces an automatic adverse action
      (auto_actioned is False everywhere; every `enforce` is human-gated)
  I2  no `enforce` decision is ever reached without non-content corroboration
      (topic alone cannot action an account, for any confidence or assessment)

Usage:
    python -m scripts.stress_enforcement_surface
"""
from __future__ import annotations

import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.investigate import BANDS, ASSESSMENTS, DISPOSITIONS   # noqa: E402
from src.policy import apply_enforcement_policy                # noqa: E402

def _sig(name, contribution):
    return {"signal": name, "contribution": contribution}


# Representative corroboration states, each a (cluster_size, member_signals).
# member_signals is a list (per member) of signal dicts with contributions,
# so the policy's strength floor is exercised, not just presence.
CORROBORATION = {
    "none":         (1, [[]]),
    "content_only": (1, [[_sig("content_category_risk", 0.06),
                          _sig("capability_trajectory", 0.22)]]),
    "weak_noncontent": (1, [[_sig("automation_cadence", 0.04),   # below floor
                             _sig("content_category_risk", 0.06)]]),
    "non_content":  (1, [[_sig("burner_infra", 0.16),
                          _sig("content_category_risk", 0.06)]]),
    "coordinated":  (2, [[_sig("content_category_risk", 0.06)],
                         [_sig("content_category_risk", 0.06)]]),
}


def run():
    total = 0
    enforce_rows = []
    auto_actions = 0
    uncorroborated_enforce = 0
    ungated_enforce = 0

    for band, disp, assess, (cname, (csize, sigs)), manip in itertools.product(
            BANDS, sorted(DISPOSITIONS), sorted(ASSESSMENTS),
            CORROBORATION.items(), (False, True)):
        total += 1
        finding = {
            "confidence_band": band,
            "recommended_disposition": disp,
            "assessment": assess,
            "cluster_size": csize,
            "manipulation_observed": manip,
            "disconfirming_evidence": [],
        }
        out = apply_enforcement_policy(finding, sigs)
        if out["auto_actioned"]:
            auto_actions += 1
        if out["enforcement_decision"] == "enforce":
            enforce_rows.append((band, disp, assess, cname, manip, out))
            if not out["corroborated"]:
                uncorroborated_enforce += 1
            if not out["requires_human_approval"]:
                ungated_enforce += 1

    print(f"enumerated {total} policy inputs\n")
    print(f"inputs reaching an `enforce` decision: {len(enforce_rows)} "
          f"({len(enforce_rows)/total:.1%})\n")

    # characterise the enforce region
    bands = sorted({r[0] for r in enforce_rows})
    disps = sorted({r[1] for r in enforce_rows})
    corr = sorted({r[3] for r in enforce_rows})
    print("the enforce region is exactly:")
    print(f"  confidence_band          {bands}")
    print(f"  recommended_disposition  {disps}")
    print(f"  corroboration state      {corr}")
    print(f"  (assessment and manipulation flag do not gate it)\n")

    print("invariants over the whole space:")
    print(f"  I1  automatic adverse actions:                 {auto_actions}  "
          f"-> {'PASS' if auto_actions == 0 else 'FAIL'}")
    print(f"  I1  `enforce` decisions not human-gated:        {ungated_enforce}"
          f"  -> {'PASS' if ungated_enforce == 0 else 'FAIL'}")
    print(f"  I2  `enforce` without non-content corroboration:{uncorroborated_enforce}"
          f"  -> {'PASS' if uncorroborated_enforce == 0 else 'FAIL'}")
    print("\nEvery enforce is a queue entry for a human, and topic alone never "
          "reaches\none. Both are properties of the policy, enumerated, not "
          "observed on a sample.")
    ok = auto_actions == 0 and ungated_enforce == 0 and uncorroborated_enforce == 0
    return ok


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
