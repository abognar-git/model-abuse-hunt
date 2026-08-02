"""Communication layer: render the investigation into a one-file HTML brief.

The job is not done when the finding exists; it is done when a decision-maker
can act on it. This renders the pipeline's artifacts - attributed actors, their
assessments, confidence bands, evidence and dispositions - into a single
self-contained HTML intelligence brief, no server and no dependencies, for the
people who do not read JSONL.

Every string that originated from an account (ids, prompt excerpts, summaries
the model wrote over untrusted input) is HTML-escaped. Attacker-controlled data
stays data, even here: a briefing is just another place a payload could try to
break out of, and the same discipline that fences the model fences the report.

Usage:
    python -m src.report   ->  data/brief.html
"""
from __future__ import annotations

import html
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"

_DISPOSITION_STYLE = {
    "enforce": ("#b30000", "ENFORCE - human approval required"),
    "monitor": ("#8a6d00", "MONITOR"),
    "gather_more": ("#00568a", "GATHER MORE"),
    "clear": ("#1a7a1a", "CLEAR"),
}


def _esc(x) -> str:
    return html.escape(str(x))


def _finding_card(f: dict) -> str:
    color, label = _DISPOSITION_STYLE.get(
        f.get("enforcement_decision", "monitor"), ("#333", "?"))
    subjects = ", ".join(_esc(s) for s in f["subject_ids"])
    manip = ('<span class="manip">manipulation attempt observed</span>'
             if f.get("manipulation_observed") else "")
    gate = (' <span class="gate">requires human approval</span>'
            if f.get("requires_human_approval") else "")
    key = "".join(f"<li>{_esc(k)}</li>" for k in f.get("key_evidence", []))
    disc = "".join(f"<li>{_esc(d)}</li>"
                   for d in f.get("disconfirming_evidence", []))
    reasons = "".join(f"<li>{_esc(r)}</li>" for r in f.get("policy_reasons", []))
    return f"""
    <div class="card">
      <div class="cardhead" style="border-color:{color}">
        <span class="subjects">{subjects}</span>
        <span class="disp" style="background:{color}">{label}{gate}</span>
      </div>
      <div class="row"><b>Assessment</b> {_esc(f['assessment'])}
        &middot; <b>Confidence</b> {_esc(f['confidence_band'])}
        &middot; <b>Cluster</b> {_esc(f.get('cluster_size', 1))} account(s)
        &middot; <b>Max risk</b> {_esc(f.get('max_risk', '-'))}</div>
      <p class="summary">{_esc(f['summary'])}</p>
      {manip}
      <div class="cols">
        <div><b>Key evidence</b><ul>{key or '<li>-</li>'}</ul></div>
        <div><b>Disconfirming / would exonerate</b><ul>{disc or '<li>-</li>'}</ul></div>
      </div>
      <details><summary>policy rationale</summary><ul>{reasons or '<li>-</li>'}</ul></details>
    </div>"""


def build():
    findings = [json.loads(l) for l in open(DATA / "findings.jsonl")] \
        if (DATA / "findings.jsonl").exists() else []
    findings.sort(key=lambda f: 0 if f.get("enforcement_decision") == "enforce"
                  else 1)

    n_enforce = sum(1 for f in findings
                    if f.get("enforcement_decision") == "enforce")
    n_actors = sum(1 for f in findings if f.get("cluster_size", 1) > 1)
    cards = "".join(_finding_card(f) for f in findings)

    doc = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>Model-abuse threat brief</title>
<style>
 body {{ font: 14px/1.5 -apple-system, Segoe UI, Roboto, sans-serif;
        max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
 h1 {{ font-size: 1.5rem; margin-bottom: .2rem; }}
 .meta {{ color: #666; margin-bottom: 1.5rem; }}
 .card {{ border: 1px solid #ddd; border-radius: 8px; margin: 1rem 0;
          padding: 0 1rem 1rem; }}
 .cardhead {{ display: flex; justify-content: space-between; align-items: center;
              border-left: 5px solid; margin: 0 -1rem 0; padding: .6rem 1rem; }}
 .subjects {{ font-family: ui-monospace, monospace; font-weight: 600; }}
 .disp {{ color: #fff; font-size: .75rem; font-weight: 700; padding: .2rem .5rem;
          border-radius: 4px; }}
 .gate {{ font-weight: 400; opacity: .9; }}
 .row {{ margin: .6rem 0; color: #333; }}
 .summary {{ background: #f7f7f7; padding: .6rem .8rem; border-radius: 6px; }}
 .manip {{ display: inline-block; background: #fff0f0; color: #b30000;
           border: 1px solid #f3caca; padding: .2rem .5rem; border-radius: 4px;
           font-size: .8rem; }}
 .cols {{ display: flex; gap: 1.5rem; margin-top: .6rem; }}
 .cols > div {{ flex: 1; }}
 ul {{ margin: .3rem 0; padding-left: 1.1rem; }}
 details {{ margin-top: .6rem; color: #555; }}
 summary {{ cursor: pointer; }}
</style></head><body>
<h1>Model-abuse threat brief</h1>
<div class="meta">{len(findings)} investigated subject(s) &middot;
  {n_actors} coordinated actor(s) &middot;
  {n_enforce} recommended for enforcement (all human-gated).
  Account-derived text is escaped; no enforcement is automatic.</div>
{cards}
</body></html>"""
    (DATA / "brief.html").write_text(doc)
    print(f"wrote data/brief.html ({len(findings)} findings, "
          f"{n_enforce} enforcement recommendations)")


if __name__ == "__main__":
    build()
