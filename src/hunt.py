"""Hunting layer: turn a pile of platform telemetry into ranked leads.

This is deterministic and offline. It scores every account on behavior and
infrastructure (src/signals.py) and surfaces the ones worth an analyst's time,
most-suspicious first, each with the signals that fired. No model is called
here: a lead is a behavioral judgement, and the accusation must never rest on
what the account typed - only on how it behaved.

Usage:
    python -m src.hunt
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from . import signals

DATA = Path(__file__).resolve().parent.parent / "data"


def load():
    accounts = {json.loads(l)["account_id"]: json.loads(l)
                for l in open(DATA / "accounts.jsonl")}
    sessions = defaultdict(list)
    for l in open(DATA / "sessions.jsonl"):
        s = json.loads(l)
        sessions[s["account_id"]].append(s)
    return accounts, sessions


def score_all(accounts, sessions):
    return {aid: signals.score_account(accounts[aid], sessions.get(aid, []))
            for aid in accounts}


def run():
    accounts, sessions = load()
    scored = score_all(accounts, sessions)
    leads = sorted((s for s in scored.values() if s["is_lead"]),
                   key=lambda s: -s["risk_score"])

    (DATA / "leads.jsonl").write_text(
        "".join(json.dumps(scored[aid]) + "\n" for aid in accounts))

    print(f"scored {len(accounts)} accounts -> "
          f"{len(leads)} leads (risk >= {signals.LEAD_THRESHOLD})\n")
    for s in leads:
        top = s["signals"][0]["signal"] if s["signals"] else "-"
        print(f"  {s['account_id']:<24} risk={s['risk_score']:.2f}  "
              f"top:{top}")
        for sig in s["signals"]:
            print(f"       {sig['signal']:<22} "
                  f"{sig['contribution']:.3f}  {sig['detail']}")
        print()

    # The honest near-miss: highest-scoring account that did NOT become a lead.
    below = sorted((s for s in scored.values() if not s["is_lead"]),
                   key=lambda s: -s["risk_score"])
    if below:
        nm = below[0]
        print(f"closest non-lead: {nm['account_id']} risk={nm['risk_score']:.2f} "
              f"(content-only portion would be {nm['content_only_score']:.2f})")
    return scored


if __name__ == "__main__":
    run()
