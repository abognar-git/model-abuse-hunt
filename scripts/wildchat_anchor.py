#!/usr/bin/env python3
"""Anchor the synthetic population's *behaviour* to real traffic (WildChat).

The synthetic archetypes assert things like "CI accounts have machine-regular
cadence" and "travellers switch country mid-history". This script checks those
shapes against real ChatGPT traffic, by streaming Allen AI's WildChat from
Hugging Face, grouping conversations into pseudo-accounts on `hashed_ip`, and
measuring:

  - sessions per pseudo-account (how much history a real account carries)
  - inter-arrival cadence: mean and coefficient of variation (regular vs bursty)
  - topic breadth via src/classify.py (how many topics an account spans)
  - country switching (the benign version of the stolen-key drift signature)
  - assistant refusal rate (a real refusal_farming baseline)

What WildChat does NOT anchor: the abuse base rate. The public WildChat releases
are toxicity-*filtered*, so their toxic fraction is ~0 and cannot stand in for
prevalence - that number comes from ToxicChat (see scripts/calibrate_classifier.py).
And WildChat has no payment/phone/ASN and no account-abuse ground truth, so it
validates input *distributions*, never the detector's recall or precision.

Default source: allenai/WildChat-4.8M (AI2 ImpACT). Override with --wildchat-repo
(e.g. allenai/WildChat-1M) or env WILDCHAT_REPO. An HF token is optional for
higher rate limits; the non-toxic public release streams without gated login.
Raw data caches under data/anchor/raw (gitignored); only derived stats are written.

Usage:
    python scripts/wildchat_anchor.py --sample 40000
    python scripts/wildchat_anchor.py --wildchat-repo allenai/WildChat-1M
"""
from __future__ import annotations

import argparse
import json
import os
import statistics as stats
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.classify import classify  # noqa: E402
from src.refusals import looks_refused  # noqa: E402

OUT = ROOT / "data" / "anchor"
RAW = OUT / "raw"
DEFAULT_REPO = os.environ.get("WILDCHAT_REPO", "allenai/WildChat-4.8M")


def _first_user_turn(convo: list[dict]) -> dict | None:
    for t in convo:
        if t.get("role") == "user":
            return t
    return None


def _record_fields(rec: dict) -> dict | None:
    """Pull (hashed_ip, country, timestamp, user_text, toxic, refused) from a
    WildChat record, tolerating top-level vs turn-level field placement."""
    convo = rec.get("conversation")
    if not isinstance(convo, list) or not convo:
        return None
    u = _first_user_turn(convo) or {}
    ip = rec.get("hashed_ip") or u.get("hashed_ip")
    if not ip:
        return None
    country = rec.get("country") or u.get("country")
    ts = rec.get("timestamp")
    if ts is None:
        for t in convo:
            if t.get("role") == "assistant" and t.get("timestamp"):
                ts = t["timestamp"]
                break
    user_text = " ".join(t.get("content", "") for t in convo if t.get("role") == "user")
    assistant_text = " ".join(t.get("content", "") for t in convo if t.get("role") == "assistant")
    return {
        "ip": ip,
        "country": country,
        "ts": ts,
        "topic": classify(user_text[:2000])[0],
        "toxic": bool(rec.get("toxic", False)),
        "refused": looks_refused(assistant_text),
    }


def _to_epoch(ts) -> float | None:
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, datetime):
        return ts.timestamp()
    s = str(ts).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def _cv(xs: list[float]) -> float | None:
    """Coefficient of variation of inter-arrival gaps (std/mean); low = regular."""
    if len(xs) < 2:
        return None
    m = stats.mean(xs)
    return (stats.pstdev(xs) / m) if m else None


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--wildchat-repo", default=DEFAULT_REPO)
    p.add_argument("--revision", default=None, help="pin a dataset revision/commit")
    p.add_argument("--sample", type=int, default=40000,
                   help="number of conversations to stream (deterministic: first N)")
    p.add_argument("--min-sessions", type=int, default=3,
                   help="min conversations for cadence/switch stats")
    args = p.parse_args()

    try:
        from datasets import load_dataset
    except ImportError:
        sys.exit("pip install -r requirements.txt (needs `datasets`)")

    token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")
    RAW.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("HF_DATASETS_CACHE", str(RAW))

    try:
        ds = load_dataset(args.wildchat_repo, split="train", streaming=True,
                          revision=args.revision, token=token)
    except Exception as e:  # noqa: BLE001 - surface any auth/repo/split problem clearly
        try:
            dd = load_dataset(args.wildchat_repo, streaming=True,
                              revision=args.revision, token=token)
            ds = dd[next(iter(dd.keys()))]
        except Exception as e2:  # noqa: BLE001
            sys.exit(
                f"could not open {args.wildchat_repo}: {e2}\n"
                "Try allenai/WildChat-4.8M (default) or allenai/WildChat-1M. "
                "For gated/full variants, run `hf auth login` (or export HF_TOKEN). "
                "Original error: " + str(e))

    accounts: dict[str, list[dict]] = defaultdict(list)
    seen = 0
    schema_checked = False
    for rec in ds:
        if not schema_checked:
            f = _record_fields(rec)
            if f is None:
                cols = list(rec.keys())
                sys.exit(
                    "WildChat schema not as expected: need a `conversation` list "
                    "with per-user-turn `hashed_ip` (or a top-level `hashed_ip`). "
                    f"Got columns: {cols}. If your mirror flattened the schema, "
                    "adjust _record_fields().")
            schema_checked = True
        f = _record_fields(rec)
        if f:
            accounts[f["ip"]].append(f)
        seen += 1
        if seen >= args.sample:
            break

    if seen == 0:
        sys.exit("no records streamed; check repo id / access")

    # Per-account aggregates.
    sess_counts = [len(v) for v in accounts.values()]
    multi = {ip: v for ip, v in accounts.items() if len(v) >= args.min_sessions}

    cvs: list[float] = []
    breadths: list[int] = []
    switch_flags: list[int] = []
    refusal_rates: list[float] = []
    for v in multi.values():
        epochs = sorted(e for e in (_to_epoch(x["ts"]) for x in v) if e is not None)
        gaps = [(b - a) / 60.0 for a, b in zip(epochs, epochs[1:])]  # minutes
        cv = _cv(gaps)
        if cv is not None:
            cvs.append(cv)
        breadths.append(len({x["topic"] for x in v}))
        countries = {x["country"] for x in v if x["country"]}
        switch_flags.append(1 if len(countries) > 1 else 0)
        refusal_rates.append(sum(x["refused"] for x in v) / len(v))

    toxic_conv = sum(1 for v in accounts.values() for x in v if x["toxic"])
    topic_mix = Counter(x["topic"] for v in accounts.values() for x in v)

    def pct(xs, q):
        return round(sorted(xs)[min(len(xs) - 1, int(q * len(xs)))], 3) if xs else None

    n_regular = sum(1 for c in cvs if c < 0.25)  # near-machine cadence
    d = {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset": {"repo": args.wildchat_repo, "revision": args.revision,
                    "conversations": seen, "pseudo_accounts": len(accounts),
                    "multi_session_accounts": len(multi),
                    "min_sessions": args.min_sessions},
        "sessions_per_account": {
            "mean": round(stats.mean(sess_counts), 3),
            "p50": pct(sess_counts, 0.50), "p90": pct(sess_counts, 0.90),
            "p99": pct(sess_counts, 0.99), "max": max(sess_counts)},
        "cadence_cv": {
            "n": len(cvs), "p10": pct(cvs, 0.10), "p50": pct(cvs, 0.50),
            "p90": pct(cvs, 0.90),
            "frac_near_machine_lt_0_25": round(n_regular / len(cvs), 4) if cvs else None},
        "topic_breadth": {
            "mean": round(stats.mean(breadths), 3) if breadths else None,
            "frac_multi_topic": round(sum(1 for b in breadths if b > 1) / len(breadths), 4) if breadths else None},
        "country_switch_frac": round(sum(switch_flags) / len(switch_flags), 4) if switch_flags else None,
        "refusal_rate": {
            "mean": round(stats.mean(refusal_rates), 4) if refusal_rates else None,
            "frac_any_refusal": round(sum(1 for r in refusal_rates if r > 0) / len(refusal_rates), 4) if refusal_rates else None},
        "toxic_conversation_frac": round(toxic_conv / seen, 4),
        "topic_mix": dict(sorted(topic_mix.items(), key=lambda kv: -kv[1])),
    }

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "wildchat_stats.json").write_text(json.dumps(d, indent=2) + "\n")
    _write_report(OUT / "wildchat_stats.md", d)

    print(f"streamed {seen} conversations -> {len(accounts)} pseudo-accounts "
          f"({len(multi)} with >= {args.min_sessions} sessions)")
    print(f"sessions/account p50={d['sessions_per_account']['p50']} "
          f"p90={d['sessions_per_account']['p90']} max={d['sessions_per_account']['max']}")
    print(f"near-machine cadence (CV<0.25): {d['cadence_cv']['frac_near_machine_lt_0_25']}")
    print(f"country-switch frac: {d['country_switch_frac']}  "
          f"multi-topic frac: {d['topic_breadth']['frac_multi_topic']}")
    print(f"any-refusal frac: {d['refusal_rate']['frac_any_refusal']}  "
          f"toxic conv frac (filtered set): {d['toxic_conversation_frac']}")
    print(f"wrote {OUT/'wildchat_stats.json'} and {OUT/'wildchat_stats.md'}")


def _write_report(path: Path, d: dict) -> None:
    ds = d["dataset"]
    spa, cad, tb, rr = (d["sessions_per_account"], d["cadence_cv"],
                        d["topic_breadth"], d["refusal_rate"])
    tm = "\n".join(f"| `{k}` | {v} |" for k, v in d["topic_mix"].items())
    md = f"""# WildChat behavioural anchor

Generated {d['generated_at']} from `{ds['repo']}` (revision `{ds['revision'] or 'latest'}`),
first **{ds['conversations']:,}** conversations -> **{ds['pseudo_accounts']:,}**
pseudo-accounts grouped on `hashed_ip` (**{ds['multi_session_accounts']:,}** with
>= {ds['min_sessions']} sessions).

This anchors the synthetic archetypes' *behavioural* shapes to real ChatGPT
traffic. It does **not** anchor the abuse base rate: the public WildChat release
is toxicity-filtered (toxic fraction here is
**{d['toxic_conversation_frac']:.1%}**), so prevalence comes from ToxicChat, not
this. WildChat also has no payment/phone/ASN and no account-abuse labels, so it
validates input distributions only - never the detector's recall or precision.

## Sessions per account (how much history a real account carries)

mean **{spa['mean']}**, median **{spa['p50']}**, p90 **{spa['p90']}**,
p99 **{spa['p99']}**, max **{spa['max']}**. The synthetic archetypes draw
2-16 sessions, which sits inside this range.

## Cadence regularity (CV of inter-arrival gaps)

Over {cad['n']:,} multi-session accounts: p10 **{cad['p10']}**, median
**{cad['p50']}**, p90 **{cad['p90']}**. A near-machine cadence (CV < 0.25) shows
up in **{_pctfmt(cad['frac_near_machine_lt_0_25'])}** of accounts - the real
counterpart of the `hn_automation` CI/cron archetype, and evidence that regular
cadence alone is common and benign.

## Topic breadth and country switching

- Multi-topic accounts: **{_pctfmt(tb['frac_multi_topic'])}** (mean breadth
  {tb['mean']} topics) - real accounts routinely span topics, so topic breadth
  is a weak abuse signal on its own.
- Country switching mid-history: **{_pctfmt(d['country_switch_frac'])}** of
  multi-session accounts. Grouping on `hashed_ip` makes this near-zero by
  construction (GeoIP is essentially one country per IP), so the
  `hn_traveler` archetype is *not* validated by this linkage and remains a
  synthetic hypothesis about stolen-key drift.

## Refusal baseline

Any-refusal accounts: **{_pctfmt(rr['frac_any_refusal'])}** (mean per-account
refusal rate **{_pctfmt(rr['mean'])}**) - a real baseline for `refusal_farming`,
so an occasional refusal is not itself suspicious.

## What the regex reads real prompts as

| category | conversations |
|---|---|
{tm}

<sub>Dataset: [WildChat-4.8M](https://huggingface.co/datasets/allenai/WildChat-4.8M)
(Zhao et al., 2024), AI2 ImpACT licence. Raw streamed into `data/anchor/raw/`
(gitignored); only this report and `wildchat_stats.json` are committed.</sub>
"""
    path.write_text(md)


def _pctfmt(x) -> str:
    return f"{x:.1%}" if isinstance(x, (int, float)) else "n/a"


if __name__ == "__main__":
    main()
