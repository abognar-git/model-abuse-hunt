"""Finding #22: how much of the result is the dataset, and how much is the
*particular* dataset.

This harness exists because of a correction. The plan was to put error bars on
every headline number the cheap way - the generator called `random.seed(31337)`,
so re-seed it fifty times and report a spread. That plan was impossible, and the
reason is itself the finding: **`random` was imported, seeded, and never
called.** `scripts/generate_telemetry.py` draws nothing. Every one of the 23
accounts is hand-authored, and the seed line was decoration that implied a
sampling process which does not exist. The dead seed has since been deleted, so
the past tense here is deliberate - the finding is about the seed that was
there, and nothing in the generator draws today either.

That matters more than a hardcoded seed would have. A reader who greps the
generator, sees a seed, and concludes "synthetic telemetry sampled from a
process, pinned for reproducibility" has been misled by a line of dead code -
and so had the author, who proposed reseeding it. The honest statement of the
limitation is not "every number rests on one draw" but "every number rests on
one hand-written fixture, and the only variation in it is variation somebody
chose to write."

So error bars have to come from somewhere real: perturbing the fixture. Each
perturbation is classified, because conflating the two kinds is how you get a
meaningless spread:

  INCIDENTAL - detail that carries no evidential weight. Relabelling an ASN,
    nudging a timestamp by minutes, reordering sessions inside an account.
    A metric that moves under these is measuring the fixture, not the actor.
    This is the class that yields honest error bars.

  STRUCTURAL - detail that IS the evidence. Dropping sessions, breaking shared
    infrastructure between burners. A metric SHOULD move under these; the
    result is a degradation curve, not an error bar.

Finding #17 already hit this by hand for one signal: the timing linker closed
6 of 6 links, and staggering the burners across the day put it back to 5 of 6 -
a fixture artifact, discovered manually. This generalises that check to every
metric the deterministic layers produce.

Fully offline. The mock assessment engine is used so a draw is reproducible and
free; that means these spreads describe the deterministic layers plus the mock's
rules, never a model. Stated here because this repo has shipped a mock artifact
under a real-model heading once already.

Usage:
    python -m scripts.stress_fixture
    python -m scripts.stress_fixture --draws 200
    python -m scripts.stress_fixture --readme-table
"""
from __future__ import annotations

import argparse
import copy
import json
import random
import statistics
from pathlib import Path

from src import signals
from src.attribute import build_actors
from src.hunt import load
from src.investigate import assess_mock, build_packet
from src.policy import apply_enforcement_policy

DATA = Path(__file__).resolve().parent.parent / "data"

DEFAULT_DRAWS = 100

# Timestamp jitter, in minutes. Bounded well below the cadence tolerance
# (signals.CADENCE_TOLERANCE_MIN) so that jitter alone cannot manufacture or
# destroy an automation signal - the perturbation has to be incidental to
# count as incidental.
JITTER_MINUTES = 3

# Session dropout probabilities for the structural sweep.
DROPOUT_GRID = [0.0, 0.1, 0.2, 0.3, 0.5]

# Account-age prefixes for the cold-start sweep: "what had the platform seen
# after this many sessions?"
PREFIX_GRID = [1, 2, 3, 4, 6, 8, 12, 18]


# ------------------------------------------------------------------ perturbations
def _parse_ts(ts):
    return int(ts[8:10]), int(ts[11:13]), int(ts[14:16])


def _fmt_ts(day, hour, minute):
    day += (hour + minute // 60) // 24 if False else 0        # no day rollover
    hour = max(0, min(23, hour))
    minute = max(0, min(59, minute))
    return f"2026-07-{day:02d}T{hour:02d}:{minute:02d}:00Z"


def perturb_identifiers(accounts, sessions, rng):
    """INCIDENTAL. Bijective relabelling of every IP and ASN.

    Also a regression test: finding #5 replaced four real company ASNs with
    RFC 5398 documentation ones and claimed the swap was measurement-preserving
    because identifiers are opaque to every scorer and only equality matters.
    That claim was verified once, by hand, against one relabelling. This checks
    it against a fresh random bijection on every draw."""
    ips = sorted({a["signup_ip"] for a in accounts.values()}
                 | {s["ip"] for sl in sessions.values() for s in sl
                    if "ip" in s})
    asns = sorted({a["signup_asn"] for a in accounts.values()}
                  | {s["asn"] for sl in sessions.values() for s in sl
                     if "asn" in s})
    # Relabel within risk class so a higher-risk ASN stays higher-risk; a
    # bijection that moved accounts between classes would be structural.
    risky = [a for a in asns if a in signals.HIGHER_RISK_ASNS]
    plain = [a for a in asns if a not in signals.HIGHER_RISK_ASNS]
    r2, p2 = risky[:], plain[:]
    rng.shuffle(r2)
    rng.shuffle(p2)
    asn_map = dict(zip(risky, r2)) | dict(zip(plain, p2))
    ip2 = ips[:]
    rng.shuffle(ip2)
    ip_map = dict(zip(ips, ip2))

    for a in accounts.values():
        a["signup_ip"] = ip_map.get(a["signup_ip"], a["signup_ip"])
        a["signup_asn"] = asn_map.get(a["signup_asn"], a["signup_asn"])
    for sl in sessions.values():
        for s in sl:
            if "ip" in s:
                s["ip"] = ip_map.get(s["ip"], s["ip"])
            if "asn" in s:
                s["asn"] = asn_map.get(s["asn"], s["asn"])
    return accounts, sessions


def perturb_timing(accounts, sessions, rng):
    """INCIDENTAL. Nudge every timestamp by a few minutes, preserving order."""
    for sl in sessions.values():
        for s in sl:
            day, hh, mm = _parse_ts(s["ts"])
            total = hh * 60 + mm + rng.randint(-JITTER_MINUTES, JITTER_MINUTES)
            total = max(0, min(23 * 60 + 59, total))
            s["ts"] = _fmt_ts(day, total // 60, total % 60)
    return accounts, sessions


def perturb_order(accounts, sessions, rng):
    """INCIDENTAL for a set-based scorer, STRUCTURAL for an ordered one.

    Permutes which category sits at which timestamp inside an account, leaving
    the multiset of categories and the timestamps themselves untouched. The
    shipped `capability_trajectory` cannot see this (it is a set cardinality);
    the `capability_arc` variant from finding #20 is defined by seeing it. The
    two therefore disagree here by construction, which is what makes this the
    cleanest available test of whether a signal reads order at all."""
    for sl in sessions.values():
        cats = [s["category"] for s in sl]
        rng.shuffle(cats)
        for s, c in zip(sorted(sl, key=lambda x: x["ts"]), cats):
            s["category"] = c
    return accounts, sessions


def perturb_dropout(p):
    """STRUCTURAL. Drop each session independently with probability p."""
    def _f(accounts, sessions, rng):
        for aid, sl in list(sessions.items()):
            kept = [s for s in sl if rng.random() >= p]
            sessions[aid] = kept
        return accounts, sessions
    return _f


def perturb_prefix(k):
    """STRUCTURAL, and the cold-start question (finding #23).

    Keeps only each account's FIRST k sessions in time order - what the
    platform would actually have seen k sessions into the account's life.
    Unlike random dropout this is a real operating condition, not a
    degradation: every account is new once.

    It matters because the strongest signals all require history to exist.
    `_baseline_drift` returns 0 below DRIFT_MIN_BASELINE + 2 = 6 sessions by
    construction; `_automation_cadence` needs 3 API calls before it computes a
    cadence at all and saturates at HIGH_VOLUME_SESSIONS = 12;
    `_capability_trajectory`'s volume ramp needs OFFENSIVE_TRAJECTORY_MIN = 3.
    An actor who rotates burners before that history accrues is not evading the
    signals - the signals are structurally unable to have fired yet. That is a
    different claim from `stress_evasion.py`'s (which prices shedding signals
    you could otherwise have) and it cannot be answered by spending money."""
    def _f(accounts, sessions, rng):
        for aid, sl in list(sessions.items()):
            sessions[aid] = sorted(sl, key=lambda s: s["ts"])[:k]
        return accounts, sessions
    return _f


PERTURBATIONS = {
    "identifier_relabel": ("incidental", perturb_identifiers),
    "timing_jitter": ("incidental", perturb_timing),
    "session_order_shuffle": ("incidental", perturb_order),
}


# ------------------------------------------------------------------ measurement
def _metrics(accounts, sessions, gt, impls=None):
    """Every deterministic-layer metric the eval report quotes, for one draw."""
    scored = {a: signals.score_account(accounts[a], sessions.get(a, []),
                                       impls=impls) for a in accounts}
    clusters, _ = build_actors(accounts, sessions)
    clustered = {a for c in clusters for a in c}
    leads = {a for a, r in scored.items() if r["is_lead"]}
    surfaced = leads | clustered

    mal = [a for a in gt if gt[a]["label"] == "malicious"]
    ben = [a for a in gt if gt[a]["label"] == "benign"]

    planted = {}
    for a in mal:
        planted.setdefault(gt[a]["actor"], set()).add(a)
    recovered = 0
    for members in planted.values():
        if len(members) == 1:
            recovered += int(next(iter(members)) in surfaced)
        elif any(members <= set(c) for c in clusters):
            recovered += 1
    impure = sum(1 for c in clusters
                 if len({gt[m]["actor"] for m in c
                         if gt[m]["label"] == "malicious"}) > 1
                 or any(gt[m]["label"] == "benign" for m in c))

    # Full mock pipeline for the false-accusation count.
    subjects, seen = [], set()
    for c in clusters:
        subjects.append(c)
        seen.update(c)
    for aid, r in scored.items():
        if r["is_lead"] and aid not in seen:
            subjects.append([aid])
            seen.add(aid)
    enforce_ids = set()
    for ids in subjects:
        packet = build_packet(ids, accounts, sessions, scored, {})
        a = assess_mock(packet)
        a["cluster_size"] = len(ids)
        a = apply_enforcement_policy(a, [scored[x]["signals"] for x in ids])
        if a["enforcement_decision"] == "enforce":
            enforce_ids.update(ids)

    return {
        "malicious_leads": sum(1 for a in mal if a in leads),
        "benign_leads": sum(1 for a in ben if a in leads),
        "malicious_surfaced": sum(1 for a in mal if a in surfaced),
        "actors_recovered": recovered,
        "impure_clusters": impure,
        "false_accusations": sum(1 for a in ben if a in enforce_ids),
        "clusters": len(clusters),
    }


METRIC_KEYS = ["malicious_leads", "benign_leads", "malicious_surfaced",
               "actors_recovered", "impure_clusters", "false_accusations",
               "clusters"]


def _spread(draws):
    out = {}
    for k in METRIC_KEYS:
        vals = [d[k] for d in draws]
        out[k] = {
            "min": min(vals), "max": max(vals),
            "mean": round(statistics.mean(vals), 3),
            "stdev": round(statistics.pstdev(vals), 3),
            "unchanged": len(set(vals)) == 1,
        }
    return out


def run_perturbation(fn, draws, gt, impls=None, seed0=0):
    out = []
    for i in range(draws):
        accounts, sessions = load()
        accounts = copy.deepcopy(dict(accounts))
        sessions = copy.deepcopy({k: list(v) for k, v in sessions.items()})
        rng = random.Random(seed0 + i)
        accounts, sessions = fn(accounts, sessions, rng)
        out.append(_metrics(accounts, sessions, gt, impls=impls))
    return out


def analyse(draws=DEFAULT_DRAWS) -> dict:
    gt = {json.loads(l)["account_id"]: json.loads(l)
          for l in open(DATA / "ground_truth.jsonl")}
    accounts, sessions = load()
    baseline = _metrics(dict(accounts), {k: list(v) for k, v in sessions.items()},
                        gt)

    arc_impls = dict(signals.SIGNAL_IMPLS)
    arc_impls["capability_trajectory"] = \
        signals.SIGNAL_VARIANTS["capability_arc"]

    incidental = {}
    for name, (kind, fn) in PERTURBATIONS.items():
        incidental[name] = {
            "kind": kind,
            "draws": draws,
            "spread": _spread(run_perturbation(fn, draws, gt)),
        }
    # The order perturbation, scored by the ordered variant: the control that
    # shows the shipped signal is order-blind rather than order-robust.
    incidental["session_order_shuffle_arc_scorer"] = {
        "kind": "control",
        "draws": draws,
        "spread": _spread(run_perturbation(
            perturb_order, draws, gt, impls=arc_impls)),
        "note": "same perturbation, scored with capability_arc instead of "
                "capability_trajectory",
    }

    structural = []
    for p in DROPOUT_GRID:
        sp = _spread(run_perturbation(perturb_dropout(p), draws, gt))
        structural.append({"dropout": p, "spread": sp})

    # Cold start is deterministic given k (no rng is consulted), so one draw
    # per prefix is the whole answer - running more would only restate it.
    coldstart = []
    for k in PREFIX_GRID:
        m = run_perturbation(perturb_prefix(k), 1, gt)[0]
        coldstart.append({"sessions_seen": k, **m})
    first_full = next((c["sessions_seen"] for c in coldstart
                       if c["malicious_surfaced"] == baseline["malicious_surfaced"]
                       and c["actors_recovered"] == baseline["actors_recovered"]),
                      None)

    return {
        "cold_start": {
            "curve": coldstart,
            "sessions_to_full_recall": first_full,
            "note": "sessions per account the platform must observe before "
                    "the pipeline reaches its steady-state recall",
        },
        "generator_uses_randomness": False,
        "generator_note": "scripts/generate_telemetry.py USED TO import random "
                          "and call random.seed(31337) while never calling any "
                          "random function; the dead seed has since been "
                          "removed. The fixture is hand-authored either way, so "
                          "there is nothing to re-seed and error bars have to "
                          "come from perturbing the data instead",
        "draws_per_perturbation": draws,
        "baseline": baseline,
        "incidental": incidental,
        "structural_dropout": structural,
    }


# ------------------------------------------------------------------ reporting
def readme_table(r: dict) -> str:
    L = []
    L.append("| Perturbation | Class | Malicious surfaced | Actors recovered "
             "| False accusations |")
    L.append("|---|---|---|---|---|")
    b = r["baseline"]
    L.append(f"| _(none - shipped fixture)_ | baseline | "
             f"{b['malicious_surfaced']} | {b['actors_recovered']} | "
             f"{b['false_accusations']} |")
    for name, blk in r["incidental"].items():
        s = blk["spread"]
        def cell(k):
            v = s[k]
            return (f"{v['min']}" if v["unchanged"]
                    else f"{v['min']}–{v['max']} (μ {v['mean']})")
        L.append(f"| `{name}` | {blk['kind']} | {cell('malicious_surfaced')} | "
                 f"{cell('actors_recovered')} | {cell('false_accusations')} |")
    L.append("")
    L.append("| Session dropout | Malicious surfaced | Actors recovered |")
    L.append("|---|---|---|")
    for row in r["structural_dropout"]:
        s = row["spread"]
        def cell(k):
            v = s[k]
            return (f"{v['min']}" if v["unchanged"]
                    else f"{v['min']}–{v['max']} (μ {v['mean']})")
        L.append(f"| {row['dropout']:.0%} | {cell('malicious_surfaced')} | "
                 f"{cell('actors_recovered')} |")
    return "\n".join(L)


def render(r: dict) -> str:
    L = []
    L.append("=== the seed that never sampled anything ===")
    L.append(f"  generator uses randomness: {r['generator_uses_randomness']}")
    L.append(f"  {r['generator_note']}")
    L.append(f"\n=== baseline (shipped fixture) ===")
    for k in METRIC_KEYS:
        L.append(f"  {k:22s} {r['baseline'][k]}")

    L.append(f"\n=== INCIDENTAL perturbations ({r['draws_per_perturbation']} "
             f"draws each) - these are the error bars ===")
    for name, blk in r["incidental"].items():
        L.append(f"  {name}  [{blk['kind']}]"
                 + (f"  ({blk['note']})" if blk.get("note") else ""))
        for k in METRIC_KEYS:
            v = blk["spread"][k]
            flag = "" if v["unchanged"] else "   <-- MOVES"
            rng_s = (f"{v['min']}" if v["unchanged"]
                     else f"{v['min']}..{v['max']} mean {v['mean']} "
                          f"sd {v['stdev']}")
            L.append(f"      {k:22s} {rng_s}{flag}")

    L.append("\n=== STRUCTURAL: session dropout (a degradation curve, not an "
             "error bar) ===")
    for row in r["structural_dropout"]:
        s = row["spread"]
        L.append(f"  dropout {row['dropout']:.0%}: "
                 + ", ".join(
                     f"{k}={s[k]['min']}..{s[k]['max']}"
                     for k in ("malicious_surfaced", "actors_recovered",
                               "false_accusations")))

    cs = r["cold_start"]
    L.append("\n=== COLD START: what the platform had seen after k sessions ===")
    L.append(f"  {'k':>3s}  {'surfaced':>8s} {'actors':>7s} {'leads':>6s} "
             f"{'benign-leads':>12s} {'false-acc':>10s}")
    for row in cs["curve"]:
        L.append(f"  {row['sessions_seen']:3d}  "
                 f"{row['malicious_surfaced']:8d} {row['actors_recovered']:7d} "
                 f"{row['malicious_leads']:6d} {row['benign_leads']:12d} "
                 f"{row['false_accusations']:10d}")
    L.append(f"  sessions per account before steady-state recall: "
             f"{cs['sessions_to_full_recall']}")
    return "\n".join(L)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--draws", type=int, default=DEFAULT_DRAWS)
    p.add_argument("--readme-table", action="store_true")
    args = p.parse_args()
    r = analyse(args.draws)
    if args.readme_table:
        print(readme_table(r))
        return
    (DATA / "fixture_sensitivity.json").write_text(json.dumps(r, indent=2) + "\n")
    print(render(r))
    print(f"\nwrote {DATA / 'fixture_sensitivity.json'}")


if __name__ == "__main__":
    main()
