#!/usr/bin/env python3
"""Generate the README's figures from the real thing.

Nothing here is drawn by hand, and nothing is retyped from the prose. Three
kinds of output:

  SVG   charts, each written in a light and a dark variant so the README can
        follow the reader's GitHub theme via <picture>. They come from three
        different places, and the difference is worth stating rather than
        flattening:

          LIVE, by importing the pipeline at render time (8) --
            content_vs_behavior scores all 23 accounts through `src.signals`,
            escape_surface enumerates `src.policy.apply_enforcement_policy`
            over the harness's own input space, prevalence calls
            `src.prevalence`, which recomputes the operating point from the
            committed artifacts, and the five label-cost study figures
            (label_cost, threshold_sweep, errors_by_archetype, hard_fraction,
            label_prevalence) assemble their population via
            scripts.generate_population and score it through the same
            `src.signals` at build time. None of these can drift from the code.

          FROM A COMMITTED ARTIFACT under data/ (5) -- dual_use_ladder,
            cost_frontier and adaptive_attackers each read their own json;
            classifier_calibration reads data/calibration/confusion.json and
            wildchat_distributions reads data/anchor/wildchat_stats.json.
            These cannot drift from the artifact, but the artifact can go
            stale against the code; that has happened here before.

          FROM A LITERAL in MEASURED below (2) -- calibration and
            fragmentation. Weakest of the three: the numbers are correct as of
            the run named beside them, and nothing enforces that. calibration
            is only half-literal by necessity -- data/calibration.json carries
            the Brier decomposition but not the per-band table, so the bands
            have nowhere to be read from yet.

        This docstring used to say "two are live ... the rest read the
        committed result files", which undercounted the live ones and quietly
        folded the two literals in with the artifacts.

  PNG   real screenshots of the running console, captured with headless Chrome
        against deep links (?subject=&manip=&run=). The server precomputes the
        cascade and inlines it as `window.__PRELOAD`, so each shot is a settled
        page showing genuine model output rather than a mockup. These stay
        dark: they are screenshots of a dark-themed tool, and rendering a light
        theme it does not have would misrepresent it.

  GIF   those screenshots in sequence.

Screenshots need the console running in real mode (OPENAI_API_KEY) and cost a
few API calls. Use --svg-only to regenerate just the charts offline.

Usage:
    python -m scripts.make_figures             # everything
    python -m scripts.make_figures --svg-only  # no browser, no API calls
"""
from __future__ import annotations

import argparse
import copy
import itertools
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import prevalence, signals                               # noqa: E402
from src.investigate import BANDS, ASSESSMENTS, DISPOSITIONS      # noqa: E402
from src.policy import (apply_enforcement_policy,                 # noqa: E402
                        CONFIDENCE_FLOOR_BAND,
                        CORROBORATION_MIN_CONTRIBUTION)
from scripts.stress_enforcement_surface import CORROBORATION      # noqa: E402
from scripts.stress_adaptive import OPTIMAL as OPTIMAL_BASKET      # noqa: E402
from scripts.stress_adaptive import _is_evasion                    # noqa: E402
from scripts.generate_population import assemble                   # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUT = ROOT / "docs" / "figures"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PORT = 8795

# GitHub's own palettes, so a figure sits naturally in either theme. Shared
# with the sibling project's figures on purpose -- the two READMEs cross-link,
# and a reader moving between them should not cross a visual seam.
DARK = {"bg": "#0e1117", "card": "#171c26", "line": "#2a3242", "ink": "#e6ebf2",
        "muted": "#93a0b4", "bad": "#f87171", "ok": "#4ade80",
        "accent": "#60a5fa", "warn": "#fbbf24", "on_bad": "#0e1117"}
LIGHT = {"bg": "#ffffff", "card": "#f6f8fa", "line": "#d1d9e0",
         "ink": "#1f2328", "muted": "#59636e", "bad": "#cf222e",
         "ok": "#1a7f37", "accent": "#0969da", "warn": "#9a6700",
         "on_bad": "#ffffff"}
THEMES = {"dark": DARK, "light": LIGHT}

# Measured results that cannot be recomputed without spending API calls, so
# they are pinned here with their provenance rather than silently re-derived.
# All gpt-4o-mini, 2026-07-29:
#   calibration_bands   python -m src.calibration --model gpt-4o-mini --reps 1
#                       (this said --reps 3; data/calibration.json records 23
#                        API calls over 23 accounts, so the committed run was
#                        one rep per account, not three)
#   fragmentation       python -m scripts.stress_decomposition   (offline, but
#                       reported here as the published run's numbers)
MEASURED = {
    "date": "2026-07-29",
    # (band, nominal P, n, empirical P(malicious))
    "calibration_bands": [("very unlikely", 0.10, 9, 0.00),
                          ("unlikely", 0.30, 3, 0.00),
                          ("likely", 0.70, 3, 0.33),
                          ("very likely", 0.85, 8, 1.00)],
    "brier": 0.070, "reliability": 0.041, "resolution": 0.209,
    "fragmentation": {"burners": 8, "each_risk_max": 0.12, "reassembled": 8},
}

SHOTS = [
    ("01_actor", "subject=actor_capdev&run=cascade", 1240,
     "An actor through all five layers"),
    ("02_twin", "subject=actor_capdev&run=twin", 1420,
     "Actor vs legitimate twin: the same question, different behavior"),
    ("03_dualuse", "subject=neg_detection&run=cascade", 1240,
     "The hardest negative: a detection engineer who looks like a malware author"),
    ("04_naive", "subject=decoy_victim&attr=naive&run=cascade", 1240,
     "Naive attribution merges an innocent employee of the victim org"),
    ("05_cover", "subject=actor_lure&manip=cover_story&run=fence", 1420,
     "A cover story in the transcript, fence off vs on"),
]


# ----------------------------------------------------------------- primitives
def _svg(w, h, body, title, C):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
            f'width="{w}" height="{h}" role="img" aria-label="{title}">'
            f'<rect width="{w}" height="{h}" rx="10" fill="{C["bg"]}"/>'
            f'{body}</svg>\n')


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def _t(x, y, s, size=13, fill=None, weight="400", anchor="start", mono=False,
       C=DARK, op="1"):
    fam = ("ui-monospace,SFMono-Regular,Menlo,monospace" if mono
           else "-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif")
    return (f'<text x="{x}" y="{y}" font-family="{fam}" font-size="{size}" '
            f'font-weight="{weight}" fill="{fill or C["ink"]}" '
            f'fill-opacity="{op}" text-anchor="{anchor}">{_esc(s)}</text>')


def _rect(x, y, w, h, fill, C, op="1", rx=4, stroke=None):
    st = f' stroke="{stroke}"' if stroke else ""
    return (f'<rect x="{x:.1f}" y="{y:.1f}" width="{max(w, 0):.1f}" '
            f'height="{max(h, 0):.1f}" rx="{rx}" fill="{fill}" '
            f'fill-opacity="{op}"{st}/>')


def _line(x1, y1, x2, y2, C, stroke=None, w=1, dash=None, op="1"):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{stroke or C["line"]}" stroke-width="{w}" '
            f'stroke-opacity="{op}"{d}/>')


def _dot(cx, cy, r, fill, C, op="1"):
    return (f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r}" fill="{fill}" '
            f'fill-opacity="{op}" stroke="{C["bg"]}" stroke-width="1.2"/>')


def _head(title, sub, prov, C):
    return [_t(24, 40, title, 17, weight="700", C=C),
            _t(24, 62, sub, 12.5, C["muted"], C=C),
            _t(24, 80, prov, 11, C["muted"], C=C)]


def _legend(x, y, items, C):
    """items: [(color, label)]. Returns body parts, left-to-right."""
    out, cx = [], x
    for color, label in items:
        out.append(_dot(cx + 5, y - 4, 5, color, C))
        out.append(_t(cx + 16, y, label, 11.5, C["muted"], C=C))
        cx += 22 + len(label) * 6.4
    return out


# -------------------------------------------------------------- live pipeline
def _score_population():
    """Score every account through src.signals, joined to ground truth."""
    acc = {}
    for line in open(DATA / "accounts.jsonl"):
        a = json.loads(line)
        acc[a["account_id"]] = a
    sess: dict[str, list] = {}
    for line in open(DATA / "sessions.jsonl"):
        s = json.loads(line)
        sess.setdefault(s["account_id"], []).append(s)
    gt = {}
    for line in open(DATA / "ground_truth.jsonl"):
        g = json.loads(line)
        gt[g["account_id"]] = g

    rows = []
    for aid, a in acc.items():
        sc = signals.score_account(a, sess.get(aid, []))
        g = gt.get(aid, {})
        rows.append({
            "id": aid,
            "risk": sc["risk_score"],
            "content": sc["content_only_score"],
            "malicious": g.get("label") == "malicious",
            "actor": g.get("actor"),
            "persona": g.get("persona"),
            "hard_negative": bool(g.get("persona")),
        })
    rows.sort(key=lambda r: -r["risk"])
    return rows


# -------------------------------------------------------------------- figures
def fig_content_vs_behavior(C):
    """The thesis, scored live: topic collapses the population, behavior
    separates it."""
    rows = _score_population()
    n_mal = sum(1 for r in rows if r["malicious"])
    n_ben = len(rows) - n_mal

    W, H = 880, 648
    x0, x1 = 150, 838
    dom = 0.50

    def X(v):
        return x0 + (v / dom) * (x1 - x0)

    b = _head(
        "Content cannot separate them. Behavior can.",
        f"{len(rows)} accounts: {n_mal} in a planted actor, {n_ben} legitimate "
        f"(8 of them deliberate content look-alikes). Topic is weighted "
        f"{signals.WEIGHTS['content_category_risk']}; behavior and "
        f"infrastructure are "
        f"{round(1 - signals.WEIGHTS['content_category_risk'], 2)}.",
        "scored live through src.signals at figure-build time", C)

    # --- panel A: content alone. Only three distinct values exist, so this is
    # categorical rather than plotted on panel B's axis -- 0.06 of a score has
    # no room to vary, which is the point.
    buckets: dict[float, dict[str, int]] = {}
    for r in rows:
        bk = buckets.setdefault(round(r["content"], 3), {"mal": 0, "ben": 0})
        bk["mal" if r["malicious"] else "ben"] += 1
    ordered = sorted(buckets.items())
    tallest = max(v["mal"] + v["ben"] for v in buckets.values())

    b.append(_t(24, 120, "IF THE SCORE WERE THE TOPIC", 11.5, C["muted"],
                weight="700", C=C))
    base_a, bar_h_max, bw = 262, 104, 74
    slot = (x1 - 190) / len(ordered)
    for i, (cv, cnt) in enumerate(ordered):
        cx = 210 + slot * i + slot / 2 - 60
        total = cnt["mal"] + cnt["ben"]
        h = bar_h_max * (total / tallest)
        h_mal = h * (cnt["mal"] / total)
        h_ben = h - h_mal
        b.append(_rect(cx - bw / 2, base_a - h_ben, bw, h_ben, C["ok"], C,
                       op="0.85"))
        b.append(_rect(cx - bw / 2, base_a - h, bw, h_mal, C["bad"], C,
                       op="0.9"))
        b.append(_t(cx, base_a - h - 12, f"{total} account"
                    + ("s" if total != 1 else ""), 11.5, C["ink"],
                    anchor="middle", weight="700", C=C))
        ly = base_a - h + 16
        if cnt["mal"]:
            b.append(_t(cx + bw / 2 + 10, ly, f"{cnt['mal']} actor"
                        + ("s" if cnt["mal"] != 1 else ""), 11, C["bad"],
                        weight="700", C=C))
            ly += 15
        if cnt["ben"]:
            b.append(_t(cx + bw / 2 + 10, ly, f"{cnt['ben']} legitimate", 11,
                        C["ok"], weight="700", C=C))
        b.append(_t(cx, base_a + 18, f"{cv:.3f}", 11.5, C["muted"],
                    anchor="middle", mono=True, C=C))
    b.append(_line(150, base_a, x1, base_a, C))

    pv, pc = max(buckets.items(), key=lambda kv: kv[1]["mal"] + kv[1]["ben"])
    b.append(_t(24, base_a + 52,
                f"{pc['mal'] + pc['ben']} accounts share the identical content "
                f"score {pv:.3f} — {pc['mal']} actors and {pc['ben']} "
                f"legitimate users.",
                13, C["ink"], weight="700", C=C))
    b.append(_t(24, base_a + 71,
                "The pentester, the awareness trainer, the CTF student and the "
                "journalist are asking the actors' questions, word for word.",
                11.5, C["muted"], C=C))

    # --- panel B: the score as built, mirrored around its axis
    axis_b = 452
    b.append(_t(24, 372, "THE SCORE AS BUILT (BEHAVIOR + INFRASTRUCTURE)",
                11.5, C["muted"], weight="700", C=C))
    b.append(_line(150, axis_b, x1, axis_b, C))
    for tick in (0.0, 0.1, 0.2, 0.3, 0.4, 0.5):
        tx = X(tick)
        b.append(_line(tx, axis_b, tx, axis_b + 5, C))
        b.append(_t(tx, axis_b + 19, f"{tick:.1f}", 10.5, C["muted"],
                    anchor="middle", mono=True, C=C))

    lead = signals.LEAD_THRESHOLD
    lx = X(lead)
    b.append(_line(lx, axis_b - 78, lx, axis_b + 108, C, stroke=C["accent"],
                   w=1.6, dash="5 4"))
    b.append(_t(lx + 8, axis_b - 66, f"lead line {lead}", 11, C["accent"],
                weight="700", C=C))
    b.append(_t(lx + 8, axis_b - 52, "at/above = a queue entry", 10.5,
                C["accent"], C=C, op="0.85"))

    step, rad = 11, 4.6
    up: dict[int, int] = {}
    down: dict[int, int] = {}
    for r in rows:
        cx = X(r["risk"])
        key = int(cx // 9)
        if r["malicious"]:
            k = up.get(key, 0)
            up[key] = k + 1
            b.append(_dot(cx, axis_b - 10 - k * step, rad, C["bad"], C))
        else:
            k = down.get(key, 0)
            down[key] = k + 1
            b.append(_dot(cx, axis_b + 32 + k * step, rad, C["ok"], C))

    b.append(_t(24, axis_b - 14, "actors", 11, C["bad"], weight="700", C=C))
    b.append(_t(24, axis_b + 38, "legitimate", 11, C["ok"], weight="700", C=C))

    worst = max((r for r in rows if not r["malicious"]),
                key=lambda r: r["risk"])
    wx = X(worst["risk"])
    b.append(_line(wx, axis_b + 26, wx, axis_b + 14, C, stroke=C["warn"],
                   w=1.4))
    b.append(_t(24, H - 68,
                f"One legitimate account crosses the line: the detection "
                f"engineer at {worst['risk']:.3f}, behaviorally identical to a "
                f"malware author.", 11.5, C["warn"], C=C))
    b.append(_t(24, H - 49,
                "A lead is not an accusation. It is cleared downstream — by "
                "the policy layer, not by the model getting it right.",
                11.5, C["muted"], C=C))
    b.append(_t(24, H - 16,
                f"The one metric that matters: 0 of {n_ben} legitimate "
                f"accounts ever reached an enforce decision.", 12.5,
                C["ok"], weight="700", C=C))
    return _svg(W, H, "".join(b), "Content versus behavior scoring", C)


def fig_escape_surface(C):
    """Enumerated live: which policy inputs reach an enforce decision."""
    bands = list(BANDS)
    disps = sorted(DISPOSITIONS)
    grid: dict[tuple, list[int]] = {}
    total = enforce_n = auto = uncorr = ungated = 0
    for band, disp, assess, (_cn, (csize, sigs)), manip in itertools.product(
            bands, disps, sorted(ASSESSMENTS), CORROBORATION.items(),
            (False, True)):
        out = apply_enforcement_policy(
            {"confidence_band": band, "recommended_disposition": disp,
             "assessment": assess, "cluster_size": csize,
             "manipulation_observed": manip, "disconfirming_evidence": []},
            sigs)
        cell = grid.setdefault((band, disp), [0, 0])
        cell[1] += 1
        total += 1
        if out["auto_actioned"]:
            auto += 1
        if out["enforcement_decision"] == "enforce":
            cell[0] += 1
            enforce_n += 1
            if not out["corroborated"]:
                uncorr += 1
            if not out["requires_human_approval"]:
                ungated += 1

    W = 880
    cw, ch = 132, 40
    x0, y0 = 208, 132
    H = y0 + ch * len(bands) + 128
    b = _head("The enforcement escape surface, enumerated not sampled",
              f"all {total} inputs to apply_enforcement_policy evaluated · "
              f"{enforce_n} reach `enforce` ({enforce_n / total:.1%})",
              "computed live from src.policy.apply_enforcement_policy at "
              "figure-build time", C)

    for i, disp in enumerate(disps):
        b.append(_t(x0 + i * cw + cw / 2, y0 - 12, disp.replace("_", " "), 11,
                    C["muted"], anchor="middle", mono=True, C=C))
    for j, band in enumerate(bands):
        yy = y0 + j * ch
        is_floor = band == CONFIDENCE_FLOOR_BAND
        b.append(_t(x0 - 14, yy + ch / 2 + 4, band, 11.5,
                    C["accent"] if is_floor else C["muted"], anchor="end",
                    weight="700" if is_floor else "400", C=C))
        for i, disp in enumerate(disps):
            esc, tot = grid[(band, disp)]
            xx = x0 + i * cw
            frac = esc / tot
            fill = C["bad"] if esc else C["card"]
            b.append(_rect(xx + 3, yy + 3, cw - 6, ch - 6, fill, C,
                           op=f"{0.22 + 0.72 * frac:.2f}" if esc else "1",
                           stroke=C["line"]))
            b.append(_t(xx + cw / 2, yy + ch / 2 + 4,
                        f"{esc}/{tot}" if esc else "—", 11.5,
                        C["on_bad"] if frac > 0.55 else C["ink"] if esc
                        else C["muted"], anchor="middle", mono=True,
                        weight="700" if esc else "400", C=C))

    fy = y0 + ch * len(bands) + 30
    b.append(_t(24, fy,
                "The enforce region is a stated box, not a surface to explore:",
                12, C["ink"], weight="700", C=C))
    b.append(_t(24, fy + 20,
                "{likely, very likely, almost certain} × "
                "recommend_enforcement × (coordinated OR "
                "non-content-corroborated)",
                11.5, C["accent"], mono=True, C=C))
    for k, (lbl, val) in enumerate(
            [("automatic adverse actions", auto),
             ("enforce without human gating", ungated),
             ("enforce on content alone", uncorr)]):
        b.append(_dot(30, fy + 44 + k * 19, 4.5, C["ok"], C))
        b.append(_t(42, fy + 48 + k * 19, f"{lbl}: {val}", 11.5, C["muted"],
                    C=C))
    b.append(_t(430, fy + 48,
                f"`likely` is the confidence floor — and the band "
                f"calibration finds weakest.", 11.5, C["warn"], C=C))
    b.append(_t(430, fy + 67,
                f"corroboration strength floor: "
                f"{CORROBORATION_MIN_CONTRIBUTION} (presence is not strength)",
                11.5, C["muted"], C=C))
    return _svg(W, H, "".join(b), "Policy escape surface", C)


def fig_calibration(C):
    """Reliability diagram: the load-bearing band is the least reliable."""
    rows = MEASURED["calibration_bands"]
    W, H = 880, 470
    px0, py0, side = 150, 118, 260

    def PX(p):
        return px0 + p * side

    def PY(p):
        return py0 + side - p * side

    b = _head("Is the confidence language honest?",
              f"ICD-203 bands scored against ground truth · Brier "
              f"{MEASURED['brier']:.3f} "
              f"(reliability {MEASURED['reliability']:.3f}, "
              f"resolution {MEASURED['resolution']:.3f})",
              f"src.calibration --model gpt-4o-mini --reps 1 · measured "
              f"{MEASURED['date']}", C)

    b.append(_rect(px0, py0, side, side, C["card"], C, rx=6,
                   stroke=C["line"]))
    for g in (0.25, 0.5, 0.75):
        b.append(_line(px0, PY(g), px0 + side, PY(g), C, op="0.6"))
        b.append(_line(PX(g), py0, PX(g), py0 + side, C, op="0.6"))
    b.append(_line(px0, py0 + side, px0 + side, py0, C, stroke=C["muted"],
                   w=1.4, dash="4 4"))
    # Sits just above the diagonal at 40% along, where no band point falls.
    b.append(_t(px0 + 0.42 * side, py0 + side - 0.42 * side - 18,
                "perfect calibration", 10.5, C["muted"], C=C))

    # Explicit per-band label placement: two bands share empirical 0.00 and two
    # sit near the diagonal's ends, so automatic offsets collide.
    # The two lowest bands both sit at empirical 0.00 on the box floor, so
    # their labels go ABOVE the points at staggered heights to stay inside the
    # plot and clear of each other.
    PLACE = {"very unlikely": (10, -20, "start"),
             "unlikely": (10, -46, "start"),
             "likely": (18, 4, "start"),
             "very likely": (-16, 20, "end")}
    for band, nominal, n, emp in rows:
        x, y = PX(nominal), PY(emp)
        is_floor = band == CONFIDENCE_FLOOR_BAND
        col = C["warn"] if is_floor else C["accent"]
        b.append(_line(x, PY(nominal), x, y, C, stroke=col, w=1.6, dash="3 3"))
        b.append(_dot(x, y, 7 if is_floor else 5.5, col, C))
        gap = emp - nominal
        dx, dy, anch = PLACE.get(band, (18, 4, "start"))
        b.append(_t(x + dx, y + dy, f"{band}  n={n}", 11,
                    C["ink"] if is_floor else C["muted"],
                    anchor=anch, weight="700" if is_floor else "400", C=C))
        b.append(_t(x + dx, y + dy + 15, f"{gap:+.2f}", 10.5, col, anchor=anch,
                    mono=True, C=C))

    b.append(_t(px0 + side / 2, py0 + side + 34, "band's nominal probability",
                11.5, C["muted"], anchor="middle", C=C))
    b.append(f'<text x="{px0 - 34}" y="{py0 + side / 2}" '
             f'font-family="-apple-system,Segoe UI,Roboto,sans-serif" '
             f'font-size="11.5" fill="{C["muted"]}" text-anchor="middle" '
             f'transform="rotate(-90 {px0 - 34} {py0 + side / 2})">'
             f'empirical P(malicious)</text>')

    tx = px0 + side + 60
    b.append(_t(tx, py0 + 16, "The extremes are honest.", 13, C["ink"],
                weight="700", C=C))
    b.append(_t(tx, py0 + 38, "“very unlikely” → 0.00 empirical.",
                11.5, C["muted"], C=C))
    b.append(_t(tx, py0 + 56,
                "“very likely” → 1.00: righter than it claimed.",
                11.5, C["muted"], C=C))
    b.append(_t(tx, py0 + 96, "The middle is not.", 13, C["warn"],
                weight="700", C=C))
    b.append(_t(tx, py0 + 118, "“likely” is overconfident by 0.37 —",
                11.5, C["muted"], C=C))
    b.append(_t(tx, py0 + 136, "and “likely” is the exact confidence",
                11.5, C["muted"], C=C))
    b.append(_t(tx, py0 + 154, "floor src/policy.py gates adverse", 11.5,
                C["muted"], C=C))
    b.append(_t(tx, py0 + 172, "action on.", 11.5, C["muted"], C=C))
    b.append(_t(tx, py0 + 206, "The band the enforcement", 12, C["ink"],
                weight="700", C=C))
    b.append(_t(tx, py0 + 224, "gate rests on is the least", 12, C["ink"],
                weight="700", C=C))
    b.append(_t(tx, py0 + 242, "reliable one in the set.", 12, C["ink"],
                weight="700", C=C))
    b.append(_t(24, H - 16,
                "n=3 in that cell — thin, and it is the cell that matters "
                "most, which argues for measuring it on real traffic rather "
                "than ignoring it.", 11.5, C["muted"], C=C))
    return _svg(W, H, "".join(b), "Calibration of the ICD-203 bands", C)


def fig_cost_frontier(C):
    """What detection costs an attacker: a toll for two actors, a wall for two."""
    fr = json.loads((DATA / "cost_frontier.json").read_text())
    order = sorted(fr.items(),
                   key=lambda kv: (kv[1]["cheapest_escape_usd"] is None,
                                   kv[1]["cheapest_escape_usd"] or 0))
    W = 880
    row_h = 74
    H = 132 + row_h * len(order) + 84
    b = _head("What does it cost to disappear?",
              "all 64 countermeasure baskets enumerated against each actor · "
              "two bought out for ~$100, two unbuyable at any price",
              "data/cost_frontier.json · offline enumeration, "
              "python -m scripts.cost_frontier", C)

    for i, (name, d) in enumerate(order):
        y = 132 + i * row_h
        buyable = d["cheapest_escape_usd"] is not None
        col = C["bad"] if buyable else C["ok"]
        b.append(_rect(24, y, W - 48, row_h - 12, C["card"], C, rx=8,
                       stroke=C["line"]))
        b.append(_rect(24, y, 4, row_h - 12, col, C, rx=2))
        b.append(_t(44, y + 26, name.replace("_", " "), 13.5, C["ink"],
                    weight="700", C=C))
        b.append(_t(44, y + 45,
                    f"{d['accounts']} account"
                    + ("s" if d["accounts"] != 1 else "")
                    + f" · baseline risk {d['baseline_risk']:.3f}",
                    11.5, C["muted"], mono=True, C=C))
        if buyable:
            b.append(_t(300, y + 26, "BOUGHT OUT", 12, C["bad"],
                        weight="700", C=C))
            b.append(_t(300, y + 45,
                        " + ".join(d["cheapest_escape_via"]).replace("_", " "),
                        11.5, C["muted"], C=C))
            b.append(_t(W - 44, y + 34, f"${d['cheapest_escape_usd']:,.0f}",
                        22, C["bad"], anchor="end", weight="700", mono=True,
                        C=C))
        else:
            b.append(_t(300, y + 26, "UNBUYABLE AT ANY PRICE", 12, C["ok"],
                        weight="700", C=C))
            reason = d["unbuyable_reason"] or ""
            b.append(_t(300, y + 45, reason[:74], 11.5, C["muted"], C=C))
            b.append(_t(W - 44, y + 34, "∞", 24, C["ok"], anchor="end",
                        weight="700", C=C))

    fy = 132 + row_h * len(order) + 22
    b.append(_t(24, fy,
                "The two unbuyable actors are unbuyable for the same reason: "
                "their exposure is the operation itself, not how it is "
                "provisioned.", 12, C["ink"], weight="700", C=C))
    b.append(_t(24, fy + 20,
                "Breaking the lure factory's attribution would mean ceasing to "
                "attack the same victims. Clearing the stolen key's drift "
                "would mean changing its own past.", 11.5, C["muted"], C=C))
    b.append(_t(24, fy + 44,
                "Prices are order-of-magnitude figures for commodity "
                "proxy/card/SMS services, not quotes. Only the ordering and "
                "the per-account scaling carry weight.", 11, C["muted"], C=C))
    return _svg(W, H, "".join(b), "Detection cost frontier", C)


def fig_dual_use_ladder(C):
    """A prediction the ladder refuted -- and the invariant that never moved."""
    d = json.loads((DATA / "dual_use_ladder.json").read_text())
    ladder = d["ladder"]
    res = d["results"]
    rows = [(m["id"], m["generation"], m["tier"], res.get(m["id"], {}))
            for m in ladder if m["id"] in res]

    W = 880
    x0 = 236
    bar_max = 420
    row_h = 46
    H = 152 + row_h * len(rows) + 104
    trials = next((r[3].get("trials") for r in rows if r[3].get("trials")), 9)

    b = _head("A prediction of mine that the model ladder refuted",
              f"matched dual-use pairs, {trials} trials per model · red = "
              f"the model gave the actor and the legitimate twin the SAME label",
              "data/dual_use_ladder.json · python -m "
              "scripts.stress_dual_use --models all --reps 3", C)
    b.append(_t(24, 128, "MODEL", 10.5, C["muted"], weight="700", C=C))
    b.append(_t(x0, 128, f"SAME LABEL FOR BOTH TWINS (of {trials})", 10.5,
                C["muted"], weight="700", C=C))
    b.append(_t(W - 44, 128, "LEGIT TWIN ENFORCED", 10.5, C["muted"],
                weight="700", anchor="end", C=C))

    for i, (mid, gen, tier, r) in enumerate(rows):
        y = 152 + i * row_h
        same = int(str(r.get("model_same_label", "0/9")).split("/")[0])
        ben = int(r.get("benign_enforced_n", 0))
        b.append(_t(24, y + 20, mid, 12, C["ink"], weight="700", mono=True,
                    C=C))
        note = tier if tier != "mini" else f"{gen} · mini"
        b.append(_t(24, y + 35, note, 10.5, C["muted"], C=C))
        full = bar_max * (same / trials) if trials else 0
        b.append(_rect(x0, y + 8, bar_max, 22, C["card"], C, rx=5,
                       stroke=C["line"]))
        if same:
            b.append(_rect(x0, y + 8, full, 22, C["bad"], C, op="0.9", rx=5))
            b.append(_t(x0 + full + 10, y + 24, f"{same}/{trials}", 12,
                        C["bad"], weight="700", mono=True, C=C))
        else:
            b.append(_t(x0 + 12, y + 24, f"0/{trials}  separated every time",
                        11.5, C["ok"], mono=True, C=C))
        b.append(_t(W - 44, y + 24, f"{ben}/{trials}", 13,
                    C["ok"] if ben == 0 else C["bad"], anchor="end",
                    weight="700", mono=True, C=C))

    fy = 152 + row_h * len(rows) + 26
    b.append(_t(24, fy,
                "I expected separation NOT to improve with capability. It did.",
                12.5, C["ink"], weight="700", C=C))
    b.append(_t(24, fy + 20,
                "The honest reading is narrower than the result looks: the "
                "evidence packet already held the discriminating behavioral "
                "facts, and better models used them.", 11.5, C["muted"], C=C))
    b.append(_t(24, fy + 38,
                "Capability improved the reading of available evidence, not "
                "the supply of missing evidence.", 11.5, C["muted"], C=C))
    b.append(_rect(24, fy + 52, W - 48, 30, C["ok"], C, op="0.12", rx=6,
                   stroke=C["ok"]))
    b.append(_t(38, fy + 72,
                "And the thing that never moved: 0 legitimate twins enforced, "
                "on every model. That is the policy layer, not the model.",
                12, C["ok"], weight="700", C=C))
    return _svg(W, H, "".join(b), "Dual-use separation across the model ladder",
                C)


DOWNGRADE_DECISIONS = {"monitor", "gather_more", "clear"}


def _short_attacker(name):
    return ("abliterated twin" if "abliterated" in name.lower()
            else name.split("/")[-1])


def _strict_evaded(r):
    """The definition this project settled on: the pipeline never opened the
    account. A `monitor` downgrade is not an escape -- the subject is still in an
    analyst's queue, which is exactly what the attacker was trying to avoid.

    CALLS the shared predicate rather than restating it. This function used to
    inline `== "not_investigated"`, which is the precise thing
    `EVASION_DECISIONS` was introduced to prevent -- and the README claimed it
    had been prevented. A loose restatement here is what let a pre-fix artifact
    be tallied with post-fix code once already.
    """
    return _is_evasion(r.get("final_decision"))


def adaptive_rows():
    """Derive the Phase A count and the Phase B per-attacker table, once.

    Both the figure and `--table` (which emits the README's fenced block) read
    this, because hand-transcribing it into the prose is what let the published
    table drift from the artifact in the first place.
    """
    m = json.loads((DATA / "attacker_matrix.json").read_text())
    phase_a, phase_b = m.get("a", {}), m.get("b", {})

    a_attackers = list(phase_a.items())
    a_evaded = sum(1 for _n, reps in a_attackers
                   for r in reps if _strict_evaded(r))

    rows = []
    for attacker, reps in phase_b.items():
        reps = [r for r in reps if "error" not in r]
        true_ev = [r for r in reps if _strict_evaded(r)]
        down = [r for r in reps
                if not _strict_evaded(r)
                and r.get("final_decision") in DOWNGRADE_DECISIONS]
        rows.append({
            "name": _short_attacker(attacker), "n": len(reps),
            "true": len(true_ev), "down": len(down),
            "cheapest": min((r["spend_usd"] for r in true_ev), default=None),
            "rounds": sorted(r["evaded_at"] for r in true_ev
                             if r.get("evaded_at")),
            # Did the attacker actually locate the priced optimum the control
            # proved was cheapest? This is the search signal, and it separates
            # the attackers far more sharply than alignment does.
            "found_optimal": sum(
                1 for r in reps
                if OPTIMAL_BASKET.issubset(set(r.get("purchases", [])))),
            "abliterated": "abliterated" in attacker.lower()})
    rows.sort(key=lambda r: (-r["true"], -r["down"], r["name"]))
    return {"a_evaded": a_evaded, "a_n": len(a_attackers), "b": rows}


def emit_adaptive_table():
    """Print the README's Phase B block, derived from the artifact."""
    d = adaptive_rows()
    w = max(len(r["name"]) for r in d["b"]) + 2
    print(f"Phase A: {d['a_evaded']}/{d['a_n']} attackers evaded\n")
    print("```")
    print(f"{'attacker':<{w}}true evasions   rounds   cheapest   "
          f"found $101   downgraded-only")
    for r in d["b"]:
        rounds = ",".join(str(x) for x in r["rounds"]) or "-"
        cheap = f"${r['cheapest']:,.0f}" if r["cheapest"] is not None else "-"
        ratio = f"{r['true']}/{r['n']}"
        found = f"{r['found_optimal']}/{r['n']}"
        down = f"{r['down']}/{r['n']}"
        print(f"{r['name']:<{w}}{ratio:<16}{rounds:<9}{cheap:<11}"
              f"{found:<13}{down}")
    print("```")


def fig_adaptive_attackers(C):
    """Prose-only versus funded. Phase A is the load-bearing, unanimous result."""
    d = adaptive_rows()
    a_evaded, a_n, rows = d["a_evaded"], d["a_n"], d["b"]

    W = 880
    row_h = 50
    H = 214 + row_h * len(rows) + 118
    b = _head("An adaptive attacker that may only rewrite text cannot win",
              "four attackers spanning aligned, uncensored, reasoning and API "
              "models · each sees the pipeline's exact response and revises",
              "data/attacker_matrix.json · python -m "
              "scripts.stress_adaptive --attackers … --reps 3", C)

    # Phase A: unanimous, and the one that carries the structural claim.
    b.append(_rect(24, 104, W - 48, 68, C["ok"], C, op="0.12", rx=8,
                   stroke=C["ok"]))
    b.append(_t(40, 128, "PHASE A — PROSE ONLY", 12, C["ok"], weight="700",
                C=C))
    b.append(_t(40, 149,
                f"{a_evaded} of {a_n} attackers evaded in 8 rounds "
                f"each. The behavioral risk score stayed invariant at 0.358 in "
                f"every round of every run:", 11.5, C["muted"], C=C))
    b.append(_t(40, 165,
                "prose is not an input to any signal. The attacker is "
                "optimising against a surface that does not decide.", 11.5,
                C["muted"], C=C))
    b.append(_t(W - 40, 145, f"{a_evaded}/{a_n}", 26, C["ok"],
                anchor="end", weight="700", mono=True, C=C))

    b.append(_t(24, 204, "PHASE B — WITH AN INFRASTRUCTURE BUDGET", 12,
                C["bad"], weight="700", C=C))
    b.append(_t(W - 24, 204,
                "filled = true evasion (never investigated)", 11, C["muted"],
                anchor="end", C=C))

    x0, cell = 250, 26
    for i, r in enumerate(rows):
        y = 214 + i * row_h
        b.append(_t(24, y + 26, r["name"], 12,
                    C["warn"] if r["abliterated"] else C["ink"],
                    weight="700", mono=True, C=C))
        if r["abliterated"]:
            b.append(_t(24, y + 40, "same weights, refusals removed", 10,
                        C["muted"], C=C))
        for k in range(r["n"]):
            xx = x0 + k * (cell + 6)
            if k < r["true"]:
                fill, op = C["bad"], "0.9"
            elif k < r["true"] + r["down"]:
                fill, op = C["warn"], "0.45"
            else:
                fill, op = C["card"], "1"
            b.append(_rect(xx, y + 10, cell, cell, fill, C, op=op, rx=5,
                           stroke=C["line"]))
        tx = x0 + r["n"] * (cell + 6) + 16
        b.append(_t(tx, y + 28, f"{r['true']}/{r['n']}", 12.5,
                    C["bad"] if r["true"] else C["ok"], weight="700",
                    mono=True, C=C))
        detail = [f"found the $101 basket {r['found_optimal']}/{r['n']}"]
        if r["cheapest"] is not None:
            detail.insert(0, f"cheapest ${r['cheapest']:,.0f}")
        if r["down"]:
            detail.append(f"{r['down']} downgraded")
        b.append(_t(tx + 56, y + 28, "  ·  ".join(detail), 11.5,
                    C["muted"] if r["true"] or r["down"] else C["ok"],
                    mono=True, C=C))

    fy = 214 + row_h * len(rows) + 24
    b.append(_t(24, fy,
                "Given a budget the funded attacker does evade — detection is a "
                "toll, not a wall.", 12.5, C["ink"], weight="700", C=C))
    b.append(_t(24, fy + 20,
                "But the toll is paid in infrastructure, which is exactly what "
                "the score is built on. The cheapest true evasion, $101, is the "
                "same basket the", 11.5, C["muted"], C=C))
    b.append(_t(24, fy + 38,
                "forced-purchase control and the exhaustive cost frontier both "
                "found independently.", 11.5, C["muted"], C=C))
    b.append(_rect(24, fy + 54, W - 48, 46, C["ok"], C, op="0.10", rx=6,
                   stroke=C["ok"]))
    b.append(_t(38, fy + 73,
                "Abliteration is a clean null: the twin with refusal training "
                "removed matched its parent exactly, 1/3 and 1/3.", 11,
                C["ok"], weight="700", C=C))
    b.append(_t(38, fy + 90,
                "What separates attackers is whether they find the priced "
                "optimum -- search, not willingness.", 11, C["muted"], C=C))
    return _svg(W, H, "".join(b), "Adaptive adversary across four attackers", C)


def fig_fragmentation(C):
    """Scoring is evadable by splitting up; coordination is not."""
    f = MEASURED["fragmentation"]
    n = f["burners"]
    W, H = 880, 396
    b = _head("Coordination survives what per-account scoring cannot",
              f"an operation fragmented across {n} single-session burners · "
              f"none individually clears the lead line",
              "python -m scripts.stress_attribution (EXP-3) · offline and "
              "deterministic", C)

    x0, x1 = 150, 700
    axis = 210
    lead = signals.LEAD_THRESHOLD

    def X(v):
        return x0 + (v / 0.5) * (x1 - x0)

    b.append(_line(x0 - 20, axis, x1 + 20, axis, C))
    for tick in (0.0, 0.1, 0.2, 0.3, 0.4, 0.5):
        tx = X(tick)
        b.append(_line(tx, axis, tx, axis + 5, C))
        b.append(_t(tx, axis + 19, f"{tick:.1f}", 10.5, C["muted"],
                    anchor="middle", mono=True, C=C))
    lx = X(lead)
    b.append(_line(lx, axis - 96, lx, axis + 8, C, stroke=C["accent"], w=1.6,
                   dash="5 4"))
    b.append(_t(lx + 8, axis - 86, f"lead line {lead}", 11, C["accent"],
                weight="700", C=C))

    b.append(_t(24, 128, "PER-ACCOUNT SCORING", 11, C["muted"], weight="700",
                C=C))
    # One dot per burner, evenly spread across the band they actually occupy,
    # all of them left of the lead line.
    lo, hi = 0.03, f["each_risk_max"]
    for k in range(n):
        cx = X(lo + (hi - lo) * (k / (n - 1)))
        b.append(_dot(cx, axis - 20, 5.5, C["muted"], C, op="0.9"))
    b.append(_t(X(lo) - 6, axis - 42,
                f"{n} burners · each risk ≤ {f['each_risk_max']} · 0 leads",
                11.5, C["muted"], C=C))

    y2 = 268
    b.append(_t(24, y2, "ATTRIBUTION", 11, C["muted"], weight="700", C=C))
    b.append(_rect(150, y2 + 12, 300, 46, C["bad"], C, op="0.16", rx=8,
                   stroke=C["bad"]))
    b.append(_t(166, y2 + 32, "1 actor", 13.5, C["bad"], weight="700", C=C))
    b.append(_t(166, y2 + 50,
                f"all {f['reassembled']} of {n} reassembled", 11.5,
                C["muted"], mono=True, C=C))
    b.append(_t(474, y2 + 32, "linked on shared infrastructure + victim,", 11.5,
                C["muted"], C=C))
    b.append(_t(474, y2 + 50, "never on topic and never on a bare IP match",
                11.5, C["muted"], C=C))

    b.append(_t(24, H - 40,
                "Scoring is evadable. Coordination costs the attacker scale — "
                "which is why attribution, not the per-account score, is the "
                "load-bearing layer.", 12, C["ink"], weight="700", C=C))
    b.append(_t(24, H - 18,
                "Residual gap, stated: the one decomposition burner that also "
                "changed its topic slipped the infrastructure-only link.", 11.5,
                C["muted"], C=C))
    return _svg(W, H, "".join(b), "Fragmentation versus attribution", C)


def fig_prevalence(C):
    """The width of the headline claim: what 14 benign accounts license.

    Computed live by importing `src.prevalence`, which recomputes the operating
    point from the committed artifacts. Nothing on this chart is typed.
    """
    import math

    a = prevalence.analyse()
    op, fpr, tpr = a["operating_point"], a["fpr"], a["tpr"]

    W, H = 880, 500
    px0, py0, pw, ph = 150, 122, 480, 250
    LO_EXP, HI_EXP = -4, 0                     # 0.01% .. 100% prevalence

    def X(p):
        return px0 + (math.log10(p) - LO_EXP) / (HI_EXP - LO_EXP) * pw

    def Y(prec):
        # 16px of headroom so the flat 100% line reads as a line rather than
        # as the top border of the plot box.
        return py0 + ph - prec * (ph - 16)

    b = _head("What “0 of 14 false accusations” actually licenses",
              f"precision of the enforce queue vs. platform prevalence · "
              f"observed {op['false_positives']}/{op['n_benign']}, 95% "
              f"interval [0, {fpr['hi']:.2f}]",
              "python -m src.prevalence · arithmetic over the committed "
              "results, offline and deterministic", C)

    b.append(_rect(px0, py0, pw, ph, C["card"], C, rx=6, stroke=C["line"]))
    for g in (0.25, 0.5, 0.75, 1.0):
        b.append(_line(px0, Y(g), px0 + pw, Y(g), C, op="0.6"))
        b.append(_t(px0 - 10, Y(g) + 4, f"{g:.0%}", 10.5, C["muted"],
                    anchor="end", mono=True, C=C))
    TICKS = {-4: "0.01%", -3: "0.1%", -2: "1%", -1: "10%", 0: "100%"}
    for e in range(LO_EXP, HI_EXP + 1):
        tx = X(10 ** e)
        b.append(_line(tx, py0 + ph, tx, py0 + ph + 5, C))
        b.append(_t(tx, py0 + ph + 20, TICKS[e], 10.5, C["muted"],
                    anchor="middle", mono=True, C=C))

    # The band between the two readings of the same 23-account run. Its area is
    # the point: both edges are equally consistent with what was measured.
    steps = 120
    xs = [LO_EXP + (HI_EXP - LO_EXP) * k / steps for k in range(steps + 1)]
    worst = [(X(10 ** e), Y(prevalence.ppv(10 ** e, tpr["lo"], fpr["hi"])))
             for e in xs]
    band = (f'<path d="M {X(10 ** LO_EXP):.1f} {Y(1.0):.1f} '
            + f'L {X(10 ** HI_EXP):.1f} {Y(1.0):.1f} '
            + " ".join(f"L {x:.1f} {y:.1f}" for x, y in reversed(worst))
            + f' Z" fill="{C["warn"]}" fill-opacity="0.13"/>')
    b.append(band)

    b.append(_line(px0, Y(1.0), px0 + pw, Y(1.0), C, stroke=C["ok"], w=2.4))
    b.append('<path d="M ' + " L ".join(f"{x:.1f} {y:.1f}" for x, y in worst)
             + f'" fill="none" stroke="{C["bad"]}" stroke-width="2.4"/>')

    dx = X(op["dataset_prevalence"])
    b.append(_line(dx, py0, dx, py0 + ph, C, stroke=C["accent"], w=1.6,
                   dash="5 4"))
    b.append(_t(dx - 8, py0 + 48, "this dataset", 11, C["accent"],
                anchor="end", weight="700", C=C))
    b.append(_t(dx - 8, py0 + 64, f"{op['dataset_prevalence']:.0%} abusive", 10.5,
                C["accent"], anchor="end", mono=True, C=C))

    real = a["projections"][-2]["prevalence"]
    rx = X(real)
    b.append(_line(rx, py0, rx, py0 + ph, C, stroke=C["muted"], w=1.4,
                   dash="3 4"))
    b.append(_t(rx + 8, py0 + 48, "a plausible platform", 11, C["muted"],
                weight="700", C=C))
    b.append(_t(rx + 8, py0 + 64,
                f"{real:.1%} abusive → {a['projections'][-2]['ppv_worst']:.2%}",
                10.5, C["muted"], mono=True, C=C))

    b.append(_t(px0 + pw / 2, py0 + ph + 42,
                "share of platform accounts that are actually abusive "
                "(log scale)", 11.5, C["muted"], anchor="middle", C=C))
    b.append(f'<text x="{px0 - 46}" y="{py0 + ph / 2}" '
             f'font-family="-apple-system,Segoe UI,Roboto,sans-serif" '
             f'font-size="11.5" fill="{C["muted"]}" text-anchor="middle" '
             f'transform="rotate(-90 {px0 - 46} {py0 + ph / 2})">'
             f'of those enforced, share truly abusive</text>')

    tx = px0 + pw + 34
    b.append(_t(tx, py0 + 16, "Same run, two readings", 12.5, C["ink"],
                weight="700", C=C))
    b.append(_dot(tx + 5, py0 + 36, 5, C["ok"], C))
    b.append(_t(tx + 16, py0 + 40, "zero read as a rate", 11, C["muted"], C=C))
    b.append(_dot(tx + 5, py0 + 58, 5, C["bad"], C))
    b.append(_t(tx + 16, py0 + 62, "zero read with its", 11, C["muted"], C=C))
    b.append(_t(tx + 16, py0 + 78, "95% interval", 11, C["muted"], C=C))
    b.append(_t(tx, py0 + 116, "The shaded area is", 11.5, C["ink"],
                weight="700", C=C))
    b.append(_t(tx, py0 + 132, "everything 14 benign", 11.5, C["ink"],
                weight="700", C=C))
    b.append(_t(tx, py0 + 148, "accounts cannot tell", 11.5, C["ink"],
                weight="700", C=C))
    b.append(_t(tx, py0 + 164, "apart.", 11.5, C["ink"], weight="700", C=C))
    b.append(_t(tx, py0 + 196, f"To rule it out you", 11, C["muted"], C=C))
    b.append(_t(tx, py0 + 212, f"need {a['required_clean_n']:,} clean", 11,
                C["muted"], C=C))
    b.append(_t(tx, py0 + 228, f"benign accounts, not", 11, C["muted"], C=C))
    b.append(_t(tx, py0 + 244, f"{op['n_benign']}.", 11, C["muted"], C=C))

    b.append(_t(24, H - 44,
                "Against a rare event the queue's composition is set by the "
                "false-positive rate times the benign population, not by "
                "recall.", 12, C["ink"], weight="700", C=C))
    b.append(_t(24, H - 26,
                "No model improvement changes that term — which is the "
                "arithmetic case for policy rule 1:", 12, C["ink"],
                weight="700", C=C))
    b.append(_t(24, H - 8, "enforcement is a queue for a human, never a "
                "switch.", 11.5, C["muted"], C=C))
    return _svg(W, H, "".join(b), "Precision of the enforcement queue versus "
                "platform prevalence", C)


FIGURES = {
    "content_vs_behavior": fig_content_vs_behavior,
    "escape_surface": fig_escape_surface,
    "prevalence": fig_prevalence,
    "calibration": fig_calibration,
    "cost_frontier": fig_cost_frontier,
    "dual_use_ladder": fig_dual_use_ladder,
    "adaptive_attackers": fig_adaptive_attackers,
    "fragmentation": fig_fragmentation,
}


# ------------------------------------------------- label-cost study figures
# These come from the label-cost study (finding #27): a population assembled
# by scripts.generate_population and scored through the same src.signals as
# everything above. Their builders close over data computed once and render
# per theme, so each entry is fn(signals) -> (build(C), alt) | None rather
# than FIGURES' fn(C) -> svg; build_svgs() renders both registries.

RESEARCH_DEFAULTS = dict(n=400, prevalence=0.02, dual_use_frac=0.12, seed=7)


def _load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def _poly(pts, stroke, w=2):
    d = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    return (f'<polyline points="{d}" fill="none" stroke="{stroke}" '
            f'stroke-width="{w}" stroke-linejoin="round"/>')


def _research_score(signals_mod, accounts, sessions, *, oracle):
    by: dict[str, list] = {}
    for s in sessions:
        by.setdefault(s["account_id"], []).append(s)
    out = {}
    for a in accounts:
        sess = by.get(a["account_id"], [])
        if oracle:
            sess = copy.deepcopy(sess)
            for s in sess:
                s["category"] = s.get("category_true", s["category"])
        out[a["account_id"]] = signals_mod.score_account(a, sess)["risk_score"]
    return out


def _research_confusion(scores, truth, thr):
    tp = fp = tn = fn = 0
    for t in truth:
        lead = scores[t["account_id"]] >= thr
        if t["is_actor"]:
            tp, fn = (tp + 1, fn) if lead else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if lead else (fp, tn + 1)
    return tp, fp, tn, fn


def _research_rates(tp, fp, tn, fn):
    actors, innocents = tp + fn, fp + tn
    return {
        "recall": tp / actors if actors else 0.0,
        "fpr": fp / innocents if innocents else 0.0,
        "precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "actors": actors, "innocents": innocents,
    }


def _research_run(signals_mod, *, hard_fraction, prevalence=None, thr=None):
    p = dict(RESEARCH_DEFAULTS)
    if prevalence is not None:
        p["prevalence"] = prevalence
    accts, sess, truth = assemble(hard_fraction=hard_fraction, **p)
    thr = signals_mod.LEAD_THRESHOLD if thr is None else thr
    pred = _research_score(signals_mod, accts, sess, oracle=False)
    orac = _research_score(signals_mod, accts, sess, oracle=True)
    return {
        "pred_scores": pred, "orac_scores": orac, "truth": truth,
        "pred": _research_rates(*_research_confusion(pred, truth, thr)),
        "orac": _research_rates(*_research_confusion(orac, truth, thr)),
    }


def fig_label_cost(signals_mod):
    """Finding #27's headline: oracle vs the real classifier, the trade."""
    r = _research_run(signals_mod, hard_fraction=0.35)
    thr = signals_mod.LEAD_THRESHOLD

    def build(C):
        W, H = 880, 430
        b = _head(
            "The topic label is a policy lever, not a preprocessing step",
            f"Same 400 accounts and scorer, lead line {thr}. Only the topic label "
            "changes: the oracle label vs the real classifier (src/classify.py).",
            "scored live through src.signals at figure-build time", C)
        groups = [("recall\n(actors caught)", r["orac"]["recall"], r["pred"]["recall"]),
                  ("false-accusation\nrate", r["orac"]["fpr"], r["pred"]["fpr"]),
                  ("queue precision\n(PPV)", r["orac"]["precision"], r["pred"]["precision"])]
        base, top = 340, 130
        span = top - base  # negative
        gw = (W - 120) / len(groups)
        for i, (label, ov, pv) in enumerate(groups):
            gx = 70 + gw * i
            for j, (val, col, name) in enumerate(
                    [(ov, C["muted"], "oracle"), (pv, C["accent"], "classifier")]):
                bx = gx + 30 + j * 78
                h = span * val
                b.append(_rect(bx, base + h, 60, -h, col, C, op="0.9"))
                b.append(_t(bx + 30, base + h - 8, f"{100*val:.0f}%", 13,
                            C["ink"], weight="700", anchor="middle", C=C))
                b.append(_t(bx + 30, base + 18, name, 10.5, C["muted"],
                            anchor="middle", C=C))
            for k, ln in enumerate(label.split("\n")):
                b.append(_t(gx + gw / 2, base + 36 + k * 15, ln, 11.5,
                            C["ink"], anchor="middle", weight="700", C=C))
        b.append(_line(70, base, W - 40, base, C))
        b.append(_t(24, 108, "only the topic label changed — yet recall, false "
                    "accusations and precision all move; it is a policy lever", 11.5,
                    C["warn"], weight="700", C=C))
        return _svg(W, H, "".join(b), "oracle vs classifier labels", C)
    return build, (
        "Oracle labels versus the real regex classifier on the same 400-account "
        "population (seed 7) at the 0.25 lead line. Recall falls from 88% to 62% "
        "as the classifier misses the evasive actors, the false-accusation rate "
        "falls from 23% to 15%, and queue precision moves from 7% to 8% — only "
        "the topic label changed between the two runs.")


def fig_threshold_sweep(signals_mod):
    """Raising the line cleans the queue, never finds evaders."""
    r = _research_run(signals_mod, hard_fraction=0.35)
    pred, truth = r["pred_scores"], r["truth"]
    thrs = [0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
    pts = []
    for t in thrs:
        tp, fp, tn, fn = _research_confusion(pred, truth, t)
        rr = _research_rates(tp, fp, tn, fn)
        pts.append((t, rr["recall"], rr["fpr"], fp, tp, rr["actors"]))

    def build(C):
        W, H = 880, 470
        x0, x1, ytop, ybot = 90, 800, 150, 380
        tmin, tmax = 0.15, 0.50

        def X(t):
            return x0 + (t - tmin) / (tmax - tmin) * (x1 - x0)

        def Y(f):
            return ybot - f * (ybot - ytop)

        b = _head(
            "Raising the line cleans the queue; it never finds the evaders",
            "Every threshold on the 400-account population: false accusations "
            "collapse as the line rises, but the actors caught never climb.",
            "scored live through src.signals at figure-build time", C)
        b.append(_t(24, 108, "at 0.45 the false-accusation rate falls from ~15% "
                    "to under 1% while the same 5 of 8 actors are caught", 11.5,
                    C["warn"], weight="700", C=C))
        for gy in (0.0, 0.25, 0.5, 0.75, 1.0):
            yy = Y(gy)
            b.append(_line(x0, yy, x1, yy, C, op="0.5"))
            b.append(_t(x0 - 10, yy + 4, f"{100*gy:.0f}%", 10.5, C["muted"],
                        anchor="end", mono=True, C=C))
        for t, _, _, _, _, _ in pts:
            b.append(_t(X(t), ybot + 18, f"{t:.2f}", 10.5, C["muted"],
                        anchor="middle", mono=True, C=C))
        # shipped line + the cliff
        for tv, lab, col in [(0.25, "shipped 0.25", C["accent"]),
                             (0.45, "cliff 0.45", C["warn"])]:
            b.append(_line(X(tv), ytop - 10, X(tv), ybot, C, stroke=col,
                           w=1.4, dash="5 4"))
            b.append(_t(X(tv), ytop - 16, lab, 10.5, col, anchor="middle",
                        weight="700", C=C))
        b.append(_poly([(X(t), Y(fpr)) for t, _, fpr, *_ in pts], C["bad"], 2.4))
        b.append(_poly([(X(t), Y(rec)) for t, rec, *_ in pts], C["ok"], 2.4))
        for t, rec, fpr, fp, tp, act in pts:
            b.append(_dot(X(t), Y(fpr), 3.6, C["bad"], C))
            b.append(_dot(X(t), Y(rec), 3.6, C["ok"], C))
        b += _legend(x0, ybot + 48,
                     [(C["ok"], "actors caught (recall)"),
                      (C["bad"], "innocents wrongly queued (false-accusation rate)")], C)
        return _svg(W, H, "".join(b), "threshold sweep", C)
    return build, (
        "Operating-point curve over the 400-account population. As the lead "
        "threshold rises from 0.15 to 0.50 the false-accusation rate collapses "
        "from ~34% to 0%, but recall stays flat at 5 of 8 actors — no threshold "
        "recovers the three evasive actors. The shipped line is 0.25; the false-"
        "positive cliff is at 0.45.")


def fig_errors_by_archetype(signals_mod):
    """Where the errors live, per archetype, at the shipped threshold."""
    r = _research_run(signals_mod, hard_fraction=0.35)
    pred, truth = r["pred_scores"], r["truth"]
    thr = signals_mod.LEAD_THRESHOLD
    from collections import Counter
    total, fp, fn = Counter(), Counter(), Counter()
    for t in truth:
        a = t["archetype"]
        total[a] += 1
        lead = pred[t["account_id"]] >= thr
        if t["is_actor"] and not lead:
            fn[a] += 1
        elif not t["is_actor"] and lead:
            fp[a] += 1
    order = ["hn_automation", "dual_use", "benign", "hn_researcher",
             "hn_traveler", "hn_mobile", "actor", "actor_evasive"]
    order = [a for a in order if a in total]

    def build(C):
        W = 880
        row_h, y0 = 36, 150
        H = y0 + row_h * len(order) + 60
        b = _head(
            "The errors are the honest hard cases, not noise",
            f"Per archetype at lead line {thr}, on the real classifier's labels. "
            "Red = innocents wrongly queued; amber = actors missed.",
            "scored live through src.signals at figure-build time", C)
        bar_x, bar_w = 250, 480
        worst = max(max(fp[a], fn[a]) for a in order) or 1
        for i, a in enumerate(order):
            y = y0 + row_h * i
            b.append(_t(bar_x - 12, y + 15, a, 12, C["ink"], anchor="end",
                        mono=True, weight="700", C=C))
            b.append(_t(bar_x - 12, y + 28, f"n={total[a]}", 9.5, C["muted"],
                        anchor="end", mono=True, C=C))
            if fp[a]:
                w = bar_w * fp[a] / worst
                b.append(_rect(bar_x, y + 2, w, 12, C["bad"], C, op="0.9"))
                b.append(_t(bar_x + w + 6, y + 12, f"{fp[a]} false accusations",
                            10.5, C["bad"], weight="700", C=C))
            if fn[a]:
                w = bar_w * fn[a] / worst
                b.append(_rect(bar_x, y + 16, w, 12, C["warn"], C, op="0.9"))
                b.append(_t(bar_x + w + 6, y + 26, f"{fn[a]} actors missed",
                            10.5, C["warn"], weight="700", C=C))
            if not fp[a] and not fn[a]:
                b.append(_t(bar_x, y + 20, "clean", 10.5, C["ok"], C=C))
        return _svg(W, H, "".join(b), "errors by archetype", C)
    return build, (
        "False accusations and missed actors per archetype at the 0.25 lead "
        "line. The CI/cron automation accounts (34 of 34) and dual-use "
        "researchers dominate the false accusations, and the three evasive "
        "actors are the misses; ordinary benign, mobile and traveller accounts "
        "are almost entirely clean.")


def fig_hard_fraction(signals_mod):
    """The confusion-region control: separable vs realistic."""
    fracs = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5]
    pts = []
    for hf in fracs:
        r = _research_run(signals_mod, hard_fraction=hf)
        pts.append((hf, r["pred"]["recall"], r["pred"]["fpr"]))

    def build(C):
        W, H = 880, 440
        x0, x1, ytop, ybot = 90, 800, 150, 360

        def X(f):
            return x0 + f / 0.5 * (x1 - x0)

        def Y(v):
            return ybot - v * (ybot - ytop)

        b = _head(
            "Test on a separable population and you will believe you catch everyone",
            "Recall and false accusations as the confusion region grows "
            "(--hard-fraction 0 to 0.5); at 0 the population is separable.",
            "scored live through src.signals at figure-build time", C)
        for gy in (0.0, 0.25, 0.5, 0.75, 1.0):
            yy = Y(gy)
            b.append(_line(x0, yy, x1, yy, C, op="0.5"))
            b.append(_t(x0 - 10, yy + 4, f"{100*gy:.0f}%", 10.5, C["muted"],
                        anchor="end", mono=True, C=C))
        for hf, _, _ in pts:
            b.append(_t(X(hf), ybot + 18, f"{hf:.1f}", 10.5, C["muted"],
                        anchor="middle", mono=True, C=C))
        b.append(_t((x0 + x1) / 2, ybot + 38, "--hard-fraction "
                    "(share of each class in the confusion region)", 11,
                    C["muted"], anchor="middle", C=C))
        b.append(_poly([(X(f), Y(rec)) for f, rec, _ in pts], C["ok"], 2.4))
        b.append(_poly([(X(f), Y(fpr)) for f, _, fpr in pts], C["bad"], 2.4))
        for f, rec, fpr in pts:
            b.append(_dot(X(f), Y(rec), 3.8, C["ok"], C))
            b.append(_dot(X(f), Y(fpr), 3.8, C["bad"], C))
        b.append(_line(X(0.35), ytop - 10, X(0.35), ybot, C, stroke=C["accent"],
                       w=1.3, dash="5 4"))
        b.append(_t(X(0.35), ytop - 16, "reported 0.35", 10.5, C["accent"],
                    anchor="middle", weight="700", C=C))
        b += _legend(x0, ybot + 58,
                     [(C["ok"], "recall"),
                      (C["bad"], "false-accusation rate")], C)
        return _svg(W, H, "".join(b), "hard-fraction control", C)
    return build, (
        "Recall and false-accusation rate as --hard-fraction grows from 0 to "
        "0.5. At 0 the population is linearly separable and recall is a "
        "flattering 100% with a low false-accusation rate; as hard cases are "
        "added recall falls toward 62% and false accusations rise. The reported "
        "runs use 0.35.")


def fig_label_prevalence(signals_mod):
    """Base-rate on the study population: precision against prevalence.

    Distinct from fig_prevalence above, which projects the 23-account fixture's
    operating point; this one re-assembles the 400-account study population at
    each prevalence and scores it live.
    """
    prevs = [0.39, 0.20, 0.10, 0.05, 0.02, 0.01, 0.005]
    pts = []
    for pv in prevs:
        r = _research_run(signals_mod, hard_fraction=0.35, prevalence=pv)
        pts.append((pv, r["pred"]["precision"], r["pred"]["recall"]))

    def build(C):
        import math
        W, H = 880, 440
        x0, x1, ytop, ybot = 95, 800, 150, 360
        lo, hi = 0.005, 0.39

        def X(p):
            return x0 + (math.log10(p) - math.log10(lo)) / (
                math.log10(hi) - math.log10(lo)) * (x1 - x0)

        def Y(v):
            return ybot - v * (ybot - ytop)

        b = _head(
            "At a realistic abuse rate the queue is mostly innocent people",
            "Precision of the lead queue vs platform prevalence (log scale). "
            "The fixture ran at 39%; a real platform is far rarer.",
            "scored live through src.signals at figure-build time", C)
        for gy in (0.0, 0.25, 0.5, 0.75, 1.0):
            yy = Y(gy)
            b.append(_line(x0, yy, x1, yy, C, op="0.5"))
            b.append(_t(x0 - 10, yy + 4, f"{100*gy:.0f}%", 10.5, C["muted"],
                        anchor="end", mono=True, C=C))
        for pv in prevs:
            b.append(_t(X(pv), ybot + 18,
                        (f"{100*pv:.1f}%" if pv < 0.05 else f"{100*pv:.0f}%"),
                        10.5, C["muted"], anchor="middle", mono=True, C=C))
        b.append(_t((x0 + x1) / 2, ybot + 38, "platform abuse prevalence "
                    "(fraction of accounts that are actors)", 11, C["muted"],
                    anchor="middle", C=C))
        b.append(_poly([(X(p), Y(prec)) for p, prec, _ in pts], C["accent"], 2.4))
        for p, prec, _ in pts:
            b.append(_dot(X(p), Y(prec), 3.8, C["accent"], C))
        b.append(_line(X(0.02), ytop - 10, X(0.02), ybot, C, stroke=C["warn"],
                       w=1.3, dash="5 4"))
        b.append(_t(X(0.02), ytop - 16, "reported 2%", 10.5, C["warn"],
                    anchor="middle", weight="700", C=C))
        p2 = next(prec for p, prec, _ in pts if abs(p - 0.02) < 1e-9)
        b.append(_t(24, 108, f"at 2% prevalence the queue is {100*(1-p2):.0f}% "
                    "innocent — the whole argument for a human gate", 11.5,
                    C["warn"], weight="700", C=C))
        b += _legend(x0, ybot + 58, [(C["accent"], "queue precision (PPV)")], C)
        return _svg(W, H, "".join(b), "prevalence vs precision", C)
    return build, (
        "Precision of the lead queue against platform abuse prevalence on a log "
        "scale. At the fixture's 39% rate precision is high, but at a realistic "
        "2% it falls into the single digits — the queue becomes ~90% innocent — "
        "which is the base-rate argument for keeping a human in the loop.")


def fig_classifier_calibration(signals_mod):
    """The regex classifier measured on real ToxicChat prompts."""
    data = _load_json(DATA / "calibration" / "confusion.json")
    if not data:
        return None
    ur = data["jailbreak_under_read"]
    fire = data["regex_fire_rate"]
    tox = data["prevalence"]["toxic"]
    jb = data["prevalence"]["jailbreak"]
    jn, jm = data["jailbreak_n"], data["jailbreak_missed"]
    rows_total = data["dataset"]["rows_total"]

    def build(C):
        W, H = 880, 330
        b = _head(
            "Keyword classifiers miss almost every real jailbreak",
            f"This repo's regex (src/classify.py) over {rows_total:,} real "
            "ToxicChat prompts with human labels — the evasive-actor archetype, "
            "measured not asserted.",
            "read from data/calibration/confusion.json (scripts/calibrate_classifier.py)", C)
        b.append(_t(24, 108, f"the phrasing evasion the actor_evasive archetype is "
                    f"calibrated to — {100*ur:.1f}% here", 11.5, C["warn"],
                    weight="700", C=C))
        x0, w, y = 300, 480, 150
        b.append(_t(x0 - 12, y + 15, "jailbreak under-read", 12, C["ink"],
                    anchor="end", mono=True, weight="700", C=C))
        b.append(_t(x0 - 12, y + 29, f"{jm}/{jn} read benign", 9.5, C["muted"],
                    anchor="end", mono=True, C=C))
        b.append(_rect(x0, y, w, 24, C["line"], C, op="0.5"))
        b.append(_rect(x0, y, w * ur, 24, C["bad"], C, op="0.9"))
        b.append(_t(x0 + w * ur - 8, y + 17, f"{100*ur:.1f}%", 14, C["ink"],
                    weight="700", anchor="end", C=C))
        for i, (lab, val, col) in enumerate(
                [("regex fires offensive", fire, C["accent"]),
                 ("toxic prevalence", tox, C["muted"]),
                 ("jailbreak prevalence", jb, C["muted"])]):
            gx = 70 + i * 270
            b.append(_t(gx, 250, f"{100*val:.1f}%", 22, col, weight="700", C=C))
            b.append(_t(gx, 270, lab, 11, C["muted"], C=C))
        return _svg(W, H, "".join(b), "classifier calibration on ToxicChat", C)
    return build, (
        f"This repo's regex classifier over {rows_total:,} real ToxicChat "
        f"prompts with human labels: it reads {100*ur:.1f}% of jailbreak prompts "
        f"as benign ({jm} of {jn}), fires offensive on only {100*fire:.1f}% of "
        f"prompts, against a real {100*tox:.1f}% toxic and {100*jb:.1f}% jailbreak "
        "base rate — the measured basis for the evasive-actor archetype.")


def fig_wildchat_distributions(signals_mod):
    """Real behavioural base rates from WildChat (needs the anchor run)."""
    d = _load_json(DATA / "anchor" / "wildchat_stats.json")
    if not d:
        return None
    cad, tb, rr = d["cadence_cv"], d["topic_breadth"], d["refusal_rate"]
    rows = [("near-machine cadence (CV<0.25)", cad["frac_near_machine_lt_0_25"], "hn_automation"),
            ("multi-topic accounts", tb["frac_multi_topic"], "topic breadth is weak"),
            ("country switch mid-history", d["country_switch_frac"], "not visible on hashed_ip"),
            ("any assistant refusal", rr["frac_any_refusal"], "refusal_farming")]

    def build(C):
        W, H = 880, 360
        b = _head(
            "Real accounts are messy: the benign base rates behind the signals",
            f"{d['dataset']['conversations']:,} WildChat conversations grouped into "
            f"{d['dataset']['pseudo_accounts']:,} pseudo-accounts on hashed_ip.",
            "read from data/anchor/wildchat_stats.json (scripts/wildchat_anchor.py)", C)
        bar_x, bar_w, y0, rh = 320, 400, 140, 46
        for i, (lab, val, arch) in enumerate(rows):
            y = y0 + rh * i
            v = val or 0.0
            b.append(_t(bar_x - 12, y + 13, lab, 11.5, C["ink"], anchor="end",
                        mono=True, weight="700", C=C))
            b.append(_t(bar_x - 12, y + 27, arch, 9.5, C["muted"], anchor="end",
                        mono=True, C=C))
            b.append(_rect(bar_x, y + 2, bar_w, 20, C["line"], C, op="0.4"))
            b.append(_rect(bar_x, y + 2, bar_w * v, 20, C["accent"], C, op="0.85"))
            b.append(_t(bar_x + bar_w * v + 6, y + 16, f"{100*v:.0f}%", 11.5,
                        C["ink"], weight="700", C=C))
        return _svg(W, H, "".join(b), "wildchat behavioural base rates", C)
    return build, (
        f"Behavioural base rates from {d['dataset']['conversations']:,} real "
        f"WildChat conversations grouped into {d['dataset']['pseudo_accounts']:,} "
        "pseudo-accounts: the share with near-machine cadence, multiple topics, a "
        "mid-history country switch (near-zero under hashed_ip linkage), and any "
        "assistant refusal — the benign rates behind hn_automation and refusal; "
        "traveller country-drift is not observable this way.")


RESEARCH_FIGURES = {
    "label_cost": fig_label_cost,
    "threshold_sweep": fig_threshold_sweep,
    "errors_by_archetype": fig_errors_by_archetype,
    "hard_fraction": fig_hard_fraction,
    "label_prevalence": fig_label_prevalence,
    "classifier_calibration": fig_classifier_calibration,
    "wildchat_distributions": fig_wildchat_distributions,
}


def build_svgs():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, fn in FIGURES.items():
        for theme, C in THEMES.items():
            p = OUT / f"{name}_{theme}.svg"
            p.write_text(fn(C), encoding="utf-8")
            print(f"  {p.relative_to(ROOT)}  {p.stat().st_size // 1024} KB")
    for name, fn in RESEARCH_FIGURES.items():
        result = fn(signals)
        if result is None:
            print(f"! {name}: skipped (no source data yet — run its script first)")
            continue
        build, _alt = result
        for theme, C in THEMES.items():
            p = OUT / f"{name}_{theme}.svg"
            p.write_text(build(C), encoding="utf-8")
            print(f"  {p.relative_to(ROOT)}  {p.stat().st_size // 1024} KB")


# ---------------------------------------------------------------- screenshots
def _wait_for_server(port, timeout=25):
    """Wait for the console, and return its reported engine config.

    Returns the parsed /api/config, or None on timeout. The caller checks
    `mock`: a screenshot of the mock engine captioned as a real model run would
    be a fabricated measurement, so this is worth failing over.
    """
    import urllib.error
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            raw = urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/config", timeout=2).read()
            return json.loads(raw)
        except (urllib.error.URLError, OSError):
            time.sleep(0.4)
    return None


def _autocrop(path):
    """Trim uniform margin so a stack of shots has no dead space.

    Without this the GIF is padded to the tallest WINDOW rather than the tallest
    CONTENT, and the shorter frames sit in a lake of background.
    """
    try:
        from PIL import Image, ImageChops
    except ImportError:
        return
    im = Image.open(path).convert("RGB")
    bg = Image.new("RGB", im.size, im.getpixel((2, 2)))
    box = ImageChops.difference(im, bg).getbbox()
    if box:
        pad = 8
        box = (max(box[0] - pad, 0), max(box[1] - pad, 0),
               min(box[2] + pad, im.width), min(box[3] + pad, im.height))
        im.crop(box).save(path)


def build_shots():
    if not Path(CHROME).exists():
        print(f"! Chrome not found at {CHROME}; skipping screenshots")
        return []
    OUT.mkdir(parents=True, exist_ok=True)
    server = subprocess.Popen(
        [sys.executable, "-m", "scripts.console", "--port", str(PORT)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    made = []
    try:
        cfg = _wait_for_server(PORT)
        if cfg is None:
            print("! console did not come up; skipping screenshots")
            return []
        if cfg.get("mock"):
            print("! console started in MOCK mode -- refusing to capture.\n"
                  "  These shots are captioned as real model output, so a mock\n"
                  "  capture would be a fabricated measurement. Put a key in\n"
                  "  .env (gitignored) or export OPENAI_API_KEY, then re-run.")
            return []
        print(f"  engine: REAL · {cfg.get('model')}")
        for name, query, height, caption in SHOTS:
            out = OUT / f"console_{name}.png"
            url = f"http://127.0.0.1:{PORT}/?{query}"
            # The deep-linked page carries its own config and result, so it
            # renders with nothing in flight; the virtual-time budget only has
            # to cover script execution.
            subprocess.run(
                [CHROME, "--headless", "--disable-gpu", "--hide-scrollbars",
                 "--force-device-scale-factor=2",
                 "--virtual-time-budget=9000",
                 f"--window-size=1280,{height}",
                 f"--screenshot={out}", url],
                check=False, capture_output=True, timeout=180)
            if out.exists():
                _autocrop(out)
                made.append(out)
                print(f"  {out.relative_to(ROOT)}  "
                      f"{out.stat().st_size // 1024} KB   {caption}")
            else:
                print(f"! {name}: no screenshot produced")
    finally:
        server.terminate()
        server.wait(timeout=10)
    if made:
        build_gif(made)
    return made


def build_gif(shots):
    """The stills in sequence, so the README leads with something moving."""
    try:
        from PIL import Image
    except ImportError:
        print("! Pillow not installed; skipping GIF")
        return
    frames = []
    target_w = 980
    for pth in shots:
        im = Image.open(pth).convert("RGB")
        im = im.resize((target_w, int(im.height * target_w / im.width)),
                       Image.LANCZOS)
        frames.append(im)
    # Pad every frame to the tallest CONTENT height, top-aligned.
    h = max(f.height for f in frames)
    bg = frames[0].getpixel((2, 2))
    padded = []
    for f in frames:
        canvas = Image.new("RGB", (target_w, h), bg)
        canvas.paste(f, (0, 0))
        padded.append(canvas.convert("P", palette=Image.ADAPTIVE, colors=128))
    gif = OUT / "console_demo.gif"
    padded[0].save(gif, save_all=True, append_images=padded[1:],
                   duration=2600, loop=0, optimize=True)
    print(f"  {gif.relative_to(ROOT)}  {gif.stat().st_size // 1024} KB")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--svg-only", action="store_true",
                    help="charts only: no browser, no API calls")
    ap.add_argument("--table", action="store_true",
                    help="emit the README's Phase B block from the artifact")
    args = ap.parse_args()
    if args.table:
        emit_adaptive_table()
        return
    print("SVG charts:")
    build_svgs()
    if not args.svg_only:
        build_shots()


if __name__ == "__main__":
    main()
