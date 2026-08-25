#!/usr/bin/env python3
"""Calibrate the gateway's keyword classifier against real, human-labelled prompts.

`src/classify.py` is a cheap regex classifier. The synthetic study measures its
error *emergently* (run it over generated prompts and compare to the archetype's
true topic), but that only proves the classifier is imperfect on prompts I wrote.
This script measures it on **ToxicChat** — 10,165 real user prompts from the
Vicuna demo with human `toxicity` and `jailbreaking` labels — so the error is a
fact about real traffic, not about my prose.

What it reports, and why:
  - Jailbreak under-read (the headline). Of the human-labelled jailbreak prompts,
    the fraction the regex reads as benign. This is the real-world analog of the
    `actor_evasive` archetype: adversarial intent behind surface text a keyword
    classifier misses. This number is what feeds back into the population.
  - Offensive-vs-toxicity overlap (a characterisation, not a grade). The regex
    targets security-abuse TOPICS (phishing/malware/exploit/recon/spam);
    ToxicChat's `toxicity` is broader undesired content (hate/sexual/harassment).
    They are different constructs, so low overlap is expected — reported as a
    loose bound, never as the classifier's "accuracy".

Public dataset (CC-BY-NC); no auth needed. Raw cached under data/calibration/raw
(gitignored); only derived stats are written to data/calibration/.

Usage:
    python scripts/calibrate_classifier.py
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.classify import classify  # noqa: E402  (the real, imperfect classifier)

# The security-abuse topics the regex is built to catch. Everything else
# (benign_code / translation / creative_writing) is treated as non-offensive.
OFFENSIVE = {"phishing_content", "malware_dev", "exploit_help", "spam_content", "recon"}

OUT = ROOT / "data" / "calibration"
RAW = OUT / "raw"


def is_offensive(prompt: str) -> tuple[bool, str]:
    cat, _ = classify(prompt)
    return cat in OFFENSIVE, cat


def confusion(preds: list[bool], labels: list[bool]) -> dict:
    tp = sum(1 for p, y in zip(preds, labels) if p and y)
    fp = sum(1 for p, y in zip(preds, labels) if p and not y)
    fn = sum(1 for p, y in zip(preds, labels) if not p and y)
    tn = sum(1 for p, y in zip(preds, labels) if not p and not y)
    n = tp + fp + fn + tn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / n if n else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "n": n,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "accuracy": round(acc, 4)}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", default="lmsys/toxic-chat")
    p.add_argument("--config", default="toxicchat0124")
    p.add_argument("--revision", default=None,
                   help="dataset revision/commit to pin (default: latest)")
    p.add_argument("--human-only", action="store_true", default=False,
                   help="restrict to human-annotated rows only (default: use all "
                        "10,165 rows, so prevalence reflects the real distribution "
                        "— the toxic/jailbreak positives are human-labelled either way)")
    args = p.parse_args()

    try:
        from datasets import concatenate_datasets, load_dataset
    except ImportError:
        sys.exit("pip install -r requirements.txt (needs `datasets`)")

    RAW.mkdir(parents=True, exist_ok=True)
    dd = load_dataset(args.repo, args.config, cache_dir=str(RAW), revision=args.revision)
    ds = concatenate_datasets([dd[s] for s in dd.keys()])
    total_rows = len(ds)
    if args.human_only and "human_annotation" in ds.column_names:
        ds = ds.filter(lambda r: bool(r["human_annotation"]))

    prompts = ds["user_input"]
    tox = [int(x) == 1 for x in ds["toxicity"]]
    jail = [int(x) == 1 for x in ds["jailbreaking"]]

    off, cats = [], []
    for text in prompts:
        o, c = is_offensive(text or "")
        off.append(o)
        cats.append(c)

    n = len(off)
    fired = sum(off)

    # Headline: jailbreak under-read.
    jb_idx = [i for i, y in enumerate(jail) if y]
    jb_missed = sum(1 for i in jb_idx if not off[i])
    jb_under_read = jb_missed / len(jb_idx) if jb_idx else 0.0

    # Toxicity subset caught (recall on the topic-relevant slice is what matters,
    # but we report the raw overlap and label it a loose characterisation).
    conf_tox = confusion(off, tox)
    # In ToxicChat, jailbreak is a labelled subset of toxicity, so (toxic OR
    # jailbreak) == toxic; we record the containment rather than a duplicate row.
    jail_subset_of_tox = all(t for t, j in zip(tox, jail) if j)

    # What the regex actually fires as, over the whole set.
    cat_counts: dict[str, int] = {}
    for c in cats:
        cat_counts[c] = cat_counts.get(c, 0) + 1
    cat_counts = dict(sorted(cat_counts.items(), key=lambda kv: -kv[1]))

    stats = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset": {"repo": args.repo, "config": args.config,
                    "revision": args.revision, "rows_total": total_rows,
                    "rows_used": n, "human_only": args.human_only},
        "prevalence": {"toxic": round(sum(tox) / n, 4),
                       "jailbreak": round(sum(jail) / n, 4)},
        "regex_fire_rate": round(fired / n, 4),
        "jailbreak_under_read": round(jb_under_read, 4),
        "jailbreak_n": len(jb_idx),
        "jailbreak_missed": jb_missed,
        "jailbreak_subset_of_toxicity": bool(jail_subset_of_tox),
        "vs_toxicity": conf_tox,
        "regex_category_counts": cat_counts,
    }

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "confusion.json").write_text(json.dumps(stats, indent=2) + "\n")
    _write_report(OUT / "classifier_report.md", stats)

    print(f"rows used: {n} (of {total_rows})")
    print(f"toxic prevalence: {stats['prevalence']['toxic']:.1%}  "
          f"jailbreak prevalence: {stats['prevalence']['jailbreak']:.1%}")
    print(f"regex fires offensive on {stats['regex_fire_rate']:.1%} of real prompts")
    print(f"HEADLINE jailbreak under-read: {jb_under_read:.1%} "
          f"({jb_missed}/{len(jb_idx)} jailbreak prompts read as benign)")
    print(f"vs toxicity (loose): precision={conf_tox['precision']:.2f} "
          f"recall={conf_tox['recall']:.2f} f1={conf_tox['f1']:.2f}")
    print(f"wrote {OUT/'confusion.json'} and {OUT/'classifier_report.md'}")


def _write_report(path: Path, s: dict) -> None:
    d = s["dataset"]
    ct = "\n".join(f"| `{k}` | {v} |" for k, v in s["regex_category_counts"].items())
    md = f"""# Classifier calibration on ToxicChat

Generated {s['generated_at']} from `{d['repo']}` (`{d['config']}`,
revision `{d['revision'] or 'latest'}`), {d['rows_used']} of {d['rows_total']}
rows. The toxic and jailbreak positives are human-verified, so the prevalences
below reflect the dataset's real distribution rather than an uncertainty-sampled
subset.

The gateway's regex classifier ([`src/classify.py`](../../src/classify.py)) is a
keyword matcher over security-abuse **topics**. ToxicChat labels general
**toxicity** and **jailbreaking**, which are different constructs — so the
overlap below is a characterisation of real behaviour, not an accuracy grade.

## Headline: jailbreak under-read

Of the **{s['jailbreak_n']}** prompts humans labelled as jailbreak attempts, the
regex reads **{s['jailbreak_missed']}** as benign — a **{s['jailbreak_under_read']:.1%}
under-read**. Real adversarial prompts routinely phrase around a keyword
classifier: this is the measured, real-world version of the `actor_evasive`
archetype, and it is the number the synthetic population is calibrated to.

## Real prevalence (for base-rate context)

- toxic: **{s['prevalence']['toxic']:.1%}**
- jailbreak: **{s['prevalence']['jailbreak']:.1%}**

The regex fires "offensive" on **{s['regex_fire_rate']:.1%}** of real prompts.

## Overlap with human labels (loose characterisation)

Treat these as a lower bound: the regex was never built to catch hate/sexual
toxicity, so its recall against the broad `toxicity` label is expected to be low.

| target | precision | recall | f1 | tp | fp | fn | tn |
|---|---|---|---|---|---|---|---|
| toxicity | {s['vs_toxicity']['precision']} | {s['vs_toxicity']['recall']} | {s['vs_toxicity']['f1']} | {s['vs_toxicity']['tp']} | {s['vs_toxicity']['fp']} | {s['vs_toxicity']['fn']} | {s['vs_toxicity']['tn']} |

(In ToxicChat, jailbreak is a labelled subset of toxicity, so a "toxicity OR
jailbreak" target is identical to toxicity — omitted rather than duplicated.)

## What the regex fires as, on real prompts

| category | count |
|---|---|
{ct}

<sub>Dataset: ToxicChat (Lin et al., 2023), CC-BY-NC. Raw cached under
`data/calibration/raw/` (gitignored); only this report and `confusion.json` are
committed.</sub>
"""
    path.write_text(md)


if __name__ == "__main__":
    main()
