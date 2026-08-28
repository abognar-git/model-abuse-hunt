#!/usr/bin/env python3
"""Check the README's counts against the artifacts they describe.

This repo already has two gates, and both guard the data: identifiers stay in
documentation space, and the scorer is identical across the label-cost runs.
Nothing guarded the prose, and the prose is where the claims live.

Four counts had drifted by the time anyone looked:

  * "eight legitimate users written specifically to look like them on
    content" - eight exist, five share a content category with an actor;
  * "three attacker profiles were tried" - stress_framing builds two, and
    the sentence before it said "both constructions";
  * "four self-inflicted measurement errors" in one section while another
    said five, and the second one carries a note saying the count had
    already been caught drifting once;
  * "34 of 34 ... plus a marketing email the regex misreads as phishing" -
    the misread is on 24 of the 34.

Every check below re-derives its number from data/ or scripts/ rather than
from a second copy of the prose. Text only, standard library only, no
network. Exit nonzero on any failure.
"""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAILURES: list[str] = []


def fail(msg: str) -> None:
    FAILURES.append(msg)


def jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
         7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven",
         12: "twelve", 20: "twenty", 40: "forty", 60: "sixty", 80: "eighty",
         100: "a hundred", 120: "a hundred and twenty"}


def main() -> int:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    flat = " ".join(readme.split())
    low = flat.lower()

    # --- the fixture's own shape -------------------------------------------
    gt = jsonl(ROOT / "data" / "ground_truth.jsonl")
    sessions = jsonl(ROOT / "data" / "sessions.jsonl")
    cats: dict[str, set[str]] = collections.defaultdict(set)
    for s in sessions:
        cats[s["account_id"]].add(s["category"])

    n_accounts = len(gt)
    actors = [g for g in gt if g["label"] == "malicious"]
    archetypes = {g.get("actor") for g in actors if g.get("actor")}
    personas = [g for g in gt if g["label"] != "malicious" and g.get("persona")]
    actor_cats: set[str] = set()
    for g in actors:
        actor_cats |= cats[g["account_id"]]
    on_content = [g for g in personas if cats[g["account_id"]] & actor_cats]

    if n_accounts != 23:
        fail(f"the fixture has {n_accounts} accounts; the README's "
             f"'Twenty-three accounts' framing needs rewriting")

    # The claim that propagated into the sibling repo before it was caught.
    n_look = len(personas)
    n_content = len(on_content)
    want = (f"**{WORDS.get(n_look, n_look)} legitimate\nusers written "
            f"specifically to be the ones you get wrong**")
    if want.replace("\n", " ") not in flat:
        fail(f"README must describe the look-alikes as "
             f"'{WORDS.get(n_look, n_look)} legitimate users written "
             f"specifically to be the ones you get wrong' - "
             f"ground_truth.jsonl has {n_look} named benign personas")
    claim = (f"**{WORDS.get(n_content, n_content)} of the "
             f"{WORDS.get(n_look, n_look)} are indistinguishable on content**")
    if claim.lower() not in low:
        fail(f"README must say '{claim}' - {n_content} of the {n_look} named "
             f"personas share a content category with an actor "
             f"({', '.join(sorted(g['persona'] for g in on_content))})")
    if "look like them on content**" in readme:
        fail("README still claims all the look-alikes are indistinguishable "
             "on content; only some of them are")

    if len(archetypes) and f"{WORDS.get(len(archetypes), len(archetypes))} real actor archetypes" not in low:
        fail(f"README must say '{WORDS.get(len(archetypes), len(archetypes))} "
             f"real actor archetypes' - ground_truth.jsonl has "
             f"{len(archetypes)}: {sorted(archetypes)}")

    # --- how many attacker constructions stress_framing builds -------------
    fram = (ROOT / "scripts" / "stress_framing.py").read_text(encoding="utf-8")
    modes = set(re.findall(r'"(standalone|actor_clone)"\s*:', fram))
    if modes:
        n = len(modes)
        if f"{WORDS.get(n, n)} constructions were tried" not in low:
            fail(f"README must say '{WORDS.get(n, n)} constructions were "
                 f"tried' - stress_framing.py builds {n}: {sorted(modes)}")
        for wrong in range(1, 7):
            if wrong == n:
                continue
            if f"{WORDS[wrong]} attacker profiles were tried" in low:
                fail(f"README says '{WORDS[wrong]} attacker profiles were "
                     f"tried'; stress_framing.py builds {n}")

    # --- the self-inflicted-error count, in both places it appears ---------
    # The same count appears twice: once as a bare number in the prose and
    # once in the errata bullet that enumerates them. Parsing the
    # enumeration is brittle (it contains its own parenthetical, with
    # commas); comparing the two words to each other is not, and it is
    # exactly the drift that happened - one moved and the other did not.
    said_prose = re.search(r"\b([a-z]+) self-inflicted measurement errors", low)
    said_errata = re.search(r"\*\*([a-z]+) of my own measurement errors\*\*", low)
    if not said_prose or not said_errata:
        fail("could not find both statements of the self-inflicted "
             "measurement-error count (the prose line and the errata bullet)")
    elif said_prose.group(1) != said_errata.group(1):
        fail(f"the README says '{said_prose.group(1)} self-inflicted "
             f"measurement errors' in the prose and "
             f"'{said_errata.group(1)} of my own measurement errors' in the "
             f"errata bullet")

    # --- the label-cost false accusations ----------------------------------
    exp_gt = ROOT / "data" / "exp" / "ground_truth.jsonl"
    exp_sess = ROOT / "data" / "exp" / "sessions.jsonl"
    if exp_gt.is_file() and exp_sess.is_file():
        auto = {g["account_id"] for g in jsonl(exp_gt)
                if g.get("archetype") == "hn_automation"}
        misread: set[str] = set()
        for s in jsonl(exp_sess):
            if (s["account_id"] in auto
                    and s.get("category") == "phishing_content"
                    and s.get("category_true") != "phishing_content"):
                misread.add(s["account_id"])
        if auto:
            if f"({len(auto)} of {len(auto)})" not in flat:
                fail(f"README must state the automation false accusations as "
                     f"({len(auto)} of {len(auto)})")
            if f"**{len(misread)} of the {len(auto)}**" not in flat:
                fail(f"README must say '{len(misread)} of the {len(auto)}' "
                     f"automation accounts carry the misread marketing email; "
                     f"the population has {len(misread)}")
            rest = len(auto) - len(misread)
            if f"**{WORDS.get(rest, rest)} cross the line without it**" not in flat:
                fail(f"README must say the other "
                     f"'{WORDS.get(rest, rest)} cross the line without it'")

    # --- the card-only reviewer --------------------------------------------
    rev = ROOT / "data" / "reviewer.json"
    if rev.is_file():
        doc = json.loads(rev.read_text())
        rows = doc.get("rows") or []
        unsound = [r for r in rows if r.get("kind") == "unsound"]
        upheld = [r for r in unsound if r.get("modal") == "uphold"]
        if unsound:
            for m2 in re.finditer(r"(\d+)\s*/\s*(\d+) unsound", flat):
                if (int(m2.group(1)), int(m2.group(2))) not in {
                        (len(upheld), len(unsound)),
                        (doc.get("reps", 0), doc.get("reps", 0))}:
                    fail(f"README says '{m2.group(0)}'; reviewer.json has "
                         f"{len(upheld)} of {len(unsound)} unsound cards "
                         f"upheld over {doc.get('reps')} reps")

    # --- how many attacker cells the loose evasion definition inflated -----
    # The README retracts that definition; the retraction said it inflated
    # "every" count, and two of the four cells read the same either way.
    am = ROOT / "data" / "attacker_matrix.json"
    if am.is_file():
        doc = json.loads(am.read_text())
        phase_b = doc.get("b") or {}
        loose = {"not_investigated", "monitor", "gather_more"}
        inflated = 0
        for runs in phase_b.values():
            decisions = [r.get("final_decision") for r in runs]
            if (sum(d in loose for d in decisions)
                    != sum(d == "not_investigated" for d in decisions)):
                inflated += 1
        if phase_b:
            want = f"**{WORDS.get(inflated, inflated)} of the {WORDS.get(len(phase_b), len(phase_b))}** attacker cells"
            if want not in readme.replace("\n", " "):
                fail(f"README must say the loose definition inflated "
                     f"'{WORDS.get(inflated, inflated)} of the "
                     f"{WORDS.get(len(phase_b), len(phase_b))} attacker "
                     f"cells' - recomputing over attacker_matrix.json gives "
                     f"{inflated} of {len(phase_b)}")
            if "inflated every" in low:
                fail("README says the loose evasion definition inflated "
                     f"'every' count; it changed {inflated} of "
                     f"{len(phase_b)} cells")

    # --- how many fixture runs actually delete sessions --------------------
    fx = ROOT / "scripts" / "stress_fixture.py"
    fs = ROOT / "data" / "fixture_sensitivity.json"
    if fx.is_file() and fs.is_file():
        grid = re.search(r"DROPOUT_GRID\s*=\s*\[([^\]]+)\]", fx.read_text())
        draws = (json.loads(fs.read_text()) or {}).get("draws_per_perturbation")
        if grid and draws:
            tiers = [float(x) for x in grid.group(1).replace(" ", "").split(",") if x]
            deleting = sum(1 for t in tiers if t > 0) * int(draws)
            forms = {WORDS.get(deleting, str(deleting)), str(deleting)}
            if not any(f"{w} deliberately delete sessions" in low
                       for w in forms):
                fail(f"README must say "
                     f"'{WORDS.get(deleting, deleting)} deliberately delete "
                     f"sessions' - "
                     f"{len([t for t in tiers if t > 0])} of {len(tiers)} "
                     f"dropout tiers delete anything, at {draws} draws each")

    # --- quotations attributed to a model must exist in the data -----------
    # The sharpest failure this file exists to prevent: the judge section
    # quoted the judge as accepting "the account has verified payment and
    # phone information" as exculpatory. That string is nowhere in
    # judge.json - what it actually accepted was an authorization
    # hypothesis. A repo whose claim is "measured, not asserted" cannot put
    # words in a model's mouth.
    #
    # Scope is by proximity: a quotation only has to be found in the data if
    # it sits near a mention of a model or of the judge/reviewer runs. Prose
    # quotations elsewhere in the document are the author's own.
    corpus = ""
    for name in ("judge.json", "reviewer.json", "findings.jsonl",
                 "agentic.json", "appeal.json", "adaptive_log.jsonl",
                 "attacker_matrix.json", "attacker_probe.json"):
        f = ROOT / "data" / name
        if f.is_file():
            corpus += f.read_text(encoding="utf-8")
    # Hand-authored attacker prose (cover stories, probes) lives in the code
    # that plants it, which is just as much a source as the run output.
    for sub in ("scripts", "src"):
        d = ROOT / sub
        if d.is_dir():
            for f in sorted(d.glob("*.py")):
                corpus += f.read_text(encoding="utf-8")
    if corpus:
        squeezed = " ".join(corpus.split())
        # An ATTRIBUTION verb immediately before the quote, not mere
        # proximity to a model name: the author quotes their own prose all
        # over this document, and only the sentences that say a model said
        # something are making a checkable claim.
        attrib = re.compile(
            r"\b(accepted|said|says|quoted|wrote|answered|replied|responded|"
            r"reasoned|justified|called it|described it as|its words|"
            r"in its own words)\b[^\n\"]{0,40}$", re.I)
        for m in re.finditer(r'"([^"\n]{35,300})"', readme):
            quote = m.group(1)
            before = readme[max(0, m.start() - 90):m.start()]
            if not attrib.search(before):
                continue
            if " ".join(quote.split()) in squeezed:
                continue
            fail(f"README attributes a quotation to a model that appears "
                 f"nowhere in data/ or the code that plants it: "
                 f"\"{' '.join(quote.split())[:80]}...\"")

    # --- every figure the README embeds exists -----------------------------
    for src in re.findall(r'(?:src|srcset)="(docs/figures/[^"]+)"', readme):
        if not (ROOT / src).is_file():
            fail(f"README embeds a figure that is not in the repo: {src}")

    # --- every script named under "Running it yourself" exists -------------
    for mod in set(re.findall(r"python -m (scripts\.[a-z_]+)", readme)):
        if not (ROOT / (mod.replace(".", "/") + ".py")).is_file():
            fail(f"README documents a command for {mod}, which does not exist")

    if FAILURES:
        print(f"check_readme: {len(FAILURES)} FAILURE(S)", file=sys.stderr)
        for f in FAILURES:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("check_readme: OK (fixture shape, look-alikes, attacker "
          "constructions, errata counts, label-cost errors, reviewer run, "
          "evasion counts, dropout tiers, quotations, figures, commands)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
