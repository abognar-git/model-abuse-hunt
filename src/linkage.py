"""Experimental linking channels: stylometry and timing.

**Measurement-only. Nothing in the pipeline sets these.** They exist the way the
triage project's `fence=False` exists - as an affordance for asking a question
the production path should not answer.

The question is the last stated gap in this repo's attribution layer. Fragment
an operation across burners that share infrastructure and `src/attribute.py`
reassembles it; fragment it across burners that *also* diverge on topic and one
of them slips the link (5 of 6 in `stress_decomposition`). The obvious fixes are
the two channels below, and both are worth taking seriously rather than
dismissing:

  * **Stylometry.** Authorship attribution is a real discipline with a real
    track record. Its whole methodological point is that the features which
    identify an author are the ones the author does not choose - function-word
    rates, punctuation habits, sentence rhythm - so a good implementation is
    *topic-independent by construction*. That matters here: if linking on style
    works, it is not the same thing as linking on content, and this project's
    thesis would survive intact.

  * **Timing.** Coordinated accounts operated by one person share a clock. That
    is behavior, not topic, so it sits comfortably inside the 0.94.

So this module gives both their best shot. `style_vector` deliberately uses a
closed-class function-word list and structural ratios, and deliberately excludes
content words - not to weaken stylometry but because smuggling topic in under
the name "style" would rig the experiment toward the answer this project already
believes. `stress_linkage.py` then measures whether the features stayed
topic-independent, whether either channel closes the gap, and what it costs on
the hard negatives.

Everything here is offline, deterministic and stdlib-only.
"""
from __future__ import annotations

import math
import re
from collections import Counter

# Closed-class words: chosen because a writer does not select them for subject
# matter. This is the standard basis for authorship attribution, and using it
# rather than content words is what makes "style" a different claim from "topic".
FUNCTION_WORDS = (
    "the a an and or but if then of to in on at for with by from as is are was "
    "were be been can could would should will do does did how what why when "
    "which that this these those it its i me my we our you your not no so up "
    "out into about over than some any all one two more most just like get make"
).split()

PUNCTUATION = list(",.?!;:'\"-()")

# Authorship attribution is not reliable on short texts. The figure varies by
# method, but no serious result claims discrimination from a few dozen words;
# low thousands is the usual floor. Named here so the harness can report how far
# under it this dataset sits, rather than quietly producing a number anyway.
STYLOMETRY_WORD_FLOOR = 1000

_WORD = re.compile(r"[a-z']+")


def _words(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def style_vector(sessions: list[dict]) -> list[float]:
    """Topic-independent authorship features for one account's prompt text.

    Function-word rates, punctuation rates, and structural ratios. No content
    words: see the module docstring for why that is a fairness choice and not a
    handicap.
    """
    text = " ".join(s["prompt_excerpt"] for s in sessions)
    words = _words(text)
    n = len(words) or 1
    counts = Counter(words)

    vec = [counts[w] / n for w in FUNCTION_WORDS]
    vec += [text.count(p) / n for p in PUNCTUATION]
    vec += [
        sum(len(w) for w in words) / n,                    # mean word length
        len(set(words)) / n,                               # type-token ratio
        n / max(len(sessions), 1) / 20.0,                  # mean words/session
        sum(1 for s in sessions
            if "?" in s["prompt_excerpt"]) / max(len(sessions), 1),
    ]
    return vec


def hour_vector(sessions: list[dict]) -> list[float]:
    """L1-normalised hour-of-day histogram: when this account is awake."""
    hist = [0.0] * 24
    for s in sessions:
        hist[int(s["ts"][11:13]) % 24] += 1.0
    total = sum(hist) or 1.0
    return [h / total for h in hist]


def cosine(u: list[float], v: list[float]) -> float:
    num = sum(a * b for a, b in zip(u, v))
    du = math.sqrt(sum(a * a for a in u))
    dv = math.sqrt(sum(b * b for b in v))
    return num / (du * dv) if du and dv else 0.0


def word_count(sessions: list[dict]) -> int:
    return sum(len(_words(s["prompt_excerpt"])) for s in sessions)


def make_linker(channel: str, threshold: float, accounts, sessions):
    """Return `extra(a, b) -> reason|None` for src.attribute.build_actors.

    `channel` is "style" or "time". The returned callable is a *link* proposer
    on that channel alone, which is the point: the harness measures what each
    channel does on its own, unmixed with the infrastructure rule.
    """
    vec = {"style": style_vector, "time": hour_vector}[channel]
    cache = {aid: vec(sessions.get(aid, [])) for aid in accounts}

    def extra(a: str, b: str) -> str | None:
        sim = cosine(cache[a], cache[b])
        if sim >= threshold:
            return f"{channel} similarity {sim:.3f} >= {threshold:.2f}"
        return None

    return extra


def pairwise(channel: str, accounts, sessions) -> dict[tuple[str, str], float]:
    """Every pairwise similarity on a channel, for sweeps and controls."""
    vec = {"style": style_vector, "time": hour_vector}[channel]
    cache = {aid: vec(sessions.get(aid, [])) for aid in accounts}
    ids = sorted(accounts)
    return {(a, b): cosine(cache[a], cache[b])
            for i, a in enumerate(ids) for b in ids[i + 1:]}
