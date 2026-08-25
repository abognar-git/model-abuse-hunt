"""Refusal-phrase markers, shared by the research scripts.

These were originally the gateway provider's refusal detector; the research
layer keeps only the constant + helper (no model client), so wildchat_anchor can
estimate a real refusal base rate over assistant turns.
"""
from __future__ import annotations

REFUSAL_MARKERS = (
    "i can't help with that",
    "i cannot help with that",
    "i'm not able to help",
    "i am not able to help",
    "can't assist with that",
    "cannot assist with that",
    "i can't fulfill",
    "i cannot fulfill",
    "i can\u2019t fulfill",
    "i can\u2019t create",
    "i cannot create",
    "i can't provide information that could",
    "i cannot provide information that could",
    "against my guidelines",
    "violates",
    "illegal activity",
    "i must refuse",
)


def looks_refused(text: str) -> bool:
    low = (text or "").lower()
    return any(m in low for m in REFUSAL_MARKERS)
