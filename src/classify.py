"""Cheap rules-based category + target_ref extraction.

Predicted labels only — not ground truth. Hunt's README already warns that
real platforms must derive category; this gateway makes that explicit.
"""
from __future__ import annotations

import re

# Hunt taxonomy (signals.py).
CATEGORIES = {
    "malware_dev",
    "exploit_help",
    "phishing_content",
    "spam_content",
    "recon",
    "benign_code",
    "translation",
    "creative_writing",
}

_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("phishing_content", re.compile(
        r"phish|credential.?capture|account.?verif|urgent.?tone|"
        r"impersonat|credential.?harvest|fake.?login|spoof.?email",
        re.I)),
    ("malware_dev", re.compile(
        r"malware|ransomware|reflective.?dll|shellcode|payload|"
        r"keylogger|trojan|backdoor|c2|command.?and.?control|"
        r"obfuscat|packer",
        re.I)),
    ("exploit_help", re.compile(
        r"exploit|buffer.?overflow|rce\b|privilege.?escalat|"
        r"0.?day|zero.?day|cve-\d|use.?after.?free|rop.?chain",
        re.I)),
    ("spam_content", re.compile(
        r"\bspam\b|mass.?email|bulk.?mail|cold.?outreach.?at.?scale",
        re.I)),
    ("recon", re.compile(
        r"recon|osint|enumerate|port.?scan|subdomain.?enum|"
        r"whois|shodan|fingerprint.?host",
        re.I)),
    ("benign_code", re.compile(
        r"python|javascript|refactor|unit.?test|fastapi|sql|"
        r"write.?a.?function|debug.?this|implement",
        re.I)),
    ("translation", re.compile(
        r"translate|traducir|ford[ií]ts|перевед",
        re.I)),
    ("creative_writing", re.compile(
        r"short.?story|poem|fiction|screenplay|write.?me.?a.?story",
        re.I)),
]

# Org-like tokens for target_fixation demos (synthetic names only).
_TARGET_RE = re.compile(
    r"\b(northbridge-bank|meridian-pay|helios-post|acme-corp|"
    r"contoso|example-org|demo-bank)\b",
    re.I,
)


def classify(prompt: str) -> tuple[str, str | None]:
    """Return (category, target_ref). Category defaults to benign_code."""
    for category, pattern in _RULES:
        if pattern.search(prompt):
            m = _TARGET_RE.search(prompt)
            return category, (m.group(1).lower() if m else None)
    m = _TARGET_RE.search(prompt)
    return "benign_code", (m.group(1).lower() if m else None)
