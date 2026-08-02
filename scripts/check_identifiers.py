"""Repo-wide identifier hygiene gate.

A synthetic fixture must not name a real operator. This repo has now shipped a
violation of that rule four times, and each fix was narrower than the rule:

  1. Four real companies cast as "bulletproof hosting", one baked into a
     screenshot beside an ENFORCE decision. Fixed by converting HIGHER_RISK_ASNS
     and the actor IPs.
  2. Every *benign* account still held real identifiers - a named cloud
     provider as the detection engineer's employer, a named CDN as the
     journalist's. Fixed by converting the generator and asserting over its
     output before write.
  3. That assertion covered the GENERATOR ONLY. Four harnesses build their own
     synthetic accounts inline - a "clean residential ASN" an attacker buys, a
     bystander's ISP, a decoy's host - and every one of them named a real
     company. The assertion could never have seen them.
  4. Fix 3 cleaned every source file and this gate went green - and two
     COMMITTED IMAGES kept the old values anyway. `console_04_naive.png` and
     the hero GIF went on rendering a real national telecom's ASN and a
     routable address next to `malicious_abuse` and `ENFORCE`, on a public
     repo, because the fixtures were corrected without re-capturing every
     figure. The README meanwhile stated that all five screenshots and the GIF
     had been re-captured. Found by looking at the images, which is the only
     way it could have been found.

The through-line is the same each time: **the fix was scoped to the instances
that had been noticed.** So this gate is scoped to the repo instead. It reads
every file, not a list of files someone remembered to add, and it is the
generator's own predicates that decide - imported, not restated, because a
constant that pins a definition does nothing if a call site restates it.

Error 4 is the standing argument against trusting this file: it passed cleanly
the whole time that leak was live, and it was right to - the text WAS clean.

RFC 5398 (AS64496-64511, AS65536-65551) and RFC 5737 (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) are unassignable, so nothing drawn from them
can name anyone.

Note the limit: this reaches text. The worst instance in errors #1 and #2 was
inside a PNG, and error #4 existed ONLY inside PNGs while every source file was
already clean and this gate already passed. No text scan can read an image.
Re-capture screenshots after any identifier change, and then look at them.

Usage:
    python -m scripts.check_identifiers          # exits non-zero on a violation
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from scripts.generate_telemetry import _is_doc_asn, _is_doc_ip

ROOT = Path(__file__).resolve().parent.parent

SCANNED_SUFFIXES = {".py", ".json", ".jsonl", ".md", ".html", ".svg", ".txt"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv"}

ASN_RE = re.compile(r"\bAS\d{3,6}\b")
IP_RE = re.compile(r"(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d.])")

# Non-routable or loopback space that is not a claim about anyone.
EXEMPT_IP_PREFIXES = ("127.", "0.0.0.0", "255.", "10.",
                      "172.16.", "192.168.", "224.")

# Version strings and the like that match the IP shape but are not addresses.
EXEMPT_CONTEXT = re.compile(r"(version|python_requires|>=|==)\s*$")


def violations():
    out = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in SCANNED_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for m in ASN_RE.finditer(text):
            if not _is_doc_asn(m.group()):
                line = text.count("\n", 0, m.start()) + 1
                out.append((path.relative_to(ROOT), line, "ASN", m.group()))
        for m in IP_RE.finditer(text):
            ip = m.group()
            if _is_doc_ip(ip) or ip.startswith(EXEMPT_IP_PREFIXES):
                continue
            line_start = text.rfind("\n", 0, m.start()) + 1
            if EXEMPT_CONTEXT.search(text[line_start:m.start()]):
                continue
            line = text.count("\n", 0, m.start()) + 1
            out.append((path.relative_to(ROOT), line, "IP", ip))
    return out


def main():
    bad = violations()
    if not bad:
        print("identifier hygiene: OK - every ASN and IP is in an "
              "RFC 5398 / RFC 5737 documentation range")
        print("  (text only; screenshots must be checked by eye)")
        return 0
    print(f"identifier hygiene: {len(bad)} VIOLATION(S)\n")
    for path, line, kind, val in bad:
        print(f"  {path}:{line}  {kind} {val}")
    print("\nA synthetic fixture must not name a real operator. Use RFC 5398 "
          "(AS64496-64511, AS65536-65551) or RFC 5737 (192.0.2.0/24, "
          "198.51.100.0/24, 203.0.113.0/24).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
