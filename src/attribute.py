"""Attribution layer: cluster accounts into actors.

Triage of a single account answers "is this one account abusive?". Attribution
answers "which accounts are the *same actor*?" - the question that turns a
pile of burners into one campaign a team can disrupt.

The hard constraint, inherited whole from the triage project's correlation
work: **shared infrastructure alone must not merge accounts.** A commercial
VPN exit node, a cloud NAT, a popular ASN - thousands of unrelated people sit
behind each. Merging on a lone shared IP is how you attribute a legitimate
user to a threat actor and then enforce against them. That is the most
expensive mistake this layer can make, so the dataset plants a decoy
(`acct_NEG_vpncoincidence`) that shares the lure factory's egress IP and ASN
and nothing else, and the merge rule has to leave it alone.

Merge rule (a link needs a *reason*, not just an overlap):
  (a) two accounts share a `target:` token - the same named victim org -
      which is a behavioral tie an attacker cannot create by accident; OR
  (b) they share at least THREE independent weak tokens including at least one
      infrastructure token AND one behavioral token (dominant category).

A lone weak token (one shared IP) never merges. Same-infra-different-behavior
(the VPN decoy) never merges. Same-actor accounts, which share infra AND
behavior AND often a victim, do.

Usage:
    python -m src.attribute
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from . import signals
from .hunt import load, score_all

DATA = Path(__file__).resolve().parent.parent / "data"

INFRA_PREFIXES = ("ip:", "asn:")
BEHAVIOR_PREFIXES = ("cat:",)
MIN_WEAK_TOKENS = 3


def _dominant_category(sess_list) -> str | None:
    cats = [s["category"] for s in sess_list]
    return Counter(cats).most_common(1)[0][0] if cats else None


def tokens(account, sess_list) -> set[str]:
    """Identifiers an account can be linked on. `target:` is strong (a named
    victim); the rest are weak and only count in combination.

    A category token is emitted ONLY for a distinctive (offensive/recon)
    dominant category. Generic categories - benign_code, translation, creative
    writing - are far too common to fingerprint an actor: two unrelated people
    behind the same VPN both writing code is not a coordinated operation, and
    treating benign_code as a behavioral tie merges them into a phantom actor.
    Found by stress_attribution.py EXP-1."""
    toks = {f"ip:{account['signup_ip']}", f"asn:{account['signup_asn']}"}
    if account["payment"] in signals.RISKY_PAYMENTS:
        toks.add(f"pay:{account['payment']}")
    dom = _dominant_category(sess_list)
    if dom in signals.OFFENSIVE_CATEGORIES | signals.RECON_CATEGORIES:
        toks.add(f"cat:{dom}")
    for s in sess_list:
        if s.get("target_ref"):
            toks.add(f"target:{s['target_ref']}")
    return toks


class _UF:
    def __init__(self, items):
        self.p = {i: i for i in items}

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def _link_reason(shared: set[str], strict: bool = True) -> str | None:
    """Return why two accounts should merge, or None. Encodes the rule above.

    `strict` guards the victim-linking rule. A shared `target:` is a strong
    behavioral tie, but linking on it ALONE is an attribution-poisoning vector:
    an actor referencing a victim org, and an ordinary employee OF that org,
    both name it - merge them and the employee is attributed to the actor. So
    in strict mode a shared victim links only alongside at least one other
    corroborating attribute (infra/category/payment), which an unrelated
    bystander will not share. strict=False is the naive linker, kept only so
    stress_attribution.py can measure what the guard buys."""
    targets = {t for t in shared if t.startswith("target:")}
    weak = {t for t in shared
            if t.startswith(INFRA_PREFIXES + BEHAVIOR_PREFIXES + ("pay:",))}
    has_infra = any(t.startswith(INFRA_PREFIXES) for t in weak)
    has_behavior = any(t.startswith(BEHAVIOR_PREFIXES) for t in weak)
    if targets and (weak or not strict):
        names = sorted(t.split(":", 1)[1] for t in targets)
        extra = f" + corroborating {sorted(weak)}" if weak else ""
        return f"shared victim {names}{extra}"
    if len(weak) >= MIN_WEAK_TOKENS and has_infra and has_behavior:
        return (f"{len(weak)} corroborating attributes "
                f"({', '.join(sorted(weak))})")
    return None


def build_actors(accounts, sessions, strict=True, extra=None):
    """Return (clusters, link_log). clusters is a list of account-id lists;
    only multi-account clusters are returned as attributed actors.

    `strict` toggles the victim-linking guard; see _link_reason.

    `extra` is a measurement-only hook: a callable `(a, b) -> reason|None` that
    can propose a link the token rules did not. Nothing in the pipeline passes
    it - it exists so `stress_linkage.py` can measure what an additional
    channel (stylometry, timing) would do if it were wired in. Kept as an
    injected callable rather than a flag on this module so no experimental
    channel can become load-bearing by accident."""
    ids = list(accounts)
    toks = {aid: tokens(accounts[aid], sessions.get(aid, [])) for aid in ids}
    uf = _UF(ids)
    link_log = []
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            shared = toks[a] & toks[b]
            reason = _link_reason(shared, strict) if shared else None
            if reason is None and extra is not None:
                reason = extra(a, b)
            if reason:
                uf.union(a, b)
                link_log.append((a, b, reason))
    clusters = defaultdict(list)
    for aid in ids:
        clusters[uf.find(aid)].append(aid)
    multi = [sorted(v) for v in clusters.values() if len(v) > 1]
    return sorted(multi, key=len, reverse=True), link_log


def run():
    accounts, sessions = load()
    scored = score_all(accounts, sessions)
    clusters, link_log = build_actors(accounts, sessions)

    out = []
    for members in clusters:
        risk = max(scored[m]["risk_score"] for m in members)
        out.append({"members": members, "size": len(members),
                    "max_member_risk": round(risk, 3)})
    (DATA / "actors.jsonl").write_text(
        "".join(json.dumps(o) + "\n" for o in out))

    print(f"attributed {len(clusters)} multi-account actor(s):\n")
    for i, o in enumerate(out, 1):
        print(f"  Actor {i}: {len(o['members'])} accounts, "
              f"max member risk {o['max_member_risk']:.2f}")
        print(f"     {', '.join(o['members'])}")
    print("\nlink decisions:")
    for a, b, reason in link_log:
        print(f"  {a} <-> {b}: {reason}")
    return clusters


if __name__ == "__main__":
    run()
