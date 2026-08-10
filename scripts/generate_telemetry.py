#!/usr/bin/env python3
"""Generate a synthetic, labeled dataset of AI-platform usage telemetry.

The unit is not a SOC alert - it is *platform activity*: accounts, the
sessions run under them, and per-session summaries of what the account asked
the model to do. This is the telemetry a model provider actually has when
hunting adversaries who *misuse the model itself*.

Produces:
  data/accounts.jsonl      - one row per account (signup metadata, infra)
  data/sessions.jsonl      - usage sessions (channel, category, prompt excerpt)
  data/ground_truth.jsonl  - per-account labels, kept separate on purpose

The set is built from three kinds of account:

  * Planted ACTORS - clusters of accounts that genuinely belong to one
    threat actor, tied together by shared infrastructure and a shared
    behavioral fingerprint (not by content alone). The attribution layer
    should recover exactly these clusters. Each ground-truth row carries an
    `actor` id so attribution can be *measured*, not eyeballed.

  * Hard NEGATIVES - legitimate accounts whose *content overlaps the actors
    deliberately*: a pentester asking the same exploit questions as the
    malware developer, a security-awareness trainer generating the same
    phishing emails as the lure factory, an SRE whose API automation looks
    exactly like the recon bot. They exist to measure the metric a
    threat-intel team actually lives or dies by: the false-accusation rate.
    If content drove attribution, every one of these would be a false
    positive. They are the whole point.

  * Background BENIGN - ordinary low-risk accounts with distinct infra that
    must never be linked to anything.

A design constraint worth stating: prompt excerpts describe intent, they are
not weaponised. Real telemetry would carry more; a synthetic demo should not
ship working offensive content, and intent is what the investigation layer
reasons over anyway.

The telemetry is synthetic; the ARCHETYPES are not. Each planted actor is
modelled on activity OpenAI has publicly documented in its own threat reporting,
and each row's `provenance` field cites the report it derives from. See
docs/PROVENANCE.md for the full mapping, including which parts are direct
citations and which (the stolen-key scenario) are labelled extensions.
Grounding the archetypes does not license any claim about real-world detection
rates - every number in the README comes from this synthetic set.
"""
from __future__ import annotations

import json
from pathlib import Path

# This module used to `import random` and call `random.seed(31337)` here, and
# never called a single random function anywhere below. Every account, session,
# timestamp and identifier in this file is hand-authored and literal.
#
# The dead seed was not harmless. It is exactly the line a reader greps for to
# answer "is this telemetry sampled, and is the sample pinned?", and it answers
# yes to both when the truth is neither - there is no distribution here, only a
# fixture. It misled the author too: the plan for putting error bars on this
# repo's headline numbers was to re-seed this generator fifty times and report
# the spread, which would have produced fifty byte-identical datasets and a set
# of confidence intervals of width zero.
#
# Removed rather than kept-and-commented, because a seed that seeds nothing is a
# claim about method. `scripts/stress_fixture.py` is where variation actually
# comes from: it perturbs this fixture along axes classified as incidental or
# structural, and reports what moves. See finding #22.
DATA = Path(__file__).resolve().parent.parent / "data"
DATA.mkdir(exist_ok=True)

_accounts: list[dict] = []
_sessions: list[dict] = []
_truth: list[dict] = []
_sid = 1

# --- identifier hygiene ------------------------------------------------------
# Every ASN and IP in this fixture must come from a range reserved for
# documentation by standard, because a fixture that casts an organisation as a
# threat actor - or merely as the place a penetration tester signs up from - is
# not made harmless by being fictional everywhere except the name.
#
# This repo has now got this wrong THREE times, each time in a smaller costume:
#   1. Four real companies named as "bulletproof/anon egress" hosting, one baked
#      into a screenshot beside an ENFORCE decision (finding #5, caught after
#      publication).
#   2. The sibling project, same bug, real registered domains as fraud actors.
#   3. This one. Finding #5 converted only HIGHER_RISK_ASNS and the actor IPs.
#      Every *benign* account kept its real identifiers - Google, Microsoft,
#      Comcast, Fastly, GitHub, AWS and Yahoo ASNs and address space - so the
#      dataset asserted that a named cloud provider is where the detection
#      engineer works and a named CDN is where the journalist does recon. Found
#      only because stress_framing.py printed those identifiers next to an
#      `enforce` decision, which is exactly how #5 was found too.
#
# The lesson the first two fixes missed: converting the instances you can think
# of is not a fix, because the next instance is the one you did not think of.
# So this is now an ASSERTION over the generated output rather than a habit.
#
# RFC 5398 (AS64496-64511, AS65536-65551) and RFC 5737 (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24) are unassignable: no real operator can hold
# one, so no real operator can be cast as anything.
DOC_ASN_RANGES = ((64496, 64511), (65536, 65551))
DOC_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")

BACKGROUND_ASNS = ("AS64507", "AS64508", "AS64509",
                   "AS64510", "AS64511", "AS65536")


def _is_doc_asn(asn: str) -> bool:
    if not asn.startswith("AS") or not asn[2:].isdigit():
        return False
    n = int(asn[2:])
    return any(lo <= n <= hi for lo, hi in DOC_ASN_RANGES)


def _is_doc_ip(ip: str) -> bool:
    return ip.startswith(DOC_IP_PREFIXES)


def assert_identifier_hygiene():
    """Refuse to write a dataset naming any real, routable identifier.

    Runs over the generated rows, not over this file's source, so an identifier
    introduced by an f-string or a helper cannot slip past a source grep - which
    is precisely what happened with the background accounts' `f"203.0.{k}.{10+k}"`,
    an expression that LOOKS like TEST-NET-3 and generates routable APNIC space."""
    bad = []
    for a in _accounts:
        if not _is_doc_asn(a["signup_asn"]):
            bad.append((a["account_id"], "signup_asn", a["signup_asn"]))
        if not _is_doc_ip(a["signup_ip"]):
            bad.append((a["account_id"], "signup_ip", a["signup_ip"]))
    for s in _sessions:
        if not _is_doc_asn(s["asn"]):
            bad.append((s["session_id"], "asn", s["asn"]))
        if not _is_doc_ip(s["src_ip"]):
            bad.append((s["session_id"], "src_ip", s["src_ip"]))
    if bad:
        lines = "\n".join(f"    {w} {f}={v}" for w, f, v in bad[:20])
        raise AssertionError(
            f"{len(bad)} identifier(s) outside the documentation ranges "
            f"(RFC 5398 / RFC 5737):\n{lines}\n"
            f"  A synthetic fixture must not name a real operator.")

# Published provenance per archetype. Keys are actor ids; values cite the report
# the behavioral signature is modelled on. `extension` marks a scenario that is a
# reasonable extrapolation from documented objectives rather than a published
# case in that exact form - flagged rather than quietly presented as a citation.
PROVENANCE = {
    "lure_factory": {
        "source": "OpenAI, PRC-linked influence operations are targeting AI "
                  "debates in the US (June 2026 Threat Report)",
        "date": "2026-06",
        "case": "'Data Center Bandwagon' / 'Tech and Tariffs' clusters",
        "signature": "multi-account clusters reaching the platform via VPN, "
                     "generating multilingual social-media content under "
                     "assumed personas",
        "extension": False,
    },
    "capability_dev": {
        "source": "OpenAI, Disrupting malicious uses of AI: October 2025",
        "date": "2025-10-07",
        "case": "Cyber Operation: Russian-speaking malware tooling development",
        "signature": "one operator across multiple accounts on proxy/ephemeral "
                     "hosting, iterating on the same code across conversations "
                     "(ongoing development, not occasional testing)",
        "extension": False,
    },
    "recon_automation": {
        "source": "OpenAI, June 2026 Threat Report; and Disrupting malicious "
                  "uses of AI: October 2025 ('Phish and Scripts')",
        "date": "2026-06 / 2025-10-07",
        "case": "workflow automation and bulk text processing at scale",
        "signature": "model used to automate and scale an existing workflow - "
                     "scripted, repetitive, high-volume API use",
        "extension": False,
    },
    "stolen_key": {
        "source": "OpenAI, Disrupting malicious uses of AI: October 2025",
        "date": "2025-10-07",
        "case": "credential-theft objectives (credential stealers, browser "
                "credential/cookie extraction)",
        "signature": "a legitimate account's credentials turned to abuse, "
                     "detectable as divergence from the account's own baseline",
        "extension": True,   # scenario extrapolated, not a published case
    },
}


def account(acct_id, created_at, email_kind, signup_ip, asn, country,
            payment, phone_verified, channel, *, label, actor=None,
            persona=None, notes=""):
    _accounts.append({
        "account_id": acct_id,
        "created_at": created_at,
        "email_kind": email_kind,          # freemail | corporate | disposable
        "signup_ip": signup_ip,
        "signup_asn": asn,
        "signup_country": country,
        "payment": payment,                # card_verified|card_prepaid|none|crypto
        "phone_verified": phone_verified,
        "primary_channel": channel,        # api | chatgpt | mixed
    })
    _truth.append({
        "account_id": acct_id, "label": label, "actor": actor,
        "persona": persona, "notes": notes,
        # Cited grounding for malicious archetypes; benign rows carry None
        # because a legitimate look-alike is a control this project designed,
        # not a documented case.
        "provenance": PROVENANCE.get(actor) if actor else None,
    })


def sess(acct_id, ts, channel, category, excerpt, disposition,
         ip, asn, country, target_ref=None):
    global _sid
    _sessions.append({
        "session_id": f"sess_{_sid:05d}",
        "account_id": acct_id,
        "ts": ts,
        "channel": channel,                # api | chatgpt
        "category": category,
        "prompt_excerpt": excerpt,         # attacker-controlled text (untrusted)
        "disposition": disposition,        # completed | refused | partial
        "src_ip": ip,
        "asn": asn,
        "country": country,
        "target_ref": target_ref,          # named real-org reference, or None
    })
    _sid += 1


def _t(day, hour, minute=0):
    """Build an ISO-8601 timestamp, and refuse to build an impossible one.

    The assertion is not decoration. A caller here wrote `21 + i * 20 % 24`
    intending `(21 + i * 20) % 24`; Python binds `%` tighter than `+`, so the
    wrap never happened and the dataset shipped a session at hour 41. Nothing
    downstream validated it - `signals._minutes` slices the characters and does
    arithmetic on whatever it finds - so an out-of-range hour stayed silent all
    the way through the pipeline and into the committed artifacts. Cheap to
    assert at the one place every timestamp is constructed."""
    assert 0 <= hour <= 23, f"hour {hour} out of range"
    assert 0 <= minute <= 59, f"minute {minute} out of range"
    assert 1 <= day <= 31, f"day {day} out of range"
    return f"2026-07-{day:02d}T{hour:02d}:{minute:02d}:00Z"


# ============================ PLANTED ACTORS ============================

def actor_lure_factory():
    """Coordinated phishing/smishing content generation across burner accounts.

    Fingerprint: a cluster of freemail accounts created in a 40-minute window
    from two shared VPN egress IPs, all prepaid/none payment, all doing the
    same job (brand-impersonation lure copy) against the same target brands,
    in the same working hours. No single account is high-volume; the *cluster*
    is the actor. This is coordinated inauthentic behaviour, model-abuse flavour.
    """
    # RFC 5737 / RFC 5398 documentation identifiers throughout - unassignable,
    # so no real operator is cast as the villain. See src.signals.
    shared_ips = ["198.51.100.44", "198.51.100.61"]        # anon-egress stand-in
    asn = "AS64497"                                        # higher-risk stand-in
    brands = ["brindlow-bank", "quorline-pay", "helios-post", "civictax-gov"]
    langs = ["English", "German", "Spanish", "Dutch"]
    for k in range(5):
        aid = f"acct_LF{k+1:02d}"
        ip = shared_ips[k % 2]
        account(aid, _t(12, 2, 5 * k), "freemail", ip, asn, "RO",
                "card_prepaid" if k % 2 else "none", False, "chatgpt",
                label="malicious", actor="lure_factory",
                notes="burner in coordinated lure cluster")
        # each burner emits a few near-identical lure jobs
        for j in range(3):
            brand = brands[(k + j) % len(brands)]
            lang = langs[(k + j) % len(langs)]
            sess(aid, _t(12, 9 + j, 10 * k % 60), "chatgpt", "phishing_content",
                 f"write a {lang} account-verification email impersonating "
                 f"{brand}, urgent tone, with a button linking to a "
                 f"credential-capture page; also a matching SMS",
                 "refused" if (k + j) % 4 == 0 else "completed",
                 ip, asn, "RO", target_ref=brand)


def actor_capability_dev():
    """Iterative offensive-tooling development across many sessions.

    Fingerprint: not any one prompt but the *trajectory* - loader, then
    obfuscation, then AV-evasion, then C2, then packaging - plus pasting its
    own crash output back in to debug. Two accounts, same actor, one aged to
    look less suspicious. The arc is the tell; no single session is damning.
    """
    arc = [
        ("malware_dev", "help structure a windows loader that stages a second "
                        "payload from a remote host, keep it modular"),
        ("malware_dev", "the loader is getting flagged on upload - how do I "
                        "restructure so a static AV signature stops matching"),
        ("exploit_help", "walk me through reflective DLL loading so nothing "
                         "touches disk"),
        ("malware_dev", "here is the exception trace from my loader <stack "
                        "trace>, why does it crash after the second stage"),
        ("malware_dev", "design a small C2 check-in over HTTPS that looks like "
                        "normal telemetry beacons, jittered interval"),
        ("malware_dev", "package all of this into a single signed-looking "
                        "installer and a build script"),
    ]
    primary, aged = "acct_CD01", "acct_CD02"
    account(primary, _t(9, 20), "freemail", "192.0.2.18", "AS64496", "RU",
            "crypto", False, "api",
            label="malicious", actor="capability_dev",
            notes="primary dev account, escalating offensive-tooling arc")
    account(aged, _t(3, 14), "freemail", "192.0.2.19", "AS64496", "RU",
            "crypto", False, "mixed",
            label="malicious", actor="capability_dev",
            notes="aged sibling, same actor, shares ASN + crypto payment")
    day = 9
    for i, (cat, ex) in enumerate(arc):
        acct = primary if i % 3 else aged
        ip = "192.0.2.18" if acct == primary else "192.0.2.19"
        sess(acct, _t(day, 20 + (i % 3)), "api", cat, ex,
             "partial" if i in (1, 2) else "completed",
             ip, "AS64496", "RU")
        if i % 2:
            day += 1


def actor_recon_automation():
    """Programmatic reconnaissance at scale via the API.

    Fingerprint: automation, not chat - identical structured prompts on a
    near-perfect cadence, high volume, single API key, one ASN. Content is
    target enumeration and breach-dump triage against a named victim org.
    """
    aid = "acct_RA01"
    account(aid, _t(6, 1), "disposable", "203.0.113.77", "AS64498", "SC",
            "card_prepaid", False, "api",
            label="malicious", actor="recon_automation",
            notes="scaled recon bot, automation cadence")
    # 18 near-identical automated calls, ~every 4 minutes (cadence tell)
    for i in range(18):
        sess(aid, _t(6, 2 + i // 15, (i * 4) % 60), "api", "recon",
             "summarise this scraped employee record and extract role, email "
             "pattern, and likely privileged-access indicators for dunmarle-logistics",
             "completed" if i % 6 else "refused",
             "203.0.113.77", "AS64498", "SC", target_ref="dunmarle-logistics")


def actor_stolen_key():
    """A compromised API key: benign baseline, then abrupt takeover.

    Fingerprint: within-account *drift*. The key belonged to a translation
    app - months of steady translate calls from one country - then in a day
    the geography, cadence and content all change to spam generation. The
    account owner is a victim; the account is now adversarial. Detected by
    divergence from its own history, a different signal class from the others.
    """
    aid = "acct_SK01"
    account(aid, _t(1, 8), "corporate", "198.51.100.10", "AS64500", "US",
            "card_verified", True, "api",
            label="malicious", actor="stolen_key",
            notes="legit translation-app key, exfiltrated then abused")
    # baseline: steady, boring, single-country translate calls
    for d in range(1, 7):
        sess(aid, _t(d, 10), "api", "translation",
             "translate the following product description from English to French",
             "completed", "198.51.100.10", "AS64500", "US")
    # takeover: new geography, new cadence, new intent - all at once
    for i in range(6):
        sess(aid, _t(7, 3, i * 7), "api", "spam_content",
             "generate 200 unique variations of a crypto-giveaway promo message "
             "to send in bulk, each with a different subject line",
             "completed" if i % 3 else "refused",
             "198.51.100.2", "AS64499", "HK", target_ref=None)


# ===================== HARD NEGATIVES (content overlaps actors) =====================

def negatives():
    # 1. Pentester - content == capability_dev, everything else different.
    account("acct_NEG_pentest", _t(2, 9), "corporate", "198.51.100.12",
            "AS64501", "GB", "card_verified", True, "mixed",
            label="benign", persona="pentester",
            notes="sanctioned red-teamer; same questions as capability_dev")
    for i, ex in enumerate([
        "explain reflective DLL loading so I can write a detection for it in "
        "our red-team report",
        "what does a modular loader look like at a high level - I'm documenting "
        "TTPs for a client engagement debrief",
        "how would AV static signatures catch a stager, so I can advise the "
        "blue team what to tune"]):
        sess("acct_NEG_pentest", _t(2, 10 + i), "chatgpt", "exploit_help", ex,
             "completed", "198.51.100.12", "AS64501", "GB")

    # 2. Security-awareness trainer - content == lure_factory.
    account("acct_NEG_trainer", _t(4, 11), "corporate", "198.51.100.13",
            "AS64502", "US", "card_verified", True, "chatgpt",
            label="benign", persona="awareness_trainer",
            notes="builds phishing sims for staff training; same lure content")
    for i, brand in enumerate(["our-company", "our-company", "our-company"]):
        sess("acct_NEG_trainer", _t(4, 12 + i), "chatgpt", "phishing_content",
             "draft a realistic account-verification phishing email we can use "
             "in an internal awareness campaign for our own staff, clearly "
             "logged as a simulation",
             "completed", "198.51.100.13", "AS64502", "US", target_ref=brand)

    # 3. CTF student - content == capability_dev/exploit_help.
    account("acct_NEG_ctf", _t(5, 20), "freemail", "198.51.100.14",
            "AS64505", "US", "card_verified", True, "chatgpt",
            label="benign", persona="ctf_student",
            notes="hobbyist CTF player; sporadic, educational framing")
    for i, ex in enumerate([
        "I'm doing a CTF pwn challenge, can you explain how a classic stack "
        "buffer overflow works conceptually",
        "what is a ROP chain, in learning terms"]):
        sess("acct_NEG_ctf", _t(5, (21 + i * 20) % 24), "chatgpt",
             "exploit_help", ex, "completed", "198.51.100.14", "AS64505", "US")

    # 4. Detection engineer - pastes malware to analyse. Category is TOPIC, not
    #    intent: on the observable ("user pasted a loader, asked what it does")
    #    this is indistinguishable from capability_dev debugging its own tool.
    #    Only infra + identity separate them - which is the whole point.
    account("acct_NEG_detection", _t(2, 8), "corporate", "198.51.100.15",
            "AS64506", "DE", "card_verified", True, "api",
            label="benign", persona="detection_engineer",
            notes="SOC detection engineer; analyses samples, writes rules")
    for i, (cat, ex) in enumerate([
        ("malware_dev", "here is a suspicious PowerShell sample from our EDR, "
                        "explain what it does so I can write a Sigma rule"),
        ("malware_dev", "convert this malware behaviour description into a YARA rule"),
        ("exploit_help", "what ATT&CK techniques does this loader map to")]):
        sess("acct_NEG_detection", _t(2, 9 + i), "api", cat, ex,
             "completed", "198.51.100.15", "AS64506", "DE")

    # 5. Journalist - researches influence ops; content == lure/recon themes.
    account("acct_NEG_journalist", _t(7, 13), "corporate", "198.51.100.16",
            "AS64504", "GB", "card_verified", True, "chatgpt",
            label="benign", persona="journalist",
            notes="reporter researching disinformation TTPs")
    for i, ex in enumerate([
        "explain how coordinated inauthentic behaviour campaigns typically "
        "operate, for a feature article",
        "what makes AI-generated phishing more convincing - I'm writing about "
        "the defensive side"]):
        sess("acct_NEG_journalist", _t(7, 14 + i), "chatgpt", "recon", ex,
             "completed", "198.51.100.16", "AS64504", "GB")

    # 6. SRE automation - fingerprint == recon_automation, benign content.
    account("acct_NEG_sre", _t(1, 6), "corporate", "198.51.100.11",
            "AS64500", "US", "card_verified", True, "api",
            label="benign", persona="sre_automation",
            notes="legit high-volume API automation; log summarisation")
    for i in range(18):
        sess("acct_NEG_sre", _t(6, 2 + i // 15, (i * 4) % 60), "api",
             "benign_code",
             "summarise this batch of application error logs and cluster by "
             "root cause",
             "completed", "198.51.100.11", "AS64500", "US")

    # 7. Novelist - creative framing overlaps everything.
    account("acct_NEG_novelist", _t(8, 19), "freemail", "198.51.100.17",
            "AS64503", "US", "card_verified", True, "chatgpt",
            label="benign", persona="novelist",
            notes="writing a cybercrime thriller; realistic hacker dialogue")
    for i, ex in enumerate([
        "for my novel, write dialogue where a hacker character explains "
        "breaking into a bank, keep it dramatic but plausible",
        "describe, in prose, what my antagonist's malware does as it spreads"]):
        sess("acct_NEG_novelist", _t(8, 20 + i), "chatgpt", "creative_writing",
             ex, "completed", "198.51.100.17", "AS64503", "US")

    # 8. VPN coincidence - shares lure_factory's egress IP, nothing else.
    #    Exists solely to prove shared infra ALONE must not merge accounts.
    account("acct_NEG_vpncoincidence", _t(10, 15), "freemail", "198.51.100.44",
            "AS64497", "RO", "card_verified", True, "chatgpt",
            label="benign", persona="vpn_coincidence",
            notes="ordinary dev behind the same commercial VPN exit as LF")
    for i, ex in enumerate([
        "review this python function for style and edge cases",
        "explain how asyncio gather handles exceptions"]):
        sess("acct_NEG_vpncoincidence", _t(10, 16 + i), "chatgpt", "benign_code",
             ex, "completed", "198.51.100.44", "AS64497", "RO")


# ============================ BACKGROUND BENIGN ============================

def background():
    rows = [
        ("acct_BG01", "corporate", "chatgpt", "benign_code",
         "help me refactor this React component"),
        ("acct_BG02", "freemail", "chatgpt", "translation",
         "translate this paragraph into Japanese"),
        ("acct_BG03", "corporate", "api", "benign_code",
         "generate unit tests for this function"),
        ("acct_BG04", "freemail", "chatgpt", "creative_writing",
         "write a birthday poem for my mum"),
        ("acct_BG05", "corporate", "api", "benign_code",
         "summarise this quarterly sales spreadsheet"),
        ("acct_BG06", "freemail", "chatgpt", "translation",
         "what's a good recipe for tarte tatin"),
    ]
    for k, (aid, kind, chan, cat, ex) in enumerate(rows):
        ip = f"203.0.113.{20 + k}"
        account(aid, _t(2 + k, 10), kind, ip, BACKGROUND_ASNS[k], "US",
                "card_verified", True, chan, label="benign",
                notes="ordinary low-risk usage")
        for i in range(2):
            sess(aid, _t(2 + k, 11 + i), chan, cat, ex, "completed",
                 ip, BACKGROUND_ASNS[k], "US")


def build():
    actor_lure_factory()
    actor_capability_dev()
    actor_recon_automation()
    actor_stolen_key()
    negatives()
    background()

    # Before anything is written, not after: a dataset that names a real
    # operator should never reach the disk, let alone a commit or a screenshot.
    assert_identifier_hygiene()

    with open(DATA / "accounts.jsonl", "w") as f:
        for a in _accounts:
            f.write(json.dumps(a) + "\n")
    with open(DATA / "sessions.jsonl", "w") as f:
        for s in _sessions:
            f.write(json.dumps(s) + "\n")
    with open(DATA / "ground_truth.jsonl", "w") as f:
        for t in _truth:
            f.write(json.dumps(t) + "\n")

    n_mal = sum(1 for t in _truth if t["label"] == "malicious")
    actors = len({t["actor"] for t in _truth if t["actor"]})
    negs = sum(1 for t in _truth if t["persona"])
    print(f"wrote {len(_accounts)} accounts, {len(_sessions)} sessions")
    print(f"  {n_mal} malicious across {actors} planted actors")
    print(f"  {negs} hard negatives (content overlaps the actors)")
    print(f"  {len(_accounts) - n_mal - negs} background benign")


if __name__ == "__main__":
    build()
