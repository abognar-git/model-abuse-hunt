# What two independent projects agreed on

I built two LLM security systems a few weeks apart, for different purposes, on
different data:

- **[alert-triage-copilot](https://github.com/abognar-git/alert-triage-copilot)** —
  a SOC triage pipeline, defending *itself* from adversarial telemetry. The
  attacker's text is an attack on the model.
- **[model-abuse-hunt](https://github.com/abognar-git/model-abuse-hunt)** —
  a threat-hunting pipeline for adversarial use *of* an AI platform. The
  attacker's text is the evidence.

They share a design rather than a file: each carries its own copy of the same
model-ladder runner, ~260 and ~300 lines, which have since diverged by about
fifty. No other code is common to both, and their datasets have nothing in
common — endpoint alerts versus account telemetry. But both were
built the same way: measure the system, attack it, record what actually happened.
Four conclusions showed up in both, and the fact that they arrived independently
is the reason to trust them more than either project's individual numbers.

## 1. The same bug wore two costumes

Triage's policy accepted `change_ticket=None`, `""`, `False` and `0` as
corroboration for closing an alert — a detector emitting that key as a null schema
default would silently disable the guard for every alert it produced. Found by
exhaustively enumerating 4,500 policy inputs, not by an attack.

Hunt's policy accepted a **0.04** automation signal — three API calls an hour
apart — as the non-content corroboration required to enforce against an account.
Found when the real model over-flagged a detection engineer and the policy let it
through to `enforce`.

Different codebases, different domains, different discovery methods, one bug:
**both tested a signal's *presence* where they needed its *strength*.** If you
have a guard that asks "is there corroboration?", check what it accepts as a yes.

## 2. The model is never the boundary

Both projects put a deterministic policy layer downstream of the model, and in
both, that layer is what saved the result.

Triage: a cover story talked `gpt-4o-mini` into `benign` on a live-C2 alert; the
policy revoked it. Across an 8-round adaptive attack the model was swayed in 2
rounds and the policy caught both.

Hunt: the real model called a legitimate detection engineer `malicious_abuse`;
the policy refused to act because no non-content signal corroborated it. Across
six models, **0/9 legitimate twins ever reached enforcement** — including cases
where the model could not separate the twins at all.

The useful phrasing: *the guarantee is not that the model is right, it is that
being wrong is not sufficient.*

## 3. The cheap filter is never the boundary either

Triage's regex input screen caught **1 of 10** payload variants, **0/5** on every
one of six models across four generations, and **0/8** rounds against an adaptive
attacker. It is not a model, so no capability upgrade improves it.

Hunt's per-account behavioral score is evadable for about **$101** of clean
residential proxy, verified card and phone verification.

Both are worth keeping — they catch the careless cheaply. Neither is a security
boundary, and treating either as one is the mistake.

## 4. An attacker cannot win on the channel it controls, and wins instantly on the channel you trust

This is the sharpest one, and both projects measured it from opposite directions.

**On the attacker's own channel, adaptive pressure achieves nothing.** Triage: 8
rounds of rewritten free text, property held 8/8. Hunt: four different attackers
— aligned, uncensored, reasoning, API — rewrote prompts for 8 rounds each, and
**0/4 evaded**, with the behavioral risk score invariant at 0.358 in every round
of every run. Prose is not an input to the gate.

**On the channel the system trusts, the same attacker wins immediately.** Triage:
allowed to also set `change_ticket` and `signer`, it won in **round 1** — benign
*and* unreviewed. Hunt: allowed to buy infrastructure, it evaded for $101.

Triage's control isolates the mechanism exactly: a cover story alone is caught by
policy; a forged field alone leaves the model unconvinced; **only the conjunction
defeats the system.** So:

> **Your security boundary is whatever input you treat as verified but never
> verify.**

Triage trusts `signer` and `change_ticket` because they are *structured* — but
structured is not verified. Hunt trusts ASN reputation and payment status for the
same reason. Both are one forgery away from silent, and the fix in both cases is
the same and is not a better model: check the claim against the system of record.

## The method, which is the fifth agreement

Between them these projects found **six** of my own measurement errors: a policy
guard that accepted null corroboration, a harness that fabricated the
coordination it was supposed to test, a confidence schema so ambiguous the model
used it two ways, an evasion definition that scored a downgrade as an escape, a
committed artifact that predated the fix to that definition and kept the
retracted version alive in published numbers, and a results file that was mock
output while the text called it a real-model run.

Not one was found by reading the code. Every one surfaced when **two instruments
disagreed** — an exhaustive enumeration contradicting a sampled attack, a forced
control contradicting an adaptive run, a cost frontier contradicting a harness.

Which is an argument for deliberately building redundant instruments, even when
they look duplicative, and for treating a disagreement between two of your own
measurements as the most interesting signal available rather than an annoyance to
reconcile.

## Caveats

Both projects use small synthetic datasets authored by the same person who wrote
their labels, and report directional findings rather than benchmarks. These
convergences are more robust than either project's individual numbers precisely
because they reproduced across two systems that share no data and almost no code
— but two is still two.
