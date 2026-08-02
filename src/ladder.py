"""Model ladder: run the same experiment across a capability curve.

Every number this project published before now rested on one model
(`gpt-4o-mini`). That makes each finding an anecdote about one system rather
than a claim about the problem. This module turns any harness into a
*scaling* experiment: hold the experiment fixed, vary the model, and see which
findings are properties of the model and which are properties of the problem.

The ladder is designed to separate two things that usually get mixed up:

  * GENERATION - hold the `-mini` tier constant across four generations
    (gpt-4o-mini -> gpt-4.1-mini -> gpt-5-mini -> gpt-5.4-mini). Any trend here
    is capability over time, not model size.
  * TIER       - then add a frontier model and a reasoning-specialised model as
    separate reference points, labelled as such, never blended into the
    generation trend.

The prediction worth testing: injection resistance should improve with
capability (it is a judgement task), while dual-use separation should NOT (it is
an evidence problem - no amount of reasoning recovers information the telemetry
does not contain). If that holds, it is the strongest claim in the project. If
it does not hold, the measured result is reported instead.

Deliberately thin. Both projects already thread `model` through a single entry
point, so this calls those and never touches pipeline internals.

Note on cost reporting: token counts are recorded, dollars are not. Pricing for
the newest models is not something this module can know reliably, and inventing
a number would violate the same evidence standard the rest of the project holds.
"""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Model:
    """One rung. `tier` and `generation` exist so the results table can keep the
    generation trend clean and quarantine the reference points."""
    id: str
    generation: str            # human-readable generation label
    tier: str                  # "mini" | "frontier" | "reasoning"
    released: str              # yyyy-mm, for ordering the curve
    note: str = ""


# The ladder. Ordered oldest -> newest within the mini tier, then references.
LADDER: list[Model] = [
    Model("gpt-4o-mini", "4o", "mini", "2024-07",
          "the baseline every earlier finding in this repo was measured on"),
    Model("gpt-4.1-mini", "4.1", "mini", "2025-04", ""),
    Model("gpt-5-mini", "5", "mini", "2025-08", "first reasoning-era mini"),
    Model("gpt-5.4-mini", "5.4", "mini", "2026-03", ""),
    Model("gpt-5.6-terra", "5.6-terra", "frontier", "2026-07",
          "frontier reference; treated as an empirical black box"),
    Model("o4-mini", "o4", "reasoning", "2025-04",
          "reasoning-specialised reference point"),
]

MINI_TIER = [m for m in LADDER if m.tier == "mini"]
BY_ID = {m.id: m for m in LADDER}

DEFAULT_MAX_WORKERS = 4        # bounded: politeness, not throughput


def resolve(spec: str | None) -> list[Model]:
    """Turn a --models spec into Model objects.

    "all"        -> the whole ladder
    "mini"       -> just the generation curve (the clean comparison)
    "a,b,c"      -> explicit ids
    None         -> the whole ladder
    """
    if not spec or spec == "all":
        return list(LADDER)
    if spec == "mini":
        return list(MINI_TIER)
    out = []
    for raw in spec.split(","):
        mid = raw.strip()
        if not mid:
            continue
        out.append(BY_ID.get(mid) or Model(mid, mid, "unknown", "?", "ad-hoc"))
    return out


# ------------------------------------------------------------------ accounting
@dataclass
class Usage:
    """Token/latency/error accounting per model. Populated by record()."""
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    seconds: float = 0.0
    errors: int = 0
    error_samples: list[str] = field(default_factory=list)

    def merge(self, other: "Usage") -> None:
        self.calls += other.calls
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.seconds += other.seconds
        self.errors += other.errors
        self.error_samples += other.error_samples


_USAGE: dict[str, Usage] = {}
_USAGE_LOCK = threading.Lock()


def record(model_id: str, *, prompt_tokens=0, completion_tokens=0,
           seconds=0.0, error: str | None = None) -> None:
    """Thread-safe usage accumulation. Call once per API call."""
    with _USAGE_LOCK:
        u = _USAGE.setdefault(model_id, Usage())
        u.calls += 1
        u.prompt_tokens += prompt_tokens
        u.completion_tokens += completion_tokens
        u.seconds += seconds
        if error:
            u.errors += 1
            if len(u.error_samples) < 3:
                u.error_samples.append(error[:160])


def usage_snapshot() -> dict[str, Usage]:
    with _USAGE_LOCK:
        return {k: Usage(v.calls, v.prompt_tokens, v.completion_tokens,
                         v.seconds, v.errors, list(v.error_samples))
                for k, v in _USAGE.items()}


def reset_usage() -> None:
    with _USAGE_LOCK:
        _USAGE.clear()


# -------------------------------------------------------------------- running
def run_across(models: list[Model], fn, *, max_workers=DEFAULT_MAX_WORKERS,
               progress=True) -> dict[str, object]:
    """Run `fn(model)` once per model, in parallel across models.

    Parallelising ACROSS models rather than within a model keeps each
    experiment's internal sequencing intact (an adaptive loop must stay ordered)
    while still collapsing wall-clock time. A failure is captured, not raised:
    one model erroring must not discard the other five's results.
    """
    results: dict[str, object] = {}
    with ThreadPoolExecutor(max_workers=min(max_workers, len(models))) as pool:
        futures = {pool.submit(fn, m): m for m in models}
        for fut in as_completed(futures):
            m = futures[fut]
            try:
                results[m.id] = fut.result()
            except Exception as e:                     # noqa: BLE001
                results[m.id] = {"error": f"{type(e).__name__}: {e}"}
                record(m.id, error=str(e))
                if progress:
                    print(f"  [{m.id}] FAILED: {type(e).__name__}: {e}")
            else:
                if progress:
                    print(f"  [{m.id}] done")
    # preserve ladder order in the returned mapping
    return {m.id: results[m.id] for m in models if m.id in results}


def call_with_retry(fn, *, model_id: str, attempts=5, base_delay=2.0):
    """Call an API-invoking thunk with 429/5xx backoff, recording usage.

    `fn` must return (value, usage_dict) where usage_dict has prompt_tokens and
    completion_tokens - so accounting cannot be forgotten at the call site.
    """
    delay = base_delay
    last = None
    for i in range(attempts):
        t0 = time.monotonic()
        try:
            value, usage = fn()
        except Exception as e:                          # noqa: BLE001
            last = e
            msg = str(e)
            transient = ("429" in msg or "rate" in msg.lower()
                         or "500" in msg or "502" in msg or "503" in msg
                         or "timeout" in msg.lower())
            record(model_id, seconds=time.monotonic() - t0,
                   error=None if transient and i < attempts - 1 else msg)
            if not transient or i == attempts - 1:
                raise
            time.sleep(delay)
            delay *= 2
            continue
        record(model_id, seconds=time.monotonic() - t0,
               prompt_tokens=usage.get("prompt_tokens", 0),
               completion_tokens=usage.get("completion_tokens", 0))
        return value
    raise last if last else RuntimeError("retry loop exhausted")


# --------------------------------------------------------------------- output
def usage_table() -> str:
    """Markdown token/latency table. Tokens, never dollars - see module docstring."""
    snap = usage_snapshot()
    if not snap:
        return "_no usage recorded_"
    lines = ["| model | generation | tier | calls | prompt tok | completion tok "
             "| avg s/call | errors |", "|---|---|---|---|---|---|---|---|"]
    for m in LADDER:
        u = snap.get(m.id)
        if not u:
            continue
        avg = u.seconds / u.calls if u.calls else 0.0
        lines.append(f"| `{m.id}` | {m.generation} | {m.tier} | {u.calls} | "
                     f"{u.prompt_tokens:,} | {u.completion_tokens:,} | "
                     f"{avg:.1f} | {u.errors} |")
    for mid, u in snap.items():                       # ad-hoc models
        if mid in BY_ID:
            continue
        avg = u.seconds / u.calls if u.calls else 0.0
        lines.append(f"| `{mid}` | ? | ? | {u.calls} | {u.prompt_tokens:,} | "
                     f"{u.completion_tokens:,} | {avg:.1f} | {u.errors} |")
    return "\n".join(lines)


def results_table(models: list[Model], rows: dict[str, dict], columns) -> str:
    """Markdown table: one row per model, `columns` = [(header, key), ...].

    Generation trend first, reference tiers separated by a rule, so a reader
    never mistakes a frontier or reasoning model for a point on the curve.
    """
    hdr = "| model | gen |" + "".join(f" {h} |" for h, _ in columns)
    sep = "|---|---|" + "---|" * len(columns)
    out = [hdr, sep]
    for tier in ("mini", "frontier", "reasoning", "unknown"):
        tier_models = [m for m in models if m.tier == tier]
        if not tier_models:
            continue
        if tier != "mini":
            out.append(f"| _{tier} reference_ | | "
                       + " | ".join("" for _ in columns) + " |")
        for m in tier_models:
            r = rows.get(m.id) or {}
            cells = []
            for _h, key in columns:
                v = r.get(key, "—")
                cells.append("ERR" if "error" in r else str(v))
            out.append(f"| `{m.id}` | {m.generation} | " + " | ".join(cells) + " |")
    return "\n".join(out)


def save(path, payload) -> None:
    """Persist a ladder run so a README number is always traceable to a file."""
    with open(path, "w") as fh:
        json.dump({"ladder": [m.__dict__ for m in LADDER],
                   "usage": {k: v.__dict__ for k, v in usage_snapshot().items()},
                   "results": payload}, fh, indent=2, default=str)
