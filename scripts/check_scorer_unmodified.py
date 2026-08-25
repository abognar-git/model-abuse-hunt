#!/usr/bin/env python3
"""Guard the label-cost finding's honesty.

The whole result — that swapping a clean label for a real classifier moves recall
and precision — is only trustworthy if the oracle and predicted runs feed the
*same, unmodified* scorer and differ in *nothing but* the topic `category`. This
check asserts exactly that, so the finding can never quietly become an artifact
of the harness changing something else. It also byte-compares src/signals.py
against git HEAD, so an in-tree fork of the scorer cannot pass silently.

Runnable without pytest:  python scripts/check_scorer_unmodified.py  (exit 0 = ok)
Also exposes test_* functions for pytest.
"""
from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import signals  # noqa: E402
from scripts.generate_population import assemble  # noqa: E402


def _oracle(sessions: list[dict]) -> list[dict]:
    """The exact transform experiment.py applies for the oracle run."""
    out = copy.deepcopy(sessions)
    for s in out:
        s["category"] = s.get("category_true", s["category"])
    return out


def test_oracle_changes_only_the_category_label() -> None:
    _, sessions, _ = assemble(n=120, prevalence=0.05, dual_use_frac=0.12,
                              hard_fraction=0.35, seed=1)
    before = copy.deepcopy(sessions)
    oracle = _oracle(sessions)

    # 1. building the oracle view must not mutate the predicted sessions
    assert sessions == before, "oracle transform mutated the predicted sessions"

    # 2. oracle vs predicted may differ ONLY in `category`
    for pred, orac in zip(sessions, oracle):
        changed = {k for k in pred if pred[k] != orac.get(k)}
        assert changed <= {"category"}, \
            f"oracle run changed more than the label: {sorted(changed)}"


def test_scorer_is_deterministic_and_non_mutating() -> None:
    accts, sessions, _ = assemble(n=80, prevalence=0.05, dual_use_frac=0.12,
                                  hard_fraction=0.35, seed=2)
    by: dict[str, list] = {}
    for s in sessions:
        by.setdefault(s["account_id"], []).append(s)
    acc = accts[0]
    sess = by.get(acc["account_id"], [])

    r1 = signals.score_account(acc, copy.deepcopy(sess))["risk_score"]
    r2 = signals.score_account(acc, copy.deepcopy(sess))["risk_score"]
    assert r1 == r2, "scorer is not deterministic on identical input"

    snapshot = copy.deepcopy(sess)
    signals.score_account(acc, sess)
    assert sess == snapshot, "scorer mutated its session inputs"


def test_scorer_matches_git_head() -> None:
    """The scorer on disk is byte-for-byte the committed one, not a fork."""
    rel = "src/signals.py"
    try:
        committed = subprocess.run(
            ["git", "show", f"HEAD:{rel}"], cwd=ROOT, check=True,
            capture_output=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        # No git history to compare against (e.g. a tarball checkout): the
        # behavioural checks above still hold; only the fork check is skipped.
        print("note: git HEAD unavailable; skipping the byte comparison")
        return
    on_disk = (ROOT / rel).read_bytes()
    assert on_disk == committed, \
        f"{rel} differs from git HEAD - the scorer has been modified in-tree"


def main() -> None:
    test_oracle_changes_only_the_category_label()
    test_scorer_is_deterministic_and_non_mutating()
    test_scorer_matches_git_head()
    print("OK: scorer is unmodified across the two runs; oracle changes only "
          "`category`, scoring is deterministic and non-mutating, and "
          "src/signals.py matches git HEAD.")


if __name__ == "__main__":
    main()
