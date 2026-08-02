"""Model-abuse threat hunting: signals, attribution, investigation, enforcement.

The pipeline is the system under test. The findings are the product.

This init also loads `.env` (gitignored) into the environment if present. The
OpenAI client reads OPENAI_API_KEY from the environment, so keeping the key in
`.env` -- never in a tracked file, never in shell history -- means the repo can
be published without a secrets scrub. Real environment variables take
precedence; `.env` only fills gaps.

Without it, every entry point that documents "real mode needs OPENAI_API_KEY"
falls back to the mock engine while a `.env` holding the key sits beside it, and
reports that only in a badge -- you believe you measured the model and you
measured the stub. Mirrors the sibling project's loader, for the same reason.
"""
from __future__ import annotations

import os
from pathlib import Path

_ENV = Path(__file__).resolve().parent.parent / ".env"

if _ENV.exists():
    for _line in _ENV.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))
