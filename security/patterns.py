"""Compiled enforcement patterns from policy.json.

Rails and the tool guard both read this module so path and command rules
cannot drift apart.
"""

from __future__ import annotations

import re
from functools import lru_cache

from security.classifier import load_policy


@lru_cache(maxsize=1)
def pattern_map() -> dict[str, re.Pattern[str]]:
    raw = load_policy().get("patterns", {})
    return {name: re.compile(str(expr), re.I) for name, expr in raw.items()}


def pattern(name: str) -> re.Pattern[str]:
    compiled = pattern_map()
    if name not in compiled:
        raise KeyError(f"policy pattern missing: {name}")
    return compiled[name]


def clear_patterns() -> None:
    pattern_map.cache_clear()
