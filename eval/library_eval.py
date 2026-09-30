"""Score the attack library with the whole input rail.

The library is held-out public attacks plus obfuscations. Rows used to train
the classifier are not in this file. Classifier quality is reported by
eval/classifier_eval.py on classifier_test.jsonl.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

from security.input_filter import detect_injection


ROOT = Path(__file__).resolve().parent


def _load(name: str) -> list[dict]:
    path = ROOT / name
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("source") == "sec_agent_regression":
            continue
        rows.append(item)
    return rows


def _rate(hit: int, total: int) -> float | None:
    if not total:
        return None
    return round(hit / total, 4)


def main() -> int:
    attacks = _load("attack_library.jsonl")
    benign = _load("benign_library.jsonl")
    by_source: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    by_cat: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    missed = []
    for row in attacks:
        blocked = bool(detect_injection(row["user_input"]).get("blocked"))
        source = row.get("source", "unknown")
        category = row.get("category", "unknown")
        by_source[source][1] += 1
        by_cat[category][1] += 1
        if blocked:
            by_source[source][0] += 1
            by_cat[category][0] += 1
        elif len(missed) < 12:
            missed.append({"id": row.get("id"), "source": source, "category": category})
    fp = 0
    for row in benign:
        if detect_injection(row["user_input"]).get("blocked"):
            fp += 1
    report = {
        "attack_library": len(attacks),
        "benign_library": len(benign),
        "interception_rate": _rate(sum(v[0] for v in by_source.values()), len(attacks)),
        "false_positive_rate": _rate(fp, len(benign)),
        "by_source": {k: {"hit": v[0], "n": v[1], "rate": _rate(v[0], v[1])} for k, v in sorted(by_source.items())},
        "by_category": {k: {"hit": v[0], "n": v[1], "rate": _rate(v[0], v[1])} for k, v in sorted(by_cat.items())},
        "missed_preview": missed,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
