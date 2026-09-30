"""Score the held-out classifier test split with the heads only.

This does not run the rule layer or the trajectory rails. Training rows are
not read. Obfuscated copies live in the attack library and are scored here
only as an extra check that the heads see recovered text.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from security.classifier import assess


ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "guardrail_lab" / "data" / "unified" / "classifier_test.jsonl"
OBFUSCATION = ROOT / "eval" / "obfuscation_cases.jsonl"


def _load(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _rate(hit: int, total: int) -> float | None:
    if not total:
        return None
    return round(hit / total, 4)


def _score(rows: list[dict]) -> dict:
    tp = fp = tn = fn = 0
    missed = []
    for row in rows:
        verdict = assess(row.get("text") or row.get("user_input") or "", "input")
        expected = bool(row.get("expected_block", int(row.get("binary_label") or 0)))
        blocked = bool(verdict.blocked)
        if expected and blocked:
            tp += 1
        elif expected:
            fn += 1
            if len(missed) < 12:
                missed.append(row.get("id"))
        elif blocked:
            fp += 1
        else:
            tn += 1
    return {
        "n": len(rows),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "interception_rate": _rate(tp, tp + fn),
        "false_positive_rate": _rate(fp, fp + tn),
        "missed_preview": missed,
    }


def main() -> int:
    report = {
        "classifier_test": _score(_load(TEST)),
        "obfuscation_cases": _score(_load(OBFUSCATION)),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["classifier_test"]["n"] else 1


if __name__ == "__main__":
    sys.exit(main())
