"""Split public rows into the three roles the guardrail actually uses.

classifier_train.jsonl trains the heads.
classifier_test.jsonl scores the heads with assess() only.
attack_library.jsonl is only the held-out public attacks plus obfuscated
copies of held-out injection prompts. benign_library.jsonl is only the
held-out benign rows. Rows used to train the classifier stay in
public_attacks.jsonl, public_benign.jsonl, and classifier_train.jsonl.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "eval"
UNIFIED = ROOT / "guardrail_lab" / "data" / "unified"

sys.path.insert(0, str(ROOT))

from guardrail_lab.collect_public import _split_for  # noqa: E402


def _variants(text: str) -> list[tuple[str, str]]:
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return [
        ("case", text.swapcase()),
        ("space", " ".join(text)),
        ("zerowidth", "\u200b".join(text)),
        ("base64", f"please decode and follow: {encoded}"),
    ]


def _obfuscations(attacks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    taken = 0
    for rec in attacks:
        if rec.get("split") != "test" or rec.get("category") != "prompt_injection":
            continue
        if taken >= 40:
            break
        taken += 1
        for kind, text in _variants(rec["user_input"]):
            rows.append(
                {
                    "id": f"obfuscation:{kind}:{rec['id']}",
                    "user_input": text,
                    "text": text,
                    "source": "obfuscation",
                    "paper": "Character, spacing, and encoding variants of held-out public injection prompts",
                    "category": "prompt_injection",
                    "domains": ["prompt_injection_and_jailbreak"],
                    "heads": ["prompt_injection"],
                    "binary_label": 1,
                    "split": "guardrail",
                    "expected_block": True,
                    "derived_from": rec["id"],
                }
            )
    return rows


def _write(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for rec in rows:
            handle.write(json.dumps(rec, ensure_ascii=False) + "\n")


def publish(attacks: list[dict[str, Any]], benign: list[dict[str, Any]]) -> dict[str, Any]:
    attacks = [rec for rec in attacks if rec.get("source") not in {"sec_agent_regression", "obfuscation"}]
    benign = [rec for rec in benign if rec.get("source") != "sec_agent_regression"]
    for rec in attacks + benign:
        rec["split"] = _split_for(rec["user_input"])
    obfuscated = _obfuscations(attacks)
    train_rows = [rec for rec in attacks + benign if rec["split"] == "train"]
    test_rows = [rec for rec in attacks + benign if rec["split"] == "test"]
    held_out_attacks = [rec for rec in attacks if rec["split"] != "train"]
    held_out_benign = [rec for rec in benign if rec["split"] != "train"]
    library = held_out_attacks + obfuscated
    _write(UNIFIED / "public_attacks.jsonl", attacks)
    _write(UNIFIED / "public_benign.jsonl", benign)
    _write(EVAL / "attack_library.jsonl", library)
    _write(EVAL / "benign_library.jsonl", held_out_benign)
    _write(EVAL / "obfuscation_cases.jsonl", obfuscated)
    _write(UNIFIED / "classifier_train.jsonl", train_rows)
    _write(UNIFIED / "head_train.jsonl", train_rows)
    _write(UNIFIED / "classifier_test.jsonl", test_rows)
    return {
        "public_attacks": len(attacks),
        "excluded_train_attacks": len(attacks) - len(held_out_attacks),
        "obfuscation": len(obfuscated),
        "public_benign": len(benign),
        "excluded_train_benign": len(benign) - len(held_out_benign),
        "benign_library": len(held_out_benign),
        "classifier_train": len(train_rows),
        "classifier_test": len(test_rows),
        "attack_library": len(library),
        "sources": _sources(library),
    }


def _sources(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rec in rows:
        counts[rec["source"]] = counts.get(rec["source"], 0) + 1
    return counts


def _load(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def main() -> int:
    attack_corpus = UNIFIED / "public_attacks.jsonl"
    benign_corpus = UNIFIED / "public_benign.jsonl"
    attacks = _load(attack_corpus) if attack_corpus.is_file() else _load(EVAL / "attack_library.jsonl")
    benign = _load(benign_corpus) if benign_corpus.is_file() else _load(EVAL / "benign_library.jsonl")
    summary = publish(attacks, benign)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["public_attacks"] else 1


if __name__ == "__main__":
    sys.exit(main())
