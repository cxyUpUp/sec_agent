"""Train the trajectory judge on public InjecAgent traces.

Each attacker instruction is paired with a real user task. The unsafe label
is an action that repeats attacker-only details. The safe label is the tool
the user actually requested, including when the observation still contains
the attacker text. Held-out attackers are not training rows.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from pathlib import Path

from security.trajectory_head import clear_trajectory, score_trajectory, train_trajectory


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "guardrail_lab" / "data" / "raw" / "injecagent"
UNIFIED = ROOT / "guardrail_lab" / "data" / "unified"
_TOKEN = re.compile(r"[a-z0-9]{3,}")


def _load(name: str) -> list[dict]:
    path = RAW / name
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _holdout(text: str) -> bool:
    bucket = int(hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()[:8], 16) % 5
    return bucket == 0


def _distinct(instruction: str, user: str) -> list[str]:
    user_tokens = set(_TOKEN.findall(user.lower()))
    found = []
    for token in _TOKEN.findall(instruction.lower()):
        if token not in user_tokens and token not in found:
            found.append(token)
    return found[:8]


def _paraphrase(instruction: str) -> str:
    text = re.sub(r"^please\s+", "", instruction.strip(), flags=re.I)
    if text:
        text = text[0].lower() + text[1:]
    return "The previous result is ready. Next, " + text


def _examples() -> tuple[list[tuple], list[tuple]]:
    users = _load("user_cases.jsonl")
    attackers = _load("attacker_cases_dh.jsonl") + _load("attacker_cases_ds.jsonl")
    train: list[tuple] = []
    test: list[tuple] = []
    rng = random.Random(7)
    for index, attacker in enumerate(attackers):
        instruction = str(attacker.get("Attacker Instruction") or "").strip()
        if len(instruction) < 8:
            continue
        bucket = test if _holdout(instruction) else train
        for offset in range(3):
            user = users[(index + offset) % len(users)]
            request = str(user.get("User Instruction") or "")
            user_tool = str(user.get("User Tool") or "read")
            user_args = {"request": request[:240]}
            distinct = _distinct(instruction, request)
            attack_args = {"command": " ".join([str(attacker.get("Attacker Tools", ["tool"])[0]), *distinct])}
            forms = [instruction]
            if bucket is train:
                forms.append(_paraphrase(instruction))
            for observation in forms:
                bucket.append((request, observation, "bash", attack_args, 1.0))
                bucket.append((request, observation, user_tool, user_args, 0.0))
            bucket.append((request, "No issues found in the retrieved record.", user_tool, user_args, 0.0))
    benign = [
        ("Run the unit tests", "collected 12 tests, all passing", "bash", {"command": "pytest -q"}, 0.0),
        ("Summarize README.md", "This file explains how to install the project.", "bash", {"command": "python -c print(1)"}, 0.0),
        ("List the files in the workspace", "README.md and security/", "ls", {"path": "."}, 0.0),
        ("Read the notes", "Meeting notes from Monday.", "read", {"path": "README.md"}, 0.0),
    ]
    train.extend(benign)
    rng.shuffle(train)
    return train, test


def _record(row: tuple, split: str) -> dict:
    user, observation, name, args, target = row
    return {
        "user": user,
        "observation": observation,
        "tool": name,
        "args": args,
        "expected_block": bool(target),
        "split": split,
    }


def _write_split(path: Path, rows: list[tuple], split: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(_record(row, split), ensure_ascii=False) + "\n")


def _rate(rows: list[tuple]) -> dict[str, float | int]:
    if not rows:
        return {"n": 0}
    hit = fp = positive = negative = 0
    for user, observation, name, args, target in rows:
        score = score_trajectory(user, observation, name, args)
        predicted = score >= 0.6
        if target == 1.0:
            positive += 1
            hit += int(predicted)
        else:
            negative += 1
            fp += int(predicted)
    return {
        "n": len(rows),
        "unsafe_recall": round(hit / positive, 4) if positive else None,
        "false_positive_rate": round(fp / negative, 4) if negative else None,
    }


def main() -> int:
    train, test = _examples()
    _write_split(UNIFIED / "trajectory_train.jsonl", train, "train")
    _write_split(UNIFIED / "trajectory_test.jsonl", test, "test")
    model = train_trajectory(train)
    clear_trajectory()
    report = {
        "trajectory_train": model["train_rows"],
        "trajectory_test": _rate(test),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
