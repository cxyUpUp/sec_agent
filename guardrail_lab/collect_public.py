"""Download public, paper-backed safety sets and classify them.

Writes three disjoint roles:
  guardrail_lab/data/unified/classifier_train.jsonl  trains the heads
  guardrail_lab/data/unified/classifier_test.jsonl   scores the heads only
  eval/attack_library.jsonl                          held-out attacks plus obfuscations
  eval/benign_library.jsonl                          held-out benign rows only

eval/attack_cases.jsonl is not copied into any of these roles.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "guardrail_lab" / "data" / "raw" / "public"
EVAL = ROOT / "eval"
os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")
sys.path.insert(0, str(ROOT))

from guardrail_lab.preprocess import map_domains  # noqa: E402


MIRROR = os.environ["HF_ENDPOINT"].rstrip("/")
MAX_BYTES = 20_000_000

GITHUB = [
    {
        "source": "advbench",
        "paper": "Zou et al., Universal and Transferable Adversarial Attacks on Aligned Language Models",
        "url": "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv",
        "kind": "goal_csv",
        "default_head": "danger_ops_and_tool_abuse",
    },
    {
        "source": "jailbreakbench",
        "paper": "Chao et al., JailbreakBench: An Open Robustness Benchmark for Jailbreaking Large Language Models",
        "url": "https://raw.githubusercontent.com/JailbreakBench/jailbreakbench/main/src/jailbreakbench/data/harmful-behaviors.csv",
        "kind": "goal_csv",
        "default_head": "danger_ops_and_tool_abuse",
    },
    {
        "source": "jailbreakbench_benign",
        "paper": "Chao et al., JailbreakBench: An Open Robustness Benchmark for Jailbreaking Large Language Models",
        "url": "https://raw.githubusercontent.com/JailbreakBench/jailbreakbench/main/src/jailbreakbench/data/benign-behaviors.csv",
        "kind": "benign_csv",
        "default_head": "",
    },
    {
        "source": "xstest",
        "paper": "Rottger et al., XSTest: A Test Suite for Identifying Exaggerated Safety Behaviours in Large Language Models",
        "url": "https://raw.githubusercontent.com/paul-rottger/exaggerated-safety/main/xstest_v2_prompts.csv",
        "kind": "xstest",
        "default_head": "",
    },
    {
        "source": "dan_forbidden",
        "paper": "Shen et al., Do Anything Now: Characterizing and Evaluating In-The-Wild Jailbreak Prompts on Large Language Models",
        "url": "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/forbidden_question/forbidden_question_set.csv",
        "kind": "goal_csv",
        "default_head": "",
    },
    {
        "source": "harmbench",
        "paper": "Mazeika et al., HarmBench: A Standardized Evaluation Framework for Automated Red Teaming and Robust Refusal",
        "url": "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_all.csv",
        "kind": "harmbench",
        "default_head": "",
    },
]

HF_REPOS = [
    ("deepset/prompt-injections", "deepset_prompt_injections", "Piet et al. / deepset prompt-injection dataset", "prompt_injection_and_jailbreak"),
    ("jackhhao/jailbreak-classification", "jailbreak_classification", "Jailbreak classification dataset (jackhhao)", "prompt_injection_and_jailbreak"),
    ("protectai/prompt-injection-validation", "protectai_validation", "Protect AI prompt-injection validation", "prompt_injection_and_jailbreak"),
]


def _download(url: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        return True
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecAgent-guardrail/1.0"})
        with urllib.request.urlopen(req, timeout=40) as resp:
            data = resp.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES or len(data) < 20:
            print(f"  [skip] size {len(data)} {url}", flush=True)
            return False
        dest.write_bytes(data)
        return True
    except Exception as exc:
        print(f"  [skip] {url}: {exc}", flush=True)
        return False


def _read_table(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".parquet":
        import pandas as pd

        return pd.read_parquet(path).to_dict(orient="records")
    if path.suffix.lower() == ".jsonl":
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("data", "rows", "examples"):
                if isinstance(payload.get(key), list):
                    return payload[key]
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    return list(csv.DictReader(io.StringIO(text)))


def _split_for(text: str) -> str:
    """Stable 20% held-out slice. The rest trains the heads."""
    bucket = int(hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()[:8], 16) % 10
    if bucket <= 1:
        return "test"
    return "train"


def _heads(text: str, default_head: str, harmful: bool) -> list[str]:
    if not harmful:
        return []
    found = map_domains(text)
    if default_head and default_head not in found:
        found.append(default_head)
    if not found:
        found = ["danger_ops_and_tool_abuse"]
    return found


def _record(source: str, paper: str, text: str, harmful: bool, default_head: str, orig_id: str) -> dict[str, Any] | None:
    text = " ".join(str(text).split())
    if len(text) < 8 or len(text) > 2000:
        return None
    domains = _heads(text, default_head, harmful)
    short = {
        "prompt_injection_and_jailbreak": "prompt_injection",
        "malicious_code_and_cyberattack": "malicious_code",
        "sensitive_info_stealing": "sensitive_info",
        "danger_ops_and_tool_abuse": "danger_ops",
        "resource_abuse": "resource_abuse",
    }
    heads = [short[d] for d in domains if d in short]
    return {
        "id": f"{source}:{orig_id}",
        "user_input": text,
        "text": text,
        "source": source,
        "paper": paper,
        "category": heads[0] if heads else "benign",
        "domains": domains,
        "heads": heads,
        "binary_label": 1 if harmful else 0,
        "split": _split_for(text),
        "expected_block": harmful,
    }


def _from_injecagent() -> list[dict[str, Any]]:
    paper = "Zhan et al., InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents"
    rows: list[dict[str, Any]] = []
    base = RAW.parent / "injecagent"
    mapping = {
        "attacker_cases_dh.jsonl": "danger_ops_and_tool_abuse",
        "attacker_cases_ds.jsonl": "sensitive_info_stealing",
    }
    for name, default in mapping.items():
        path = base / name
        if not path.exists():
            continue
        for i, item in enumerate(_read_table(path)):
            text = item.get("Attacker Instruction") or item.get("Attacker instruction") or ""
            rec = _record("injecagent", paper, text, True, default, f"{name}-{i}")
            if rec:
                rows.append(rec)
    user_path = base / "user_cases.jsonl"
    if user_path.exists():
        for i, item in enumerate(_read_table(user_path)):
            text = item.get("User Instruction") or item.get("User instruction") or ""
            rec = _record("injecagent_user", paper, text, False, "", str(i))
            if rec:
                rows.append(rec)
    print(f"[injecagent] {len(rows)}", flush=True)
    return rows


def _from_github() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for spec in GITHUB:
        dest = RAW / f"{spec['source']}{Path(spec['url']).suffix}"
        print(f"[get] {spec['source']}", flush=True)
        if not _download(spec["url"], dest):
            alt = spec["url"].replace("xstest_v2_prompts.csv", "xstest_prompts.csv")
            if alt != spec["url"]:
                dest = RAW / "xstest_prompts.csv"
                if not _download(alt, dest):
                    continue
            else:
                continue
        table = _read_table(dest)
        kind = spec["kind"]
        for i, item in enumerate(table):
            if kind == "xstest":
                text = item.get("prompt") or item.get("text") or ""
                label = str(item.get("label") or "").lower().strip()
                harmful = label in {"unsafe", "contrast_unsafe"} or label.endswith("unsafe")
                rec = _record(spec["source"], spec["paper"], text, harmful, "", str(i))
            elif kind == "benign_csv":
                text = item.get("Goal") or item.get("goal") or item.get("Behavior") or item.get("behavior") or ""
                rec = _record(spec["source"], spec["paper"], text, False, "", str(i))
            elif kind == "harmbench":
                text = item.get("Behavior") or item.get("behavior") or item.get("goal") or ""
                rec = _record(spec["source"], spec["paper"], text, True, spec["default_head"], str(i))
            else:
                text = item.get("goal") or item.get("Goal") or item.get("question") or item.get("prompt") or item.get("text") or ""
                rec = _record(spec["source"], spec["paper"], text, True, spec["default_head"], str(i))
            if rec:
                rows.append(rec)
        print(f"  -> {len(table)}", flush=True)
    return rows


def _hf_files(repo: str) -> list[str]:
    url = f"{MIRROR}/api/datasets/{repo}/tree/main?recursive=1"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecAgent-guardrail/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        print(f"  [skip] tree {repo}: {exc}", flush=True)
        return []
    paths = []
    if isinstance(payload, dict):
        payload = payload.get("siblings") or payload.get("tree") or []
    for item in payload:
        path = item.get("path") or item.get("rfilename") or ""
        size = int(item.get("size") or 0)
        if not path:
            continue
        lower = path.lower()
        if not lower.endswith((".csv", ".jsonl", ".json", ".parquet")):
            continue
        if size and size > MAX_BYTES:
            continue
        paths.append(path)
    return paths[:6]


def _from_hf() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for repo, source, paper, default in HF_REPOS:
        print(f"[hf] {repo}", flush=True)
        paths = _hf_files(repo)
        local_dir = RAW / repo.replace("/", "__")
        if local_dir.is_dir():
            known = {Path(rel).name for rel in paths}
            for path in sorted(local_dir.iterdir()):
                if path.is_file() and path.name not in known and path.suffix.lower() in {".csv", ".jsonl", ".json", ".parquet"}:
                    paths.append(path.name)
        got = 0
        for rel in paths:
            dest = RAW / repo.replace("/", "__") / Path(rel).name
            url = f"{MIRROR}/datasets/{repo}/resolve/main/{rel}"
            if not _download(url, dest):
                continue
            try:
                table = _read_table(dest)
            except Exception as exc:
                print(f"  [skip] parse {dest.name}: {exc}", flush=True)
                continue
            for i, item in enumerate(table):
                text = item.get("text") or item.get("prompt") or item.get("question") or ""
                raw = item.get("label", item.get("type"))
                if isinstance(raw, str):
                    harmful = raw.lower() in {"1", "true", "jailbreak", "injection", "unsafe", "harmful"}
                else:
                    try:
                        harmful = int(raw or 0) == 1
                    except (TypeError, ValueError):
                        harmful = False
                rec = _record(source, paper, text, harmful, default if harmful else "", f"{Path(rel).stem}-{i}")
                if rec:
                    rows.append(rec)
                    got += 1
        print(f"  -> {got}", flush=True)
    return rows


def main() -> int:
    RAW.mkdir(parents=True, exist_ok=True)
    rows = _from_injecagent() + _from_github() + _from_hf()
    seen: set[str] = set()
    attacks: list[dict[str, Any]] = []
    benign: list[dict[str, Any]] = []
    for rec in rows:
        key = rec["user_input"].strip().lower()
        if key in seen:
            continue
        seen.add(key)
        if rec["binary_label"] == 1:
            attacks.append(rec)
        else:
            benign.append(rec)
    from guardrail_lab.assign_roles import publish

    summary = publish(attacks, benign)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return 0 if attacks else 1


if __name__ == "__main__":
    sys.exit(main())
