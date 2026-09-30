"""Build classification-head training sets from public agent-security datasets.

Output schema (per-domain binary files):
  {"text": str, "wrapped_text": str, "label": 0|1, "id": str, "source": str, "neg_kind": str|null}

Negative sampling follows SingGuard-NSFA §3.1.2:
  hard negatives + cross-domain positives + No_Risk, Pos:Neg <= 1:3.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent
# Hugging Face is often unreachable from CN; prefer the public mirror.
os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")
os.environ.setdefault("HF_HUB_ENABLE_HF_TRANSFER", "0")
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
UNIFIED_DIR = DATA_DIR / "unified"
HEADS_DIR = DATA_DIR / "heads"
SEC_AGENT_ROOT = ROOT.parent

DOMAINS = [
    "prompt_injection_and_jailbreak",
    "malicious_code_and_cyberattack",
    "sensitive_info_stealing",
    "danger_ops_and_tool_abuse",
    "resource_abuse",
]
DOMAIN_SET = set(DOMAINS)
NO_RISK = "No_Risk"

INJECTION_HINTS = re.compile(
    r"(ignore (all )?(previous|above)|disregard previous|jailbreak|"
    r"developer mode|dan mode|do anything now|override (the )?(system|instructions)|"
    r"new instructions|system prompt|hidden (prompt|instructions)|"
    r"you are now|act as|ignore your (rules|guidelines)|"
    r"忽略(之前|以上|全部)|越狱|开发者模式|系统提示)",
    re.I,
)
CODE_HINTS = re.compile(
    r"(malware|ransomware|ransomware|exploit|payload|reverse shell|keylogger|"
    r"ddos|sql injection|xss |zero[- ]day|rootkit|botnet|c2 server|phishing kit|"
    r"木马|勒索|漏洞利用|钓鱼)",
    re.I,
)
STEAL_HINTS = re.compile(
    r"(steal|exfiltrat|leak (the )?(api|secret|password|key)|dump (the )?(prompt|credentials)|"
    r"system prompt|developer prompt|api[_ ]?key|password|credentials|"
    r"泄露|窃取|系统提示词|密钥)",
    re.I,
)
TOOL_HINTS = re.compile(
    r"(run (this )?command|execute (the )?shell|powershell|rm -rf|delete all|"
    r"grant (admin|root)|privilege escalation|webhook|http_request|"
    r"send .* to https?://|upload the secrets|"
    r"执行(命令|shell)|越权|root 权限)",
    re.I,
)
RESOURCE_HINTS = re.compile(
    r"(infinite loop|fork bomb|max tokens|repeat forever|busy.?wait|"
    r"exhaust|overgenerate|resource abuse)",
    re.I,
)


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:16]


def wrap_query(text: str) -> str:
    return f"<untrusted_input>\n{text.strip()}\n</untrusted_input>"


def infer_lang(text: str) -> str:
    if re.search(r"[\u4e00-\u9fff]", text):
        return "zh"
    return "en"


def clean_text(text: Any, max_chars: int = 4000) -> str | None:
    if text is None:
        return None
    s = str(text).strip()
    s = s.replace("\x00", " ")
    s = re.sub(r"\s+", " ", s)
    if len(s) < 8 or len(s) > max_chars:
        return None
    return s


def map_domains(text: str, hints: Iterable[str] | None = None) -> list[str]:
    found: list[str] = []
    blob = " ".join([text] + list(hints or [])).lower()
    if INJECTION_HINTS.search(blob):
        found.append("prompt_injection_and_jailbreak")
    if CODE_HINTS.search(blob):
        found.append("malicious_code_and_cyberattack")
    if STEAL_HINTS.search(blob):
        found.append("sensitive_info_stealing")
    if TOOL_HINTS.search(blob):
        found.append("danger_ops_and_tool_abuse")
    if RESOURCE_HINTS.search(blob):
        found.append("resource_abuse")
    # keep order, unique
    out: list[str] = []
    for d in found:
        if d not in out:
            out.append(d)
    return out


def normalize_l1(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        parts = raw
    else:
        parts = re.split(r"[;,|/]+", str(raw))
    aliases = {
        "prompt_injection": "prompt_injection_and_jailbreak",
        "jailbreak": "prompt_injection_and_jailbreak",
        "prompt injection & jailbreak": "prompt_injection_and_jailbreak",
        "malicious_code": "malicious_code_and_cyberattack",
        "cyberattack": "malicious_code_and_cyberattack",
        "sensitive_info": "sensitive_info_stealing",
        "sensitive_information_stealing": "sensitive_info_stealing",
        "danger_ops": "danger_ops_and_tool_abuse",
        "dangerous_operations_and_tool_abuse": "danger_ops_and_tool_abuse",
        "tool_abuse": "danger_ops_and_tool_abuse",
        "resource": "resource_abuse",
        "no_risk": NO_RISK,
        "norisk": NO_RISK,
        "benign": NO_RISK,
        "safe": NO_RISK,
    }
    out: list[str] = []
    for p in parts:
        key = str(p).strip().lower().replace(" ", "_").replace("-", "_")
        if not key:
            continue
        mapped = aliases.get(key, key)
        if mapped == NO_RISK:
            continue
        if mapped in DOMAIN_SET and mapped not in out:
            out.append(mapped)
    return out


def make_record(
    *,
    source: str,
    text: str,
    binary_label: int,
    domains: list[str],
    orig_id: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    text = clean_text(text)  # type: ignore[assignment]
    if not text:
        return None
    if binary_label not in (0, 1):
        return None
    domains = [d for d in domains if d in DOMAIN_SET]
    if binary_label == 1 and not domains:
        domains = map_domains(text) or ["prompt_injection_and_jailbreak"]
    if binary_label == 0:
        domains = []
    rec = {
        "id": f"{source}:{orig_id or _hash_text(text)}",
        "text": text,
        "wrapped_text": wrap_query(text),
        "binary_label": int(binary_label),
        "domains": domains,
        "source": source,
        "lang": infer_lang(text),
        "neg_kind": None,
    }
    if extra:
        rec["extra"] = extra
    return rec


def dump_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1
    return n


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def http_get(url: str, dest: Path, timeout: int = 60) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecAgent-guardrail-lab/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            dest.write_bytes(resp.read())
        return True
    except Exception as exc:
        print(f"  [skip] download failed {url}: {exc}", flush=True)
        return False


MIRROR = os.environ.get("HF_ENDPOINT", "https://hf-mirror.com").rstrip("/")


def hf_file_url(repo: str, relpath: str) -> str:
    return f"{MIRROR}/datasets/{repo}/resolve/main/{relpath}"


def load_table_file(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return load_jsonl(path)
    if suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("data", "rows", "examples"):
                if isinstance(payload.get(key), list):
                    return payload[key]
        return []
    if suffix == ".csv":
        import csv

        with path.open(encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))
    if suffix == ".parquet":
        import pandas as pd

        return pd.read_parquet(path).to_dict(orient="records")
    return []


def try_download_hf_files(repo: str, relpaths: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rel in relpaths:
        dest = RAW_DIR / repo.replace("/", "__") / Path(rel).name
        if dest.exists() and dest.stat().st_size > 0:
            rows.extend(load_table_file(dest))
            continue
        url = hf_file_url(repo, rel)
        print(f"  GET {url}", flush=True)
        if http_get(url, dest, timeout=45):
            try:
                rows.extend(load_table_file(dest))
            except Exception as exc:
                print(f"  [skip] parse {dest.name}: {exc}", flush=True)
    return rows


def try_hf_load(name: str, *args: Any, **kwargs: Any):
    try:
        from datasets import load_dataset  # type: ignore
    except ImportError:
        print("  [skip] python package `datasets` not installed", flush=True)
        return None
    try:
        print(f"  HF load {name} via {os.environ.get('HF_ENDPOINT')}", flush=True)
        return load_dataset(name, *args, **kwargs)
    except Exception as exc:
        print(f"  [skip] HF {name}: {exc}", flush=True)
        return None


# ---- source loaders ----

def load_local_sec_agent() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cat_map = {
        "jailbreak": ["prompt_injection_and_jailbreak"],
        "role_hijack": ["prompt_injection_and_jailbreak"],
        "developer_mode": ["prompt_injection_and_jailbreak"],
        "bypass": ["prompt_injection_and_jailbreak"],
        "marker": ["prompt_injection_and_jailbreak"],
        "format_bypass": ["prompt_injection_and_jailbreak"],
        "mixed": ["prompt_injection_and_jailbreak"],
        "obfuscation": ["prompt_injection_and_jailbreak"],
        "prompt_leak": ["sensitive_info_stealing", "prompt_injection_and_jailbreak"],
        "exfil": ["sensitive_info_stealing", "danger_ops_and_tool_abuse"],
        "shell": ["danger_ops_and_tool_abuse"],
        "privilege": ["danger_ops_and_tool_abuse"],
        "normal": [],
    }
    path = SEC_AGENT_ROOT / "eval" / "attack_cases.jsonl"
    if not path.exists():
        return rows
    for item in load_jsonl(path):
        text = item.get("user_input") or ""
        blocked = bool(item.get("expected_block"))
        cat = str(item.get("category") or "normal")
        domains = cat_map.get(cat, map_domains(text))
        rec = make_record(
            source="sec_agent_attack_cases",
            text=text,
            binary_label=1 if blocked else 0,
            domains=domains,
            orig_id=str(item.get("id") or ""),
            extra={"category": cat, "holdout": True},
        )
        if rec:
            rec["holdout"] = True
            rows.append(rec)
    return rows


def load_deepset() -> list[dict[str, Any]]:
    print("[load] deepset/prompt-injections", flush=True)
    table = try_download_hf_files(
        "deepset/prompt-injections",
        [
            "data/train-00000-of-00001.parquet",
            "data/test-00000-of-00001.parquet",
            "train.csv",
            "test.csv",
        ],
    )
    rows: list[dict[str, Any]] = []
    if table:
        for i, item in enumerate(table):
            rec = make_record(
                source="deepset_prompt_injections",
                text=item.get("text") or "",
                binary_label=int(item.get("label") or 0),
                domains=["prompt_injection_and_jailbreak"] if int(item.get("label") or 0) == 1 else [],
                orig_id=str(item.get("id") or i),
            )
            if rec:
                rows.append(rec)
        print(f"  -> {len(rows)}", flush=True)
        return rows
    ds = try_hf_load("deepset/prompt-injections")
    rows: list[dict[str, Any]] = []
    if ds is None:
        return rows
    for split, subset in ds.items():
        for i, item in enumerate(subset):
            rec = make_record(
                source="deepset_prompt_injections",
                text=item.get("text") or "",
                binary_label=int(item.get("label") or 0),
                domains=["prompt_injection_and_jailbreak"] if int(item.get("label") or 0) == 1 else [],
                orig_id=f"{split}-{i}",
            )
            if rec:
                rows.append(rec)
    print(f"  -> {len(rows)}")
    return rows


def load_jailbreak_cls() -> list[dict[str, Any]]:
    print("[load] jackhhao/jailbreak-classification", flush=True)
    table = try_download_hf_files(
        "jackhhao/jailbreak-classification",
        ["data.csv", "jailbreak_dataset.csv", "train.csv"],
    )
    rows: list[dict[str, Any]] = []
    if table:
        for i, item in enumerate(table):
            raw = str(item.get("type") or item.get("label") or "").lower()
            is_jail = raw in {"jailbreak", "1", "true", "unsafe", "injection"}
            text = item.get("prompt") or item.get("text") or item.get("question") or ""
            rec = make_record(
                source="jailbreak_classification",
                text=text,
                binary_label=1 if is_jail else 0,
                domains=["prompt_injection_and_jailbreak"] if is_jail else [],
                orig_id=str(i),
            )
            if rec:
                rows.append(rec)
        print(f"  -> {len(rows)}", flush=True)
        return rows
    ds = try_hf_load("jackhhao/jailbreak-classification")
    rows: list[dict[str, Any]] = []
    if ds is None:
        return rows
    for split, subset in ds.items():
        for i, item in enumerate(subset):
            raw = str(item.get("type") or item.get("label") or "").lower()
            is_jail = raw in {"jailbreak", "1", "true", "unsafe", "injection"}
            if "prompt" in item:
                text = item.get("prompt")
            else:
                text = item.get("text") or item.get("question") or ""
            rec = make_record(
                source="jailbreak_classification",
                text=text,
                binary_label=1 if is_jail else 0,
                domains=["prompt_injection_and_jailbreak"] if is_jail else [],
                orig_id=f"{split}-{i}",
            )
            if rec:
                rows.append(rec)
    print(f"  -> {len(rows)}")
    return rows


def load_harelix(max_n: int = 8000) -> list[dict[str, Any]]:
    print("[load] Harelix/Prompt-Injection-Mixed-Techniques-2024", flush=True)
    ds = try_hf_load("Harelix/Prompt-Injection-Mixed-Techniques-2024")
    rows: list[dict[str, Any]] = []
    if ds is None:
        return rows
    n = 0
    for split, subset in ds.items():
        for i, item in enumerate(subset):
            if n >= max_n:
                break
            text = item.get("text") or item.get("prompt") or item.get("user_input") or ""
            label_raw = item.get("label")
            if label_raw is None:
                label_raw = item.get("injection")
            try:
                label = int(label_raw)
            except (TypeError, ValueError):
                label = 1 if str(label_raw).lower() in {"injection", "jailbreak", "true", "unsafe"} else 0
            rec = make_record(
                source="harelix_injection",
                text=text,
                binary_label=label,
                domains=["prompt_injection_and_jailbreak"] if label == 1 else [],
                orig_id=f"{split}-{i}",
            )
            if rec:
                rows.append(rec)
                n += 1
    print(f"  -> {len(rows)}")
    return rows


def load_jbb() -> list[dict[str, Any]]:
    print("[load] JailbreakBench/JBB-Behaviors", flush=True)
    ds = try_hf_load("JailbreakBench/JBB-Behaviors", "behaviors")
    rows: list[dict[str, Any]] = []
    if ds is None:
        return rows
    for split, subset in ds.items():
        for i, item in enumerate(subset):
            goal = item.get("Goal") or item.get("goal") or item.get("Behavior") or ""
            source = str(item.get("Source") or item.get("Category") or "")
            # JBB has harmful + benign thematically similar goals
            kind = str(item.get("BehaviorType") or item.get("Type") or item.get("split") or "").lower()
            is_harm = True
            if "benign" in kind or str(item.get("Index") or "").startswith("benign"):
                is_harm = False
            # dataset often uses separate files; inspect Category
            cat = str(item.get("Category") or "")
            if "benign" in str(item).lower() and "harmful" not in cat.lower():
                # keep heuristic conservative: if a Benign field exists
                pass
            if "Benign" in item:
                is_harm = not bool(item.get("Benign"))
            if split.lower().startswith("benign") or "benign" in split.lower():
                is_harm = False
            domains = map_domains(str(goal), [cat, source]) if is_harm else []
            rec = make_record(
                source="jbb_behaviors",
                text=goal,
                binary_label=1 if is_harm else 0,
                domains=domains,
                orig_id=f"{split}-{i}",
                extra={"category": cat},
            )
            if rec:
                rows.append(rec)
    print(f"  -> {len(rows)}")
    return rows


def load_wildguard(max_n: int = 12000) -> list[dict[str, Any]]:
    print("[load] allenai/wildguardmix:wildguardtrain", flush=True)
    ds = try_hf_load("allenai/wildguardmix", "wildguardtrain", split="train")
    rows: list[dict[str, Any]] = []
    if ds is None:
        return rows
    rng = random.Random(42)
    indices = list(range(len(ds)))
    rng.shuffle(indices)
    taken = 0
    for i in indices:
        if taken >= max_n:
            break
        item = ds[i]
        prompt = item.get("prompt") or ""
        harm = str(item.get("prompt_harm_label") or "").lower()
        adversarial = str(item.get("adversarial") or item.get("prompt_type") or "").lower()
        if harm in {"harmful", "unsafe", "1", "true"}:
            label = 1
            domains = map_domains(prompt, [str(item.get("subcategory") or ""), str(item.get("category") or "")])
            if "jailbreak" in adversarial or "adversarial" in adversarial:
                if "prompt_injection_and_jailbreak" not in domains:
                    domains = ["prompt_injection_and_jailbreak"] + domains
        else:
            label = 0
            domains = []
        rec = make_record(
            source="wildguardmix",
            text=prompt,
            binary_label=label,
            domains=domains,
            orig_id=str(item.get("id") or i),
        )
        if rec:
            # mark keyword-like benign as hard-neg candidates
            if label == 0 and INJECTION_HINTS.search(prompt):
                rec["neg_kind"] = "hard_candidate"
            rows.append(rec)
            taken += 1
    print(f"  -> {len(rows)}")
    return rows


def load_protectai_validation() -> list[dict[str, Any]]:
    print("[load] protectai/prompt-injection-validation", flush=True)
    ds = try_hf_load("protectai/prompt-injection-validation")
    rows: list[dict[str, Any]] = []
    if ds is None:
        return rows
    for split, subset in ds.items():
        for i, item in enumerate(subset):
            text = item.get("text") or item.get("prompt") or ""
            try:
                label = int(item.get("label") or 0)
            except (TypeError, ValueError):
                label = 0
            rec = make_record(
                source=f"protectai_{split}",
                text=text,
                binary_label=label,
                domains=["prompt_injection_and_jailbreak"] if label == 1 else [],
                orig_id=str(i),
            )
            if rec:
                if split.lower() in {"not_inject", "notinject"} and label == 0:
                    rec["neg_kind"] = "hard_candidate"
                rows.append(rec)
    print(f"  -> {len(rows)}")
    return rows


def load_injecagent() -> list[dict[str, Any]]:
    print("[load] InjecAgent attacker cases (GitHub)", flush=True)
    files = {
        "attacker_cases_dh.jsonl": "danger_ops_and_tool_abuse",
        "attacker_cases_ds.jsonl": "sensitive_info_stealing",
    }
    rows: list[dict[str, Any]] = []
    base = "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/"
    for fname, domain in files.items():
        dest = RAW_DIR / "injecagent" / fname
        if not dest.exists():
            if not http_get(base + fname, dest):
                continue
        for i, item in enumerate(load_jsonl(dest)):
            text = item.get("Attacker Instruction") or item.get("Attacker instruction") or ""
            extra = str(item.get("Attack Type") or "") + " " + str(item.get("Expected Achievements") or "")
            domains = [domain]
            if INJECTION_HINTS.search(text):
                domains.insert(0, "prompt_injection_and_jailbreak")
            more = map_domains(text, [extra])
            for d in more:
                if d not in domains:
                    domains.append(d)
            rec = make_record(
                source="injecagent",
                text=text,
                binary_label=1,
                domains=domains,
                orig_id=f"{fname}-{i}",
                extra={"attack_type": item.get("Attack Type")},
            )
            if rec:
                rows.append(rec)
    # user cases as benign / hard-neg (normal tool requests)
    dest = RAW_DIR / "injecagent" / "user_cases.jsonl"
    if not dest.exists():
        http_get(base + "user_cases.jsonl", dest)
    if dest.exists():
        for i, item in enumerate(load_jsonl(dest)):
            text = item.get("User Instruction") or item.get("instruction") or item.get("User instruction") or ""
            rec = make_record(
                source="injecagent_user",
                text=text,
                binary_label=0,
                domains=[],
                orig_id=str(i),
            )
            if rec:
                rows.append(rec)
    print(f"  -> {len(rows)}")
    return rows


def load_atbench(max_n: int = 1000) -> list[dict[str, Any]]:
    print("[load] AI45Research/ATBench")
    ds = try_hf_load("AI45Research/ATBench", "ATBench", split="test")
    rows: list[dict[str, Any]] = []
    if ds is None:
        return rows
    for i, item in enumerate(ds):
        if i >= max_n:
            break
        # extract a single-turn query: first user utterance or injected text
        text = ""
        for key in ("query", "user_query", "instruction", "text"):
            if item.get(key):
                text = str(item.get(key))
                break
        if not text:
            traj = item.get("trajectory") or item.get("messages") or item.get("dialog") or []
            if isinstance(traj, str):
                try:
                    traj = json.loads(traj)
                except json.JSONDecodeError:
                    text = traj[:4000]
                    traj = []
            if isinstance(traj, list):
                for turn in traj:
                    if isinstance(turn, dict):
                        role = str(turn.get("role") or turn.get("from") or "").lower()
                        content = turn.get("content") or turn.get("text") or ""
                        if role in {"user", "human"} and content:
                            text = str(content)
                            break
        unsafe = item.get("unsafe")
        if unsafe is None:
            unsafe = item.get("label")
        if isinstance(unsafe, str):
            binary = 1 if unsafe.lower() in {"unsafe", "1", "true", "harm"} else 0
        else:
            binary = int(bool(unsafe))
        l1 = normalize_l1(item.get("L1-Risk") or item.get("risk_source") or item.get("risk"))
        rec = make_record(
            source="atbench",
            text=text,
            binary_label=binary,
            domains=l1 if binary else [],
            orig_id=str(item.get("id") or i),
        )
        if rec:
            rows.append(rec)
    print(f"  -> {len(rows)}")
    return rows


def load_nsfa_benchmarks(max_per_split: int = 20000) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Returns (train_unused, test_holdout). Entire dataset is holdout/test."""
    print("[load] inclusionAI/NSFA_Benchmarks (test-only)")
    test_rows: list[dict[str, Any]] = []
    ds = try_hf_load("inclusionAI/NSFA_Benchmarks")
    if ds is None:
        return [], test_rows
    configs = ds if isinstance(ds, dict) else {"default": ds}
    # datasets.load_dataset without config may return a DatasetDict of splits
    try:
        from datasets import get_dataset_config_names, load_dataset  # type: ignore

        names = get_dataset_config_names("inclusionAI/NSFA_Benchmarks")
    except Exception:
        names = ["NSFA_Query_Multilingual", "NSFA_Response_Multilingual", "NSFA_CrossSource_Query_Multilingual"]
        load_dataset = None  # type: ignore
    for cfg in names:
        print(f"  config {cfg}")
        try:
            from datasets import load_dataset as _ld  # type: ignore

            subset = _ld("inclusionAI/NSFA_Benchmarks", cfg)
        except Exception as exc:
            print(f"    [skip] {exc}")
            continue
        splits = subset if isinstance(subset, dict) else {"train": subset}
        for split, table in splits.items():
            n = 0
            for i, item in enumerate(table):
                if n >= max_per_split:
                    break
                text = item.get("text") or ""
                try:
                    label = int(item.get("label") or 0)
                except (TypeError, ValueError):
                    label = 0
                domains = normalize_l1(item.get("L1-Risk"))
                rec = make_record(
                    source=f"nsfa_{cfg}",
                    text=text,
                    binary_label=label,
                    domains=domains,
                    orig_id=str(item.get("id") or f"{split}-{i}"),
                    extra={"lang": item.get("lang")},
                )
                if rec:
                    rec["holdout"] = True
                    rec["lang"] = str(item.get("lang") or rec["lang"])
                    test_rows.append(rec)
                    n += 1
    print(f"  -> holdout {len(test_rows)}")
    return [], test_rows


def dedup(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out = []
    for rec in rows:
        key = _hash_text(rec["text"].lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def assign_splits(rows: list[dict[str, Any]], val_ratio: float = 0.1) -> None:
    for rec in rows:
        if rec.get("holdout"):
            rec["split"] = "test"
            continue
        h = int(_hash_text(rec["text"]), 16)
        rec["split"] = "val" if (h % 1000) < int(val_ratio * 1000) else "train"


def build_domain_sets(
    rows: list[dict[str, Any]],
    split: str,
    rng: random.Random,
    pos_neg_ratio: float = 3.0,
) -> dict[str, list[dict[str, Any]]]:
    pool = [r for r in rows if r.get("split") == split]
    positives: dict[str, list[dict[str, Any]]] = {d: [] for d in DOMAINS}
    hard: dict[str, list[dict[str, Any]]] = {d: [] for d in DOMAINS}
    safe: list[dict[str, Any]] = []
    for rec in pool:
        if rec["binary_label"] == 0:
            if rec.get("neg_kind") == "hard_candidate" or INJECTION_HINTS.search(rec["text"]):
                # attach as hard-neg for injection domain mainly
                hard["prompt_injection_and_jailbreak"].append(rec)
            else:
                safe.append(rec)
        else:
            for d in rec["domains"]:
                positives[d].append(rec)

    out: dict[str, list[dict[str, Any]]] = {}
    for domain in DOMAINS:
        pos = positives[domain]
        if not pos:
            continue
        rng.shuffle(pos)
        n_pos = len(pos)
        # hard negatives capped at |P|
        hard_pool = [r for r in hard[domain] if domain not in r.get("domains", [])]
        rng.shuffle(hard_pool)
        hard_sel = hard_pool[:n_pos]
        rem = int(pos_neg_ratio * n_pos) - len(hard_sel)
        rem = max(0, rem)
        half = rem // 2
        # cross-domain: positives of other domains that do not carry T
        cross_pool = []
        for other, items in positives.items():
            if other == domain:
                continue
            for r in items:
                if domain not in r.get("domains", []):
                    cross_pool.append(r)
        rng.shuffle(cross_pool)
        cross_sel = cross_pool[:half]
        safe_pool = [r for r in safe if r not in hard_sel]
        rng.shuffle(safe_pool)
        safe_sel = safe_pool[: rem - len(cross_sel)]

        samples = []
        for r in pos:
            samples.append(_head_row(r, domain, 1, None))
        for r in hard_sel:
            samples.append(_head_row(r, domain, 0, "hard"))
        for r in cross_sel:
            samples.append(_head_row(r, domain, 0, "cross"))
        for r in safe_sel:
            samples.append(_head_row(r, domain, 0, "safe"))
        rng.shuffle(samples)
        out[domain] = samples
    return out


def _head_row(rec: dict[str, Any], domain: str, label: int, neg_kind: str | None) -> dict[str, Any]:
    return {
        "id": rec["id"],
        "text": rec["text"],
        "wrapped_text": rec["wrapped_text"],
        "label": label,
        "domain": domain,
        "source": rec["source"],
        "lang": rec.get("lang", "en"),
        "neg_kind": neg_kind,
        "split": rec.get("split"),
    }


def write_stats(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-hf", action="store_true", help="only local + GitHub sources")
    parser.add_argument("--nsfa-max", type=int, default=8000)
    args = parser.parse_args()

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    UNIFIED_DIR.mkdir(parents=True, exist_ok=True)
    HEADS_DIR.mkdir(parents=True, exist_ok=True)

    train_pool: list[dict[str, Any]] = []
    holdout: list[dict[str, Any]] = []

    local = load_local_sec_agent()
    holdout.extend([r for r in local if r.get("holdout")])

    loaders = [load_injecagent]
    if not args.skip_hf:
        loaders.extend(
            [
                load_deepset,
                load_jailbreak_cls,
                load_harelix,
                load_jbb,
                load_protectai_validation,
                load_wildguard,
                load_atbench,
            ]
        )
    for fn in loaders:
        try:
            train_pool.extend(fn())
        except Exception as exc:
            print(f"  [error] {fn.__name__}: {exc}")

    if not args.skip_hf:
        try:
            _, nsfa = load_nsfa_benchmarks(max_per_split=args.nsfa_max)
            holdout.extend(nsfa)
        except Exception as exc:
            print(f"  [error] nsfa: {exc}")

    train_pool = dedup(train_pool)
    holdout = dedup(holdout)
    # prevent test leakage: drop train texts that appear in holdout
    hold_keys = {_hash_text(r["text"].lower()) for r in holdout}
    train_pool = [r for r in train_pool if _hash_text(r["text"].lower()) not in hold_keys]

    assign_splits(train_pool)
    for r in holdout:
        r["split"] = "test"

    unified = train_pool + holdout
    dump_jsonl(UNIFIED_DIR / "all.jsonl", unified)
    dump_jsonl(UNIFIED_DIR / "train_pool.jsonl", [r for r in train_pool if r["split"] == "train"])
    dump_jsonl(UNIFIED_DIR / "val_pool.jsonl", [r for r in train_pool if r["split"] == "val"])
    dump_jsonl(UNIFIED_DIR / "test_holdout.jsonl", holdout)

    rng = random.Random(42)
    summary: dict[str, Any] = {"sources": Counter(r["source"] for r in unified), "heads": {}}
    for split in ("train", "val"):
        domain_sets = build_domain_sets(train_pool, split, rng)
        for domain, samples in domain_sets.items():
            out_path = HEADS_DIR / domain / f"{split}.jsonl"
            dump_jsonl(out_path, samples)
            pos = sum(1 for s in samples if s["label"] == 1)
            neg = len(samples) - pos
            kinds = Counter(s.get("neg_kind") or "pos" for s in samples)
            summary["heads"].setdefault(domain, {})[split] = {
                "n": len(samples),
                "pos": pos,
                "neg": neg,
                "pos_neg": f"1:{neg / pos:.2f}" if pos else "n/a",
                "neg_kinds": dict(kinds),
                "path": str(out_path.relative_to(ROOT)),
            }

    # test files: holdout mapped per domain (no resampling; real distribution)
    for domain in DOMAINS:
        tests = []
        for rec in holdout:
            if rec["binary_label"] == 1:
                label = 1 if domain in rec["domains"] else 0
                # skip unlabeled positives for other-domain binary eval? keep as neg if not in domain
                if rec["domains"] and domain not in rec["domains"]:
                    tests.append(_head_row(rec, domain, 0, "cross"))
                elif domain in rec["domains"]:
                    tests.append(_head_row(rec, domain, 1, None))
            else:
                tests.append(_head_row(rec, domain, 0, "safe"))
        if tests:
            dump_jsonl(HEADS_DIR / domain / "test.jsonl", tests)
            pos = sum(1 for s in tests if s["label"] == 1)
            summary["heads"].setdefault(domain, {})["test"] = {
                "n": len(tests),
                "pos": pos,
                "neg": len(tests) - pos,
                "path": str((HEADS_DIR / domain / "test.jsonl").relative_to(ROOT)),
            }

    summary["unified"] = {
        "train_pool": len([r for r in train_pool if r["split"] == "train"]),
        "val_pool": len([r for r in train_pool if r["split"] == "val"]),
        "test_holdout": len(holdout),
        "binary_pos": sum(1 for r in train_pool if r["binary_label"] == 1),
        "binary_neg": sum(1 for r in train_pool if r["binary_label"] == 0),
        "domain_pos": {d: sum(1 for r in train_pool if d in r["domains"]) for d in DOMAINS},
    }
    write_stats(DATA_DIR / "stats.json", summary)
    print(json.dumps(summary["unified"], ensure_ascii=False, indent=2))
    print("wrote", DATA_DIR / "stats.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
