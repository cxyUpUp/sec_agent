from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any


_AUDIT_FILE = Path(__file__).resolve().parent.parent / "logs" / "security_audit.jsonl"
_LAST_HASH = "GENESIS"


def _event_hash(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _load_last_hash() -> str:
    if not _AUDIT_FILE.is_file():
        return "GENESIS"
    last = "GENESIS"
    with _AUDIT_FILE.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line).get("event_hash", last)
            except json.JSONDecodeError:
                continue
    return last


_LAST_HASH = _load_last_hash()


def append_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    global _LAST_HASH
    _AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    material = dict(event)
    material.setdefault("decision_id", uuid.uuid4().hex[:16])
    if "policy_version" not in material:
        from security.classifier import load_policy

        material["policy_version"] = str(load_policy().get("version", ""))
    material["ts"] = time.time()
    material["prev_hash"] = _LAST_HASH
    material["event_hash"] = _event_hash(material)
    with _AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(material, ensure_ascii=False) + "\n")
    _LAST_HASH = material["event_hash"]
    return material
