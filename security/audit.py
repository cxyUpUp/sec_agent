from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


_AUDIT_FILE = Path(__file__).resolve().parent.parent / "logs" / "security_audit.jsonl"
_LAST_HASH = "GENESIS"


def _event_hash(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def append_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    global _LAST_HASH
    _AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    material = dict(event)
    material["ts"] = time.time()
    material["prev_hash"] = _LAST_HASH
    material["event_hash"] = _event_hash(material)
    with _AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(material, ensure_ascii=False) + "\n")
    _LAST_HASH = material["event_hash"]
    return material
