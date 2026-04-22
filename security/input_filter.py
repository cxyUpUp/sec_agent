import base64
import binascii
import re
import secrets
from typing import Any


BLOCK_PATTERNS = [
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "reveal hidden",
    "jailbreak",
    "忽略之前",
    "忽略以上",
    "越狱",
]


SUSPICIOUS_REGEXES = [
    re.compile(r"(base64|b64)\s*(decode|解码)", re.I),
    re.compile(r"(print|reveal|show)\s+(the\s+)?(system|developer)\s+prompt", re.I),
    re.compile(r"(执行|运行).*(命令|shell|powershell)", re.I),
]


def _maybe_decode_base64_snippet(text: str) -> str:
    # Attempt to decode likely base64 payloads for injection detection.
    candidates = re.findall(r"[A-Za-z0-9+/=]{16,}", text)
    for item in candidates[:5]:
        if len(item) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(item, validate=True).decode("utf-8", errors="ignore")
            if decoded:
                return decoded.lower()
        except (binascii.Error, ValueError):
            continue
    return ""


def detect_injection(text: str) -> dict[str, Any]:
    normalized = str(text).lower()
    reasons: list[str] = []
    risk_score = 0.0

    if any(pattern in normalized for pattern in BLOCK_PATTERNS):
        reasons.append("keyword_pattern")
        risk_score += 0.7
    if any(rx.search(normalized) for rx in SUSPICIOUS_REGEXES):
        reasons.append("suspicious_regex")
        risk_score += 0.7

    decoded = _maybe_decode_base64_snippet(normalized)
    if decoded and any(pattern in decoded for pattern in BLOCK_PATTERNS):
        reasons.append("base64_obfuscated_pattern")
        risk_score += 0.7

    blocked = risk_score >= 0.7
    return {
        "blocked": blocked,
        "risk_score": round(min(risk_score, 1.0), 3),
        "reasons": reasons,
    }


def build_session_token() -> str:
    return secrets.token_hex(16)


def wrap_user_input(user_input: str) -> str:
    return (
        "[USER_INPUT]\n"
        f"{user_input}\n"
        "[/USER_INPUT]"
    )