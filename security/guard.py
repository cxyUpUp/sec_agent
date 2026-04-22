from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


ALLOWED_TOOLS = {"get_time", "echo", "pwned_check"}
DENY_PARAM_NAMES = {"cmd", "command", "script", "__proto__", "constructor", "class"}
ROLE_LEVEL = {"viewer": 0, "user": 1, "admin": 2}
USER_ROLES = {"local_user": "admin"}
TOOL_POLICY = {
    "get_time": {"min_role": "viewer", "sensitive": False, "rate_limit": (20, 60)},
    "echo": {"min_role": "viewer", "sensitive": False, "rate_limit": (30, 60)},
    "pwned_check": {"min_role": "user", "sensitive": True, "rate_limit": (5, 60)},
}

_RATE_BUCKETS: dict[tuple[str, str], list[float]] = {}
_CONFIRMATIONS: dict[tuple[str, str], float] = {}
_CONFIRM_TTL_S = 120.0


@dataclass
class GuardDecision:
    allowed: bool
    reason: str = ""
    requires_confirmation: bool = False


def get_user_role(user_id: str) -> str:
    return USER_ROLES.get(user_id, "user")


def record_confirmation(user_id: str, action: str) -> None:
    _CONFIRMATIONS[(user_id, action)] = time.time()


def _has_valid_confirmation(user_id: str, action: str) -> bool:
    ts = _CONFIRMATIONS.get((user_id, action))
    if ts is None:
        return False
    if (time.time() - ts) > _CONFIRM_TTL_S:
        _CONFIRMATIONS.pop((user_id, action), None)
        return False
    _CONFIRMATIONS.pop((user_id, action), None)
    return True


def _rate_limit_allow(user_id: str, action: str, limit: int, window_s: int) -> bool:
    now = time.time()
    key = (user_id, action)
    bucket = _RATE_BUCKETS.get(key, [])
    window_start = now - window_s
    bucket = [t for t in bucket if t >= window_start]
    if len(bucket) >= limit:
        _RATE_BUCKETS[key] = bucket
        return False
    bucket.append(now)
    _RATE_BUCKETS[key] = bucket
    return True


def _base_param_check(action: str, params: dict[str, Any]) -> GuardDecision:
    lower_keys = {str(k).lower() for k in params.keys()}
    risky = sorted(lower_keys & DENY_PARAM_NAMES)
    if risky:
        return GuardDecision(False, f"dangerous_param_names:{','.join(risky)}")

    if action == "get_time" and params:
        return GuardDecision(False, "invalid_params_for_get_time")

    if action == "echo":
        extra = set(params.keys()) - {"response"}
        if extra:
            return GuardDecision(False, f"invalid_params_for_echo:{sorted(extra)}")
        if "response" in params and not isinstance(params["response"], str):
            return GuardDecision(False, "echo_response_not_string")
        if isinstance(params.get("response", ""), str) and len(params.get("response", "")) > 2000:
            return GuardDecision(False, "echo_response_too_long")

    if action == "pwned_check":
        extra = set(params.keys()) - {"password"}
        if extra:
            return GuardDecision(False, f"invalid_params_for_pwned_check:{sorted(extra)}")
        if "password" not in params or not isinstance(params["password"], str):
            return GuardDecision(False, "pwned_password_invalid")
        if params["password"] == "":
            return GuardDecision(False, "pwned_password_empty")
        if len(params["password"]) > 256:
            return GuardDecision(False, "pwned_password_too_long")
        if any(ch in params["password"] for ch in ("\n", "\r", "\t")):
            return GuardDecision(False, "pwned_password_control_chars")

    return GuardDecision(True)


def authorize_tool_call(user_id: str, action: str, params: dict[str, Any]) -> GuardDecision:
    if action == "none":
        return GuardDecision(True)
    if action not in ALLOWED_TOOLS:
        return GuardDecision(False, "tool_not_whitelisted")
    if not isinstance(params, dict):
        return GuardDecision(False, "params_not_object")

    base = _base_param_check(action, params)
    if not base.allowed:
        return base

    policy = TOOL_POLICY[action]
    user_role = get_user_role(user_id)
    if ROLE_LEVEL[user_role] < ROLE_LEVEL[policy["min_role"]]:
        return GuardDecision(False, "rbac_denied")

    limit, window_s = policy["rate_limit"]
    if not _rate_limit_allow(user_id, action, limit, window_s):
        return GuardDecision(False, "rate_limited")

    if policy["sensitive"] and not _has_valid_confirmation(user_id, action):
        return GuardDecision(False, "sensitive_tool_needs_confirmation", requires_confirmation=True)

    return GuardDecision(True)