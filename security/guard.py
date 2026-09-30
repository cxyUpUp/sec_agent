from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from agent.coding_tools import ALLOWED_BINARIES, GIT_ALLOWED_SUBCOMMANDS, SHELL_META_RE
from security.classifier import load_policy
from security.patterns import pattern


ALLOWED_TOOLS = {
    "get_time",
    "echo",
    "pwned_check",
    "list_dir",
    "read_file",
    "write_file",
    "str_replace",
    "search_text",
    "glob_files",
    "run_command",
}
DENY_PARAM_NAMES = {"cmd", "command", "script", "__proto__", "constructor", "class"}
ROLE_LEVEL = {"viewer": 0, "user": 1, "admin": 2}
USER_ROLES = {"local_user": "admin"}
TOOL_POLICY = {
    "get_time": {"min_role": "viewer", "sensitive": False, "rate_limit": (20, 60)},
    "echo": {"min_role": "viewer", "sensitive": False, "rate_limit": (30, 60)},
    "pwned_check": {"min_role": "user", "sensitive": True, "rate_limit": (5, 60)},
    "list_dir": {"min_role": "viewer", "sensitive": False, "rate_limit": (40, 60)},
    "read_file": {"min_role": "viewer", "sensitive": False, "rate_limit": (40, 60)},
    "search_text": {"min_role": "viewer", "sensitive": False, "rate_limit": (30, 60)},
    "glob_files": {"min_role": "viewer", "sensitive": False, "rate_limit": (30, 60)},
    "write_file": {"min_role": "user", "sensitive": True, "rate_limit": (10, 60)},
    "str_replace": {"min_role": "user", "sensitive": True, "rate_limit": (20, 60)},
    "run_command": {"min_role": "admin", "sensitive": True, "rate_limit": (8, 60)},
}

_RATE_BUCKETS: dict[tuple[str, str], list[float]] = {}
_CONFIRMATIONS: dict[tuple[str, str], tuple[float, str]] = {}


@dataclass
class GuardDecision:
    allowed: bool
    reason: str = ""
    requires_confirmation: bool = False


def get_user_role(user_id: str) -> str:
    return USER_ROLES.get(user_id, "user")


def _params_fingerprint(params: dict[str, Any] | None) -> str:
    if params is None:
        return "*"
    body = json.dumps(params, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


def record_confirmation(user_id: str, action: str, params: dict[str, Any] | None = None) -> None:
    """Confirm a sensitive tool.

    params=None keeps the legacy action-wide confirmation used by the eval suite.
    Passing params binds the confirmation to that argument set.
    """
    _CONFIRMATIONS[(user_id, action)] = (time.time(), _params_fingerprint(params))


def _has_valid_confirmation(user_id: str, action: str, params: dict[str, Any]) -> bool:
    stored = _CONFIRMATIONS.get((user_id, action))
    if stored is None:
        return False
    ts, fingerprint = stored
    ttl_s = float(load_policy().get("confirmation_ttl_s", 120))
    if (time.time() - ts) > ttl_s:
        _CONFIRMATIONS.pop((user_id, action), None)
        return False
    if fingerprint != "*" and fingerprint != _params_fingerprint(params):
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


def _path_looks_safe(path: Any) -> bool:
    if not isinstance(path, str) or not path.strip():
        return False
    if "\x00" in path:
        return False
    lowered = path.replace("\\", "/").lower()
    if ".." in lowered.split("/"):
        return False
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

    if action in {"list_dir", "read_file", "write_file", "str_replace", "search_text", "glob_files"}:
        if "path" in params and not _path_looks_safe(params["path"]):
            return GuardDecision(False, "unsafe_path")
        if "path" in params and pattern("sensitive_path").search(str(params["path"]).replace("\\", "/")):
            return GuardDecision(False, "sensitive_path")

    if action == "write_file":
        if "content" not in params or not isinstance(params["content"], str):
            return GuardDecision(False, "write_content_invalid")
        if len(params["content"]) > 100_000:
            return GuardDecision(False, "write_content_too_long")

    if action == "str_replace":
        if not isinstance(params.get("old_string"), str) or not params.get("old_string"):
            return GuardDecision(False, "str_replace_old_invalid")
        if not isinstance(params.get("new_string"), str):
            return GuardDecision(False, "str_replace_new_invalid")

    if action == "run_command":
        argv = params.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
            return GuardDecision(False, "run_command_argv_invalid")
        if any(SHELL_META_RE.search(x) for x in argv):
            return GuardDecision(False, "run_command_shell_meta")
        binary = argv[0].replace("\\", "/").split("/")[-1].lower()
        if binary.endswith(".exe"):
            binary = binary[:-4]
        if binary not in ALLOWED_BINARIES:
            return GuardDecision(False, "run_command_binary_denied")
        if binary == "git" and (len(argv) < 2 or argv[1] not in GIT_ALLOWED_SUBCOMMANDS):
            return GuardDecision(False, "run_command_git_subcommand_denied")

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

    if policy["sensitive"] and not _has_valid_confirmation(user_id, action, params):
        return GuardDecision(False, "sensitive_tool_needs_confirmation", requires_confirmation=True)

    return GuardDecision(True)
