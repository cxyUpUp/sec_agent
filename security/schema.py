import json


# Centralized schema/constraints for LLM tool calls.
# Keep this file dependency-free (no pydantic/jsonschema) for interview portability.


ALLOWED_ACTIONS = {
    "none",
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

MAX_STRING_LEN = 2000
MAX_PATH_LEN = 512
MAX_WRITE_CHARS = 100_000


def _is_json_object(value) -> bool:
    return isinstance(value, dict)


def _check_path(params: dict, errors: list[str], required: bool = True) -> None:
    if "path" not in params:
        if required:
            errors.append("params.path is required")
        return
    path = params["path"]
    if not isinstance(path, str):
        errors.append("params.path must be a string")
    elif not path.strip():
        errors.append("params.path must not be empty")
    elif len(path) > MAX_PATH_LEN:
        errors.append(f"params.path too long (>{MAX_PATH_LEN})")


def _validate_params_for_action(action: str, params: dict) -> list[str]:
    errors: list[str] = []

    if not _is_json_object(params):
        return ["params must be an object"]

    if action == "none":
        if "response" not in params:
            errors.append('params.response is required when action="none"')
        elif not isinstance(params["response"], str):
            errors.append("params.response must be a string")
        elif len(params["response"]) > MAX_STRING_LEN:
            errors.append(f"params.response too long (>{MAX_STRING_LEN})")
        return errors

    if action == "get_time":
        if params:
            errors.append('params must be empty for action="get_time"')
        return errors

    if action == "echo":
        extra = set(params.keys()) - {"response"}
        if extra:
            errors.append(f"unexpected params fields for echo: {sorted(extra)}")
        response = params.get("response", "")
        if not isinstance(response, str):
            errors.append("params.response must be a string")
        elif len(response) > MAX_STRING_LEN:
            errors.append(f"params.response too long (>{MAX_STRING_LEN})")
        return errors

    if action == "pwned_check":
        extra = set(params.keys()) - {"password"}
        if extra:
            errors.append(f"unexpected params fields for pwned_check: {sorted(extra)}")
        if "password" not in params:
            errors.append("params.password is required")
            return errors
        if not isinstance(params["password"], str):
            errors.append("params.password must be a string")
            return errors
        if params["password"] == "":
            errors.append("params.password must not be empty")
        if len(params["password"]) > 256:
            errors.append("params.password too long (>256)")
        return errors

    if action == "list_dir":
        extra = set(params.keys()) - {"path"}
        if extra:
            errors.append(f"unexpected params fields for list_dir: {sorted(extra)}")
        if "path" in params:
            _check_path(params, errors, required=False)
        return errors

    if action == "read_file":
        extra = set(params.keys()) - {"path", "offset", "limit"}
        if extra:
            errors.append(f"unexpected params fields for read_file: {sorted(extra)}")
        _check_path(params, errors, required=True)
        if "offset" in params and (not isinstance(params["offset"], int) or params["offset"] < 1):
            errors.append("params.offset must be an integer >= 1")
        if "limit" in params and (
            not isinstance(params["limit"], int) or params["limit"] < 1 or params["limit"] > 2000
        ):
            errors.append("params.limit must be an integer in [1, 2000]")
        return errors

    if action == "write_file":
        extra = set(params.keys()) - {"path", "content"}
        if extra:
            errors.append(f"unexpected params fields for write_file: {sorted(extra)}")
        _check_path(params, errors, required=True)
        if "content" not in params:
            errors.append("params.content is required")
        elif not isinstance(params["content"], str):
            errors.append("params.content must be a string")
        elif len(params["content"]) > MAX_WRITE_CHARS:
            errors.append(f"params.content too long (>{MAX_WRITE_CHARS})")
        return errors

    if action == "str_replace":
        extra = set(params.keys()) - {"path", "old_string", "new_string"}
        if extra:
            errors.append(f"unexpected params fields for str_replace: {sorted(extra)}")
        _check_path(params, errors, required=True)
        if "old_string" not in params or not isinstance(params["old_string"], str) or not params["old_string"]:
            errors.append("params.old_string must be a non-empty string")
        elif len(params["old_string"]) > MAX_WRITE_CHARS:
            errors.append(f"params.old_string too long (>{MAX_WRITE_CHARS})")
        if "new_string" not in params or not isinstance(params["new_string"], str):
            errors.append("params.new_string must be a string")
        elif len(params["new_string"]) > MAX_WRITE_CHARS:
            errors.append(f"params.new_string too long (>{MAX_WRITE_CHARS})")
        return errors

    if action == "search_text":
        extra = set(params.keys()) - {"pattern", "path", "glob"}
        if extra:
            errors.append(f"unexpected params fields for search_text: {sorted(extra)}")
        if "pattern" not in params or not isinstance(params["pattern"], str) or not params["pattern"]:
            errors.append("params.pattern must be a non-empty string")
        elif len(params["pattern"]) > 200:
            errors.append("params.pattern too long (>200)")
        if "path" in params:
            _check_path(params, errors, required=False)
        if "glob" in params:
            if not isinstance(params["glob"], str) or not params["glob"]:
                errors.append("params.glob must be a non-empty string")
            elif len(params["glob"]) > 200:
                errors.append("params.glob too long (>200)")
        return errors

    if action == "glob_files":
        extra = set(params.keys()) - {"pattern", "path"}
        if extra:
            errors.append(f"unexpected params fields for glob_files: {sorted(extra)}")
        if "pattern" in params:
            if not isinstance(params["pattern"], str) or not params["pattern"].strip():
                errors.append("params.pattern must be a non-empty string")
            elif len(params["pattern"]) > 200:
                errors.append("params.pattern too long (>200)")
        if "path" in params:
            _check_path(params, errors, required=False)
        return errors

    if action == "run_command":
        extra = set(params.keys()) - {"argv", "timeout_s"}
        if extra:
            errors.append(f"unexpected params fields for run_command: {sorted(extra)}")
        if "argv" not in params:
            errors.append("params.argv is required")
        elif not isinstance(params["argv"], list) or not params["argv"]:
            errors.append("params.argv must be a non-empty list")
        elif len(params["argv"]) > 32:
            errors.append("params.argv too long (>32)")
        elif not all(isinstance(x, str) for x in params["argv"]):
            errors.append("params.argv items must be strings")
        elif any(len(x) > 500 for x in params["argv"]):
            errors.append("params.argv item too long (>500)")
        if "timeout_s" in params and (
            not isinstance(params["timeout_s"], int)
            or params["timeout_s"] < 1
            or params["timeout_s"] > 15
        ):
            errors.append("params.timeout_s must be an integer in [1, 15]")
        return errors

    return ["unknown action"]


def validate_llm_tool_call(text: str):
    """
    Returns: (ok: bool, action: str | None, params: dict | None, errors: list[str])
    """
    try:
        data = json.loads(text)
    except Exception:
        return False, None, None, ["LLM output is not valid JSON"]

    if not _is_json_object(data):
        return False, None, None, ["top-level JSON must be an object"]

    action = data.get("action")
    params = data.get("params", {})

    if not isinstance(action, str):
        return False, None, None, ["action must be a string"]

    if action not in ALLOWED_ACTIONS:
        return False, action, params if isinstance(params, dict) else None, [f"action not allowed: {action}"]

    errors = _validate_params_for_action(action, params)
    if errors:
        return False, action, params if isinstance(params, dict) else None, errors

    return True, action, params, []
