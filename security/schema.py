import json


# Centralized schema/constraints for LLM tool calls.
# Keep this file dependency-free (no pydantic/jsonschema) for interview portability.


ALLOWED_ACTIONS = {"none", "get_time", "echo", "pwned_check"}


MAX_STRING_LEN = 2000


def _is_json_object(value) -> bool:
    return isinstance(value, dict)


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
        # No params allowed (keeps tool surface minimal)
        if params:
            errors.append('params must be empty for action="get_time"')
        return errors

    if action == "echo":
        # Only allow response as string, bounded length.
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

    # Should be unreachable if action validated earlier
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

