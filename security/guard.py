ALLOWED_TOOLS = ["get_time", "echo", "pwned_check"]
DENY_PARAM_NAMES = {"cmd", "command", "script", "__proto__", "constructor", "class"}

def tool_guard(action, params):
    if action == "none":
        return True

    if action not in ALLOWED_TOOLS:
        print("[Guard] Blocked unknown tool:", action)
        return False

    if not isinstance(params, dict):
        print("[Guard] Blocked non-object params")
        return False

    lower_keys = {str(k).lower() for k in params.keys()}
    risky = sorted(lower_keys & DENY_PARAM_NAMES)
    if risky:
        print("[Guard] Blocked dangerous param names:", risky)
        return False

    # Tool-specific parameter constraints (defense-in-depth; schema should also enforce this).
    if action == "get_time":
        if params:
            print("[Guard] Blocked get_time with non-empty params")
            return False

    if action == "echo":
        extra = set(params.keys()) - {"response"}
        if extra:
            print("[Guard] Blocked echo with extra params:", sorted(extra))
            return False
        if "response" in params and not isinstance(params["response"], str):
            print("[Guard] Blocked echo with non-string response")
            return False
        if isinstance(params.get("response", ""), str) and len(params.get("response", "")) > 2000:
            print("[Guard] Blocked echo response too long")
            return False

    if action == "pwned_check":
        extra = set(params.keys()) - {"password"}
        if extra:
            print("[Guard] Blocked pwned_check with extra params:", sorted(extra))
            return False
        if "password" not in params or not isinstance(params["password"], str):
            print("[Guard] Blocked pwned_check with invalid password param")
            return False
        if params["password"] == "":
            print("[Guard] Blocked pwned_check with empty password")
            return False
        if len(params["password"]) > 256:
            print("[Guard] Blocked pwned_check password too long")
            return False
        if any(ch in params["password"] for ch in ("\n", "\r", "\t")):
            print("[Guard] Blocked pwned_check password with control chars")
            return False

    return True