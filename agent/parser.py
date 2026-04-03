import json
from security.schema import validate_llm_tool_call


def _unwrap_fenced_json(text: str) -> str:
    s = text.strip()
    if not s.startswith("```"):
        return text
    lines = s.splitlines()
    if len(lines) >= 3 and lines[0].startswith("```") and lines[-1].startswith("```"):
        return "\n".join(lines[1:-1]).strip()
    return text


def parse_action(text: str):
    """
    Returns:
      action: str
      params: dict
      errors: list[str]   # schema/format errors (empty if ok)
      raw_is_json: bool   # whether the model response was valid JSON
    """
    normalized = _unwrap_fenced_json(text)
    ok, action, params, errors = validate_llm_tool_call(normalized)
    if ok:
        return action, params, [], True

    # If it wasn't valid JSON at all, treat as plain assistant response.
    if errors == ["LLM output is not valid JSON"]:
        return "none", {"response": text}, [], False

    # JSON but invalid schema/action/params: block tool execution and return a safe error.
    safe_msg = "Invalid tool call format; tool execution blocked"
    return "none", {"response": safe_msg}, errors, True