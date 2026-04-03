import json
import re

from agent.llm import call_llm
from agent.parser import parse_action
from agent.tools import TOOL_MAP
from privacy.session_manager import get_session_manager
from security.guard import tool_guard
from security.input_filter import detect_injection
from security.output_filter import filter_output

SESSION_MANAGER = get_session_manager()
DEFAULT_USER_ID = "local_user"


def handle_llm_output(raw_output):
    text = str(raw_output)
    # Accept common fenced JSON output from models.
    m = re.match(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", text, flags=re.S | re.I)
    if m:
        text = m.group(1)
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            params = data.get("params")
            if isinstance(params, dict) and isinstance(params.get("response"), str):
                return params["response"]
            for key in ("response", "answer", "message", "content", "text"):
                value = data.get(key)
                if isinstance(value, str):
                    return value
        return text
    except Exception:
        return text


def _extract_pwned_password(user_input: str):
    """
    Local commands that trigger Pwned Passwords check without calling LLM.
    Supported:
      - /pwned <password>
      - pwned <password>
      - 查泄露 <password>
      - 泄露检测 <password>
    """
    s = user_input.strip()
    for prefix in ("/pwned ", "pwned ", "查泄露 ", "泄露检测 "):
        if s.startswith(prefix):
            return s[len(prefix) :].strip()
    return None


def _new_trace(user_id: str, user_input: str):
    def _mask_password(text: str) -> str:
        t = str(text)
        if not t:
            return "[REDACTED]"
        if len(t) <= 4:
            return "*" * len(t)
        return f"{t[:2]}***{t[-2:]}"

    # Redact sensitive substrings from trace to reduce accidental data exposure.
    s = user_input.strip()
    for prefix in ("/pwned ", "pwned ", "查泄露 ", "泄露检测 "):
        if s.startswith(prefix):
            pw = s[len(prefix) :].strip()
            return {
                "user_id": user_id,
                "user_input": prefix + _mask_password(pw),
                "blocked": False,
                "block_reason": "",
                "action": "none",
                "schema_errors": [],
                "raw_is_json": None,
                "llm_called": False,
                "injection_detection": {},
                "privacy_session": {},
            }

    # Reuse output filter rules for general sensitive patterns in trace.
    redacted = filter_output(user_input)
    return {
        "user_id": user_id,
        "user_input": redacted,
        "blocked": False,
        "block_reason": "",
        "action": "none",
        "schema_errors": [],
        "raw_is_json": None,
        "llm_called": False,
        "injection_detection": {},
        "privacy_session": {},
    }


def run_agent(user_input: str, user_id: str = DEFAULT_USER_ID, with_trace: bool = False):
    SESSION_MANAGER.get_or_create_session(user_id)
    trace = _new_trace(user_id, user_input)

    # Local privacy-preserving password check: do not send password to LLM.
    password = _extract_pwned_password(user_input)
    if password is not None:
        print("\n[User]: pwned_check [REDACTED]")
        trace["action"] = "pwned_check"
        if not tool_guard("pwned_check", {"password": password}):
            trace["blocked"] = True
            trace["block_reason"] = "unsafe_tool_execution"
            output = "[Blocked] Unsafe tool execution"
            return (output, trace) if with_trace else output
        audit_ctx = SESSION_MANAGER.before_tool_execution(
            user_id,
            "pwned_check",
            {"password": password},
        )
        trace["privacy_session"] = {
            "session_id": audit_ctx.session_id,
            "tool_key_id": audit_ctx.tool_key_id,
            "counter_before": audit_ctx.counter,
            "sanitized_params": audit_ctx.sanitized_params,
        }
        print(
            f"[PrivacySession] sid={audit_ctx.session_id} "
            f"kid={audit_ctx.tool_key_id} "
            f"counter={audit_ctx.counter} "
            f"params={audit_ctx.sanitized_params}"
        )
        result = TOOL_MAP["pwned_check"](password=password)
        new_counter = SESSION_MANAGER.after_tool_execution(user_id, "pwned_check")
        trace["privacy_session"]["counter_after"] = new_counter
        print(f"[PrivacySession] rotated counter={new_counter}")
        output = handle_llm_output(filter_output(result))
        return (output, trace) if with_trace else output

    print(f"\n[User]: {user_input}")

    # 输入检测（防prompt injection）
    injection = detect_injection(user_input)
    trace["injection_detection"] = injection
    if injection.get("blocked"):
        trace["blocked"] = True
        trace["block_reason"] = f"prompt_injection:{','.join(injection.get('reasons', []))}"
        output = "[Blocked] Potential prompt injection detected"
        return (output, trace) if with_trace else output

    # 调用LLM
    llm_output = call_llm(user_input)
    trace["llm_called"] = True
    # print(f"[LLM Raw Output]: {llm_output}")

    # 解析action
    action, params, schema_errors, raw_is_json = parse_action(llm_output)
    trace["action"] = action
    trace["schema_errors"] = schema_errors
    trace["raw_is_json"] = raw_is_json
    if schema_errors:
        print("[Schema] Blocked invalid tool call:", schema_errors)

    # 工具安全检查（核心）
    if not tool_guard(action, params):
        trace["blocked"] = True
        trace["block_reason"] = "unsafe_tool_execution"
        output = "[Blocked] Unsafe tool execution"
        return (output, trace) if with_trace else output

    # 执行工具
    if action in TOOL_MAP:
        audit_ctx = SESSION_MANAGER.before_tool_execution(user_id, action, params)
        trace["privacy_session"] = {
            "session_id": audit_ctx.session_id,
            "tool_key_id": audit_ctx.tool_key_id,
            "counter_before": audit_ctx.counter,
            "sanitized_params": audit_ctx.sanitized_params,
        }
        print(
            f"[PrivacySession] sid={audit_ctx.session_id} "
            f"kid={audit_ctx.tool_key_id} "
            f"counter={audit_ctx.counter} "
            f"params={audit_ctx.sanitized_params}"
        )
        result = TOOL_MAP[action](**params)
        new_counter = SESSION_MANAGER.after_tool_execution(user_id, action)
        trace["privacy_session"]["counter_after"] = new_counter
        print(f"[PrivacySession] rotated counter={new_counter}")
    else:
        result = llm_output  # fallback

    # 输出过滤
    safe_result = filter_output(result)

    output = handle_llm_output(safe_result)
    return (output, trace) if with_trace else output


if __name__ == "__main__":
    while True:
        user_input = input("\n>>> ")
        raw = run_agent(user_input)
        print(raw)