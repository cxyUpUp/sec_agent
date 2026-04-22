import json
import re
import base64
import binascii
from typing import Optional

from agent.llm import call_llm
from agent.parser import parse_action
from agent.tools import TOOL_MAP
from privacy.session_manager import get_session_manager
from security.audit import append_audit_event
from security.guard import authorize_tool_call, record_confirmation
from security.input_filter import build_session_token, detect_injection
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


def _extract_confirm_action(user_input: str) -> Optional[str]:
    s = user_input.strip()
    if not s.lower().startswith("/confirm "):
        return None
    action = s.split(" ", 1)[1].strip()
    return action or None


def _extract_base64_payload(user_input: str) -> Optional[str]:
    s = user_input.strip()
    patterns = (
        r"^帮我解码这段base64(?:并执行)?[：:]\s*(.+)$",
        r"^解码这段base64(?:并执行)?[：:]\s*(.+)$",
        r"^base64解码(?:并执行)?[：:]\s*(.+)$",
        r"^/base64\s+(.+)$",
    )
    for p in patterns:
        m = re.match(p, s, flags=re.I)
        if m:
            payload = m.group(1).strip()
            return payload or None
    return None


def _wants_execute_after_decode(user_input: str) -> bool:
    s = user_input.strip().lower()
    return ("并执行" in user_input) or (" and execute" in s) or ("execute" in s)


def _decode_base64_to_text(payload: str) -> str:
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return "[Error] Invalid base64 input"
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.hex()


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
                "protocol_trace": {},
                "privacy_session": {},  # backward-compatible alias
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
        "protocol_trace": {},
        "privacy_session": {},  # backward-compatible alias
    }


def _set_protocol_trace(trace: dict, audit_ctx, action: str, counter_after: Optional[int] = None):
    protocol = {
        "protocol": "pcka_ratchet",
        "action": action,
        "session_id": audit_ctx.session_id,
        "tool_key_id": audit_ctx.tool_key_id,
        "counter_before": audit_ctx.counter,
        "sanitized_params": audit_ctx.sanitized_params,
        "pcka_sealed_params": {
            "nonce_b64": audit_ctx.pcka_params_nonce_b64,
            "ciphertext_b64": audit_ctx.pcka_params_ciphertext_b64,
            "seal_counter": audit_ctx.counter,
        },
    }
    if counter_after is not None:
        protocol["counter_after"] = counter_after
    trace["protocol_trace"] = protocol
    trace["privacy_session"] = protocol


def _run_precheck(user_input: str, trace: dict) -> tuple[bool, str]:
    injection = detect_injection(user_input)
    trace["injection_detection"] = injection
    if injection.get("blocked"):
        trace["blocked"] = True
        trace["block_reason"] = f"prompt_injection:{','.join(injection.get('reasons', []))}"
        return False, "[Blocked] Potential prompt injection detected"
    return True, ""


def _run_protocol_step(user_id: str, action: str, params: dict, trace: dict):
    audit_ctx = SESSION_MANAGER.before_tool_execution(user_id, action, params)
    _set_protocol_trace(trace, audit_ctx, action)
    print(
        f"[Protocol] pcka_ratchet sid={audit_ctx.session_id} "
        f"kid={audit_ctx.tool_key_id} "
        f"counter={audit_ctx.counter} "
        f"params={audit_ctx.sanitized_params}"
    )
    return audit_ctx


def _execute_and_filter(action: str, params: dict, llm_output: str):
    if action in TOOL_MAP:
        raw_result = TOOL_MAP[action](**params)
    else:
        raw_result = llm_output
    safe_result = filter_output(raw_result)
    return handle_llm_output(safe_result)


def run_agent(user_input: str, user_id: str = DEFAULT_USER_ID, with_trace: bool = False):
    SESSION_MANAGER.get_or_create_session(user_id)
    trace = _new_trace(user_id, user_input)
    session_token = build_session_token()
    trace["session_token"] = session_token

    # Local privacy-preserving password check: do not send password to LLM.
    confirm_action = _extract_confirm_action(user_input)
    if confirm_action is not None:
        record_confirmation(user_id, confirm_action)
        output = f"[Confirm] action={confirm_action} confirmed for 120s"
        append_audit_event(
            {
                "kind": "confirm",
                "user_id": user_id,
                "action": confirm_action,
                "status": "ok",
            }
        )
        return (output, trace) if with_trace else output

    password = _extract_pwned_password(user_input)
    if password is not None:
        print("\n[User]: pwned_check [REDACTED]")
        trace["action"] = "pwned_check"
        params = {"password": password}
        decision = authorize_tool_call(user_id, "pwned_check", params)
        if not decision.allowed:
            trace["blocked"] = True
            trace["block_reason"] = decision.reason
            output = "[Blocked] Unsafe tool execution"
            if decision.requires_confirmation:
                output = "[Blocked] Sensitive tool needs confirmation. Use: /confirm pwned_check"
            append_audit_event(
                {
                    "kind": "tool_call",
                    "user_id": user_id,
                    "action": "pwned_check",
                    "status": "blocked",
                    "reason": decision.reason,
                }
            )
            return (output, trace) if with_trace else output
        _run_protocol_step(
            user_id=user_id,
            action="pwned_check",
            params=params,
            trace=trace,
        )
        result = _execute_and_filter(
            action="pwned_check",
            params=params,
            llm_output="",
        )
        new_counter = SESSION_MANAGER.after_tool_execution(user_id, "pwned_check")
        trace["protocol_trace"]["counter_after"] = new_counter
        trace["privacy_session"]["counter_after"] = new_counter
        print(f"[Protocol] pcka_ratchet rotated counter={new_counter}")
        append_audit_event(
            {
                "kind": "tool_call",
                "user_id": user_id,
                "action": "pwned_check",
                "status": "ok",
                "tool_key_id": trace.get("protocol_trace", {}).get("tool_key_id"),
                "counter_before": trace.get("protocol_trace", {}).get("counter_before"),
                "counter_after": new_counter,
            }
        )
        return (result, trace) if with_trace else result

    b64_payload = _extract_base64_payload(user_input)
    if b64_payload is not None:
        trace["action"] = "base64_decode_local"
        output = _decode_base64_to_text(b64_payload)
        decoded_injection = detect_injection(output) if not output.startswith("[Error]") else {"blocked": False}
        if _wants_execute_after_decode(user_input) or decoded_injection.get("blocked"):
            trace["blocked"] = True
            trace["block_reason"] = "decode_then_execute_blocked"
            trace["injection_detection"] = decoded_injection
            append_audit_event(
                {
                    "kind": "local_task",
                    "user_id": user_id,
                    "action": "base64_decode_local",
                    "status": "blocked",
                    "reason": "decode_then_execute_blocked",
                }
            )
            blocked_output = "[Blocked] Decoded content cannot be executed"
            return (blocked_output, trace) if with_trace else blocked_output
        append_audit_event(
            {
                "kind": "local_task",
                "user_id": user_id,
                "action": "base64_decode_local",
                "status": "ok" if not output.startswith("[Error]") else "blocked",
            }
        )
        return (output, trace) if with_trace else output

    print(f"\n[User]: {user_input}")

    precheck_ok, precheck_output = _run_precheck(user_input, trace)
    if not precheck_ok:
        output = precheck_output
        return (output, trace) if with_trace else output

    # 调用LLM
    llm_output = call_llm(user_input, session_token=session_token)
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
    decision = authorize_tool_call(user_id, action, params)
    if not decision.allowed:
        trace["blocked"] = True
        trace["block_reason"] = decision.reason
        output = "[Blocked] Unsafe tool execution"
        if decision.requires_confirmation:
            output = f"[Blocked] Sensitive tool needs confirmation. Use: /confirm {action}"
        append_audit_event(
            {
                "kind": "tool_call",
                "user_id": user_id,
                "action": action,
                "status": "blocked",
                "reason": decision.reason,
                "schema_errors": schema_errors,
            }
        )
        return (output, trace) if with_trace else output

    # 执行工具
    if action in TOOL_MAP:
        _run_protocol_step(user_id=user_id, action=action, params=params, trace=trace)
    output = _execute_and_filter(action=action, params=params, llm_output=llm_output)
    if action in TOOL_MAP:
        new_counter = SESSION_MANAGER.after_tool_execution(user_id, action)
        trace["protocol_trace"]["counter_after"] = new_counter
        trace["privacy_session"]["counter_after"] = new_counter
        print(f"[Protocol] pcka_ratchet rotated counter={new_counter}")
        append_audit_event(
            {
                "kind": "tool_call",
                "user_id": user_id,
                "action": action,
                "status": "ok",
                "tool_key_id": trace.get("protocol_trace", {}).get("tool_key_id"),
                "counter_before": trace.get("protocol_trace", {}).get("counter_before"),
                "counter_after": new_counter,
            }
        )
    else:
        append_audit_event(
            {
                "kind": "llm_response",
                "user_id": user_id,
                "action": "none",
                "status": "ok",
            }
        )
    return (output, trace) if with_trace else output


if __name__ == "__main__":
    while True:
        user_input = input("\n>>> ")
        raw = run_agent(user_input)
        print(raw)