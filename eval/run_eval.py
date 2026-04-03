import json
import os
from collections import Counter, defaultdict
from typing import Optional

from agent.parser import parse_action
from privacy.session_manager import get_session_manager
from security.guard import tool_guard
from security.input_filter import detect_injection
from security.schema import validate_llm_tool_call


def _load_cases(path: str):
    cases = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            cases.append(json.loads(line))
    return cases


def _eval_input_filter(cases):
    total = 0
    tp = fp = tn = fn = 0
    for c in cases:
        total += 1
        expected_block = bool(c["expected_block"])
        detect = detect_injection(c["user_input"])
        got_block = bool(detect.get("blocked"))
        if expected_block and got_block:
            tp += 1
        elif expected_block and not got_block:
            fn += 1
        elif not expected_block and got_block:
            fp += 1
        else:
            tn += 1
    return {
        "total": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "block_recall_tpr": (tp / (tp + fn)) if (tp + fn) else None,
        "block_precision": (tp / (tp + fp)) if (tp + fp) else None,
        "false_positive_rate": (fp / (fp + tn)) if (fp + tn) else None,
    }


def _eval_llm_outputs(cases):
    total = 0
    tool_allowed_correct = 0
    reasons = Counter()
    schema_ok_count = 0
    json_count = 0

    # Confusion for "tool allowed" expectation
    tp = fp = tn = fn = 0

    for c in cases:
        total += 1
        llm_output = c["llm_output"]
        expected_tool_allowed = bool(c["expected_tool_allowed"])

        ok, action0, params0, errors0 = validate_llm_tool_call(llm_output)
        if errors0 != ["LLM output is not valid JSON"]:
            json_count += 1
        if ok:
            schema_ok_count += 1

        action, params, schema_errors, raw_is_json = parse_action(llm_output)
        allowed = (action in ("get_time", "echo")) and tool_guard(action, params)

        if allowed == expected_tool_allowed:
            tool_allowed_correct += 1

        # confusion matrix
        if expected_tool_allowed and allowed:
            tp += 1
        elif expected_tool_allowed and not allowed:
            fn += 1
        elif not expected_tool_allowed and allowed:
            fp += 1
        else:
            tn += 1

        if schema_errors:
            for e in schema_errors:
                reasons[e] += 1
        elif not raw_is_json:
            reasons["non_json_fallback"] += 1
        elif action == "none":
            reasons["action_none"] += 1

    return {
        "total": total,
        "json_rate": (json_count / total) if total else None,
        "schema_ok_rate": (schema_ok_count / total) if total else None,
        "tool_allowed_accuracy": (tool_allowed_correct / total) if total else None,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "reasons_top": reasons.most_common(10),
    }


def _eval_privacy_session(cases):
    total = 0
    redact_ok = 0
    rotation_ok = 0
    key_id_ok = 0
    leaked_fields = Counter()
    errors = Counter()

    for c in cases:
        total += 1
        user_id = c.get("user_id", f"eval_user_{total}")
        action = c["action"]
        params = c.get("params", {})
        expected_sensitive = c.get("sensitive_fields", [])

        manager = get_session_manager()

        try:
            before = manager.before_tool_execution(user_id, action, params)

            # 1) redact checks
            redacted_this_case = True
            for field in expected_sensitive:
                raw_value = params.get(field)
                safe_value = before.sanitized_params.get(field)
                if raw_value is None:
                    continue
                if str(raw_value) == str(safe_value):
                    redacted_this_case = False
                    leaked_fields[field] += 1
            if redacted_this_case:
                redact_ok += 1

            # 2) key fingerprint checks
            key_id = before.tool_key_id
            if isinstance(key_id, str) and len(key_id) >= 8:
                key_id_ok += 1
            else:
                errors["invalid_key_fingerprint"] += 1

            # 3) rotate checks
            old_counter = before.counter
            new_counter = manager.after_tool_execution(user_id, action)
            if new_counter == old_counter + 1:
                rotation_ok += 1
            else:
                errors["counter_not_incremented"] += 1
        except Exception as exc:
            errors[f"exception:{type(exc).__name__}"] += 1

    return {
        "total": total,
        "redaction_success_rate": (redact_ok / total) if total else None,
        "rotation_success_rate": (rotation_ok / total) if total else None,
        "key_fingerprint_valid_rate": (key_id_ok / total) if total else None,
        "leaked_fields": dict(leaked_fields),
        "errors": dict(errors),
    }


def evaluate_all(cases_path: Optional[str] = None):
    here = os.path.dirname(__file__)
    resolved_cases_path = cases_path or os.path.join(here, "cases.jsonl")
    cases = _load_cases(resolved_cases_path)

    groups = defaultdict(list)
    for c in cases:
        groups[c["kind"]].append(c)

    results = {}
    if "input_filter" in groups:
        results["input_filter"] = _eval_input_filter(groups["input_filter"])
    if "llm_output" in groups:
        results["llm_output"] = _eval_llm_outputs(groups["llm_output"])
    if "privacy_session" in groups:
        results["privacy_session"] = _eval_privacy_session(groups["privacy_session"])
    return results


def main():
    results = evaluate_all()

    print("== Sec_Agent eval ==")
    if "input_filter" in results:
        r = results["input_filter"]
        print("\n[input_filter]")
        for k, v in r.items():
            print(f"{k}: {v}")

    if "llm_output" in results:
        r = results["llm_output"]
        print("\n[llm_output]")
        for k, v in r.items():
            print(f"{k}: {v}")

    if "privacy_session" in results:
        r = results["privacy_session"]
        print("\n[privacy_session]")
        for k, v in r.items():
            print(f"{k}: {v}")


if __name__ == "__main__":
    main()

