import json
import os
import base64
import hashlib
import hmac
import secrets
from collections import Counter, defaultdict
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from agent.parser import parse_action
from eval.red_team import evaluate_red_team
from privacy.secure_channel import get_secure_channel_manager
from privacy.session_manager import get_session_manager
from security.guard import authorize_tool_call, record_confirmation
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
        if action in ("get_time", "echo", "pwned_check"):
            if action == "pwned_check":
                record_confirmation("eval_user", "pwned_check")
            allowed = authorize_tool_call("eval_user", action, params).allowed
        else:
            allowed = False

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
    seal_roundtrip_ok = 0
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

            # 0) PCKA tool key -> AES-GCM roundtrip (must run before ratchet)
            try:
                recovered = manager.decrypt_tool_params_sealed(
                    user_id,
                    action,
                    before.pcka_params_nonce_b64,
                    before.pcka_params_ciphertext_b64,
                    before.counter,
                )
                if json.loads(recovered.decode("utf-8")) == params:
                    seal_roundtrip_ok += 1
                else:
                    errors["seal_roundtrip_mismatch"] += 1
            except Exception:
                errors["seal_roundtrip_failed"] += 1

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
        "pcka_seal_roundtrip_rate": (seal_roundtrip_ok / total) if total else None,
        "leaked_fields": dict(leaked_fields),
        "errors": dict(errors),
    }


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _eval_protocol_flow():
    manager = get_secure_channel_manager()
    user_id = f"eval_protocol_{secrets.token_hex(4)}"
    alpha = secrets.token_hex(16)
    client_nonce = secrets.token_hex(16)

    client_private = ec.generate_private_key(ec.SECP256R1())
    client_public_bytes = client_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    start = manager.start_handshake(
        user_id=user_id,
        alpha=alpha,
        client_nonce=client_nonce,
        client_pubkey_b64=_b64e(client_public_bytes),
    )

    sid = _b64d(start["sid"])
    server_nonce = start["server_nonce"]
    beta = start["beta"]
    handshake_id = start["handshake_id"]

    server_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        _b64d(start["server_pubkey_b64"]),
    )
    shared_secret = client_private.exchange(ec.ECDH(), server_pub)
    dh_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sid,
        info=b"sec-agent-ecdh|" + client_nonce.encode("utf-8") + b"|" + server_nonce.encode("utf-8"),
    ).derive(shared_secret)

    session_key = secrets.token_bytes(32)
    client_proof = hmac.new(
        session_key,
        digestmod=hashlib.sha256,
    )
    client_proof.update(b"client_finish")
    client_proof.update(alpha.encode("utf-8"))
    client_proof.update(beta.encode("utf-8"))
    payload = json.dumps(
        {
            "session_key_b64": _b64e(session_key),
            "client_proof": client_proof.hexdigest(),
        }
    ).encode("utf-8")

    aad = handshake_id.encode("utf-8") + b"|" + alpha.encode("utf-8") + b"|" + beta.encode("utf-8")
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(dh_key).encrypt(nonce, payload, aad)

    finished = manager.finish_handshake(
        handshake_id=handshake_id,
        encrypted_session_key_b64=_b64e(encrypted),
        nonce_b64=_b64e(nonce),
    )
    secure_session_id = finished["secure_session_id"]
    expected_server_proof = hmac.new(session_key, b"server_finish", hashlib.sha256).hexdigest()
    handshake_ok = bool(
        secure_session_id
        and finished.get("server_proof") == expected_server_proof
        and finished.get("protocol") == "pcka_ratchet"
    )

    before = manager.get_session_meta(secure_session_id)
    key_before = before.get("protocol_key_id")
    counter_before = int(before.get("ratchet_counter", 0))
    c1 = manager.ratchet(secure_session_id)
    middle = manager.get_session_meta(secure_session_id)
    c2 = manager.ratchet(secure_session_id)
    after = manager.get_session_meta(secure_session_id)

    ratchet_ok = (
        c1 == counter_before + 1
        and c2 == counter_before + 2
        and int(after.get("ratchet_counter", -1)) == counter_before + 2
        and middle.get("protocol_key_id") != key_before
        and after.get("protocol_key_id") != middle.get("protocol_key_id")
    )

    return {
        "handshake_validity": 1.0 if handshake_ok else 0.0,
        "ratchet_progression": 1.0 if ratchet_ok else 0.0,
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
    protocol_flow = _eval_protocol_flow()
    results["protocol_flow"] = protocol_flow
    results["red_team"] = evaluate_red_team()
    results["stages"] = {
        "handshake_validity": protocol_flow["handshake_validity"],
        "ratchet_progression": protocol_flow["ratchet_progression"],
        "policy_blocking_quality": results.get("input_filter", {}).get("block_recall_tpr"),
        "sensitive_redaction_quality": results.get("privacy_session", {}).get("redaction_success_rate"),
        "red_team_block_quality": results.get("red_team", {}).get("blocked_expectation_accuracy"),
    }
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
    if "protocol_flow" in results:
        r = results["protocol_flow"]
        print("\n[protocol_flow]")
        for k, v in r.items():
            print(f"{k}: {v}")
    if "red_team" in results:
        r = results["red_team"]
        print("\n[red_team]")
        for k, v in r.items():
            print(f"{k}: {v}")
    if "stages" in results:
        r = results["stages"]
        print("\n[stages]")
        for k, v in r.items():
            print(f"{k}: {v}")


if __name__ == "__main__":
    main()

