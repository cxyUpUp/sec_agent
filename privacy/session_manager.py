from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from privacy.crypto_session import (
    create_session,
    key_fingerprint,
    pcka_aad_tool_payload,
    pcka_open,
    pcka_seal,
)


SENSITIVE_FIELDS = {"password", "token", "api_key", "secret", "phone"}


def _mask(value: Any) -> str:
    text = str(value)
    if not text:
        return "[REDACTED]"
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}***{text[-2:]}"


def _sanitize_params(params: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in params.items():
        if key.lower() in SENSITIVE_FIELDS:
            sanitized[key] = _mask(value)
        else:
            sanitized[key] = value
    return sanitized


@dataclass
class ToolAuditContext:
    session_id: str
    tool_key_id: str
    sanitized_params: dict[str, Any]
    counter: int
    # PCKA tool key -> AES-256-GCM over full params (decrypt before ratchet; see decrypt_tool_params_sealed).
    pcka_params_nonce_b64: str
    pcka_params_ciphertext_b64: str


@dataclass
class ProtocolSnapshot:
    protocol: str
    session_id: str
    counter: int
    key_id: str | None = None


class SessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, Any] = {}

    def get_or_create_session(self, user_id: str):
        if user_id not in self._sessions:
            self._sessions[user_id] = create_session()
        return self._sessions[user_id]

    def before_tool_execution(self, user_id: str, action: str, params: dict[str, Any]) -> ToolAuditContext:
        session = self.get_or_create_session(user_id)
        tool_key = session.derive_tool_key(action)
        seal_counter = session.counter
        payload = json.dumps(params, ensure_ascii=False, sort_keys=True).encode("utf-8")
        aad = pcka_aad_tool_payload(session.session_id, action, seal_counter)
        nonce, ciphertext = pcka_seal(tool_key, payload, aad)
        return ToolAuditContext(
            session_id=session.session_id,
            tool_key_id=key_fingerprint(tool_key),
            sanitized_params=_sanitize_params(params),
            counter=seal_counter,
            pcka_params_nonce_b64=base64.b64encode(nonce).decode("ascii"),
            pcka_params_ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
        )

    def decrypt_tool_params_sealed(
        self,
        user_id: str,
        action: str,
        nonce_b64: str,
        ciphertext_b64: str,
        seal_counter: int,
    ) -> bytes:
        """
        Recover params JSON bytes using the current PCKA ratchet step.
        Only valid while session.counter == seal_counter (before after_tool_execution).
        """
        session = self.get_or_create_session(user_id)
        if session.counter != seal_counter:
            raise ValueError(
                "PCKA ratchet advanced: sealed params cannot be opened with the current session state"
            )
        tool_key = session.derive_tool_key(action)
        aad = pcka_aad_tool_payload(session.session_id, action, seal_counter)
        return pcka_open(
            tool_key,
            base64.b64decode(nonce_b64.encode("ascii")),
            base64.b64decode(ciphertext_b64.encode("ascii")),
            aad,
        )

    def after_tool_execution(self, user_id: str, action: str) -> int:
        session = self.get_or_create_session(user_id)
        session.rotate(context=action)
        return session.counter

    def get_session_snapshot(self, user_id: str) -> dict[str, Any]:
        session = self.get_or_create_session(user_id)
        return {
            "user_id": user_id,
            "session_id": session.session_id,
            "counter": session.counter,
            "protocol": "pcka_ratchet",
        }

    def build_protocol_snapshot(self, user_id: str, action: str = "") -> ProtocolSnapshot:
        session = self.get_or_create_session(user_id)
        key_id = None
        if action:
            key_id = key_fingerprint(session.derive_tool_key(action))
        return ProtocolSnapshot(
            protocol="pcka_ratchet",
            session_id=session.session_id,
            counter=session.counter,
            key_id=key_id,
        )


_SESSION_MANAGER = SessionManager()


def get_session_manager() -> SessionManager:
    return _SESSION_MANAGER
