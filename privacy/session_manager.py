from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from privacy.crypto_session import create_session, key_fingerprint


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
        return ToolAuditContext(
            session_id=session.session_id,
            tool_key_id=key_fingerprint(tool_key),
            sanitized_params=_sanitize_params(params),
            counter=session.counter,
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
        }


_SESSION_MANAGER = SessionManager()


def get_session_manager() -> SessionManager:
    return _SESSION_MANAGER
