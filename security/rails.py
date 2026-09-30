"""Trajectory-aware guardrail runtime.

Five rails, cheap checks first:

- input: user text, before the model acts
- pre_tool: arguments, before a tool runs
- trajectory: cross-step chains (secret read followed by exfil)
- observation: tool output that tries to steer the next step
- output: secret redaction on text that will re-enter the model

`profile="chat"` keeps Sec_Agent's existing injection detector.
`profile="coding"` drops script-class and fullwidth rules that false-positive
on source code and Chinese punctuation, and adds path / command checks for
MiniClaw tools.
"""

from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from security.classifier import assess
from security.context_guard import injected_goal, judge_prompt, review_trajectory, user_already_asked
from security.input_filter import detect_injection
from security.output_filter import filter_output
from security.patterns import pattern


_STRICT_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", re.I),
    re.compile(r"(disregard|forget)\s+(all\s+)?(previous|prior|above)", re.I),
    re.compile(r"(忽略|无视)(之前|以上|上述|全部).{0,16}(指令|提示|规则|约束)"),
    re.compile(r"(jailbreak|越狱|开发者模式|developer\s*mode)", re.I),
    re.compile(r"(reveal|print|show|泄露|输出).{0,40}(system\s*prompt|系统提示词|系统指令)", re.I),
    re.compile(r"(绕过|bypass).{0,24}(安全|防护|guardrail|content\s+policy)", re.I),
]

_OBSERVATION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)", re.I),
    re.compile(r"(disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)", re.I),
    re.compile(r"忽略(之前|以上|上述).{0,12}(指令|提示|规则)"),
    re.compile(r"<\s*/?\s*(system|hidden|instructions)\s*>", re.I),
    re.compile(r"(curl|wget).{0,80}\|\s*(sh|bash|powershell)\b", re.I),
]

_SECRET_ASSIGN = re.compile(
    r"(api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*['\"]?[\w\-@#$%^&*!]{6,}",
    re.I,
)
_SK = re.compile(r"\bsk-[A-Za-z0-9\-_]{10,}\b")
_AWS = re.compile(r"\bAKIA[A-Z0-9]{16}\b")
_GHP = re.compile(r"\bghp_[A-Za-z0-9_]{20,}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]{20,}\b")

_CANON = {
    "read_file": "read",
    "write_file": "write",
    "list_dir": "ls",
    "str_replace": "edit",
    "run_command": "bash",
    "search_text": "grep",
    "glob_files": "find",
}
_PATH_TOOLS = {"read", "write", "edit", "ls", "grep", "find"}
_WORKSPACE_ESCAPE = re.compile(
    r"(~[/\\]|/tmp\b|/home\b|/Users\b|Documents[/\\]Private|[A-Za-z]:[/\\](?:Users|Windows|tmp)\b)",
    re.I,
)
_READONLY = {
    "read",
    "ls",
    "grep",
    "find",
    "get_time",
    "echo",
    "pwned_check",
    "none",
}


@dataclass
class RailDecision:
    action: str
    rail: str
    reason: str = ""
    text: str = ""
    elapsed_ms: float = 0.0


@dataclass
class GuardrailSession:
    profile: str = "coding"
    workspace: Path | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    timings_ms: list[float] = field(default_factory=list)
    saw_secret: bool = False
    pending_taint: bool = False
    user_text: str = ""
    trace_steps: list[dict[str, Any]] = field(default_factory=list)
    _seen_user: str | None = None
    input_blocked_reason: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.workspace, str):
            self.workspace = Path(self.workspace)
        if self.workspace is not None:
            self.workspace = self.workspace.resolve()

    def record_user(self, text: str) -> None:
        self.user_text = text
        self.trace_steps.append({"kind": "user", "text": text[:2000]})

    def note_user(self, text: str) -> RailDecision:
        if text == self._seen_user:
            return RailDecision("allow", "input", "unchanged")
        self.pending_taint = False
        self.input_blocked_reason = ""
        self._seen_user = text
        self.record_user(text)
        decision = self._timed("input", lambda: self._check_input(text))
        if decision.action == "block":
            self.input_blocked_reason = decision.reason
        return decision

    def on_tool(self, name: str, args: dict[str, Any] | None) -> RailDecision:
        args = args if isinstance(args, dict) else {}
        return self._timed("pre_tool", lambda: self._check_tool(name, args))

    def on_observation(self, name: str, text: str) -> RailDecision:
        return self._timed("observation", lambda: self._check_observation(name, text))

    def on_output(self, text: str) -> RailDecision:
        return self._timed("output", lambda: self._check_output(text))

    def _timed(self, rail: str, fn) -> RailDecision:
        start = time.perf_counter()
        decision = fn()
        elapsed = (time.perf_counter() - start) * 1000
        decision.elapsed_ms = elapsed
        decision.rail = decision.rail or rail
        self.timings_ms.append(elapsed)
        self.events.append(
            {
                "rail": decision.rail,
                "action": decision.action,
                "reason": decision.reason,
                "elapsed_ms": round(elapsed, 3),
            }
        )
        return decision

    def _check_input(self, text: str) -> RailDecision:
        strict = _strict_hit(text)
        if self.profile == "chat":
            legacy = detect_injection(text)
            if legacy.get("blocked") or strict:
                reason = ",".join(legacy.get("reasons") or []) or "strict_injection"
                return RailDecision("block", "input", reason, text=text)
            return RailDecision("allow", "input", text=text)
        if strict or _strict_hit(_decoded_snippets(text)):
            return RailDecision("block", "input", "strict_injection", text=text)
        verdict = assess(text, "input")
        if verdict.blocked:
            return RailDecision("block", "input", verdict.reason, text=text)
        from security.context_guard import judge_prompt

        context_label, context_reason = judge_prompt(text)
        if context_label == "unsafe":
            return RailDecision("block", "input", context_reason or "context_guard", text=text)
        return RailDecision("allow", "input", text=text)

    def _check_tool(self, name: str, args: dict[str, Any]) -> RailDecision:
        if self.input_blocked_reason:
            return RailDecision("block", "input", self.input_blocked_reason)

        canon = _CANON.get(name, name)
        path = str(args.get("path") or "")

        if canon in _PATH_TOOLS and path:
            path_reason = _path_block_reason(path, self.workspace)
            if path_reason:
                return RailDecision("block", "pre_tool", path_reason)

        if canon == "bash":
            if args.get("allow_dangerous") is True:
                return RailDecision("block", "pre_tool", "policy_bypass")
            cwd = args.get("cwd")
            if isinstance(cwd, str) and cwd.strip():
                cwd_reason = _path_block_reason(cwd, self.workspace)
                if cwd_reason:
                    return RailDecision("block", "pre_tool", cwd_reason)
            command = _command_blob(_command_text(args))
            if pattern("destructive_command").search(command) or pattern("pipe_to_shell").search(command):
                return RailDecision("block", "pre_tool", "dangerous_command")
            if pattern("sensitive_file_read").search(command):
                return RailDecision("block", "pre_tool", "sensitive_file_read")
            secretish = bool(pattern("sensitive_path").search(command)) or ".env" in command.lower()
            if secretish and not pattern("network_command").search(command):
                return RailDecision("block", "pre_tool", "sensitive_path")
            if pattern("network_command").search(command) and (self.saw_secret or secretish):
                return RailDecision("block", "trajectory", "secret_exfil")
            if _WORKSPACE_ESCAPE.search(command):
                return RailDecision("block", "pre_tool", "workspace_escape")

        if self.pending_taint and canon not in _READONLY:
            return RailDecision("block", "trajectory", "tainted_observation")

        has_context = any(step.get("kind") in {"user", "observation"} for step in self.trace_steps)
        if has_context:
            blocked, reason = review_trajectory(self.trace_steps, canon, args)
            if blocked:
                return RailDecision("block", "trajectory", reason)

        inspected = " ".join(part for part in (canon, path, _command_text(args)) if part)
        verdict = assess(inspected, "pre_tool", tool=canon)
        if verdict.blocked:
            return RailDecision("block", "pre_tool", verdict.reason)
        self.trace_steps.append({"kind": "tool", "name": canon, "args": args})
        return RailDecision("allow", "pre_tool")

    def _check_observation(self, name: str, text: str) -> RailDecision:
        _ = name
        if not text:
            return RailDecision("allow", "observation", text=text)
        from security.normalize import scan_forms

        forms = scan_forms(text)
        if any(_pattern_hit(_OBSERVATION_PATTERNS, form) for form in forms):
            self.pending_taint = True
            return RailDecision("quarantine", "observation", "indirect_injection", text=_quarantine("indirect_injection"))
        rewrite_label, rewrite_reason = "safe", ""
        for form in forms:
            rewrite_label, rewrite_reason = judge_prompt(form)
            if rewrite_label == "unsafe":
                break
        if rewrite_label == "unsafe":
            self.pending_taint = True
            self.trace_steps.append({"kind": "observation", "text": text[:1500]})
            return RailDecision(
                "quarantine",
                "observation",
                rewrite_reason or "prompt_rewrite",
                text=_quarantine(rewrite_reason or "prompt_rewrite"),
            )
        if any(injected_goal(form) and not user_already_asked(self.user_text, form) for form in forms):
            self.pending_taint = True
            self.trace_steps.append({"kind": "observation", "text": text[:1500]})
            return RailDecision("quarantine", "observation", "injected_goal", text=_quarantine("injected_goal"))
        if self.profile == "coding":
            redacted = _redact_secrets(text)
        else:
            redacted = filter_output(text)
        if redacted != text:
            self.saw_secret = True
            self.trace_steps.append({"kind": "observation", "text": redacted[:1500]})
            return RailDecision("redact", "observation", "secret_redaction", text=redacted)
        verdict = assess(text[:4000], "observation")
        if verdict.blocked:
            self.pending_taint = True
            self.trace_steps.append({"kind": "observation", "text": text[:1500]})
            return RailDecision("quarantine", "observation", verdict.reason, text=_quarantine(verdict.reason))
        self.trace_steps.append({"kind": "observation", "text": text[:1500]})
        return RailDecision("allow", "observation", text=text)

    def _check_output(self, text: str) -> RailDecision:
        if self.profile == "coding":
            redacted = _redact_secrets(text)
        else:
            redacted = filter_output(text)
        verdict = assess(redacted, "output")
        if verdict.blocked:
            return RailDecision("block", "output", verdict.reason, text="[Blocked] Unsafe model output")
        if redacted != text:
            return RailDecision("redact", "output", "secret_redaction", text=redacted)
        return RailDecision("allow", "output", text=text)


def quarantine_observation(text: str, profile: str = "chat") -> tuple[str, str]:
    """One-shot observation rail for Sec_Agent's single tool return."""
    decision = GuardrailSession(profile=profile).on_observation("tool", text or "")
    if decision.action in {"quarantine", "redact"}:
        return decision.text, decision.reason
    return text, ""


def _quarantine(reason: str) -> str:
    return (
        f"[UNTRUSTED_TOOL_OUTPUT quarantined reason={reason}]\n"
        "Tool output contained instruction-like content and was withheld."
    )


def _strict_hit(text: str) -> bool:
    from security.normalize import scan_forms

    for form in scan_forms(text):
        if _pattern_hit(_STRICT_PATTERNS, form):
            return True
        lowered = form.lower()
        if any(token in lowered for token in ("ignore previous", "ignore all previous", "jailbreak", "越狱")):
            return True
    return False


def _pattern_hit(patterns: list[re.Pattern[str]], text: str) -> bool:
    return any(rx.search(text) for rx in patterns)


def _unsafe_path(path: str) -> bool:
    if "\x00" in path:
        return True
    normalized = path.replace("\\", "/")
    if _looks_host_absolute(normalized):
        return True
    return ".." in normalized.split("/")


def _looks_host_absolute(normalized: str) -> bool:
    if normalized.startswith("/"):
        return True
    return len(normalized) > 2 and normalized[1] == ":"


def _path_block_reason(path: str, workspace: Path | None) -> str | None:
    """Block escapes and secret files.

    Without a workspace, absolute paths and `..` are rejected outright.
    With a workspace, a path is allowed only when it resolves inside that root.
    """
    if not isinstance(path, str) or "\x00" in path:
        return "unsafe_path"
    normalized = path.replace("\\", "/")
    if not normalized.strip():
        return None
    sensitive = bool(pattern("sensitive_path").search(normalized))
    if workspace is None:
        if _unsafe_path(path):
            return "unsafe_path"
        if sensitive:
            return "sensitive_path"
        return None
    if _looks_host_absolute(normalized):
        try:
            target = Path(path).resolve()
            rel = target.relative_to(workspace).as_posix()
        except (OSError, ValueError):
            return "unsafe_path"
        if sensitive or pattern("sensitive_path").search("/" + rel):
            return "sensitive_path"
        return None
    if sensitive:
        return "sensitive_path"
    try:
        target = (workspace / path).resolve()
        rel = target.relative_to(workspace).as_posix()
    except (OSError, ValueError):
        return "unsafe_path"
    if pattern("sensitive_path").search("/" + rel):
        return "sensitive_path"
    return None


def _decoded_snippets(text: str) -> str:
    chunks: list[str] = []
    for item in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text or "")[:5]:
        padded = item + ("=" * ((4 - len(item) % 4) % 4))
        try:
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
        except (ValueError, UnicodeError):
            continue
        if decoded and any(ch.isalpha() for ch in decoded):
            chunks.append(decoded)
    return "\n".join(chunks)


def _command_blob(command: str) -> str:
    decoded = _decoded_snippets(command)
    if not decoded:
        return command
    return command + "\n" + decoded


def _command_text(args: dict[str, Any]) -> str:
    command = args.get("command")
    if isinstance(command, str) and command.strip():
        return command
    argv = args.get("argv")
    if isinstance(argv, list):
        return " ".join(str(part) for part in argv)
    return ""


def _redact_secrets(text: str) -> str:
    text = _SK.sub("[REDACTED_SECRET]", text)
    text = _AWS.sub("[REDACTED_AWS_KEY]", text)
    text = _GHP.sub("[REDACTED_GITHUB_TOKEN]", text)
    text = _JWT.sub("[REDACTED_JWT]", text)
    text = _SECRET_ASSIGN.sub("[REDACTED_CREDENTIAL]", text)
    return text
