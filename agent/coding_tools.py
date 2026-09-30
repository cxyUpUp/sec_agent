"""Sandboxed coding tools for the secure agent.

All filesystem access is confined to SEC_AGENT_WORKSPACE (default: project root).
Command execution uses argv lists only (no shell) with a small binary allowlist.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = Path(
    os.environ.get("SEC_AGENT_WORKSPACE") or str(_PROJECT_ROOT)
).resolve()

MAX_READ_BYTES = 200_000
MAX_WRITE_CHARS = 100_000
MAX_LIST_ENTRIES = 500
MAX_SEARCH_MATCHES = 50
MAX_GLOB_RESULTS = 200
MAX_COMMAND_OUTPUT = 20_000
COMMAND_TIMEOUT_S = 15

ALLOWED_BINARIES = {
    "python",
    "python3",
    "py",
    "git",
}
GIT_ALLOWED_SUBCOMMANDS = {
    "status",
    "log",
    "diff",
    "show",
    "branch",
    "rev-parse",
    "ls-files",
}
SHELL_META_RE = re.compile(r"[;&|`$<>\n\r]")


def _err(msg: str) -> str:
    return f"[Error] {msg}"


def resolve_workspace_path(path: str) -> Path:
    if not isinstance(path, str) or not path.strip():
        raise ValueError("path must be a non-empty string")
    raw = path.strip()
    if "\x00" in raw:
        raise ValueError("path contains null byte")
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = WORKSPACE_ROOT / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(WORKSPACE_ROOT)
    except ValueError as exc:
        raise ValueError("path escapes workspace") from exc
    return resolved


def list_dir(path: str = ".") -> str:
    try:
        target = resolve_workspace_path(path)
    except ValueError as exc:
        return _err(str(exc))
    if not target.exists():
        return _err("directory not found")
    if not target.is_dir():
        return _err("path is not a directory")

    entries: list[str] = []
    try:
        children = sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except OSError as exc:
        return _err(f"cannot list directory: {exc}")

    for child in children[:MAX_LIST_ENTRIES]:
        kind = "dir" if child.is_dir() else "file"
        rel = child.relative_to(WORKSPACE_ROOT).as_posix()
        entries.append(f"{kind}\t{rel}")
    if len(children) > MAX_LIST_ENTRIES:
        entries.append(f"... truncated ({len(children) - MAX_LIST_ENTRIES} more)")
    return "\n".join(entries) if entries else "(empty)"


def read_file(path: str, offset: int = 1, limit: int = 200) -> str:
    try:
        target = resolve_workspace_path(path)
    except ValueError as exc:
        return _err(str(exc))
    if not target.exists():
        return _err("file not found")
    if not target.is_file():
        return _err("path is not a file")
    if not isinstance(offset, int) or offset < 1:
        return _err("offset must be an integer >= 1")
    if not isinstance(limit, int) or limit < 1 or limit > 2000:
        return _err("limit must be an integer in [1, 2000]")

    try:
        raw = target.read_bytes()
    except OSError as exc:
        return _err(f"cannot read file: {exc}")
    if len(raw) > MAX_READ_BYTES:
        raw = raw[:MAX_READ_BYTES]
        truncated = True
    else:
        truncated = False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _err("file is not valid utf-8 text")

    lines = text.splitlines()
    start = offset - 1
    chunk = lines[start : start + limit]
    numbered = [f"{i + offset}|{line}" for i, line in enumerate(chunk)]
    footer = []
    if start + limit < len(lines):
        footer.append(f"... {len(lines) - (start + limit)} more lines")
    if truncated:
        footer.append(f"... file truncated at {MAX_READ_BYTES} bytes")
    return "\n".join(numbered + footer) if numbered else "(empty file range)"


def write_file(path: str, content: str) -> str:
    try:
        target = resolve_workspace_path(path)
    except ValueError as exc:
        return _err(str(exc))
    if not isinstance(content, str):
        return _err("content must be a string")
    if len(content) > MAX_WRITE_CHARS:
        return _err(f"content too long (>{MAX_WRITE_CHARS})")
    if target.exists() and target.is_dir():
        return _err("path is a directory")

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
    except OSError as exc:
        return _err(f"cannot write file: {exc}")
    rel = target.relative_to(WORKSPACE_ROOT).as_posix()
    return f"[OK] wrote {len(content)} chars to {rel}"


def str_replace(path: str, old_string: str, new_string: str) -> str:
    try:
        target = resolve_workspace_path(path)
    except ValueError as exc:
        return _err(str(exc))
    if not target.exists() or not target.is_file():
        return _err("file not found")
    if not isinstance(old_string, str) or not old_string:
        return _err("old_string must be a non-empty string")
    if not isinstance(new_string, str):
        return _err("new_string must be a string")
    if len(new_string) > MAX_WRITE_CHARS:
        return _err(f"new_string too long (>{MAX_WRITE_CHARS})")

    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return _err(f"cannot read file: {exc}")

    count = text.count(old_string)
    if count == 0:
        return _err("old_string not found")
    if count > 1:
        return _err(f"old_string is not unique ({count} matches)")
    updated = text.replace(old_string, new_string, 1)
    if len(updated) > MAX_WRITE_CHARS:
        return _err(f"result too long (>{MAX_WRITE_CHARS})")
    try:
        target.write_text(updated, encoding="utf-8", newline="\n")
    except OSError as exc:
        return _err(f"cannot write file: {exc}")
    rel = target.relative_to(WORKSPACE_ROOT).as_posix()
    return f"[OK] replaced 1 occurrence in {rel}"


def search_text(pattern: str, path: str = ".", glob: str = "*.py") -> str:
    if not isinstance(pattern, str) or not pattern:
        return _err("pattern must be a non-empty string")
    if len(pattern) > 200:
        return _err("pattern too long (>200)")
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return _err(f"invalid regex: {exc}")

    try:
        root = resolve_workspace_path(path)
    except ValueError as exc:
        return _err(str(exc))
    if not root.exists():
        return _err("search root not found")

    matches: list[str] = []
    files = [root] if root.is_file() else sorted(root.rglob(glob if glob else "*"))
    for file_path in files:
        if not file_path.is_file():
            continue
        try:
            if file_path.stat().st_size > MAX_READ_BYTES:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = file_path.relative_to(WORKSPACE_ROOT).as_posix()
        for i, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                matches.append(f"{rel}:{i}:{line[:300]}")
                if len(matches) >= MAX_SEARCH_MATCHES:
                    matches.append("... truncated")
                    return "\n".join(matches)
    return "\n".join(matches) if matches else "(no matches)"


def glob_files(pattern: str = "**/*", path: str = ".") -> str:
    if not isinstance(pattern, str) or not pattern.strip():
        return _err("pattern must be a non-empty string")
    if len(pattern) > 200:
        return _err("pattern too long (>200)")
    try:
        root = resolve_workspace_path(path)
    except ValueError as exc:
        return _err(str(exc))
    if not root.exists() or not root.is_dir():
        return _err("path is not a directory")

    hits = sorted(p for p in root.glob(pattern) if p.is_file())
    lines = [p.relative_to(WORKSPACE_ROOT).as_posix() for p in hits[:MAX_GLOB_RESULTS]]
    if len(hits) > MAX_GLOB_RESULTS:
        lines.append(f"... truncated ({len(hits) - MAX_GLOB_RESULTS} more)")
    return "\n".join(lines) if lines else "(no files)"


def _validate_argv(argv: list[Any]) -> str | None:
    if not isinstance(argv, list) or not argv:
        return "argv must be a non-empty list"
    if len(argv) > 32:
        return "argv too long (>32)"
    if not all(isinstance(x, str) for x in argv):
        return "argv items must be strings"
    if any(len(x) > 500 for x in argv):
        return "argv item too long (>500)"
    if any(SHELL_META_RE.search(x) for x in argv):
        return "argv contains shell metacharacters"
    binary = Path(argv[0]).name.lower()
    if binary.endswith(".exe"):
        binary = binary[:-4]
    if binary not in ALLOWED_BINARIES:
        return f"binary not allowlisted: {binary}"
    if binary == "git":
        if len(argv) < 2 or argv[1] not in GIT_ALLOWED_SUBCOMMANDS:
            return "git subcommand not allowlisted"
    return None


def run_command(argv: list[str], timeout_s: int = COMMAND_TIMEOUT_S) -> str:
    err = _validate_argv(argv)
    if err:
        return _err(err)
    if not isinstance(timeout_s, int) or timeout_s < 1 or timeout_s > COMMAND_TIMEOUT_S:
        return _err(f"timeout_s must be in [1, {COMMAND_TIMEOUT_S}]")

    try:
        proc = subprocess.run(
            argv,
            cwd=str(WORKSPACE_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            shell=False,
            env={
                "PATH": os.environ.get("PATH", ""),
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                "LANG": "C.UTF-8",
                "PYTHONIOENCODING": "utf-8",
            },
        )
    except subprocess.TimeoutExpired:
        return _err(f"command timed out after {timeout_s}s")
    except OSError as exc:
        return _err(f"failed to start command: {exc}")

    out = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    if len(out) > MAX_COMMAND_OUTPUT:
        out = out[:MAX_COMMAND_OUTPUT] + "\n... truncated"
    return f"exit={proc.returncode}\n{out}".rstrip()
