"""Undo cheap obfuscation before rules and the word classifier.

Case folding, fullwidth characters, zero-width marks, homoglyphs, letters
split by spaces or dots, and encoded payloads are recovered into text the
existing heads can score. This does not invent new attack content.
"""

from __future__ import annotations

import base64
import re
import unicodedata
import urllib.parse


_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]")
_SPACED = re.compile(r"(?:[A-Za-z]\s+){5,}[A-Za-z]")
_DOTTED = re.compile(r"(?:[A-Za-z][.\-_])+[A-Za-z]")
_PERCENT = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_HEX_ESCAPE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}")
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "А": "A",
        "Е": "E",
        "О": "O",
        "Р": "P",
        "С": "C",
        "і": "i",
        "І": "I",
        "ѕ": "s",
        "һ": "h",
    }
)


def fold(text: str) -> str:
    folded = unicodedata.normalize("NFKC", str(text or ""))
    folded = _ZERO_WIDTH.sub("", folded)
    letters = [char for char in folded if char.isalpha()]
    cyrillic = sum(1 for char in letters if "\u0400" <= char <= "\u04ff")
    if letters and cyrillic / len(letters) < 0.3:
        folded = folded.translate(_HOMOGLYPHS)
    return folded


def _join_run(match: re.Match[str]) -> str:
    return re.sub(r"[\s.\-_]+", "", match.group(0))


def collapse_separators(text: str) -> str:
    collapsed = _SPACED.sub(_join_run, text)
    return _DOTTED.sub(_join_run, collapsed)


def recover(text: str) -> str:
    """Text the word classifier should see."""
    return collapse_separators(fold(text))


def looks_obfuscated(text: str) -> bool:
    raw = str(text or "")
    if _ZERO_WIDTH.search(raw) or _PERCENT.search(raw) or _HEX_ESCAPE.search(raw):
        return True
    if _SPACED.search(raw) or _DOTTED.search(raw):
        return True
    letters = [char for char in raw if char.isalpha()]
    if len(letters) >= 8:
        flips = sum(1 for left, right in zip(letters, letters[1:]) if left.isupper() != right.isupper())
        if flips >= len(letters) * 0.45:
            return True
    return False


def _sentence(text: str) -> bool:
    letters = sum(1 for char in text if char.isalpha() or "\u4e00" <= char <= "\u9fff")
    return letters >= 8 and (" " in text or any("\u4e00" <= char <= "\u9fff" for char in text))


def hidden_payloads(text: str) -> list[str]:
    raw = str(text or "")
    found: list[str] = []
    if _PERCENT.search(raw):
        decoded = urllib.parse.unquote(raw)
        if decoded != raw and _sentence(decoded):
            found.append(decoded)
    if _HEX_ESCAPE.search(raw) or "\\u" in raw:
        try:
            decoded = raw.encode("utf-8").decode("unicode_escape")
        except UnicodeError:
            decoded = ""
        if decoded and decoded != raw and _sentence(decoded):
            found.append(decoded)
    for item in _B64.findall(raw)[:3]:
        padded = item + ("=" * ((4 - len(item) % 4) % 4))
        try:
            decoded = base64.b64decode(padded, validate=False).decode("utf-8")
        except (ValueError, UnicodeError):
            continue
        if _sentence(decoded):
            found.append(decoded)
    unique: list[str] = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique


def scan_forms(text: str) -> list[str]:
    """Original text plus recovered and decoded forms, for rule checks."""
    raw = str(text or "")
    forms: list[str] = []
    for item in (raw, fold(raw), recover(raw)):
        if item and item not in forms:
            forms.append(item)
    for payload in hidden_payloads(raw):
        restored = recover(payload)
        if restored not in forms:
            forms.append(restored)
    return forms[:6]
