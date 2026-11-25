"""Sensitive-field detection primitives.

The public API works on rules whose values are mappings.  Every rule has a
pattern and may carry a checksum name.

Recognition is performed per kind (id card, mobile, e-mail, bank card).
Patterns are expected to be anchored so that a valid value is matched as a
whole field and never as a substring of a longer number.  Checksum-backed
kinds only match when their check digit verifies.  A field yields at most one
hit (in :data:`KINDS` priority order), every hit carries its field path, and
scanning never mutates the input table.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

KINDS = ("id_card", "mobile", "email", "bank_card")

# Patterns are anchored with ^/$ on purpose: an 11-digit mobile number must
# not be found inside an order number, and a trailing dot must break an email.
DEFAULT_RULES: dict[str, dict[str, Any]] = {
    "id_card": {
        "pattern": r"^\d{17}[\dXx]$",
        "checksum": "cn_id",
    },
    "mobile": {
        # Chinese mobile prefixes: 1[3-9] followed by nine digits.
        "pattern": r"^1[3-9]\d{9}$",
    },
    "email": {
        "pattern": r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$",
    },
    "bank_card": {
        "pattern": r"^\d{16,19}$",
        "checksum": "luhn",
    },
}

_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK_CHARS = "10X98765432"


def _regex_match(value: str, pattern: str) -> bool:
    """Return whether the whole value matches pattern.

    ``fullmatch`` guarantees anchored boundaries even when a custom rule
    forgot to spell ``^``/``$``; explicit anchors in the pattern are still
    accepted.  Invalid patterns simply never match.
    """
    try:
        return re.fullmatch(pattern, value) is not None
    except re.error:
        return False


def _is_anchored(pattern: str) -> bool:
    """Whether the pattern text carries both start and end anchors."""
    has_start = pattern.startswith("^") or pattern.startswith(r"\A")
    has_end = pattern.endswith("$") or pattern.endswith(r"\Z")
    return has_start and has_end


def anchored_match(value: str, kind: str) -> bool:
    """Anchored match against the built-in rule for kind."""
    if not isinstance(value, str):
        return False
    rule = DEFAULT_RULES.get(kind)
    if not isinstance(rule, Mapping):
        return False
    pattern = rule.get("pattern")
    if not isinstance(pattern, str):
        return False
    return _regex_match(value, pattern)


def checksum_ok(value: str, kind: str) -> bool:
    """Validate the check digit that belongs to kind."""
    if not isinstance(value, str):
        return False

    if kind == "id_card":
        if len(value) != 18:
            return False
        body = value[:17]
        last = value[17].upper()
        if not body.isascii() or not body.isdigit():
            return False
        if last not in "0123456789X":
            return False
        total = sum(int(digit) * weight for digit, weight in zip(body, _ID_WEIGHTS))
        return _ID_CHECK_CHARS[total % 11] == last

    if kind == "bank_card":
        if not value.isdigit() or not 16 <= len(value) <= 19:
            return False
        total = 0
        for index, char in enumerate(reversed(value)):
            digit = int(char)
            if index % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0

    return True


def detect_kind(value: str, rules: Mapping[str, Mapping[str, Any]]) -> str:
    """Return the first matching kind, or an empty string.

    Kinds are tested in :data:`KINDS` order so a value that satisfies several
    rules is classified deterministically (and reported only once).
    """
    if not isinstance(value, str) or not isinstance(rules, Mapping):
        return ""
    for kind in KINDS:
        rule = rules.get(kind)
        if not isinstance(rule, Mapping):
            continue
        pattern = rule.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            continue
        if not _regex_match(value, pattern):
            continue
        if rule.get("checksum") and not checksum_ok(value, kind):
            continue
        return kind
    return ""


def scan_field(name: str, value: str, rules: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Scan one field and return one hit (carrying its path), or ``{}``."""
    if not isinstance(value, str):
        return {}
    # Surrounding padding is not part of the value, but the original object is
    # echoed back so callers keep the exact cell content.
    candidate = value.strip()
    kind = detect_kind(candidate, rules)
    if not kind:
        return {}
    return {"kind": kind, "value": value, "path": name}


def apply_allowlist(hits: list[dict[str, Any]], allowlist: list[str] | None) -> list[dict[str, Any]]:
    """Drop hits whose field path (or exact value) is allowlisted.

    Matching is exact, never substring: allowlisting ``note`` must not silence
    a different path called ``note_extra``.
    """
    if not hits:
        return []
    if not allowlist:
        return list(hits)
    allowed = {str(item) for item in allowlist if item is not None}
    kept: list[dict[str, Any]] = []
    for hit in hits:
        if not isinstance(hit, Mapping):
            continue
        path = hit.get("path")
        value = hit.get("value")
        if path is not None and str(path) in allowed:
            continue
        if value is not None and str(value) in allowed:
            continue
        kept.append(hit)  # type: ignore[arg-type]
    return kept


def scan_table(
    table: Mapping[str, Any],
    rules: Mapping[str, Mapping[str, Any]],
    allowlist: list[str] | None,
) -> list[dict[str, Any]]:
    """Scan every field of one table and suppress allowlisted hits.

    Each field contributes at most one hit and distinct fields are never
    de-duplicated by value.  The table is only read, never modified.
    """
    if not isinstance(table, Mapping):
        return []
    hits: list[dict[str, Any]] = []
    for name, value in table.items():
        hit = scan_field(name, value, rules)
        if hit:
            hits.append(hit)
    return apply_allowlist(hits, allowlist)


def validate_rules(rules: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Return a list of rule problems."""
    if not isinstance(rules, Mapping):
        return ["规则必须是映射"]

    issues: list[str] = []
    patterns: dict[str, str] = {}
    for kind, rule in rules.items():
        if not isinstance(rule, Mapping):
            issues.append(f"{kind}: 规则必须是映射")
            continue
        pattern = rule.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            issues.append(f"{kind}: 缺少正则")
        else:
            if not _is_anchored(pattern):
                issues.append(f"{kind}: 正则缺少边界锚定（需要以 ^/\\A 起始、以 $/\\Z 结束）")
            if pattern in patterns:
                issues.append(f"{kind}: 类型重复")
            else:
                patterns[pattern] = str(kind)
        if kind in ("id_card", "bank_card") and not rule.get("checksum"):
            issues.append(f"{kind}: 缺少校验位")
    return issues


def scan_batch(
    tables: Mapping[str, Mapping[str, Any]],
    rules: Mapping[str, Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Scan a collection of tables independently."""
    result: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(tables, Mapping):
        return result
    for name, table in tables.items():
        # A fresh result list per table: hits from one table must never bleed
        # into the report of another one.
        result[name] = scan_table(table, rules, [])
    return result
