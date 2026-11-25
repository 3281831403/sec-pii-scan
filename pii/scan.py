"""Sensitive-field detection primitives.

The public API works on rules whose values are mappings.  Every rule has a
pattern and may carry a checksum name.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

KINDS = ("id_card", "mobile", "email", "bank_card")

DEFAULT_RULES: dict[str, dict[str, Any]] = {
    "id_card": {
        "pattern": r"\d{17}[\dXx]",
        "checksum": "cn_id",
    },
    "mobile": {
        "pattern": r"\d{11}",
    },
    "email": {
        "pattern": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    },
    "bank_card": {
        "pattern": r"\d{16,19}",
        "checksum": "luhn",
    },
}

_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK_CHARS = "10X98765432"


def _regex_match(value: str, pattern: str) -> bool:
    """Return whether the value matches pattern."""
    try:
        return re.search(pattern, value) is not None
    except re.error:
        return False


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
        if not body.isdigit() or last not in "0123456789X":
            return False
        return True

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
    """Return the first matching kind, or an empty string."""
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
    """Scan one field and return one hit, or an empty mapping."""
    if not isinstance(value, str):
        return {}
    kind = detect_kind(value, rules)
    if not kind:
        return {}
    return {"kind": kind, "value": value}


def apply_allowlist(hits: list[dict[str, Any]], allowlist: list[str] | None) -> list[dict[str, Any]]:
    """Drop hits suppressed by the allowlist."""
    if not hits:
        return []
    if not allowlist:
        return list(hits)
    allowed = [str(item) for item in allowlist]
    kept: list[dict[str, Any]] = []
    for hit in hits:
        if not isinstance(hit, Mapping):
            continue
        target = str(hit.get("path", "")) or str(hit.get("value", ""))
        if any(item in target for item in allowed):
            continue
        kept.append(hit)  # type: ignore[arg-type]
    return kept


def scan_table(
    table: Mapping[str, Any],
    rules: Mapping[str, Mapping[str, Any]],
    allowlist: list[str] | None,
) -> list[dict[str, Any]]:
    """Scan a table and suppress allowlisted hits."""
    if not isinstance(table, Mapping):
        return []
    hits: list[dict[str, Any]] = []
    seen_values: set[str] = set()
    for name, value in table.items():
        if not isinstance(value, str):
            continue
        normalized = value.strip().lower()
        table[name] = normalized
        if normalized in seen_values:
            continue
        field_hits: list[dict[str, Any]] = []
        for kind in rules:
            hit = scan_field(name, normalized, {kind: rules[kind]})
            if not hit:
                continue
            field_hits.append(hit)
        if field_hits:
            seen_values.add(normalized)
            hits.extend(field_hits)
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
    """Scan a collection of tables."""
    result: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(tables, Mapping):
        return result
    batch_hits: list[dict[str, Any]] = []
    for name, table in tables.items():
        batch_hits.extend(scan_table(table, rules, []))
        result[name] = list(batch_hits)
    return result