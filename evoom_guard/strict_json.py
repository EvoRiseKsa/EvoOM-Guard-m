"""Bounded, unambiguous JSON decoding shared by offline evidence consumers."""

from __future__ import annotations

import json
import math
from typing import Any

MAX_JSON_DEPTH = 256
MAX_JSON_INTEGER_DIGITS = 128
MAX_JSON_NUMBER_CHARS = 256


def _check_nesting(text: str) -> None:
    """Reject excessive object/array nesting before the recursive decoder runs."""

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError(
                    f"JSON nesting exceeds the {MAX_JSON_DEPTH}-level parser limit"
                )
        elif character in "]}":
            depth -= 1


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def _bounded_float(value: str) -> float:
    if len(value) > MAX_JSON_NUMBER_CHARS:
        raise ValueError(
            f"JSON number exceeds the {MAX_JSON_NUMBER_CHARS}-character parser limit"
        )
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number is not permitted: {value}")
    return parsed


def _bounded_int(value: str) -> int:
    if len(value.lstrip("-")) > MAX_JSON_INTEGER_DIGITS:
        raise ValueError(
            f"JSON integer exceeds the {MAX_JSON_INTEGER_DIGITS}-digit parser limit"
        )
    return int(value)


def _reject_unpaired_surrogates(value: object) -> None:
    """Ensure every decoded string is valid scalar Unicode/UTF-8."""

    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("JSON contains an unpaired Unicode surrogate") from exc
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def strict_json_loads(text: str) -> object:
    """Decode strict JSON under explicit numeric and nesting limits.

    The decoder rejects duplicate keys, Python's NaN/Infinity extensions,
    numeric literals too large for evidence records, excessive nesting, and
    unpaired Unicode surrogates. It raises ``ValueError`` for every rejected
    document so CLI/API consumers can fail closed without parser tracebacks.
    """

    if not isinstance(text, str):
        raise TypeError(f"JSON input must be str, got {type(text).__name__}")
    _check_nesting(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_bounded_float,
            parse_int=_bounded_int,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the safe parser depth") from exc
    _reject_unpaired_surrogates(value)
    return value
