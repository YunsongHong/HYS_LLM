"""Small, strict canonical-JSON boundary for durable command identities.

This is intentionally narrower than general JSON.  ParamGuard persistence
records contain identifiers, strings, Booleans, nulls, lists, mappings and
signed 64-bit integers; floating point values are not part of the contract.
Keeping that narrow contract avoids multiple spellings of the same command
and makes duplicate-key or non-finite-number attacks fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import TypeAlias


JsonScalar: TypeAlias = None | bool | int | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

MAX_JSON_DEPTH = 64
MAX_JSON_ITEMS = 100_000
MAX_JSON_TEXT_BYTES = 8 * 1024 * 1024
MIN_SIGNED_INT64 = -(2**63)
MAX_SIGNED_INT64 = 2**63 - 1


class CanonicalJsonError(ValueError):
    """Base class for rejected or non-canonical JSON data."""


class DuplicateJsonKeyError(CanonicalJsonError):
    """A JSON object repeated a member name."""


class UnknownJsonKeyError(CanonicalJsonError):
    """A schema-bound top-level object contained an unknown member."""


class MissingJsonKeyError(CanonicalJsonError):
    """A schema-bound top-level object omitted a required member."""


@dataclass(frozen=True, slots=True)
class CanonicalJsonDocument:
    """Validated data together with its re-encoded identity."""

    value: JsonValue
    text: str
    sha256: str


def _reject_constant(token: str) -> None:
    raise CanonicalJsonError(f"Non-finite JSON number is forbidden: {token}")


def _reject_float(token: str) -> None:
    raise CanonicalJsonError(
        f"Floating-point JSON numbers are outside this persistence contract: {token}"
    )


def _pairs_without_duplicates(
    pairs: list[tuple[str, JsonValue]],
) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _validate_value(value: object, *, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise CanonicalJsonError(
            f"JSON nesting exceeds the {MAX_JSON_DEPTH}-level limit"
        )
    value_type = type(value)
    if value is None or value_type is bool or value_type is str:
        return 1
    if value_type is int:
        if value < MIN_SIGNED_INT64 or value > MAX_SIGNED_INT64:
            raise CanonicalJsonError("JSON integer must fit a signed 64-bit value")
        return 1
    if value_type is list:
        count = 1
        for item in value:
            count += _validate_value(item, depth=depth + 1)
            if count > MAX_JSON_ITEMS:
                raise CanonicalJsonError(
                    f"JSON document exceeds the {MAX_JSON_ITEMS}-item limit"
                )
        return count
    if value_type is dict:
        count = 1
        for key, item in value.items():
            if type(key) is not str:
                raise CanonicalJsonError("JSON object keys must be exact str values")
            count += _validate_value(item, depth=depth + 1)
            if count > MAX_JSON_ITEMS:
                raise CanonicalJsonError(
                    f"JSON document exceeds the {MAX_JSON_ITEMS}-item limit"
                )
        return count
    raise CanonicalJsonError(
        f"Unsupported or non-exact JSON value type: {value_type.__name__}"
    )


def _check_top_level_keys(
    value: JsonValue,
    *,
    allowed_keys: frozenset[str] | None,
    required_keys: frozenset[str] | None,
) -> None:
    if allowed_keys is None and required_keys is None:
        return
    if type(value) is not dict:
        raise CanonicalJsonError("A schema-bound JSON document must be an object")
    if allowed_keys is not None:
        if type(allowed_keys) is not frozenset or any(
            type(item) is not str for item in allowed_keys
        ):
            raise TypeError("allowed_keys must be a frozenset of exact str values")
        unknown = sorted(set(value).difference(allowed_keys))
        if unknown:
            raise UnknownJsonKeyError(
                "Unknown JSON object key(s): " + ", ".join(unknown)
            )
    if required_keys is not None:
        if type(required_keys) is not frozenset or any(
            type(item) is not str for item in required_keys
        ):
            raise TypeError("required_keys must be a frozenset of exact str values")
        missing = sorted(required_keys.difference(value))
        if missing:
            raise MissingJsonKeyError(
                "Missing JSON object key(s): " + ", ".join(missing)
            )


def canonical_json_text(
    value: JsonValue,
    *,
    allowed_keys: frozenset[str] | None = None,
    required_keys: frozenset[str] | None = None,
) -> str:
    """Validate and deterministically encode the supported JSON subset."""

    _validate_value(value)
    _check_top_level_keys(value, allowed_keys=allowed_keys, required_keys=required_keys)
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(encoded.encode("utf-8")) > MAX_JSON_TEXT_BYTES:
        raise CanonicalJsonError(
            f"Canonical JSON exceeds the {MAX_JSON_TEXT_BYTES}-byte limit"
        )
    return encoded


def canonical_json_bytes(
    value: JsonValue,
    *,
    allowed_keys: frozenset[str] | None = None,
    required_keys: frozenset[str] | None = None,
) -> bytes:
    return canonical_json_text(
        value, allowed_keys=allowed_keys, required_keys=required_keys
    ).encode("utf-8")


def canonical_json_sha256(
    value: JsonValue,
    *,
    allowed_keys: frozenset[str] | None = None,
    required_keys: frozenset[str] | None = None,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            value, allowed_keys=allowed_keys, required_keys=required_keys
        )
    ).hexdigest()


def load_json_strict(
    source: str | bytes,
    *,
    allowed_keys: frozenset[str] | None = None,
    required_keys: frozenset[str] | None = None,
) -> JsonValue:
    """Parse untrusted JSON while rejecting duplicates and number ambiguity."""

    if type(source) is bytes:
        if len(source) > MAX_JSON_TEXT_BYTES:
            raise CanonicalJsonError(
                f"JSON input exceeds the {MAX_JSON_TEXT_BYTES}-byte limit"
            )
        try:
            text = source.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise CanonicalJsonError("JSON input must be valid UTF-8") from error
    elif type(source) is str:
        text = source
        if len(text.encode("utf-8")) > MAX_JSON_TEXT_BYTES:
            raise CanonicalJsonError(
                f"JSON input exceeds the {MAX_JSON_TEXT_BYTES}-byte limit"
            )
    else:
        raise TypeError("source must be an exact str or bytes value")

    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
            parse_int=int,
        )
    except CanonicalJsonError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise CanonicalJsonError(f"Invalid JSON document: {error}") from error
    _validate_value(value)
    _check_top_level_keys(value, allowed_keys=allowed_keys, required_keys=required_keys)
    return value


def canonicalize_json(
    source: str | bytes,
    *,
    allowed_keys: frozenset[str] | None = None,
    required_keys: frozenset[str] | None = None,
) -> CanonicalJsonDocument:
    """Parse, validate, re-encode, then hash; never hash attacker spelling."""

    value = load_json_strict(
        source, allowed_keys=allowed_keys, required_keys=required_keys
    )
    text = canonical_json_text(
        value, allowed_keys=allowed_keys, required_keys=required_keys
    )
    return CanonicalJsonDocument(
        value=value,
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )
