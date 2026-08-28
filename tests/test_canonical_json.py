from __future__ import annotations

import hashlib
import math
import unittest

from paramguard.canonical_json import (
    CanonicalJsonError,
    DuplicateJsonKeyError,
    MissingJsonKeyError,
    UnknownJsonKeyError,
    canonical_json_sha256,
    canonical_json_text,
    canonicalize_json,
    load_json_strict,
)


class DictSubclass(dict):
    pass


class IntSubclass(int):
    pass


class CanonicalJsonTests(unittest.TestCase):
    def test_reorders_object_members_and_hashes_reencoded_bytes(self) -> None:
        document = canonicalize_json('{ "z" : 1, "a": [true, null, "\u00e9"] }')

        self.assertEqual(document.text, '{"a":[true,null,"é"],"z":1}')
        self.assertEqual(
            document.sha256,
            hashlib.sha256(document.text.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(document.sha256, canonical_json_sha256(document.value))

    def test_rejects_duplicate_keys_at_every_depth(self) -> None:
        for source in ('{"a":1,"a":2}', '{"outer":{"x":1,"x":2}}'):
            with self.subTest(source=source):
                with self.assertRaises(DuplicateJsonKeyError):
                    load_json_strict(source)

    def test_rejects_nan_infinity_and_every_float_spelling(self) -> None:
        for source in ("NaN", "Infinity", "-Infinity", "1.0", "1e3"):
            with self.subTest(source=source):
                with self.assertRaises(CanonicalJsonError):
                    load_json_strict(source)
        for value in (math.nan, math.inf, -math.inf, 1.25):
            with self.subTest(value=value):
                with self.assertRaises(CanonicalJsonError):
                    canonical_json_text(value)  # type: ignore[arg-type]

    def test_rejects_unknown_and_missing_schema_keys(self) -> None:
        allowed = frozenset({"a", "b"})
        with self.assertRaises(UnknownJsonKeyError):
            load_json_strict('{"a":1,"unexpected":2}', allowed_keys=allowed)
        with self.assertRaises(MissingJsonKeyError):
            load_json_strict(
                '{"a":1}', allowed_keys=allowed, required_keys=frozenset({"a", "b"})
            )

    def test_rejects_non_exact_python_container_scalar_and_key_types(self) -> None:
        values = (
            DictSubclass(a=1),
            {"a": IntSubclass(1)},
            {1: "not-a-string-key"},
            ("tuple",),
            bytearray(b"{}"),
        )
        for value in values:
            with self.subTest(value=repr(value)):
                if isinstance(value, bytearray):
                    with self.assertRaises(TypeError):
                        load_json_strict(value)  # type: ignore[arg-type]
                else:
                    with self.assertRaises(CanonicalJsonError):
                        canonical_json_text(value)  # type: ignore[arg-type]

    def test_rejects_out_of_range_integer_and_invalid_utf8(self) -> None:
        with self.assertRaises(CanonicalJsonError):
            canonical_json_text(2**63)  # type: ignore[arg-type]
        with self.assertRaises(CanonicalJsonError):
            load_json_strict(b'"\xff"')


if __name__ == "__main__":
    unittest.main()
