"""V0.1 严格比较器的回归测试。"""

from decimal import Decimal
import subprocess
import sys
import unittest

from paramguard import ComparisonKind, compare_values


class CompareValuesTests(unittest.TestCase):
    def test_identical_non_empty_strings_are_exact_match(self) -> None:
        result = compare_values("37.0 °C", "37.0 °C")

        self.assertTrue(result.exact_match)
        self.assertEqual(result.kind, ComparisonKind.EXACT_MATCH)

    def test_two_missing_values_are_not_a_match(self) -> None:
        result = compare_values(None, None)

        self.assertFalse(result.exact_match)
        self.assertEqual(result.kind, ComparisonKind.MISSING_VALUE)

    def test_empty_and_zero_are_not_the_same(self) -> None:
        result = compare_values("", "0")

        self.assertFalse(result.exact_match)
        self.assertEqual(result.kind, ComparisonKind.MISSING_VALUE)

    def test_numeric_value_difference_is_detected(self) -> None:
        result = compare_values("7.20", "7.25")

        self.assertEqual(result.kind, ComparisonKind.VALUE_MISMATCH)
        self.assertEqual(result.left_number, Decimal("7.20"))
        self.assertEqual(result.right_number, Decimal("7.25"))

    def test_missing_minus_sign_is_detected(self) -> None:
        result = compare_values("-0.5 °C", "0.5 °C")

        self.assertFalse(result.exact_match)
        self.assertEqual(result.kind, ComparisonKind.VALUE_MISMATCH)

    def test_unit_difference_is_detected(self) -> None:
        result = compare_values("10 mg", "10 μg")

        self.assertEqual(result.kind, ComparisonKind.UNIT_MISMATCH)
        self.assertEqual(result.left_unit, "mg")
        self.assertEqual(result.right_unit, "μg")

    def test_leading_zero_is_a_format_difference_not_a_match(self) -> None:
        result = compare_values("025.0 L/min", "25.0 L/min")

        self.assertFalse(result.exact_match)
        self.assertEqual(result.kind, ComparisonKind.FORMAT_DIFFERENCE)
        self.assertEqual(result.left_number, result.right_number)

    def test_decimal_precision_is_a_format_difference_not_a_match(self) -> None:
        result = compare_values("1.0 bar", "1.00 bar")

        self.assertFalse(result.exact_match)
        self.assertEqual(result.kind, ComparisonKind.FORMAT_DIFFERENCE)

    def test_case_difference_is_a_normalization_collision_not_a_match(self) -> None:
        result = compare_values("AUTO", "auto")

        self.assertFalse(result.exact_match)
        self.assertEqual(result.kind, ComparisonKind.NORMALIZATION_COLLISION)

    def test_different_text_is_detected(self) -> None:
        result = compare_values("CLOSED", "CLOSEO")

        self.assertFalse(result.exact_match)
        self.assertEqual(result.kind, ComparisonKind.TEXT_MISMATCH)

    def test_raw_values_are_never_overwritten(self) -> None:
        result = compare_values("  AUTO", "AUTO")

        self.assertEqual(result.left_raw, "  AUTO")
        self.assertEqual(result.right_raw, "AUTO")
        self.assertFalse(result.exact_match)

    def test_unit_case_is_not_normalised_away(self) -> None:
        result = compare_values("1 m", "1 M")

        self.assertEqual(result.kind, ComparisonKind.UNIT_MISMATCH)

    def test_thousands_separator_is_not_misread_as_a_unit(self) -> None:
        result = compare_values("1,000 mg", "1000 mg")

        self.assertEqual(result.kind, ComparisonKind.UNPARSEABLE_DIFFERENCE)

    def test_malformed_decimal_is_not_misread_as_a_unit(self) -> None:
        result = compare_values("1..0", "1.0")

        self.assertEqual(result.kind, ComparisonKind.UNPARSEABLE_DIFFERENCE)

    def test_value_and_unit_difference_are_both_reported(self) -> None:
        result = compare_values("10 mg", "20 μg")

        self.assertEqual(result.kind, ComparisonKind.VALUE_AND_UNIT_MISMATCH)

    def test_aggressive_unicode_normalisation_is_not_called_low_risk_formatting(
        self,
    ) -> None:
        result = compare_values("①", "1")

        self.assertEqual(result.kind, ComparisonKind.NORMALIZATION_COLLISION)

    def test_unicode_minus_is_not_silently_parsed_as_an_ascii_minus(self) -> None:
        result = compare_values("−0.5 °C", "-0.5 °C")

        self.assertEqual(result.kind, ComparisonKind.UNPARSEABLE_DIFFERENCE)

    def test_non_string_display_value_has_a_clear_error(self) -> None:
        with self.assertRaisesRegex(TypeError, "must be str or None"):
            compare_values(1, "1")  # type: ignore[arg-type]

    def test_objects_cannot_override_raw_string_equality(self) -> None:
        class AlwaysEqual(str):
            def __eq__(self, other: object) -> bool:
                return True

        class PretendString:
            @property
            def __class__(self):
                return str

            def strip(self) -> str:
                return "synthetic-left"

            def __eq__(self, other: object) -> bool:
                return True

        for value in (AlwaysEqual("synthetic-left"), PretendString()):
            for left, right in ((value, "synthetic-right"), ("synthetic-right", value)):
                with self.subTest(
                    value_type=type(value).__name__, left_type=type(left).__name__
                ):
                    with self.assertRaises(TypeError):
                        compare_values(left, right)

    def test_long_whitespace_with_invalid_suffix_has_no_quadratic_backtracking(
        self,
    ) -> None:
        probe = (
            "from paramguard import compare_values; "
            "value = '1' + ' ' * 64000 + '!'; "
            "result = compare_values(value, '0'); "
            "assert result.left_raw == value and not result.exact_match; "
            "print(result.kind.value)"
        )
        try:
            completed = subprocess.run(
                [sys.executable, "-c", probe],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            self.fail("64k-space comparison exceeded the 5-second regression budget")
        self.assertEqual(completed.stdout.strip(), "UNPARSEABLE_DIFFERENCE")

    def test_numeric_whitespace_and_unit_captures_are_preserved(self) -> None:
        for whitespace in ("", " ", "\t", "\n", "\u00a0", " " * 64000):
            for unit in ("", "mg", "µg", "m/s^2"):
                left = f"{whitespace}01.0{whitespace}{unit}{whitespace}"
                right = f"1.0{unit}"
                with self.subTest(length=len(whitespace), unit=unit):
                    result = compare_values(left, right)
                    self.assertEqual(result.kind, ComparisonKind.FORMAT_DIFFERENCE)
                    self.assertEqual(result.left_number, Decimal("01.0"))
                    self.assertEqual(result.left_unit, unit)
                    self.assertEqual(result.left_raw, left)


if __name__ == "__main__":
    unittest.main()
