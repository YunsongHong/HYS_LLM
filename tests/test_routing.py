"""Tests for conservative discrepancy and exception routing."""

import unittest

from paramguard import ComparisonKind
from paramguard.routing import (
    FieldIssue,
    ImageQuality,
    ReviewRoute,
    ReviewSignals,
    RouteReason,
    route_parameter,
)
from paramguard.workflow import AiVerdict, HumanVerdict


def safe_signals(**changes: object) -> ReviewSignals:
    values: dict[str, object] = {
        "parameter_id": "temperature",
        "human_verdict": HumanVerdict.SAME,
        "ai_verdict": AiVerdict.SAME,
        "comparison_kind": ComparisonKind.EXACT_MATCH,
    }
    values.update(changes)
    return ReviewSignals(**values)  # type: ignore[arg-type]


class RouteParameterTests(unittest.TestCase):
    def test_clean_noncritical_agreement_has_no_exception_but_no_release(self) -> None:
        result = route_parameter(safe_signals())

        self.assertEqual(result.route, ReviewRoute.NO_EXCEPTION_DETECTED)
        self.assertEqual(result.reasons, ())
        self.assertFalse(result.automatic_release_allowed)

    def test_human_ai_disagreement_requires_second_review(self) -> None:
        result = route_parameter(
            safe_signals(ai_verdict=AiVerdict.DIFFERENT)
        )

        self.assertEqual(
            result.route, ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED
        )
        self.assertIn(RouteReason.HUMAN_AI_DISAGREEMENT, result.reasons)
        self.assertIn(RouteReason.AI_DETECTED_DIFFERENCE, result.reasons)

    def test_two_difference_verdicts_still_require_second_review(self) -> None:
        result = route_parameter(
            safe_signals(
                human_verdict=HumanVerdict.DIFFERENT,
                ai_verdict=AiVerdict.DIFFERENT,
                comparison_kind=ComparisonKind.VALUE_MISMATCH,
            )
        )

        self.assertEqual(
            result.route, ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED
        )
        self.assertNotIn(RouteReason.HUMAN_AI_DISAGREEMENT, result.reasons)
        self.assertIn(RouteReason.HUMAN_DETECTED_DIFFERENCE, result.reasons)
        self.assertIn(RouteReason.AI_DETECTED_DIFFERENCE, result.reasons)

    def test_human_uncertainty_requires_second_review(self) -> None:
        result = route_parameter(
            safe_signals(human_verdict=HumanVerdict.UNABLE_TO_JUDGE)
        )

        self.assertIn(RouteReason.HUMAN_UNABLE_TO_JUDGE, result.reasons)
        self.assertEqual(
            result.route, ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED
        )

    def test_ai_uncertainty_requires_second_review(self) -> None:
        result = route_parameter(
            safe_signals(ai_verdict=AiVerdict.UNABLE_TO_JUDGE)
        )

        self.assertIn(RouteReason.AI_UNABLE_TO_JUDGE, result.reasons)

    def test_ai_system_error_takes_qa_route_not_match(self) -> None:
        result = route_parameter(
            safe_signals(ai_verdict=AiVerdict.SYSTEM_ERROR)
        )

        self.assertEqual(result.route, ReviewRoute.QA_REVIEW_REQUIRED)
        self.assertIn(RouteReason.AI_SYSTEM_ERROR, result.reasons)
        self.assertNotIn(RouteReason.HUMAN_AI_DISAGREEMENT, result.reasons)
        self.assertFalse(result.automatic_release_allowed)

    def test_low_and_unreadable_image_each_require_second_review(self) -> None:
        cases = (
            (ImageQuality.LOW, RouteReason.LOW_IMAGE_QUALITY),
            (ImageQuality.UNREADABLE, RouteReason.UNREADABLE_IMAGE),
        )
        for quality, reason in cases:
            with self.subTest(quality=quality):
                result = route_parameter(safe_signals(image_quality=quality))
                self.assertEqual(
                    result.route, ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED
                )
                self.assertIn(reason, result.reasons)

    def test_critical_parameter_always_requires_second_review(self) -> None:
        result = route_parameter(safe_signals(is_critical=True))

        self.assertEqual(
            result.route, ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED
        )
        self.assertEqual(result.reasons, (RouteReason.CRITICAL_PARAMETER,))

    def test_any_nonexact_deterministic_comparison_requires_review(self) -> None:
        for kind in ComparisonKind:
            if kind is ComparisonKind.EXACT_MATCH:
                continue
            with self.subTest(kind=kind):
                result = route_parameter(safe_signals(comparison_kind=kind))
                self.assertEqual(
                    result.route, ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED
                )
                self.assertIn(
                    RouteReason.DETERMINISTIC_COMPARISON_NOT_EXACT,
                    result.reasons,
                )

    def test_each_structural_issue_takes_qa_route(self) -> None:
        cases = (
            (FieldIssue.MISSING_EXPECTED_FIELD, RouteReason.MISSING_EXPECTED_FIELD),
            (
                FieldIssue.DUPLICATE_EXPECTED_FIELD,
                RouteReason.DUPLICATE_EXPECTED_FIELD,
            ),
            (FieldIssue.UNKNOWN_FIELD, RouteReason.UNKNOWN_FIELD),
        )
        for issue, reason in cases:
            with self.subTest(issue=issue):
                result = route_parameter(safe_signals(field_issues=(issue,)))
                self.assertEqual(result.route, ReviewRoute.QA_REVIEW_REQUIRED)
                self.assertIn(reason, result.reasons)

    def test_qa_route_wins_when_multiple_concerns_exist(self) -> None:
        result = route_parameter(
            safe_signals(
                human_verdict=HumanVerdict.DIFFERENT,
                image_quality=ImageQuality.UNREADABLE,
                field_issues=(FieldIssue.UNKNOWN_FIELD,),
            )
        )

        self.assertEqual(result.route, ReviewRoute.QA_REVIEW_REQUIRED)
        self.assertIn(RouteReason.UNKNOWN_FIELD, result.reasons)
        self.assertIn(RouteReason.UNREADABLE_IMAGE, result.reasons)
        self.assertIn(RouteReason.HUMAN_DETECTED_DIFFERENCE, result.reasons)

    def test_empty_parameter_id_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            route_parameter(safe_signals(parameter_id="  "))

    def test_wrong_enum_type_is_rejected_instead_of_guessed(self) -> None:
        with self.assertRaises(TypeError):
            route_parameter(safe_signals(human_verdict="SAME"))

    def test_duplicate_field_issues_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            route_parameter(
                safe_signals(
                    field_issues=(
                        FieldIssue.UNKNOWN_FIELD,
                        FieldIssue.UNKNOWN_FIELD,
                    )
                )
            )


if __name__ == "__main__":
    unittest.main()
