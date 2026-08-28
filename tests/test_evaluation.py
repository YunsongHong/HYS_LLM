"""Tests for risk-focused evaluation and hidden-split isolation."""

import unittest

from paramguard.evaluation import (
    DatasetSplit,
    FieldEvaluationRecord,
    evaluate_fields,
)
from paramguard.routing import ReviewRoute
from paramguard.workflow import AiVerdict


def record(
    parameter_id: str,
    *,
    left: str | None,
    right: str | None,
    verdict: AiVerdict,
    route: ReviewRoute,
    left_extracted: str | None = None,
    right_extracted: str | None = None,
    split: DatasetSplit = DatasetSplit.HIDDEN_TEST,
) -> FieldEvaluationRecord:
    return FieldEvaluationRecord(
        case_id="case-001",
        parameter_id=parameter_id,
        split=split,
        left_truth=left,
        right_truth=right,
        left_extracted=left if left_extracted is None else left_extracted,
        right_extracted=right if right_extracted is None else right_extracted,
        ai_verdict=verdict,
        route=route,
        human_review_seconds=2.0,
        ai_processing_seconds=0.5,
    )


class EvaluationTests(unittest.TestCase):
    def test_reports_detected_missed_and_unresolved_differences_separately(self) -> None:
        records = (
            record(
                "detected",
                left="1.0",
                right="2.0",
                verdict=AiVerdict.DIFFERENT,
                route=ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED,
            ),
            record(
                "false-negative",
                left="-1.0",
                right="1.0",
                verdict=AiVerdict.SAME,
                route=ReviewRoute.NO_EXCEPTION_DETECTED,
            ),
            record(
                "abstained-difference",
                left=None,
                right="1.0",
                verdict=AiVerdict.UNABLE_TO_JUDGE,
                route=ReviewRoute.QA_REVIEW_REQUIRED,
            ),
            record(
                "false-positive",
                left="AUTO",
                right="AUTO",
                verdict=AiVerdict.DIFFERENT,
                route=ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED,
            ),
            record(
                "true-same",
                left="37.0 C",
                right="37.0 C",
                verdict=AiVerdict.SAME,
                route=ReviewRoute.NO_EXCEPTION_DETECTED,
                left_extracted="37.0C",
                right_extracted="37.0C",
            ),
        )

        report = evaluate_fields(records, split=DatasetSplit.HIDDEN_TEST)

        self.assertEqual(report.true_difference_count, 3)
        self.assertEqual(report.true_same_count, 2)
        self.assertEqual(report.difference_recall.value, 1 / 3)
        self.assertEqual(report.false_negative_rate.value, 1 / 3)
        self.assertEqual(report.unresolved_difference_rate.value, 1 / 3)
        self.assertEqual(report.false_positive_rate.value, 1 / 2)
        self.assertEqual(report.escalation_recall.value, 2 / 3)
        self.assertEqual(report.pair_extraction_exact_rate.value, 4 / 5)
        self.assertEqual(report.median_human_review_seconds, 2.0)
        self.assertEqual(report.median_ai_processing_seconds, 0.5)
        self.assertNotIn("overall_accuracy", report.to_record())

    def test_split_filter_prevents_development_rows_from_changing_hidden_report(self) -> None:
        hidden = record(
            "hidden",
            left="1",
            right="2",
            verdict=AiVerdict.DIFFERENT,
            route=ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED,
        )
        development = record(
            "development",
            left="1",
            right="2",
            verdict=AiVerdict.SAME,
            route=ReviewRoute.NO_EXCEPTION_DETECTED,
            split=DatasetSplit.DEVELOPMENT,
        )

        report = evaluate_fields(
            (hidden, development), split=DatasetSplit.HIDDEN_TEST
        )
        self.assertEqual(report.field_count, 1)
        self.assertEqual(report.difference_recall.value, 1.0)

    def test_zero_denominator_rate_is_none_not_nan_or_misleading_zero(self) -> None:
        only_same = record(
            "same",
            left="AUTO",
            right="AUTO",
            verdict=AiVerdict.SAME,
            route=ReviewRoute.NO_EXCEPTION_DETECTED,
        )
        report = evaluate_fields((only_same,), split=DatasetSplit.HIDDEN_TEST)
        self.assertIsNone(report.difference_recall.value)
        self.assertIsNone(report.false_negative_rate.value)
        self.assertIn('"value": null', report.to_json())

    def test_empty_requested_split_is_rejected(self) -> None:
        development = record(
            "development",
            left="1",
            right="1",
            verdict=AiVerdict.SAME,
            route=ReviewRoute.NO_EXCEPTION_DETECTED,
            split=DatasetSplit.DEVELOPMENT,
        )
        with self.assertRaises(ValueError):
            evaluate_fields((development,), split=DatasetSplit.HIDDEN_TEST)


if __name__ == "__main__":
    unittest.main()
