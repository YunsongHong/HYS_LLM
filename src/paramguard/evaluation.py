"""Risk-focused evaluation metrics for OCR-assisted difference detection.

The report intentionally leads with true differences, false negatives, and
unresolved/abstained cases.  A single overall-accuracy number can hide the
failure mode that matters most here: declaring two different displays equal.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import math
import statistics

from .comparison import ComparisonKind, compare_values
from .routing import ReviewRoute
from .workflow import AiVerdict


class DatasetSplit(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    HIDDEN_TEST = "HIDDEN_TEST"
    CHALLENGE = "CHALLENGE"


@dataclass(frozen=True, slots=True)
class FieldEvaluationRecord:
    case_id: str
    parameter_id: str
    split: DatasetSplit
    left_truth: str | None
    right_truth: str | None
    left_extracted: str | None
    right_extracted: str | None
    ai_verdict: AiVerdict
    route: ReviewRoute
    human_review_seconds: float | None = None
    ai_processing_seconds: float | None = None

    def __post_init__(self) -> None:
        for name in ("case_id", "parameter_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or value.strip() == "":
                raise ValueError(f"{name} must be non-empty text")
        if not isinstance(self.split, DatasetSplit):
            raise TypeError("split must be a DatasetSplit")
        for name in (
            "left_truth",
            "right_truth",
            "left_extracted",
            "right_extracted",
        ):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{name} must be str or None")
        if not isinstance(self.ai_verdict, AiVerdict):
            raise TypeError("ai_verdict must be an AiVerdict")
        if not isinstance(self.route, ReviewRoute):
            raise TypeError("route must be a ReviewRoute")
        for name in ("human_review_seconds", "ai_processing_seconds"):
            value = getattr(self, name)
            if value is not None and (
                type(value) not in (int, float)
                or not math.isfinite(float(value))
                or value < 0
            ):
                raise ValueError(f"{name} must be a finite non-negative number")

    @property
    def truth_comparison_kind(self) -> ComparisonKind:
        return compare_values(self.left_truth, self.right_truth).kind

    @property
    def true_difference(self) -> bool:
        return self.truth_comparison_kind is not ComparisonKind.EXACT_MATCH

    @property
    def extraction_pair_exact(self) -> bool:
        return (
            self.left_extracted == self.left_truth
            and self.right_extracted == self.right_truth
        )

    def to_record(self) -> dict[str, object]:
        """Return an explicit, JSON-safe evidence row for later inspection."""

        return {
            "case_id": self.case_id,
            "parameter_id": self.parameter_id,
            "split": self.split.value,
            "left_truth": self.left_truth,
            "right_truth": self.right_truth,
            "left_extracted": self.left_extracted,
            "right_extracted": self.right_extracted,
            "truth_comparison_kind": self.truth_comparison_kind.value,
            "true_difference": self.true_difference,
            "ai_verdict": self.ai_verdict.value,
            "route": self.route.value,
            "human_review_seconds": self.human_review_seconds,
            "ai_processing_seconds": self.ai_processing_seconds,
        }


@dataclass(frozen=True, slots=True)
class RateMetric:
    numerator: int
    denominator: int

    @property
    def value(self) -> float | None:
        if self.denominator == 0:
            return None
        return self.numerator / self.denominator

    def to_record(self) -> dict[str, int | float | None]:
        return {
            "numerator": self.numerator,
            "denominator": self.denominator,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    split: DatasetSplit
    field_count: int
    true_difference_count: int
    true_same_count: int
    difference_recall: RateMetric
    false_negative_rate: RateMetric
    unresolved_difference_rate: RateMetric
    false_positive_rate: RateMetric
    escalation_recall: RateMetric
    left_extraction_exact_rate: RateMetric
    right_extraction_exact_rate: RateMetric
    pair_extraction_exact_rate: RateMetric
    overall_abstention_rate: RateMetric
    median_human_review_seconds: float | None
    median_ai_processing_seconds: float | None

    def to_record(self) -> dict[str, object]:
        return {
            "split": self.split.value,
            "field_count": self.field_count,
            "true_difference_count": self.true_difference_count,
            "true_same_count": self.true_same_count,
            "difference_recall": self.difference_recall.to_record(),
            "false_negative_rate": self.false_negative_rate.to_record(),
            "unresolved_difference_rate": self.unresolved_difference_rate.to_record(),
            "false_positive_rate": self.false_positive_rate.to_record(),
            "escalation_recall": self.escalation_recall.to_record(),
            "left_extraction_exact_rate": self.left_extraction_exact_rate.to_record(),
            "right_extraction_exact_rate": self.right_extraction_exact_rate.to_record(),
            "pair_extraction_exact_rate": self.pair_extraction_exact_rate.to_record(),
            "overall_abstention_rate": self.overall_abstention_rate.to_record(),
            "median_human_review_seconds": self.median_human_review_seconds,
            "median_ai_processing_seconds": self.median_ai_processing_seconds,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_record(),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )


def evaluate_fields(
    records: tuple[FieldEvaluationRecord, ...],
    *,
    split: DatasetSplit,
) -> EvaluationReport:
    """Compute one report without mixing development and held-out labels."""

    if not isinstance(records, tuple):
        raise TypeError("records must be a tuple")
    if not isinstance(split, DatasetSplit):
        raise TypeError("split must be a DatasetSplit")
    if any(not isinstance(record, FieldEvaluationRecord) for record in records):
        raise TypeError("records must contain only FieldEvaluationRecord values")
    selected = tuple(record for record in records if record.split is split)
    if not selected:
        raise ValueError(f"No evaluation records exist for split {split.value}")

    differences = tuple(record for record in selected if record.true_difference)
    same = tuple(record for record in selected if not record.true_difference)
    detected = sum(
        record.ai_verdict is AiVerdict.DIFFERENT for record in differences
    )
    missed_as_same = sum(
        record.ai_verdict is AiVerdict.SAME for record in differences
    )
    unresolved_difference = sum(
        record.ai_verdict in (AiVerdict.UNABLE_TO_JUDGE, AiVerdict.SYSTEM_ERROR)
        for record in differences
    )
    false_positive = sum(
        record.ai_verdict is AiVerdict.DIFFERENT for record in same
    )
    escalated_differences = sum(
        record.route is not ReviewRoute.NO_EXCEPTION_DETECTED
        for record in differences
    )
    abstentions = sum(
        record.ai_verdict in (AiVerdict.UNABLE_TO_JUDGE, AiVerdict.SYSTEM_ERROR)
        for record in selected
    )

    human_times = [
        float(record.human_review_seconds)
        for record in selected
        if record.human_review_seconds is not None
    ]
    ai_times = [
        float(record.ai_processing_seconds)
        for record in selected
        if record.ai_processing_seconds is not None
    ]

    return EvaluationReport(
        split=split,
        field_count=len(selected),
        true_difference_count=len(differences),
        true_same_count=len(same),
        difference_recall=RateMetric(detected, len(differences)),
        false_negative_rate=RateMetric(missed_as_same, len(differences)),
        unresolved_difference_rate=RateMetric(
            unresolved_difference, len(differences)
        ),
        false_positive_rate=RateMetric(false_positive, len(same)),
        escalation_recall=RateMetric(escalated_differences, len(differences)),
        left_extraction_exact_rate=RateMetric(
            sum(record.left_extracted == record.left_truth for record in selected),
            len(selected),
        ),
        right_extraction_exact_rate=RateMetric(
            sum(record.right_extracted == record.right_truth for record in selected),
            len(selected),
        ),
        pair_extraction_exact_rate=RateMetric(
            sum(record.extraction_pair_exact for record in selected), len(selected)
        ),
        overall_abstention_rate=RateMetric(abstentions, len(selected)),
        median_human_review_seconds=(
            None if not human_times else statistics.median(human_times)
        ),
        median_ai_processing_seconds=(
            None if not ai_times else statistics.median(ai_times)
        ),
    )
