"""Strict, development-only scoring of synthetic OCR tool comparisons.

This module does not run OCR or replace the human-first execution gate.  It
scores complete observation cohorts, without accepting a caller's verdict or
declaring statistical superiority.  Structural missing values are reported
separately from pairs whose two ground-truth strings are present.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import TypedDict, cast


_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_MAX_RAW_CHARACTERS = 4096


class ObservationStatus(str, Enum):
    VALID = "VALID"
    ABSTAIN = "ABSTAIN"
    ERROR = "ERROR"


def _require_identifier(name: str, value: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{name} must be a built-in str")
    if not 1 <= len(value) <= 128 or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe 1-128 character identifier")


def _require_raw(name: str, value: str | None) -> None:
    if value is None:
        return
    if type(value) is not str:
        raise TypeError(f"{name} must be a built-in str or None")
    if not 1 <= len(value) <= _MAX_RAW_CHARACTERS:
        raise ValueError(f"{name} must contain 1-4096 characters when present")


@dataclass(frozen=True, slots=True)
class ComparisonTruth:
    case_id: str
    parameter_id: str
    left_raw: str | None
    right_raw: str | None

    def __post_init__(self) -> None:
        _require_identifier("case_id", self.case_id)
        _require_identifier("parameter_id", self.parameter_id)
        _require_raw("left_raw", self.left_raw)
        _require_raw("right_raw", self.right_raw)

    @property
    def key(self) -> tuple[str, str]:
        return (self.case_id, self.parameter_id)


@dataclass(frozen=True, slots=True)
class ToolObservation:
    case_id: str
    parameter_id: str
    left_raw: str | None
    right_raw: str | None
    status: ObservationStatus

    def __post_init__(self) -> None:
        _require_identifier("case_id", self.case_id)
        _require_identifier("parameter_id", self.parameter_id)
        _require_raw("left_raw", self.left_raw)
        _require_raw("right_raw", self.right_raw)
        if type(self.status) is not ObservationStatus:
            raise TypeError("status must be an ObservationStatus")
        if self.status is ObservationStatus.VALID and (
            self.left_raw is None or self.right_raw is None
        ):
            raise ValueError("VALID observations require both raw strings")

    @property
    def key(self) -> tuple[str, str]:
        return (self.case_id, self.parameter_id)


class _RateRecord(TypedDict):
    numerator: int
    denominator: int
    value: float | None


def _rate(numerator: int, denominator: int) -> _RateRecord:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator if denominator else None,
    }


def _truth_index(
    truth: tuple[ComparisonTruth, ...],
) -> dict[tuple[str, str], ComparisonTruth]:
    if type(truth) is not tuple:
        raise TypeError("truth must be a built-in tuple")
    if not truth:
        raise ValueError("truth must not be empty")
    result: dict[tuple[str, str], ComparisonTruth] = {}
    for row in truth:
        if type(row) is not ComparisonTruth:
            raise TypeError("truth rows must be ComparisonTruth instances")
        # Frozen records are a convenience, not an input-validation boundary.
        ComparisonTruth.__post_init__(row)
        if row.key in result:
            raise ValueError("truth contains a duplicate key")
        result[row.key] = row
    return result


def _observation_index(
    observations: tuple[ToolObservation, ...],
    expected: dict[tuple[str, str], ComparisonTruth],
) -> dict[tuple[str, str], ToolObservation]:
    if type(observations) is not tuple:
        raise TypeError("observations must be a built-in tuple")
    result: dict[tuple[str, str], ToolObservation] = {}
    for row in observations:
        if type(row) is not ToolObservation:
            raise TypeError("observation rows must be ToolObservation instances")
        ToolObservation.__post_init__(row)
        if row.key in result:
            raise ValueError("observations contain a duplicate key")
        result[row.key] = row
    missing = expected.keys() - result.keys()
    unknown = result.keys() - expected.keys()
    if missing or unknown:
        raise ValueError(
            "observations must exactly cover truth keys "
            f"(missing={len(missing)}, unknown={len(unknown)})"
        )
    return result


def score_tool(
    truth: tuple[ComparisonTruth, ...],
    observations: tuple[ToolObservation, ...],
) -> dict[str, object]:
    """Score a complete cohort using literal strings, without normalization.

    Present pairs have two non-None truth strings.  Their raw exact rate is a
    diagnostic that includes candidate text on rejected observations; their
    accepted exact rate and supported difference recall require VALID status.
    ABSTAIN and ERROR are separate all-field rates.  Both count as unresolved
    differences and safe rejection of a structural pair, never as detection.
    Image quality does not remove a present pair from any denominator.
    """

    expected = _truth_index(truth)
    observed = _observation_index(observations, expected)
    present = structural = differences = same = 0
    supported = ordinary = false_same = false_positive = unresolved = 0
    raw_exact = accepted_exact = abstentions = errors = structural_rejected = 0
    wrong_accepted = unsupported_difference = 0

    for key, row in expected.items():
        observation = observed[key]
        valid = observation.status is ObservationStatus.VALID
        abstentions += observation.status is ObservationStatus.ABSTAIN
        errors += observation.status is ObservationStatus.ERROR
        pair_present = row.left_raw is not None and row.right_raw is not None
        pair_exact = (
            pair_present
            and observation.left_raw == row.left_raw
            and observation.right_raw == row.right_raw
        )
        predicted_difference = valid and observation.left_raw != observation.right_raw
        wrong_accepted += valid and not pair_exact

        if not pair_present:
            structural += 1
            structural_rejected += not valid
            unsupported_difference += predicted_difference
            continue

        present += 1
        raw_exact += pair_exact
        accepted_exact += valid and pair_exact
        if row.left_raw != row.right_raw:
            differences += 1
            supported += predicted_difference and pair_exact
            ordinary += predicted_difference
            false_same += valid and not predicted_difference
            unresolved += not valid
            unsupported_difference += predicted_difference and not pair_exact
        else:
            same += 1
            false_positive += predicted_difference
            unsupported_difference += predicted_difference

    field_count = len(expected)
    return {
        "field_count": field_count,
        "present_pair_count": present,
        "structural_pair_count": structural,
        "true_difference_count": differences,
        "true_same_count": same,
        "supported_difference_recall": _rate(supported, differences),
        "ordinary_difference_recall": _rate(ordinary, differences),
        "false_same_rate": _rate(false_same, differences),
        "false_positive_rate": _rate(false_positive, same),
        "unresolved_difference_rate": _rate(unresolved, differences),
        "raw_pair_exact_rate": _rate(raw_exact, present),
        "accepted_pair_exact_rate": _rate(accepted_exact, present),
        "abstention_rate": _rate(abstentions, field_count),
        "error_rate": _rate(errors, field_count),
        "structural_rejection_rate": _rate(structural_rejected, structural),
        "wrong_accepted_pair_count": wrong_accepted,
        "unsupported_difference_count": unsupported_difference,
    }


def _development_delta(
    candidate_rate: _RateRecord, baseline_rate: _RateRecord
) -> dict[str, object]:
    denominator = candidate_rate["denominator"]
    candidate_count = candidate_rate["numerator"]
    baseline_count = baseline_rate["numerator"]
    # Every tool was scored against the same truth cohort and denominator.
    absolute_difference = (
        (candidate_count - baseline_count) / denominator if denominator else None
    )
    relative_gain = (
        (candidate_count - baseline_count) / baseline_count if baseline_count else None
    )
    target_feasible: bool | None
    if not denominator:
        target_feasible = None
        target_reason = "NO_PRESENT_DIFFERENCES"
    elif not baseline_count:
        target_feasible = None
        target_reason = "ZERO_BASELINE_RELATIVE_UNDEFINED"
    else:
        # 1.05 * baseline <= 1, tested without rounding the 20/21 boundary.
        target_feasible = 21 * baseline_count <= 20 * denominator
        target_reason = (
            "WITHIN_SCORE_CEILING" if target_feasible else "EXCEEDS_SCORE_CEILING"
        )
    return {
        "status": "DEVELOPMENT_ONLY",
        "candidate_supported_difference_recall": candidate_rate["value"],
        "baseline_supported_difference_recall": baseline_rate["value"],
        "absolute_difference": absolute_difference,
        "percentage_point_difference": (
            100 * absolute_difference if absolute_difference is not None else None
        ),
        "relative_gain": relative_gain,
        "requested_relative_gain": 0.05,
        "relative_5pct_target_feasible": target_feasible,
        "relative_5pct_target_reason": target_reason,
        "baseline_at_score_ceiling": bool(
            denominator and baseline_count == denominator
        ),
        "five_percent_confirmed": False,
    }


def compare_development(
    truth: tuple[ComparisonTruth, ...],
    tools: dict[str, tuple[ToolObservation, ...]],
    candidate: str,
) -> dict[str, object]:
    """Describe paired development results, never a confirmed five-percent gain.

    Tool identifiers name configurations, not necessarily independent engines.
    At least one baseline is required.  Relative gains are undefined for a
    zero baseline or a cohort without present differences.  No confidence
    interval, significance test, human-time estimate, or release decision is
    produced here.
    """

    _truth_index(truth)
    if type(tools) is not dict:
        raise TypeError("tools must be a built-in dict")
    if len(tools) < 2:
        raise ValueError("tools must include a candidate and at least one baseline")
    for name in tools:
        _require_identifier("tool name", name)
    _require_identifier("candidate", candidate)
    if candidate not in tools:
        raise ValueError("candidate must name a supplied tool")

    tool_scores = {name: score_tool(truth, tools[name]) for name in sorted(tools)}
    candidate_rate = cast(
        _RateRecord, tool_scores[candidate]["supported_difference_recall"]
    )
    comparisons = {
        name: _development_delta(
            candidate_rate,
            cast(_RateRecord, score["supported_difference_recall"]),
        )
        for name, score in tool_scores.items()
        if name != candidate
    }
    return {
        "status": "DEVELOPMENT_ONLY",
        "candidate": candidate,
        "human_review_seconds": None,
        "tool_scores": tool_scores,
        "comparisons": comparisons,
        "five_percent_confirmed": False,
    }
