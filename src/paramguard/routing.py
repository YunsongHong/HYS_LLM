"""Deterministic routing for auxiliary-review signals.

Routing is deliberately conservative.  Agreement between a human and an AI
does not create a release decision.  Any detected difference, uncertainty,
critical field, image-quality concern, or structural field problem stays in a
human-controlled review path.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .comparison import ComparisonKind
from .workflow import AiVerdict, HumanVerdict


class ImageQuality(str, Enum):
    """Coarse quality gate used before trusting an extracted field."""

    ACCEPTABLE = "ACCEPTABLE"
    LOW = "LOW"
    UNREADABLE = "UNREADABLE"


class FieldIssue(str, Enum):
    """Schema/alignment problems that require QA-level handling."""

    MISSING_EXPECTED_FIELD = "MISSING_EXPECTED_FIELD"
    DUPLICATE_EXPECTED_FIELD = "DUPLICATE_EXPECTED_FIELD"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"


class ReviewRoute(str, Enum):
    """The next manual-control path; none of these authorises release."""

    NO_EXCEPTION_DETECTED = "NO_EXCEPTION_DETECTED"
    INDEPENDENT_SECOND_REVIEW_REQUIRED = "INDEPENDENT_SECOND_REVIEW_REQUIRED"
    QA_REVIEW_REQUIRED = "QA_REVIEW_REQUIRED"


class RouteReason(str, Enum):
    MISSING_EXPECTED_FIELD = "MISSING_EXPECTED_FIELD"
    DUPLICATE_EXPECTED_FIELD = "DUPLICATE_EXPECTED_FIELD"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    LOW_IMAGE_QUALITY = "LOW_IMAGE_QUALITY"
    UNREADABLE_IMAGE = "UNREADABLE_IMAGE"
    CRITICAL_PARAMETER = "CRITICAL_PARAMETER"
    HUMAN_UNABLE_TO_JUDGE = "HUMAN_UNABLE_TO_JUDGE"
    AI_UNABLE_TO_JUDGE = "AI_UNABLE_TO_JUDGE"
    AI_SYSTEM_ERROR = "AI_SYSTEM_ERROR"
    HUMAN_AI_DISAGREEMENT = "HUMAN_AI_DISAGREEMENT"
    HUMAN_DETECTED_DIFFERENCE = "HUMAN_DETECTED_DIFFERENCE"
    AI_DETECTED_DIFFERENCE = "AI_DETECTED_DIFFERENCE"
    DETERMINISTIC_COMPARISON_NOT_EXACT = "DETERMINISTIC_COMPARISON_NOT_EXACT"


@dataclass(frozen=True)
class ReviewSignals:
    """Signals already produced for one expected parameter."""

    parameter_id: str
    human_verdict: HumanVerdict
    ai_verdict: AiVerdict
    comparison_kind: ComparisonKind
    is_critical: bool = False
    image_quality: ImageQuality = ImageQuality.ACCEPTABLE
    field_issues: tuple[FieldIssue, ...] = ()


@dataclass(frozen=True)
class RoutingDecision:
    """A deterministic explanation of where the parameter goes next."""

    parameter_id: str
    route: ReviewRoute
    reasons: tuple[RouteReason, ...]

    @property
    def automatic_release_allowed(self) -> bool:
        """AI-assisted routing never grants a final release decision."""

        return False


_FIELD_ISSUE_REASON = {
    FieldIssue.MISSING_EXPECTED_FIELD: RouteReason.MISSING_EXPECTED_FIELD,
    FieldIssue.DUPLICATE_EXPECTED_FIELD: RouteReason.DUPLICATE_EXPECTED_FIELD,
    FieldIssue.UNKNOWN_FIELD: RouteReason.UNKNOWN_FIELD,
}


def _validate_signals(signals: ReviewSignals) -> None:
    if not isinstance(signals, ReviewSignals):
        raise TypeError("signals must be a ReviewSignals instance")
    if not isinstance(signals.parameter_id, str):
        raise TypeError("parameter_id must be str")
    if signals.parameter_id.strip() == "":
        raise ValueError("parameter_id must not be empty or whitespace")
    if not isinstance(signals.human_verdict, HumanVerdict):
        raise TypeError("human_verdict must be a HumanVerdict")
    if not isinstance(signals.ai_verdict, AiVerdict):
        raise TypeError("ai_verdict must be an AiVerdict")
    if not isinstance(signals.comparison_kind, ComparisonKind):
        raise TypeError("comparison_kind must be a ComparisonKind")
    if type(signals.is_critical) is not bool:
        raise TypeError("is_critical must be bool")
    if not isinstance(signals.image_quality, ImageQuality):
        raise TypeError("image_quality must be an ImageQuality")
    if not isinstance(signals.field_issues, tuple):
        raise TypeError("field_issues must be a tuple of FieldIssue values")
    if any(not isinstance(issue, FieldIssue) for issue in signals.field_issues):
        raise TypeError("field_issues must contain only FieldIssue values")
    if len(set(signals.field_issues)) != len(signals.field_issues):
        raise ValueError("field_issues must not contain duplicates")


def route_parameter(signals: ReviewSignals) -> RoutingDecision:
    """Route one parameter using fixed, auditable rules.

    Structural alignment problems take the QA route.  Every other concern
    takes an independent second-review route.  Only a non-critical field with
    acceptable image quality, no schema issue, two SAME verdicts, and a strict
    exact comparison receives NO_EXCEPTION_DETECTED.  That label still does
    not mean valid, approved, or released.
    """

    _validate_signals(signals)
    reasons: list[RouteReason] = []

    for issue in signals.field_issues:
        reasons.append(_FIELD_ISSUE_REASON[issue])

    if signals.image_quality is ImageQuality.LOW:
        reasons.append(RouteReason.LOW_IMAGE_QUALITY)
    elif signals.image_quality is ImageQuality.UNREADABLE:
        reasons.append(RouteReason.UNREADABLE_IMAGE)

    if signals.is_critical:
        reasons.append(RouteReason.CRITICAL_PARAMETER)

    if signals.human_verdict is HumanVerdict.UNABLE_TO_JUDGE:
        reasons.append(RouteReason.HUMAN_UNABLE_TO_JUDGE)
    if signals.ai_verdict is AiVerdict.UNABLE_TO_JUDGE:
        reasons.append(RouteReason.AI_UNABLE_TO_JUDGE)
    if signals.ai_verdict is AiVerdict.SYSTEM_ERROR:
        reasons.append(RouteReason.AI_SYSTEM_ERROR)

    judged_human = signals.human_verdict is not HumanVerdict.UNABLE_TO_JUDGE
    judged_ai = signals.ai_verdict not in (
        AiVerdict.UNABLE_TO_JUDGE,
        AiVerdict.SYSTEM_ERROR,
    )
    if judged_human and judged_ai:
        verdicts_agree = signals.human_verdict.value == signals.ai_verdict.value
        if not verdicts_agree:
            reasons.append(RouteReason.HUMAN_AI_DISAGREEMENT)

    if signals.human_verdict is HumanVerdict.DIFFERENT:
        reasons.append(RouteReason.HUMAN_DETECTED_DIFFERENCE)
    if signals.ai_verdict is AiVerdict.DIFFERENT:
        reasons.append(RouteReason.AI_DETECTED_DIFFERENCE)
    if signals.comparison_kind is not ComparisonKind.EXACT_MATCH:
        reasons.append(RouteReason.DETERMINISTIC_COMPARISON_NOT_EXACT)

    if signals.field_issues or signals.ai_verdict is AiVerdict.SYSTEM_ERROR:
        route = ReviewRoute.QA_REVIEW_REQUIRED
    elif reasons:
        route = ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED
    else:
        route = ReviewRoute.NO_EXCEPTION_DETECTED

    return RoutingDecision(
        parameter_id=signals.parameter_id,
        route=route,
        reasons=tuple(reasons),
    )
