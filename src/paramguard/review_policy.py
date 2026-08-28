"""Versioned post-lock review-policy profiles.

The low-level :mod:`paramguard.routing` module deliberately expresses a very
conservative route.  This module projects the same trusted ``ReviewSignals``
into an explicit *process profile* without weakening the human-first gate:

* R1 must already be complete and locked before these post-lock signals exist;
* an AI ``SAME`` observation never authorises release;
* structural or AI-system failures always go to QA;
* every profile makes its critical-parameter treatment explicit.

The function here is pure.  It does not read a task, mutate a workflow, or
prove that R1 was locked; callers must enforce those state-machine controls.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re

from .routing import ReviewRoute, ReviewSignals, RouteReason, route_parameter


REVIEW_POLICY_SCHEMA_VERSION = 1

_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ReviewPolicyId(str, Enum):
    """Named policy families; neither name claims to be an external SOP."""

    INTERVIEW_TARGETED_RECHECK = "INTERVIEW_TARGETED_RECHECK"
    CONSERVATIVE_BLIND_R2 = "CONSERVATIVE_BLIND_R2"


class ReviewNextStep(str, Enum):
    """Fixed human-controlled next steps after R1 lock and AI processing."""

    WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION = (
        "WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION"
    )
    TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK = (
        "TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK"
    )
    FULL_MANIFEST_BLIND_SECOND_REVIEW = "FULL_MANIFEST_BLIND_SECOND_REVIEW"
    QA_STRUCTURAL_OR_SYSTEM_REVIEW = "QA_STRUCTURAL_OR_SYSTEM_REVIEW"
    QA_CRITICAL_POLICY_CONFIRMATION = "QA_CRITICAL_POLICY_CONFIRMATION"


_EXCEPTION_STEPS = frozenset(
    {
        ReviewNextStep.TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK,
        ReviewNextStep.FULL_MANIFEST_BLIND_SECOND_REVIEW,
    }
)

_CRITICAL_STEPS = frozenset(
    {
        ReviewNextStep.TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK,
        ReviewNextStep.FULL_MANIFEST_BLIND_SECOND_REVIEW,
        ReviewNextStep.QA_CRITICAL_POLICY_CONFIRMATION,
    }
)

_STEP_PRIORITY = {
    ReviewNextStep.WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION: 0,
    ReviewNextStep.TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK: 1,
    ReviewNextStep.FULL_MANIFEST_BLIND_SECOND_REVIEW: 2,
    ReviewNextStep.QA_CRITICAL_POLICY_CONFIRMATION: 3,
    ReviewNextStep.QA_STRUCTURAL_OR_SYSTEM_REVIEW: 4,
}


@dataclass(frozen=True, slots=True)
class ReviewPolicyProfile:
    """Immutable configuration for mapping trusted route facts to a next step.

    ``critical_parameter_next_step`` is intentionally required rather than
    inferred.  A real organisation must select it from its approved SOP and
    risk assessment; this PoC cannot discover that rule from an interview.
    """

    profile_id: ReviewPolicyId
    policy_version: str
    exception_next_step: ReviewNextStep
    critical_parameter_next_step: ReviewNextStep

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, ReviewPolicyId):
            raise TypeError("profile_id must be a ReviewPolicyId")
        if not isinstance(self.policy_version, str):
            raise TypeError("policy_version must be str")
        if _VERSION_PATTERN.fullmatch(self.policy_version) is None:
            raise ValueError(
                "policy_version must be a safe 1-128 character identifier"
            )
        if not isinstance(self.exception_next_step, ReviewNextStep):
            raise TypeError("exception_next_step must be a ReviewNextStep")
        if self.exception_next_step not in _EXCEPTION_STEPS:
            raise ValueError(
                "exception_next_step must be targeted post-lock recheck or "
                "full-manifest blind second review"
            )
        if not isinstance(self.critical_parameter_next_step, ReviewNextStep):
            raise TypeError(
                "critical_parameter_next_step must be a ReviewNextStep"
            )
        if self.critical_parameter_next_step not in _CRITICAL_STEPS:
            raise ValueError(
                "critical_parameter_next_step must explicitly require "
                "targeted recheck, full-manifest blind R2, or QA policy "
                "confirmation"
            )

    def to_record(self) -> dict[str, object]:
        """Return the canonical, JSON-safe policy record used for hashing."""

        return {
            "review_policy_schema_version": REVIEW_POLICY_SCHEMA_VERSION,
            "profile_id": self.profile_id.value,
            "policy_version": self.policy_version,
            "exception_next_step": self.exception_next_step.value,
            "critical_parameter_next_step": (
                self.critical_parameter_next_step.value
            ),
            "structural_or_system_next_step": (
                ReviewNextStep.QA_STRUCTURAL_OR_SYSTEM_REVIEW.value
            ),
            "no_exception_next_step": (
                ReviewNextStep.WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION.value
            ),
            "r1_lock_required_before_ai": True,
            "automatic_release_allowed": False,
        }

    @property
    def content_sha256(self) -> str:
        canonical = json.dumps(
            self.to_record(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


INTERVIEW_TARGETED_RECHECK = ReviewPolicyProfile(
    profile_id=ReviewPolicyId.INTERVIEW_TARGETED_RECHECK,
    policy_version="1.0",
    exception_next_step=(
        ReviewNextStep.TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK
    ),
    # The interview description does not establish the real critical-field
    # SOP.  Fail closed to a QA policy decision instead of silently guessing
    # either "no extra check" or "repeat the entire manifest".
    critical_parameter_next_step=(
        ReviewNextStep.QA_CRITICAL_POLICY_CONFIRMATION
    ),
)


CONSERVATIVE_BLIND_R2 = ReviewPolicyProfile(
    profile_id=ReviewPolicyId.CONSERVATIVE_BLIND_R2,
    policy_version="1.0",
    exception_next_step=ReviewNextStep.FULL_MANIFEST_BLIND_SECOND_REVIEW,
    critical_parameter_next_step=(
        ReviewNextStep.FULL_MANIFEST_BLIND_SECOND_REVIEW
    ),
)


@dataclass(frozen=True, slots=True)
class ReviewPolicyDecision:
    """One deterministic post-lock process decision for one parameter."""

    parameter_id: str
    profile_id: ReviewPolicyId
    profile_version: str
    profile_content_sha256: str
    next_step: ReviewNextStep
    reasons: tuple[RouteReason, ...]

    @property
    def automatic_release_allowed(self) -> bool:
        """No policy projection can approve, release, or close an exception."""

        return False


def decide_post_lock_next_step(
    signals: ReviewSignals,
    profile: ReviewPolicyProfile = INTERVIEW_TARGETED_RECHECK,
) -> ReviewPolicyDecision:
    """Map trusted post-lock signals through a versioned review profile.

    Priority is fail-closed and independent of input ordering:

    1. structural or AI-system failure -> QA;
    2. otherwise, select the stricter of the profile's ordinary-exception and
       critical-parameter controls;
    3. a clean, non-critical observation only waits for the final human
       process confirmation.

    This function cannot itself verify workflow state.  The caller must only
    construct ``ReviewSignals`` after the complete R1 decision set is locked
    and the permitted AI run has finished.
    """

    if not isinstance(profile, ReviewPolicyProfile):
        raise TypeError("profile must be a ReviewPolicyProfile")

    # Reuse the existing validated route facts instead of reimplementing or
    # trusting caller-supplied reason labels.
    route_facts = route_parameter(signals)
    reasons = route_facts.reasons

    if route_facts.route is ReviewRoute.QA_REVIEW_REQUIRED:
        next_step = ReviewNextStep.QA_STRUCTURAL_OR_SYSTEM_REVIEW
    else:
        candidates = [ReviewNextStep.WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION]
        noncritical_reasons = tuple(
            reason
            for reason in reasons
            if reason is not RouteReason.CRITICAL_PARAMETER
        )
        if noncritical_reasons:
            candidates.append(profile.exception_next_step)
        if RouteReason.CRITICAL_PARAMETER in reasons:
            candidates.append(profile.critical_parameter_next_step)
        next_step = max(candidates, key=_STEP_PRIORITY.__getitem__)

    return ReviewPolicyDecision(
        parameter_id=route_facts.parameter_id,
        profile_id=profile.profile_id,
        profile_version=profile.policy_version,
        profile_content_sha256=profile.content_sha256,
        next_step=next_step,
        reasons=reasons,
    )
