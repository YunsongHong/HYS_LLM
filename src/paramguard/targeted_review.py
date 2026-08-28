"""Fail-closed, post-AI human recheck of only the routed exception fields.

This aggregate implements the interview-inspired *targeted* profile.  It is
created from a completed :class:`~paramguard.workflow.ReviewTask`, freezes the
source evidence, recomputes routing itself, and gives its assigned human only
the fields selected by the versioned policy.  It is intentionally not the
structurally blind, full-manifest review implemented by ``blind_review``.

The in-process ``RLock``, revision checks, and idempotency records are useful
domain controls for a learning PoC.  They are not durable transactions,
authentication, electronic signatures, or an audit archive.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from threading import RLock
from types import MappingProxyType
from typing import Any, Protocol

from .comparison import ComparisonKind, ComparisonResult, compare_values
from .evidence import EvidenceArtifact, EvidenceManifest
from .identity import Actor, PrincipalKind, Role
from .pipeline import PipelineSpec
from .review_policy import (
    INTERVIEW_TARGETED_RECHECK,
    ReviewNextStep,
    ReviewPolicyDecision,
    ReviewPolicyId,
    ReviewPolicyProfile,
    decide_post_lock_next_step,
)
from .routing import (
    FieldIssue,
    ImageQuality,
    ReviewSignals,
    RouteReason,
    RoutingDecision,
    route_parameter,
)
from .workflow import (
    AiAssessment,
    AiRun,
    AiVerdict,
    HumanDecision,
    HumanVerdict,
    ReviewState,
    ReviewTask,
    WorkflowMode,
)


class TargetedReviewState(str, Enum):
    OPEN = "OPEN"
    LOCKED = "LOCKED"


class TargetedVerdict(str, Enum):
    """A new human observation; it never replaces R1 or approves the task."""

    SAME = "SAME"
    DIFFERENT = "DIFFERENT"
    UNABLE_TO_JUDGE = "UNABLE_TO_JUDGE"


class TargetedReviewError(Exception):
    code = "TARGETED_REVIEW_ERROR"


class TargetedSourceStateError(TargetedReviewError):
    code = "TARGETED_SOURCE_STATE_ERROR"


class TargetedSourceBindingError(TargetedReviewError):
    code = "TARGETED_SOURCE_BINDING_ERROR"


class UnsupportedTargetedProfileError(TargetedReviewError):
    code = "UNSUPPORTED_TARGETED_PROFILE"


class TargetedRoutingSchemaError(TargetedReviewError):
    code = "TARGETED_ROUTING_SCHEMA_ERROR"

    def __init__(
        self,
        message: str,
        *,
        missing_parameter_ids: tuple[str, ...] = (),
        unknown_parameter_ids: tuple[str, ...] = (),
        duplicate_parameter_ids: tuple[str, ...] = (),
    ) -> None:
        self.missing_parameter_ids = missing_parameter_ids
        self.unknown_parameter_ids = unknown_parameter_ids
        self.duplicate_parameter_ids = duplicate_parameter_ids
        super().__init__(message)


class TargetedRoutingContextBindingError(TargetedReviewError):
    code = "TARGETED_ROUTING_CONTEXT_BINDING_ERROR"


class TargetedSubmissionBindingError(TargetedReviewError):
    code = "TARGETED_SUBMISSION_BINDING_ERROR"


class UnauthorizedTargetedReviewerError(TargetedReviewError):
    code = "UNAUTHORIZED_TARGETED_REVIEWER"


class TargetedTaskBindingError(TargetedReviewError):
    code = "TARGETED_TASK_BINDING_ERROR"


class TargetedAssignmentBindingError(TargetedReviewError):
    code = "TARGETED_ASSIGNMENT_BINDING_ERROR"


class TargetedEvidenceBindingError(TargetedReviewError):
    code = "TARGETED_EVIDENCE_BINDING_ERROR"


class TargetedSnapshotBindingError(TargetedReviewError):
    code = "TARGETED_SNAPSHOT_BINDING_ERROR"


class UnknownTargetedParameterError(TargetedReviewError):
    code = "UNKNOWN_TARGETED_PARAMETER"


class TargetedReasonRequiredError(TargetedReviewError):
    code = "TARGETED_REASON_REQUIRED"


class IncompleteTargetedReviewError(TargetedReviewError):
    code = "INCOMPLETE_TARGETED_REVIEW"

    def __init__(self, missing_parameter_ids: tuple[str, ...]) -> None:
        self.missing_parameter_ids = missing_parameter_ids
        super().__init__(
            "Targeted review is incomplete; missing: "
            + ", ".join(missing_parameter_ids)
        )


class TargetedReviewLockedError(TargetedReviewError):
    code = "TARGETED_REVIEW_LOCKED"


class StaleTargetedReviewRevisionError(TargetedReviewError):
    code = "STALE_TARGETED_REVIEW_REVISION"


class DuplicateTargetedCommandConflictError(TargetedReviewError):
    code = "DUPLICATE_TARGETED_COMMAND_CONFLICT"


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_REASON_LENGTH = 1000


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe 1-128 character identifier")
    return value


def _require_sha256(name: str, value: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"{name} must contain 64 lowercase hexadecimal characters"
        )
    return value


def _require_reason(reason: str | None) -> str | None:
    if reason is None:
        return None
    if not isinstance(reason, str):
        raise TypeError("reason must be str or None")
    if reason.strip() == "":
        raise ValueError("reason must not be empty or whitespace")
    if len(reason) > _MAX_REASON_LENGTH:
        raise ValueError(
            f"reason must not exceed {_MAX_REASON_LENGTH} characters"
        )
    return reason


def _aware_utc(name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include timezone information")
    return value.astimezone(timezone.utc)


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class LockedParameterRoutingContext:
    """Trusted non-AI routing facts for one frozen expected field.

    Human/AI verdicts and deterministic-comparison facts are deliberately not
    accepted here: ``TargetedReviewSession`` derives those from the completed
    ``ReviewTask``.  This record carries only facts that must come from a
    separately controlled schema/quality/criticality source.
    """

    parameter_id: str
    is_critical: bool = False
    image_quality: ImageQuality = ImageQuality.ACCEPTABLE
    field_issues: tuple[FieldIssue, ...] = ()

    def __post_init__(self) -> None:
        _require_identifier("routing parameter_id", self.parameter_id)
        if type(self.is_critical) is not bool:
            raise TypeError("is_critical must be bool")
        if not isinstance(self.image_quality, ImageQuality):
            raise TypeError("image_quality must be an ImageQuality")
        if not isinstance(self.field_issues, tuple):
            raise TypeError("field_issues must be a tuple of FieldIssue values")
        if any(not isinstance(issue, FieldIssue) for issue in self.field_issues):
            raise TypeError("field_issues must contain only FieldIssue values")
        if len(set(self.field_issues)) != len(self.field_issues):
            raise ValueError("field_issues must not contain duplicates")

    def to_record(self) -> dict[str, object]:
        return {
            "parameter_id": self.parameter_id,
            "is_critical": self.is_critical,
            "image_quality": self.image_quality.value,
            "field_issues": [issue.value for issue in self.field_issues],
        }


@dataclass(frozen=True, slots=True)
class LockedRoutingContext:
    """Write-once resolver result bound to one task and evidence manifest."""

    context_id: str
    context_version: str
    task_id: str
    evidence_manifest_hash: str
    locked_at: datetime
    parameters: tuple[LockedParameterRoutingContext, ...]

    def __post_init__(self) -> None:
        _require_identifier("context_id", self.context_id)
        _require_identifier("context_version", self.context_version)
        _require_identifier("routing task_id", self.task_id)
        _require_sha256(
            "routing evidence_manifest_hash", self.evidence_manifest_hash
        )
        _aware_utc("routing locked_at", self.locked_at)
        if not isinstance(self.parameters, tuple):
            raise TypeError(
                "routing parameters must be a tuple of "
                "LockedParameterRoutingContext values"
            )
        if any(
            type(item) is not LockedParameterRoutingContext
            for item in self.parameters
        ):
            raise TypeError(
                "routing parameters must contain only "
                "LockedParameterRoutingContext values"
            )
        ids = tuple(item.parameter_id for item in self.parameters)
        if len(ids) != len(set(ids)):
            raise ValueError("routing parameters must not contain duplicates")

    def to_record(self) -> dict[str, object]:
        return {
            "routing_context_schema_version": 1,
            "context_id": self.context_id,
            "context_version": self.context_version,
            "task_id": self.task_id,
            "evidence_manifest_hash": self.evidence_manifest_hash,
            "locked_at": self.locked_at.astimezone(timezone.utc).isoformat(),
            "parameters": [item.to_record() for item in self.parameters],
        }

    @property
    def content_sha256(self) -> str:
        return _canonical_hash(self.to_record())


class TrustedRoutingContextResolver(Protocol):
    """Composition-root trust boundary for locked upstream routing facts.

    A Web request must never be allowed to choose or implement this resolver.
    A production adapter would resolve a write-once row/version from trusted
    storage.  The protocol itself is not authentication or a signature.
    """

    def resolve_locked_context(
        self,
        *,
        task_id: str,
        evidence_manifest_hash: str,
        expected_parameter_ids: tuple[str, ...],
    ) -> LockedRoutingContext: ...


@dataclass(frozen=True, slots=True)
class TargetedReviewItem:
    """One internally selected field shown in the targeted human queue."""

    parameter_id: str
    reasons: tuple[RouteReason, ...]
    primary_verdict: HumanVerdict
    ai_verdict: AiVerdict
    comparison_kind: ComparisonKind
    next_step: ReviewNextStep

    @property
    def automatic_release_allowed(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class TargetedQaReferral:
    """A field held outside the targeted queue for an explicit QA path."""

    parameter_id: str
    reasons: tuple[RouteReason, ...]
    next_step: ReviewNextStep

    @property
    def automatic_release_allowed(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class TargetedQueuePlan:
    """Immutable result of canonical routing and policy projection."""

    targeted_case_id: str
    task_id: str
    assignment_id: str
    assigned_reviewer_id: str
    evidence_manifest_hash: str
    routing_context_id: str
    routing_context_version: str
    routing_context_sha256: str
    source_snapshot_sha256: str
    profile_id: ReviewPolicyId
    profile_version: str
    profile_content_sha256: str
    targeted_items: tuple[TargetedReviewItem, ...]
    qa_referrals: tuple[TargetedQaReferral, ...]
    no_exception_parameter_ids: tuple[str, ...]

    @property
    def automatic_release_allowed(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class TargetedReviewPacket:
    """Allowlist DTO for the assigned post-lock reviewer."""

    targeted_case_id: str
    task_id: str
    assignment_id: str
    assigned_reviewer_id: str
    evidence_manifest: EvidenceManifest
    evidence_manifest_hash: str
    routing_context_id: str
    routing_context_version: str
    routing_context_sha256: str
    source_snapshot_sha256: str
    profile_id: ReviewPolicyId
    profile_version: str
    profile_content_sha256: str
    targeted_items: tuple[TargetedReviewItem, ...]
    revision: int

    @property
    def automatic_release_allowed(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class TargetedReviewDecision:
    parameter_id: str
    verdict: TargetedVerdict
    reason: str | None
    reviewer_id: str
    decided_at: datetime
    task_id: str
    assignment_id: str
    evidence_manifest_hash: str
    source_snapshot_sha256: str

    @property
    def automatic_release_allowed(self) -> bool:
        return False

    @property
    def closes_exception(self) -> bool:
        """A targeted observation never disposes the source exception."""

        return False


@dataclass(frozen=True, slots=True)
class LockedTargetedReviewSubmission:
    """Complete targeted-review snapshot; never a final approval artifact."""

    targeted_case_id: str
    task_id: str
    assignment_id: str
    reviewer_id: str
    evidence_manifest_hash: str
    expected_parameter_ids: tuple[str, ...]
    routing_context_id: str
    routing_context_version: str
    routing_context_sha256: str
    source_snapshot_sha256: str
    profile_id: ReviewPolicyId
    profile_version: str
    profile_content_sha256: str
    targeted_items: tuple[TargetedReviewItem, ...]
    decisions: tuple[TargetedReviewDecision, ...]
    qa_referrals: tuple[TargetedQaReferral, ...]
    no_exception_parameter_ids: tuple[str, ...]
    locked_at: datetime
    submission_hash: str

    @property
    def automatic_release_allowed(self) -> bool:
        return False

    @property
    def requires_qa(self) -> bool:
        return bool(self.qa_referrals) or any(
            item.verdict is not TargetedVerdict.SAME for item in self.decisions
        )

    @property
    def final_human_confirmation_required(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class _StoredCommand:
    payload_hash: str
    result: Any


def _locked_submission_payload(
    *,
    targeted_case_id: str,
    task_id: str,
    assignment_id: str,
    reviewer_id: str,
    evidence_manifest_hash: str,
    expected_parameter_ids: tuple[str, ...],
    routing_context_id: str,
    routing_context_version: str,
    routing_context_sha256: str,
    source_snapshot_sha256: str,
    profile_id: ReviewPolicyId,
    profile_version: str,
    profile_content_sha256: str,
    targeted_items: tuple[TargetedReviewItem, ...],
    decisions: tuple[TargetedReviewDecision, ...],
    qa_referrals: tuple[TargetedQaReferral, ...],
    no_exception_parameter_ids: tuple[str, ...],
    locked_at: datetime,
) -> dict[str, Any]:
    return {
        "targeted_submission_version": 2,
        "targeted_case_id": targeted_case_id,
        "task_id": task_id,
        "assignment_id": assignment_id,
        "reviewer_id": reviewer_id,
        "evidence_manifest_hash": evidence_manifest_hash,
        "expected_parameter_ids": list(expected_parameter_ids),
        "routing_context_id": routing_context_id,
        "routing_context_version": routing_context_version,
        "routing_context_sha256": routing_context_sha256,
        "source_snapshot_sha256": source_snapshot_sha256,
        "profile_id": profile_id.value,
        "profile_version": profile_version,
        "profile_content_sha256": profile_content_sha256,
        "targeted_items": [
            {
                "parameter_id": item.parameter_id,
                "reasons": [reason.value for reason in item.reasons],
                "primary_verdict": item.primary_verdict.value,
                "ai_verdict": item.ai_verdict.value,
                "comparison_kind": item.comparison_kind.value,
                "next_step": item.next_step.value,
            }
            for item in targeted_items
        ],
        "decisions": [
            {
                "parameter_id": item.parameter_id,
                "verdict": item.verdict.value,
                "reason": item.reason,
                "reviewer_id": item.reviewer_id,
                "decided_at": item.decided_at.isoformat(),
                "task_id": item.task_id,
                "assignment_id": item.assignment_id,
                "evidence_manifest_hash": item.evidence_manifest_hash,
                "source_snapshot_sha256": item.source_snapshot_sha256,
            }
            for item in decisions
        ],
        "qa_referrals": [
            {
                "parameter_id": item.parameter_id,
                "reasons": [reason.value for reason in item.reasons],
                "next_step": item.next_step.value,
            }
            for item in qa_referrals
        ],
        "no_exception_parameter_ids": list(no_exception_parameter_ids),
        "locked_at": locked_at.isoformat(),
        "automatic_release_allowed": False,
        "final_human_confirmation_required": True,
    }


def canonical_locked_targeted_submission_record(
    submission: LockedTargetedReviewSubmission,
) -> dict[str, Any]:
    """Return the one canonical JSON-shaped record for a locked submission.

    This helper deliberately accepts only the exact frozen domain type.  It
    does *not* establish trust in a caller-provided submission: downstream
    code must still obtain the expected source and submission hashes from its
    trusted resolver and call :func:`validate_locked_targeted_submission`.
    Keeping the serializer public avoids subtly different audit, persistence,
    and domain hash representations.
    """

    if type(submission) is not LockedTargetedReviewSubmission:
        raise TypeError(
            "submission must be an exact LockedTargetedReviewSubmission"
        )
    locked_at = _aware_utc("locked_at", submission.locked_at)
    return _locked_submission_payload(
        targeted_case_id=submission.targeted_case_id,
        task_id=submission.task_id,
        assignment_id=submission.assignment_id,
        reviewer_id=submission.reviewer_id,
        evidence_manifest_hash=submission.evidence_manifest_hash,
        expected_parameter_ids=submission.expected_parameter_ids,
        routing_context_id=submission.routing_context_id,
        routing_context_version=submission.routing_context_version,
        routing_context_sha256=submission.routing_context_sha256,
        source_snapshot_sha256=submission.source_snapshot_sha256,
        profile_id=submission.profile_id,
        profile_version=submission.profile_version,
        profile_content_sha256=submission.profile_content_sha256,
        targeted_items=submission.targeted_items,
        decisions=submission.decisions,
        qa_referrals=submission.qa_referrals,
        no_exception_parameter_ids=submission.no_exception_parameter_ids,
        locked_at=locked_at,
    )


class TargetedReviewSession:
    """Revisioned aggregate for a post-AI, exception-only human recheck."""

    def __init__(
        self,
        *,
        targeted_case_id: str,
        source_review_task: ReviewTask,
        routing_context_resolver: TrustedRoutingContextResolver,
        profile: ReviewPolicyProfile,
        assignment_id: str,
        assigned_reviewer: Actor,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._targeted_case_id = _require_identifier(
            "targeted_case_id", targeted_case_id
        )
        self._assignment_id = _require_identifier("assignment_id", assignment_id)
        self._validate_reviewer(assigned_reviewer)
        if not callable(clock):
            raise TypeError("clock must be callable")
        if type(profile) is not ReviewPolicyProfile:
            raise TypeError("profile must be a ReviewPolicyProfile")
        if profile != INTERVIEW_TARGETED_RECHECK:
            raise UnsupportedTargetedProfileError(
                "TargetedReviewSession accepts only the frozen "
                "INTERVIEW_TARGETED_RECHECK profile"
            )
        (
            self._task_id,
            self._manifest,
            self._manifest_hash,
            self._expected_parameter_ids,
            self._primary_reviewer_id,
            self._human_locked_at,
            self._primary_decisions,
            self._pipeline_spec,
            self._ai_run,
            self._ai_assessments,
        ) = self._capture_completed_review(source_review_task)
        self._expected_parameter_id_set = frozenset(self._expected_parameter_ids)
        self._assigned_reviewer = assigned_reviewer
        self._assigned_reviewer_id = assigned_reviewer.actor_id
        self._profile = profile
        self._routing_context = self._resolve_routing_context(
            routing_context_resolver
        )
        self._routing_context_sha256 = self._routing_context.content_sha256
        self._signals = self._signals_from_routing_context()

        # The resolver may perform I/O.  Re-capture the source after it returns
        # and fail closed if any source field changed during that window.
        captured_again = self._capture_completed_review(source_review_task)
        captured_initial = (
            self._task_id,
            self._manifest,
            self._manifest_hash,
            self._expected_parameter_ids,
            self._primary_reviewer_id,
            self._human_locked_at,
            self._primary_decisions,
            self._pipeline_spec,
            self._ai_run,
            self._ai_assessments,
        )
        if captured_again != captured_initial:
            raise TargetedSourceBindingError(
                "Source review changed while routing context was resolved"
            )
        (
            self._routing_decisions,
            self._policy_decisions,
            targeted_items,
            qa_referrals,
            no_exception_parameter_ids,
        ) = self._compute_plan()
        self._source_snapshot_sha256 = self._calculate_source_snapshot_hash()
        self._plan = TargetedQueuePlan(
            targeted_case_id=self._targeted_case_id,
            task_id=self._task_id,
            assignment_id=self._assignment_id,
            assigned_reviewer_id=self._assigned_reviewer_id,
            evidence_manifest_hash=self._manifest_hash,
            routing_context_id=self._routing_context.context_id,
            routing_context_version=self._routing_context.context_version,
            routing_context_sha256=self._routing_context_sha256,
            source_snapshot_sha256=self._source_snapshot_sha256,
            profile_id=self._profile.profile_id,
            profile_version=self._profile.policy_version,
            profile_content_sha256=self._profile.content_sha256,
            targeted_items=targeted_items,
            qa_referrals=qa_referrals,
            no_exception_parameter_ids=no_exception_parameter_ids,
        )

        self._targeted_parameter_ids = tuple(
            item.parameter_id for item in self._plan.targeted_items
        )
        self._targeted_parameter_id_set = frozenset(
            self._targeted_parameter_ids
        )
        self._clock = clock
        self._latest_time = max(
            self._human_locked_at,
            self._routing_context.locked_at,
            *(item.assessed_at for item in self._ai_assessments.values()),
        )
        self._lock = RLock()
        self._state = TargetedReviewState.OPEN
        self._revision = 0
        self._decisions: dict[str, TargetedReviewDecision] = {}
        self._decision_history: list[TargetedReviewDecision] = []
        self._commands: dict[str, _StoredCommand] = {}
        self._locked_submission: LockedTargetedReviewSubmission | None = None

    @property
    def state(self) -> TargetedReviewState:
        with self._lock:
            return self._state

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    @property
    def task_id(self) -> str:
        return self._task_id

    @property
    def assignment_id(self) -> str:
        return self._assignment_id

    @property
    def evidence_manifest_hash(self) -> str:
        return self._manifest_hash

    @property
    def source_snapshot_sha256(self) -> str:
        return self._source_snapshot_sha256

    def queue_plan(self) -> TargetedQueuePlan:
        return self._plan

    def packet(self, *, actor: Actor) -> TargetedReviewPacket:
        with self._lock:
            self._authorize(actor)
            return TargetedReviewPacket(
                targeted_case_id=self._targeted_case_id,
                task_id=self._task_id,
                assignment_id=self._assignment_id,
                assigned_reviewer_id=self._assigned_reviewer_id,
                evidence_manifest=self._manifest,
                evidence_manifest_hash=self._manifest_hash,
                routing_context_id=self._routing_context.context_id,
                routing_context_version=self._routing_context.context_version,
                routing_context_sha256=self._routing_context_sha256,
                source_snapshot_sha256=self._source_snapshot_sha256,
                profile_id=self._profile.profile_id,
                profile_version=self._profile.policy_version,
                profile_content_sha256=self._profile.content_sha256,
                targeted_items=self._plan.targeted_items,
                revision=self._revision,
            )

    def own_decisions(
        self, *, actor: Actor
    ) -> Mapping[str, TargetedReviewDecision]:
        with self._lock:
            self._authorize(actor)
            return MappingProxyType(dict(self._decisions))

    def own_decision_history(
        self, *, actor: Actor
    ) -> tuple[TargetedReviewDecision, ...]:
        with self._lock:
            self._authorize(actor)
            return tuple(self._decision_history)

    def missing_parameter_ids(self, *, actor: Actor) -> tuple[str, ...]:
        with self._lock:
            self._authorize(actor)
            return tuple(
                parameter_id
                for parameter_id in self._targeted_parameter_ids
                if parameter_id not in self._decisions
            )

    def record_decision(
        self,
        *,
        actor: Actor,
        task_id: str,
        assignment_id: str,
        evidence_manifest_hash: str,
        source_snapshot_sha256: str,
        parameter_id: str,
        verdict: TargetedVerdict,
        command_id: str,
        expected_revision: int,
        reason: str | None = None,
    ) -> TargetedReviewDecision:
        """Record or revise one selected field before the targeted lock."""

        with self._lock:
            self._authorize(actor)
            checked_task_id = self._require_task_id(task_id)
            checked_assignment_id = self._require_assignment_id(assignment_id)
            checked_manifest_hash = self._require_manifest_hash(
                evidence_manifest_hash
            )
            checked_snapshot_hash = self._require_snapshot_hash(
                source_snapshot_sha256
            )
            checked_parameter_id = _require_identifier(
                "parameter_id", parameter_id
            )
            if checked_parameter_id not in self._targeted_parameter_id_set:
                raise UnknownTargetedParameterError(
                    "Parameter is not in the internally computed targeted queue: "
                    + checked_parameter_id
                )
            if not isinstance(verdict, TargetedVerdict):
                raise TypeError("verdict must be a TargetedVerdict")
            checked_reason = _require_reason(reason)
            if checked_reason is None:
                raise TargetedReasonRequiredError(
                    "A reason is required for every targeted exception recheck"
                )
            payload = {
                "operation": "record_decision",
                "actor_id": actor.actor_id,
                "task_id": checked_task_id,
                "assignment_id": checked_assignment_id,
                "evidence_manifest_hash": checked_manifest_hash,
                "source_snapshot_sha256": checked_snapshot_hash,
                "parameter_id": checked_parameter_id,
                "verdict": verdict.value,
                "reason": checked_reason,
                "expected_revision": expected_revision,
            }
            stored = self._idempotent_result(command_id, payload)
            if stored is not None:
                assert isinstance(stored, TargetedReviewDecision)
                return stored
            self._require_open()
            self._require_revision(expected_revision)

            decision = TargetedReviewDecision(
                parameter_id=checked_parameter_id,
                verdict=verdict,
                reason=checked_reason,
                reviewer_id=self._assigned_reviewer_id,
                decided_at=self._now(),
                task_id=self._task_id,
                assignment_id=self._assignment_id,
                evidence_manifest_hash=self._manifest_hash,
                source_snapshot_sha256=self._source_snapshot_sha256,
            )
            self._decisions[checked_parameter_id] = decision
            self._decision_history.append(decision)
            self._revision += 1
            self._remember_command(command_id, payload, decision)
            return decision

    def lock(
        self,
        *,
        actor: Actor,
        task_id: str,
        assignment_id: str,
        evidence_manifest_hash: str,
        source_snapshot_sha256: str,
        command_id: str,
        expected_revision: int,
    ) -> LockedTargetedReviewSubmission:
        """Freeze all targeted decisions while retaining every QA hold."""

        with self._lock:
            self._authorize(actor)
            checked_task_id = self._require_task_id(task_id)
            checked_assignment_id = self._require_assignment_id(assignment_id)
            checked_manifest_hash = self._require_manifest_hash(
                evidence_manifest_hash
            )
            checked_snapshot_hash = self._require_snapshot_hash(
                source_snapshot_sha256
            )
            payload = {
                "operation": "lock",
                "actor_id": actor.actor_id,
                "task_id": checked_task_id,
                "assignment_id": checked_assignment_id,
                "evidence_manifest_hash": checked_manifest_hash,
                "source_snapshot_sha256": checked_snapshot_hash,
                "expected_revision": expected_revision,
            }
            stored = self._idempotent_result(command_id, payload)
            if stored is not None:
                assert isinstance(stored, LockedTargetedReviewSubmission)
                return stored
            self._require_open()
            self._require_revision(expected_revision)
            missing = tuple(
                parameter_id
                for parameter_id in self._targeted_parameter_ids
                if parameter_id not in self._decisions
            )
            if missing:
                raise IncompleteTargetedReviewError(missing)
            if set(self._decisions) != self._targeted_parameter_id_set:
                raise TargetedReviewError(
                    "Targeted decisions do not exactly match the frozen queue"
                )
            if any(
                key != item.parameter_id
                or item.reviewer_id != self._assigned_reviewer_id
                or item.task_id != self._task_id
                or item.assignment_id != self._assignment_id
                or item.evidence_manifest_hash != self._manifest_hash
                or item.source_snapshot_sha256 != self._source_snapshot_sha256
                for key, item in self._decisions.items()
            ):
                raise TargetedReviewError(
                    "Targeted decision snapshot has inconsistent bindings"
                )

            locked_at = self._now()
            ordered = tuple(
                self._decisions[parameter_id]
                for parameter_id in self._targeted_parameter_ids
            )
            submission_hash = self._submission_hash(ordered, locked_at)
            submission = LockedTargetedReviewSubmission(
                targeted_case_id=self._targeted_case_id,
                task_id=self._task_id,
                assignment_id=self._assignment_id,
                reviewer_id=self._assigned_reviewer_id,
                evidence_manifest_hash=self._manifest_hash,
                expected_parameter_ids=self._expected_parameter_ids,
                routing_context_id=self._routing_context.context_id,
                routing_context_version=self._routing_context.context_version,
                routing_context_sha256=self._routing_context_sha256,
                source_snapshot_sha256=self._source_snapshot_sha256,
                profile_id=self._profile.profile_id,
                profile_version=self._profile.policy_version,
                profile_content_sha256=self._profile.content_sha256,
                targeted_items=self._plan.targeted_items,
                decisions=ordered,
                qa_referrals=self._plan.qa_referrals,
                no_exception_parameter_ids=(
                    self._plan.no_exception_parameter_ids
                ),
                locked_at=locked_at,
                submission_hash=submission_hash,
            )
            validate_locked_targeted_submission(
                submission,
                expected_source_snapshot_sha256=self._source_snapshot_sha256,
                expected_submission_hash=submission_hash,
            )
            self._locked_submission = submission
            self._state = TargetedReviewState.LOCKED
            self._revision += 1
            self._remember_command(command_id, payload, submission)
            return submission

    @staticmethod
    def _validate_reviewer(actor: Actor) -> None:
        if type(actor) is not Actor:
            raise TypeError("assigned_reviewer must be an Actor")
        allowed_roles = frozenset(
            {Role.PRIMARY_REVIEWER, Role.SECOND_REVIEWER}
        )
        has_reviewer_role = bool(actor.roles & allowed_roles)
        if (
            actor.kind is not PrincipalKind.HUMAN
            or not has_reviewer_role
            or not actor.roles <= allowed_roles
        ):
            raise UnauthorizedTargetedReviewerError(
                "Targeted recheck requires a HUMAN with only primary and/or "
                "second-reviewer roles"
            )

    def _authorize(self, actor: Actor) -> None:
        self._validate_reviewer(actor)
        if actor != self._assigned_reviewer:
            raise UnauthorizedTargetedReviewerError(
                "Actor identity and role claims do not match the assignment"
            )

    def _capture_completed_review(
        self, source: ReviewTask
    ) -> tuple[
        str,
        EvidenceManifest,
        str,
        tuple[str, ...],
        str,
        datetime,
        dict[str, HumanDecision],
        PipelineSpec,
        AiRun,
        dict[str, AiAssessment],
    ]:
        if type(source) is not ReviewTask:
            raise TypeError("source_review_task must be an exact ReviewTask")
        try:
            # ReviewTask does not yet expose a public atomic export.  Holding
            # its in-process lock makes these existing getters one atomic read
            # relative to every supported ReviewTask mutation.
            source_lock = source._lock
            with source_lock:
                if source.state is not ReviewState.AI_REVIEW_COMPLETE:
                    raise TargetedSourceStateError(
                        "Targeted recheck can be created only after the "
                        "complete AI run"
                    )
                if source.mode is not WorkflowMode.STRICT_SEQUENTIAL:
                    raise ValueError("source task is not STRICT_SEQUENTIAL")
                task_id = _require_identifier("source task_id", source.task_id)
                source_manifest = source.evidence_manifest
                if type(source_manifest) is not EvidenceManifest:
                    raise TypeError("source evidence is not an EvidenceManifest")
                artifacts: list[EvidenceArtifact] = []
                for artifact in source_manifest.artifacts:
                    if type(artifact) is not EvidenceArtifact:
                        raise TypeError(
                            "source manifest contains an invalid artifact"
                        )
                    artifacts.append(
                        EvidenceArtifact(
                            artifact_id=artifact.artifact_id,
                            role=artifact.role,
                            sha256=artifact.sha256,
                            byte_length=artifact.byte_length,
                            media_type=artifact.media_type,
                        )
                    )
                manifest = EvidenceManifest(
                    manifest_id=source_manifest.manifest_id,
                    schema_id=source_manifest.schema_id,
                    schema_version=source_manifest.schema_version,
                    schema_sha256=source_manifest.schema_sha256,
                    template_id=source_manifest.template_id,
                    template_version=source_manifest.template_version,
                    template_sha256=source_manifest.template_sha256,
                    expected_parameter_ids=(
                        source_manifest.expected_parameter_ids
                    ),
                    artifacts=tuple(artifacts),
                )
                manifest_hash = _require_sha256(
                    "source evidence_manifest_hash",
                    source.evidence_manifest_hash,
                )
                if manifest_hash != manifest.manifest_hash:
                    raise ValueError(
                        "source manifest hash differs from its content"
                    )
                expected_ids = manifest.expected_parameter_ids
                if source.expected_parameter_ids != expected_ids:
                    raise ValueError("source Schema differs from its manifest")
                primary_reviewer_id = _require_identifier(
                    "source reviewer_id", source.reviewer_id
                )
                locked_at_raw = source.human_locked_at
                if locked_at_raw is None:
                    raise ValueError("source has no human lock timestamp")
                locked_at = _aware_utc(
                    "source human_locked_at", locked_at_raw
                )
                primary = copy.deepcopy(dict(source.human_decisions()))
                source_pipeline_spec = source.approved_pipeline_spec
                if type(source_pipeline_spec) is not PipelineSpec:
                    raise TypeError("source pipeline is not a PipelineSpec")
                pipeline_spec = PipelineSpec(
                    spec_id=source_pipeline_spec.spec_id,
                    engine_name=source_pipeline_spec.engine_name,
                    engine_version=source_pipeline_spec.engine_version,
                    pipeline_version=source_pipeline_spec.pipeline_version,
                    comparator_version=(
                        source_pipeline_spec.comparator_version
                    ),
                    configuration_sha256=(
                        source_pipeline_spec.configuration_sha256
                    ),
                )
                ai_run = copy.deepcopy(source.revealed_ai_run())
                assessments = copy.deepcopy(
                    dict(source.revealed_ai_results())
                )
                self._validate_primary_snapshot(
                    primary,
                    expected_ids=expected_ids,
                    reviewer_id=primary_reviewer_id,
                    manifest_hash=manifest_hash,
                    locked_at=locked_at,
                )
                self._validate_ai_snapshot(
                    ai_run,
                    assessments,
                    pipeline_spec=pipeline_spec,
                    expected_ids=expected_ids,
                    manifest_hash=manifest_hash,
                    human_locked_at=locked_at,
                )
                if source.state is not ReviewState.AI_REVIEW_COMPLETE:
                    raise TargetedSourceStateError(
                        "Source review changed while its snapshot was captured"
                    )
        except TargetedReviewError:
            raise
        except Exception as error:
            raise TargetedSourceBindingError(
                f"Could not freeze completed source review: {error}"
            ) from error
        return (
            task_id,
            manifest,
            manifest_hash,
            expected_ids,
            primary_reviewer_id,
            locked_at,
            primary,
            pipeline_spec,
            ai_run,
            assessments,
        )

    @staticmethod
    def _validate_primary_snapshot(
        primary: Mapping[str, HumanDecision],
        *,
        expected_ids: tuple[str, ...],
        reviewer_id: str,
        manifest_hash: str,
        locked_at: datetime,
    ) -> None:
        keys = tuple(primary)
        if len(keys) != len(set(keys)) or set(keys) != set(expected_ids):
            raise TargetedSourceBindingError(
                "Primary decisions must exactly cover the frozen Schema"
            )
        for parameter_id in expected_ids:
            item = primary[parameter_id]
            if type(item) is not HumanDecision:
                raise TargetedSourceBindingError(
                    "Primary snapshot contains a non-HumanDecision value"
                )
            if (
                item.parameter_id != parameter_id
                or item.reviewer_id != reviewer_id
                or item.evidence_manifest_hash != manifest_hash
                or not isinstance(item.verdict, HumanVerdict)
            ):
                raise TargetedSourceBindingError(
                    "Primary decision identity or evidence is inconsistent"
                )
            decided_at = _aware_utc("primary decided_at", item.decided_at)
            if decided_at > locked_at:
                raise TargetedSourceBindingError(
                    "Primary decision occurs after the human lock"
                )
            reason = _require_reason(item.reason)
            if item.verdict is not HumanVerdict.SAME and reason is None:
                raise TargetedSourceBindingError(
                    "Exceptional primary decision has no reason"
                )

    @staticmethod
    def _validate_ai_snapshot(
        run: AiRun,
        assessments: Mapping[str, AiAssessment],
        *,
        pipeline_spec: PipelineSpec,
        expected_ids: tuple[str, ...],
        manifest_hash: str,
        human_locked_at: datetime,
    ) -> None:
        if type(run) is not AiRun:
            raise TargetedSourceBindingError("Source AI run has an invalid type")
        keys = tuple(assessments)
        if len(keys) != len(set(keys)) or set(keys) != set(expected_ids):
            raise TargetedSourceBindingError(
                "AI assessments must exactly cover the frozen Schema"
            )
        spec = pipeline_spec
        queued_at = _aware_utc("AI queued_at", run.queued_at)
        if run.started_at is None:
            raise TargetedSourceBindingError("Completed AI run has no start time")
        started_at = _aware_utc("AI started_at", run.started_at)
        if queued_at < human_locked_at or started_at < queued_at:
            raise TargetedSourceBindingError(
                "AI was not queued and started after the human lock"
            )
        if (
            run.evidence_manifest_hash != manifest_hash
            or run.pipeline_spec_hash != spec.spec_hash
            or run.engine_name != spec.engine_name
            or run.engine_version != spec.engine_version
            or run.pipeline_version != spec.pipeline_version
            or run.comparator_version != spec.comparator_version
        ):
            raise TargetedSourceBindingError(
                "AI run is not bound to the manifest and approved pipeline"
            )
        _require_identifier("AI run_id", run.run_id)
        for parameter_id in expected_ids:
            item = assessments[parameter_id]
            if type(item) is not AiAssessment:
                raise TargetedSourceBindingError(
                    "AI snapshot contains a non-AiAssessment value"
                )
            if (
                item.parameter_id != parameter_id
                or item.run_id != run.run_id
                or item.evidence_manifest_hash != manifest_hash
                or item.engine_name != run.engine_name
                or item.engine_version != run.engine_version
                or item.pipeline_version != run.pipeline_version
                or item.comparator_version != run.comparator_version
                or item.pipeline_spec_hash != run.pipeline_spec_hash
                or not isinstance(item.verdict, AiVerdict)
                or type(item.extraction_reliable) is not bool
            ):
                raise TargetedSourceBindingError(
                    "AI assessment identity or evidence is inconsistent"
                )
            assessed_at = _aware_utc("AI assessed_at", item.assessed_at)
            if assessed_at < started_at:
                raise TargetedSourceBindingError(
                    "AI assessment predates the AI run start"
                )
            TargetedReviewSession._validate_ai_evidence(parameter_id, item)

    @staticmethod
    def _validate_ai_evidence(parameter_id: str, item: AiAssessment) -> None:
        reason = _require_reason(item.reason)
        if item.verdict is AiVerdict.SYSTEM_ERROR:
            if (
                item.left_raw is not None
                or item.right_raw is not None
                or item.comparison_result is not None
                or item.extraction_reliable
                or reason is None
            ):
                raise TargetedSourceBindingError(
                    f"Malformed AI system error for {parameter_id}"
                )
            return
        if item.comparison_result is None:
            raise TargetedSourceBindingError(
                f"AI assessment has no deterministic comparison for {parameter_id}"
            )
        if type(item.comparison_result) is not ComparisonResult:
            raise TargetedSourceBindingError(
                f"AI assessment comparison has an invalid type for {parameter_id}"
            )
        try:
            recomputed = compare_values(item.left_raw, item.right_raw)
        except (TypeError, ValueError) as error:
            raise TargetedSourceBindingError(
                f"AI raw values are invalid for {parameter_id}: {error}"
            ) from error
        if recomputed != item.comparison_result:
            raise TargetedSourceBindingError(
                f"AI comparison differs from raw evidence for {parameter_id}"
            )
        if (
            not item.extraction_reliable
            or recomputed.kind is ComparisonKind.MISSING_VALUE
        ):
            expected_verdict = AiVerdict.UNABLE_TO_JUDGE
            if reason is None:
                raise TargetedSourceBindingError(
                    f"Unreliable AI assessment has no reason for {parameter_id}"
                )
        elif recomputed.exact_match:
            expected_verdict = AiVerdict.SAME
        else:
            expected_verdict = AiVerdict.DIFFERENT
        if item.verdict is not expected_verdict:
            raise TargetedSourceBindingError(
                f"AI verdict contradicts deterministic evidence for {parameter_id}"
            )

    def _resolve_routing_context(
        self, resolver: TrustedRoutingContextResolver
    ) -> LockedRoutingContext:
        resolve = getattr(resolver, "resolve_locked_context", None)
        if not callable(resolve):
            raise TypeError(
                "routing_context_resolver must implement "
                "resolve_locked_context()"
            )
        try:
            supplied_context = resolve(
                task_id=self._task_id,
                evidence_manifest_hash=self._manifest_hash,
                expected_parameter_ids=self._expected_parameter_ids,
            )
        except Exception as error:
            raise TargetedRoutingContextBindingError(
                f"Trusted routing-context resolution failed: {error}"
            ) from error
        if type(supplied_context) is not LockedRoutingContext:
            raise TargetedRoutingContextBindingError(
                "Resolver did not return a LockedRoutingContext"
            )
        try:
            supplied_digest_before = supplied_context.content_sha256
            if supplied_context.task_id != self._task_id:
                raise ValueError("routing context task ID differs from source")
            if supplied_context.evidence_manifest_hash != self._manifest_hash:
                raise ValueError(
                    "routing context manifest differs from source evidence"
                )
            if not isinstance(supplied_context.parameters, tuple):
                raise TypeError("routing context parameters must be tuple")
            supplied = tuple(supplied_context.parameters)
        except Exception as error:
            raise TargetedRoutingContextBindingError(
                f"Routing context is malformed: {error}"
            ) from error

        by_parameter: dict[str, LockedParameterRoutingContext] = {}
        duplicates: list[str] = []
        unknown: list[str] = []
        for item in supplied:
            if type(item) is not LockedParameterRoutingContext:
                raise TypeError(
                    "routing context must contain LockedParameterRoutingContext "
                    "values"
                )
            if type(item.is_critical) is not bool:
                raise TypeError("routing is_critical must be bool")
            if not isinstance(item.image_quality, ImageQuality):
                raise TypeError("routing image_quality has an invalid type")
            if not isinstance(item.field_issues, tuple):
                raise TypeError("routing field_issues must be tuple")
            if any(
                not isinstance(issue, FieldIssue)
                for issue in item.field_issues
            ):
                raise TypeError("routing field_issues has an invalid value")
            if len(set(item.field_issues)) != len(item.field_issues):
                raise ValueError("routing field_issues contains duplicates")
            # Reconstruct below so even an object made through private-memory
            # tricks has every strict type/tuple invariant checked again.
            parameter_id = _require_identifier(
                "routing parameter_id", item.parameter_id
            )
            if parameter_id in by_parameter:
                if parameter_id not in duplicates:
                    duplicates.append(parameter_id)
            else:
                by_parameter[parameter_id] = item
            if (
                parameter_id not in self._expected_parameter_id_set
                and parameter_id not in unknown
            ):
                unknown.append(parameter_id)
        missing = tuple(
            parameter_id
            for parameter_id in self._expected_parameter_ids
            if parameter_id not in by_parameter
        )
        if (
            missing
            or unknown
            or duplicates
            or len(supplied) != len(by_parameter)
        ):
            raise TargetedRoutingSchemaError(
                "Routing context must exactly cover the frozen Schema",
                missing_parameter_ids=missing,
                unknown_parameter_ids=tuple(unknown),
                duplicate_parameter_ids=tuple(duplicates),
            )
        supplied_ids = tuple(item.parameter_id for item in supplied)
        if supplied_ids != self._expected_parameter_ids:
            raise TargetedRoutingSchemaError(
                "Routing context must preserve frozen Schema order"
            )

        ordered_context: list[LockedParameterRoutingContext] = []
        for parameter_id in self._expected_parameter_ids:
            supplied_item = by_parameter[parameter_id]
            ordered_context.append(
                LockedParameterRoutingContext(
                    parameter_id=parameter_id,
                    is_critical=supplied_item.is_critical,
                    image_quality=supplied_item.image_quality,
                    field_issues=tuple(supplied_item.field_issues),
                )
            )
        try:
            frozen = LockedRoutingContext(
                context_id=supplied_context.context_id,
                context_version=supplied_context.context_version,
                task_id=self._task_id,
                evidence_manifest_hash=self._manifest_hash,
                locked_at=copy.deepcopy(supplied_context.locked_at),
                parameters=tuple(ordered_context),
            )
            if supplied_context.content_sha256 != supplied_digest_before:
                raise ValueError(
                    "routing context changed while it was being frozen"
                )
            return frozen
        except Exception as error:
            raise TargetedRoutingContextBindingError(
                f"Routing context could not be frozen: {error}"
            ) from error

    def _signals_from_routing_context(self) -> tuple[ReviewSignals, ...]:
        ordered: list[ReviewSignals] = []
        for supplied_item in self._routing_context.parameters:
            parameter_id = supplied_item.parameter_id
            primary = self._primary_decisions[parameter_id]
            ai = self._ai_assessments[parameter_id]
            expected_kind = (
                ComparisonKind.MISSING_VALUE
                if ai.comparison_result is None
                else ai.comparison_result.kind
            )
            canonical = ReviewSignals(
                parameter_id=parameter_id,
                human_verdict=primary.verdict,
                ai_verdict=ai.verdict,
                comparison_kind=expected_kind,
                is_critical=supplied_item.is_critical,
                image_quality=supplied_item.image_quality,
                field_issues=supplied_item.field_issues,
            )
            route_parameter(canonical)
            ordered.append(canonical)
        return tuple(ordered)

    def _compute_plan(
        self,
    ) -> tuple[
        tuple[RoutingDecision, ...],
        tuple[ReviewPolicyDecision, ...],
        tuple[TargetedReviewItem, ...],
        tuple[TargetedQaReferral, ...],
        tuple[str, ...],
    ]:
        routing: list[RoutingDecision] = []
        policy: list[ReviewPolicyDecision] = []
        targeted: list[TargetedReviewItem] = []
        qa: list[TargetedQaReferral] = []
        clean: list[str] = []
        for signals in self._signals:
            route = route_parameter(signals)
            projected = decide_post_lock_next_step(signals, self._profile)
            if projected.reasons != route.reasons:
                raise TargetedRoutingSchemaError(
                    "Policy reasons differ from canonical routing reasons"
                )
            routing.append(route)
            policy.append(projected)
            if (
                projected.next_step
                is ReviewNextStep.TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK
            ):
                targeted.append(
                    TargetedReviewItem(
                        parameter_id=signals.parameter_id,
                        reasons=projected.reasons,
                        primary_verdict=signals.human_verdict,
                        ai_verdict=signals.ai_verdict,
                        comparison_kind=signals.comparison_kind,
                        next_step=projected.next_step,
                    )
                )
            elif projected.next_step in {
                ReviewNextStep.QA_STRUCTURAL_OR_SYSTEM_REVIEW,
                ReviewNextStep.QA_CRITICAL_POLICY_CONFIRMATION,
            }:
                qa.append(
                    TargetedQaReferral(
                        parameter_id=signals.parameter_id,
                        reasons=projected.reasons,
                        next_step=projected.next_step,
                    )
                )
            elif (
                projected.next_step
                is ReviewNextStep.WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION
            ):
                clean.append(signals.parameter_id)
            else:
                raise UnsupportedTargetedProfileError(
                    "The selected policy produced a non-targeted review step"
                )
        return (
            tuple(routing),
            tuple(policy),
            tuple(targeted),
            tuple(qa),
            tuple(clean),
        )

    def _calculate_source_snapshot_hash(self) -> str:
        return _canonical_hash(
            {
                "targeted_review_snapshot_version": 2,
                "targeted_case_id": self._targeted_case_id,
                "task_id": self._task_id,
                "assignment_id": self._assignment_id,
                "assigned_reviewer": {
                    "actor_id": self._assigned_reviewer.actor_id,
                    "kind": self._assigned_reviewer.kind.value,
                    "roles": sorted(
                        role.value for role in self._assigned_reviewer.roles
                    ),
                },
                "workflow_mode": WorkflowMode.STRICT_SEQUENTIAL.value,
                "evidence_manifest": self._manifest.to_record(),
                "evidence_manifest_hash": self._manifest_hash,
                "approved_pipeline_spec": self._pipeline_spec.to_record(),
                "approved_pipeline_spec_hash": self._pipeline_spec.spec_hash,
                "routing_context": self._routing_context.to_record(),
                "routing_context_sha256": self._routing_context_sha256,
                "profile": self._profile.to_record(),
                "profile_content_sha256": self._profile.content_sha256,
                "primary_reviewer_id": self._primary_reviewer_id,
                "human_locked_at": self._human_locked_at.isoformat(),
                "primary_decisions": [
                    self._human_record(self._primary_decisions[parameter_id])
                    for parameter_id in self._expected_parameter_ids
                ],
                "ai_run": self._ai_run_record(self._ai_run),
                "ai_assessments": [
                    self._ai_record(self._ai_assessments[parameter_id])
                    for parameter_id in self._expected_parameter_ids
                ],
                "routing_signals": [
                    self._signals_record(item) for item in self._signals
                ],
                "routing": [
                    self._routing_record(item) for item in self._routing_decisions
                ],
                "policy_decisions": [
                    self._policy_record(item) for item in self._policy_decisions
                ],
            }
        )

    def _submission_hash(
        self,
        decisions: tuple[TargetedReviewDecision, ...],
        locked_at: datetime,
    ) -> str:
        return _canonical_hash(
            _locked_submission_payload(
                targeted_case_id=self._targeted_case_id,
                task_id=self._task_id,
                assignment_id=self._assignment_id,
                reviewer_id=self._assigned_reviewer_id,
                evidence_manifest_hash=self._manifest_hash,
                expected_parameter_ids=self._expected_parameter_ids,
                routing_context_id=self._routing_context.context_id,
                routing_context_version=self._routing_context.context_version,
                routing_context_sha256=self._routing_context_sha256,
                source_snapshot_sha256=self._source_snapshot_sha256,
                profile_id=self._profile.profile_id,
                profile_version=self._profile.policy_version,
                profile_content_sha256=self._profile.content_sha256,
                targeted_items=self._plan.targeted_items,
                decisions=decisions,
                qa_referrals=self._plan.qa_referrals,
                no_exception_parameter_ids=(
                    self._plan.no_exception_parameter_ids
                ),
                locked_at=locked_at,
            )
        )

    @staticmethod
    def _human_record(item: HumanDecision) -> dict[str, Any]:
        return {
            "parameter_id": item.parameter_id,
            "verdict": item.verdict.value,
            "reviewer_id": item.reviewer_id,
            "decided_at": item.decided_at.isoformat(),
            "evidence_manifest_hash": item.evidence_manifest_hash,
            "reason": item.reason,
        }

    @staticmethod
    def _ai_run_record(item: AiRun) -> dict[str, Any]:
        return {
            "run_id": item.run_id,
            "evidence_manifest_hash": item.evidence_manifest_hash,
            "engine_name": item.engine_name,
            "engine_version": item.engine_version,
            "pipeline_version": item.pipeline_version,
            "comparator_version": item.comparator_version,
            "pipeline_spec_hash": item.pipeline_spec_hash,
            "queued_at": item.queued_at.isoformat(),
            "started_at": None
            if item.started_at is None
            else item.started_at.isoformat(),
        }

    @staticmethod
    def _ai_record(item: AiAssessment) -> dict[str, Any]:
        comparison = item.comparison_result
        return {
            "parameter_id": item.parameter_id,
            "verdict": item.verdict.value,
            "assessed_at": item.assessed_at.isoformat(),
            "run_id": item.run_id,
            "evidence_manifest_hash": item.evidence_manifest_hash,
            "engine_name": item.engine_name,
            "engine_version": item.engine_version,
            "pipeline_version": item.pipeline_version,
            "comparator_version": item.comparator_version,
            "pipeline_spec_hash": item.pipeline_spec_hash,
            "left_raw": item.left_raw,
            "right_raw": item.right_raw,
            "extraction_reliable": item.extraction_reliable,
            "comparison": None
            if comparison is None
            else {
                "left_raw": comparison.left_raw,
                "right_raw": comparison.right_raw,
                "exact_match": comparison.exact_match,
                "kind": comparison.kind.value,
                "explanation": comparison.explanation,
                "left_number": None
                if comparison.left_number is None
                else str(comparison.left_number),
                "right_number": None
                if comparison.right_number is None
                else str(comparison.right_number),
                "left_unit": comparison.left_unit,
                "right_unit": comparison.right_unit,
            },
            "reason": item.reason,
        }

    @staticmethod
    def _signals_record(item: ReviewSignals) -> dict[str, Any]:
        return {
            "parameter_id": item.parameter_id,
            "human_verdict": item.human_verdict.value,
            "ai_verdict": item.ai_verdict.value,
            "comparison_kind": item.comparison_kind.value,
            "is_critical": item.is_critical,
            "image_quality": item.image_quality.value,
            "field_issues": [issue.value for issue in item.field_issues],
        }

    @staticmethod
    def _routing_record(item: RoutingDecision) -> dict[str, Any]:
        return {
            "parameter_id": item.parameter_id,
            "route": item.route.value,
            "reasons": [reason.value for reason in item.reasons],
        }

    @staticmethod
    def _policy_record(item: ReviewPolicyDecision) -> dict[str, Any]:
        return {
            "parameter_id": item.parameter_id,
            "profile_id": item.profile_id.value,
            "profile_version": item.profile_version,
            "profile_content_sha256": item.profile_content_sha256,
            "next_step": item.next_step.value,
            "reasons": [reason.value for reason in item.reasons],
            "automatic_release_allowed": False,
        }

    def _require_task_id(self, value: str) -> str:
        checked = _require_identifier("task_id", value)
        if checked != self._task_id:
            raise TargetedTaskBindingError(
                "Command task ID does not match this targeted review"
            )
        return checked

    def _require_assignment_id(self, value: str) -> str:
        checked = _require_identifier("assignment_id", value)
        if checked != self._assignment_id:
            raise TargetedAssignmentBindingError(
                "Command assignment does not match this targeted review"
            )
        return checked

    def _require_manifest_hash(self, value: str) -> str:
        try:
            checked = _require_sha256("evidence_manifest_hash", value)
        except (TypeError, ValueError) as error:
            raise TargetedEvidenceBindingError(str(error)) from error
        if checked != self._manifest_hash:
            raise TargetedEvidenceBindingError(
                "Command evidence does not match the frozen manifest"
            )
        return checked

    def _require_snapshot_hash(self, value: str) -> str:
        try:
            checked = _require_sha256("source_snapshot_sha256", value)
        except (TypeError, ValueError) as error:
            raise TargetedSnapshotBindingError(str(error)) from error
        if checked != self._source_snapshot_sha256:
            raise TargetedSnapshotBindingError(
                "Command source snapshot does not match the frozen queue"
            )
        return checked

    def _require_open(self) -> None:
        if self._state is not TargetedReviewState.OPEN:
            raise TargetedReviewLockedError("Targeted review is already locked")

    def _require_revision(self, expected_revision: int) -> None:
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")
        if expected_revision != self._revision:
            raise StaleTargetedReviewRevisionError(
                f"Expected revision {expected_revision}, current revision "
                f"{self._revision}"
            )

    def _idempotent_result(
        self, command_id: str, payload: dict[str, Any]
    ) -> Any | None:
        checked_id = _require_identifier("command_id", command_id)
        stored = self._commands.get(checked_id)
        if stored is None:
            return None
        payload_hash = _canonical_hash(payload)
        if stored.payload_hash != payload_hash:
            raise DuplicateTargetedCommandConflictError(
                "The command ID was already used with a different payload"
            )
        return stored.result

    def _remember_command(
        self, command_id: str, payload: dict[str, Any], result: Any
    ) -> None:
        checked_id = _require_identifier("command_id", command_id)
        self._commands[checked_id] = _StoredCommand(
            payload_hash=_canonical_hash(payload), result=result
        )

    def _now(self) -> datetime:
        value = _aware_utc("clock result", self._clock())
        if value < self._latest_time:
            raise TargetedSourceBindingError(
                "Targeted-review time cannot precede frozen source evidence"
            )
        self._latest_time = value
        return value


def validate_locked_targeted_submission(
    submission: LockedTargetedReviewSubmission,
    *,
    expected_source_snapshot_sha256: str,
    expected_submission_hash: str,
) -> None:
    """Validate a locked hand-off against hashes from trusted storage.

    A SHA-256 digest is an integrity anchor, not an electronic signature.  A
    downstream consumer must obtain both ``expected_*`` values from its
    append-only audit/transaction boundary rather than from the same request
    that supplies ``submission``.
    """

    try:
        if type(submission) is not LockedTargetedReviewSubmission:
            raise TypeError(
                "submission must be an exact LockedTargetedReviewSubmission"
            )
        trusted_source_hash = _require_sha256(
            "expected_source_snapshot_sha256",
            expected_source_snapshot_sha256,
        )
        trusted_submission_hash = _require_sha256(
            "expected_submission_hash", expected_submission_hash
        )
        for name in (
            "targeted_case_id",
            "task_id",
            "assignment_id",
            "reviewer_id",
            "routing_context_id",
            "routing_context_version",
            "profile_version",
        ):
            _require_identifier(name, getattr(submission, name))
        for name in (
            "evidence_manifest_hash",
            "routing_context_sha256",
            "source_snapshot_sha256",
            "profile_content_sha256",
            "submission_hash",
        ):
            _require_sha256(name, getattr(submission, name))
        locked_at = _aware_utc("locked_at", submission.locked_at)
        if submission.source_snapshot_sha256 != trusted_source_hash:
            raise ValueError("submission source snapshot differs from trusted anchor")
        if submission.submission_hash != trusted_submission_hash:
            raise ValueError("submission digest differs from trusted anchor")
        if (
            submission.profile_id is not INTERVIEW_TARGETED_RECHECK.profile_id
            or submission.profile_version
            != INTERVIEW_TARGETED_RECHECK.policy_version
            or submission.profile_content_sha256
            != INTERVIEW_TARGETED_RECHECK.content_sha256
        ):
            raise ValueError("submission uses an unsupported policy profile")
        if not isinstance(submission.targeted_items, tuple):
            raise TypeError("targeted_items must be tuple")
        if not isinstance(submission.decisions, tuple):
            raise TypeError("decisions must be tuple")
        if not isinstance(submission.qa_referrals, tuple):
            raise TypeError("qa_referrals must be tuple")
        if not isinstance(submission.no_exception_parameter_ids, tuple):
            raise TypeError("no_exception_parameter_ids must be tuple")
        if not isinstance(submission.expected_parameter_ids, tuple):
            raise TypeError("expected_parameter_ids must be tuple")
        expected_ids = tuple(
            _require_identifier("parameter_id", value)
            for value in submission.expected_parameter_ids
        )
        if not expected_ids or len(expected_ids) != len(set(expected_ids)):
            raise ValueError(
                "expected_parameter_ids must be nonempty and unique"
            )

        targeted_ids: list[str] = []
        for item in submission.targeted_items:
            if type(item) is not TargetedReviewItem:
                raise TypeError("targeted_items contains an invalid value")
            targeted_ids.append(_require_identifier("parameter_id", item.parameter_id))
            if (
                not isinstance(item.reasons, tuple)
                or not item.reasons
                or any(not isinstance(reason, RouteReason) for reason in item.reasons)
                or len(set(item.reasons)) != len(item.reasons)
            ):
                raise TypeError("targeted item reasons are invalid")
            if not isinstance(item.primary_verdict, HumanVerdict):
                raise TypeError("targeted primary verdict is invalid")
            if not isinstance(item.ai_verdict, AiVerdict):
                raise TypeError("targeted AI verdict is invalid")
            if not isinstance(item.comparison_kind, ComparisonKind):
                raise TypeError("targeted comparison kind is invalid")
            if (
                item.next_step
                is not ReviewNextStep.TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK
            ):
                raise ValueError("targeted item has a non-targeted next step")

        decision_ids: list[str] = []
        for item in submission.decisions:
            if type(item) is not TargetedReviewDecision:
                raise TypeError("decisions contains an invalid value")
            decision_ids.append(_require_identifier("parameter_id", item.parameter_id))
            if not isinstance(item.verdict, TargetedVerdict):
                raise TypeError("targeted decision verdict is invalid")
            if _require_reason(item.reason) is None:
                raise ValueError("every targeted decision requires a reason")
            decided_at = _aware_utc("decided_at", item.decided_at)
            if decided_at > locked_at:
                raise ValueError("targeted decision occurs after its lock")
            if (
                item.reviewer_id != submission.reviewer_id
                or item.task_id != submission.task_id
                or item.assignment_id != submission.assignment_id
                or item.evidence_manifest_hash
                != submission.evidence_manifest_hash
                or item.source_snapshot_sha256
                != submission.source_snapshot_sha256
            ):
                raise ValueError("targeted decision binding is inconsistent")
        if tuple(decision_ids) != tuple(targeted_ids):
            raise ValueError(
                "decisions must exactly cover targeted items in frozen order"
            )

        qa_ids: list[str] = []
        qa_steps = {
            ReviewNextStep.QA_STRUCTURAL_OR_SYSTEM_REVIEW,
            ReviewNextStep.QA_CRITICAL_POLICY_CONFIRMATION,
        }
        for item in submission.qa_referrals:
            if type(item) is not TargetedQaReferral:
                raise TypeError("qa_referrals contains an invalid value")
            qa_ids.append(_require_identifier("parameter_id", item.parameter_id))
            if (
                not isinstance(item.reasons, tuple)
                or not item.reasons
                or any(not isinstance(reason, RouteReason) for reason in item.reasons)
                or len(set(item.reasons)) != len(item.reasons)
            ):
                raise TypeError("QA referral reasons are invalid")
            if item.next_step not in qa_steps:
                raise ValueError("QA referral has a non-QA next step")

        clean_ids = [
            _require_identifier("parameter_id", value)
            for value in submission.no_exception_parameter_ids
        ]
        partitions = [*targeted_ids, *qa_ids, *clean_ids]
        if len(partitions) != len(set(partitions)):
            raise ValueError(
                "targeted, QA, and no-exception partitions must be disjoint"
            )
        if set(partitions) != set(expected_ids):
            raise ValueError(
                "targeted, QA, and no-exception partitions must exactly cover "
                "expected_parameter_ids"
            )
        schema_index = {
            parameter_id: index
            for index, parameter_id in enumerate(expected_ids)
        }
        for name, values in (
            ("targeted", targeted_ids),
            ("QA", qa_ids),
            ("no-exception", clean_ids),
        ):
            positions = [schema_index[value] for value in values]
            if positions != sorted(positions):
                raise ValueError(f"{name} partition is not in Schema order")

        recomputed_hash = _canonical_hash(
            canonical_locked_targeted_submission_record(submission)
        )
        if recomputed_hash != submission.submission_hash:
            raise ValueError("submission content does not match submission_hash")
    except TargetedSubmissionBindingError:
        raise
    except Exception as error:
        raise TargetedSubmissionBindingError(
            f"Locked targeted submission is invalid: {error}"
        ) from error
