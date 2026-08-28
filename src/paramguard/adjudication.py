"""Trusted reconciliation, QA disposition, and final human decision gates.

This module sits *after* the structurally blind second-review boundary.  It may
join locked primary, AI, routing, and second-review evidence, but none of these
objects is exposed back through :mod:`paramguard.blind_review`.

The implementation is an in-memory learning PoC.  Its ``RLock``, hashes, and
idempotency records make domain transitions deterministic inside one process;
they do not replace database transactions, durable uniqueness constraints,
validated identity infrastructure, electronic signatures, or a WORM audit
archive.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from threading import RLock
from types import MappingProxyType
from typing import Any

from .audit import calculate_final_commit_request_hash
from .blind_review import (
    BlindVerdict,
    LockedSecondReviewSubmission,
    SecondReviewDecision,
)
from .comparison import ComparisonKind, compare_values
from .evidence import EvidenceManifest
from .identity import Actor, PrincipalKind, Role
from .routing import (
    ReviewRoute,
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
)


class AdjudicationState(str, Enum):
    ROUTING_PENDING = "ROUTING_PENDING"
    SECOND_REVIEW_OPEN = "SECOND_REVIEW_OPEN"
    QA_DISPOSITION_OPEN = "QA_DISPOSITION_OPEN"
    READY_FOR_FINAL_HUMAN_DECISION = "READY_FOR_FINAL_HUMAN_DECISION"
    APPROVAL_BLOCKED = "APPROVAL_BLOCKED"
    REWORK_REQUIRED = "REWORK_REQUIRED"
    FINAL_APPROVED = "FINAL_APPROVED"
    FINAL_REJECTED = "FINAL_REJECTED"


class ExceptionSource(str, Enum):
    ROUTING = "ROUTING"
    SECOND_REVIEW_RECONCILIATION = "SECOND_REVIEW_RECONCILIATION"


class ReconciliationReason(str, Enum):
    PRIMARY_SECOND_DISAGREEMENT = "PRIMARY_SECOND_DISAGREEMENT"
    AI_SECOND_DISAGREEMENT = "AI_SECOND_DISAGREEMENT"
    SECOND_REVIEW_UNABLE_TO_JUDGE = "SECOND_REVIEW_UNABLE_TO_JUDGE"


class QaDispositionOutcome(str, Enum):
    """Per-exception outcome; only the first removes an approval blocker."""

    RESOLVED_NO_BLOCKING_EXCEPTION = "RESOLVED_NO_BLOCKING_EXCEPTION"
    CONFIRMED_DIFFERENCE = "CONFIRMED_DIFFERENCE"
    EVIDENCE_REWORK_REQUIRED = "EVIDENCE_REWORK_REQUIRED"
    EXTERNAL_DEVIATION_CONTROL_REQUIRED = "EXTERNAL_DEVIATION_CONTROL_REQUIRED"
    TASK_INVALIDATED = "TASK_INVALIDATED"


class FinalDecisionKind(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AdjudicationError(Exception):
    code = "ADJUDICATION_ERROR"


class RoutingSchemaError(AdjudicationError):
    code = "ROUTING_SCHEMA_ERROR"

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


class InvalidAdjudicationTransitionError(AdjudicationError):
    code = "INVALID_ADJUDICATION_TRANSITION"


class SecondReviewAssignmentMissingError(AdjudicationError):
    code = "SECOND_REVIEW_ASSIGNMENT_MISSING"


class SecondReviewBindingError(AdjudicationError):
    code = "SECOND_REVIEW_BINDING_ERROR"


class UnauthorizedQaActorError(AdjudicationError):
    code = "UNAUTHORIZED_QA_ACTOR"


class UnknownExceptionError(AdjudicationError):
    code = "UNKNOWN_EXCEPTION"


class DuplicateDispositionError(AdjudicationError):
    code = "DUPLICATE_DISPOSITION"


class IncompleteQaDispositionError(AdjudicationError):
    code = "INCOMPLETE_QA_DISPOSITION"

    def __init__(self, unresolved_exception_ids: tuple[str, ...]) -> None:
        self.unresolved_exception_ids = unresolved_exception_ids
        super().__init__(
            "QA disposition is incomplete; unresolved exceptions: "
            + ", ".join(unresolved_exception_ids)
        )


class UnauthorizedFinalActorError(AdjudicationError):
    code = "UNAUTHORIZED_FINAL_ACTOR"


class ApprovalBlockedError(AdjudicationError):
    code = "APPROVAL_BLOCKED"


class FinalDecisionAlreadyRecordedError(AdjudicationError):
    code = "FINAL_DECISION_ALREADY_RECORDED"


class EvidenceBindingError(AdjudicationError):
    code = "EVIDENCE_BINDING_ERROR"


class AuditVerificationError(AdjudicationError):
    code = "AUDIT_VERIFICATION_ERROR"


class StaleAdjudicationVersionError(AdjudicationError):
    code = "STALE_ADJUDICATION_VERSION"


class DuplicateAdjudicationCommandConflictError(AdjudicationError):
    code = "DUPLICATE_ADJUDICATION_COMMAND_CONFLICT"


class SourceReviewProvenanceError(AdjudicationError):
    code = "SOURCE_REVIEW_PROVENANCE_ERROR"


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe 1-128 character identifier")
    return value


def _require_text(name: str, value: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if value.strip() == "":
        raise ValueError(f"{name} must not be empty or whitespace")
    return value


def _require_sha256(name: str, value: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"{name} must contain 64 lowercase hexadecimal characters"
        )
    return value


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
class ExceptionItem:
    exception_id: str
    parameter_id: str
    source: ExceptionSource
    reason_code: str
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    second_submission_hash: str
    added_exception_ids: tuple[str, ...]
    next_state: AdjudicationState


@dataclass(frozen=True, slots=True)
class RoutingEvidenceContext:
    """Versioned provenance for criticality, quality, and alignment signals."""

    routing_rules_version: str
    criticality_source_sha256: str
    quality_report_sha256: str
    alignment_report_sha256: str

    def __post_init__(self) -> None:
        _require_identifier("routing_rules_version", self.routing_rules_version)
        for name in (
            "criticality_source_sha256",
            "quality_report_sha256",
            "alignment_report_sha256",
        ):
            _require_sha256(name, getattr(self, name))


@dataclass(frozen=True, slots=True)
class QaDisposition:
    exception_id: str
    outcome: QaDispositionOutcome
    rationale: str
    reference_ids: tuple[str, ...]
    qa_actor_id: str
    disposed_at: datetime


@dataclass(frozen=True, slots=True)
class FinalDecision:
    decision: FinalDecisionKind
    actor_id: str
    rationale: str
    decided_at: datetime
    evidence_manifest_hash: str
    second_submission_hash: str | None
    resolution_digest: str
    previous_audit_head_hash: str
    audit_head_hash: str


@dataclass(frozen=True, slots=True)
class FinalAuditCommitRequest:
    """Inputs an audit adapter must verify and append atomically.

    The adapter contract is intentionally stronger than separate ``verify``
    and ``append`` calls: under one file lock or database transaction it must
    verify the chain and task-specific prerequisite actions, compare-and-swap
    the current head, append and durably flush the final-decision event, then
    return a receipt.  The aggregate never treats a bare Boolean as evidence.
    """

    task_id: str
    decision: FinalDecisionKind
    actor_id: str
    rationale: str
    evidence_manifest_hash: str
    second_submission_hash: str | None
    primary_reviewer_id: str
    ai_run_id: str
    expected_parameter_ids: tuple[str, ...]
    exception_ids: tuple[str, ...]
    qa_disposition_exception_ids: tuple[str, ...]
    resolution_digest: str
    expected_adjudication_version: int
    expected_previous_head_hash: str
    required_prior_actions: tuple[str, ...]
    command_id: str


@dataclass(frozen=True, slots=True)
class FinalAuditCommitReceipt:
    request_hash: str
    previous_head_hash: str
    new_head_hash: str
    event_id: str
    committed_at: datetime


def final_audit_commit_request_record(
    request: FinalAuditCommitRequest,
) -> dict[str, Any]:
    if not isinstance(request, FinalAuditCommitRequest):
        raise TypeError("request must be a FinalAuditCommitRequest")
    return {
        "task_id": request.task_id,
        "decision": request.decision.value,
        "actor_id": request.actor_id,
        "rationale": request.rationale,
        "evidence_manifest_hash": request.evidence_manifest_hash,
        "second_submission_hash": request.second_submission_hash,
        "primary_reviewer_id": request.primary_reviewer_id,
        "ai_run_id": request.ai_run_id,
        "expected_parameter_ids": list(request.expected_parameter_ids),
        "exception_ids": list(request.exception_ids),
        "qa_disposition_exception_ids": list(
            request.qa_disposition_exception_ids
        ),
        "resolution_digest": request.resolution_digest,
        "expected_adjudication_version": request.expected_adjudication_version,
        "expected_previous_head_hash": request.expected_previous_head_hash,
        "required_prior_actions": list(request.required_prior_actions),
        "command_id": request.command_id,
    }


def final_audit_commit_request_hash(request: FinalAuditCommitRequest) -> str:
    return calculate_final_commit_request_hash(
        final_audit_commit_request_record(request)
    )


@dataclass(frozen=True, slots=True)
class _StoredCommand:
    payload_hash: str
    result: Any


class AdjudicationCase:
    """A task-level, fail-closed human adjudication aggregate."""

    def __init__(
        self,
        *,
        task_id: str,
        evidence_manifest: EvidenceManifest,
        source_review_task: ReviewTask,
        routing_signals: Mapping[str, ReviewSignals],
        routing_evidence_context: RoutingEvidenceContext,
        final_audit_committer: Callable[
            [FinalAuditCommitRequest], FinalAuditCommitReceipt
        ],
        expected_blind_case_id: str | None = None,
        expected_second_reviewer_id: str | None = None,
        locked_second_submission_resolver: Callable[
            [str, str, str, str], LockedSecondReviewSubmission | None
        ]
        | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._task_id = _require_identifier("task_id", task_id)
        if not isinstance(evidence_manifest, EvidenceManifest):
            raise TypeError("evidence_manifest must be an EvidenceManifest")
        if not isinstance(source_review_task, ReviewTask):
            raise TypeError("source_review_task must be a ReviewTask")
        if not isinstance(routing_signals, Mapping):
            raise TypeError("routing_signals must be a Mapping")
        if not isinstance(routing_evidence_context, RoutingEvidenceContext):
            raise TypeError(
                "routing_evidence_context must be a RoutingEvidenceContext"
            )
        if not callable(final_audit_committer):
            raise TypeError("final_audit_committer must be callable")
        if not callable(clock):
            raise TypeError("clock must be callable")

        if (expected_blind_case_id is None) != (
            expected_second_reviewer_id is None
        ):
            raise ValueError(
                "blind case ID and second reviewer ID must be supplied together"
            )
        if expected_blind_case_id is not None:
            expected_blind_case_id = _require_identifier(
                "expected_blind_case_id", expected_blind_case_id
            )
            expected_second_reviewer_id = _require_identifier(
                "expected_second_reviewer_id", expected_second_reviewer_id
            )
            if not callable(locked_second_submission_resolver):
                raise TypeError(
                    "locked_second_submission_resolver must be callable for "
                    "a bound second review"
                )
        elif locked_second_submission_resolver is not None:
            raise ValueError(
                "locked_second_submission_resolver requires a bound blind assignment"
            )

        self._manifest = evidence_manifest
        self._manifest_hash = evidence_manifest.manifest_hash
        self._expected_parameter_ids = evidence_manifest.expected_parameter_ids
        self._expected_parameter_id_set = frozenset(self._expected_parameter_ids)
        self._primary_reviewer_id = _require_identifier(
            "source primary reviewer_id", source_review_task.reviewer_id
        )
        (
            self._primary_locked_at,
            self._primary_decisions,
            self._ai_run,
            self._ai_assessments,
        ) = self._capture_completed_source_review(source_review_task)
        if (
            expected_second_reviewer_id is not None
            and expected_second_reviewer_id == self._primary_reviewer_id
        ):
            raise SecondReviewBindingError(
                "Primary and second reviewer must be different actors"
            )
        self._routing_signals = self._validate_routing_signals(
            routing_signals
        )
        self._routing_evidence_context = routing_evidence_context
        self._final_audit_committer = final_audit_committer
        self._expected_blind_case_id = expected_blind_case_id
        self._expected_second_reviewer_id = expected_second_reviewer_id
        self._locked_second_submission_resolver = (
            locked_second_submission_resolver
        )
        self._clock = clock

        self._lock = RLock()
        self._state = AdjudicationState.ROUTING_PENDING
        self._version = 0
        self._routing: tuple[RoutingDecision, ...] = ()
        self._exceptions: list[ExceptionItem] = []
        self._exception_by_id: dict[str, ExceptionItem] = {}
        self._qa_dispositions: dict[str, QaDisposition] = {}
        self._second_submission: LockedSecondReviewSubmission | None = None
        self._final_decision: FinalDecision | None = None
        self._commands: dict[str, _StoredCommand] = {}

    @property
    def task_id(self) -> str:
        return self._task_id

    @property
    def state(self) -> AdjudicationState:
        with self._lock:
            return self._state

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    @property
    def evidence_manifest_hash(self) -> str:
        return self._manifest_hash

    @property
    def final_decision(self) -> FinalDecision | None:
        with self._lock:
            return self._final_decision

    def resolution_digest(self) -> str:
        """Return the audit-head-independent digest of resolved domain facts."""

        with self._lock:
            if self._state not in {
                AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
                AdjudicationState.APPROVAL_BLOCKED,
                AdjudicationState.REWORK_REQUIRED,
                AdjudicationState.FINAL_APPROVED,
                AdjudicationState.FINAL_REJECTED,
            }:
                raise InvalidAdjudicationTransitionError(
                    "Resolution digest is unavailable before adjudication is resolved"
                )
            return self._resolution_digest()

    def routing_snapshot(self) -> tuple[RoutingDecision, ...]:
        with self._lock:
            return self._routing

    def exception_ledger(self) -> tuple[ExceptionItem, ...]:
        with self._lock:
            return tuple(self._exceptions)

    def qa_dispositions(self) -> Mapping[str, QaDisposition]:
        with self._lock:
            return MappingProxyType(dict(self._qa_dispositions))

    def record_routing(
        self,
        *,
        decisions: Sequence[RoutingDecision],
        command_id: str,
        expected_version: int,
    ) -> AdjudicationState:
        """Bind one and only one routing result to every frozen Schema field."""

        with self._lock:
            ordered = self._validate_and_order_routing(decisions)
            payload = {
                "operation": "record_routing",
                "decisions": [self._routing_record(item) for item in ordered],
                "expected_version": expected_version,
            }
            stored = self._idempotent_result(command_id, payload)
            if stored is not None:
                assert isinstance(stored, AdjudicationState)
                return stored
            self._require_state(AdjudicationState.ROUTING_PENDING)
            self._require_version(expected_version)

            needs_second = any(
                item.route is ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED
                for item in ordered
            )
            if needs_second and (
                self._expected_blind_case_id is None
                or self._expected_second_reviewer_id is None
            ):
                raise SecondReviewAssignmentMissingError(
                    "Independent second review was routed but no bound blind "
                    "assignment exists"
                )

            detected_at = self._now()
            new_exceptions = self._routing_exceptions(ordered, detected_at)
            self._routing = ordered
            self._install_exceptions(new_exceptions)
            if needs_second:
                self._state = AdjudicationState.SECOND_REVIEW_OPEN
            elif new_exceptions:
                self._state = AdjudicationState.QA_DISPOSITION_OPEN
            else:
                # NO_EXCEPTION is only a routing outcome.  It never approves.
                self._state = AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION
            self._version += 1
            self._remember_command(command_id, payload, self._state)
            return self._state

    def reconcile_locked_second_review(
        self,
        *,
        submission: LockedSecondReviewSubmission,
        command_id: str,
        expected_version: int,
    ) -> ReconciliationResult:
        """Join prior results only after validating a complete locked submission."""

        with self._lock:
            if not isinstance(submission, LockedSecondReviewSubmission):
                raise TypeError(
                    "submission must be a LockedSecondReviewSubmission"
                )
            payload = {
                "operation": "reconcile_locked_second_review",
                "submission_hash": submission.submission_hash,
                "expected_version": expected_version,
            }
            stored = self._idempotent_result(command_id, payload)
            if stored is not None:
                assert isinstance(stored, ReconciliationResult)
                return stored
            self._require_state(AdjudicationState.SECOND_REVIEW_OPEN)
            self._require_version(expected_version)
            # Complete all fallible local validation and timestamp generation
            # before the trusted resolver atomically claims the submission.
            self._validate_second_submission(submission)
            detected_at = self._now()
            new_exceptions = self._reconciliation_exceptions(
                submission, detected_at
            )
            trusted_submission = self._resolve_locked_second_submission(
                submission, command_id=command_id
            )
            self._install_exceptions(new_exceptions)
            self._second_submission = trusted_submission
            # Every pre-existing or newly discovered exception is explicitly
            # dispositioned by a human QA actor before final approval review.
            self._state = AdjudicationState.QA_DISPOSITION_OPEN
            self._version += 1
            result = ReconciliationResult(
                second_submission_hash=trusted_submission.submission_hash,
                added_exception_ids=tuple(
                    item.exception_id for item in new_exceptions
                ),
                next_state=self._state,
            )
            self._remember_command(command_id, payload, result)
            return result

    def record_qa_disposition(
        self,
        *,
        actor: Actor,
        exception_id: str,
        outcome: QaDispositionOutcome,
        rationale: str,
        command_id: str,
        expected_version: int,
        reference_ids: tuple[str, ...] = (),
    ) -> QaDisposition:
        with self._lock:
            self._authorize_qa(actor)
            checked_exception_id = _require_identifier(
                "exception_id", exception_id
            )
            if not isinstance(outcome, QaDispositionOutcome):
                raise TypeError("outcome must be a QaDispositionOutcome")
            checked_rationale = _require_text("rationale", rationale)
            checked_references = self._validate_reference_ids(reference_ids)
            payload = {
                "operation": "record_qa_disposition",
                "actor_id": actor.actor_id,
                "exception_id": checked_exception_id,
                "outcome": outcome.value,
                "rationale": checked_rationale,
                "reference_ids": list(checked_references),
                "expected_version": expected_version,
            }
            stored = self._idempotent_result(command_id, payload)
            if stored is not None:
                assert isinstance(stored, QaDisposition)
                return stored
            self._require_state(AdjudicationState.QA_DISPOSITION_OPEN)
            self._require_version(expected_version)
            if checked_exception_id not in self._exception_by_id:
                raise UnknownExceptionError(
                    f"Unknown exception ID: {checked_exception_id}"
                )
            if checked_exception_id in self._qa_dispositions:
                raise DuplicateDispositionError(
                    "An existing disposition cannot be silently overwritten"
                )

            disposition = QaDisposition(
                exception_id=checked_exception_id,
                outcome=outcome,
                rationale=checked_rationale,
                reference_ids=checked_references,
                qa_actor_id=actor.actor_id,
                disposed_at=self._now(),
            )
            self._qa_dispositions[checked_exception_id] = disposition
            self._version += 1
            self._remember_command(command_id, payload, disposition)
            return disposition

    def complete_qa_disposition(
        self,
        *,
        actor: Actor,
        command_id: str,
        expected_version: int,
    ) -> AdjudicationState:
        with self._lock:
            self._authorize_qa(actor)
            payload = {
                "operation": "complete_qa_disposition",
                "actor_id": actor.actor_id,
                "expected_version": expected_version,
            }
            stored = self._idempotent_result(command_id, payload)
            if stored is not None:
                assert isinstance(stored, AdjudicationState)
                return stored
            self._require_state(AdjudicationState.QA_DISPOSITION_OPEN)
            self._require_version(expected_version)
            unresolved = tuple(
                item.exception_id
                for item in self._exceptions
                if item.exception_id not in self._qa_dispositions
            )
            if unresolved:
                raise IncompleteQaDispositionError(unresolved)
            if set(self._qa_dispositions) != set(self._exception_by_id):
                raise IncompleteQaDispositionError(unresolved)

            outcomes = {
                disposition.outcome
                for disposition in self._qa_dispositions.values()
            }
            rework_outcomes = {
                QaDispositionOutcome.EVIDENCE_REWORK_REQUIRED,
                QaDispositionOutcome.TASK_INVALIDATED,
            }
            blocking_outcomes = {
                QaDispositionOutcome.CONFIRMED_DIFFERENCE,
                QaDispositionOutcome.EXTERNAL_DEVIATION_CONTROL_REQUIRED,
            }
            if outcomes & rework_outcomes:
                next_state = AdjudicationState.REWORK_REQUIRED
            elif outcomes & blocking_outcomes:
                next_state = AdjudicationState.APPROVAL_BLOCKED
            else:
                next_state = AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION

            self._state = next_state
            self._version += 1
            self._remember_command(command_id, payload, next_state)
            return next_state

    def approve(
        self,
        *,
        actor: Actor,
        rationale: str,
        evidence_manifest_hash: str,
        second_submission_hash: str | None,
        audit_head_hash: str,
        command_id: str,
        expected_version: int,
    ) -> FinalDecision:
        return self._record_final_decision(
            decision=FinalDecisionKind.APPROVED,
            actor=actor,
            rationale=rationale,
            evidence_manifest_hash=evidence_manifest_hash,
            second_submission_hash=second_submission_hash,
            audit_head_hash=audit_head_hash,
            command_id=command_id,
            expected_version=expected_version,
        )

    def reject(
        self,
        *,
        actor: Actor,
        rationale: str,
        evidence_manifest_hash: str,
        second_submission_hash: str | None,
        audit_head_hash: str,
        command_id: str,
        expected_version: int,
    ) -> FinalDecision:
        return self._record_final_decision(
            decision=FinalDecisionKind.REJECTED,
            actor=actor,
            rationale=rationale,
            evidence_manifest_hash=evidence_manifest_hash,
            second_submission_hash=second_submission_hash,
            audit_head_hash=audit_head_hash,
            command_id=command_id,
            expected_version=expected_version,
        )

    def _record_final_decision(
        self,
        *,
        decision: FinalDecisionKind,
        actor: Actor,
        rationale: str,
        evidence_manifest_hash: str,
        second_submission_hash: str | None,
        audit_head_hash: str,
        command_id: str,
        expected_version: int,
    ) -> FinalDecision:
        with self._lock:
            self._authorize_final(actor)
            checked_rationale = _require_text("rationale", rationale)
            checked_manifest_hash = _require_sha256(
                "evidence_manifest_hash", evidence_manifest_hash
            )
            checked_audit_hash = _require_sha256(
                "audit_head_hash", audit_head_hash
            )
            if second_submission_hash is not None:
                second_submission_hash = _require_sha256(
                    "second_submission_hash", second_submission_hash
                )
            payload = {
                "operation": "final_decision",
                "decision": decision.value,
                "actor_id": actor.actor_id,
                "actor_kind": actor.kind.value,
                "actor_roles": sorted(role.value for role in actor.roles),
                "rationale": checked_rationale,
                "evidence_manifest_hash": checked_manifest_hash,
                "second_submission_hash": second_submission_hash,
                "audit_head_hash": checked_audit_hash,
                "expected_version": expected_version,
            }
            stored = self._idempotent_result(command_id, payload)
            if stored is not None:
                assert isinstance(stored, FinalDecision)
                return stored
            if self._final_decision is not None:
                raise FinalDecisionAlreadyRecordedError(
                    "A final human decision is already recorded"
                )
            self._require_version(expected_version)

            if decision is FinalDecisionKind.APPROVED:
                if self._state is not AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION:
                    raise ApprovalBlockedError(
                        f"Approval is blocked in state {self._state.value}"
                    )
            elif self._state not in {
                AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
                AdjudicationState.APPROVAL_BLOCKED,
                AdjudicationState.REWORK_REQUIRED,
            }:
                raise InvalidAdjudicationTransitionError(
                    f"Final rejection is not allowed from state {self._state.value}"
                )

            self._verify_final_evidence_bindings(
                evidence_manifest_hash=checked_manifest_hash,
                second_submission_hash=second_submission_hash,
            )
            if checked_audit_hash == "0" * 64:
                raise AuditVerificationError(
                    "A final decision cannot be committed onto an empty audit chain"
                )
            resolution_digest = self._resolution_digest()
            commit_request = FinalAuditCommitRequest(
                task_id=self._task_id,
                decision=decision,
                actor_id=actor.actor_id,
                rationale=checked_rationale,
                evidence_manifest_hash=self._manifest_hash,
                second_submission_hash=second_submission_hash,
                primary_reviewer_id=self._primary_reviewer_id,
                ai_run_id=self._ai_run.run_id,
                expected_parameter_ids=self._expected_parameter_ids,
                exception_ids=tuple(
                    sorted(item.exception_id for item in self._exceptions)
                ),
                qa_disposition_exception_ids=tuple(
                    sorted(self._qa_dispositions)
                ),
                resolution_digest=resolution_digest,
                expected_adjudication_version=expected_version,
                expected_previous_head_hash=checked_audit_hash,
                required_prior_actions=self._required_prior_audit_actions(),
                command_id=_require_identifier("command_id", command_id),
            )
            receipt = self._commit_final_audit(commit_request)
            result = FinalDecision(
                decision=decision,
                actor_id=actor.actor_id,
                rationale=checked_rationale,
                decided_at=receipt.committed_at,
                evidence_manifest_hash=self._manifest_hash,
                second_submission_hash=second_submission_hash,
                resolution_digest=resolution_digest,
                previous_audit_head_hash=receipt.previous_head_hash,
                audit_head_hash=receipt.new_head_hash,
            )
            self._final_decision = result
            self._state = (
                AdjudicationState.FINAL_APPROVED
                if decision is FinalDecisionKind.APPROVED
                else AdjudicationState.FINAL_REJECTED
            )
            self._version += 1
            self._remember_command(command_id, payload, result)
            return result

    def _verify_final_evidence_bindings(
        self,
        *,
        evidence_manifest_hash: str,
        second_submission_hash: str | None,
    ) -> None:
        if evidence_manifest_hash != self._manifest_hash:
            raise EvidenceBindingError(
                "Final decision evidence does not match the frozen manifest"
            )
        expected_second_hash = (
            None
            if self._second_submission is None
            else self._second_submission.submission_hash
        )
        if second_submission_hash != expected_second_hash:
            raise EvidenceBindingError(
                "Final decision does not match the required second-review submission"
            )

    def _commit_final_audit(
        self, request: FinalAuditCommitRequest
    ) -> FinalAuditCommitReceipt:
        try:
            receipt = self._final_audit_committer(request)
        except Exception as error:
            raise AuditVerificationError(
                f"Atomic final-audit commit failed: {error}"
            ) from error
        if not isinstance(receipt, FinalAuditCommitReceipt):
            raise AuditVerificationError(
                "Final-audit committer returned an invalid receipt type"
            )
        try:
            request_hash = final_audit_commit_request_hash(request)
            previous_head = _require_sha256(
                "receipt previous head", receipt.previous_head_hash
            )
            new_head = _require_sha256("receipt new head", receipt.new_head_hash)
            _require_identifier("receipt event_id", receipt.event_id)
            committed_at = _aware_utc("receipt committed_at", receipt.committed_at)
        except (TypeError, ValueError) as error:
            raise AuditVerificationError(
                f"Final-audit receipt is malformed: {error}"
            ) from error
        if receipt.request_hash != request_hash:
            raise AuditVerificationError(
                "Final-audit receipt is not bound to the requested decision"
            )
        if previous_head != request.expected_previous_head_hash:
            raise AuditVerificationError(
                "Final-audit receipt used an unexpected previous head"
            )
        if new_head in {previous_head, "0" * 64}:
            raise AuditVerificationError(
                "Final-audit receipt did not advance to a non-genesis head"
            )
        if committed_at < self._latest_domain_evidence_time():
            raise AuditVerificationError(
                "Final-audit event predates evidence used for the decision"
            )
        return receipt

    @staticmethod
    def _final_commit_request_hash(request: FinalAuditCommitRequest) -> str:
        """Backward-compatible alias for the public contract hash helper."""

        return final_audit_commit_request_hash(request)

    def _required_prior_audit_actions(self) -> tuple[str, ...]:
        actions = [
            "TASK_CREATED",
            "HUMAN_DECISION_RECORDED",
            "HUMAN_REVIEW_LOCKED",
            "AI_REVIEW_STARTED",
            "AI_ASSESSMENT_RECORDED",
            "AI_REVIEW_COMPLETED",
            "ROUTE_ASSIGNED",
        ]
        if self._second_submission is not None:
            actions.extend(
                (
                    "SECOND_REVIEW_ASSIGNED",
                    "SECOND_REVIEW_DECISION_RECORDED",
                    "SECOND_REVIEW_LOCKED",
                )
            )
        if self._exceptions:
            actions.extend(
                (
                    "QA_CASE_OPENED",
                    "QA_DISPOSITION_RECORDED",
                    "QA_DISPOSITION_COMPLETED",
                )
            )
        return tuple(actions)

    def _latest_domain_evidence_time(self) -> datetime:
        times = [
            self._primary_locked_at,
            *(item.assessed_at for item in self._ai_assessments.values()),
            *(item.detected_at for item in self._exceptions),
            *(item.disposed_at for item in self._qa_dispositions.values()),
        ]
        if self._second_submission is not None:
            times.append(self._second_submission.locked_at)
        return max(times)

    def _capture_completed_source_review(
        self, source: ReviewTask
    ) -> tuple[
        datetime,
        dict[str, HumanDecision],
        AiRun,
        dict[str, AiAssessment],
    ]:
        """Capture evidence only from the completed human-first state machine."""

        if source.task_id != self._task_id:
            raise SourceReviewProvenanceError(
                "Source review task ID does not match the adjudication case"
            )
        if (
            source.evidence_manifest_hash != self._manifest_hash
            or source.expected_parameter_ids != self._expected_parameter_ids
        ):
            raise SourceReviewProvenanceError(
                "Source review is not bound to the frozen evidence and Schema"
            )
        if source.state is not ReviewState.AI_REVIEW_COMPLETE:
            raise SourceReviewProvenanceError(
                "Adjudication requires a locked primary review and completed AI run"
            )
        locked_at = source.human_locked_at
        if locked_at is None:
            raise SourceReviewProvenanceError(
                "Source review has no human lock timestamp"
            )
        try:
            locked_at = _aware_utc("human_locked_at", locked_at)
            primary = self._validate_primary_snapshot(source.human_decisions())
            ai_run = source.revealed_ai_run()
            assessments = self._validate_ai_snapshot(
                source.revealed_ai_results()
            )
            queued_at = _aware_utc("AI queued_at", ai_run.queued_at)
            if ai_run.started_at is None:
                raise SourceReviewProvenanceError(
                    "Completed AI run has no start timestamp"
                )
            started_at = _aware_utc("AI started_at", ai_run.started_at)
        except SourceReviewProvenanceError:
            raise
        except Exception as error:
            raise SourceReviewProvenanceError(
                f"Could not capture completed source review: {error}"
            ) from error

        if any(item.decided_at > locked_at for item in primary.values()):
            raise SourceReviewProvenanceError(
                "A primary decision occurs after the primary lock"
            )
        if queued_at < locked_at or started_at < queued_at:
            raise SourceReviewProvenanceError(
                "AI was not queued and started after the human lock"
            )
        if any(item.assessed_at < started_at for item in assessments.values()):
            raise SourceReviewProvenanceError(
                "An AI assessment predates the completed run start"
            )

        approved_spec = source.approved_pipeline_spec
        if (
            ai_run.pipeline_spec_hash != approved_spec.spec_hash
            or ai_run.engine_name != approved_spec.engine_name
            or ai_run.engine_version != approved_spec.engine_version
            or ai_run.pipeline_version != approved_spec.pipeline_version
            or ai_run.comparator_version != approved_spec.comparator_version
        ):
            raise SourceReviewProvenanceError(
                "AI run is not bound to the source task's approved pipeline"
            )
        for assessment in assessments.values():
            if (
                assessment.run_id != ai_run.run_id
                or assessment.evidence_manifest_hash
                != ai_run.evidence_manifest_hash
                or assessment.pipeline_spec_hash != ai_run.pipeline_spec_hash
                or assessment.engine_name != ai_run.engine_name
                or assessment.engine_version != ai_run.engine_version
                or assessment.pipeline_version != ai_run.pipeline_version
                or assessment.comparator_version != ai_run.comparator_version
            ):
                raise SourceReviewProvenanceError(
                    "AI assessment is not part of the completed approved run"
                )
        return locked_at, primary, ai_run, assessments

    def _validate_routing_signals(
        self, signals: Mapping[str, ReviewSignals]
    ) -> dict[str, ReviewSignals]:
        copied = dict(signals)
        self._require_exact_mapping_keys("routing signals", copied)
        for parameter_id, item in copied.items():
            if not isinstance(item, ReviewSignals):
                raise TypeError(
                    "routing_signals must contain ReviewSignals values"
                )
            # Calling the canonical rule also validates every enum, boolean,
            # field-issue tuple, and duplicate issue before the snapshot is kept.
            route_parameter(item)
            if item.parameter_id != parameter_id:
                raise EvidenceBindingError(
                    "Routing signal key differs from its parameter ID"
                )
            primary = self._primary_decisions[parameter_id]
            ai = self._ai_assessments[parameter_id]
            if (
                item.human_verdict is not primary.verdict
                or item.ai_verdict is not ai.verdict
            ):
                raise EvidenceBindingError(
                    "Routing signals do not match the bound primary and AI verdicts"
                )
            if (
                ai.comparison_result is not None
                and item.comparison_kind is not ai.comparison_result.kind
            ):
                raise EvidenceBindingError(
                    "Routing comparison kind does not match deterministic AI evidence"
                )
        return copied

    def _validate_primary_snapshot(
        self, decisions: Mapping[str, HumanDecision]
    ) -> dict[str, HumanDecision]:
        copied = dict(decisions)
        self._require_exact_mapping_keys("primary decisions", copied)
        for key, decision in copied.items():
            if not isinstance(decision, HumanDecision):
                raise TypeError("primary_decisions must contain HumanDecision values")
            if (
                key != decision.parameter_id
                or decision.reviewer_id != self._primary_reviewer_id
                or decision.evidence_manifest_hash != self._manifest_hash
                or not isinstance(decision.verdict, HumanVerdict)
            ):
                raise EvidenceBindingError(
                    "Primary decisions are not bound to the task reviewer and manifest"
                )
            _aware_utc("primary decision time", decision.decided_at)
            if decision.reason is not None:
                try:
                    _require_text("primary decision reason", decision.reason)
                except (TypeError, ValueError) as error:
                    raise EvidenceBindingError(
                        f"Primary decision reason is invalid for {key}: {error}"
                    ) from error
            if decision.verdict is not HumanVerdict.SAME and decision.reason is None:
                raise EvidenceBindingError(
                    f"Exceptional primary decision has no reason for {key}"
                )
        return copied

    def _validate_ai_snapshot(
        self, assessments: Mapping[str, AiAssessment]
    ) -> dict[str, AiAssessment]:
        copied = dict(assessments)
        self._require_exact_mapping_keys("AI assessments", copied)
        run_identity: tuple[str, str, str, str, str, str] | None = None
        for key, assessment in copied.items():
            if not isinstance(assessment, AiAssessment):
                raise TypeError("ai_assessments must contain AiAssessment values")
            if (
                key != assessment.parameter_id
                or assessment.evidence_manifest_hash != self._manifest_hash
                or not isinstance(assessment.verdict, AiVerdict)
            ):
                raise EvidenceBindingError(
                    "AI assessments are not bound to the task manifest"
                )
            _aware_utc("AI assessment time", assessment.assessed_at)
            for name in (
                "run_id",
                "engine_name",
                "engine_version",
                "pipeline_version",
                "comparator_version",
            ):
                try:
                    _require_identifier(name, getattr(assessment, name))
                except ValueError as error:
                    raise EvidenceBindingError(
                        f"AI run identity is invalid for {key}: {error}"
                    ) from error
            try:
                _require_sha256(
                    "pipeline_spec_hash", assessment.pipeline_spec_hash
                )
            except ValueError as error:
                raise EvidenceBindingError(
                    f"AI pipeline binding is invalid for {key}: {error}"
                ) from error
            self._validate_ai_evidence(key, assessment)
            identity = (
                assessment.run_id,
                assessment.engine_name,
                assessment.engine_version,
                assessment.pipeline_version,
                assessment.comparator_version,
                assessment.pipeline_spec_hash,
            )
            if run_identity is None:
                run_identity = identity
            elif identity != run_identity:
                raise EvidenceBindingError(
                    "AI assessments do not belong to one immutable run identity"
                )
        return copied

    @staticmethod
    def _validate_ai_evidence(parameter_id: str, assessment: AiAssessment) -> None:
        """Re-derive persisted AI evidence instead of trusting its verdict field."""

        if type(assessment.extraction_reliable) is not bool:
            raise EvidenceBindingError(
                f"AI extraction reliability is not bool for {parameter_id}"
            )
        if assessment.reason is not None:
            try:
                _require_text("AI assessment reason", assessment.reason)
            except (TypeError, ValueError) as error:
                raise EvidenceBindingError(
                    f"AI assessment reason is invalid for {parameter_id}: {error}"
                ) from error

        if assessment.verdict is AiVerdict.SYSTEM_ERROR:
            if (
                assessment.left_raw is not None
                or assessment.right_raw is not None
                or assessment.comparison_result is not None
                or assessment.extraction_reliable
                or assessment.reason is None
            ):
                raise EvidenceBindingError(
                    f"Malformed AI system-error evidence for {parameter_id}"
                )
            return

        if assessment.comparison_result is None:
            raise EvidenceBindingError(
                f"AI assessment has no deterministic comparison for {parameter_id}"
            )
        try:
            recomputed = compare_values(assessment.left_raw, assessment.right_raw)
        except (TypeError, ValueError) as error:
            raise EvidenceBindingError(
                f"AI raw values are invalid for {parameter_id}: {error}"
            ) from error
        if recomputed != assessment.comparison_result:
            raise EvidenceBindingError(
                f"AI comparison does not match its raw values for {parameter_id}"
            )
        if (
            not assessment.extraction_reliable
            or recomputed.kind is ComparisonKind.MISSING_VALUE
        ):
            expected_verdict = AiVerdict.UNABLE_TO_JUDGE
            if assessment.reason is None:
                raise EvidenceBindingError(
                    f"Unreliable AI assessment has no reason for {parameter_id}"
                )
        elif recomputed.exact_match:
            expected_verdict = AiVerdict.SAME
        else:
            expected_verdict = AiVerdict.DIFFERENT
        if assessment.verdict is not expected_verdict:
            raise EvidenceBindingError(
                "AI verdict is inconsistent with deterministic evidence for "
                f"{parameter_id}"
            )

    def _require_exact_mapping_keys(
        self, label: str, values: Mapping[str, Any]
    ) -> None:
        keys = tuple(values.keys())
        if any(not isinstance(key, str) for key in keys):
            raise TypeError(f"{label} keys must be str")
        key_set = set(keys)
        if key_set != self._expected_parameter_id_set or len(keys) != len(key_set):
            raise EvidenceBindingError(
                f"{label} must exactly cover the frozen Schema"
            )

    def _validate_and_order_routing(
        self, decisions: Sequence[RoutingDecision]
    ) -> tuple[RoutingDecision, ...]:
        if isinstance(decisions, (str, bytes)) or not isinstance(decisions, Sequence):
            raise TypeError("decisions must be a Sequence of RoutingDecision values")
        frozen_decisions = tuple(decisions)
        by_parameter: dict[str, RoutingDecision] = {}
        duplicates: list[str] = []
        unknown: list[str] = []
        for decision in frozen_decisions:
            if not isinstance(decision, RoutingDecision):
                raise TypeError("decisions must contain only RoutingDecision values")
            parameter_id = _require_identifier(
                "routing parameter_id", decision.parameter_id
            )
            if parameter_id in by_parameter and parameter_id not in duplicates:
                duplicates.append(parameter_id)
            else:
                by_parameter[parameter_id] = decision
            if (
                parameter_id not in self._expected_parameter_id_set
                and parameter_id not in unknown
            ):
                unknown.append(parameter_id)
            if not isinstance(decision.route, ReviewRoute):
                raise TypeError("routing route must be a ReviewRoute")
            if not isinstance(decision.reasons, tuple) or any(
                not isinstance(reason, RouteReason) for reason in decision.reasons
            ):
                raise TypeError("routing reasons must be a tuple of RouteReason values")
            if len(set(decision.reasons)) != len(decision.reasons):
                raise RoutingSchemaError(
                    f"Routing reasons contain duplicates for {parameter_id}"
                )
            if decision.route is ReviewRoute.NO_EXCEPTION_DETECTED:
                if decision.reasons:
                    raise RoutingSchemaError(
                        "NO_EXCEPTION_DETECTED cannot contain exception reasons"
                    )
            elif not decision.reasons:
                raise RoutingSchemaError(
                    f"Exceptional route for {parameter_id} must contain a reason"
                )
            self._validate_route_semantics(decision)
            if parameter_id in self._expected_parameter_id_set:
                canonical = route_parameter(
                    self._routing_signals[parameter_id]
                )
                if decision != canonical:
                    raise RoutingSchemaError(
                        f"Routing for {parameter_id} differs from the frozen "
                        "criticality, quality, alignment, or verdict signals"
                    )

        missing = tuple(
            parameter_id
            for parameter_id in self._expected_parameter_ids
            if parameter_id not in by_parameter
        )
        if (
            missing
            or unknown
            or duplicates
            or len(frozen_decisions) != len(by_parameter)
        ):
            raise RoutingSchemaError(
                "Routing decisions do not exactly cover the frozen Schema",
                missing_parameter_ids=missing,
                unknown_parameter_ids=tuple(unknown),
                duplicate_parameter_ids=tuple(duplicates),
            )
        return tuple(by_parameter[item] for item in self._expected_parameter_ids)

    def _validate_route_semantics(self, decision: RoutingDecision) -> None:
        """Check all facts reproducible from the bound primary and AI snapshots."""

        parameter_id = decision.parameter_id
        if parameter_id not in self._expected_parameter_id_set:
            # Exact Schema diagnostics are assembled by the caller.
            return
        primary = self._primary_decisions[parameter_id]
        ai = self._ai_assessments[parameter_id]
        actual = set(decision.reasons)
        required: set[RouteReason] = set()

        if primary.verdict is HumanVerdict.UNABLE_TO_JUDGE:
            required.add(RouteReason.HUMAN_UNABLE_TO_JUDGE)
        if ai.verdict is AiVerdict.UNABLE_TO_JUDGE:
            required.add(RouteReason.AI_UNABLE_TO_JUDGE)
        if ai.verdict is AiVerdict.SYSTEM_ERROR:
            required.add(RouteReason.AI_SYSTEM_ERROR)

        human_judged = primary.verdict is not HumanVerdict.UNABLE_TO_JUDGE
        ai_judged = ai.verdict not in (
            AiVerdict.UNABLE_TO_JUDGE,
            AiVerdict.SYSTEM_ERROR,
        )
        if human_judged and ai_judged and primary.verdict.value != ai.verdict.value:
            required.add(RouteReason.HUMAN_AI_DISAGREEMENT)
        if primary.verdict is HumanVerdict.DIFFERENT:
            required.add(RouteReason.HUMAN_DETECTED_DIFFERENCE)
        if ai.verdict is AiVerdict.DIFFERENT:
            required.add(RouteReason.AI_DETECTED_DIFFERENCE)
        if (
            ai.comparison_result is not None
            and ai.comparison_result.kind is not ComparisonKind.EXACT_MATCH
        ):
            required.add(RouteReason.DETERMINISTIC_COMPARISON_NOT_EXACT)

        missing = required - actual
        if missing:
            raise RoutingSchemaError(
                f"Routing for {parameter_id} omits bound evidence reasons: "
                + ", ".join(sorted(reason.value for reason in missing))
            )

        fact_checks = {
            RouteReason.HUMAN_UNABLE_TO_JUDGE: (
                primary.verdict is HumanVerdict.UNABLE_TO_JUDGE
            ),
            RouteReason.AI_UNABLE_TO_JUDGE: (
                ai.verdict is AiVerdict.UNABLE_TO_JUDGE
            ),
            RouteReason.AI_SYSTEM_ERROR: ai.verdict is AiVerdict.SYSTEM_ERROR,
            RouteReason.HUMAN_AI_DISAGREEMENT: (
                human_judged
                and ai_judged
                and primary.verdict.value != ai.verdict.value
            ),
            RouteReason.HUMAN_DETECTED_DIFFERENCE: (
                primary.verdict is HumanVerdict.DIFFERENT
            ),
            RouteReason.AI_DETECTED_DIFFERENCE: (
                ai.verdict is AiVerdict.DIFFERENT
            ),
            RouteReason.DETERMINISTIC_COMPARISON_NOT_EXACT: (
                ai.comparison_result is not None
                and ai.comparison_result.kind is not ComparisonKind.EXACT_MATCH
            ),
        }
        contradicted = tuple(
            reason
            for reason, fact_is_true in fact_checks.items()
            if reason in actual and not fact_is_true
        )
        if contradicted:
            raise RoutingSchemaError(
                f"Routing for {parameter_id} asserts unsupported reasons: "
                + ", ".join(reason.value for reason in contradicted)
            )

        qa_only_reasons = {
            RouteReason.MISSING_EXPECTED_FIELD,
            RouteReason.DUPLICATE_EXPECTED_FIELD,
            RouteReason.UNKNOWN_FIELD,
            RouteReason.AI_SYSTEM_ERROR,
        }
        if (
            actual & qa_only_reasons
            and decision.route is not ReviewRoute.QA_REVIEW_REQUIRED
        ):
            raise RoutingSchemaError(
                f"Structural or AI-system exception for {parameter_id} must "
                "take the QA route"
            )

    def _routing_exceptions(
        self,
        decisions: tuple[RoutingDecision, ...],
        detected_at: datetime,
    ) -> tuple[ExceptionItem, ...]:
        result: list[ExceptionItem] = []
        for decision in decisions:
            for reason in decision.reasons:
                result.append(
                    self._make_exception(
                        parameter_id=decision.parameter_id,
                        source=ExceptionSource.ROUTING,
                        reason_code=reason.value,
                        detected_at=detected_at,
                    )
                )
        return tuple(result)

    def _reconciliation_exceptions(
        self,
        submission: LockedSecondReviewSubmission,
        detected_at: datetime,
    ) -> tuple[ExceptionItem, ...]:
        second_by_parameter = {
            decision.parameter_id: decision for decision in submission.decisions
        }
        result: list[ExceptionItem] = []
        for parameter_id in self._expected_parameter_ids:
            primary = self._primary_decisions[parameter_id]
            ai = self._ai_assessments[parameter_id]
            second = second_by_parameter[parameter_id]
            reasons: list[ReconciliationReason] = []
            if second.verdict is BlindVerdict.UNABLE_TO_JUDGE:
                reasons.append(ReconciliationReason.SECOND_REVIEW_UNABLE_TO_JUDGE)
            if primary.verdict.value != second.verdict.value:
                reasons.append(ReconciliationReason.PRIMARY_SECOND_DISAGREEMENT)
            if (
                ai.verdict not in (AiVerdict.UNABLE_TO_JUDGE, AiVerdict.SYSTEM_ERROR)
                and ai.verdict.value != second.verdict.value
            ):
                reasons.append(ReconciliationReason.AI_SECOND_DISAGREEMENT)
            for reason in reasons:
                candidate = self._make_exception(
                    parameter_id=parameter_id,
                    source=ExceptionSource.SECOND_REVIEW_RECONCILIATION,
                    reason_code=reason.value,
                    detected_at=detected_at,
                )
                if candidate.exception_id not in self._exception_by_id:
                    result.append(candidate)
        return tuple(result)

    def _resolve_locked_second_submission(
        self,
        submitted: LockedSecondReviewSubmission,
        *,
        command_id: str,
    ) -> LockedSecondReviewSubmission:
        """Resolve the unique LOCKED record from a trusted blind-review store.

        A public SHA-256 proves content consistency, not authorship or workflow
        provenance.  The injected resolver is therefore the security boundary:
        under one trusted transaction it must return and claim for this task the
        unique, unconsumed LOCKED record for this assignment and command ID.
        """

        if (
            self._expected_blind_case_id is None
            or self._locked_second_submission_resolver is None
        ):
            raise SecondReviewAssignmentMissingError(
                "This case has no trusted blind-review record resolver"
            )
        try:
            trusted = self._locked_second_submission_resolver(
                self._task_id,
                self._expected_blind_case_id,
                submitted.submission_hash,
                _require_identifier("command_id", command_id),
            )
        except Exception as error:
            raise SecondReviewBindingError(
                f"Could not resolve trusted locked second review: {error}"
            ) from error
        if not isinstance(trusted, LockedSecondReviewSubmission):
            raise SecondReviewBindingError(
                "Trusted blind-review store has no unique LOCKED submission"
            )
        if trusted != submitted:
            raise SecondReviewBindingError(
                "Submitted second review is not the trusted LOCKED store record"
            )
        self._validate_second_submission(trusted)
        return trusted

    def _validate_second_submission(
        self, submission: LockedSecondReviewSubmission
    ) -> None:
        if not isinstance(submission, LockedSecondReviewSubmission):
            raise TypeError("submission must be a LockedSecondReviewSubmission")
        if (
            self._expected_blind_case_id is None
            or self._expected_second_reviewer_id is None
        ):
            raise SecondReviewAssignmentMissingError(
                "This case has no bound blind second-review assignment"
            )
        if (
            submission.blind_case_id != self._expected_blind_case_id
            or submission.reviewer_id != self._expected_second_reviewer_id
            or submission.reviewer_id == self._primary_reviewer_id
            or submission.evidence_manifest_hash != self._manifest_hash
        ):
            raise SecondReviewBindingError(
                "Second-review submission identity or evidence does not match this case"
            )
        _aware_utc("second-review lock time", submission.locked_at)
        if not isinstance(submission.decisions, tuple):
            raise SecondReviewBindingError("Second-review decisions must be a tuple")
        if tuple(item.parameter_id for item in submission.decisions) != (
            self._expected_parameter_ids
        ):
            raise SecondReviewBindingError(
                "Second-review decisions must exactly follow the frozen Schema order"
            )
        for decision in submission.decisions:
            if not isinstance(decision, SecondReviewDecision):
                raise SecondReviewBindingError(
                    "Second-review snapshot contains an invalid decision type"
                )
            if (
                decision.reviewer_id != submission.reviewer_id
                or decision.evidence_manifest_hash != self._manifest_hash
                or not isinstance(decision.verdict, BlindVerdict)
            ):
                raise SecondReviewBindingError(
                    "Second-review decision identity or evidence is inconsistent"
                )
            _aware_utc("second-review decision time", decision.decided_at)
            if decision.reason is not None:
                try:
                    _require_text("second-review reason", decision.reason)
                except (TypeError, ValueError) as error:
                    raise SecondReviewBindingError(
                        f"Second-review reason is invalid: {error}"
                    ) from error
            if decision.verdict is not BlindVerdict.SAME and decision.reason is None:
                raise SecondReviewBindingError(
                    "Exceptional second-review decision has no reason"
                )
            if decision.decided_at > submission.locked_at:
                raise SecondReviewBindingError(
                    "Second-review decision cannot occur after the lock time"
                )
        calculated = self._calculate_submission_hash(submission)
        if submission.submission_hash != calculated:
            raise SecondReviewBindingError(
                "Second-review submission hash does not match its locked content"
            )

    @staticmethod
    def _calculate_submission_hash(
        submission: LockedSecondReviewSubmission,
    ) -> str:
        body = {
            "blind_case_id": submission.blind_case_id,
            "evidence_manifest_hash": submission.evidence_manifest_hash,
            "reviewer_id": submission.reviewer_id,
            "locked_at": submission.locked_at.isoformat(),
            "decisions": [
                {
                    "parameter_id": decision.parameter_id,
                    "verdict": decision.verdict.value,
                    "reason": decision.reason,
                    "decided_at": decision.decided_at.isoformat(),
                    "evidence_manifest_hash": decision.evidence_manifest_hash,
                }
                for decision in submission.decisions
            ],
        }
        return _canonical_hash(body)

    def _make_exception(
        self,
        *,
        parameter_id: str,
        source: ExceptionSource,
        reason_code: str,
        detected_at: datetime,
    ) -> ExceptionItem:
        digest = _canonical_hash(
            {
                "task_id": self._task_id,
                "parameter_id": parameter_id,
                "source": source.value,
                "reason_code": reason_code,
            }
        )
        return ExceptionItem(
            exception_id="exc-" + digest[:24],
            parameter_id=parameter_id,
            source=source,
            reason_code=reason_code,
            detected_at=detected_at,
        )

    def _install_exceptions(self, items: Sequence[ExceptionItem]) -> None:
        for item in items:
            existing = self._exception_by_id.get(item.exception_id)
            if existing is not None and (
                existing.parameter_id,
                existing.source,
                existing.reason_code,
            ) != (item.parameter_id, item.source, item.reason_code):
                raise AdjudicationError("Deterministic exception ID collision")
            if existing is None:
                self._exceptions.append(item)
                self._exception_by_id[item.exception_id] = item

    @staticmethod
    def _routing_record(decision: RoutingDecision) -> dict[str, Any]:
        return {
            "parameter_id": decision.parameter_id,
            "route": decision.route.value,
            "reasons": [reason.value for reason in decision.reasons],
        }

    @staticmethod
    def _validate_reference_ids(reference_ids: tuple[str, ...]) -> tuple[str, ...]:
        if not isinstance(reference_ids, tuple):
            raise TypeError("reference_ids must be a tuple")
        checked = tuple(
            _require_identifier("reference_id", value) for value in reference_ids
        )
        if len(set(checked)) != len(checked):
            raise ValueError("reference_ids must not contain duplicates")
        return checked

    @staticmethod
    def _authorize_qa(actor: Actor) -> None:
        if not isinstance(actor, Actor):
            raise TypeError("actor must be an Actor")
        if (
            actor.kind is not PrincipalKind.HUMAN
            or not actor.has_role(Role.QA_REVIEWER)
            or actor.has_role(Role.ADMIN)
            or actor.has_role(Role.AI_WORKER)
        ):
            raise UnauthorizedQaActorError(
                "QA disposition requires a non-admin human QA_REVIEWER"
            )

    @staticmethod
    def _authorize_final(actor: Actor) -> None:
        if not isinstance(actor, Actor):
            raise TypeError("actor must be an Actor")
        if (
            actor.kind is not PrincipalKind.HUMAN
            or not actor.has_role(Role.FINAL_APPROVER)
            or actor.has_role(Role.ADMIN)
            or actor.has_role(Role.AI_WORKER)
        ):
            raise UnauthorizedFinalActorError(
                "Final decision requires a non-admin human FINAL_APPROVER"
            )

    def _require_state(self, expected: AdjudicationState) -> None:
        if self._state is not expected:
            raise InvalidAdjudicationTransitionError(
                f"Expected state {expected.value}, current state {self._state.value}"
            )

    def _require_version(self, expected_version: int) -> None:
        if type(expected_version) is not int or expected_version < 0:
            raise ValueError("expected_version must be a non-negative integer")
        if expected_version != self._version:
            raise StaleAdjudicationVersionError(
                f"Expected version {expected_version}, current version {self._version}"
            )

    def _idempotent_result(
        self, command_id: str, payload: dict[str, Any]
    ) -> Any | None:
        checked_command_id = _require_identifier("command_id", command_id)
        stored = self._commands.get(checked_command_id)
        if stored is None:
            return None
        payload_hash = _canonical_hash(payload)
        if stored.payload_hash != payload_hash:
            raise DuplicateAdjudicationCommandConflictError(
                "The command ID was already used with a different payload"
            )
        return stored.result

    def _remember_command(
        self, command_id: str, payload: dict[str, Any], result: Any
    ) -> None:
        checked_command_id = _require_identifier("command_id", command_id)
        self._commands[checked_command_id] = _StoredCommand(
            payload_hash=_canonical_hash(payload), result=result
        )

    def _resolution_digest(self) -> str:
        """Hash domain evidence only; the final CAS binds the audit head separately."""

        body = {
            "task_id": self._task_id,
            "evidence_manifest_hash": self._manifest_hash,
            "primary": [
                {
                    "parameter_id": parameter_id,
                    "verdict": self._primary_decisions[parameter_id].verdict.value,
                    "reviewer_id": self._primary_decisions[
                        parameter_id
                    ].reviewer_id,
                    "reason": self._primary_decisions[parameter_id].reason,
                    "decided_at": self._primary_decisions[
                        parameter_id
                    ].decided_at.isoformat(),
                    "evidence_manifest_hash": self._primary_decisions[
                        parameter_id
                    ].evidence_manifest_hash,
                }
                for parameter_id in self._expected_parameter_ids
            ],
            "primary_locked_at": self._primary_locked_at.isoformat(),
            "ai_run": {
                "run_id": self._ai_run.run_id,
                "evidence_manifest_hash": self._ai_run.evidence_manifest_hash,
                "engine_name": self._ai_run.engine_name,
                "engine_version": self._ai_run.engine_version,
                "pipeline_version": self._ai_run.pipeline_version,
                "comparator_version": self._ai_run.comparator_version,
                "pipeline_spec_hash": self._ai_run.pipeline_spec_hash,
                "queued_at": self._ai_run.queued_at.isoformat(),
                "started_at": None
                if self._ai_run.started_at is None
                else self._ai_run.started_at.isoformat(),
            },
            "ai": [
                {
                    "parameter_id": parameter_id,
                    "verdict": self._ai_assessments[parameter_id].verdict.value,
                    "run_id": self._ai_assessments[parameter_id].run_id,
                    "evidence_manifest_hash": self._ai_assessments[
                        parameter_id
                    ].evidence_manifest_hash,
                    "engine_name": self._ai_assessments[
                        parameter_id
                    ].engine_name,
                    "engine_version": self._ai_assessments[
                        parameter_id
                    ].engine_version,
                    "pipeline_version": self._ai_assessments[
                        parameter_id
                    ].pipeline_version,
                    "comparator_version": self._ai_assessments[
                        parameter_id
                    ].comparator_version,
                    "pipeline_spec_hash": self._ai_assessments[
                        parameter_id
                    ].pipeline_spec_hash,
                    "left_raw": self._ai_assessments[parameter_id].left_raw,
                    "right_raw": self._ai_assessments[parameter_id].right_raw,
                    "extraction_reliable": self._ai_assessments[
                        parameter_id
                    ].extraction_reliable,
                    "comparison": self._comparison_record(
                        self._ai_assessments[parameter_id]
                    ),
                    "reason": self._ai_assessments[parameter_id].reason,
                    "assessed_at": self._ai_assessments[
                        parameter_id
                    ].assessed_at.isoformat(),
                }
                for parameter_id in self._expected_parameter_ids
            ],
            "routing_evidence_context": {
                "routing_rules_version": (
                    self._routing_evidence_context.routing_rules_version
                ),
                "criticality_source_sha256": (
                    self._routing_evidence_context.criticality_source_sha256
                ),
                "quality_report_sha256": (
                    self._routing_evidence_context.quality_report_sha256
                ),
                "alignment_report_sha256": (
                    self._routing_evidence_context.alignment_report_sha256
                ),
            },
            "routing_signals": [
                {
                    "parameter_id": parameter_id,
                    "human_verdict": self._routing_signals[
                        parameter_id
                    ].human_verdict.value,
                    "ai_verdict": self._routing_signals[
                        parameter_id
                    ].ai_verdict.value,
                    "comparison_kind": self._routing_signals[
                        parameter_id
                    ].comparison_kind.value,
                    "is_critical": self._routing_signals[
                        parameter_id
                    ].is_critical,
                    "image_quality": self._routing_signals[
                        parameter_id
                    ].image_quality.value,
                    "field_issues": [
                        issue.value
                        for issue in self._routing_signals[
                            parameter_id
                        ].field_issues
                    ],
                }
                for parameter_id in self._expected_parameter_ids
            ],
            "routing": [self._routing_record(item) for item in self._routing],
            "second_submission_hash": None
            if self._second_submission is None
            else self._second_submission.submission_hash,
            "exceptions": [
                {
                    "exception_id": item.exception_id,
                    "parameter_id": item.parameter_id,
                    "source": item.source.value,
                    "reason_code": item.reason_code,
                    "detected_at": item.detected_at.isoformat(),
                }
                for item in self._exceptions
            ],
            "qa_dispositions": [
                {
                    "exception_id": exception_id,
                    "outcome": self._qa_dispositions[exception_id].outcome.value,
                    "rationale": self._qa_dispositions[exception_id].rationale,
                    "reference_ids": list(
                        self._qa_dispositions[exception_id].reference_ids
                    ),
                    "qa_actor_id": self._qa_dispositions[exception_id].qa_actor_id,
                    "disposed_at": self._qa_dispositions[
                        exception_id
                    ].disposed_at.isoformat(),
                }
                for exception_id in sorted(self._qa_dispositions)
            ],
        }
        return _canonical_hash(body)

    @staticmethod
    def _comparison_record(assessment: AiAssessment) -> dict[str, Any] | None:
        result = assessment.comparison_result
        if result is None:
            return None
        return {
            "left_raw": result.left_raw,
            "right_raw": result.right_raw,
            "exact_match": result.exact_match,
            "kind": result.kind.value,
            "explanation": result.explanation,
            "left_number": None
            if result.left_number is None
            else str(result.left_number),
            "right_number": None
            if result.right_number is None
            else str(result.right_number),
            "left_unit": result.left_unit,
            "right_unit": result.right_unit,
        }

    def _now(self) -> datetime:
        return _aware_utc("clock result", self._clock())
