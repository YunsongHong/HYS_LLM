"""Trusted downstream closure for the interview-style targeted profile.

The aggregate consumes a locked targeted submission through a composition-root
resolver.  No public command accepts source, profile, partition, manifest, run,
or submission hashes from a client.  Those facts are copied only from the
resolver record and are then committed through typed JSONL compare-and-swap
operations.

This remains a learning PoC: :class:`~paramguard.identity.Actor` is assumed to
come from an authenticated server boundary, and the JSONL file is not a
validated identity, e-signature, database, or WORM system.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from threading import RLock
from types import MappingProxyType
from typing import Any, Protocol

from .adjudication import FinalDecisionKind, QaDispositionOutcome
from .audit import (
    EvidenceContext,
    calculate_targeted_exception_records,
    calculate_targeted_final_request_hash,
    calculate_targeted_lock_request_hash,
    calculate_targeted_qa_request_hash,
    calculate_targeted_resolution_digest,
)
from .identity import Actor, PrincipalKind, Role
from .targeted_review import (
    LockedTargetedReviewSubmission,
    canonical_locked_targeted_submission_record,
    validate_locked_targeted_submission,
)


class TargetedAdjudicationState(str, Enum):
    AUDIT_LOCK_PENDING = "AUDIT_LOCK_PENDING"
    QA_DISPOSITION_OPEN = "QA_DISPOSITION_OPEN"
    READY_FOR_FINAL_HUMAN_DECISION = "READY_FOR_FINAL_HUMAN_DECISION"
    APPROVAL_BLOCKED = "APPROVAL_BLOCKED"
    REWORK_REQUIRED = "REWORK_REQUIRED"
    FINAL_APPROVED = "FINAL_APPROVED"
    FINAL_REJECTED = "FINAL_REJECTED"


class TargetedExceptionOrigin(str, Enum):
    TARGETED_RECHECK = "TARGETED_RECHECK"
    PROFILE_QA_REFERRAL = "PROFILE_QA_REFERRAL"


class TargetedAdjudicationError(Exception):
    code = "TARGETED_ADJUDICATION_ERROR"


class TrustedTargetedRecordError(TargetedAdjudicationError):
    code = "TRUSTED_TARGETED_RECORD_ERROR"


class InvalidTargetedTransitionError(TargetedAdjudicationError):
    code = "INVALID_TARGETED_TRANSITION"


class StaleTargetedAdjudicationVersionError(TargetedAdjudicationError):
    code = "STALE_TARGETED_ADJUDICATION_VERSION"


class DuplicateTargetedAdjudicationCommandError(TargetedAdjudicationError):
    code = "DUPLICATE_TARGETED_ADJUDICATION_COMMAND"


class UnknownTargetedExceptionError(TargetedAdjudicationError):
    code = "UNKNOWN_TARGETED_EXCEPTION"


class TargetedQaNotRequiredError(TargetedAdjudicationError):
    code = "TARGETED_QA_NOT_REQUIRED"


class DuplicateTargetedQaDispositionError(TargetedAdjudicationError):
    code = "DUPLICATE_TARGETED_QA_DISPOSITION"


class UnauthorizedTargetedQaActorError(TargetedAdjudicationError):
    code = "UNAUTHORIZED_TARGETED_QA_ACTOR"


class UnauthorizedTargetedFinalActorError(TargetedAdjudicationError):
    code = "UNAUTHORIZED_TARGETED_FINAL_ACTOR"


class TargetedApprovalBlockedError(TargetedAdjudicationError):
    code = "TARGETED_APPROVAL_BLOCKED"


class TargetedFinalAlreadyRecordedError(TargetedAdjudicationError):
    code = "TARGETED_FINAL_ALREADY_RECORDED"


class TargetedAuditVerificationError(TargetedAdjudicationError):
    code = "TARGETED_AUDIT_VERIFICATION_ERROR"


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _require_identifier(name: str, value: str) -> str:
    if type(value) is not str or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe 1-128 character identifier")
    return value


def _require_sha256(name: str, value: str) -> str:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _require_text(name: str, value: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{name} must be str")
    if value.strip() == "":
        raise ValueError(f"{name} must not be empty or whitespace")
    return value


def _aware_utc(name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include timezone information")
    return value.astimezone(timezone.utc)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedTargetedSubmissionRecord:
    """Server-resolved record; callers do not supply its anchors to commands."""

    task_id: str
    primary_reviewer_id: str
    ai_run_id: str
    targeted_reviewer: Actor
    assigned_qa_reviewer_id: str | None
    assigned_final_approver_id: str
    evidence_context: EvidenceContext
    submission: LockedTargetedReviewSubmission
    expected_source_snapshot_sha256: str
    expected_submission_hash: str

    def __post_init__(self) -> None:
        try:
            _require_identifier("task_id", self.task_id)
            _require_identifier("primary_reviewer_id", self.primary_reviewer_id)
            _require_identifier("ai_run_id", self.ai_run_id)
            if self.assigned_qa_reviewer_id is not None:
                _require_identifier(
                    "assigned_qa_reviewer_id",
                    self.assigned_qa_reviewer_id,
                )
            _require_identifier(
                "assigned_final_approver_id",
                self.assigned_final_approver_id,
            )
            _require_sha256(
                "expected_source_snapshot_sha256",
                self.expected_source_snapshot_sha256,
            )
            _require_sha256(
                "expected_submission_hash", self.expected_submission_hash
            )
            if type(self.targeted_reviewer) is not Actor:
                raise TypeError("targeted_reviewer must be an exact Actor")
            if (
                self.targeted_reviewer.kind is not PrincipalKind.HUMAN
                or not self.targeted_reviewer.roles
                or not self.targeted_reviewer.roles
                <= frozenset({Role.PRIMARY_REVIEWER, Role.SECOND_REVIEWER})
            ):
                raise ValueError(
                    "targeted_reviewer must be a human with only reviewer roles"
                )
            if type(self.evidence_context) is not EvidenceContext:
                raise TypeError("evidence_context must be an exact EvidenceContext")
            if type(self.submission) is not LockedTargetedReviewSubmission:
                raise TypeError(
                    "submission must be an exact LockedTargetedReviewSubmission"
                )
            validate_locked_targeted_submission(
                self.submission,
                expected_source_snapshot_sha256=(
                    self.expected_source_snapshot_sha256
                ),
                expected_submission_hash=self.expected_submission_hash,
            )
        except Exception as error:
            if isinstance(error, TrustedTargetedRecordError):
                raise
            raise TrustedTargetedRecordError(
                f"Trusted targeted resolver record is invalid: {error}"
            ) from error
        if self.submission.task_id != self.task_id:
            raise TrustedTargetedRecordError("submission belongs to another task")
        if self.submission.reviewer_id != self.targeted_reviewer.actor_id:
            raise TrustedTargetedRecordError(
                "submission reviewer differs from the trusted assignment actor"
            )
        if self.evidence_context.manifest_hash != self.submission.evidence_manifest_hash:
            raise TrustedTargetedRecordError(
                "audit context differs from the targeted evidence manifest"
            )
        if self.evidence_context.run_id != self.ai_run_id:
            raise TrustedTargetedRecordError(
                "audit context differs from the trusted completed AI run"
            )
        if (
            self.evidence_context.pipeline_spec_hash is None
            or self.evidence_context.pipeline_version is None
            or self.evidence_context.comparator_version is None
            or (
                self.evidence_context.ocr_engine is None
                and self.evidence_context.model_name is None
            )
        ):
            raise TrustedTargetedRecordError(
                "targeted audit context lacks complete AI provenance"
            )
        canonical = canonical_locked_targeted_submission_record(self.submission)
        if _canonical_hash(canonical) != self.expected_submission_hash:
            raise TrustedTargetedRecordError(
                "canonical submission differs from its trusted anchor"
            )
        exceptions = calculate_targeted_exception_records(
            canonical,
            submission_hash=self.expected_submission_hash,
        )
        if (
            any(item["qa_required"] for item in exceptions)
            and self.assigned_qa_reviewer_id is None
        ):
            raise TrustedTargetedRecordError(
                "QA-required targeted exceptions need a trusted QA assignment"
            )
        prior_actor_ids = {
            self.primary_reviewer_id,
            self.targeted_reviewer.actor_id,
        }
        if (
            self.assigned_qa_reviewer_id is not None
            and self.assigned_qa_reviewer_id in prior_actor_ids
        ):
            raise TrustedTargetedRecordError(
                "trusted QA assignment must be independent of prior reviewers"
            )
        if self.assigned_final_approver_id in {
            *prior_actor_ids,
            self.assigned_qa_reviewer_id,
        }:
            raise TrustedTargetedRecordError(
                "trusted final assignment must be independent of earlier roles"
            )


class TrustedTargetedSubmissionResolver(Protocol):
    def resolve_locked_submission(
        self, *, task_id: str
    ) -> TrustedTargetedSubmissionRecord: ...


@dataclass(frozen=True, slots=True)
class TargetedException:
    exception_id: str
    parameter_id: str
    origin: TargetedExceptionOrigin
    targeted_verdict: str | None
    qa_required: bool

    @property
    def closed_by_targeted_review(self) -> bool:
        """Even a targeted SAME observation does not close the exception."""

        return False


@dataclass(frozen=True, slots=True)
class TargetedQaDisposition:
    exception_id: str
    outcome: QaDispositionOutcome
    rationale: str
    reference_ids: tuple[str, ...]
    qa_actor_id: str
    accepted_at: datetime


@dataclass(frozen=True, slots=True)
class TargetedFinalDecision:
    decision: FinalDecisionKind
    actor_id: str
    rationale: str
    decided_at: datetime
    resolution_digest: str
    previous_audit_head_hash: str
    audit_head_hash: str


@dataclass(frozen=True, slots=True)
class TargetedAuditCommitReceipt:
    request_hash: str
    previous_head_hash: str
    new_head_hash: str
    event_id: str
    committed_at: datetime


@dataclass(frozen=True, slots=True)
class TargetedLockCommitRequest:
    task_id: str
    actor_id: str
    primary_reviewer_id: str
    ai_run_id: str
    targeted_reviewer_kind: PrincipalKind
    targeted_reviewer_roles: tuple[Role, ...]
    assigned_qa_reviewer_id: str | None
    assigned_final_approver_id: str
    evidence_context: EvidenceContext
    submission_json: str
    submission_hash: str
    expected_previous_head_hash: str
    command_id: str

    def to_record(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "actor_id": self.actor_id,
            "primary_reviewer_id": self.primary_reviewer_id,
            "ai_run_id": self.ai_run_id,
            "targeted_reviewer_kind": self.targeted_reviewer_kind.value,
            "targeted_reviewer_roles": [
                role.value for role in self.targeted_reviewer_roles
            ],
            "assigned_qa_reviewer_id": self.assigned_qa_reviewer_id,
            "assigned_final_approver_id": self.assigned_final_approver_id,
            "evidence_context": self.evidence_context.to_record(),
            "submission": json.loads(self.submission_json),
            "submission_hash": self.submission_hash,
            "expected_previous_head_hash": self.expected_previous_head_hash,
            "command_id": self.command_id,
        }

    @property
    def request_hash(self) -> str:
        return calculate_targeted_lock_request_hash(self.to_record())


@dataclass(frozen=True, slots=True)
class TargetedQaCommitRequest:
    task_id: str
    actor_id: str
    targeted_submission_hash: str
    exception_id: str
    outcome: QaDispositionOutcome
    rationale: str
    reference_ids: tuple[str, ...]
    expected_adjudication_version: int
    expected_previous_head_hash: str
    command_id: str

    def to_record(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "actor_id": self.actor_id,
            "targeted_submission_hash": self.targeted_submission_hash,
            "exception_id": self.exception_id,
            "outcome": self.outcome.value,
            "rationale": self.rationale,
            "reference_ids": list(self.reference_ids),
            "expected_adjudication_version": self.expected_adjudication_version,
            "expected_previous_head_hash": self.expected_previous_head_hash,
            "command_id": self.command_id,
        }

    @property
    def request_hash(self) -> str:
        return calculate_targeted_qa_request_hash(self.to_record())


@dataclass(frozen=True, slots=True)
class TargetedFinalCommitRequest:
    task_id: str
    decision: FinalDecisionKind
    actor_id: str
    rationale: str
    evidence_manifest_hash: str
    targeted_submission_hash: str
    primary_reviewer_id: str
    ai_run_id: str
    expected_parameter_ids: tuple[str, ...]
    exception_ids: tuple[str, ...]
    qa_required_exception_ids: tuple[str, ...]
    qa_disposition_exception_ids: tuple[str, ...]
    resolution_digest: str
    expected_adjudication_version: int
    expected_previous_head_hash: str
    command_id: str

    def to_record(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "decision": self.decision.value,
            "actor_id": self.actor_id,
            "rationale": self.rationale,
            "evidence_manifest_hash": self.evidence_manifest_hash,
            "targeted_submission_hash": self.targeted_submission_hash,
            "primary_reviewer_id": self.primary_reviewer_id,
            "ai_run_id": self.ai_run_id,
            "expected_parameter_ids": list(self.expected_parameter_ids),
            "exception_ids": list(self.exception_ids),
            "qa_required_exception_ids": list(self.qa_required_exception_ids),
            "qa_disposition_exception_ids": list(
                self.qa_disposition_exception_ids
            ),
            "resolution_digest": self.resolution_digest,
            "expected_adjudication_version": self.expected_adjudication_version,
            "expected_previous_head_hash": self.expected_previous_head_hash,
            "command_id": self.command_id,
        }

    @property
    def request_hash(self) -> str:
        return calculate_targeted_final_request_hash(self.to_record())


class TargetedAuditCommitter(Protocol):
    def commit_lock(
        self, request: TargetedLockCommitRequest
    ) -> TargetedAuditCommitReceipt: ...

    def accept_qa_disposition(
        self, request: TargetedQaCommitRequest
    ) -> TargetedAuditCommitReceipt: ...

    def commit_final(
        self, request: TargetedFinalCommitRequest
    ) -> TargetedAuditCommitReceipt: ...


@dataclass(frozen=True, slots=True)
class _StoredCommand:
    payload_hash: str
    result: Any


class TargetedAdjudicationCase:
    """Revisioned targeted closure with no automatic-release state."""

    def __init__(
        self,
        *,
        task_id: str,
        trusted_submission_resolver: TrustedTargetedSubmissionResolver,
        audit_committer: TargetedAuditCommitter,
    ) -> None:
        self._task_id = _require_identifier("task_id", task_id)
        if not hasattr(trusted_submission_resolver, "resolve_locked_submission"):
            raise TypeError(
                "trusted_submission_resolver must provide resolve_locked_submission"
            )
        if not all(
            hasattr(audit_committer, name)
            for name in ("commit_lock", "accept_qa_disposition", "commit_final")
        ):
            raise TypeError("audit_committer does not implement the typed contract")
        record = trusted_submission_resolver.resolve_locked_submission(
            task_id=self._task_id
        )
        if type(record) is not TrustedTargetedSubmissionRecord:
            raise TrustedTargetedRecordError(
                "resolver returned an invalid trusted record type"
            )
        if record.task_id != self._task_id:
            raise TrustedTargetedRecordError("resolver returned another task")
        self._record = record
        self._audit_committer = audit_committer
        self._submission_record = canonical_locked_targeted_submission_record(
            record.submission
        )
        raw_exceptions = calculate_targeted_exception_records(
            self._submission_record,
            submission_hash=record.expected_submission_hash,
        )
        self._exceptions = tuple(
            TargetedException(
                exception_id=item["exception_id"],
                parameter_id=item["parameter_id"],
                origin=TargetedExceptionOrigin(item["origin"]),
                targeted_verdict=item["targeted_verdict"],
                qa_required=item["qa_required"],
            )
            for item in raw_exceptions
        )
        self._exception_by_id = {
            item.exception_id: item for item in self._exceptions
        }
        self._qa_required_ids = tuple(
            sorted(item.exception_id for item in self._exceptions if item.qa_required)
        )
        self._lock = RLock()
        self._state = TargetedAdjudicationState.AUDIT_LOCK_PENDING
        self._version = 0
        self._qa_dispositions: dict[str, TargetedQaDisposition] = {}
        self._final_decision: TargetedFinalDecision | None = None
        self._commands: dict[str, _StoredCommand] = {}
        self._latest_audit_time = _aware_utc(
            "submission locked_at", record.submission.locked_at
        )

    @property
    def task_id(self) -> str:
        return self._task_id

    @property
    def state(self) -> TargetedAdjudicationState:
        with self._lock:
            return self._state

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    @property
    def automatic_release_allowed(self) -> bool:
        return False

    def exception_ledger(self) -> tuple[TargetedException, ...]:
        return self._exceptions

    def qa_dispositions(self) -> Mapping[str, TargetedQaDisposition]:
        with self._lock:
            return MappingProxyType(dict(self._qa_dispositions))

    @property
    def final_decision(self) -> TargetedFinalDecision | None:
        with self._lock:
            return self._final_decision

    def register_locked_submission(
        self,
        *,
        audit_head_hash: str,
        command_id: str,
        expected_version: int,
    ) -> TargetedAuditCommitReceipt:
        """Durably accept the resolver's lock; no source hash is client input."""

        with self._lock:
            checked_head = _require_sha256("audit_head_hash", audit_head_hash)
            checked_command = _require_identifier("command_id", command_id)
            payload = {
                "operation": "register_locked_submission",
                "audit_head_hash": checked_head,
                "expected_version": expected_version,
            }
            stored = self._idempotent(checked_command, payload)
            if stored is not None:
                assert isinstance(stored, TargetedAuditCommitReceipt)
                return stored
            self._require_state(TargetedAdjudicationState.AUDIT_LOCK_PENDING)
            self._require_version(expected_version)
            request = TargetedLockCommitRequest(
                task_id=self._task_id,
                actor_id=self._record.targeted_reviewer.actor_id,
                primary_reviewer_id=self._record.primary_reviewer_id,
                ai_run_id=self._record.ai_run_id,
                targeted_reviewer_kind=self._record.targeted_reviewer.kind,
                targeted_reviewer_roles=tuple(
                    sorted(
                        self._record.targeted_reviewer.roles,
                        key=lambda role: role.value,
                    )
                ),
                assigned_qa_reviewer_id=(
                    self._record.assigned_qa_reviewer_id
                ),
                assigned_final_approver_id=(
                    self._record.assigned_final_approver_id
                ),
                evidence_context=self._record.evidence_context,
                submission_json=_canonical_json(self._submission_record),
                submission_hash=self._record.expected_submission_hash,
                expected_previous_head_hash=checked_head,
                command_id=checked_command,
            )
            receipt = self._call_audit("commit_lock", request)
            self._state = (
                TargetedAdjudicationState.QA_DISPOSITION_OPEN
                if self._qa_required_ids
                else TargetedAdjudicationState.READY_FOR_FINAL_HUMAN_DECISION
            )
            self._version = 1
            self._remember(checked_command, payload, receipt)
            return receipt

    def record_qa_disposition(
        self,
        *,
        actor: Actor,
        exception_id: str,
        outcome: QaDispositionOutcome,
        rationale: str,
        reference_ids: tuple[str, ...],
        audit_head_hash: str,
        command_id: str,
        expected_version: int,
    ) -> TargetedQaDisposition:
        with self._lock:
            self._authorize_qa(actor)
            checked_exception = _require_identifier("exception_id", exception_id)
            if not isinstance(outcome, QaDispositionOutcome):
                raise TypeError("outcome must be a QaDispositionOutcome")
            checked_rationale = _require_text("rationale", rationale)
            checked_refs = self._validate_reference_ids(reference_ids)
            checked_head = _require_sha256("audit_head_hash", audit_head_hash)
            checked_command = _require_identifier("command_id", command_id)
            payload = {
                "operation": "record_qa_disposition",
                "actor_id": actor.actor_id,
                "actor_kind": actor.kind.value,
                "actor_roles": sorted(role.value for role in actor.roles),
                "exception_id": checked_exception,
                "outcome": outcome.value,
                "rationale": checked_rationale,
                "reference_ids": list(checked_refs),
                "audit_head_hash": checked_head,
                "expected_version": expected_version,
            }
            stored = self._idempotent(checked_command, payload)
            if stored is not None:
                assert isinstance(stored, TargetedQaDisposition)
                return stored
            self._require_state(TargetedAdjudicationState.QA_DISPOSITION_OPEN)
            self._require_version(expected_version)
            exception = self._exception_by_id.get(checked_exception)
            if exception is None:
                raise UnknownTargetedExceptionError(
                    f"Unknown targeted exception: {checked_exception}"
                )
            if not exception.qa_required:
                raise TargetedQaNotRequiredError(
                    "A targeted SAME observation is retained for final human review, "
                    "not converted into a QA disposition"
                )
            if checked_exception in self._qa_dispositions:
                raise DuplicateTargetedQaDispositionError(
                    "The targeted exception already has a QA disposition"
                )
            request = TargetedQaCommitRequest(
                task_id=self._task_id,
                actor_id=actor.actor_id,
                targeted_submission_hash=self._record.expected_submission_hash,
                exception_id=checked_exception,
                outcome=outcome,
                rationale=checked_rationale,
                reference_ids=checked_refs,
                expected_adjudication_version=expected_version,
                expected_previous_head_hash=checked_head,
                command_id=checked_command,
            )
            receipt = self._call_audit("accept_qa_disposition", request)
            disposition = TargetedQaDisposition(
                exception_id=checked_exception,
                outcome=outcome,
                rationale=checked_rationale,
                reference_ids=checked_refs,
                qa_actor_id=actor.actor_id,
                accepted_at=receipt.committed_at,
            )
            self._qa_dispositions[checked_exception] = disposition
            self._version += 1
            if set(self._qa_dispositions) == set(self._qa_required_ids):
                self._state = self._state_after_complete_qa()
            self._remember(checked_command, payload, disposition)
            return disposition

    def approve(
        self,
        *,
        actor: Actor,
        rationale: str,
        audit_head_hash: str,
        command_id: str,
        expected_version: int,
    ) -> TargetedFinalDecision:
        return self._record_final(
            decision=FinalDecisionKind.APPROVED,
            actor=actor,
            rationale=rationale,
            audit_head_hash=audit_head_hash,
            command_id=command_id,
            expected_version=expected_version,
        )

    def reject(
        self,
        *,
        actor: Actor,
        rationale: str,
        audit_head_hash: str,
        command_id: str,
        expected_version: int,
    ) -> TargetedFinalDecision:
        return self._record_final(
            decision=FinalDecisionKind.REJECTED,
            actor=actor,
            rationale=rationale,
            audit_head_hash=audit_head_hash,
            command_id=command_id,
            expected_version=expected_version,
        )

    def _record_final(
        self,
        *,
        decision: FinalDecisionKind,
        actor: Actor,
        rationale: str,
        audit_head_hash: str,
        command_id: str,
        expected_version: int,
    ) -> TargetedFinalDecision:
        with self._lock:
            self._authorize_final(actor)
            checked_rationale = _require_text("rationale", rationale)
            checked_head = _require_sha256("audit_head_hash", audit_head_hash)
            checked_command = _require_identifier("command_id", command_id)
            payload = {
                "operation": "final",
                "decision": decision.value,
                "actor_id": actor.actor_id,
                "actor_kind": actor.kind.value,
                "actor_roles": sorted(role.value for role in actor.roles),
                "rationale": checked_rationale,
                "audit_head_hash": checked_head,
                "expected_version": expected_version,
            }
            stored = self._idempotent(checked_command, payload)
            if stored is not None:
                assert isinstance(stored, TargetedFinalDecision)
                return stored
            if self._final_decision is not None:
                raise TargetedFinalAlreadyRecordedError(
                    "A final targeted decision is already recorded"
                )
            self._require_version(expected_version)
            if decision is FinalDecisionKind.APPROVED:
                if (
                    self._state
                    is not TargetedAdjudicationState.READY_FOR_FINAL_HUMAN_DECISION
                ):
                    raise TargetedApprovalBlockedError(
                        f"Approval is blocked in state {self._state.value}"
                    )
            elif self._state not in {
                TargetedAdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
                TargetedAdjudicationState.APPROVAL_BLOCKED,
                TargetedAdjudicationState.REWORK_REQUIRED,
            }:
                raise InvalidTargetedTransitionError(
                    f"Final rejection is not allowed in {self._state.value}"
                )
            exceptions = self._exception_records()
            dispositions = self._disposition_records()
            resolution_digest = calculate_targeted_resolution_digest(
                task_id=self._task_id,
                submission_hash=self._record.expected_submission_hash,
                exceptions=exceptions,
                dispositions=dispositions,
            )
            request = TargetedFinalCommitRequest(
                task_id=self._task_id,
                decision=decision,
                actor_id=actor.actor_id,
                rationale=checked_rationale,
                evidence_manifest_hash=(
                    self._record.submission.evidence_manifest_hash
                ),
                targeted_submission_hash=self._record.expected_submission_hash,
                primary_reviewer_id=self._record.primary_reviewer_id,
                ai_run_id=self._record.ai_run_id,
                expected_parameter_ids=(
                    self._record.submission.expected_parameter_ids
                ),
                exception_ids=tuple(
                    sorted(item.exception_id for item in self._exceptions)
                ),
                qa_required_exception_ids=self._qa_required_ids,
                qa_disposition_exception_ids=tuple(
                    sorted(self._qa_dispositions)
                ),
                resolution_digest=resolution_digest,
                expected_adjudication_version=expected_version,
                expected_previous_head_hash=checked_head,
                command_id=checked_command,
            )
            receipt = self._call_audit("commit_final", request)
            result = TargetedFinalDecision(
                decision=decision,
                actor_id=actor.actor_id,
                rationale=checked_rationale,
                decided_at=receipt.committed_at,
                resolution_digest=resolution_digest,
                previous_audit_head_hash=receipt.previous_head_hash,
                audit_head_hash=receipt.new_head_hash,
            )
            self._final_decision = result
            self._state = (
                TargetedAdjudicationState.FINAL_APPROVED
                if decision is FinalDecisionKind.APPROVED
                else TargetedAdjudicationState.FINAL_REJECTED
            )
            self._version += 1
            self._remember(checked_command, payload, result)
            return result

    def _call_audit(self, operation: str, request: Any) -> TargetedAuditCommitReceipt:
        try:
            receipt = getattr(self._audit_committer, operation)(request)
        except Exception as error:
            raise TargetedAuditVerificationError(
                f"Atomic targeted audit operation failed: {error}"
            ) from error
        if type(receipt) is not TargetedAuditCommitReceipt:
            raise TargetedAuditVerificationError(
                "Targeted audit adapter returned an invalid receipt type"
            )
        try:
            previous = _require_sha256(
                "receipt previous_head_hash", receipt.previous_head_hash
            )
            new = _require_sha256("receipt new_head_hash", receipt.new_head_hash)
            _require_identifier("receipt event_id", receipt.event_id)
            committed_at = _aware_utc("receipt committed_at", receipt.committed_at)
        except (TypeError, ValueError) as error:
            raise TargetedAuditVerificationError(
                f"Targeted audit receipt is malformed: {error}"
            ) from error
        if receipt.request_hash != request.request_hash:
            raise TargetedAuditVerificationError(
                "Targeted audit receipt is not bound to the request"
            )
        if previous != request.expected_previous_head_hash:
            raise TargetedAuditVerificationError(
                "Targeted audit receipt used an unexpected predecessor"
            )
        if new in {previous, "0" * 64}:
            raise TargetedAuditVerificationError(
                "Targeted audit receipt did not advance the chain"
            )
        if committed_at < self._latest_audit_time:
            raise TargetedAuditVerificationError(
                "Targeted audit receipt predates evidence already accepted"
            )
        self._latest_audit_time = committed_at
        return receipt

    def _state_after_complete_qa(self) -> TargetedAdjudicationState:
        outcomes = {item.outcome for item in self._qa_dispositions.values()}
        if outcomes & {
            QaDispositionOutcome.EVIDENCE_REWORK_REQUIRED,
            QaDispositionOutcome.TASK_INVALIDATED,
        }:
            return TargetedAdjudicationState.REWORK_REQUIRED
        if outcomes & {
            QaDispositionOutcome.CONFIRMED_DIFFERENCE,
            QaDispositionOutcome.EXTERNAL_DEVIATION_CONTROL_REQUIRED,
        }:
            return TargetedAdjudicationState.APPROVAL_BLOCKED
        return TargetedAdjudicationState.READY_FOR_FINAL_HUMAN_DECISION

    def _exception_records(self) -> tuple[dict[str, Any], ...]:
        return calculate_targeted_exception_records(
            self._submission_record,
            submission_hash=self._record.expected_submission_hash,
        )

    def _disposition_records(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            {
                "exception_id": exception_id,
                "outcome": item.outcome.value,
                "rationale": item.rationale,
                "reference_ids": list(item.reference_ids),
                "qa_actor_id": item.qa_actor_id,
            }
            for exception_id, item in sorted(self._qa_dispositions.items())
        )

    def _authorize_qa(self, actor: Actor) -> None:
        if (
            type(actor) is not Actor
            or actor.kind is not PrincipalKind.HUMAN
            or actor.roles != frozenset({Role.QA_REVIEWER})
        ):
            raise UnauthorizedTargetedQaActorError(
                "QA requires an authenticated human with only QA_REVIEWER"
            )
        if actor.actor_id != self._record.assigned_qa_reviewer_id:
            raise UnauthorizedTargetedQaActorError(
                "QA actor differs from the trusted task assignment"
            )

    def _authorize_final(self, actor: Actor) -> None:
        if (
            type(actor) is not Actor
            or actor.kind is not PrincipalKind.HUMAN
            or actor.roles != frozenset({Role.FINAL_APPROVER})
        ):
            raise UnauthorizedTargetedFinalActorError(
                "Final decision requires a human with only FINAL_APPROVER"
            )
        if actor.actor_id != self._record.assigned_final_approver_id:
            raise UnauthorizedTargetedFinalActorError(
                "Final actor differs from the trusted task assignment"
            )

    @staticmethod
    def _validate_reference_ids(values: tuple[str, ...]) -> tuple[str, ...]:
        if not isinstance(values, tuple):
            raise TypeError("reference_ids must be a tuple")
        checked = tuple(_require_identifier("reference_id", item) for item in values)
        if len(set(checked)) != len(checked):
            raise ValueError("reference_ids must not contain duplicates")
        return checked

    def _require_state(self, expected: TargetedAdjudicationState) -> None:
        if self._state is not expected:
            raise InvalidTargetedTransitionError(
                f"Expected {expected.value}, found {self._state.value}"
            )

    def _require_version(self, expected: int) -> None:
        if type(expected) is not int or expected != self._version:
            raise StaleTargetedAdjudicationVersionError(
                f"Expected version {expected!r}, current version is {self._version}"
            )

    def _idempotent(self, command_id: str, payload: Any) -> Any | None:
        stored = self._commands.get(command_id)
        if stored is None:
            return None
        payload_hash = _canonical_hash(payload)
        if stored.payload_hash != payload_hash:
            raise DuplicateTargetedAdjudicationCommandError(
                "command_id was already used for another targeted command"
            )
        return stored.result

    def _remember(self, command_id: str, payload: Any, result: Any) -> None:
        self._commands[command_id] = _StoredCommand(
            payload_hash=_canonical_hash(payload), result=result
        )
