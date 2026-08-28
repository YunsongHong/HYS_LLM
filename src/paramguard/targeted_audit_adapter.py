"""Typed bridge from targeted adjudication to :mod:`paramguard.audit`."""

from __future__ import annotations

from .audit import (
    AuditAction,
    JsonlAuditLog,
    TargetedFinalAuditWriteRequest,
    TargetedLockAuditWriteRequest,
    TargetedQaAuditWriteRequest,
)
from .targeted_adjudication import (
    TargetedAuditCommitReceipt,
    TargetedFinalCommitRequest,
    TargetedLockCommitRequest,
    TargetedQaCommitRequest,
)


class JsonlTargetedAuditAdapter:
    """Delegate every irreversible targeted event to one atomic JSONL API."""

    def __init__(self, audit_log: JsonlAuditLog) -> None:
        if not isinstance(audit_log, JsonlAuditLog):
            raise TypeError("audit_log must be a JsonlAuditLog")
        self._audit_log = audit_log

    def commit_lock(
        self, request: TargetedLockCommitRequest
    ) -> TargetedAuditCommitReceipt:
        if type(request) is not TargetedLockCommitRequest:
            raise TypeError("request must be a TargetedLockCommitRequest")
        event = self._audit_log.commit_targeted_lock_cas(
            TargetedLockAuditWriteRequest(
                task_id=request.task_id,
                actor_id=request.actor_id,
                primary_reviewer_id=request.primary_reviewer_id,
                ai_run_id=request.ai_run_id,
                targeted_reviewer_kind=request.targeted_reviewer_kind.value,
                targeted_reviewer_roles=tuple(
                    role.value for role in request.targeted_reviewer_roles
                ),
                assigned_qa_reviewer_id=(
                    request.assigned_qa_reviewer_id
                ),
                assigned_final_approver_id=(
                    request.assigned_final_approver_id
                ),
                evidence_context=request.evidence_context,
                submission_json=request.submission_json,
                submission_hash=request.submission_hash,
                expected_previous_head_hash=request.expected_previous_head_hash,
                command_id=request.command_id,
                request_hash=request.request_hash,
            )
        )
        return self._receipt(event, request.request_hash)

    def accept_qa_disposition(
        self, request: TargetedQaCommitRequest
    ) -> TargetedAuditCommitReceipt:
        if type(request) is not TargetedQaCommitRequest:
            raise TypeError("request must be a TargetedQaCommitRequest")
        event = self._audit_log.accept_targeted_qa_disposition_cas(
            TargetedQaAuditWriteRequest(
                task_id=request.task_id,
                actor_id=request.actor_id,
                targeted_submission_hash=request.targeted_submission_hash,
                exception_id=request.exception_id,
                outcome=request.outcome.value,
                rationale=request.rationale,
                reference_ids=request.reference_ids,
                expected_adjudication_version=(
                    request.expected_adjudication_version
                ),
                expected_previous_head_hash=request.expected_previous_head_hash,
                command_id=request.command_id,
                request_hash=request.request_hash,
            )
        )
        return self._receipt(event, request.request_hash)

    def commit_final(
        self, request: TargetedFinalCommitRequest
    ) -> TargetedAuditCommitReceipt:
        if type(request) is not TargetedFinalCommitRequest:
            raise TypeError("request must be a TargetedFinalCommitRequest")
        action = (
            AuditAction.TARGETED_FINAL_APPROVAL_RECORDED
            if request.decision.value == "APPROVED"
            else AuditAction.TARGETED_FINAL_REJECTION_RECORDED
        )
        event = self._audit_log.commit_targeted_final_cas(
            TargetedFinalAuditWriteRequest(
                task_id=request.task_id,
                action=action,
                actor_id=request.actor_id,
                rationale=request.rationale,
                evidence_manifest_hash=request.evidence_manifest_hash,
                targeted_submission_hash=request.targeted_submission_hash,
                primary_reviewer_id=request.primary_reviewer_id,
                ai_run_id=request.ai_run_id,
                expected_parameter_ids=request.expected_parameter_ids,
                exception_ids=request.exception_ids,
                qa_required_exception_ids=request.qa_required_exception_ids,
                qa_disposition_exception_ids=(
                    request.qa_disposition_exception_ids
                ),
                resolution_digest=request.resolution_digest,
                expected_adjudication_version=(
                    request.expected_adjudication_version
                ),
                expected_previous_head_hash=request.expected_previous_head_hash,
                command_id=request.command_id,
                request_hash=request.request_hash,
            )
        )
        return self._receipt(event, request.request_hash)

    @staticmethod
    def _receipt(event, request_hash: str) -> TargetedAuditCommitReceipt:
        return TargetedAuditCommitReceipt(
            request_hash=request_hash,
            previous_head_hash=event.previous_hash,
            new_head_hash=event.event_hash,
            event_id=event.event_id,
            committed_at=event.occurred_at,
        )
