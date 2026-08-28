"""Concrete atomic bridge from adjudication to the JSONL audit store."""

from __future__ import annotations

from .adjudication import (
    FinalAuditCommitReceipt,
    FinalAuditCommitRequest,
    FinalDecisionKind,
    final_audit_commit_request_hash,
)
from .audit import (
    AuditAction,
    AuditPolicyError,
    FinalAuditWriteRequest,
    JsonlAuditLog,
)


class JsonlFinalAuditCommitter:
    """Commit a domain final decision through ``JsonlAuditLog``'s CAS API.

    This adapter performs no read-then-write sequence of its own.  It converts
    the domain request into the audit module's typed request and delegates to
    the public atomic method whose verification and write share one file lock.
    """

    def __init__(self, audit_log: JsonlAuditLog) -> None:
        if not isinstance(audit_log, JsonlAuditLog):
            raise TypeError("audit_log must be a JsonlAuditLog")
        self._audit_log = audit_log

    def __call__(
        self, request: FinalAuditCommitRequest
    ) -> FinalAuditCommitReceipt:
        return self.commit(request)

    def commit(
        self, request: FinalAuditCommitRequest
    ) -> FinalAuditCommitReceipt:
        if not isinstance(request, FinalAuditCommitRequest):
            raise TypeError("request must be a FinalAuditCommitRequest")
        if request.decision is FinalDecisionKind.APPROVED:
            action = AuditAction.FINAL_APPROVAL_RECORDED
        elif request.decision is FinalDecisionKind.REJECTED:
            action = AuditAction.FINAL_REJECTION_RECORDED
        else:  # pragma: no cover - enum exhaustiveness guard
            raise TypeError("request decision must be a FinalDecisionKind")

        if "SECOND_REVIEW_RECORDED" in request.required_prior_actions:
            raise AuditPolicyError(
                "Legacy SECOND_REVIEW_RECORDED cannot satisfy final coverage"
            )
        try:
            required_actions = tuple(
                AuditAction(value) for value in request.required_prior_actions
            )
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(
                "Final request contains an unknown required audit action"
            ) from error

        request_hash = final_audit_commit_request_hash(request)
        write_request = FinalAuditWriteRequest(
            task_id=request.task_id,
            action=action,
            actor_id=request.actor_id,
            rationale=request.rationale,
            evidence_manifest_hash=request.evidence_manifest_hash,
            second_submission_hash=request.second_submission_hash,
            primary_reviewer_id=request.primary_reviewer_id,
            ai_run_id=request.ai_run_id,
            expected_parameter_ids=request.expected_parameter_ids,
            exception_ids=request.exception_ids,
            qa_disposition_exception_ids=(
                request.qa_disposition_exception_ids
            ),
            resolution_digest=request.resolution_digest,
            expected_adjudication_version=(
                request.expected_adjudication_version
            ),
            expected_previous_head_hash=request.expected_previous_head_hash,
            required_prior_actions=required_actions,
            command_id=request.command_id,
            commit_request_hash=request_hash,
        )
        event = self._audit_log.commit_final_cas(write_request)
        if (
            event.details["commit_request_hash"] != request_hash
            or event.details["command_id"] != request.command_id
            or event.previous_hash != request.expected_previous_head_hash
        ):
            raise AuditPolicyError(
                "Durable final event is not exactly bound to the commit request"
            )
        return FinalAuditCommitReceipt(
            request_hash=request_hash,
            previous_head_hash=event.previous_hash,
            new_head_hash=event.event_hash,
            event_id=event.event_id,
            committed_at=event.occurred_at,
        )
