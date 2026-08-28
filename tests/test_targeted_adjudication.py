"""Adversarial domain tests for trusted targeted downstream closure."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
from threading import Barrier, Lock, Thread
import unittest

from paramguard.adjudication import FinalDecisionKind, QaDispositionOutcome
from paramguard.audit import EvidenceContext
from paramguard.identity import Actor, PrincipalKind, Role
from paramguard.routing import FieldIssue
from paramguard.targeted_adjudication import (
    DuplicateTargetedAdjudicationCommandError,
    StaleTargetedAdjudicationVersionError,
    TargetedAdjudicationCase,
    TargetedAdjudicationState,
    TargetedApprovalBlockedError,
    TargetedAuditCommitReceipt,
    TargetedFinalAlreadyRecordedError,
    TargetedQaNotRequiredError,
    TrustedTargetedRecordError,
    TrustedTargetedSubmissionRecord,
    UnauthorizedTargetedFinalActorError,
    UnauthorizedTargetedQaActorError,
)
from paramguard.targeted_review import (
    TargetedVerdict,
    canonical_locked_targeted_submission_record,
)
from test_targeted_review import (
    StaticTrustedResolver,
    build_completed_task,
    command_bindings,
    make_session,
    reviewer_actor,
    routing_context_from_task,
)


def actor(actor_id: str, role: Role) -> Actor:
    return Actor(
        actor_id=actor_id,
        kind=PrincipalKind.HUMAN,
        roles=frozenset({role}),
    )


class StaticSubmissionResolver:
    def __init__(self, record: TrustedTargetedSubmissionRecord) -> None:
        self.record = record
        self.calls: list[str] = []

    def resolve_locked_submission(
        self, *, task_id: str
    ) -> TrustedTargetedSubmissionRecord:
        self.calls.append(task_id)
        return self.record


class FakeTypedAudit:
    def __init__(self) -> None:
        self.head = "f" * 64
        self.now = datetime(2026, 8, 25, 22, 0, tzinfo=timezone.utc)
        self.calls: list[tuple[str, object]] = []
        self._lock = Lock()

    def _commit(self, operation: str, request) -> TargetedAuditCommitReceipt:
        with self._lock:
            self.calls.append((operation, request))
            if request.expected_previous_head_hash != self.head:
                raise RuntimeError("stale audit head")
            previous = self.head
            new = hashlib.sha256(
                f"{previous}:{request.request_hash}:{operation}".encode()
            ).hexdigest()
            receipt = TargetedAuditCommitReceipt(
                request_hash=request.request_hash,
                previous_head_hash=previous,
                new_head_hash=new,
                event_id=f"event-{len(self.calls)}",
                committed_at=self.now,
            )
            self.now += timedelta(seconds=1)
            self.head = new
            return receipt

    def commit_lock(self, request) -> TargetedAuditCommitReceipt:
        return self._commit("lock", request)

    def accept_qa_disposition(self, request) -> TargetedAuditCommitReceipt:
        return self._commit("qa", request)

    def commit_final(self, request) -> TargetedAuditCommitReceipt:
        return self._commit("final", request)


def make_trusted_record(task, submission) -> TrustedTargetedSubmissionRecord:
    pipeline = task.approved_pipeline_spec
    context = EvidenceContext.from_manifest(
        task.evidence_manifest,
        rules_version="routing-v1",
        run_id="run-targeted-001",
        pipeline_spec_hash=pipeline.spec_hash,
        pipeline_version=pipeline.pipeline_version,
        comparator_version=pipeline.comparator_version,
        ocr_engine=pipeline.engine_name,
        ocr_version=pipeline.engine_version,
    )
    return TrustedTargetedSubmissionRecord(
        task_id=task.task_id,
        primary_reviewer_id=task.reviewer_id,
        ai_run_id="run-targeted-001",
        targeted_reviewer=reviewer_actor(),
        assigned_qa_reviewer_id="qa-001",
        assigned_final_approver_id="approver-001",
        evidence_context=context,
        submission=submission,
        expected_source_snapshot_sha256=submission.source_snapshot_sha256,
        expected_submission_hash=submission.submission_hash,
    )


def locked_submission(
    path: str,
    *,
    expected_ids: tuple[str, ...] = ("temperature", "pressure", "flow"),
):
    if path == "clean":
        task = build_completed_task(expected_ids=expected_ids)
        session = make_session(task)
    elif path in {"same", "different", "unable"}:
        task = build_completed_task(
            expected_ids=expected_ids,
            ai_pairs={expected_ids[0]: ("100", "101")},
        )
        session = make_session(task)
        verdict = {
            "same": TargetedVerdict.SAME,
            "different": TargetedVerdict.DIFFERENT,
            "unable": TargetedVerdict.UNABLE_TO_JUDGE,
        }[path]
        session.record_decision(
            **command_bindings(session, expected_revision=0),
            parameter_id=expected_ids[0],
            verdict=verdict,
            reason=f"synthetic {path} targeted observation",
            command_id="decision-001",
        )
    elif path == "qa":
        task = build_completed_task(expected_ids=expected_ids)
        context = routing_context_from_task(
            task,
            context={expected_ids[0]: {"field_issues": (FieldIssue.UNKNOWN_FIELD,)}},
        )
        session = make_session(
            task, resolver=StaticTrustedResolver(context)
        )
    elif path == "mixed":
        task = build_completed_task(
            expected_ids=expected_ids,
            ai_pairs={expected_ids[0]: ("100", "101")},
        )
        context = routing_context_from_task(
            task,
            context={expected_ids[1]: {"field_issues": (FieldIssue.UNKNOWN_FIELD,)}},
        )
        session = make_session(task, resolver=StaticTrustedResolver(context))
        session.record_decision(
            **command_bindings(session, expected_revision=0),
            parameter_id=expected_ids[0],
            verdict=TargetedVerdict.SAME,
            reason="synthetic targeted SAME",
            command_id="decision-001",
        )
    else:  # pragma: no cover - fixture guard
        raise AssertionError(path)
    submission = session.lock(
        **command_bindings(session, expected_revision=session.revision),
        command_id="targeted-lock-001",
    )
    return task, submission


def make_case(path: str):
    task, submission = locked_submission(path)
    record = make_trusted_record(task, submission)
    audit = FakeTypedAudit()
    case = TargetedAdjudicationCase(
        task_id=task.task_id,
        trusted_submission_resolver=StaticSubmissionResolver(record),
        audit_committer=audit,
    )
    case.register_locked_submission(
        audit_head_hash=audit.head,
        command_id="register-001",
        expected_version=0,
    )
    return case, audit, record


class TargetedPathTests(unittest.TestCase):
    def test_no_exception_still_has_empty_lock_and_final_human(self) -> None:
        case, audit, _ = make_case("clean")
        self.assertEqual(case.exception_ledger(), ())
        self.assertEqual(
            case.state,
            TargetedAdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
        )
        result = case.approve(
            actor=actor("approver-001", Role.FINAL_APPROVER),
            rationale="Final human checked the empty exception queue",
            audit_head_hash=audit.head,
            command_id="final-001",
            expected_version=1,
        )
        self.assertEqual(result.decision, FinalDecisionKind.APPROVED)
        self.assertFalse(case.automatic_release_allowed)

    def test_targeted_same_is_retained_but_can_reach_final_human(self) -> None:
        case, _, _ = make_case("same")
        (exception,) = case.exception_ledger()
        self.assertFalse(exception.qa_required)
        self.assertFalse(exception.closed_by_targeted_review)
        self.assertEqual(
            case.state,
            TargetedAdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
        )
        mixed, audit, _ = make_case("mixed")
        retained_same = next(
            item for item in mixed.exception_ledger() if not item.qa_required
        )
        with self.assertRaises(TargetedQaNotRequiredError):
            mixed.record_qa_disposition(
                actor=actor("qa-001", Role.QA_REVIEWER),
                exception_id=retained_same.exception_id,
                outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
                rationale="must not turn SAME into QA closure",
                reference_ids=(),
                audit_head_hash=audit.head,
                command_id="qa-invalid",
                expected_version=1,
            )

    def test_targeted_different_and_unable_require_qa(self) -> None:
        for path in ("different", "unable"):
            with self.subTest(path=path):
                case, audit, _ = make_case(path)
                self.assertEqual(
                    case.state, TargetedAdjudicationState.QA_DISPOSITION_OPEN
                )
                (exception,) = case.exception_ledger()
                case.record_qa_disposition(
                    actor=actor("qa-001", Role.QA_REVIEWER),
                    exception_id=exception.exception_id,
                    outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
                    rationale="QA resolved synthetic evidence",
                    reference_ids=("qa-record-001",),
                    audit_head_hash=audit.head,
                    command_id="qa-001",
                    expected_version=1,
                )
                self.assertEqual(
                    case.state,
                    TargetedAdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
                )

    def test_qa_only_and_mixed_partitions_use_exact_qa_ledger(self) -> None:
        for path, count in (("qa", 1), ("mixed", 2)):
            with self.subTest(path=path):
                case, _, _ = make_case(path)
                self.assertEqual(len(case.exception_ledger()), count)
                self.assertEqual(
                    sum(item.qa_required for item in case.exception_ledger()), 1
                )
                self.assertEqual(
                    case.state, TargetedAdjudicationState.QA_DISPOSITION_OPEN
                )

    def test_blocking_qa_prevents_approval_and_allows_rejection(self) -> None:
        case, audit, _ = make_case("different")
        exception = case.exception_ledger()[0]
        case.record_qa_disposition(
            actor=actor("qa-001", Role.QA_REVIEWER),
            exception_id=exception.exception_id,
            outcome=QaDispositionOutcome.CONFIRMED_DIFFERENCE,
            rationale="Confirmed synthetic mismatch",
            reference_ids=(),
            audit_head_hash=audit.head,
            command_id="qa-001",
            expected_version=1,
        )
        self.assertEqual(case.state, TargetedAdjudicationState.APPROVAL_BLOCKED)
        with self.assertRaises(TargetedApprovalBlockedError):
            case.approve(
                actor=actor("approver-001", Role.FINAL_APPROVER),
                rationale="must fail",
                audit_head_hash=audit.head,
                command_id="approve-invalid",
                expected_version=2,
            )
        result = case.reject(
            actor=actor("approver-001", Role.FINAL_APPROVER),
            rationale="Final human rejected confirmed mismatch",
            audit_head_hash=audit.head,
            command_id="reject-001",
            expected_version=2,
        )
        self.assertEqual(result.decision, FinalDecisionKind.REJECTED)


class TargetedTrustAndConcurrencyTests(unittest.TestCase):
    def test_targeted_profile_does_not_invent_primary_reviewer_separation(self) -> None:
        task, submission = locked_submission("clean")
        same_reviewer = actor(task.reviewer_id, Role.PRIMARY_REVIEWER)
        rewritten = replace(
            submission,
            reviewer_id=task.reviewer_id,
        )
        # Empty clean submissions contain no per-field targeted decisions, so
        # changing the assignment actor changes only the canonical lock hash.
        canonical = canonical_locked_targeted_submission_record(rewritten)
        rewritten_hash = hashlib.sha256(json_bytes(canonical)).hexdigest()
        rewritten = replace(rewritten, submission_hash=rewritten_hash)
        original = make_trusted_record(task, submission)
        trusted = TrustedTargetedSubmissionRecord(
            task_id=task.task_id,
            primary_reviewer_id=task.reviewer_id,
            ai_run_id="run-targeted-001",
            targeted_reviewer=same_reviewer,
            assigned_qa_reviewer_id="qa-001",
            assigned_final_approver_id="approver-001",
            evidence_context=original.evidence_context,
            submission=rewritten,
            expected_source_snapshot_sha256=rewritten.source_snapshot_sha256,
            expected_submission_hash=rewritten.submission_hash,
        )
        self.assertEqual(
            trusted.primary_reviewer_id, trusted.targeted_reviewer.actor_id
        )

    def test_public_commands_do_not_accept_self_reported_source_hashes(self) -> None:
        for method in (
            TargetedAdjudicationCase.register_locked_submission,
            TargetedAdjudicationCase.record_qa_disposition,
            TargetedAdjudicationCase.approve,
            TargetedAdjudicationCase.reject,
        ):
            parameters = inspect.signature(method).parameters
            self.assertNotIn("evidence_manifest_hash", parameters)
            self.assertNotIn("submission_hash", parameters)
            self.assertNotIn("source_snapshot_sha256", parameters)
            self.assertNotIn("expected_parameter_ids", parameters)

    def test_self_consistent_forgery_cannot_replace_trusted_anchor(self) -> None:
        task, submission = locked_submission("same")
        decision = replace(submission.decisions[0], reason="forged reason")
        forged = replace(submission, decisions=(decision,))
        forged_record = canonical_locked_targeted_submission_record(forged)
        forged_hash = hashlib.sha256(
            json_bytes(forged_record)
        ).hexdigest()
        forged = replace(forged, submission_hash=forged_hash)
        with self.assertRaises(TrustedTargetedRecordError):
            TrustedTargetedSubmissionRecord(
                task_id=task.task_id,
                primary_reviewer_id=task.reviewer_id,
                ai_run_id="run-targeted-001",
                targeted_reviewer=reviewer_actor(),
                assigned_qa_reviewer_id="qa-001",
                assigned_final_approver_id="approver-001",
                evidence_context=make_trusted_record(task, submission).evidence_context,
                submission=forged,
                expected_source_snapshot_sha256=submission.source_snapshot_sha256,
                expected_submission_hash=submission.submission_hash,
            )

    def test_same_id_cannot_swap_qa_or_final_role(self) -> None:
        case, audit, record = make_case("different")
        exception = case.exception_ledger()[0]
        with self.assertRaises(UnauthorizedTargetedQaActorError):
            case.record_qa_disposition(
                actor=actor(record.targeted_reviewer.actor_id, Role.QA_REVIEWER),
                exception_id=exception.exception_id,
                outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
                rationale="role swap",
                reference_ids=(),
                audit_head_hash=audit.head,
                command_id="qa-swap",
                expected_version=1,
            )
        with self.assertRaises(UnauthorizedTargetedQaActorError):
            case.record_qa_disposition(
                actor=actor("unassigned-qa", Role.QA_REVIEWER),
                exception_id=exception.exception_id,
                outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
                rationale="unassigned role holder",
                reference_ids=(),
                audit_head_hash=audit.head,
                command_id="qa-unassigned",
                expected_version=1,
            )
        with self.assertRaises(UnauthorizedTargetedQaActorError):
            case.record_qa_disposition(
                actor=actor(record.assigned_qa_reviewer_id, Role.FINAL_APPROVER),
                exception_id=exception.exception_id,
                outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
                rationale="assigned ID changed role",
                reference_ids=(),
                audit_head_hash=audit.head,
                command_id="qa-assigned-role-swap",
                expected_version=1,
            )
        with self.assertRaises(UnauthorizedTargetedFinalActorError):
            case.reject(
                actor=actor(record.primary_reviewer_id, Role.FINAL_APPROVER),
                rationale="role swap",
                audit_head_hash=audit.head,
                command_id="final-swap",
                expected_version=1,
            )
        with self.assertRaises(UnauthorizedTargetedFinalActorError):
            case.reject(
                actor=actor("unassigned-final", Role.FINAL_APPROVER),
                rationale="unassigned role holder",
                audit_head_hash=audit.head,
                command_id="final-unassigned",
                expected_version=1,
            )
        with self.assertRaises(UnauthorizedTargetedFinalActorError):
            case.reject(
                actor=actor(
                    record.assigned_final_approver_id,
                    Role.QA_REVIEWER,
                ),
                rationale="assigned ID changed role",
                audit_head_hash=audit.head,
                command_id="final-assigned-role-swap",
                expected_version=1,
            )

    def test_trusted_downstream_assignments_are_required_and_separated(self) -> None:
        _, _, record = make_case("different")
        with self.assertRaises(TrustedTargetedRecordError):
            replace(record, assigned_qa_reviewer_id=None)
        with self.assertRaises(TrustedTargetedRecordError):
            replace(
                record,
                assigned_qa_reviewer_id=record.targeted_reviewer.actor_id,
            )
        with self.assertRaises(TrustedTargetedRecordError):
            replace(
                record,
                assigned_final_approver_id=record.assigned_qa_reviewer_id,
            )

    def test_stale_version_and_command_reuse_fail_closed(self) -> None:
        case, audit, _ = make_case("different")
        exception = case.exception_ledger()[0]
        with self.assertRaises(StaleTargetedAdjudicationVersionError):
            case.record_qa_disposition(
                actor=actor("qa-001", Role.QA_REVIEWER),
                exception_id=exception.exception_id,
                outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
                rationale="stale",
                reference_ids=(),
                audit_head_hash=audit.head,
                command_id="qa-stale",
                expected_version=0,
            )
        case.record_qa_disposition(
            actor=actor("qa-001", Role.QA_REVIEWER),
            exception_id=exception.exception_id,
            outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
            rationale="valid",
            reference_ids=(),
            audit_head_hash=audit.head,
            command_id="qa-valid",
            expected_version=1,
        )
        with self.assertRaises(DuplicateTargetedAdjudicationCommandError):
            case.approve(
                actor=actor("approver-001", Role.FINAL_APPROVER),
                rationale="reused command",
                audit_head_hash=audit.head,
                command_id="qa-valid",
                expected_version=2,
            )

    def test_concurrent_approve_reject_has_one_domain_winner(self) -> None:
        case, audit, _ = make_case("clean")
        barrier = Barrier(3)
        outcomes: list[str] = []

        def run(decision: str) -> None:
            barrier.wait()
            try:
                method = case.approve if decision == "approve" else case.reject
                method(
                    actor=actor("approver-001", Role.FINAL_APPROVER),
                    rationale=decision,
                    audit_head_hash=audit.head,
                    command_id=f"final-{decision}",
                    expected_version=1,
                )
                outcomes.append("ok")
            except Exception as error:  # expected losing race
                outcomes.append(type(error).__name__)

        threads = [Thread(target=run, args=(value,)) for value in ("approve", "reject")]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertTrue(
            any(
                value
                in {
                    TargetedFinalAlreadyRecordedError.__name__,
                    StaleTargetedAdjudicationVersionError.__name__,
                }
                for value in outcomes
            )
        )

    def test_1001_fields_preserve_complete_partition(self) -> None:
        expected_ids = tuple(f"field-{index:04d}" for index in range(1001))
        task, submission = locked_submission("clean", expected_ids=expected_ids)
        self.assertEqual(submission.expected_parameter_ids, expected_ids)
        case = TargetedAdjudicationCase(
            task_id=task.task_id,
            trusted_submission_resolver=StaticSubmissionResolver(
                make_trusted_record(task, submission)
            ),
            audit_committer=FakeTypedAudit(),
        )
        self.assertEqual(case.exception_ledger(), ())


def json_bytes(value) -> bytes:
    import json

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
