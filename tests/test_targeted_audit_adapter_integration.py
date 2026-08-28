"""Real JSONL integration for targeted lock, QA acceptance, and final CAS."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
from threading import Barrier, Lock, Thread
import unittest

import paramguard.audit as audit_module
from paramguard.adjudication import QaDispositionOutcome
from paramguard.audit import (
    AuditAction,
    AuditIntegrityError,
    AuditPolicyError,
    EvidenceContext,
    FinalAuditWriteRequest,
    JsonlAuditLog,
    TargetedFinalAuditWriteRequest,
    TargetedQaAuditWriteRequest,
    calculate_targeted_exception_records,
    calculate_final_commit_request_hash,
    calculate_targeted_final_request_hash,
    calculate_targeted_qa_request_hash,
    calculate_targeted_resolution_digest,
)
from paramguard.targeted_adjudication import (
    TargetedAdjudicationCase,
    TargetedAdjudicationState,
    TargetedAuditVerificationError,
)
from paramguard.targeted_audit_adapter import JsonlTargetedAuditAdapter
from test_targeted_adjudication import (
    StaticSubmissionResolver,
    actor,
    locked_submission,
    make_trusted_record,
)
from paramguard.identity import Role


class AdvancingClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 8, 25, 21, 0, tzinfo=timezone.utc)
        self._lock = Lock()

    def __call__(self) -> datetime:
        with self._lock:
            result = self.current
            self.current += timedelta(seconds=1)
            return result


class CountingIds:
    def __init__(self) -> None:
        self.value = 0
        self._lock = Lock()

    def __call__(self) -> str:
        with self._lock:
            self.value += 1
            return f"targeted-event-{self.value:05d}"


def append_source_history(
    log: JsonlAuditLog, task, context: EvidenceContext
) -> None:
    base = EvidenceContext.from_manifest(task.evidence_manifest)
    log.append(
        task_id=task.task_id,
        actor_id="service:workflow:orchestrator",
        action=AuditAction.TASK_CREATED,
        details={
            "expected_parameter_ids": list(task.expected_parameter_ids),
            "reviewer_id": task.reviewer_id,
        },
        evidence_context=base,
    )
    decisions = task.human_decisions()
    for parameter_id in task.expected_parameter_ids:
        decision = decisions[parameter_id]
        log.append(
            task_id=task.task_id,
            parameter_id=parameter_id,
            actor_id=decision.reviewer_id,
            action=AuditAction.HUMAN_DECISION_RECORDED,
            details={"verdict": decision.verdict.value},
            reason=decision.reason,
            evidence_context=base,
        )
    log.append(
        task_id=task.task_id,
        actor_id=task.reviewer_id,
        action=AuditAction.HUMAN_REVIEW_LOCKED,
        details={"decision_count": len(task.expected_parameter_ids)},
        evidence_context=base,
    )
    log.append(
        task_id=task.task_id,
        actor_id="service:ai:targeted-worker",
        action=AuditAction.AI_REVIEW_STARTED,
        details={},
        evidence_context=context,
    )
    assessments = task.revealed_ai_results()
    for parameter_id in task.expected_parameter_ids:
        assessment = assessments[parameter_id]
        comparison = assessment.comparison_result
        reason = assessment.reason
        if reason is None and assessment.verdict.value != "SAME":
            reason = "synthetic non-SAME assessment"
        log.append(
            task_id=task.task_id,
            parameter_id=parameter_id,
            actor_id="service:ai:targeted-worker",
            action=AuditAction.AI_ASSESSMENT_RECORDED,
            details={
                "verdict": assessment.verdict.value,
                "left_raw": assessment.left_raw,
                "right_raw": assessment.right_raw,
                "extraction_reliable": assessment.extraction_reliable,
                "comparison_kind": (
                    None if comparison is None else comparison.kind.value
                ),
                "exact_match": (
                    False if comparison is None else comparison.exact_match
                ),
            },
            reason=reason,
            evidence_context=context,
        )
    log.append(
        task_id=task.task_id,
        actor_id="service:ai:targeted-worker",
        action=AuditAction.AI_REVIEW_COMPLETED,
        details={"assessment_count": len(task.expected_parameter_ids)},
        evidence_context=context,
    )


class RealTargetedAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.counter = 0

    def new_log(self) -> JsonlAuditLog:
        self.counter += 1
        return JsonlAuditLog(
            Path(self.temp.name) / f"targeted-{self.counter}.jsonl",
            clock=AdvancingClock(),
            event_id_factory=CountingIds(),
        )

    def build(self, path: str):
        task, submission = locked_submission(path)
        record = make_trusted_record(task, submission)
        log = self.new_log()
        append_source_history(log, task, record.evidence_context)
        case = TargetedAdjudicationCase(
            task_id=task.task_id,
            trusted_submission_resolver=StaticSubmissionResolver(record),
            audit_committer=JsonlTargetedAuditAdapter(log),
        )
        case.register_locked_submission(
            audit_head_hash=log.head_hash(),
            command_id="register-targeted-001",
            expected_version=0,
        )
        return task, record, log, case

    def test_clean_and_same_paths_have_typed_empty_or_retained_lock_then_final(self) -> None:
        for path, exception_count in (("clean", 0), ("same", 1)):
            with self.subTest(path=path):
                _, _, log, case = self.build(path)
                case.approve(
                    actor=actor("approver-001", Role.FINAL_APPROVER),
                    rationale="Independent final human confirmation",
                    audit_head_hash=log.head_hash(),
                    command_id="targeted-final-001",
                    expected_version=1,
                )
                log.verify()
                actions = [event.action for event in log.events()]
                self.assertEqual(
                    actions.count(AuditAction.TARGETED_REVIEW_LOCKED), 1
                )
                self.assertEqual(
                    actions.count(AuditAction.TARGETED_FINAL_APPROVAL_RECORDED),
                    1,
                )
                self.assertNotIn(AuditAction.QA_CASE_OPENED, actions)
                self.assertEqual(len(case.exception_ledger()), exception_count)

    def test_clean_path_can_freeze_no_qa_assignment_and_still_needs_final(self) -> None:
        task, submission = locked_submission("clean")
        record = replace(
            make_trusted_record(task, submission),
            assigned_qa_reviewer_id=None,
        )
        log = self.new_log()
        append_source_history(log, task, record.evidence_context)
        case = TargetedAdjudicationCase(
            task_id=task.task_id,
            trusted_submission_resolver=StaticSubmissionResolver(record),
            audit_committer=JsonlTargetedAuditAdapter(log),
        )
        case.register_locked_submission(
            audit_head_hash=log.head_hash(),
            command_id="clean-without-qa-assignment",
            expected_version=0,
        )
        lock_event = next(
            event
            for event in log.events()
            if event.action is AuditAction.TARGETED_REVIEW_LOCKED
        )
        self.assertIsNone(lock_event.details["assigned_qa_reviewer_id"])
        case.approve(
            actor=actor("approver-001", Role.FINAL_APPROVER),
            rationale="Independent final remains mandatory",
            audit_head_hash=log.head_hash(),
            command_id="clean-final-without-qa",
            expected_version=1,
        )
        self.assertEqual(case.state, TargetedAdjudicationState.FINAL_APPROVED)
        log.verify()

    def test_different_unable_qa_only_and_mixed_use_exact_typed_qa(self) -> None:
        for path in ("different", "unable", "qa", "mixed"):
            with self.subTest(path=path):
                _, _, log, case = self.build(path)
                for exception in case.exception_ledger():
                    if not exception.qa_required:
                        continue
                    case.record_qa_disposition(
                        actor=actor("qa-001", Role.QA_REVIEWER),
                        exception_id=exception.exception_id,
                        outcome=(
                            QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION
                        ),
                        rationale="QA resolved synthetic exception",
                        reference_ids=("qa-note-001",),
                        audit_head_hash=log.head_hash(),
                        command_id=f"qa-{exception.exception_id}",
                        expected_version=case.version,
                    )
                self.assertEqual(
                    case.state,
                    TargetedAdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
                )
                case.approve(
                    actor=actor("approver-001", Role.FINAL_APPROVER),
                    rationale="Final human accepted QA evidence",
                    audit_head_hash=log.head_hash(),
                    command_id="targeted-final-001",
                    expected_version=case.version,
                )
                log.verify()
                qa_events = [
                    event
                    for event in log.events()
                    if event.action
                    is AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED
                ]
                self.assertEqual(
                    len(qa_events),
                    sum(item.qa_required for item in case.exception_ledger()),
                )

    def test_generic_append_cannot_forge_lock_qa_or_final(self) -> None:
        task, record, log, _ = self.build("clean")
        for action in (
            AuditAction.TARGETED_REVIEW_LOCKED,
            AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED,
            AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
        ):
            with self.subTest(action=action):
                with self.assertRaisesRegex(AuditPolicyError, "typed CAS"):
                    log.append(
                        task_id=task.task_id,
                        actor_id="final-human-999",
                        action=action,
                        details={},
                        evidence_context=record.evidence_context,
                    )

    def test_typed_qa_and_final_cannot_bypass_audited_assignments(self) -> None:
        _, record, log, case = self.build("different")
        exception = next(
            item for item in case.exception_ledger() if item.qa_required
        )
        qa_record = {
            "task_id": record.task_id,
            "actor_id": "unassigned-qa",
            "targeted_submission_hash": record.expected_submission_hash,
            "exception_id": exception.exception_id,
            "outcome": "RESOLVED_NO_BLOCKING_EXCEPTION",
            "rationale": "self-consistent but unassigned QA",
            "reference_ids": [],
            "expected_adjudication_version": 1,
            "expected_previous_head_hash": log.head_hash(),
            "command_id": "unassigned-qa-command",
        }
        qa_request = TargetedQaAuditWriteRequest(
            task_id=qa_record["task_id"],
            actor_id=qa_record["actor_id"],
            targeted_submission_hash=qa_record[
                "targeted_submission_hash"
            ],
            exception_id=qa_record["exception_id"],
            outcome=qa_record["outcome"],
            rationale=qa_record["rationale"],
            reference_ids=(),
            expected_adjudication_version=1,
            expected_previous_head_hash=qa_record[
                "expected_previous_head_hash"
            ],
            command_id=qa_record["command_id"],
            request_hash=calculate_targeted_qa_request_hash(qa_record),
        )
        with self.assertRaisesRegex(AuditPolicyError, "audited assignment"):
            log.accept_targeted_qa_disposition_cas(qa_request)

        _, clean_record, clean_log, _ = self.build("clean")
        resolution = calculate_targeted_resolution_digest(
            task_id=clean_record.task_id,
            submission_hash=clean_record.expected_submission_hash,
            exceptions=(),
            dispositions=(),
        )
        final_record = {
            "task_id": clean_record.task_id,
            "decision": "APPROVED",
            "actor_id": "unassigned-final",
            "rationale": "self-consistent but unassigned final",
            "evidence_manifest_hash": (
                clean_record.submission.evidence_manifest_hash
            ),
            "targeted_submission_hash": (
                clean_record.expected_submission_hash
            ),
            "primary_reviewer_id": clean_record.primary_reviewer_id,
            "ai_run_id": clean_record.ai_run_id,
            "expected_parameter_ids": list(
                clean_record.submission.expected_parameter_ids
            ),
            "exception_ids": [],
            "qa_required_exception_ids": [],
            "qa_disposition_exception_ids": [],
            "resolution_digest": resolution,
            "expected_adjudication_version": 1,
            "expected_previous_head_hash": clean_log.head_hash(),
            "command_id": "unassigned-final-command",
        }
        final_request = TargetedFinalAuditWriteRequest(
            task_id=final_record["task_id"],
            action=AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
            actor_id=final_record["actor_id"],
            rationale=final_record["rationale"],
            evidence_manifest_hash=final_record[
                "evidence_manifest_hash"
            ],
            targeted_submission_hash=final_record[
                "targeted_submission_hash"
            ],
            primary_reviewer_id=final_record["primary_reviewer_id"],
            ai_run_id=final_record["ai_run_id"],
            expected_parameter_ids=tuple(
                final_record["expected_parameter_ids"]
            ),
            exception_ids=(),
            qa_required_exception_ids=(),
            qa_disposition_exception_ids=(),
            resolution_digest=resolution,
            expected_adjudication_version=1,
            expected_previous_head_hash=final_record[
                "expected_previous_head_hash"
            ],
            command_id=final_record["command_id"],
            request_hash=calculate_targeted_final_request_hash(
                final_record
            ),
        )
        with self.assertRaisesRegex(AuditPolicyError, "audited assignment"):
            clean_log.commit_targeted_final_cas(final_request)

    def test_stale_head_and_cross_branch_both_fail_closed(self) -> None:
        task, submission = locked_submission("clean")
        record = make_trusted_record(task, submission)
        log = self.new_log()
        append_source_history(log, task, record.evidence_context)
        stale = log.head_hash()
        log.append(
            task_id=task.task_id,
            actor_id="auditor-001",
            action=AuditAction.GENERIC_NOTE_RECORDED,
            details={"note": "concurrent harmless audit note"},
            evidence_context=record.evidence_context,
        )
        case = TargetedAdjudicationCase(
            task_id=task.task_id,
            trusted_submission_resolver=StaticSubmissionResolver(record),
            audit_committer=JsonlTargetedAuditAdapter(log),
        )
        with self.assertRaisesRegex(TargetedAuditVerificationError, "compare-and-swap"):
            case.register_locked_submission(
                audit_head_hash=stale,
                command_id="stale-lock",
                expected_version=0,
            )

        # Choosing the legacy/blind route first excludes targeted lock.
        log.append(
            task_id=task.task_id,
            parameter_id=task.expected_parameter_ids[0],
            actor_id="service:rules:router",
            action=AuditAction.ROUTE_ASSIGNED,
            details={"route": "NO_EXCEPTION_DETECTED", "reasons": []},
            evidence_context=record.evidence_context,
        )
        with self.assertRaisesRegex(TargetedAuditVerificationError, "exclusive|branch"):
            case.register_locked_submission(
                audit_head_hash=log.head_hash(),
                command_id="branch-lock",
                expected_version=0,
            )

        # Conversely, a targeted lock excludes later legacy routing.
        _, record2, log2, _ = self.build("clean")
        with self.assertRaisesRegex(AuditPolicyError, "exclusive"):
            log2.append(
                task_id=record2.task_id,
                parameter_id=record2.submission.expected_parameter_ids[0],
                actor_id="service:rules:router",
                action=AuditAction.ROUTE_ASSIGNED,
                details={"route": "NO_EXCEPTION_DETECTED", "reasons": []},
                evidence_context=record2.evidence_context,
            )

    def test_concurrent_targeted_and_blind_branch_start_have_one_winner(self) -> None:
        task, submission = locked_submission("clean")
        record = make_trusted_record(task, submission)
        log = self.new_log()
        append_source_history(log, task, record.evidence_context)
        case = TargetedAdjudicationCase(
            task_id=task.task_id,
            trusted_submission_resolver=StaticSubmissionResolver(record),
            audit_committer=JsonlTargetedAuditAdapter(log),
        )
        head = log.head_hash()
        barrier = Barrier(3)
        outcomes: list[tuple[str, str]] = []

        def start_targeted() -> None:
            barrier.wait()
            try:
                case.register_locked_submission(
                    audit_head_hash=head,
                    command_id="concurrent-targeted-start",
                    expected_version=0,
                )
                outcomes.append(("targeted", "ok"))
            except Exception as error:
                outcomes.append(("targeted", type(error).__name__))

        def start_blind() -> None:
            barrier.wait()
            try:
                log.append(
                    task_id=task.task_id,
                    parameter_id=task.expected_parameter_ids[0],
                    actor_id="service:rules:router",
                    action=AuditAction.ROUTE_ASSIGNED,
                    details={"route": "NO_EXCEPTION_DETECTED", "reasons": []},
                    evidence_context=record.evidence_context,
                )
                outcomes.append(("blind", "ok"))
            except Exception as error:
                outcomes.append(("blind", type(error).__name__))

        threads = [Thread(target=start_targeted), Thread(target=start_blind)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()

        self.assertEqual(sum(result == "ok" for _, result in outcomes), 1)
        task_actions = {
            event.action for event in log.events(task_id=task.task_id)
        }
        self.assertEqual(
            sum(
                action in task_actions
                for action in (
                    AuditAction.TARGETED_REVIEW_LOCKED,
                    AuditAction.ROUTE_ASSIGNED,
                )
            ),
            1,
        )
        log.verify()

    def test_two_cases_concurrent_approve_reject_have_one_durable_final(self) -> None:
        task, record, log, first = self.build("clean")
        second = TargetedAdjudicationCase(
            task_id=task.task_id,
            trusted_submission_resolver=StaticSubmissionResolver(record),
            audit_committer=JsonlTargetedAuditAdapter(log),
        )
        second.register_locked_submission(
            audit_head_hash=log.events()[-1].previous_hash,
            command_id="register-targeted-001",
            expected_version=0,
        )
        head = log.head_hash()
        barrier = Barrier(3)
        outcomes: list[str] = []

        def decide(case, approve: bool) -> None:
            barrier.wait()
            try:
                method = case.approve if approve else case.reject
                method(
                    actor=actor("approver-001", Role.FINAL_APPROVER),
                    rationale="concurrent human final",
                    audit_head_hash=head,
                    command_id="approve-cmd" if approve else "reject-cmd",
                    expected_version=1,
                )
                outcomes.append("ok")
            except Exception as error:
                outcomes.append(type(error).__name__)

        threads = [
            Thread(target=decide, args=(first, True)),
            Thread(target=decide, args=(second, False)),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count("ok"), 1)
        final_actions = {
            AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
            AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
        }
        self.assertEqual(
            sum(event.action in final_actions for event in log.events()), 1
        )
        log.verify()

    def test_restart_cannot_replay_only_lock_after_qa_or_final(self) -> None:
        for path, add_later_transition in (
            ("different", "qa"),
            ("clean", "final"),
        ):
            with self.subTest(path=path, later=add_later_transition):
                task, record, log, case = self.build(path)
                if add_later_transition == "qa":
                    exception = next(
                        item
                        for item in case.exception_ledger()
                        if item.qa_required
                    )
                    case.record_qa_disposition(
                        actor=actor("qa-001", Role.QA_REVIEWER),
                        exception_id=exception.exception_id,
                        outcome=(
                            QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION
                        ),
                        rationale="Durable QA transition",
                        reference_ids=(),
                        audit_head_hash=log.head_hash(),
                        command_id="durable-qa-before-restart",
                        expected_version=1,
                    )
                else:
                    case.approve(
                        actor=actor("approver-001", Role.FINAL_APPROVER),
                        rationale="Durable final before restart",
                        audit_head_hash=log.head_hash(),
                        command_id="durable-final-before-restart",
                        expected_version=1,
                    )

                restarted = TargetedAdjudicationCase(
                    task_id=task.task_id,
                    trusted_submission_resolver=(
                        StaticSubmissionResolver(record)
                    ),
                    audit_committer=JsonlTargetedAuditAdapter(log),
                )
                lock_event = next(
                    event
                    for event in log.events()
                    if event.action is AuditAction.TARGETED_REVIEW_LOCKED
                )
                with self.assertRaisesRegex(
                    TargetedAuditVerificationError, "rehydration is required"
                ):
                    restarted.register_locked_submission(
                        audit_head_hash=lock_event.previous_hash,
                        command_id="register-targeted-001",
                        expected_version=0,
                    )
                self.assertEqual(
                    restarted.state,
                    TargetedAdjudicationState.AUDIT_LOCK_PENDING,
                )
                self.assertEqual(restarted.version, 0)
                log.verify()

    def test_same_actor_id_with_changed_assignment_role_is_not_exact_retry(self) -> None:
        task, record, log, _ = self.build("clean")
        changed_claims = replace(
            record,
            targeted_reviewer=actor(
                record.targeted_reviewer.actor_id, Role.PRIMARY_REVIEWER
            ),
        )
        second = TargetedAdjudicationCase(
            task_id=task.task_id,
            trusted_submission_resolver=StaticSubmissionResolver(changed_claims),
            audit_committer=JsonlTargetedAuditAdapter(log),
        )
        lock_event = next(
            event
            for event in log.events()
            if event.action is AuditAction.TARGETED_REVIEW_LOCKED
        )
        with self.assertRaisesRegex(
            TargetedAuditVerificationError, "command_id|another request"
        ):
            second.register_locked_submission(
                audit_head_hash=lock_event.previous_hash,
                command_id="register-targeted-001",
                expected_version=0,
            )

        changed_downstream_assignment = replace(
            record,
            assigned_final_approver_id="other-final-assignment",
        )
        third = TargetedAdjudicationCase(
            task_id=task.task_id,
            trusted_submission_resolver=StaticSubmissionResolver(
                changed_downstream_assignment
            ),
            audit_committer=JsonlTargetedAuditAdapter(log),
        )
        with self.assertRaisesRegex(
            TargetedAuditVerificationError, "command_id|another request"
        ):
            third.register_locked_submission(
                audit_head_hash=lock_event.previous_hash,
                command_id="register-targeted-001",
                expected_version=0,
            )

    def test_existing_blind_final_blocks_targeted_final_for_same_task(self) -> None:
        # Reuse the mature blind audit fixture only to establish a valid old final.
        from test_audit import JsonlAuditLogTests

        fixture = JsonlAuditLogTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture._prepare_two_field_routing(
            first_route="NO_EXCEPTION_DETECTED",
            first_reasons=(),
        )
        fixture._append_final(
            AuditAction.FINAL_APPROVAL_RECORDED,
            second_submission_hash=None,
            resolution_digest="2" * 64,
        )
        record = {
            "task_id": "TASK-001",
            "decision": "APPROVED",
            "actor_id": "other-final-human",
            "rationale": "must not create a second branch final",
            "evidence_manifest_hash": "c" * 64,
            "targeted_submission_hash": "3" * 64,
            "primary_reviewer_id": "reviewer-001",
            "ai_run_id": "run-001",
            "expected_parameter_ids": ["temperature", "pressure"],
            "exception_ids": [],
            "qa_required_exception_ids": [],
            "qa_disposition_exception_ids": [],
            "resolution_digest": "4" * 64,
            "expected_adjudication_version": 1,
            "expected_previous_head_hash": fixture.log.head_hash(),
            "command_id": "targeted-final-after-blind",
        }
        request_hash = calculate_targeted_final_request_hash(record)
        request = TargetedFinalAuditWriteRequest(
            task_id=record["task_id"],
            action=AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
            actor_id=record["actor_id"],
            rationale=record["rationale"],
            evidence_manifest_hash=record["evidence_manifest_hash"],
            targeted_submission_hash=record["targeted_submission_hash"],
            primary_reviewer_id=record["primary_reviewer_id"],
            ai_run_id=record["ai_run_id"],
            expected_parameter_ids=tuple(record["expected_parameter_ids"]),
            exception_ids=(),
            qa_required_exception_ids=(),
            qa_disposition_exception_ids=(),
            resolution_digest=record["resolution_digest"],
            expected_adjudication_version=1,
            expected_previous_head_hash=record["expected_previous_head_hash"],
            command_id=record["command_id"],
            request_hash=request_hash,
        )
        with self.assertRaisesRegex(AuditPolicyError, "already recorded"):
            fixture.log.commit_targeted_final_cas(request)

    def test_existing_targeted_final_blocks_old_blind_final_for_same_task(self) -> None:
        _, record, log, case = self.build("clean")
        case.approve(
            actor=actor("approver-001", Role.FINAL_APPROVER),
            rationale="Durable targeted final",
            audit_head_hash=log.head_hash(),
            command_id="targeted-final-first",
            expected_version=1,
        )
        request_record = {
            "task_id": record.task_id,
            "decision": "APPROVED",
            "actor_id": "other-final-human",
            "rationale": "must not create an old-branch final",
            "evidence_manifest_hash": (
                record.submission.evidence_manifest_hash
            ),
            "second_submission_hash": None,
            "primary_reviewer_id": record.primary_reviewer_id,
            "ai_run_id": record.ai_run_id,
            "expected_parameter_ids": list(
                record.submission.expected_parameter_ids
            ),
            "exception_ids": [],
            "qa_disposition_exception_ids": [],
            "resolution_digest": "7" * 64,
            "expected_adjudication_version": 0,
            "expected_previous_head_hash": log.head_hash(),
            "required_prior_actions": [],
            "command_id": "old-final-after-targeted",
        }
        request = FinalAuditWriteRequest(
            task_id=request_record["task_id"],
            action=AuditAction.FINAL_APPROVAL_RECORDED,
            actor_id=request_record["actor_id"],
            rationale=request_record["rationale"],
            evidence_manifest_hash=request_record[
                "evidence_manifest_hash"
            ],
            second_submission_hash=None,
            primary_reviewer_id=request_record["primary_reviewer_id"],
            ai_run_id=request_record["ai_run_id"],
            expected_parameter_ids=tuple(
                request_record["expected_parameter_ids"]
            ),
            exception_ids=(),
            qa_disposition_exception_ids=(),
            resolution_digest=request_record["resolution_digest"],
            expected_adjudication_version=0,
            expected_previous_head_hash=request_record[
                "expected_previous_head_hash"
            ],
            required_prior_actions=(),
            command_id=request_record["command_id"],
            commit_request_hash=calculate_final_commit_request_hash(
                request_record
            ),
        )
        with self.assertRaisesRegex(AuditPolicyError, "already recorded"):
            log.commit_final_cas(request)

    def test_self_consistent_final_request_cannot_omit_retained_exception(self) -> None:
        _, record, log, case = self.build("mixed")
        qa_exception = next(
            item for item in case.exception_ledger() if item.qa_required
        )
        case.record_qa_disposition(
            actor=actor("qa-001", Role.QA_REVIEWER),
            exception_id=qa_exception.exception_id,
            outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
            rationale="QA resolved the synthetic referral",
            reference_ids=(),
            audit_head_hash=log.head_hash(),
            command_id="qa-complete",
            expected_version=1,
        )
        lock_event = next(
            event
            for event in log.events()
            if event.action is AuditAction.TARGETED_REVIEW_LOCKED
        )
        exceptions = calculate_targeted_exception_records(
            lock_event.details["submission"],
            submission_hash=lock_event.details["submission_hash"],
        )
        qa_event = next(
            event
            for event in log.events()
            if event.action is AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED
        )
        dispositions = (
            {
                "exception_id": qa_event.details["exception_id"],
                "outcome": qa_event.details["outcome"],
                "rationale": qa_event.details["rationale"],
                "reference_ids": qa_event.details["reference_ids"],
                "qa_actor_id": qa_event.actor_id,
            },
        )
        resolution = calculate_targeted_resolution_digest(
            task_id=record.task_id,
            submission_hash=record.expected_submission_hash,
            exceptions=exceptions,
            dispositions=dispositions,
        )
        # Omit the retained targeted-SAME exception while keeping a fully
        # self-consistent request hash.  Durable coverage must still reject it.
        supplied_exception_ids = (qa_exception.exception_id,)
        request_record = {
            "task_id": record.task_id,
            "decision": "APPROVED",
            "actor_id": "approver-001",
            "rationale": "forged omission",
            "evidence_manifest_hash": record.submission.evidence_manifest_hash,
            "targeted_submission_hash": record.expected_submission_hash,
            "primary_reviewer_id": record.primary_reviewer_id,
            "ai_run_id": record.ai_run_id,
            "expected_parameter_ids": list(
                record.submission.expected_parameter_ids
            ),
            "exception_ids": list(supplied_exception_ids),
            "qa_required_exception_ids": [qa_exception.exception_id],
            "qa_disposition_exception_ids": [qa_exception.exception_id],
            "resolution_digest": resolution,
            "expected_adjudication_version": 2,
            "expected_previous_head_hash": log.head_hash(),
            "command_id": "forged-final-omission",
        }
        request = TargetedFinalAuditWriteRequest(
            task_id=record.task_id,
            action=AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
            actor_id=request_record["actor_id"],
            rationale=request_record["rationale"],
            evidence_manifest_hash=request_record["evidence_manifest_hash"],
            targeted_submission_hash=request_record["targeted_submission_hash"],
            primary_reviewer_id=request_record["primary_reviewer_id"],
            ai_run_id=request_record["ai_run_id"],
            expected_parameter_ids=tuple(
                request_record["expected_parameter_ids"]
            ),
            exception_ids=supplied_exception_ids,
            qa_required_exception_ids=(qa_exception.exception_id,),
            qa_disposition_exception_ids=(qa_exception.exception_id,),
            resolution_digest=resolution,
            expected_adjudication_version=2,
            expected_previous_head_hash=log.head_hash(),
            command_id="forged-final-omission",
            request_hash=calculate_targeted_final_request_hash(request_record),
        )
        with self.assertRaisesRegex(AuditPolicyError, "trusted facts"):
            log.commit_targeted_final_cas(request)

    def test_targeted_event_delete_and_reorder_are_detected(self) -> None:
        _, _, log, case = self.build("same")
        case.approve(
            actor=actor("approver-001", Role.FINAL_APPROVER),
            rationale="Final human decision",
            audit_head_hash=log.head_hash(),
            command_id="targeted-final-001",
            expected_version=1,
        )
        lines = log.path.read_text(encoding="utf-8").splitlines()
        # Removing the targeted lock leaves a final whose predecessor/semantics fail.
        log.path.write_text("\n".join(lines[:-2] + [lines[-1]]) + "\n", encoding="utf-8")
        with self.assertRaises(AuditIntegrityError):
            log.verify()

        # Restore then reorder the last two targeted events.
        log.path.write_text(
            "\n".join(lines[:-2] + [lines[-1], lines[-2]]) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(AuditIntegrityError):
            log.verify()

    def test_targeted_lock_clock_skew_fails_before_durable_append(self) -> None:
        task, submission = locked_submission("clean")
        record = make_trusted_record(task, submission)
        clock = AdvancingClock()
        clock.current = datetime(2020, 1, 1, tzinfo=timezone.utc)
        log = JsonlAuditLog(
            Path(self.temp.name) / "targeted-clock-skew.jsonl",
            clock=clock,
            event_id_factory=CountingIds(),
        )
        append_source_history(log, task, record.evidence_context)
        case = TargetedAdjudicationCase(
            task_id=task.task_id,
            trusted_submission_resolver=StaticSubmissionResolver(record),
            audit_committer=JsonlTargetedAuditAdapter(log),
        )

        with self.assertRaisesRegex(
            TargetedAuditVerificationError, "cannot predate"
        ):
            case.register_locked_submission(
                audit_head_hash=log.head_hash(),
                command_id="clock-skew-lock",
                expected_version=0,
            )

        self.assertEqual(case.state, TargetedAdjudicationState.AUDIT_LOCK_PENDING)
        self.assertEqual(case.version, 0)
        self.assertFalse(
            any(
                event.action is AuditAction.TARGETED_REVIEW_LOCKED
                for event in log.events()
            )
        )

        # The failed command was never consumed and can be retried after the
        # trusted audit clock is corrected.
        clock.current = submission.locked_at + timedelta(seconds=1)
        case.register_locked_submission(
            audit_head_hash=log.head_hash(),
            command_id="clock-skew-lock",
            expected_version=0,
        )
        self.assertEqual(case.version, 1)
        self.assertEqual(
            sum(
                event.action is AuditAction.TARGETED_REVIEW_LOCKED
                for event in log.events()
            ),
            1,
        )

    def test_replay_rejects_rehashed_targeted_lock_causal_inversion(self) -> None:
        task, _, log, _ = self.build("clean")
        records = [
            json.loads(line)
            for line in log.path.read_text(encoding="utf-8").splitlines()
        ]
        lock = records[-1]
        self.assertEqual(lock["action"], "TARGETED_REVIEW_LOCKED")
        submission = lock["details"]["submission"]
        occurred_at = datetime.fromisoformat(lock["occurred_at"])
        submission["locked_at"] = (occurred_at + timedelta(hours=1)).isoformat()
        submission_hash = hashlib.sha256(
            audit_module._canonical_json(submission).encode("utf-8")
        ).hexdigest()
        lock["details"]["submission_hash"] = submission_hash
        request_record = {
            "task_id": task.task_id,
            "actor_id": lock["actor_id"],
            "primary_reviewer_id": lock["details"]["primary_reviewer_id"],
            "ai_run_id": lock["details"]["ai_run_id"],
            "targeted_reviewer_kind": lock["details"][
                "targeted_reviewer_kind"
            ],
            "targeted_reviewer_roles": lock["details"][
                "targeted_reviewer_roles"
            ],
            "assigned_qa_reviewer_id": lock["details"][
                "assigned_qa_reviewer_id"
            ],
            "assigned_final_approver_id": lock["details"][
                "assigned_final_approver_id"
            ],
            "evidence_context": lock["evidence_context"],
            "submission": submission,
            "submission_hash": submission_hash,
            "expected_previous_head_hash": lock["previous_hash"],
            "command_id": lock["details"]["command_id"],
        }
        lock["details"]["request_hash"] = (
            audit_module.calculate_targeted_lock_request_hash(request_record)
        )
        lock["event_hash"] = "0" * 64
        parsed = audit_module._event_from_record(lock)
        lock["event_hash"] = audit_module._calculate_event_hash(parsed)
        log.path.write_text(
            "\n".join(
                json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                for record in records
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(AuditIntegrityError, "cannot predate"):
            log.verify()

    def test_nested_duplicate_json_key_is_rejected_on_replay(self) -> None:
        _, _, log, _ = self.build("clean")
        raw = log.path.read_text(encoding="utf-8")
        needle = '"targeted_submission_version":2'
        self.assertIn(needle, raw)
        # Last-wins JSON parsers would reconstruct the original semantic
        # object, so the existing event hash would otherwise still verify.
        tampered = raw.replace(
            needle,
            '"targeted_submission_version":1,' + needle,
            1,
        )
        log.path.write_text(tampered, encoding="utf-8")
        with self.assertRaisesRegex(
            AuditIntegrityError, "duplicate JSON object key"
        ):
            log.verify()

    def test_rehashed_but_semantically_incomplete_targeted_lock_is_detected(self) -> None:
        task, _, log, _ = self.build("clean")
        records = [
            json.loads(line)
            for line in log.path.read_text(encoding="utf-8").splitlines()
        ]
        lock = records[-1]
        self.assertEqual(lock["action"], "TARGETED_REVIEW_LOCKED")
        submission = lock["details"]["submission"]
        removed = submission["expected_parameter_ids"].pop()
        submission["no_exception_parameter_ids"].remove(removed)
        submission_hash = hashlib.sha256(
            audit_module._canonical_json(submission).encode("utf-8")
        ).hexdigest()
        lock["details"]["submission_hash"] = submission_hash
        request_record = {
            "task_id": task.task_id,
            "actor_id": lock["actor_id"],
            "primary_reviewer_id": lock["details"]["primary_reviewer_id"],
            "ai_run_id": lock["details"]["ai_run_id"],
            "targeted_reviewer_kind": lock["details"][
                "targeted_reviewer_kind"
            ],
            "targeted_reviewer_roles": lock["details"][
                "targeted_reviewer_roles"
            ],
            "assigned_qa_reviewer_id": lock["details"][
                "assigned_qa_reviewer_id"
            ],
            "assigned_final_approver_id": lock["details"][
                "assigned_final_approver_id"
            ],
            "evidence_context": lock["evidence_context"],
            "submission": submission,
            "submission_hash": submission_hash,
            "expected_previous_head_hash": lock["previous_hash"],
            "command_id": lock["details"]["command_id"],
        }
        lock["details"]["request_hash"] = (
            audit_module.calculate_targeted_lock_request_hash(request_record)
        )
        lock["event_hash"] = "0" * 64
        event = audit_module._event_from_record(lock)
        lock["event_hash"] = audit_module._calculate_event_hash(event)
        log.path.write_text(
            "\n".join(
                json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                for record in records
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(AuditIntegrityError, "frozen schema"):
            log.verify()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
