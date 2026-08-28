"""Real JSONL integration across workflow, blind review, QA, and final CAS."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from threading import Lock
import unittest

from paramguard.adjudication import (
    AdjudicationCase,
    AdjudicationState,
    AuditVerificationError,
    QaDispositionOutcome,
    RoutingEvidenceContext,
)
from paramguard.audit import (
    AuditAction,
    AuditPolicyError,
    EvidenceContext,
    JsonlAuditLog,
)
from paramguard.audit_adapter import JsonlFinalAuditCommitter
from paramguard.blind_review import BlindReviewSession, BlindVerdict
from paramguard.evidence import (
    EvidenceArtifact,
    EvidenceManifest,
    EvidenceRole,
    content_sha256,
)
from paramguard.identity import Actor, PrincipalKind, Role
from paramguard.pipeline import PipelineSpec
from paramguard.routing import (
    FieldIssue,
    ImageQuality,
    ReviewRoute,
    ReviewSignals,
    RouteReason,
    RoutingDecision,
)
from paramguard.workflow import HumanVerdict, ReviewTask


class AdvancingClock:
    def __init__(self, hour: int) -> None:
        self.current = datetime(2026, 8, 25, hour, 0, tzinfo=timezone.utc)
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
            return f"integration-event-{self.value:04d}"


def human(actor_id: str, role: Role) -> Actor:
    return Actor(
        actor_id=actor_id,
        kind=PrincipalKind.HUMAN,
        roles=frozenset({role}),
    )


class RealAuditAdapterIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.manifest = self._manifest()
        self.pipeline = PipelineSpec(
            spec_id="integration-pipeline",
            engine_name="synthetic-ocr",
            engine_version="1.0",
            pipeline_version="1.0",
            comparator_version="1.0",
            configuration_sha256=content_sha256(b"integration-pipeline-v1"),
        )

    @staticmethod
    def _manifest() -> EvidenceManifest:
        left = EvidenceArtifact.from_bytes(
            artifact_id="integration-left",
            role=EvidenceRole.LEFT_PHOTO,
            content=b"left-image-bytes",
            media_type="image/png",
        )
        right = EvidenceArtifact.from_bytes(
            artifact_id="integration-right",
            role=EvidenceRole.RIGHT_SCREENSHOT,
            content=b"right-image-bytes",
            media_type="image/png",
        )
        return EvidenceManifest(
            manifest_id="integration-manifest",
            schema_id="integration-schema",
            schema_version="1.0",
            schema_sha256=content_sha256(b"integration-schema-v1"),
            template_id="integration-template",
            template_version="1.0",
            template_sha256=content_sha256(b"integration-template-v1"),
            expected_parameter_ids=("temperature", "pressure"),
            artifacts=(left, right),
        )

    def _new_log(self) -> JsonlAuditLog:
        return JsonlAuditLog(
            Path(self.temp_directory.name) / "integration-audit.jsonl",
            clock=AdvancingClock(hour=20),
            event_id_factory=CountingIds(),
        )

    def _complete_review_and_audit(
        self, log: JsonlAuditLog
    ) -> tuple[ReviewTask, EvidenceContext, EvidenceContext]:
        base_context = EvidenceContext.from_manifest(self.manifest)
        ai_context = EvidenceContext.from_manifest(
            self.manifest,
            rules_version="routing-v1",
            run_id="integration-run-001",
            pipeline_spec_hash=self.pipeline.spec_hash,
            pipeline_version=self.pipeline.pipeline_version,
            comparator_version=self.pipeline.comparator_version,
            ocr_engine=self.pipeline.engine_name,
            ocr_version=self.pipeline.engine_version,
        )
        task = ReviewTask(
            task_id="integration-task",
            evidence_manifest=self.manifest,
            approved_pipeline_spec=self.pipeline,
            reviewer_id="reviewer-001",
            clock=AdvancingClock(hour=12),
        )
        log.append(
            task_id=task.task_id,
            actor_id="service:workflow:orchestrator",
            action=AuditAction.TASK_CREATED,
            details={
                "expected_parameter_ids": list(
                    self.manifest.expected_parameter_ids
                ),
                "reviewer_id": task.reviewer_id,
            },
            evidence_context=base_context,
        )
        for parameter_id in self.manifest.expected_parameter_ids:
            decision = task.record_human_decision(
                parameter_id=parameter_id,
                verdict=HumanVerdict.SAME,
                evidence_manifest_hash=self.manifest.manifest_hash,
            )
            log.append(
                task_id=task.task_id,
                parameter_id=parameter_id,
                actor_id=decision.reviewer_id,
                action=AuditAction.HUMAN_DECISION_RECORDED,
                details={"verdict": decision.verdict.value},
                reason=decision.reason,
                evidence_context=base_context,
            )
        task.lock_human_review(
            evidence_manifest_hash=self.manifest.manifest_hash
        )
        log.append(
            task_id=task.task_id,
            actor_id=task.reviewer_id,
            action=AuditAction.HUMAN_REVIEW_LOCKED,
            details={"decision_count": 2},
            evidence_context=base_context,
        )

        task.queue_ai_review(
            run_id="integration-run-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
            pipeline_spec_hash=self.pipeline.spec_hash,
        )
        task.start_ai_review(
            run_id="integration-run-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
        )
        log.append(
            task_id=task.task_id,
            actor_id="service:ai:integration-worker",
            action=AuditAction.AI_REVIEW_STARTED,
            details={},
            evidence_context=ai_context,
        )
        for parameter_id in self.manifest.expected_parameter_ids:
            task.record_ai_assessment(
                run_id="integration-run-001",
                evidence_manifest_hash=self.manifest.manifest_hash,
                parameter_id=parameter_id,
                left_raw="1.0",
                right_raw="1.0",
                extraction_reliable=True,
            )
        task.complete_ai_review(
            run_id="integration-run-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
        )
        assessments = task.revealed_ai_results()
        for parameter_id in self.manifest.expected_parameter_ids:
            assessment = assessments[parameter_id]
            assert assessment.comparison_result is not None
            log.append(
                task_id=task.task_id,
                parameter_id=parameter_id,
                actor_id="service:ai:integration-worker",
                action=AuditAction.AI_ASSESSMENT_RECORDED,
                details={
                    "verdict": assessment.verdict.value,
                    "left_raw": assessment.left_raw,
                    "right_raw": assessment.right_raw,
                    "extraction_reliable": assessment.extraction_reliable,
                    "comparison_kind": assessment.comparison_result.kind.value,
                    "exact_match": assessment.comparison_result.exact_match,
                },
                reason=assessment.reason,
                evidence_context=ai_context,
            )
        log.append(
            task_id=task.task_id,
            actor_id="service:ai:integration-worker",
            action=AuditAction.AI_REVIEW_COMPLETED,
            details={"assessment_count": 2},
            evidence_context=ai_context,
        )
        return task, base_context, ai_context

    def _signals(
        self, task: ReviewTask, path: str
    ) -> dict[str, ReviewSignals]:
        decisions = task.human_decisions()
        assessments = task.revealed_ai_results()
        result: dict[str, ReviewSignals] = {}
        for parameter_id in self.manifest.expected_parameter_ids:
            assessment = assessments[parameter_id]
            assert assessment.comparison_result is not None
            result[parameter_id] = ReviewSignals(
                parameter_id=parameter_id,
                human_verdict=decisions[parameter_id].verdict,
                ai_verdict=assessment.verdict,
                comparison_kind=assessment.comparison_result.kind,
                is_critical=(
                    path == "second" and parameter_id == "temperature"
                ),
                image_quality=ImageQuality.ACCEPTABLE,
                field_issues=(
                    (FieldIssue.UNKNOWN_FIELD,)
                    if path == "direct_qa" and parameter_id == "temperature"
                    else ()
                ),
            )
        return result

    @staticmethod
    def _routes(path: str) -> tuple[RoutingDecision, ...]:
        if path == "second":
            first = RoutingDecision(
                parameter_id="temperature",
                route=ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED,
                reasons=(RouteReason.CRITICAL_PARAMETER,),
            )
        elif path == "direct_qa":
            first = RoutingDecision(
                parameter_id="temperature",
                route=ReviewRoute.QA_REVIEW_REQUIRED,
                reasons=(RouteReason.UNKNOWN_FIELD,),
            )
        else:
            first = RoutingDecision(
                parameter_id="temperature",
                route=ReviewRoute.NO_EXCEPTION_DETECTED,
                reasons=(),
            )
        return (
            first,
            RoutingDecision(
                parameter_id="pressure",
                route=ReviewRoute.NO_EXCEPTION_DETECTED,
                reasons=(),
            ),
        )

    def _prepare_path(
        self,
        path: str,
        *,
        qa_outcome: QaDispositionOutcome = (
            QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION
        ),
    ):
        log = self._new_log()
        task, _base_context, ai_context = self._complete_review_and_audit(log)
        adapter = JsonlFinalAuditCommitter(log)
        captured_requests = []

        def commit(request):
            captured_requests.append(request)
            return adapter(request)

        submission_store = {}
        case = AdjudicationCase(
            task_id=task.task_id,
            evidence_manifest=self.manifest,
            source_review_task=task,
            routing_signals=self._signals(task, path),
            routing_evidence_context=RoutingEvidenceContext(
                routing_rules_version="routing-v1",
                criticality_source_sha256=content_sha256(b"criticality-v1"),
                quality_report_sha256=content_sha256(b"quality-v1"),
                alignment_report_sha256=content_sha256(b"alignment-v1"),
            ),
            final_audit_committer=commit,
            expected_blind_case_id=(
                "integration-blind" if path == "second" else None
            ),
            expected_second_reviewer_id=(
                "reviewer-002" if path == "second" else None
            ),
            locked_second_submission_resolver=(
                (
                    lambda task_id, blind_case_id, submission_hash, command_id: (
                        submission_store.get(blind_case_id)
                    )
                )
                if path == "second"
                else None
            ),
            clock=AdvancingClock(hour=16),
        )
        routes = self._routes(path)
        case.record_routing(
            decisions=routes,
            command_id="integration-route",
            expected_version=0,
        )
        for route in routes:
            log.append(
                task_id=task.task_id,
                parameter_id=route.parameter_id,
                actor_id="service:rules:integration-router",
                action=AuditAction.ROUTE_ASSIGNED,
                details={
                    "route": route.route.value,
                    "reasons": [item.value for item in route.reasons],
                },
                evidence_context=ai_context,
            )

        submission = None
        if path == "second":
            second_reviewer = human("reviewer-002", Role.SECOND_REVIEWER)
            log.append(
                task_id=task.task_id,
                actor_id="service:workflow:orchestrator",
                action=AuditAction.SECOND_REVIEW_ASSIGNED,
                details={
                    "blind_case_id": "integration-blind",
                    "assigned_reviewer_id": second_reviewer.actor_id,
                },
                evidence_context=ai_context,
            )
            blind = BlindReviewSession(
                blind_case_id="integration-blind",
                evidence_manifest=self.manifest,
                primary_reviewer_id=task.reviewer_id,
                assigned_reviewer=second_reviewer,
                clock=AdvancingClock(hour=15),
            )
            for index, parameter_id in enumerate(
                self.manifest.expected_parameter_ids
            ):
                decision = blind.record_decision(
                    actor=second_reviewer,
                    evidence_manifest_hash=self.manifest.manifest_hash,
                    parameter_id=parameter_id,
                    verdict=BlindVerdict.SAME,
                    command_id=f"integration-blind-{index}",
                    expected_version=index,
                )
                log.append(
                    task_id=task.task_id,
                    parameter_id=parameter_id,
                    actor_id=second_reviewer.actor_id,
                    action=AuditAction.SECOND_REVIEW_DECISION_RECORDED,
                    details={
                        "blind_case_id": "integration-blind",
                        "verdict": decision.verdict.value,
                    },
                    reason=decision.reason,
                    evidence_context=ai_context,
                )
            submission = blind.lock(
                actor=second_reviewer,
                evidence_manifest_hash=self.manifest.manifest_hash,
                command_id="integration-blind-lock",
                expected_version=2,
            )
            log.append(
                task_id=task.task_id,
                actor_id=second_reviewer.actor_id,
                action=AuditAction.SECOND_REVIEW_LOCKED,
                details={
                    "blind_case_id": submission.blind_case_id,
                    "decision_count": len(submission.decisions),
                    "second_submission_hash": submission.submission_hash,
                },
                evidence_context=ai_context,
            )
            submission_store[submission.blind_case_id] = submission
            case.reconcile_locked_second_review(
                submission=submission,
                command_id="integration-reconcile",
                expected_version=1,
            )

        if case.exception_ledger():
            exceptions = [
                {
                    "exception_id": item.exception_id,
                    "parameter_id": item.parameter_id,
                    "source": item.source.value,
                    "reason_code": item.reason_code,
                }
                for item in case.exception_ledger()
            ]
            log.append(
                task_id=task.task_id,
                actor_id="service:workflow:orchestrator",
                action=AuditAction.QA_CASE_OPENED,
                details={
                    "exceptions": exceptions,
                    "second_submission_hash": (
                        None if submission is None else submission.submission_hash
                    ),
                },
                evidence_context=ai_context,
            )
            qa_reviewer = human("qa-001", Role.QA_REVIEWER)
            for index, item in enumerate(case.exception_ledger()):
                disposition = case.record_qa_disposition(
                    actor=qa_reviewer,
                    exception_id=item.exception_id,
                    outcome=qa_outcome,
                    rationale="QA resolved against the frozen evidence",
                    reference_ids=(f"qa-ref-{index}",),
                    command_id=f"integration-qa-{index}",
                    expected_version=case.version,
                )
                log.append(
                    task_id=task.task_id,
                    actor_id=qa_reviewer.actor_id,
                    action=AuditAction.QA_DISPOSITION_RECORDED,
                    details={
                        "exception_id": disposition.exception_id,
                        "outcome": disposition.outcome.value,
                        "rationale": disposition.rationale,
                        "reference_ids": list(disposition.reference_ids),
                    },
                    evidence_context=ai_context,
                )
            state = case.complete_qa_disposition(
                actor=qa_reviewer,
                command_id="integration-qa-complete",
                expected_version=case.version,
            )
            digest = case.resolution_digest()
            log.append(
                task_id=task.task_id,
                actor_id=qa_reviewer.actor_id,
                action=AuditAction.QA_DISPOSITION_COMPLETED,
                details={
                    "disposition_count": len(case.exception_ledger()),
                    "result_state": state.value,
                    "resolution_digest": digest,
                },
                evidence_context=ai_context,
            )

        expected_state = (
            AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION
            if qa_outcome is QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION
            else AdjudicationState.APPROVAL_BLOCKED
        )
        self.assertEqual(case.state, expected_state)
        return log, adapter, captured_requests, case, submission

    def _approve_path(self, path: str):
        log, adapter, captured, case, submission = self._prepare_path(path)
        predecessor = log.head_hash()
        digest_before = case.resolution_digest()
        decision = case.approve(
            actor=human("approver-001", Role.FINAL_APPROVER),
            rationale="Approved after reviewing the complete adjudication record",
            evidence_manifest_hash=self.manifest.manifest_hash,
            second_submission_hash=(
                None if submission is None else submission.submission_hash
            ),
            audit_head_hash=predecessor,
            command_id=f"integration-final-{path}",
            expected_version=case.version,
        )
        log.verify()
        final_event = log.events()[-1]
        self.assertEqual(decision.resolution_digest, digest_before)
        self.assertEqual(final_event.details["resolution_digest"], digest_before)
        self.assertEqual(decision.previous_audit_head_hash, predecessor)
        self.assertEqual(final_event.previous_hash, predecessor)
        self.assertEqual(decision.audit_head_hash, final_event.event_hash)
        self.assertEqual(log.head_hash(), final_event.event_hash)
        retry_receipt = adapter(captured[-1])
        self.assertEqual(
            final_event.details["commit_request_hash"],
            retry_receipt.request_hash,
        )
        self.assertEqual(log.head_hash(), final_event.event_hash)
        return log, captured[-1], case

    def test_no_exception_path_commits_real_atomic_final_event(self) -> None:
        log, request, case = self._approve_path("clean")
        actions = [event.action for event in log.events(task_id=case.task_id)]
        self.assertNotIn(AuditAction.QA_CASE_OPENED, actions)
        self.assertNotIn(AuditAction.SECOND_REVIEW_ASSIGNED, actions)
        self.assertEqual(actions[-1], AuditAction.FINAL_APPROVAL_RECORDED)
        self.assertNotIn("SECOND_REVIEW_RECORDED", request.required_prior_actions)

    def test_direct_qa_path_binds_domain_digest_without_hash_cycle(self) -> None:
        log, request, case = self._approve_path("direct_qa")
        events = log.events(task_id=case.task_id)
        completion = next(
            event
            for event in events
            if event.action is AuditAction.QA_DISPOSITION_COMPLETED
        )
        final = events[-1]
        self.assertEqual(
            completion.details["resolution_digest"],
            final.details["resolution_digest"],
        )
        self.assertNotEqual(completion.event_hash, final.event_hash)
        self.assertNotIn(AuditAction.SECOND_REVIEW_ASSIGNED, [e.action for e in events])
        self.assertIn("QA_CASE_OPENED", request.required_prior_actions)

    def test_independent_route_uses_full_field_formal_r2_before_final(self) -> None:
        log, request, case = self._approve_path("second")
        events = log.events(task_id=case.task_id)
        second_ids = {
            event.parameter_id
            for event in events
            if event.action is AuditAction.SECOND_REVIEW_DECISION_RECORDED
        }
        self.assertEqual(second_ids, set(self.manifest.expected_parameter_ids))
        self.assertTrue(
            {
                "SECOND_REVIEW_ASSIGNED",
                "SECOND_REVIEW_DECISION_RECORDED",
                "SECOND_REVIEW_LOCKED",
            }.issubset(request.required_prior_actions)
        )
        self.assertNotIn("SECOND_REVIEW_RECORDED", request.required_prior_actions)

    def test_stale_head_fails_cas_without_domain_final_then_retry_succeeds(self) -> None:
        log, _adapter, _captured, case, _submission = self._prepare_path("clean")
        stale_head = log.head_hash()
        log.append(
            task_id=case.task_id,
            actor_id="observer-001",
            action=AuditAction.GENERIC_NOTE_RECORDED,
            details={"note": "interleaving append"},
        )
        with self.assertRaises(AuditVerificationError):
            case.approve(
                actor=human("approver-001", Role.FINAL_APPROVER),
                rationale="Approve with stale head",
                evidence_manifest_hash=self.manifest.manifest_hash,
                second_submission_hash=None,
                audit_head_hash=stale_head,
                command_id="stale-final-command",
                expected_version=case.version,
            )
        self.assertIsNone(case.final_decision)
        self.assertFalse(
            any(
                event.action is AuditAction.FINAL_APPROVAL_RECORDED
                for event in log.events()
            )
        )
        decision = case.approve(
            actor=human("approver-001", Role.FINAL_APPROVER),
            rationale="Approve after refreshing audit head",
            evidence_manifest_hash=self.manifest.manifest_hash,
            second_submission_hash=None,
            audit_head_hash=log.head_hash(),
            command_id="fresh-final-command",
            expected_version=case.version,
        )
        self.assertEqual(decision.audit_head_hash, log.head_hash())

    def test_blocked_direct_qa_path_commits_real_final_rejection(self) -> None:
        log, _adapter, captured, case, _submission = self._prepare_path(
            "direct_qa",
            qa_outcome=QaDispositionOutcome.CONFIRMED_DIFFERENCE,
        )
        predecessor = log.head_hash()
        decision = case.reject(
            actor=human("approver-001", Role.FINAL_APPROVER),
            rationale="Rejected because QA confirmed a parameter difference",
            evidence_manifest_hash=self.manifest.manifest_hash,
            second_submission_hash=None,
            audit_head_hash=predecessor,
            command_id="integration-final-rejection",
            expected_version=case.version,
        )
        final = log.events()[-1]
        self.assertEqual(final.action, AuditAction.FINAL_REJECTION_RECORDED)
        self.assertEqual(final.previous_hash, predecessor)
        self.assertEqual(final.details["resolution_digest"], case.resolution_digest())
        self.assertEqual(decision.audit_head_hash, final.event_hash)
        self.assertEqual(captured[-1].decision.value, "REJECTED")

    def test_exact_retry_returns_same_receipt_and_changed_request_conflicts(self) -> None:
        log, request, _case = self._approve_path("clean")
        adapter = JsonlFinalAuditCommitter(log)
        first_head = log.head_hash()
        receipt = adapter(request)
        self.assertEqual(receipt.new_head_hash, first_head)
        self.assertEqual(log.head_hash(), first_head)
        with self.assertRaisesRegex(AuditPolicyError, "Legacy"):
            adapter(
                replace(
                    request,
                    required_prior_actions=(
                        *request.required_prior_actions,
                        "SECOND_REVIEW_RECORDED",
                    ),
                )
            )
        with self.assertRaises(AuditPolicyError):
            adapter(replace(request, rationale="Changed retry payload"))


if __name__ == "__main__":
    unittest.main()
