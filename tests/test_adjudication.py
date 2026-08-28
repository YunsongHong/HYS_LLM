"""Fail-closed tests for reconciliation, QA, and final human decisions."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from threading import Barrier, Thread
import unittest

from paramguard.adjudication import (
    AdjudicationCase,
    AdjudicationState,
    ApprovalBlockedError,
    AuditVerificationError,
    DuplicateAdjudicationCommandConflictError,
    DuplicateDispositionError,
    EvidenceBindingError,
    ExceptionSource,
    FinalDecisionAlreadyRecordedError,
    FinalAuditCommitReceipt,
    FinalDecisionKind,
    IncompleteQaDispositionError,
    InvalidAdjudicationTransitionError,
    QaDispositionOutcome,
    ReconciliationReason,
    RoutingEvidenceContext,
    RoutingSchemaError,
    SecondReviewAssignmentMissingError,
    SecondReviewBindingError,
    StaleAdjudicationVersionError,
    SourceReviewProvenanceError,
    UnauthorizedFinalActorError,
    UnauthorizedQaActorError,
    UnknownExceptionError,
)
from paramguard.blind_review import BlindReviewSession, BlindVerdict
from paramguard.comparison import ComparisonKind
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
from paramguard.workflow import AiVerdict, HumanVerdict, ReviewState, ReviewTask


class AdvancingClock:
    def __init__(self, hour: int = 16) -> None:
        self.current = datetime(2026, 8, 25, hour, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        result = self.current
        self.current += timedelta(seconds=1)
        return result


class AuditFixture:
    def __init__(self) -> None:
        self.head = "f" * 64
        self.calls = []
        self.error: Exception | None = None
        self.coverage_complete = True
        self.invalid_receipt_field: str | None = None
        self.current = datetime(2026, 8, 25, 22, 0, tzinfo=timezone.utc)

    def commit(self, request):
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        if request.expected_previous_head_hash != self.head:
            raise RuntimeError("audit compare-and-swap failed")
        if not self.coverage_complete:
            raise RuntimeError("task-specific prerequisite events are incomplete")
        required = {
            "TASK_CREATED",
            "HUMAN_DECISION_RECORDED",
            "HUMAN_REVIEW_LOCKED",
            "AI_REVIEW_STARTED",
            "AI_ASSESSMENT_RECORDED",
            "AI_REVIEW_COMPLETED",
            "ROUTE_ASSIGNED",
        }
        if not required.issubset(request.required_prior_actions):
            raise RuntimeError("required task audit actions are missing")
        if request.expected_parameter_ids != ("temperature", "pressure"):
            raise RuntimeError("parameter-level audit coverage is incomplete")
        if set(request.exception_ids) != set(
            request.qa_disposition_exception_ids
        ):
            raise RuntimeError("exception-level QA audit coverage is incomplete")

        request_hash = AdjudicationCase._final_commit_request_hash(request)
        previous = self.head
        event_id = f"final-event-{len(self.calls)}"
        new_head = hashlib.sha256(
            f"{previous}:{request_hash}:{event_id}".encode("utf-8")
        ).hexdigest()
        receipt = FinalAuditCommitReceipt(
            request_hash=request_hash,
            previous_head_hash=previous,
            new_head_hash=new_head,
            event_id=event_id,
            committed_at=self.current,
        )
        self.current += timedelta(seconds=1)
        self.head = new_head
        if self.invalid_receipt_field == "request_hash":
            return replace(receipt, request_hash="e" * 64)
        if self.invalid_receipt_field == "previous_head_hash":
            return replace(receipt, previous_head_hash="e" * 64)
        if self.invalid_receipt_field == "new_head_hash":
            return replace(receipt, new_head_hash=previous)
        return receipt


def make_manifest() -> EvidenceManifest:
    left = EvidenceArtifact.from_bytes(
        artifact_id="left-photo",
        role=EvidenceRole.LEFT_PHOTO,
        content=b"synthetic-left-image",
        media_type="image/png",
    )
    right = EvidenceArtifact.from_bytes(
        artifact_id="right-screenshot",
        role=EvidenceRole.RIGHT_SCREENSHOT,
        content=b"synthetic-right-image",
        media_type="image/png",
    )
    return EvidenceManifest(
        manifest_id="manifest-adjudication-001",
        schema_id="schema-adjudication",
        schema_version="1.0",
        schema_sha256=content_sha256(b"schema-v1"),
        template_id="template-adjudication",
        template_version="1.0",
        template_sha256=content_sha256(b"template-v1"),
        expected_parameter_ids=("temperature", "pressure"),
        artifacts=(left, right),
    )


def actor(
    actor_id: str,
    *,
    kind: PrincipalKind = PrincipalKind.HUMAN,
    roles: frozenset[Role],
) -> Actor:
    return Actor(actor_id=actor_id, kind=kind, roles=roles)


def qa_actor(actor_id: str = "qa-001") -> Actor:
    return actor(actor_id, roles=frozenset({Role.QA_REVIEWER}))


def final_actor(actor_id: str = "approver-001") -> Actor:
    return actor(actor_id, roles=frozenset({Role.FINAL_APPROVER}))


def second_actor(actor_id: str = "reviewer-002") -> Actor:
    return actor(actor_id, roles=frozenset({Role.SECOND_REVIEWER}))


def clean_routes() -> tuple[RoutingDecision, ...]:
    return (
        RoutingDecision(
            parameter_id="temperature",
            route=ReviewRoute.NO_EXCEPTION_DETECTED,
            reasons=(),
        ),
        RoutingDecision(
            parameter_id="pressure",
            route=ReviewRoute.NO_EXCEPTION_DETECTED,
            reasons=(),
        ),
    )


def second_review_routes() -> tuple[RoutingDecision, ...]:
    return (
        RoutingDecision(
            parameter_id="temperature",
            route=ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED,
            reasons=(RouteReason.CRITICAL_PARAMETER,),
        ),
        clean_routes()[1],
    )


def qa_routes(
    *,
    reasons: tuple[RouteReason, ...] = (RouteReason.UNKNOWN_FIELD,),
) -> tuple[RoutingDecision, ...]:
    return (
        RoutingDecision(
            parameter_id="temperature",
            route=ReviewRoute.QA_REVIEW_REQUIRED,
            reasons=reasons,
        ),
        clean_routes()[1],
    )


class AdjudicationCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = make_manifest()
        self.clock = AdvancingClock()
        self.audit = AuditFixture()
        self.submission_store = {}
        self.review_task = self._completed_review_task()

    def _completed_review_task(
        self,
        *,
        human_verdicts: dict[str, HumanVerdict] | None = None,
        ai_verdicts: dict[str, AiVerdict] | None = None,
        exact_raw: str = "1",
        engine_version: str = "1.0",
    ) -> ReviewTask:
        human_verdicts = human_verdicts or {
            "temperature": HumanVerdict.SAME,
            "pressure": HumanVerdict.SAME,
        }
        ai_verdicts = ai_verdicts or {
            "temperature": AiVerdict.SAME,
            "pressure": AiVerdict.SAME,
        }
        spec = PipelineSpec(
            spec_id="pipeline-adjudication",
            engine_name="synthetic-ocr",
            engine_version=engine_version,
            pipeline_version="1.0",
            comparator_version="1.0",
            configuration_sha256=content_sha256(
                f"pipeline-{engine_version}".encode("utf-8")
            ),
        )
        task = ReviewTask(
            task_id="task-adjudication-001",
            evidence_manifest=self.manifest,
            approved_pipeline_spec=spec,
            reviewer_id="reviewer-001",
            clock=AdvancingClock(hour=12),
        )
        for parameter_id in self.manifest.expected_parameter_ids:
            verdict = human_verdicts[parameter_id]
            task.record_human_decision(
                parameter_id=parameter_id,
                verdict=verdict,
                reason=(
                    None if verdict is HumanVerdict.SAME else "Primary reason"
                ),
                evidence_manifest_hash=self.manifest.manifest_hash,
            )
        task.lock_human_review(
            evidence_manifest_hash=self.manifest.manifest_hash
        )
        task.queue_ai_review(
            run_id="ai-run-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
            pipeline_spec_hash=spec.spec_hash,
        )
        task.start_ai_review(
            run_id="ai-run-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
        )
        for parameter_id in self.manifest.expected_parameter_ids:
            verdict = ai_verdicts[parameter_id]
            if verdict is AiVerdict.SYSTEM_ERROR:
                task.record_ai_system_error(
                    run_id="ai-run-001",
                    evidence_manifest_hash=self.manifest.manifest_hash,
                    parameter_id=parameter_id,
                    reason="Synthetic system error",
                )
                continue
            if verdict is AiVerdict.SAME:
                left_raw, right_raw, reliable, reason = (
                    exact_raw,
                    exact_raw,
                    True,
                    None,
                )
            elif verdict is AiVerdict.DIFFERENT:
                left_raw, right_raw, reliable, reason = "1", "2", True, "AI reason"
            else:
                left_raw, right_raw, reliable, reason = None, "1", False, "AI reason"
            task.record_ai_assessment(
                run_id="ai-run-001",
                evidence_manifest_hash=self.manifest.manifest_hash,
                parameter_id=parameter_id,
                left_raw=left_raw,
                right_raw=right_raw,
                extraction_reliable=reliable,
                reason=reason,
            )
        task.complete_ai_review(
            run_id="ai-run-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
        )
        return task

    def _routing_signals(
        self,
        task: ReviewTask,
        *,
        with_second: bool,
        with_qa: bool,
        low_quality: bool,
        unreadable: bool,
    ) -> dict[str, ReviewSignals]:
        humans = task.human_decisions()
        ai = task.revealed_ai_results()
        result = {}
        for parameter_id in self.manifest.expected_parameter_ids:
            assessment = ai[parameter_id]
            comparison_kind = (
                ComparisonKind.UNPARSEABLE_DIFFERENCE
                if assessment.comparison_result is None
                else assessment.comparison_result.kind
            )
            result[parameter_id] = ReviewSignals(
                parameter_id=parameter_id,
                human_verdict=humans[parameter_id].verdict,
                ai_verdict=assessment.verdict,
                comparison_kind=comparison_kind,
                is_critical=(with_second and parameter_id == "temperature"),
                image_quality=(
                    ImageQuality.UNREADABLE
                    if unreadable and parameter_id == "temperature"
                    else ImageQuality.LOW
                    if low_quality and parameter_id == "temperature"
                    else ImageQuality.ACCEPTABLE
                ),
                field_issues=(
                    (FieldIssue.UNKNOWN_FIELD,)
                    if with_qa and parameter_id == "temperature"
                    else ()
                ),
            )
        return result

    def _case(
        self,
        *,
        with_second: bool = False,
        with_qa: bool = False,
        low_quality: bool = False,
        unreadable: bool = False,
        **changes: object,
    ) -> AdjudicationCase:
        source_task = changes.pop("source_review_task", self.review_task)
        assert isinstance(source_task, ReviewTask)
        routing_signals = changes.pop("routing_signals", None)
        if routing_signals is None:
            routing_signals = self._routing_signals(
                source_task,
                with_second=with_second,
                with_qa=with_qa,
                low_quality=low_quality,
                unreadable=unreadable,
            )
        values: dict[str, object] = {
            "task_id": "task-adjudication-001",
            "evidence_manifest": self.manifest,
            "source_review_task": source_task,
            "routing_signals": routing_signals,
            "routing_evidence_context": RoutingEvidenceContext(
                routing_rules_version="routing-v1",
                criticality_source_sha256=content_sha256(b"criticality-v1"),
                quality_report_sha256=content_sha256(b"quality-report-v1"),
                alignment_report_sha256=content_sha256(b"alignment-report-v1"),
            ),
            "final_audit_committer": self.audit.commit,
            "clock": self.clock,
        }
        if with_second:
            values.update(
                expected_blind_case_id="blind-case-001",
                expected_second_reviewer_id="reviewer-002",
                locked_second_submission_resolver=(
                    lambda task_id, blind_case_id, submission_hash, command_id: (
                        self.submission_store.get(blind_case_id)
                    )
                ),
            )
        values.update(changes)
        return AdjudicationCase(**values)  # type: ignore[arg-type]

    def _record_routing(
        self,
        case: AdjudicationCase,
        routes: tuple[RoutingDecision, ...],
    ) -> AdjudicationState:
        return case.record_routing(
            decisions=routes,
            command_id="route-001",
            expected_version=0,
        )

    def _locked_second_submission(
        self,
        *,
        temperature: BlindVerdict = BlindVerdict.SAME,
        pressure: BlindVerdict = BlindVerdict.SAME,
    ):
        reviewer = second_actor()
        session = BlindReviewSession(
            blind_case_id="blind-case-001",
            evidence_manifest=self.manifest,
            primary_reviewer_id="reviewer-001",
            assigned_reviewer=reviewer,
            clock=AdvancingClock(hour=15),
        )
        for index, (parameter_id, verdict) in enumerate(
            (("temperature", temperature), ("pressure", pressure))
        ):
            session.record_decision(
                actor=reviewer,
                evidence_manifest_hash=self.manifest.manifest_hash,
                parameter_id=parameter_id,
                verdict=verdict,
                reason=None if verdict is BlindVerdict.SAME else "Second review reason",
                command_id=f"blind-decision-{index}",
                expected_version=index,
            )
        submission = session.lock(
            actor=reviewer,
            evidence_manifest_hash=self.manifest.manifest_hash,
            command_id="blind-lock-001",
            expected_version=2,
        )
        self.submission_store[submission.blind_case_id] = submission
        return submission

    def _disposition_all(
        self,
        case: AdjudicationCase,
        *,
        outcome: QaDispositionOutcome = (
            QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION
        ),
    ) -> None:
        reviewer = qa_actor()
        for index, item in enumerate(case.exception_ledger()):
            case.record_qa_disposition(
                actor=reviewer,
                exception_id=item.exception_id,
                outcome=outcome,
                rationale="QA reviewed immutable evidence",
                command_id=f"qa-item-{index}",
                expected_version=case.version,
            )

    def _approve(
        self,
        case: AdjudicationCase,
        *,
        command_id: str = "final-approve-001",
        expected_version: int | None = None,
        manifest_hash: str | None = None,
        second_hash: str | None = None,
        audit_hash: str | None = None,
        final_reviewer: Actor | None = None,
    ):
        return case.approve(
            actor=final_reviewer or final_actor(),
            rationale="Human final review completed",
            evidence_manifest_hash=manifest_hash or self.manifest.manifest_hash,
            second_submission_hash=second_hash,
            audit_head_hash=audit_hash or self.audit.head,
            command_id=command_id,
            expected_version=(
                case.version if expected_version is None else expected_version
            ),
        )

    # Routing coverage and exception-ledger tests.

    def test_routing_must_exactly_cover_frozen_schema(self) -> None:
        cases = (
            (
                clean_routes()[:1],
                ("pressure",),
                (),
                (),
            ),
            (
                (
                    clean_routes()[0],
                    RoutingDecision(
                        parameter_id="unknown",
                        route=ReviewRoute.NO_EXCEPTION_DETECTED,
                        reasons=(),
                    ),
                ),
                ("pressure",),
                ("unknown",),
                (),
            ),
            (
                (clean_routes()[0], clean_routes()[0]),
                ("pressure",),
                (),
                ("temperature",),
            ),
        )
        for routes, missing, unknown, duplicates in cases:
            with self.subTest(routes=routes):
                case = self._case()
                with self.assertRaises(RoutingSchemaError) as context:
                    self._record_routing(case, routes)
                self.assertEqual(context.exception.missing_parameter_ids, missing)
                self.assertEqual(context.exception.unknown_parameter_ids, unknown)
                self.assertEqual(context.exception.duplicate_parameter_ids, duplicates)
                self.assertEqual(case.state, AdjudicationState.ROUTING_PENDING)
                self.assertEqual(case.version, 0)

    def test_inconsistent_route_reason_combinations_fail_closed(self) -> None:
        invalid = (
            (
                RoutingDecision(
                    parameter_id="temperature",
                    route=ReviewRoute.NO_EXCEPTION_DETECTED,
                    reasons=(RouteReason.CRITICAL_PARAMETER,),
                ),
                clean_routes()[1],
            ),
            (
                RoutingDecision(
                    parameter_id="temperature",
                    route=ReviewRoute.QA_REVIEW_REQUIRED,
                    reasons=(),
                ),
                clean_routes()[1],
            ),
        )
        for routes in invalid:
            with self.subTest(routes=routes):
                case = self._case()
                with self.assertRaises(RoutingSchemaError):
                    self._record_routing(case, routes)
                self.assertEqual(case.version, 0)

    def test_routing_cannot_hide_or_invent_bound_human_ai_facts(self) -> None:
        different_primary = self._completed_review_task(
            human_verdicts={
                "temperature": HumanVerdict.DIFFERENT,
                "pressure": HumanVerdict.SAME,
            }
        )
        different_ai = self._completed_review_task(
            ai_verdicts={
                "temperature": AiVerdict.DIFFERENT,
                "pressure": AiVerdict.SAME,
            }
        )
        cases = (
            (
                self._case(source_review_task=different_primary),
                clean_routes(),
            ),
            (
                self._case(source_review_task=different_ai),
                clean_routes(),
            ),
            (
                self._case(with_second=True),
                (
                    RoutingDecision(
                        parameter_id="temperature",
                        route=ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED,
                        reasons=(RouteReason.UNKNOWN_FIELD,),
                    ),
                    clean_routes()[1],
                ),
            ),
            (
                self._case(with_second=True),
                (
                    RoutingDecision(
                        parameter_id="temperature",
                        route=ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED,
                        reasons=(RouteReason.HUMAN_DETECTED_DIFFERENCE,),
                    ),
                    clean_routes()[1],
                ),
            ),
        )
        for case, routes in cases:
            with self.subTest(routes=routes):
                with self.assertRaises(RoutingSchemaError):
                    self._record_routing(case, routes)
                self.assertEqual(case.state, AdjudicationState.ROUTING_PENDING)
                self.assertEqual(case.version, 0)

    def test_critical_quality_and_structural_signals_cannot_be_omitted(self) -> None:
        cases = (
            (self._case(with_second=True), clean_routes()),
            (self._case(low_quality=True), clean_routes()),
            (self._case(unreadable=True), clean_routes()),
            (self._case(with_qa=True), clean_routes()),
        )
        for case, forged_clean_routes in cases:
            with self.subTest(case=case):
                with self.assertRaises(RoutingSchemaError):
                    self._record_routing(case, forged_clean_routes)
                self.assertEqual(case.state, AdjudicationState.ROUTING_PENDING)
                self.assertEqual(case.version, 0)

    def test_routing_signal_snapshot_must_cover_and_match_source_review(self) -> None:
        signals = self._routing_signals(
            self.review_task,
            with_second=False,
            with_qa=False,
            low_quality=False,
            unreadable=False,
        )
        missing = dict(signals)
        del missing["pressure"]
        mismatched = dict(signals)
        mismatched["temperature"] = replace(
            mismatched["temperature"],
            human_verdict=HumanVerdict.DIFFERENT,
        )

        with self.assertRaises(EvidenceBindingError):
            self._case(routing_signals=missing)
        with self.assertRaises(EvidenceBindingError):
            self._case(routing_signals=mismatched)

    def test_source_must_be_completed_human_first_review_task(self) -> None:
        complete = self._completed_review_task()
        signals = self._routing_signals(
            complete,
            with_second=False,
            with_qa=False,
            low_quality=False,
            unreadable=False,
        )
        complete._state = ReviewState.HUMAN_REVIEW_LOCKED
        with self.assertRaises(SourceReviewProvenanceError):
            self._case(
                source_review_task=complete,
                routing_signals=signals,
            )

        reversed_time = self._completed_review_task()
        reversed_signals = self._routing_signals(
            reversed_time,
            with_second=False,
            with_qa=False,
            low_quality=False,
            unreadable=False,
        )
        reversed_time._ai_results["temperature"] = replace(
            reversed_time._ai_results["temperature"],
            assessed_at=datetime(2026, 8, 25, 1, 0, tzinfo=timezone.utc),
        )
        with self.assertRaises(SourceReviewProvenanceError):
            self._case(
                source_review_task=reversed_time,
                routing_signals=reversed_signals,
            )

    def test_all_no_exception_is_ready_but_never_auto_approved(self) -> None:
        case = self._case()

        state = self._record_routing(case, clean_routes())

        self.assertEqual(state, AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION)
        self.assertEqual(case.exception_ledger(), ())
        self.assertIsNone(case.final_decision)
        self.assertNotEqual(case.state, AdjudicationState.FINAL_APPROVED)

    def test_each_route_reason_becomes_a_distinct_exception_item(self) -> None:
        case = self._case(with_second=True, low_quality=True)
        routes = (
            RoutingDecision(
                parameter_id="temperature",
                route=ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED,
                reasons=(
                    RouteReason.LOW_IMAGE_QUALITY,
                    RouteReason.CRITICAL_PARAMETER,
                ),
            ),
            clean_routes()[1],
        )

        self._record_routing(case, routes)
        ledger = case.exception_ledger()

        self.assertEqual(case.state, AdjudicationState.SECOND_REVIEW_OPEN)
        self.assertEqual(len(ledger), 2)
        self.assertEqual(len({item.exception_id for item in ledger}), 2)
        self.assertEqual(
            {item.reason_code for item in ledger},
            {"CRITICAL_PARAMETER", "LOW_IMAGE_QUALITY"},
        )
        self.assertTrue(all(item.source is ExceptionSource.ROUTING for item in ledger))

    def test_second_review_route_requires_a_bound_blind_assignment(self) -> None:
        signals = self._routing_signals(
            self.review_task,
            with_second=True,
            with_qa=False,
            low_quality=False,
            unreadable=False,
        )
        case = self._case(routing_signals=signals)

        with self.assertRaises(SecondReviewAssignmentMissingError):
            self._record_routing(case, second_review_routes())

        self.assertEqual(case.state, AdjudicationState.ROUTING_PENDING)
        self.assertEqual(case.exception_ledger(), ())
        self.assertEqual(case.version, 0)

    def test_direct_qa_route_opens_qa_without_second_submission(self) -> None:
        case = self._case(with_qa=True)

        state = self._record_routing(case, qa_routes())

        self.assertEqual(state, AdjudicationState.QA_DISPOSITION_OPEN)
        self.assertEqual(len(case.exception_ledger()), 1)

    def test_routing_command_is_idempotent_and_conflicting_reuse_fails(self) -> None:
        case = self._case()
        first = self._record_routing(case, clean_routes())
        retry = case.record_routing(
            decisions=clean_routes(), command_id="route-001", expected_version=0
        )

        self.assertIs(first, retry)
        self.assertEqual(case.version, 1)
        with self.assertRaises(DuplicateAdjudicationCommandConflictError):
            case.record_routing(
                decisions=clean_routes(),
                command_id="route-001",
                expected_version=999,
            )

    # Locked second-review binding and reconciliation tests.

    def test_locked_second_review_adds_reconciliation_exceptions(self) -> None:
        case = self._case(with_second=True)
        self._record_routing(case, second_review_routes())
        submission = self._locked_second_submission(
            temperature=BlindVerdict.DIFFERENT
        )

        result = case.reconcile_locked_second_review(
            submission=submission,
            command_id="reconcile-001",
            expected_version=1,
        )

        self.assertEqual(result.next_state, AdjudicationState.QA_DISPOSITION_OPEN)
        self.assertEqual(result.second_submission_hash, submission.submission_hash)
        added = {
            item.reason_code
            for item in case.exception_ledger()
            if item.source is ExceptionSource.SECOND_REVIEW_RECONCILIATION
        }
        self.assertEqual(
            added,
            {
                ReconciliationReason.PRIMARY_SECOND_DISAGREEMENT.value,
                ReconciliationReason.AI_SECOND_DISAGREEMENT.value,
            },
        )

    def test_self_consistent_untrusted_second_hash_is_rejected(self) -> None:
        case = self._case(with_second=True)
        self._record_routing(case, second_review_routes())
        self_consistent = self._locked_second_submission()
        self.submission_store.clear()

        with self.assertRaises(SecondReviewBindingError):
            case.reconcile_locked_second_review(
                submission=self_consistent,
                command_id="reconcile-untrusted",
                expected_version=1,
            )

        self.assertEqual(case.state, AdjudicationState.SECOND_REVIEW_OPEN)
        self.assertEqual(case.version, 1)

    def test_tampered_second_submission_is_rejected_without_mutation(self) -> None:
        case = self._case(with_second=True)
        self._record_routing(case, second_review_routes())
        good = self._locked_second_submission()
        missing_reason_decisions = (
            replace(
                good.decisions[0],
                verdict=BlindVerdict.DIFFERENT,
                reason=None,
            ),
            good.decisions[1],
        )
        unsigned_missing_reason = replace(
            good,
            decisions=missing_reason_decisions,
            submission_hash="0" * 64,
        )
        signed_missing_reason = replace(
            unsigned_missing_reason,
            submission_hash=case._calculate_submission_hash(
                unsigned_missing_reason
            ),
        )
        candidates = (
            replace(good, submission_hash="0" * 64),
            replace(good, blind_case_id="blind-case-wrong"),
            replace(good, reviewer_id="reviewer-003"),
            replace(good, evidence_manifest_hash="e" * 64),
            signed_missing_reason,
        )
        for index, candidate in enumerate(candidates):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SecondReviewBindingError):
                    case.reconcile_locked_second_review(
                        submission=candidate,
                        command_id=f"reconcile-bad-{index}",
                        expected_version=1,
                    )
                self.assertEqual(case.state, AdjudicationState.SECOND_REVIEW_OPEN)
                self.assertEqual(case.version, 1)

    def test_second_reconciliation_retry_is_idempotent(self) -> None:
        case = self._case(with_second=True)
        self._record_routing(case, second_review_routes())
        submission = self._locked_second_submission()
        first = case.reconcile_locked_second_review(
            submission=submission,
            command_id="reconcile-001",
            expected_version=1,
        )
        retry = case.reconcile_locked_second_review(
            submission=submission,
            command_id="reconcile-001",
            expected_version=1,
        )

        self.assertIs(first, retry)
        self.assertEqual(case.version, 2)

    # QA authorization, completeness, and outcome tests.

    def test_only_human_qa_reviewer_can_disposition(self) -> None:
        case = self._case(with_qa=True)
        self._record_routing(case, qa_routes())
        exception_id = case.exception_ledger()[0].exception_id
        bad_actors = (
            actor("person-no-role", roles=frozenset()),
            actor(
                "ai-qa",
                kind=PrincipalKind.AI_SERVICE,
                roles=frozenset({Role.QA_REVIEWER}),
            ),
            actor(
                "system-qa",
                kind=PrincipalKind.SYSTEM_SERVICE,
                roles=frozenset({Role.QA_REVIEWER}),
            ),
            actor(
                "admin-qa",
                roles=frozenset({Role.ADMIN, Role.QA_REVIEWER}),
            ),
            actor(
                "ai-worker-qa",
                roles=frozenset({Role.AI_WORKER, Role.QA_REVIEWER}),
            ),
        )
        for bad_actor in bad_actors:
            with self.subTest(actor=bad_actor):
                with self.assertRaises(UnauthorizedQaActorError):
                    case.record_qa_disposition(
                        actor=bad_actor,
                        exception_id=exception_id,
                        outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
                        rationale="Should not work",
                        command_id="bad-qa",
                        expected_version=1,
                    )

    def test_every_exception_requires_its_own_qa_disposition(self) -> None:
        case = self._case(with_qa=True, unreadable=True)
        self._record_routing(
            case,
            qa_routes(
                reasons=(
                    RouteReason.UNKNOWN_FIELD,
                    RouteReason.UNREADABLE_IMAGE,
                )
            ),
        )
        first = case.exception_ledger()[0]
        case.record_qa_disposition(
            actor=qa_actor(),
            exception_id=first.exception_id,
            outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
            rationale="One item checked",
            command_id="qa-item-001",
            expected_version=1,
        )

        with self.assertRaises(IncompleteQaDispositionError) as context:
            case.complete_qa_disposition(
                actor=qa_actor(),
                command_id="qa-complete-001",
                expected_version=2,
            )

        self.assertEqual(len(context.exception.unresolved_exception_ids), 1)
        self.assertEqual(case.state, AdjudicationState.QA_DISPOSITION_OPEN)
        self.assertEqual(case.version, 2)

    def test_unknown_or_duplicate_disposition_is_rejected(self) -> None:
        case = self._case(with_qa=True)
        self._record_routing(case, qa_routes())
        with self.assertRaises(UnknownExceptionError):
            case.record_qa_disposition(
                actor=qa_actor(),
                exception_id="exc-unknown",
                outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
                rationale="Unknown",
                command_id="qa-unknown",
                expected_version=1,
            )
        item = case.exception_ledger()[0]
        case.record_qa_disposition(
            actor=qa_actor(),
            exception_id=item.exception_id,
            outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
            rationale="First immutable result",
            command_id="qa-first",
            expected_version=1,
        )
        with self.assertRaises(DuplicateDispositionError):
            case.record_qa_disposition(
                actor=qa_actor(),
                exception_id=item.exception_id,
                outcome=QaDispositionOutcome.CONFIRMED_DIFFERENCE,
                rationale="Overwrite attempt",
                command_id="qa-overwrite",
                expected_version=2,
            )

    def test_resolved_qa_only_makes_case_ready_for_human_decision(self) -> None:
        case = self._case(with_qa=True)
        self._record_routing(case, qa_routes())
        self._disposition_all(case)

        state = case.complete_qa_disposition(
            actor=qa_actor(),
            command_id="qa-complete-001",
            expected_version=case.version,
        )

        self.assertEqual(state, AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION)
        self.assertIsNone(case.final_decision)

    def test_blocking_and_rework_outcomes_cannot_reach_approval_ready(self) -> None:
        cases = (
            (
                QaDispositionOutcome.CONFIRMED_DIFFERENCE,
                AdjudicationState.APPROVAL_BLOCKED,
            ),
            (
                QaDispositionOutcome.EXTERNAL_DEVIATION_CONTROL_REQUIRED,
                AdjudicationState.APPROVAL_BLOCKED,
            ),
            (
                QaDispositionOutcome.EVIDENCE_REWORK_REQUIRED,
                AdjudicationState.REWORK_REQUIRED,
            ),
            (
                QaDispositionOutcome.TASK_INVALIDATED,
                AdjudicationState.REWORK_REQUIRED,
            ),
        )
        for outcome, expected_state in cases:
            with self.subTest(outcome=outcome):
                case = self._case(with_qa=True)
                self._record_routing(case, qa_routes())
                self._disposition_all(case, outcome=outcome)
                state = case.complete_qa_disposition(
                    actor=qa_actor(),
                    command_id="qa-complete-001",
                    expected_version=case.version,
                )
                self.assertEqual(state, expected_state)
                with self.assertRaises(ApprovalBlockedError):
                    self._approve(case)

    def test_qa_commands_are_versioned_and_idempotent(self) -> None:
        case = self._case(with_qa=True)
        self._record_routing(case, qa_routes())
        item = case.exception_ledger()[0]
        first = case.record_qa_disposition(
            actor=qa_actor(),
            exception_id=item.exception_id,
            outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
            rationale="Reviewed",
            command_id="qa-item-001",
            expected_version=1,
        )
        retry = case.record_qa_disposition(
            actor=qa_actor(),
            exception_id=item.exception_id,
            outcome=QaDispositionOutcome.RESOLVED_NO_BLOCKING_EXCEPTION,
            rationale="Reviewed",
            command_id="qa-item-001",
            expected_version=1,
        )
        self.assertIs(first, retry)
        self.assertEqual(case.version, 2)
        with self.assertRaises(StaleAdjudicationVersionError):
            case.complete_qa_disposition(
                actor=qa_actor(), command_id="qa-complete", expected_version=1
            )

    # Final decision authorization, binding, and concurrency tests.

    def test_only_non_admin_human_final_approver_can_approve_or_reject(self) -> None:
        bad_actors = (
            actor("human-no-role", roles=frozenset()),
            actor(
                "ai-approver",
                kind=PrincipalKind.AI_SERVICE,
                roles=frozenset({Role.FINAL_APPROVER}),
            ),
            actor(
                "system-approver",
                kind=PrincipalKind.SYSTEM_SERVICE,
                roles=frozenset({Role.FINAL_APPROVER}),
            ),
            actor(
                "admin-approver",
                roles=frozenset({Role.ADMIN, Role.FINAL_APPROVER}),
            ),
            actor(
                "ai-worker-person",
                roles=frozenset({Role.AI_WORKER, Role.FINAL_APPROVER}),
            ),
        )
        for bad_actor in bad_actors:
            with self.subTest(actor=bad_actor):
                case = self._case()
                self._record_routing(case, clean_routes())
                with self.assertRaises(UnauthorizedFinalActorError):
                    self._approve(case, final_reviewer=bad_actor)
                with self.assertRaises(UnauthorizedFinalActorError):
                    case.reject(
                        actor=bad_actor,
                        rationale="Unauthorized rejection",
                        evidence_manifest_hash=self.manifest.manifest_hash,
                        second_submission_hash=None,
                        audit_head_hash=self.audit.head,
                        command_id="bad-reject",
                        expected_version=1,
                    )
                self.assertIsNone(case.final_decision)

    def test_final_approval_binds_manifest_audit_head_and_resolution(self) -> None:
        case = self._case()
        self._record_routing(case, clean_routes())
        previous_head = self.audit.head

        result = self._approve(case, audit_hash=previous_head)

        self.assertEqual(result.decision, FinalDecisionKind.APPROVED)
        self.assertEqual(case.state, AdjudicationState.FINAL_APPROVED)
        self.assertEqual(result.evidence_manifest_hash, self.manifest.manifest_hash)
        self.assertEqual(result.audit_head_hash, self.audit.head)
        self.assertEqual(result.previous_audit_head_hash, previous_head)
        self.assertNotEqual(result.audit_head_hash, previous_head)
        self.assertIsNone(result.second_submission_hash)
        self.assertEqual(len(result.resolution_digest), 64)
        self.assertEqual(len(self.audit.calls), 1)
        self.assertIn(
            "ROUTE_ASSIGNED", self.audit.calls[0].required_prior_actions
        )

    def test_resolution_digest_binds_raw_ai_and_pipeline_identity(self) -> None:
        first_task = self._completed_review_task(
            exact_raw="1", engine_version="1.0"
        )
        second_task = self._completed_review_task(
            exact_raw="999", engine_version="99.0"
        )
        first = self._case(source_review_task=first_task)
        second = self._case(source_review_task=second_task)
        self._record_routing(first, clean_routes())
        self._record_routing(second, clean_routes())

        first_digest = first.resolution_digest()
        second_digest = second.resolution_digest()

        self.assertNotEqual(first_digest, second_digest)

    def test_final_approval_rejects_wrong_manifest_or_audit_binding(self) -> None:
        case = self._case()
        self._record_routing(case, clean_routes())
        with self.assertRaises(EvidenceBindingError):
            self._approve(case, manifest_hash="e" * 64)
        self.assertEqual(
            case.state, AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION
        )
        self.assertEqual(case.version, 1)

        stale_head_case = self._case()
        self._record_routing(stale_head_case, clean_routes())
        with self.assertRaises(AuditVerificationError):
            self._approve(stale_head_case, audit_hash="d" * 64)
        self.assertEqual(
            stale_head_case.state,
            AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
        )
        self.assertEqual(stale_head_case.version, 1)

    def test_atomic_audit_commit_failure_blocks_final_decision(self) -> None:
        case = self._case()
        self._record_routing(case, clean_routes())
        self.audit.error = RuntimeError("synthetic audit failure")

        with self.assertRaises(AuditVerificationError):
            self._approve(case)

        self.assertIsNone(case.final_decision)
        self.assertEqual(case.version, 1)

    def test_empty_incomplete_or_malformed_audit_receipt_cannot_approve(self) -> None:
        scenarios = ("genesis", "coverage", "request_hash", "new_head_hash")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.audit = AuditFixture()
                if scenario == "genesis":
                    self.audit.head = "0" * 64
                elif scenario == "coverage":
                    self.audit.coverage_complete = False
                else:
                    self.audit.invalid_receipt_field = scenario
                case = self._case()
                self._record_routing(case, clean_routes())
                with self.assertRaises(AuditVerificationError):
                    self._approve(case)
                self.assertIsNone(case.final_decision)
                self.assertEqual(case.version, 1)

    def test_second_review_hash_is_required_and_bound_at_final_decision(self) -> None:
        case = self._case(with_second=True)
        self._record_routing(case, second_review_routes())
        submission = self._locked_second_submission()
        case.reconcile_locked_second_review(
            submission=submission,
            command_id="reconcile-001",
            expected_version=1,
        )
        self._disposition_all(case)
        case.complete_qa_disposition(
            actor=qa_actor(),
            command_id="qa-complete-001",
            expected_version=case.version,
        )

        with self.assertRaises(EvidenceBindingError):
            self._approve(case, second_hash=None)
        with self.assertRaises(EvidenceBindingError):
            self._approve(case, second_hash="b" * 64)

        result = self._approve(case, second_hash=submission.submission_hash)
        self.assertEqual(result.second_submission_hash, submission.submission_hash)
        required_actions = set(self.audit.calls[-1].required_prior_actions)
        self.assertNotIn("SECOND_REVIEW_RECORDED", required_actions)
        self.assertTrue(
            {
                "SECOND_REVIEW_ASSIGNED",
                "SECOND_REVIEW_DECISION_RECORDED",
                "SECOND_REVIEW_LOCKED",
            }.issubset(required_actions)
        )
        self.assertIn("QA_CASE_OPENED", required_actions)
        self.assertIn("QA_DISPOSITION_RECORDED", required_actions)
        self.assertEqual(
            set(self.audit.calls[-1].exception_ids),
            set(self.audit.calls[-1].qa_disposition_exception_ids),
        )

    def test_authorized_human_can_reject_a_blocked_case_but_not_open_case(self) -> None:
        open_case = self._case()
        with self.assertRaises(InvalidAdjudicationTransitionError):
            open_case.reject(
                actor=final_actor(),
                rationale="Too early",
                evidence_manifest_hash=self.manifest.manifest_hash,
                second_submission_hash=None,
                audit_head_hash=self.audit.head,
                command_id="reject-open",
                expected_version=0,
            )

        blocked = self._case(with_qa=True)
        self._record_routing(blocked, qa_routes())
        self._disposition_all(
            blocked, outcome=QaDispositionOutcome.CONFIRMED_DIFFERENCE
        )
        blocked.complete_qa_disposition(
            actor=qa_actor(),
            command_id="qa-complete-001",
            expected_version=blocked.version,
        )
        result = blocked.reject(
            actor=final_actor(),
            rationale="Confirmed parameter difference",
            evidence_manifest_hash=self.manifest.manifest_hash,
            second_submission_hash=None,
            audit_head_hash=self.audit.head,
            command_id="final-reject-001",
            expected_version=blocked.version,
        )
        self.assertEqual(result.decision, FinalDecisionKind.REJECTED)
        self.assertEqual(blocked.state, AdjudicationState.FINAL_REJECTED)

    def test_final_command_retry_is_idempotent_and_conflict_is_rejected(self) -> None:
        case = self._case()
        self._record_routing(case, clean_routes())
        previous_head = self.audit.head
        first = self._approve(
            case, expected_version=1, audit_hash=previous_head
        )
        retry = self._approve(
            case, expected_version=1, audit_hash=previous_head
        )

        self.assertIs(first, retry)
        self.assertEqual(case.version, 2)
        self.assertEqual(len(self.audit.calls), 1)
        with self.assertRaises(DuplicateAdjudicationCommandConflictError):
            case.approve(
                actor=final_actor(),
                rationale="Changed retry payload",
                evidence_manifest_hash=self.manifest.manifest_hash,
                second_submission_hash=None,
                audit_head_hash=self.audit.head,
                command_id="final-approve-001",
                expected_version=1,
            )

    def test_two_concurrent_final_approvals_create_at_most_one_decision(self) -> None:
        case = self._case()
        self._record_routing(case, clean_routes())
        previous_head = self.audit.head
        barrier = Barrier(3)
        results = []
        errors = []

        def approve(command_id: str) -> None:
            barrier.wait(timeout=2)
            try:
                results.append(
                    self._approve(
                        case,
                        command_id=command_id,
                        expected_version=1,
                        audit_hash=previous_head,
                    )
                )
            except Exception as error:  # pragma: no cover - diagnostic capture
                errors.append(error)

        threads = (
            Thread(target=approve, args=("concurrent-approve-1",)),
            Thread(target=approve, args=("concurrent-approve-2",)),
        )
        for thread in threads:
            thread.start()
        barrier.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=2)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], FinalDecisionAlreadyRecordedError)
        self.assertEqual(case.state, AdjudicationState.FINAL_APPROVED)
        self.assertEqual(case.version, 2)

    def test_naive_clock_fails_before_route_mutation(self) -> None:
        case = self._case(clock=lambda: datetime(2026, 8, 25, 16, 0))

        with self.assertRaises(ValueError):
            self._record_routing(case, clean_routes())

        self.assertEqual(case.state, AdjudicationState.ROUTING_PENDING)
        self.assertEqual(case.version, 0)


if __name__ == "__main__":
    unittest.main()
