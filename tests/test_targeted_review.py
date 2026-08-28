"""Adversarial tests for the post-AI targeted human-recheck aggregate."""

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import inspect
from threading import Barrier, Lock, Thread
import unittest

from paramguard.comparison import compare_values
from paramguard.identity import Actor, PrincipalKind, Role
from paramguard.review_policy import (
    CONSERVATIVE_BLIND_R2,
    INTERVIEW_TARGETED_RECHECK,
    ReviewNextStep,
)
from paramguard.routing import (
    FieldIssue,
    ImageQuality,
    RouteReason,
)
from paramguard.targeted_review import (
    DuplicateTargetedCommandConflictError,
    IncompleteTargetedReviewError,
    LockedParameterRoutingContext,
    LockedRoutingContext,
    StaleTargetedReviewRevisionError,
    TargetedAssignmentBindingError,
    TargetedEvidenceBindingError,
    TargetedReasonRequiredError,
    TargetedReviewLockedError,
    TargetedReviewSession,
    TargetedReviewState,
    TargetedRoutingContextBindingError,
    TargetedRoutingSchemaError,
    TargetedSnapshotBindingError,
    TargetedSourceBindingError,
    TargetedSourceStateError,
    TargetedTaskBindingError,
    TargetedVerdict,
    TargetedSubmissionBindingError,
    UnauthorizedTargetedReviewerError,
    UnknownTargetedParameterError,
    UnsupportedTargetedProfileError,
    validate_locked_targeted_submission,
)
from paramguard.workflow import AiVerdict, HumanVerdict, ReviewTask
from test_workflow import make_manifest, make_pipeline_spec


class AdvancingClock:
    def __init__(self, hour: int) -> None:
        self.current = datetime(2026, 8, 25, hour, 0, tzinfo=timezone.utc)
        self._lock = Lock()

    def __call__(self) -> datetime:
        with self._lock:
            result = self.current
            self.current += timedelta(milliseconds=1)
            return result


def reviewer_actor(
    actor_id: str = "reviewer-002",
    *,
    roles: frozenset[Role] | None = None,
    kind: PrincipalKind = PrincipalKind.HUMAN,
) -> Actor:
    return Actor(
        actor_id=actor_id,
        kind=kind,
        roles=(
            frozenset({Role.SECOND_REVIEWER})
            if roles is None
            else roles
        ),
    )


def different_sha256(value: str) -> str:
    replacement = "0" if value[0] != "0" else "1"
    return replacement + value[1:]


def build_completed_task(
    *,
    expected_ids: tuple[str, ...] = ("temperature", "pressure", "flow"),
    human: dict[str, HumanVerdict] | None = None,
    ai_pairs: dict[str, tuple[str | None, str | None]] | None = None,
    ai_system_errors: frozenset[str] = frozenset(),
    reverse_recording_order: bool = False,
    pipeline_configuration_sha256: str | None = None,
    run_id: str = "run-targeted-001",
) -> ReviewTask:
    manifest = make_manifest(expected_ids)
    pipeline = make_pipeline_spec()
    if pipeline_configuration_sha256 is not None:
        pipeline = replace(
            pipeline,
            configuration_sha256=pipeline_configuration_sha256,
        )
    task = ReviewTask(
        task_id="TASK-TARGETED-001",
        evidence_manifest=manifest,
        approved_pipeline_spec=pipeline,
        reviewer_id="reviewer-001",
        clock=AdvancingClock(10),
    )
    human_values = human or {}
    order = tuple(reversed(expected_ids)) if reverse_recording_order else expected_ids
    for parameter_id in order:
        verdict = human_values.get(parameter_id, HumanVerdict.SAME)
        task.record_human_decision(
            parameter_id=parameter_id,
            verdict=verdict,
            evidence_manifest_hash=task.evidence_manifest_hash,
            reason=(
                None
                if verdict is HumanVerdict.SAME
                else f"R1 observation for {parameter_id}"
            ),
        )
    task.lock_human_review(evidence_manifest_hash=task.evidence_manifest_hash)
    task.queue_ai_review(
        run_id=run_id,
        evidence_manifest_hash=task.evidence_manifest_hash,
        pipeline_spec_hash=pipeline.spec_hash,
    )
    task.start_ai_review(
        run_id=run_id,
        evidence_manifest_hash=task.evidence_manifest_hash,
    )
    pairs = ai_pairs or {}
    for parameter_id in order:
        if parameter_id in ai_system_errors:
            task.record_ai_system_error(
                run_id=run_id,
                evidence_manifest_hash=task.evidence_manifest_hash,
                parameter_id=parameter_id,
                reason="synthetic OCR worker failure",
            )
            continue
        left, right = pairs.get(
            parameter_id,
            (f"synthetic-{parameter_id}", f"synthetic-{parameter_id}"),
        )
        reliable = left is not None and right is not None
        task.record_ai_assessment(
            run_id=run_id,
            evidence_manifest_hash=task.evidence_manifest_hash,
            parameter_id=parameter_id,
            left_raw=left,
            right_raw=right,
            extraction_reliable=reliable,
            reason=None if reliable else "synthetic crop unreadable",
        )
    task.complete_ai_review(
        run_id=run_id,
        evidence_manifest_hash=task.evidence_manifest_hash,
    )
    return task


def routing_context_from_task(
    task: ReviewTask,
    *,
    context: dict[str, dict[str, object]] | None = None,
) -> LockedRoutingContext:
    context = context or {}
    result = []
    for parameter_id in task.expected_parameter_ids:
        changes = context.get(parameter_id, {})
        result.append(
            LockedParameterRoutingContext(
                parameter_id=parameter_id,
                is_critical=changes.get("is_critical", False),  # type: ignore[arg-type]
                image_quality=changes.get(  # type: ignore[arg-type]
                    "image_quality", ImageQuality.ACCEPTABLE
                ),
                field_issues=changes.get("field_issues", ()),  # type: ignore[arg-type]
            )
        )
    return LockedRoutingContext(
        context_id="routing-context-001",
        context_version="1",
        task_id=task.task_id,
        evidence_manifest_hash=task.evidence_manifest_hash,
        locked_at=datetime(2026, 8, 25, 17, 0, tzinfo=timezone.utc),
        parameters=tuple(result),
    )


class StaticTrustedResolver:
    def __init__(
        self,
        context: LockedRoutingContext,
        *,
        on_resolve=None,  # type: ignore[no-untyped-def]
    ) -> None:
        self.context = context
        self.on_resolve = on_resolve
        self.calls: list[tuple[str, str, tuple[str, ...]]] = []

    def resolve_locked_context(
        self,
        *,
        task_id: str,
        evidence_manifest_hash: str,
        expected_parameter_ids: tuple[str, ...],
    ) -> LockedRoutingContext:
        self.calls.append(
            (task_id, evidence_manifest_hash, expected_parameter_ids)
        )
        if self.on_resolve is not None:
            self.on_resolve()
        return self.context


def make_session(
    task: ReviewTask,
    *,
    routing_context: LockedRoutingContext | None = None,
    resolver: StaticTrustedResolver | None = None,
    actor: Actor | None = None,
    profile=INTERVIEW_TARGETED_RECHECK,  # type: ignore[no-untyped-def]
) -> TargetedReviewSession:
    return TargetedReviewSession(
        targeted_case_id="targeted-case-001",
        source_review_task=task,
        routing_context_resolver=(
            resolver
            or StaticTrustedResolver(
                routing_context or routing_context_from_task(task)
            )
        ),
        profile=profile,
        assignment_id="targeted-assignment-001",
        assigned_reviewer=actor or reviewer_actor(),
        clock=AdvancingClock(18),
    )


def command_bindings(
    session: TargetedReviewSession,
    *,
    expected_revision: int,
) -> dict[str, object]:
    return {
        "actor": reviewer_actor(),
        "task_id": session.task_id,
        "assignment_id": session.assignment_id,
        "evidence_manifest_hash": session.evidence_manifest_hash,
        "source_snapshot_sha256": session.source_snapshot_sha256,
        "expected_revision": expected_revision,
    }


class TargetedCreationTests(unittest.TestCase):
    def test_source_must_already_be_ai_review_complete(self) -> None:
        task = ReviewTask(
            task_id="TASK-TARGETED-001",
            evidence_manifest=make_manifest(),
            approved_pipeline_spec=make_pipeline_spec(),
            reviewer_id="reviewer-001",
        )
        with self.assertRaises(TargetedSourceStateError):
            TargetedReviewSession(
                targeted_case_id="targeted-case-001",
                source_review_task=task,
                routing_context_resolver=StaticTrustedResolver(
                    routing_context_from_task(task)
                ),
                profile=INTERVIEW_TARGETED_RECHECK,
                assignment_id="targeted-assignment-001",
                assigned_reviewer=reviewer_actor(),
            )

    def test_only_exact_interview_targeted_profile_is_accepted(self) -> None:
        task = build_completed_task()
        with self.assertRaises(UnsupportedTargetedProfileError):
            make_session(task, profile=CONSERVATIVE_BLIND_R2)
        modified = replace(
            INTERVIEW_TARGETED_RECHECK,
            policy_version="1.0-modified",
        )
        with self.assertRaises(UnsupportedTargetedProfileError):
            make_session(task, profile=modified)

    def test_completed_source_is_valid_even_if_fields_were_recorded_out_of_order(self) -> None:
        task = build_completed_task(reverse_recording_order=True)
        session = make_session(task)
        self.assertEqual(
            session.queue_plan().no_exception_parameter_ids,
            task.expected_parameter_ids,
        )

    def test_tampered_completed_ai_snapshot_fails_closed(self) -> None:
        task = build_completed_task(
            ai_pairs={"temperature": ("100", "101")}
        )
        original = task._ai_results["temperature"]
        task._ai_results["temperature"] = replace(
            original,
            verdict=AiVerdict.SAME,
        )
        with self.assertRaises(TargetedSourceBindingError):
            make_session(task)

    def test_source_change_during_trusted_context_resolution_fails_closed(self) -> None:
        task = build_completed_task()
        context = routing_context_from_task(task)
        original = task._ai_results["temperature"]

        def mutate_source() -> None:
            comparison = compare_values("synthetic-before", "synthetic-after")
            task._ai_results["temperature"] = replace(
                original,
                verdict=AiVerdict.DIFFERENT,
                left_raw=comparison.left_raw,
                right_raw=comparison.right_raw,
                extraction_reliable=True,
                comparison_result=comparison,
                reason=None,
            )

        resolver = StaticTrustedResolver(context, on_resolve=mutate_source)
        with self.assertRaises(TargetedSourceBindingError):
            make_session(task, resolver=resolver)

    def test_routing_context_must_bind_task_manifest_and_resolver_contract(self) -> None:
        task = build_completed_task()
        context = routing_context_from_task(task)
        mismatches = (
            replace(context, task_id="OTHER-TASK"),
            replace(context, evidence_manifest_hash="0" * 64),
        )
        for malformed in mismatches:
            with self.subTest(context=malformed):
                with self.assertRaises(TargetedRoutingContextBindingError):
                    make_session(task, routing_context=malformed)

        with self.assertRaises(TypeError):
            TargetedReviewSession(
                targeted_case_id="targeted-case-001",
                source_review_task=task,
                routing_context_resolver=object(),  # type: ignore[arg-type]
                profile=INTERVIEW_TARGETED_RECHECK,
                assignment_id="targeted-assignment-001",
                assigned_reviewer=reviewer_actor(),
            )
        wrong_type = StaticTrustedResolver(context)
        wrong_type.context = object()  # type: ignore[assignment]
        with self.assertRaises(TargetedRoutingContextBindingError):
            make_session(task, resolver=wrong_type)

    def test_assignment_requires_non_admin_human_reviewer_role(self) -> None:
        task = build_completed_task()
        invalid = (
            reviewer_actor(kind=PrincipalKind.AI_SERVICE),
            reviewer_actor(
                roles=frozenset({Role.SECOND_REVIEWER, Role.ADMIN})
            ),
            reviewer_actor(
                roles=frozenset({Role.SECOND_REVIEWER, Role.AI_WORKER})
            ),
            reviewer_actor(kind=PrincipalKind.SYSTEM_SERVICE),
            reviewer_actor(roles=frozenset()),
            reviewer_actor(
                roles=frozenset({Role.SECOND_REVIEWER, Role.QA_REVIEWER})
            ),
            reviewer_actor(
                roles=frozenset({Role.SECOND_REVIEWER, Role.FINAL_APPROVER})
            ),
            reviewer_actor(
                roles=frozenset({Role.SECOND_REVIEWER, Role.AUDITOR})
            ),
        )
        for actor in invalid:
            with self.subTest(actor=actor):
                with self.assertRaises(UnauthorizedTargetedReviewerError):
                    make_session(task, actor=actor)

    def test_profile_does_not_invent_r1_reviewer_separation(self) -> None:
        task = build_completed_task(
            human={"temperature": HumanVerdict.DIFFERENT}
        )
        same_r1_actor = reviewer_actor(
            "reviewer-001",
            roles=frozenset({Role.PRIMARY_REVIEWER}),
        )
        session = make_session(task, actor=same_r1_actor)
        packet = session.packet(actor=same_r1_actor)
        self.assertEqual(packet.assigned_reviewer_id, "reviewer-001")


class CanonicalQueueTests(unittest.TestCase):
    def test_locked_context_types_are_strict_and_do_not_accept_bool_confusion(self) -> None:
        for changes in (
            {"is_critical": 1},
            {"image_quality": "LOW"},
            {"field_issues": [FieldIssue.UNKNOWN_FIELD]},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(TypeError):
                    LockedParameterRoutingContext(
                        parameter_id="temperature",
                        **changes,  # type: ignore[arg-type]
                    )
        task = build_completed_task()
        valid = routing_context_from_task(task)
        with self.assertRaises(TypeError):
            LockedRoutingContext(
                context_id=valid.context_id,
                context_version=valid.context_version,
                task_id=valid.task_id,
                evidence_manifest_hash=valid.evidence_manifest_hash,
                locked_at=valid.locked_at,
                parameters=list(valid.parameters),  # type: ignore[arg-type]
            )
        bypassed_context = routing_context_from_task(task)
        object.__setattr__(
            bypassed_context,
            "parameters",
            list(bypassed_context.parameters),
        )
        with self.assertRaises(TargetedRoutingContextBindingError):
            make_session(task, routing_context=bypassed_context)
        bypassed_item_context = routing_context_from_task(task)
        object.__setattr__(
            bypassed_item_context.parameters[0],
            "field_issues",
            [FieldIssue.UNKNOWN_FIELD],
        )
        with self.assertRaises(TypeError):
            make_session(task, routing_context=bypassed_item_context)

    def test_queue_is_computed_from_source_and_policy_not_supplied_routes(self) -> None:
        task = build_completed_task(
            human={"temperature": HumanVerdict.DIFFERENT},
            ai_pairs={"pressure": ("10.0", "10")},
        )
        resolver = StaticTrustedResolver(routing_context_from_task(task))
        session = make_session(task, resolver=resolver)
        plan = session.queue_plan()
        self.assertEqual(
            plan.routing_context_sha256,
            resolver.context.content_sha256,
        )

        self.assertEqual(
            tuple(item.parameter_id for item in plan.targeted_items),
            ("temperature", "pressure"),
        )
        self.assertEqual(plan.no_exception_parameter_ids, ("flow",))
        by_id = {item.parameter_id: item for item in plan.targeted_items}
        self.assertIn(
            RouteReason.HUMAN_DETECTED_DIFFERENCE,
            by_id["temperature"].reasons,
        )
        self.assertIn(
            RouteReason.DETERMINISTIC_COMPARISON_NOT_EXACT,
            by_id["pressure"].reasons,
        )
        forbidden_constructor_inputs = {
            "targeted_parameter_ids",
            "routes",
            "reasons",
            "trusted_routing_signals",
            "routing_context_sha256",
        }
        self.assertTrue(
            forbidden_constructor_inputs.isdisjoint(
                inspect.signature(TargetedReviewSession).parameters
            )
        )
        self.assertEqual(
            resolver.calls,
            [
                (
                    task.task_id,
                    task.evidence_manifest_hash,
                    task.expected_parameter_ids,
                )
            ],
        )

    def test_context_cannot_supply_human_ai_or_comparison_facts(self) -> None:
        accepted = set(inspect.signature(LockedParameterRoutingContext).parameters)
        self.assertEqual(
            accepted,
            {"parameter_id", "is_critical", "image_quality", "field_issues"},
        )
        self.assertTrue(
            {"human_verdict", "ai_verdict", "comparison_kind"}.isdisjoint(
                accepted
            )
        )

    def test_missing_duplicate_and_unknown_context_fields_are_rejected(self) -> None:
        task = build_completed_task()
        original = routing_context_from_task(task)
        parameter_cases = (
            original.parameters[:-1],
            (*original.parameters, original.parameters[0]),
            tuple(reversed(original.parameters)),
            (
                *original.parameters[1:],
                replace(original.parameters[0], parameter_id="unknown-field"),
            ),
        )
        for parameters in parameter_cases:
            malformed = routing_context_from_task(task)
            object.__setattr__(malformed, "parameters", parameters)
            with self.subTest(ids=[item.parameter_id for item in parameters]):
                with self.assertRaises(TargetedRoutingSchemaError):
                    make_session(task, routing_context=malformed)

    def test_structural_system_and_critical_policy_fields_go_to_qa_not_queue(self) -> None:
        task = build_completed_task(
            ai_system_errors=frozenset({"temperature"})
        )
        routing_context = routing_context_from_task(
            task,
            context={
                "pressure": {"is_critical": True},
                "flow": {
                    "field_issues": (FieldIssue.MISSING_EXPECTED_FIELD,)
                },
            },
        )
        plan = make_session(
            task, routing_context=routing_context
        ).queue_plan()

        self.assertEqual(plan.targeted_items, ())
        self.assertEqual(
            tuple(item.parameter_id for item in plan.qa_referrals),
            ("temperature", "pressure", "flow"),
        )
        by_id = {item.parameter_id: item for item in plan.qa_referrals}
        self.assertEqual(
            by_id["temperature"].next_step,
            ReviewNextStep.QA_STRUCTURAL_OR_SYSTEM_REVIEW,
        )
        self.assertIn(RouteReason.AI_SYSTEM_ERROR, by_id["temperature"].reasons)
        self.assertEqual(
            by_id["pressure"].next_step,
            ReviewNextStep.QA_CRITICAL_POLICY_CONFIRMATION,
        )
        self.assertEqual(
            by_id["flow"].next_step,
            ReviewNextStep.QA_STRUCTURAL_OR_SYSTEM_REVIEW,
        )
        self.assertFalse(plan.automatic_release_allowed)

    def test_only_targeted_items_appear_in_reviewer_packet(self) -> None:
        task = build_completed_task(
            ai_pairs={"temperature": ("1", "2")}
        )
        routing_context = routing_context_from_task(
            task,
            context={"pressure": {"is_critical": True}},
        )
        session = make_session(task, routing_context=routing_context)
        packet = session.packet(actor=reviewer_actor())
        self.assertEqual(
            tuple(item.parameter_id for item in packet.targeted_items),
            ("temperature",),
        )
        self.assertEqual(
            tuple(item.parameter_id for item in session.queue_plan().qa_referrals),
            ("pressure",),
        )

    def test_ai_same_cannot_erase_r1_difference(self) -> None:
        task = build_completed_task(
            human={"temperature": HumanVerdict.DIFFERENT}
        )
        session = make_session(task)
        item = session.queue_plan().targeted_items[0]
        self.assertEqual(item.primary_verdict, HumanVerdict.DIFFERENT)
        self.assertEqual(item.ai_verdict, AiVerdict.SAME)
        self.assertIn(RouteReason.HUMAN_AI_DISAGREEMENT, item.reasons)
        self.assertIn(RouteReason.HUMAN_DETECTED_DIFFERENCE, item.reasons)

        decision = session.record_decision(
            **command_bindings(session, expected_revision=0),
            parameter_id="temperature",
            verdict=TargetedVerdict.SAME,
            reason="synthetic targeted recheck",
            command_id="targeted-decision-001",
        )
        submission = session.lock(
            **command_bindings(session, expected_revision=1),
            command_id="targeted-lock-001",
        )
        self.assertEqual(decision.verdict, TargetedVerdict.SAME)
        self.assertEqual(
            submission.targeted_items[0].primary_verdict,
            HumanVerdict.DIFFERENT,
        )
        self.assertFalse(submission.automatic_release_allowed)
        self.assertFalse(hasattr(session, "approve"))

    def test_source_plan_is_frozen_and_hash_bound(self) -> None:
        task = build_completed_task(
            ai_pairs={"temperature": ("1", "2")}
        )
        session = make_session(task)
        plan = session.queue_plan()
        packet = session.packet(actor=reviewer_actor())
        self.assertEqual(len(plan.source_snapshot_sha256), 64)
        source_manifest = task.evidence_manifest
        self.assertEqual(packet.evidence_manifest, source_manifest)
        self.assertIsNot(packet.evidence_manifest, source_manifest)
        object.__setattr__(source_manifest, "schema_version", "forged")
        self.assertEqual(packet.evidence_manifest.schema_version, "1.0")
        source_assessment = task._ai_results["temperature"]
        object.__setattr__(source_assessment, "left_raw", "forged")
        self.assertNotEqual(
            session._ai_assessments["temperature"].left_raw,
            "forged",
        )
        with self.assertRaises(FrozenInstanceError):
            plan.task_id = "forged"  # type: ignore[misc]

    def test_locked_context_is_copied_and_flags_cannot_be_cleared_after_resolution(self) -> None:
        task = build_completed_task()
        context = routing_context_from_task(
            task,
            context={
                "temperature": {"is_critical": True},
                "pressure": {"image_quality": ImageQuality.LOW},
                "flow": {"field_issues": (FieldIssue.UNKNOWN_FIELD,)},
            },
        )
        session = make_session(task, routing_context=context)
        before = session.queue_plan()
        before_hash = session.source_snapshot_sha256

        for item in context.parameters:
            object.__setattr__(item, "is_critical", False)
            object.__setattr__(item, "image_quality", ImageQuality.ACCEPTABLE)
            object.__setattr__(item, "field_issues", ())

        after = session.queue_plan()
        self.assertIs(after, before)
        self.assertEqual(session.source_snapshot_sha256, before_hash)
        self.assertEqual(
            tuple(item.parameter_id for item in after.qa_referrals),
            ("temperature", "flow"),
        )
        self.assertEqual(
            tuple(item.parameter_id for item in after.targeted_items),
            ("pressure",),
        )

    def test_source_hash_covers_human_ai_run_spec_and_all_context_facts(self) -> None:
        base_task = build_completed_task()
        base_hash = make_session(base_task).source_snapshot_sha256
        source_variants = (
            build_completed_task(
                human={"temperature": HumanVerdict.DIFFERENT}
            ),
            build_completed_task(ai_pairs={"temperature": ("1", "2")}),
            build_completed_task(run_id="run-targeted-002"),
            build_completed_task(pipeline_configuration_sha256="b" * 64),
        )
        for variant in source_variants:
            with self.subTest(source=variant.revealed_ai_run().run_id):
                self.assertNotEqual(
                    make_session(variant).source_snapshot_sha256,
                    base_hash,
                )

        context_variants = (
            {"temperature": {"is_critical": True}},
            {"temperature": {"image_quality": ImageQuality.LOW}},
            {
                "temperature": {
                    "field_issues": (FieldIssue.MISSING_EXPECTED_FIELD,)
                }
            },
        )
        for facts in context_variants:
            with self.subTest(facts=facts):
                changed = make_session(
                    base_task,
                    routing_context=routing_context_from_task(
                        base_task, context=facts
                    ),
                )
                self.assertNotEqual(changed.source_snapshot_sha256, base_hash)
                self.assertEqual(
                    changed.queue_plan().profile_content_sha256,
                    INTERVIEW_TARGETED_RECHECK.content_sha256,
                )

    def test_1001_fields_are_classified_exactly_without_truncation(self) -> None:
        expected = tuple(f"p{index:04d}" for index in range(1001))
        differences = {
            parameter_id: ("1", "2")
            for index, parameter_id in enumerate(expected)
            if index % 250 == 0
        }
        task = build_completed_task(expected_ids=expected, ai_pairs=differences)
        plan = make_session(task).queue_plan()
        self.assertEqual(len(plan.targeted_items), 5)
        self.assertEqual(len(plan.no_exception_parameter_ids), 996)
        self.assertEqual(
            tuple(item.parameter_id for item in plan.targeted_items),
            ("p0000", "p0250", "p0500", "p0750", "p1000"),
        )


class TargetedMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.actor = reviewer_actor()
        self.task = build_completed_task(
            ai_pairs={
                "temperature": ("100", "101"),
                "pressure": ("20", "21"),
            }
        )
        self.session = make_session(self.task, actor=self.actor)

    def test_each_mutation_requires_task_assignment_manifest_snapshot_and_revision(self) -> None:
        base = command_bindings(self.session, expected_revision=0)
        attempts = (
            ("task_id", "OTHER-TASK", TargetedTaskBindingError),
            (
                "assignment_id",
                "other-assignment",
                TargetedAssignmentBindingError,
            ),
            (
                "evidence_manifest_hash",
                different_sha256(self.session.evidence_manifest_hash),
                TargetedEvidenceBindingError,
            ),
            (
                "source_snapshot_sha256",
                different_sha256(self.session.source_snapshot_sha256),
                TargetedSnapshotBindingError,
            ),
            ("expected_revision", 1, StaleTargetedReviewRevisionError),
        )
        for name, value, error_type in attempts:
            with self.subTest(name=name):
                values = dict(base)
                values[name] = value
                with self.assertRaises(error_type):
                    self.session.record_decision(
                        **values,
                        parameter_id="temperature",
                        verdict=TargetedVerdict.SAME,
                        reason="synthetic targeted recheck",
                        command_id=f"binding-{name}",
                    )
                self.assertEqual(self.session.revision, 0)
                self.assertEqual(
                    dict(self.session.own_decisions(actor=self.actor)), {}
                )

    def test_wrong_bindings_do_not_consume_an_idempotency_key(self) -> None:
        wrong = command_bindings(self.session, expected_revision=0)
        wrong["evidence_manifest_hash"] = different_sha256(
            self.session.evidence_manifest_hash
        )
        with self.assertRaises(TargetedEvidenceBindingError):
            self.session.record_decision(
                **wrong,
                parameter_id="temperature",
                verdict=TargetedVerdict.SAME,
                reason="synthetic targeted recheck",
                command_id="reusable-command",
            )
        result = self.session.record_decision(
            **command_bindings(self.session, expected_revision=0),
            parameter_id="temperature",
            verdict=TargetedVerdict.SAME,
            reason="synthetic targeted recheck",
            command_id="reusable-command",
        )
        self.assertEqual(result.parameter_id, "temperature")

    def test_wrong_identity_and_wrong_assignee_are_rejected(self) -> None:
        invalid = (
            reviewer_actor("other-reviewer"),
            reviewer_actor(
                "reviewer-002",
                roles=frozenset({Role.PRIMARY_REVIEWER}),
            ),
            reviewer_actor(kind=PrincipalKind.AI_SERVICE),
            reviewer_actor(
                roles=frozenset({Role.SECOND_REVIEWER, Role.ADMIN})
            ),
            reviewer_actor(
                roles=frozenset({Role.SECOND_REVIEWER, Role.AI_WORKER})
            ),
        )
        for actor in invalid:
            with self.subTest(actor=actor):
                values = command_bindings(self.session, expected_revision=0)
                values["actor"] = actor
                with self.assertRaises(UnauthorizedTargetedReviewerError):
                    self.session.record_decision(
                        **values,
                        parameter_id="temperature",
                        verdict=TargetedVerdict.SAME,
                        reason="synthetic targeted recheck",
                        command_id="wrong-actor",
                    )
        self.assertEqual(self.session.revision, 0)

    def test_unknown_clean_qa_and_arbitrary_fields_cannot_enter_queue(self) -> None:
        task = build_completed_task(ai_pairs={"temperature": ("1", "2")})
        routing_context = routing_context_from_task(
            task,
            context={"pressure": {"is_critical": True}},
        )
        session = make_session(task, routing_context=routing_context)
        for parameter_id in ("pressure", "flow", "unknown"):
            with self.subTest(parameter_id=parameter_id):
                with self.assertRaises(UnknownTargetedParameterError):
                    session.record_decision(
                        **command_bindings(session, expected_revision=0),
                        parameter_id=parameter_id,
                        verdict=TargetedVerdict.SAME,
                        reason="synthetic targeted recheck",
                        command_id=f"unknown-{parameter_id}",
                    )

    def test_every_targeted_verdict_requires_reason_and_types_are_strict(self) -> None:
        for verdict in (
            TargetedVerdict.SAME,
            TargetedVerdict.DIFFERENT,
            TargetedVerdict.UNABLE_TO_JUDGE,
        ):
            with self.subTest(verdict=verdict):
                with self.assertRaises(TargetedReasonRequiredError):
                    self.session.record_decision(
                        **command_bindings(self.session, expected_revision=0),
                        parameter_id="temperature",
                        verdict=verdict,
                        command_id=f"reason-{verdict.value}",
                    )
        with self.assertRaises(TypeError):
            self.session.record_decision(
                **command_bindings(self.session, expected_revision=0),
                parameter_id="temperature",
                verdict="SAME",  # type: ignore[arg-type]
                command_id="string-verdict",
            )
        bad_revision = command_bindings(self.session, expected_revision=0)
        bad_revision["expected_revision"] = True
        with self.assertRaises(ValueError):
            self.session.record_decision(
                **bad_revision,
                parameter_id="temperature",
                verdict=TargetedVerdict.SAME,
                reason="synthetic targeted recheck",
                command_id="bool-revision",
            )

    def test_incomplete_lock_lists_every_omitted_target_and_is_atomic(self) -> None:
        self.session.record_decision(
            **command_bindings(self.session, expected_revision=0),
            parameter_id="temperature",
            verdict=TargetedVerdict.SAME,
            reason="synthetic targeted recheck",
            command_id="decision-temperature",
        )
        with self.assertRaises(IncompleteTargetedReviewError) as caught:
            self.session.lock(
                **command_bindings(self.session, expected_revision=1),
                command_id="early-lock",
            )
        self.assertEqual(caught.exception.missing_parameter_ids, ("pressure",))
        self.assertEqual(self.session.state, TargetedReviewState.OPEN)
        self.assertEqual(self.session.revision, 1)

    def test_record_and_lock_are_idempotent_but_conflicting_reuse_fails(self) -> None:
        first = self.session.record_decision(
            **command_bindings(self.session, expected_revision=0),
            parameter_id="temperature",
            verdict=TargetedVerdict.SAME,
            reason="synthetic targeted recheck",
            command_id="idempotent-decision",
        )
        replay = self.session.record_decision(
            **command_bindings(self.session, expected_revision=0),
            parameter_id="temperature",
            verdict=TargetedVerdict.SAME,
            reason="synthetic targeted recheck",
            command_id="idempotent-decision",
        )
        self.assertIs(replay, first)
        self.assertEqual(self.session.revision, 1)
        with self.assertRaises(DuplicateTargetedCommandConflictError):
            self.session.record_decision(
                **command_bindings(self.session, expected_revision=0),
                parameter_id="temperature",
                verdict=TargetedVerdict.DIFFERENT,
                reason="different payload",
                command_id="idempotent-decision",
            )

        self.session.record_decision(
            **command_bindings(self.session, expected_revision=1),
            parameter_id="pressure",
            verdict=TargetedVerdict.DIFFERENT,
            reason="confirmed synthetic mismatch",
            command_id="pressure-decision",
        )
        locked = self.session.lock(
            **command_bindings(self.session, expected_revision=2),
            command_id="idempotent-lock",
        )
        lock_replay = self.session.lock(
            **command_bindings(self.session, expected_revision=2),
            command_id="idempotent-lock",
        )
        self.assertIs(lock_replay, locked)
        self.assertEqual(self.session.revision, 3)
        with self.assertRaises(DuplicateTargetedCommandConflictError):
            self.session.lock(
                **command_bindings(self.session, expected_revision=3),
                command_id="idempotent-lock",
            )

    def test_decisions_can_be_revised_before_lock_but_never_after(self) -> None:
        first = self.session.record_decision(
            **command_bindings(self.session, expected_revision=0),
            parameter_id="temperature",
            verdict=TargetedVerdict.SAME,
            reason="synthetic targeted recheck",
            command_id="revision-one",
        )
        revised = self.session.record_decision(
            **command_bindings(self.session, expected_revision=1),
            parameter_id="temperature",
            verdict=TargetedVerdict.DIFFERENT,
            reason="noticed a synthetic digit difference",
            command_id="revision-two",
        )
        self.assertNotEqual(first, revised)
        self.assertEqual(
            len(self.session.own_decision_history(actor=self.actor)), 2
        )
        self.session.record_decision(
            **command_bindings(self.session, expected_revision=2),
            parameter_id="pressure",
            verdict=TargetedVerdict.SAME,
            reason="synthetic targeted recheck",
            command_id="pressure-final",
        )
        self.session.lock(
            **command_bindings(self.session, expected_revision=3),
            command_id="final-lock",
        )
        with self.assertRaises(TargetedReviewLockedError):
            self.session.record_decision(
                **command_bindings(self.session, expected_revision=4),
                parameter_id="temperature",
                verdict=TargetedVerdict.SAME,
                reason="synthetic targeted recheck",
                command_id="after-lock",
            )

    def test_concurrent_same_revision_allows_exactly_one_mutation(self) -> None:
        barrier = Barrier(3)
        successes = []
        errors = []
        result_lock = Lock()

        def worker(index: int) -> None:
            barrier.wait()
            try:
                result = self.session.record_decision(
                    **command_bindings(self.session, expected_revision=0),
                    parameter_id="temperature",
                    verdict=TargetedVerdict.SAME,
                    reason="synthetic targeted recheck",
                    command_id=f"concurrent-{index}",
                )
                with result_lock:
                    successes.append(result)
            except Exception as error:  # noqa: BLE001 - asserted below
                with result_lock:
                    errors.append(error)

        threads = [Thread(target=worker, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], StaleTargetedReviewRevisionError)
        self.assertEqual(self.session.revision, 1)
        self.assertEqual(
            len(self.session.own_decision_history(actor=self.actor)), 1
        )

    def test_returned_decision_mapping_is_a_detached_read_only_view(self) -> None:
        self.session.record_decision(
            **command_bindings(self.session, expected_revision=0),
            parameter_id="temperature",
            verdict=TargetedVerdict.SAME,
            reason="synthetic targeted recheck",
            command_id="mapping-view",
        )
        view = self.session.own_decisions(actor=self.actor)
        with self.assertRaises(TypeError):
            view["pressure"] = view["temperature"]  # type: ignore[index]
        self.assertEqual(
            self.session.missing_parameter_ids(actor=self.actor),
            ("pressure",),
        )


class TargetedTerminalPathTests(unittest.TestCase):
    def test_locked_submission_rejects_omission_and_forgery_against_trusted_hashes(self) -> None:
        task = build_completed_task(ai_pairs={"temperature": ("1", "2")})
        context = routing_context_from_task(
            task,
            context={"pressure": {"is_critical": True}},
        )
        session = make_session(task, routing_context=context)
        session.record_decision(
            **command_bindings(session, expected_revision=0),
            parameter_id="temperature",
            verdict=TargetedVerdict.SAME,
            reason="independent synthetic recheck observation",
            command_id="submission-decision",
        )
        submission = session.lock(
            **command_bindings(session, expected_revision=1),
            command_id="submission-lock",
        )
        validate_locked_targeted_submission(
            submission,
            expected_source_snapshot_sha256=session.source_snapshot_sha256,
            expected_submission_hash=submission.submission_hash,
        )

        tampered_decision = replace(
            submission.decisions[0], reviewer_id="forged-reviewer"
        )
        forged_values = (
            replace(submission, decisions=()),
            replace(submission, qa_referrals=()),
            replace(submission, no_exception_parameter_ids=()),
            replace(
                submission,
                expected_parameter_ids=("temperature", "pressure"),
            ),
            replace(submission, decisions=(tampered_decision,)),
            replace(submission, routing_context_id="forged-context"),
            replace(submission, submission_hash="0" * 64),
        )
        for forged in forged_values:
            with self.subTest(forged=forged):
                with self.assertRaises(TargetedSubmissionBindingError):
                    validate_locked_targeted_submission(
                        forged,
                        expected_source_snapshot_sha256=(
                            session.source_snapshot_sha256
                        ),
                        expected_submission_hash=submission.submission_hash,
                    )
        with self.assertRaises(TargetedSubmissionBindingError):
            validate_locked_targeted_submission(
                submission,
                expected_source_snapshot_sha256=different_sha256(
                    session.source_snapshot_sha256
                ),
                expected_submission_hash=submission.submission_hash,
            )

    def test_same_recheck_never_closes_exception_or_skips_final_human(self) -> None:
        task = build_completed_task(ai_pairs={"temperature": ("1", "2")})
        session = make_session(task)
        decision = session.record_decision(
            **command_bindings(session, expected_revision=0),
            parameter_id="temperature",
            verdict=TargetedVerdict.SAME,
            reason="synthetic evidence independently rechecked",
            command_id="same-does-not-close",
        )
        submission = session.lock(
            **command_bindings(session, expected_revision=1),
            command_id="same-does-not-close-lock",
        )
        self.assertFalse(decision.closes_exception)
        self.assertFalse(decision.automatic_release_allowed)
        self.assertFalse(submission.requires_qa)
        self.assertTrue(submission.final_human_confirmation_required)
        self.assertFalse(submission.automatic_release_allowed)

    def test_confirmed_difference_or_unable_recheck_requires_qa(self) -> None:
        for verdict in (
            TargetedVerdict.DIFFERENT,
            TargetedVerdict.UNABLE_TO_JUDGE,
        ):
            with self.subTest(verdict=verdict):
                task = build_completed_task(
                    ai_pairs={"temperature": ("1", "2")}
                )
                session = make_session(task)
                session.record_decision(
                    **command_bindings(session, expected_revision=0),
                    parameter_id="temperature",
                    verdict=verdict,
                    reason="synthetic exception remains unresolved",
                    command_id=f"escalate-{verdict.value}",
                )
                submission = session.lock(
                    **command_bindings(session, expected_revision=1),
                    command_id=f"escalate-lock-{verdict.value}",
                )
                self.assertTrue(submission.requires_qa)
                self.assertTrue(
                    submission.final_human_confirmation_required
                )

    def test_lock_also_requires_task_assignment_manifest_snapshot_and_revision(self) -> None:
        task = build_completed_task()
        attempts = (
            ("task_id", "OTHER-TASK", TargetedTaskBindingError),
            (
                "assignment_id",
                "other-assignment",
                TargetedAssignmentBindingError,
            ),
            (
                "evidence_manifest_hash",
                None,
                TargetedEvidenceBindingError,
            ),
            (
                "source_snapshot_sha256",
                "0" * 64,
                TargetedSnapshotBindingError,
            ),
            ("expected_revision", 1, StaleTargetedReviewRevisionError),
        )
        for name, value, error_type in attempts:
            with self.subTest(name=name):
                session = make_session(task)
                values = command_bindings(session, expected_revision=0)
                values[name] = value
                with self.assertRaises(error_type):
                    session.lock(
                        **values,
                        command_id=f"bad-lock-{name}",
                    )
                self.assertEqual(session.state, TargetedReviewState.OPEN)
                self.assertEqual(session.revision, 0)

    def test_zero_exception_path_locks_empty_submission_without_release(self) -> None:
        task = build_completed_task()
        session = make_session(task)
        self.assertEqual(session.queue_plan().targeted_items, ())
        self.assertEqual(session.queue_plan().qa_referrals, ())
        submission = session.lock(
            **command_bindings(session, expected_revision=0),
            command_id="zero-exception-lock",
        )
        self.assertEqual(submission.decisions, ())
        self.assertEqual(
            submission.no_exception_parameter_ids,
            task.expected_parameter_ids,
        )
        self.assertFalse(submission.requires_qa)
        self.assertFalse(submission.automatic_release_allowed)
        self.assertEqual(session.state, TargetedReviewState.LOCKED)

    def test_qa_only_path_retains_referral_and_never_releases(self) -> None:
        task = build_completed_task(
            ai_system_errors=frozenset({"temperature"})
        )
        session = make_session(task)
        submission = session.lock(
            **command_bindings(session, expected_revision=0),
            command_id="qa-only-lock",
        )
        self.assertEqual(submission.decisions, ())
        self.assertEqual(
            tuple(item.parameter_id for item in submission.qa_referrals),
            ("temperature",),
        )
        self.assertTrue(submission.requires_qa)
        self.assertFalse(submission.automatic_release_allowed)


if __name__ == "__main__":
    unittest.main()
