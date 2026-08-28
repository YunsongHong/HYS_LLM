"""Regression and adversarial tests for the strict human-first workflow."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import inspect
from threading import Event, Thread
import unittest

from paramguard.comparison import ComparisonKind
from paramguard.evidence import (
    EvidenceArtifact,
    EvidenceManifest,
    EvidenceRole,
    content_sha256,
)
from paramguard.pipeline import PipelineSpec
from paramguard.workflow import (
    AiResultAccessDenied,
    AiResultIntegrityError,
    AiRunIdentityError,
    AiVerdict,
    DuplicateParameterError,
    EvidenceVersionConflictError,
    HumanVerdict,
    IncompleteReviewError,
    InvalidTransitionError,
    ReasonRequiredError,
    ReviewLockedError,
    ReviewState,
    ReviewTask,
    UnknownParameterError,
    WorkflowMode,
)


class AdvancingClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        result = self.current
        self.current += timedelta(seconds=1)
        return result


def make_manifest(
    expected_parameter_ids: tuple[str, ...] = ("temperature", "pressure"),
) -> EvidenceManifest:
    left = EvidenceArtifact.from_bytes(
        artifact_id="left-a",
        role=EvidenceRole.LEFT_PHOTO,
        content=b"synthetic-left-image",
        media_type="image/png",
    )
    right = EvidenceArtifact.from_bytes(
        artifact_id="right-a-prime",
        role=EvidenceRole.RIGHT_SCREENSHOT,
        content=b"synthetic-right-image",
        media_type="image/png",
    )
    return EvidenceManifest(
        manifest_id="manifest-001",
        schema_id="parameter-schema",
        schema_version="1.0",
        schema_sha256=content_sha256(b"parameter-schema-v1"),
        template_id="pair-template",
        template_version="1.0",
        template_sha256=content_sha256(b"pair-template-v1"),
        expected_parameter_ids=expected_parameter_ids,
        artifacts=(left, right),
    )


def make_pipeline_spec() -> PipelineSpec:
    return PipelineSpec(
        spec_id="approved-synthetic-pipeline",
        engine_name="synthetic-ocr",
        engine_version="1.0",
        pipeline_version="1.0",
        comparator_version="1.0",
        configuration_sha256=content_sha256(b"synthetic-pipeline-config-v1"),
    )


class ReviewTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = AdvancingClock()
        self.manifest = make_manifest()
        self.pipeline = make_pipeline_spec()
        self.task = ReviewTask(
            task_id="TASK-001",
            evidence_manifest=self.manifest,
            approved_pipeline_spec=self.pipeline,
            reviewer_id="reviewer-001",
            clock=self.clock,
        )

    def _record_complete_human_review(self) -> None:
        self.task.record_human_decision(
            parameter_id="temperature",
            verdict=HumanVerdict.SAME,
            evidence_manifest_hash=self.task.evidence_manifest_hash,
        )
        self.task.record_human_decision(
            parameter_id="pressure",
            verdict=HumanVerdict.DIFFERENT,
            evidence_manifest_hash=self.task.evidence_manifest_hash,
            reason="Displayed values differ",
        )

    def _lock_queue_and_start_ai(self) -> None:
        self._record_complete_human_review()
        self.task.lock_human_review(
            evidence_manifest_hash=self.task.evidence_manifest_hash
        )
        self.task.queue_ai_review(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
            pipeline_spec_hash=self.pipeline.spec_hash,
        )
        self.task.start_ai_review(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
        )

    def _record_ai(
        self,
        parameter_id: str,
        left_raw: str | None,
        right_raw: str | None,
        *,
        reliable: bool = True,
        reason: str | None = None,
    ) -> None:
        self.task.record_ai_assessment(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
            parameter_id=parameter_id,
            left_raw=left_raw,
            right_raw=right_raw,
            extraction_reliable=reliable,
            reason=reason,
        )

    def test_task_starts_strict_open_and_bound_to_manifest(self) -> None:
        self.assertEqual(self.task.mode, WorkflowMode.STRICT_SEQUENTIAL)
        self.assertEqual(self.task.state, ReviewState.HUMAN_REVIEW_OPEN)
        self.assertEqual(self.task.evidence_manifest, self.manifest)
        self.assertEqual(self.task.evidence_manifest_hash, self.manifest.manifest_hash)
        self.assertEqual(
            self.task.missing_human_parameter_ids(),
            ("temperature", "pressure"),
        )

    def test_task_requires_real_frozen_manifest(self) -> None:
        with self.assertRaises(TypeError):
            ReviewTask(
                task_id="TASK-002",
                evidence_manifest="manifest-hash-only",  # type: ignore[arg-type]
                approved_pipeline_spec=self.pipeline,
                reviewer_id="reviewer-001",
            )

    def test_unknown_human_parameter_is_rejected(self) -> None:
        with self.assertRaises(UnknownParameterError):
            self.task.record_human_decision(
                parameter_id="not-in-schema",
                verdict=HumanVerdict.SAME,
                evidence_manifest_hash=self.task.evidence_manifest_hash,
            )

    def test_exception_human_verdict_requires_reason(self) -> None:
        for verdict in (HumanVerdict.DIFFERENT, HumanVerdict.UNABLE_TO_JUDGE):
            with self.subTest(verdict=verdict):
                with self.assertRaises(ReasonRequiredError):
                    self.task.record_human_decision(
                        parameter_id="temperature",
                        verdict=verdict,
                        evidence_manifest_hash=self.task.evidence_manifest_hash,
                    )

    def test_human_decision_is_bound_to_frozen_evidence(self) -> None:
        decision = self.task.record_human_decision(
            parameter_id="temperature",
            verdict=HumanVerdict.SAME,
            evidence_manifest_hash=self.task.evidence_manifest_hash,
        )

        self.assertEqual(
            decision.evidence_manifest_hash, self.manifest.manifest_hash
        )

    def test_stale_human_client_cannot_write_or_lock_different_evidence(self) -> None:
        wrong_hash = "0" * 64
        if wrong_hash == self.task.evidence_manifest_hash:  # pragma: no cover
            wrong_hash = "1" * 64

        with self.assertRaises(EvidenceVersionConflictError):
            self.task.record_human_decision(
                parameter_id="temperature",
                verdict=HumanVerdict.SAME,
                evidence_manifest_hash=wrong_hash,
            )
        self.assertEqual(
            self.task.missing_human_parameter_ids(),
            ("temperature", "pressure"),
        )

        self._record_complete_human_review()
        with self.assertRaises(EvidenceVersionConflictError):
            self.task.lock_human_review(evidence_manifest_hash=wrong_hash)
        self.assertEqual(self.task.state, ReviewState.HUMAN_REVIEW_OPEN)
        self.assertIsNone(self.task.human_locked_at)

    def test_human_can_revise_before_lock_but_snapshot_is_read_only(self) -> None:
        first = self.task.record_human_decision(
            parameter_id="temperature",
            verdict=HumanVerdict.SAME,
            evidence_manifest_hash=self.task.evidence_manifest_hash,
        )
        revised = self.task.record_human_decision(
            parameter_id="temperature",
            verdict=HumanVerdict.DIFFERENT,
            evidence_manifest_hash=self.task.evidence_manifest_hash,
            reason="Noticed a missing minus sign",
        )
        snapshot = self.task.human_decisions()

        self.assertNotEqual(first.decided_at, revised.decided_at)
        self.assertEqual(snapshot["temperature"].verdict, HumanVerdict.DIFFERENT)
        with self.assertRaises(TypeError):
            snapshot["pressure"] = revised  # type: ignore[index]

    def test_incomplete_review_cannot_lock_atomically(self) -> None:
        self.task.record_human_decision(
            parameter_id="temperature",
            verdict=HumanVerdict.SAME,
            evidence_manifest_hash=self.task.evidence_manifest_hash,
        )

        with self.assertRaises(IncompleteReviewError) as context:
            self.task.lock_human_review(
                evidence_manifest_hash=self.task.evidence_manifest_hash
            )

        self.assertEqual(context.exception.missing_parameter_ids, ("pressure",))
        self.assertEqual(context.exception.phase, "Human review")
        self.assertEqual(self.task.state, ReviewState.HUMAN_REVIEW_OPEN)
        self.assertIsNone(self.task.human_locked_at)

    def test_large_review_missing_one_of_1001_fields_cannot_lock(self) -> None:
        ids = tuple(f"field-{number:04d}" for number in range(1001))
        task = ReviewTask(
            task_id="TASK-LARGE",
            evidence_manifest=make_manifest(ids),
            approved_pipeline_spec=self.pipeline,
            reviewer_id="reviewer-001",
            clock=self.clock,
        )
        for parameter_id in ids[:-1]:
            task.record_human_decision(
                parameter_id=parameter_id,
                verdict=HumanVerdict.SAME,
                evidence_manifest_hash=task.evidence_manifest_hash,
            )

        with self.assertRaises(IncompleteReviewError) as context:
            task.lock_human_review(
                evidence_manifest_hash=task.evidence_manifest_hash
            )

        self.assertEqual(context.exception.missing_parameter_ids, (ids[-1],))
        self.assertEqual(task.state, ReviewState.HUMAN_REVIEW_OPEN)

    def test_lock_is_timezone_aware_and_prevents_changes_or_relock(self) -> None:
        self._record_complete_human_review()
        locked_at = self.task.lock_human_review(
            evidence_manifest_hash=self.task.evidence_manifest_hash
        )

        self.assertEqual(self.task.state, ReviewState.HUMAN_REVIEW_LOCKED)
        self.assertIsNotNone(locked_at.utcoffset())
        with self.assertRaises(ReviewLockedError):
            self.task.record_human_decision(
                parameter_id="temperature",
                verdict=HumanVerdict.SAME,
                evidence_manifest_hash=self.task.evidence_manifest_hash,
            )
        with self.assertRaises(InvalidTransitionError):
            self.task.lock_human_review(
                evidence_manifest_hash=self.task.evidence_manifest_hash
            )

    def test_ai_cannot_be_queued_started_or_written_before_human_lock(self) -> None:
        with self.assertRaises(InvalidTransitionError):
            self.task.queue_ai_review(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
                pipeline_spec_hash=self.pipeline.spec_hash,
            )
        with self.assertRaises(InvalidTransitionError):
            self.task.start_ai_review(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
            )
        with self.assertRaises(InvalidTransitionError):
            self._record_ai("temperature", "1", "1")

    def test_filled_but_unlocked_human_review_still_cannot_queue_ai(self) -> None:
        self._record_complete_human_review()
        with self.assertRaises(InvalidTransitionError):
            self.task.queue_ai_review(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
                pipeline_spec_hash=self.pipeline.spec_hash,
            )

    def test_wrong_evidence_hash_cannot_queue_start_write_or_complete(self) -> None:
        wrong_hash = "f" * 64
        self._record_complete_human_review()
        self.task.lock_human_review(
            evidence_manifest_hash=self.task.evidence_manifest_hash
        )
        with self.assertRaises(EvidenceVersionConflictError):
            self.task.queue_ai_review(
                run_id="run-001",
                evidence_manifest_hash=wrong_hash,
                pipeline_spec_hash=self.pipeline.spec_hash,
            )
        self.assertEqual(self.task.state, ReviewState.HUMAN_REVIEW_LOCKED)

        self.task.queue_ai_review(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
            pipeline_spec_hash=self.pipeline.spec_hash,
        )
        with self.assertRaises(EvidenceVersionConflictError):
            self.task.start_ai_review(
                run_id="run-001", evidence_manifest_hash=wrong_hash
            )
        self.task.start_ai_review(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
        )
        with self.assertRaises(EvidenceVersionConflictError):
            self.task.record_ai_assessment(
                run_id="run-001",
                evidence_manifest_hash=wrong_hash,
                parameter_id="temperature",
                left_raw="1",
                right_raw="1",
                extraction_reliable=True,
            )
        with self.assertRaises(EvidenceVersionConflictError):
            self.task.complete_ai_review(
                run_id="run-001", evidence_manifest_hash=wrong_hash
            )

    def test_unapproved_pipeline_spec_cannot_be_queued(self) -> None:
        self._record_complete_human_review()
        self.task.lock_human_review(
            evidence_manifest_hash=self.task.evidence_manifest_hash
        )
        wrong_spec_hash = "0" * 64
        if wrong_spec_hash == self.pipeline.spec_hash:  # pragma: no cover
            wrong_spec_hash = "1" * 64

        with self.assertRaises(EvidenceVersionConflictError):
            self.task.queue_ai_review(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
                pipeline_spec_hash=wrong_spec_hash,
            )
        self.assertEqual(self.task.state, ReviewState.HUMAN_REVIEW_LOCKED)
        self.assertIsNone(self.task._ai_run)

    def test_wrong_run_id_is_rejected(self) -> None:
        self._lock_queue_and_start_ai()
        with self.assertRaises(AiRunIdentityError):
            self.task.record_ai_assessment(
                run_id="run-other",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
                parameter_id="temperature",
                left_raw="1",
                right_raw="1",
                extraction_reliable=True,
            )

    def test_execution_authorization_checks_run_evidence_and_pipeline(self) -> None:
        self._lock_queue_and_start_ai()
        self.task.assert_ai_execution_authorized(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
            pipeline_spec_hash=self.pipeline.spec_hash,
        )
        with self.assertRaises(AiRunIdentityError):
            self.task.assert_ai_execution_authorized(
                run_id="run-other",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
                pipeline_spec_hash=self.pipeline.spec_hash,
            )
        with self.assertRaises(EvidenceVersionConflictError):
            self.task.assert_ai_execution_authorized(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
                pipeline_spec_hash="f" * 64,
            )

    def test_ai_run_and_partial_results_are_not_revealed(self) -> None:
        with self.assertRaises(AiResultAccessDenied):
            self.task.revealed_ai_results()
        with self.assertRaises(AiResultAccessDenied):
            self.task.revealed_ai_run()

        self._lock_queue_and_start_ai()
        self._record_ai("temperature", "37.0 °C", "37.0 °C")
        with self.assertRaises(AiResultAccessDenied):
            self.task.revealed_ai_results()
        with self.assertRaises(AiResultAccessDenied):
            self.task.revealed_ai_run()

    def test_caller_cannot_freely_submit_ai_verdict(self) -> None:
        parameters = inspect.signature(
            ReviewTask.record_ai_assessment
        ).parameters
        self.assertNotIn("verdict", parameters)

    def test_ai_same_is_derived_only_from_reliable_exact_raw_strings(self) -> None:
        self._lock_queue_and_start_ai()
        self._record_ai("temperature", "37.0 °C", "37.0 °C")
        self._record_ai("pressure", "1.0 bar", "1.00 bar")
        self.task.complete_ai_review(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
        )

        results = self.task.revealed_ai_results()
        self.assertEqual(results["temperature"].verdict, AiVerdict.SAME)
        self.assertTrue(results["temperature"].comparison_result.exact_match)  # type: ignore[union-attr]
        self.assertEqual(results["pressure"].verdict, AiVerdict.DIFFERENT)
        self.assertEqual(
            results["pressure"].comparison_result.kind,  # type: ignore[union-attr]
            ComparisonKind.FORMAT_DIFFERENCE,
        )

    def test_unreliable_or_missing_extraction_requires_reason_and_abstains(self) -> None:
        self._lock_queue_and_start_ai()
        with self.assertRaises(ReasonRequiredError):
            self._record_ai(
                "temperature", "37.0 °C", "37.0 °C", reliable=False
            )
        with self.assertRaises(ReasonRequiredError):
            self._record_ai("temperature", None, "37.0 °C")

        self._record_ai(
            "temperature",
            "37.0 °C",
            "37.0 °C",
            reliable=False,
            reason="Image is blurred",
        )
        self._record_ai(
            "pressure",
            None,
            "1.0 bar",
            reason="Left field could not be located",
        )
        self.task.complete_ai_review(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
        )

        results = self.task.revealed_ai_results()
        self.assertEqual(results["temperature"].verdict, AiVerdict.UNABLE_TO_JUDGE)
        self.assertEqual(results["pressure"].verdict, AiVerdict.UNABLE_TO_JUDGE)

    def test_system_error_is_distinct_and_never_a_match(self) -> None:
        self._lock_queue_and_start_ai()
        self.task.record_ai_system_error(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
            parameter_id="temperature",
            reason="OCR process timed out",
        )
        self._record_ai("pressure", "1.0 bar", "1.0 bar")
        self.task.complete_ai_review(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
        )

        result = self.task.revealed_ai_results()["temperature"]
        self.assertEqual(result.verdict, AiVerdict.SYSTEM_ERROR)
        self.assertIsNone(result.comparison_result)

    def test_duplicate_unknown_and_incomplete_ai_results_are_rejected(self) -> None:
        self._lock_queue_and_start_ai()
        self._record_ai("temperature", "1", "1")
        with self.assertRaises(DuplicateParameterError):
            self._record_ai("temperature", "1", "2")
        with self.assertRaises(UnknownParameterError):
            self._record_ai("unknown", "1", "1")
        with self.assertRaises(IncompleteReviewError) as context:
            self.task.complete_ai_review(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
            )
        self.assertEqual(context.exception.missing_parameter_ids, ("pressure",))
        self.assertEqual(self.task.state, ReviewState.AI_REVIEW_RUNNING)

    def test_complete_ai_results_and_run_metadata_are_read_only(self) -> None:
        self._lock_queue_and_start_ai()
        self._record_ai("temperature", "37.0 °C", "37.0 °C")
        self._record_ai("pressure", "1.0 bar", "1.1 bar")
        self.task.complete_ai_review(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
        )

        results = self.task.revealed_ai_results()
        run = self.task.revealed_ai_run()
        self.assertEqual(run.run_id, "run-001")
        self.assertEqual(run.evidence_manifest_hash, self.manifest.manifest_hash)
        self.assertIsNotNone(run.started_at)
        with self.assertRaises(TypeError):
            results["extra"] = results["pressure"]  # type: ignore[index]

    def test_forged_persisted_ai_verdict_cannot_pass_completion_gate(self) -> None:
        self._lock_queue_and_start_ai()
        self._record_ai("temperature", "1.0", "1.00")
        self._record_ai("pressure", "1", "1")
        original = self.task._ai_results["temperature"]
        self.task._ai_results["temperature"] = replace(
            original,
            verdict=AiVerdict.SAME,
            engine_version="forged-version",
            parameter_id="pressure",
        )

        with self.assertRaises(AiResultIntegrityError):
            self.task.complete_ai_review(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
            )
        self.assertEqual(self.task.state, ReviewState.AI_REVIEW_RUNNING)

    def test_forged_comparison_payload_cannot_pass_completion_gate(self) -> None:
        self._lock_queue_and_start_ai()
        self._record_ai("temperature", "1.0", "1.00")
        self._record_ai("pressure", "1", "1")
        exact = self.task._ai_results["pressure"].comparison_result
        original = self.task._ai_results["temperature"]
        self.task._ai_results["temperature"] = replace(
            original, comparison_result=exact
        )

        with self.assertRaisesRegex(
            AiResultIntegrityError, "Stored comparison differs"
        ):
            self.task.complete_ai_review(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
            )

    def test_forged_run_and_all_result_versions_still_fail_approved_spec(self) -> None:
        self._lock_queue_and_start_ai()
        self._record_ai("temperature", "1", "1")
        self._record_ai("pressure", "2", "2")
        original_run = self.task._ai_run
        assert original_run is not None
        forged_hash = "f" * 64
        forged_run = replace(
            original_run,
            engine_name="forged-engine",
            engine_version="forged-version",
            pipeline_version="forged-pipeline",
            comparator_version="forged-comparator",
            pipeline_spec_hash=forged_hash,
        )
        self.task._ai_run = forged_run
        for parameter_id, result in tuple(self.task._ai_results.items()):
            self.task._ai_results[parameter_id] = replace(
                result,
                engine_name=forged_run.engine_name,
                engine_version=forged_run.engine_version,
                pipeline_version=forged_run.pipeline_version,
                comparator_version=forged_run.comparator_version,
                pipeline_spec_hash=forged_hash,
            )

        with self.assertRaises(AiResultIntegrityError):
            self.task.complete_ai_review(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
            )
        self.assertEqual(self.task.state, ReviewState.AI_REVIEW_RUNNING)

    def test_forged_manifest_binding_on_run_and_results_is_rejected(self) -> None:
        self._lock_queue_and_start_ai()
        self._record_ai("temperature", "1", "1")
        self._record_ai("pressure", "2", "2")
        original_run = self.task._ai_run
        assert original_run is not None
        forged_hash = "f" * 64
        self.task._ai_run = replace(
            original_run, evidence_manifest_hash=forged_hash
        )
        for parameter_id, result in tuple(self.task._ai_results.items()):
            self.task._ai_results[parameter_id] = replace(
                result, evidence_manifest_hash=forged_hash
            )

        with self.assertRaises(AiResultIntegrityError):
            self.task.complete_ai_review(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
            )

    def test_forged_ai_scalar_types_are_rejected_at_completion(self) -> None:
        self._lock_queue_and_start_ai()
        self._record_ai("temperature", "1", "1")
        self._record_ai("pressure", "2", "2")
        original = self.task._ai_results["temperature"]

        self.task._ai_results["temperature"] = replace(
            original, extraction_reliable=1  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(AiResultIntegrityError, "strict boolean"):
            self.task.complete_ai_review(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
            )

        self.task._ai_results["temperature"] = replace(
            original, reason=123  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(AiResultIntegrityError, "reason"):
            self.task.complete_ai_review(
                run_id="run-001",
                evidence_manifest_hash=self.task.evidence_manifest_hash,
            )

    def test_naive_clock_is_rejected_before_state_change(self) -> None:
        task = ReviewTask(
            task_id="TASK-003",
            evidence_manifest=make_manifest(("pH",)),
            approved_pipeline_spec=self.pipeline,
            reviewer_id="reviewer-001",
            clock=lambda: datetime(2026, 8, 25, 10, 0),
        )
        with self.assertRaises(ValueError):
            task.record_human_decision(
                parameter_id="pH",
                verdict=HumanVerdict.SAME,
                evidence_manifest_hash=task.evidence_manifest_hash,
            )
        self.assertEqual(task.missing_human_parameter_ids(), ("pH",))

    def test_task_and_reviewer_ids_are_read_only(self) -> None:
        with self.assertRaises(AttributeError):
            self.task.task_id = "CHANGED"  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            self.task.reviewer_id = "reviewer-evil"  # type: ignore[misc]

    def test_concurrent_human_write_is_serialised_with_lock(self) -> None:
        self._record_complete_human_review()
        writer_entered_clock = Event()
        release_writer = Event()
        original_clock = self.task._clock

        def blocking_clock() -> datetime:
            writer_entered_clock.set()
            if not release_writer.wait(timeout=2):
                raise TimeoutError("test did not release writer")
            return original_clock()

        self.task._clock = blocking_clock
        writer_errors: list[Exception] = []
        lock_errors: list[Exception] = []
        lock_finished = Event()

        def revise() -> None:
            try:
                self.task.record_human_decision(
                    parameter_id="temperature",
                    verdict=HumanVerdict.DIFFERENT,
                    evidence_manifest_hash=self.task.evidence_manifest_hash,
                    reason="Concurrent revision",
                )
            except Exception as error:  # pragma: no cover
                writer_errors.append(error)

        def lock_review() -> None:
            try:
                self.task.lock_human_review(
                    evidence_manifest_hash=self.task.evidence_manifest_hash
                )
            except Exception as error:  # pragma: no cover
                lock_errors.append(error)
            finally:
                lock_finished.set()

        writer = Thread(target=revise)
        locker = Thread(target=lock_review)
        writer.start()
        self.assertTrue(writer_entered_clock.wait(timeout=2))
        locker.start()
        self.assertFalse(lock_finished.wait(timeout=0.05))
        release_writer.set()
        writer.join(timeout=2)
        locker.join(timeout=2)

        self.assertEqual(writer_errors, [])
        self.assertEqual(lock_errors, [])
        self.assertEqual(self.task.state, ReviewState.HUMAN_REVIEW_LOCKED)
        self.assertEqual(
            self.task.human_decisions()["temperature"].verdict,
            HumanVerdict.DIFFERENT,
        )

    def test_concurrent_duplicate_ai_write_cannot_overwrite_result(self) -> None:
        self._lock_queue_and_start_ai()
        writer_entered_clock = Event()
        release_writer = Event()
        original_clock = self.task._clock

        def blocking_clock() -> datetime:
            writer_entered_clock.set()
            if not release_writer.wait(timeout=2):
                raise TimeoutError("test did not release writer")
            return original_clock()

        self.task._clock = blocking_clock
        first_errors: list[Exception] = []
        duplicate_errors: list[Exception] = []

        def write(left: str, errors: list[Exception]) -> None:
            try:
                self._record_ai("temperature", left, left)
            except Exception as error:
                errors.append(error)

        first = Thread(target=write, args=("first", first_errors))
        duplicate = Thread(target=write, args=("duplicate", duplicate_errors))
        first.start()
        self.assertTrue(writer_entered_clock.wait(timeout=2))
        duplicate.start()
        release_writer.set()
        first.join(timeout=2)
        duplicate.join(timeout=2)

        self.assertEqual(first_errors, [])
        self.assertEqual(len(duplicate_errors), 1)
        self.assertIsInstance(duplicate_errors[0], DuplicateParameterError)
        self._record_ai("pressure", "1", "1")
        self.task.complete_ai_review(
            run_id="run-001",
            evidence_manifest_hash=self.task.evidence_manifest_hash,
        )
        self.assertEqual(
            self.task.revealed_ai_results()["temperature"].left_raw, "first"
        )


if __name__ == "__main__":
    unittest.main()
