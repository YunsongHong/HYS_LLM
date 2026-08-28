"""Integrity, policy, identity, and concurrency tests for the audit log."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from threading import Event, Lock, Thread
import tempfile
import unittest

import paramguard.audit as audit_module
from paramguard.audit import (
    AuditAction,
    AuditIntegrityError,
    AuditPolicyError,
    DuplicateAuditEventError,
    EvidenceContext,
    FinalAuditWriteRequest,
    JsonlAuditLog,
    UnknownCorrectedEventError,
    verify_audit_chain,
)


LEFT_HASH = "a" * 64
RIGHT_HASH = "b" * 64
MANIFEST_HASH = "c" * 64
SCHEMA_HASH = "d" * 64
TEMPLATE_HASH = "e" * 64
PIPELINE_HASH = "f" * 64
SECOND_SUBMISSION_HASH = "1" * 64
RESOLUTION_HASH = "2" * 64


class AdvancingClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
        self._lock = Lock()

    def __call__(self) -> datetime:
        with self._lock:
            result = self.current
            self.current += timedelta(seconds=1)
            return result


class CountingIds:
    def __init__(self) -> None:
        self.number = 0
        self._lock = Lock()

    def __call__(self) -> str:
        with self._lock:
            self.number += 1
            return f"event-{self.number:04d}"


def base_context(**changes: object) -> EvidenceContext:
    values: dict[str, object] = {
        "manifest_hash": MANIFEST_HASH,
        "source_artifact_sha256_by_role": (
            ("LEFT_PHOTO", LEFT_HASH),
            ("RIGHT_SCREENSHOT", RIGHT_HASH),
        ),
        "schema_id": "synthetic-schema",
        "schema_version": "1.0",
        "schema_sha256": SCHEMA_HASH,
        "template_id": "synthetic-template",
        "template_version": "1.0",
        "template_sha256": TEMPLATE_HASH,
    }
    values.update(changes)
    return EvidenceContext(**values)  # type: ignore[arg-type]


def ai_context(**changes: object) -> EvidenceContext:
    values: dict[str, object] = {
        "run_id": "run-001",
        "pipeline_spec_hash": PIPELINE_HASH,
        "pipeline_version": "pipeline-1.0",
        "comparator_version": "comparator-1.0",
        "ocr_engine": "synthetic-ocr",
        "ocr_version": "ocr-1.0",
    }
    values.update(changes)
    return base_context(**values)


def same_assessment_details() -> dict[str, object]:
    return {
        "verdict": "SAME",
        "left_raw": "37.0 °C",
        "right_raw": "37.0 °C",
        "extraction_reliable": True,
        "comparison_kind": "EXACT_MATCH",
        "exact_match": True,
    }


class JsonlAuditLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.path = Path(self.temp_directory.name) / "audit.jsonl"
        self.clock = AdvancingClock()
        self.ids = CountingIds()
        self.log = JsonlAuditLog(
            self.path, clock=self.clock, event_id_factory=self.ids
        )
        self.context = base_context()
        self.ai_context = ai_context()

    def _create_task(
        self,
        *,
        log: JsonlAuditLog | None = None,
        task_id: str = "TASK-001",
        expected_parameter_ids: tuple[str, ...] = ("temperature",),
        reviewer_id: str = "reviewer-001",
        context: EvidenceContext | None = None,
    ):
        target = self.log if log is None else log
        return target.append(
            task_id=task_id,
            actor_id="service:workflow:orchestrator",
            action=AuditAction.TASK_CREATED,
            details={
                "expected_parameter_ids": list(expected_parameter_ids),
                "reviewer_id": reviewer_id,
            },
            evidence_context=self.context if context is None else context,
        )

    def _append_human_event(
        self,
        *,
        parameter_id: str = "temperature",
        verdict: str = "SAME",
        reason: str | None = None,
    ):
        return self.log.append(
            task_id="TASK-001",
            parameter_id=parameter_id,
            actor_id="reviewer-001",
            action=AuditAction.HUMAN_DECISION_RECORDED,
            details={"verdict": verdict},
            reason=reason,
            evidence_context=self.context,
        )

    def _lock_human_review(self) -> None:
        self.log.append(
            task_id="TASK-001",
            actor_id="reviewer-001",
            action=AuditAction.HUMAN_REVIEW_LOCKED,
            details={"decision_count": 1},
            evidence_context=self.context,
        )

    def _prepare_ai_run(self) -> None:
        self._create_task()
        self._append_human_event()
        self._lock_human_review()
        self.log.append(
            task_id="TASK-001",
            actor_id="service:ai:worker",
            action=AuditAction.AI_REVIEW_STARTED,
            details={},
            evidence_context=self.ai_context,
        )

    def _append_ai_same(self, *, parameter_id: str = "temperature"):
        return self.log.append(
            task_id="TASK-001",
            parameter_id=parameter_id,
            actor_id="service:ai:worker",
            action=AuditAction.AI_ASSESSMENT_RECORDED,
            details=same_assessment_details(),
            evidence_context=self.ai_context,
        )

    def _complete_ai(self) -> None:
        self.log.append(
            task_id="TASK-001",
            actor_id="service:ai:worker",
            action=AuditAction.AI_REVIEW_COMPLETED,
            details={"assessment_count": 1},
            evidence_context=self.ai_context,
        )

    def _prepare_two_field_routing(
        self,
        *,
        first_route: str = "INDEPENDENT_SECOND_REVIEW_REQUIRED",
        first_reasons: tuple[str, ...] = ("CRITICAL_PARAMETER",),
        second_route: str = "NO_EXCEPTION_DETECTED",
        second_reasons: tuple[str, ...] = (),
    ) -> None:
        parameter_ids = ("temperature", "pressure")
        self._create_task(expected_parameter_ids=parameter_ids)
        for parameter_id in parameter_ids:
            self._append_human_event(parameter_id=parameter_id)
        self.log.append(
            task_id="TASK-001",
            actor_id="reviewer-001",
            action=AuditAction.HUMAN_REVIEW_LOCKED,
            details={"decision_count": 2},
            evidence_context=self.context,
        )
        self.log.append(
            task_id="TASK-001",
            actor_id="service:ai:worker",
            action=AuditAction.AI_REVIEW_STARTED,
            details={},
            evidence_context=self.ai_context,
        )
        for parameter_id in parameter_ids:
            self._append_ai_same(parameter_id=parameter_id)
        self.log.append(
            task_id="TASK-001",
            actor_id="service:ai:worker",
            action=AuditAction.AI_REVIEW_COMPLETED,
            details={"assessment_count": 2},
            evidence_context=self.ai_context,
        )
        for parameter_id, route, reasons in (
            ("temperature", first_route, first_reasons),
            ("pressure", second_route, second_reasons),
        ):
            self.log.append(
                task_id="TASK-001",
                parameter_id=parameter_id,
                actor_id="service:rules:router",
                action=AuditAction.ROUTE_ASSIGNED,
                details={"route": route, "reasons": list(reasons)},
                evidence_context=self.ai_context,
            )

    def _assign_second_reviewer(self) -> None:
        self.log.append(
            task_id="TASK-001",
            actor_id="service:workflow:orchestrator",
            action=AuditAction.SECOND_REVIEW_ASSIGNED,
            details={
                "blind_case_id": "blind-001",
                "assigned_reviewer_id": "reviewer-002",
            },
            evidence_context=self.ai_context,
        )

    def _record_second_decision(
        self,
        parameter_id: str,
        *,
        verdict: str = "SAME",
        reason: str | None = None,
        action: AuditAction = AuditAction.SECOND_REVIEW_DECISION_RECORDED,
    ):
        return self.log.append(
            task_id="TASK-001",
            parameter_id=parameter_id,
            actor_id="reviewer-002",
            action=action,
            details={"blind_case_id": "blind-001", "verdict": verdict},
            reason=reason,
            evidence_context=self.ai_context,
        )

    def _lock_second_review(self):
        return self.log.append(
            task_id="TASK-001",
            actor_id="reviewer-002",
            action=AuditAction.SECOND_REVIEW_LOCKED,
            details={
                "blind_case_id": "blind-001",
                "decision_count": 2,
                "second_submission_hash": SECOND_SUBMISSION_HASH,
            },
            evidence_context=self.ai_context,
        )

    def _prepare_locked_second_review(self) -> None:
        self._prepare_two_field_routing()
        self._assign_second_reviewer()
        self._record_second_decision("temperature")
        self._record_second_decision("pressure")
        self._lock_second_review()

    @staticmethod
    def _exception_record(
        parameter_id: str,
        reason_code: str,
        *,
        source: str = "ROUTING",
    ) -> dict[str, str]:
        return audit_module._make_exception_record(
            task_id="TASK-001",
            parameter_id=parameter_id,
            source=source,
            reason_code=reason_code,
        )

    def _open_single_exception_qa(
        self,
        *,
        second_submission_hash: str | None = SECOND_SUBMISSION_HASH,
    ) -> str:
        exception = self._exception_record("temperature", "CRITICAL_PARAMETER")
        self.log.append(
            task_id="TASK-001",
            actor_id="service:workflow:orchestrator",
            action=AuditAction.QA_CASE_OPENED,
            details={
                "exceptions": [exception],
                "second_submission_hash": second_submission_hash,
            },
            evidence_context=self.ai_context,
        )
        return exception["exception_id"]

    def _record_qa_disposition(
        self,
        exception_id: str,
        *,
        outcome: str = "RESOLVED_NO_BLOCKING_EXCEPTION",
    ) -> None:
        self.log.append(
            task_id="TASK-001",
            actor_id="qa-reviewer-001",
            action=AuditAction.QA_DISPOSITION_RECORDED,
            details={
                "exception_id": exception_id,
                "outcome": outcome,
                "rationale": "Reviewed against the frozen source evidence",
                "reference_ids": ["qa-note-001"],
            },
            evidence_context=self.ai_context,
        )

    def _complete_qa(self, *, result_state: str) -> None:
        self.log.append(
            task_id="TASK-001",
            actor_id="qa-reviewer-001",
            action=AuditAction.QA_DISPOSITION_COMPLETED,
            details={
                "disposition_count": 1,
                "result_state": result_state,
                "resolution_digest": RESOLUTION_HASH,
            },
            evidence_context=self.ai_context,
        )

    def _append_final(
        self,
        action: AuditAction,
        *,
        actor_id: str = "final-approver-001",
        second_submission_hash: str | None = SECOND_SUBMISSION_HASH,
        resolution_digest: str = RESOLUTION_HASH,
        predecessor: str | None = None,
    ):
        if predecessor is None:
            predecessor = self.log.events()[-1].event_hash
        events = self.log.events(task_id="TASK-001")
        created = next(
            event for event in events if event.action is AuditAction.TASK_CREATED
        )
        qa_open = next(
            (
                event
                for event in events
                if event.action is AuditAction.QA_CASE_OPENED
            ),
            None,
        )
        exception_ids = (
            ()
            if qa_open is None
            else tuple(
                sorted(
                    item["exception_id"]
                    for item in qa_open.details["exceptions"]
                )
            )
        )
        disposition_ids = tuple(
            sorted(
                event.details["exception_id"]
                for event in events
                if event.action is AuditAction.QA_DISPOSITION_RECORDED
            )
        )
        required_actions = [
            AuditAction.TASK_CREATED,
            AuditAction.HUMAN_DECISION_RECORDED,
            AuditAction.HUMAN_REVIEW_LOCKED,
            AuditAction.AI_REVIEW_STARTED,
            AuditAction.AI_ASSESSMENT_RECORDED,
            AuditAction.AI_REVIEW_COMPLETED,
            AuditAction.ROUTE_ASSIGNED,
        ]
        if second_submission_hash is not None:
            required_actions.extend(
                (
                    AuditAction.SECOND_REVIEW_ASSIGNED,
                    AuditAction.SECOND_REVIEW_DECISION_RECORDED,
                    AuditAction.SECOND_REVIEW_LOCKED,
                )
            )
        if exception_ids:
            required_actions.extend(
                (
                    AuditAction.QA_CASE_OPENED,
                    AuditAction.QA_DISPOSITION_RECORDED,
                    AuditAction.QA_DISPOSITION_COMPLETED,
                )
            )
        adjudication_version = (
            1
            + (1 if second_submission_hash is not None else 0)
            + len(disposition_ids)
            + (1 if disposition_ids else 0)
        )
        command_id = f"commit-{action.value.lower()}-{actor_id}"
        commit_record = {
            "task_id": "TASK-001",
            "decision": (
                "APPROVED"
                if action is AuditAction.FINAL_APPROVAL_RECORDED
                else "REJECTED"
            ),
            "actor_id": actor_id,
            "rationale": "Final human assessment of the complete record",
            "evidence_manifest_hash": MANIFEST_HASH,
            "second_submission_hash": second_submission_hash,
            "primary_reviewer_id": created.details["reviewer_id"],
            "ai_run_id": "run-001",
            "expected_parameter_ids": created.details["expected_parameter_ids"],
            "exception_ids": list(exception_ids),
            "qa_disposition_exception_ids": list(disposition_ids),
            "resolution_digest": resolution_digest,
            "expected_adjudication_version": adjudication_version,
            "expected_previous_head_hash": predecessor,
            "required_prior_actions": [item.value for item in required_actions],
            "command_id": command_id,
        }
        request_hash = audit_module.calculate_final_commit_request_hash(
            commit_record
        )
        return self.log.commit_final_cas(
            FinalAuditWriteRequest(
                task_id="TASK-001",
                action=action,
                actor_id=actor_id,
                rationale=commit_record["rationale"],
                evidence_manifest_hash=MANIFEST_HASH,
                second_submission_hash=second_submission_hash,
                primary_reviewer_id=created.details["reviewer_id"],
                ai_run_id="run-001",
                expected_parameter_ids=tuple(
                    created.details["expected_parameter_ids"]
                ),
                exception_ids=exception_ids,
                qa_disposition_exception_ids=disposition_ids,
                resolution_digest=resolution_digest,
                expected_adjudication_version=adjudication_version,
                expected_previous_head_hash=predecessor,
                required_prior_actions=tuple(required_actions),
                command_id=command_id,
                commit_request_hash=request_hash,
            )
        )

    def test_append_persists_and_restart_continues_hash_chain(self) -> None:
        created = self._create_task()
        human = self._append_human_event()
        restarted = JsonlAuditLog(
            self.path, clock=self.clock, event_id_factory=self.ids
        )
        locked = restarted.append(
            task_id="TASK-001",
            actor_id="reviewer-001",
            action=AuditAction.HUMAN_REVIEW_LOCKED,
            details={"decision_count": 1},
            evidence_context=self.context,
        )

        events = restarted.events()
        self.assertEqual([event.sequence for event in events], [1, 2, 3])
        self.assertEqual(human.previous_hash, created.event_hash)
        self.assertEqual(locked.previous_hash, human.event_hash)
        restarted.verify()

    def test_generic_note_preserves_extensible_details_without_advancing_workflow(self) -> None:
        details = {"nested": {"value": "original"}, "future_field": [1, 2]}
        event = self.log.append(
            task_id="TASK-001",
            actor_id="observer-001",
            action=AuditAction.GENERIC_NOTE_RECORDED,
            details=details,
        )
        details["nested"]["value"] = "changed"  # type: ignore[index]
        first_read = event.details
        first_read["nested"]["value"] = "also changed"

        self.assertEqual(event.details["nested"]["value"], "original")
        with self.assertRaises(AuditPolicyError):
            self._append_human_event()

    def test_controlled_event_requires_frozen_manifest_context(self) -> None:
        with self.assertRaisesRegex(AuditPolicyError, "frozen evidence"):
            self.log.append(
                task_id="TASK-001",
                actor_id="service:workflow:orchestrator",
                action=AuditAction.TASK_CREATED,
                details={
                    "expected_parameter_ids": ["temperature"],
                    "reviewer_id": "reviewer-001",
                },
            )

    def test_ai_event_preserves_complete_evidence_run_and_pipeline_binding(self) -> None:
        self._prepare_ai_run()
        event = self._append_ai_same()

        context = event.evidence_context
        assert context is not None
        self.assertEqual(context["manifest_hash"], MANIFEST_HASH)
        self.assertEqual(context["run_id"], "run-001")
        self.assertEqual(context["pipeline_spec_hash"], PIPELINE_HASH)
        self.assertEqual(
            context["source_artifact_sha256_by_role"],
            {"LEFT_PHOTO": LEFT_HASH, "RIGHT_SCREENSHOT": RIGHT_HASH},
        )

    def test_incomplete_artifact_role_binding_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one"):
            base_context(
                source_artifact_sha256_by_role=(("LEFT_PHOTO", LEFT_HASH),)
            )
        with self.assertRaisesRegex(ValueError, "canonical order"):
            base_context(
                source_artifact_sha256_by_role=(
                    ("RIGHT_SCREENSHOT", RIGHT_HASH),
                    ("LEFT_PHOTO", LEFT_HASH),
                )
            )

    def test_ai_event_requires_fixed_run_pipeline_comparator_and_engine_identity(self) -> None:
        self._create_task()
        self._append_human_event()
        self._lock_human_review()
        incomplete_contexts = (
            replace(self.ai_context, run_id=None),
            replace(self.ai_context, pipeline_spec_hash=None),
            replace(self.ai_context, pipeline_version=None),
            replace(self.ai_context, comparator_version=None),
            replace(self.ai_context, ocr_engine=None, ocr_version=None),
        )
        for context in incomplete_contexts:
            with self.subTest(context=context):
                with self.assertRaises(AuditPolicyError):
                    self.log.append(
                        task_id="TASK-001",
                        actor_id="service:ai:worker",
                        action=AuditAction.AI_REVIEW_STARTED,
                        details={},
                        evidence_context=context,
                    )

    def test_ai_action_requires_ai_service_actor(self) -> None:
        self._create_task()
        self._append_human_event()
        self._lock_human_review()
        with self.assertRaisesRegex(AuditPolicyError, "AI-service"):
            self.log.append(
                task_id="TASK-001",
                actor_id="reviewer-001",
                action=AuditAction.AI_REVIEW_STARTED,
                details={},
                evidence_context=self.ai_context,
            )

    def test_ai_service_cannot_write_human_decision(self) -> None:
        self._create_task()
        with self.assertRaisesRegex(AuditPolicyError, "human actor"):
            self.log.append(
                task_id="TASK-001",
                parameter_id="temperature",
                actor_id="service:ai:worker",
                action=AuditAction.HUMAN_DECISION_RECORDED,
                details={"verdict": "SAME"},
                evidence_context=self.context,
            )

    def test_only_assigned_reviewer_can_write_or_lock_first_review(self) -> None:
        self._create_task()
        with self.assertRaisesRegex(AuditPolicyError, "assigned first reviewer"):
            self.log.append(
                task_id="TASK-001",
                parameter_id="temperature",
                actor_id="reviewer-evil",
                action=AuditAction.HUMAN_DECISION_RECORDED,
                details={"verdict": "SAME"},
                evidence_context=self.context,
            )

    def test_human_lock_requires_exact_frozen_field_set(self) -> None:
        self._create_task(expected_parameter_ids=("temperature", "pressure"))
        self._append_human_event()
        with self.assertRaisesRegex(AuditPolicyError, "missing=pressure"):
            self.log.append(
                task_id="TASK-001",
                actor_id="reviewer-001",
                action=AuditAction.HUMAN_REVIEW_LOCKED,
                details={"decision_count": 1},
                evidence_context=self.context,
            )

    def test_ai_cannot_start_before_human_lock(self) -> None:
        self._create_task()
        self._append_human_event()
        with self.assertRaisesRegex(AuditPolicyError, "before human lock"):
            self.log.append(
                task_id="TASK-001",
                actor_id="service:ai:worker",
                action=AuditAction.AI_REVIEW_STARTED,
                details={},
                evidence_context=self.ai_context,
            )

    def test_free_or_inconsistent_ai_verdict_is_rejected(self) -> None:
        self._prepare_ai_run()
        forged = same_assessment_details()
        forged["verdict"] = "TOTALLY_MADE_UP"
        with self.assertRaisesRegex(AuditPolicyError, "allowed fixed value"):
            self.log.append(
                task_id="TASK-001",
                parameter_id="temperature",
                actor_id="service:ai:worker",
                action=AuditAction.AI_ASSESSMENT_RECORDED,
                details=forged,
                evidence_context=self.ai_context,
            )

        forged = same_assessment_details()
        forged["verdict"] = "DIFFERENT"
        with self.assertRaisesRegex(AuditPolicyError, "differs"):
            self.log.append(
                task_id="TASK-001",
                parameter_id="temperature",
                actor_id="service:ai:worker",
                action=AuditAction.AI_ASSESSMENT_RECORDED,
                details=forged,
                reason="forged",
                evidence_context=self.ai_context,
            )

    def test_ai_assessment_schema_is_exact_and_parameter_is_required(self) -> None:
        self._prepare_ai_run()
        details = same_assessment_details()
        details["uncontrolled"] = True
        with self.assertRaisesRegex(AuditPolicyError, "fixed schema"):
            self.log.append(
                task_id="TASK-001",
                parameter_id="temperature",
                actor_id="service:ai:worker",
                action=AuditAction.AI_ASSESSMENT_RECORDED,
                details=details,
                evidence_context=self.ai_context,
            )
        with self.assertRaisesRegex(AuditPolicyError, "requires parameter_id"):
            self.log.append(
                task_id="TASK-001",
                actor_id="service:ai:worker",
                action=AuditAction.AI_ASSESSMENT_RECORDED,
                details=same_assessment_details(),
                evidence_context=self.ai_context,
            )

    def test_missing_or_unreliable_ai_values_must_abstain_with_reason(self) -> None:
        self._prepare_ai_run()
        details = {
            "verdict": "UNABLE_TO_JUDGE",
            "left_raw": None,
            "right_raw": "37.0 °C",
            "extraction_reliable": True,
            "comparison_kind": "MISSING_VALUE",
            "exact_match": False,
        }
        with self.assertRaisesRegex(AuditPolicyError, "requires a reason"):
            self.log.append(
                task_id="TASK-001",
                parameter_id="temperature",
                actor_id="service:ai:worker",
                action=AuditAction.AI_ASSESSMENT_RECORDED,
                details=details,
                evidence_context=self.ai_context,
            )
        event = self.log.append(
            task_id="TASK-001",
            parameter_id="temperature",
            actor_id="service:ai:worker",
            action=AuditAction.AI_ASSESSMENT_RECORDED,
            details=details,
            reason="Left value was not extracted",
            evidence_context=self.ai_context,
        )
        self.assertEqual(event.details["verdict"], "UNABLE_TO_JUDGE")

    def test_wrong_manifest_run_or_pipeline_cannot_join_task(self) -> None:
        self._prepare_ai_run()
        changed_contexts = (
            replace(self.ai_context, manifest_hash="0" * 64),
            replace(self.ai_context, run_id="run-other"),
            replace(self.ai_context, pipeline_spec_hash="1" * 64),
            replace(self.ai_context, comparator_version="other"),
        )
        for context in changed_contexts:
            with self.subTest(context=context):
                with self.assertRaises(AuditPolicyError):
                    self.log.append(
                        task_id="TASK-001",
                        parameter_id="temperature",
                        actor_id="service:ai:worker",
                        action=AuditAction.AI_ASSESSMENT_RECORDED,
                        details=same_assessment_details(),
                        evidence_context=context,
                    )

    def test_duplicate_ai_assessment_and_incomplete_completion_are_rejected(self) -> None:
        self._prepare_ai_run()
        self._append_ai_same()
        with self.assertRaisesRegex(AuditPolicyError, "already exists"):
            self._append_ai_same()

        other_directory = tempfile.TemporaryDirectory()
        self.addCleanup(other_directory.cleanup)
        other = JsonlAuditLog(
            Path(other_directory.name) / "audit.jsonl",
            clock=AdvancingClock(),
            event_id_factory=CountingIds(),
        )
        self._create_task(
            log=other,
            expected_parameter_ids=("temperature", "pressure"),
        )
        for parameter_id in ("temperature", "pressure"):
            other.append(
                task_id="TASK-001",
                parameter_id=parameter_id,
                actor_id="reviewer-001",
                action=AuditAction.HUMAN_DECISION_RECORDED,
                details={"verdict": "SAME"},
                evidence_context=self.context,
            )
        other.append(
            task_id="TASK-001",
            actor_id="reviewer-001",
            action=AuditAction.HUMAN_REVIEW_LOCKED,
            details={"decision_count": 2},
            evidence_context=self.context,
        )
        other.append(
            task_id="TASK-001",
            actor_id="service:ai:worker",
            action=AuditAction.AI_REVIEW_STARTED,
            details={},
            evidence_context=self.ai_context,
        )
        other.append(
            task_id="TASK-001",
            parameter_id="temperature",
            actor_id="service:ai:worker",
            action=AuditAction.AI_ASSESSMENT_RECORDED,
            details=same_assessment_details(),
            evidence_context=self.ai_context,
        )
        with self.assertRaisesRegex(AuditPolicyError, "missing=pressure"):
            other.append(
                task_id="TASK-001",
                actor_id="service:ai:worker",
                action=AuditAction.AI_REVIEW_COMPLETED,
                details={"assessment_count": 1},
                evidence_context=self.ai_context,
            )

    def test_routing_and_blind_second_review_keep_same_run_binding(self) -> None:
        self._prepare_ai_run()
        self._append_ai_same()
        self._complete_ai()
        route = self.log.append(
            task_id="TASK-001",
            parameter_id="temperature",
            actor_id="service:rules:router",
            action=AuditAction.ROUTE_ASSIGNED,
            details={
                "route": "QA_REVIEW_REQUIRED",
                "reasons": ["CRITICAL_PARAMETER"],
            },
            evidence_context=self.ai_context,
        )
        second = self.log.append(
            task_id="TASK-001",
            parameter_id="temperature",
            actor_id="reviewer-002",
            action=AuditAction.SECOND_REVIEW_RECORDED,
            details={"verdict": "DIFFERENT"},
            reason="Independent inspection found a mismatch",
            evidence_context=self.ai_context,
        )

        self.assertEqual(route.evidence_context["run_id"], "run-001")  # type: ignore[index]
        self.assertEqual(second.actor_id, "reviewer-002")

    def test_first_reviewer_cannot_act_as_independent_second_reviewer(self) -> None:
        self._prepare_ai_run()
        self._append_ai_same()
        self._complete_ai()
        self.log.append(
            task_id="TASK-001",
            parameter_id="temperature",
            actor_id="service:rules:router",
            action=AuditAction.ROUTE_ASSIGNED,
            details={
                "route": "QA_REVIEW_REQUIRED",
                "reasons": ["CRITICAL_PARAMETER"],
            },
            evidence_context=self.ai_context,
        )
        with self.assertRaisesRegex(AuditPolicyError, "must differ"):
            self.log.append(
                task_id="TASK-001",
                parameter_id="temperature",
                actor_id="reviewer-001",
                action=AuditAction.SECOND_REVIEW_RECORDED,
                details={"verdict": "SAME"},
                evidence_context=self.ai_context,
            )

    def test_route_reason_uses_fixed_allowlist(self) -> None:
        self._prepare_ai_run()
        self._append_ai_same()
        self._complete_ai()
        with self.assertRaisesRegex(AuditPolicyError, "invalid fixed reason"):
            self.log.append(
                task_id="TASK-001",
                parameter_id="temperature",
                actor_id="service:rules:router",
                action=AuditAction.ROUTE_ASSIGNED,
                details={
                    "route": "QA_REVIEW_REQUIRED",
                    "reasons": ["FREE_TEXT_REASON"],
                },
                    evidence_context=self.ai_context,
                )

    def test_independent_route_requires_distinct_assignment_and_full_manifest_lock(self) -> None:
        self._prepare_two_field_routing()
        with self.assertRaisesRegex(AuditPolicyError, "human assigned reviewer"):
            self.log.append(
                task_id="TASK-001",
                actor_id="service:workflow:orchestrator",
                action=AuditAction.SECOND_REVIEW_ASSIGNED,
                details={
                    "blind_case_id": "blind-001",
                    "assigned_reviewer_id": "ai:reviewer-002",
                },
                evidence_context=self.ai_context,
            )
        with self.assertRaisesRegex(AuditPolicyError, "must differ"):
            self.log.append(
                task_id="TASK-001",
                actor_id="service:workflow:orchestrator",
                action=AuditAction.SECOND_REVIEW_ASSIGNED,
                details={
                    "blind_case_id": "blind-001",
                    "assigned_reviewer_id": "reviewer-001",
                },
                evidence_context=self.ai_context,
            )

        self._assign_second_reviewer()
        self._record_second_decision("temperature")
        with self.assertRaisesRegex(AuditPolicyError, "missing=pressure"):
            self._lock_second_review()
        with self.assertRaisesRegex(AuditPolicyError, "earlier decision"):
            self._record_second_decision(
                "pressure", action=AuditAction.SECOND_REVIEW_DECISION_REVISED
            )
        revised = self._record_second_decision(
            "temperature", action=AuditAction.SECOND_REVIEW_DECISION_REVISED
        )
        self.assertEqual(revised.details["verdict"], "SAME")
        self._record_second_decision("pressure")
        locked = self._lock_second_review()
        self.assertEqual(locked.details["decision_count"], 2)
        self.assertEqual(
            locked.details["second_submission_hash"], SECOND_SUBMISSION_HASH
        )

    def test_legacy_second_review_event_cannot_bypass_assignment_or_lock(self) -> None:
        self._prepare_two_field_routing()
        self.log.append(
            task_id="TASK-001",
            parameter_id="temperature",
            actor_id="reviewer-002",
            action=AuditAction.SECOND_REVIEW_RECORDED,
            details={"verdict": "SAME"},
            evidence_context=self.ai_context,
        )
        exception = self._exception_record("temperature", "CRITICAL_PARAMETER")
        with self.assertRaisesRegex(AuditPolicyError, "full-field second review"):
            self.log.append(
                task_id="TASK-001",
                actor_id="service:workflow:orchestrator",
                action=AuditAction.QA_CASE_OPENED,
                details={
                    "exceptions": [exception],
                    "second_submission_hash": None,
                },
                evidence_context=self.ai_context,
            )
        with self.assertRaisesRegex(AuditPolicyError, "locked full-field"):
            self._append_final(
                AuditAction.FINAL_REJECTION_RECORDED,
                second_submission_hash=None,
            )

    def test_qa_ledger_and_dispositions_require_exact_exception_set(self) -> None:
        self._prepare_locked_second_review()
        expected = self._exception_record("temperature", "CRITICAL_PARAMETER")
        forged = {**expected, "exception_id": "exc-forged"}
        with self.assertRaisesRegex(AuditPolicyError, "exactly equal"):
            self.log.append(
                task_id="TASK-001",
                actor_id="service:workflow:orchestrator",
                action=AuditAction.QA_CASE_OPENED,
                details={
                    "exceptions": [forged],
                    "second_submission_hash": SECOND_SUBMISSION_HASH,
                },
                evidence_context=self.ai_context,
            )

        exception_id = self._open_single_exception_qa()
        with self.assertRaisesRegex(AuditPolicyError, "unknown exception_id"):
            self._record_qa_disposition("exc-unknown")
        with self.assertRaisesRegex(AuditPolicyError, "missing="):
            self._complete_qa(result_state="READY_FOR_FINAL_HUMAN_DECISION")
        self._record_qa_disposition(exception_id)
        with self.assertRaisesRegex(AuditPolicyError, "immutable"):
            self._record_qa_disposition(exception_id)
        with self.assertRaisesRegex(AuditPolicyError, "contradicts"):
            self._complete_qa(result_state="APPROVAL_BLOCKED")
        self._complete_qa(result_state="READY_FOR_FINAL_HUMAN_DECISION")

    def test_blocking_qa_outcome_prevents_approval_but_allows_human_rejection(self) -> None:
        self._prepare_locked_second_review()
        exception_id = self._open_single_exception_qa()
        self._record_qa_disposition(
            exception_id, outcome="CONFIRMED_DIFFERENCE"
        )
        self._complete_qa(result_state="APPROVAL_BLOCKED")

        with self.assertRaisesRegex(AuditPolicyError, "approval is blocked"):
            self._append_final(AuditAction.FINAL_APPROVAL_RECORDED)
        rejected = self._append_final(AuditAction.FINAL_REJECTION_RECORDED)
        self.assertEqual(rejected.actor_id, "final-approver-001")
        self.assertEqual(
            rejected.details["audit_head_predecessor"], rejected.previous_hash
        )

    def test_rework_qa_outcome_prevents_final_approval(self) -> None:
        self._prepare_locked_second_review()
        exception_id = self._open_single_exception_qa()
        self._record_qa_disposition(
            exception_id, outcome="EVIDENCE_REWORK_REQUIRED"
        )
        self._complete_qa(result_state="REWORK_REQUIRED")
        with self.assertRaisesRegex(AuditPolicyError, "approval is blocked"):
            self._append_final(AuditAction.FINAL_APPROVAL_RECORDED)

    def test_direct_qa_route_does_not_invent_a_second_review(self) -> None:
        self._prepare_two_field_routing(
            first_route="QA_REVIEW_REQUIRED",
            first_reasons=("CRITICAL_PARAMETER",),
        )
        exception_id = self._open_single_exception_qa(
            second_submission_hash=None
        )
        self._record_qa_disposition(exception_id)
        self._complete_qa(result_state="READY_FOR_FINAL_HUMAN_DECISION")
        approved = self._append_final(
            AuditAction.FINAL_APPROVAL_RECORDED,
            second_submission_hash=None,
        )
        self.assertIsNone(approved.details["second_submission_hash"])

    def test_final_event_rejects_machine_admin_and_stale_bindings(self) -> None:
        self._prepare_two_field_routing(
            first_route="NO_EXCEPTION_DETECTED",
            first_reasons=(),
        )
        for actor_id in (
            "service:ai:worker",
            "ai:approver",
            "system:approver",
            "admin:approver",
            "reviewer-admin",
        ):
            with self.subTest(actor_id=actor_id):
                with self.assertRaises(AuditPolicyError):
                    self._append_final(
                        AuditAction.FINAL_APPROVAL_RECORDED,
                        actor_id=actor_id,
                        second_submission_hash=None,
                    )

        with self.assertRaisesRegex(AuditPolicyError, "current head"):
            self._append_final(
                AuditAction.FINAL_APPROVAL_RECORDED,
                second_submission_hash=None,
                predecessor="9" * 64,
            )
        with self.assertRaisesRegex(AuditPolicyError, "SECOND_REVIEW"):
            self._append_final(AuditAction.FINAL_APPROVAL_RECORDED)
        approved = self._append_final(
            AuditAction.FINAL_APPROVAL_RECORDED,
            second_submission_hash=None,
        )
        self.assertEqual(approved.previous_hash, approved.details["audit_head_predecessor"])

    def test_generic_append_api_cannot_bypass_atomic_final_committer(self) -> None:
        with self.assertRaisesRegex(AuditPolicyError, "commit_final_cas"):
            self.log.append(
                task_id="TASK-001",
                actor_id="final-approver-001",
                action=AuditAction.FINAL_APPROVAL_RECORDED,
                details={},
                evidence_context=self.ai_context,
            )

    def test_concurrent_final_decisions_have_exactly_one_winner(self) -> None:
        self._prepare_two_field_routing(
            first_route="NO_EXCEPTION_DETECTED",
            first_reasons=(),
        )
        predecessor = self.log.events()[-1].event_hash
        release = Event()
        successes: list[object] = []
        errors: list[Exception] = []
        result_lock = Lock()

        def decide(actor_id: str) -> None:
            release.wait(timeout=2)
            try:
                event = self._append_final(
                    AuditAction.FINAL_APPROVAL_RECORDED,
                    actor_id=actor_id,
                    second_submission_hash=None,
                    predecessor=predecessor,
                )
                with result_lock:
                    successes.append(event)
            except Exception as error:  # pragma: no cover - diagnostic capture
                with result_lock:
                    errors.append(error)

        threads = [
            Thread(target=decide, args=(f"final-reviewer-{index}",))
            for index in (1, 2)
        ]
        for thread in threads:
            thread.start()
        release.set()
        for thread in threads:
            thread.join(timeout=2)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], AuditPolicyError)
        self.assertEqual(
            sum(
                event.action is AuditAction.FINAL_APPROVAL_RECORDED
                for event in self.log.events()
            ),
            1,
        )

    def test_hash_consistent_final_before_qa_fails_semantic_replay(self) -> None:
        self._prepare_locked_second_review()
        predecessor = self.log.events()[-1].event_hash
        generic = self.log.append(
            task_id="TASK-001",
            actor_id="final-approver-001",
            action=AuditAction.GENERIC_NOTE_RECORDED,
            details={
                "evidence_manifest_hash": MANIFEST_HASH,
                "second_submission_hash": SECOND_SUBMISSION_HASH,
                "resolution_digest": RESOLUTION_HASH,
                "audit_head_predecessor": predecessor,
                "rationale": "forged premature approval",
                "commit_request_hash": "3" * 64,
                "command_id": "forged-final-command",
                "adjudication_version": 2,
            },
            evidence_context=self.ai_context,
        )
        forged_without_hash = replace(
            generic,
            action=AuditAction.FINAL_APPROVAL_RECORDED,
            event_hash="0" * 64,
        )
        forged = replace(
            forged_without_hash,
            event_hash=audit_module._calculate_event_hash(forged_without_hash),
        )
        records = [event.to_record() for event in self.log.events()[:-1]]
        records.append(forged.to_record())
        self.path.write_text(
            "".join(json.dumps(record) + "\n" for record in records),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(AuditIntegrityError, "semantics"):
            self.log.events()

    def test_original_event_remains_when_correction_is_appended(self) -> None:
        self._create_task()
        original = self._append_human_event()
        correction = self.log.record_correction(
            task_id="TASK-001",
            actor_id="reviewer-001",
            corrects_event_id=original.event_id,
            reason="Transcription mistake noticed during QA review",
            corrected_details={"verdict": "DIFFERENT"},
        )

        events = self.log.events()
        self.assertEqual(events[1], original)
        self.assertEqual(correction.action, AuditAction.CORRECTION_RECORDED)
        self.assertEqual(correction.parameter_id, original.parameter_id)
        self.assertEqual(correction.evidence_context, original.evidence_context)

    def test_correction_to_unknown_or_other_task_is_rejected(self) -> None:
        self._create_task()
        original = self._append_human_event()
        with self.assertRaises(UnknownCorrectedEventError):
            self.log.record_correction(
                task_id="TASK-001",
                actor_id="reviewer-001",
                corrects_event_id="unknown",
                reason="test",
                corrected_details={"verdict": "DIFFERENT"},
            )
        with self.assertRaises(UnknownCorrectedEventError):
            self.log.record_correction(
                task_id="TASK-OTHER",
                actor_id="reviewer-001",
                corrects_event_id=original.event_id,
                reason="test",
                corrected_details={"verdict": "DIFFERENT"},
            )

    def test_tampered_details_are_detected(self) -> None:
        self._create_task()
        event = self._append_human_event()
        tampered = replace(event, details_json='{"verdict":"DIFFERENT"}')

        with self.assertRaisesRegex(AuditIntegrityError, "hash mismatch"):
            verify_audit_chain((self.log.events()[0], tampered))

    def test_deleted_or_reordered_event_is_detected(self) -> None:
        created = self._create_task()
        human = self._append_human_event()

        with self.assertRaises(AuditIntegrityError):
            verify_audit_chain((human,))
        with self.assertRaises(AuditIntegrityError):
            verify_audit_chain((human, created))

    def test_duplicate_generated_event_id_is_rejected(self) -> None:
        duplicate_log = JsonlAuditLog(
            self.path,
            clock=self.clock,
            event_id_factory=lambda: "same-event-id",
        )
        duplicate_log.append(
            task_id="TASK-001",
            actor_id="observer-001",
            action=AuditAction.GENERIC_NOTE_RECORDED,
            details={},
        )
        with self.assertRaises(DuplicateAuditEventError):
            duplicate_log.append(
                task_id="TASK-002",
                actor_id="observer-002",
                action=AuditAction.GENERIC_NOTE_RECORDED,
                details={},
            )

    def test_naive_or_backwards_clock_is_rejected(self) -> None:
        naive_log = JsonlAuditLog(
            self.path,
            clock=lambda: datetime(2026, 8, 25, 12, 0),
            event_id_factory=lambda: "naive-event",
        )
        with self.assertRaises(ValueError):
            naive_log.append(
                task_id="TASK-001",
                actor_id="observer-001",
                action=AuditAction.GENERIC_NOTE_RECORDED,
                details={},
            )

        self.log.append(
            task_id="TASK-001",
            actor_id="observer-001",
            action=AuditAction.GENERIC_NOTE_RECORDED,
            details={},
        )
        backwards_log = JsonlAuditLog(
            self.path,
            clock=lambda: datetime(2020, 1, 1, tzinfo=timezone.utc),
            event_id_factory=lambda: "backwards-event",
        )
        with self.assertRaises(ValueError):
            backwards_log.append(
                task_id="TASK-001",
                actor_id="observer-001",
                action=AuditAction.GENERIC_NOTE_RECORDED,
                details={},
            )

    def test_clock_and_event_id_are_generated_inside_exclusive_lock(self) -> None:
        first_clock_called = Event()
        first_id_called = Event()
        release_first_id = Event()
        second_clock_called = Event()
        errors: list[Exception] = []

        def first_clock() -> datetime:
            first_clock_called.set()
            return datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)

        def first_id() -> str:
            first_id_called.set()
            if not release_first_id.wait(timeout=2):
                raise TimeoutError("test did not release first event ID")
            return "event-A"

        def second_clock() -> datetime:
            second_clock_called.set()
            return datetime(2026, 8, 25, 12, 0, 1, tzinfo=timezone.utc)

        first_log = JsonlAuditLog(
            self.path, clock=first_clock, event_id_factory=first_id
        )
        second_log = JsonlAuditLog(
            self.path, clock=second_clock, event_id_factory=lambda: "event-B"
        )

        def append(log: JsonlAuditLog, task_id: str) -> None:
            try:
                log.append(
                    task_id=task_id,
                    actor_id="observer-001",
                    action=AuditAction.GENERIC_NOTE_RECORDED,
                    details={},
                )
            except Exception as error:  # pragma: no cover - diagnostic capture
                errors.append(error)

        first = Thread(target=append, args=(first_log, "TASK-A"))
        second = Thread(target=append, args=(second_log, "TASK-B"))
        first.start()
        self.assertTrue(first_clock_called.wait(timeout=2))
        self.assertTrue(first_id_called.wait(timeout=2))
        second.start()
        self.assertFalse(second_clock_called.wait(timeout=0.05))
        release_first_id.set()
        first.join(timeout=2)
        second.join(timeout=2)

        self.assertEqual(errors, [])
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertTrue(second_clock_called.is_set())
        self.assertEqual(
            [event.event_id for event in second_log.events()],
            ["event-A", "event-B"],
        )

    def test_non_json_or_non_finite_details_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self.log.append(
                task_id="TASK-001",
                actor_id="observer-001",
                action=AuditAction.GENERIC_NOTE_RECORDED,
                details={"bad": object()},
            )
        with self.assertRaises(ValueError):
            self.log.append(
                task_id="TASK-001",
                actor_id="observer-001",
                action=AuditAction.GENERIC_NOTE_RECORDED,
                details={"bad": float("nan")},
            )

    def test_truncated_or_invalid_json_line_fails_closed(self) -> None:
        self.path.write_text('{"incomplete": true', encoding="utf-8")
        with self.assertRaisesRegex(AuditIntegrityError, "truncated"):
            self.log.events()

        self.path.write_text("not-json\n", encoding="utf-8")
        with self.assertRaisesRegex(AuditIntegrityError, "Invalid JSON"):
            self.log.events()

    def test_unknown_record_or_context_fields_fail_closed(self) -> None:
        event = self.log.append(
            task_id="TASK-001",
            actor_id="observer-001",
            action=AuditAction.GENERIC_NOTE_RECORDED,
            details={},
            evidence_context=self.context,
        )
        record = event.to_record()
        record["unexpected"] = True
        self.path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(AuditIntegrityError, "Invalid audit event fields"):
            self.log.events()

        record.pop("unexpected")
        record["evidence_context"]["unexpected"] = True
        self.path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(AuditIntegrityError, "Unknown evidence-context"):
            self.log.events()

    def test_hash_consistent_but_semantically_forged_record_fails_closed(self) -> None:
        generic = self.log.append(
            task_id="TASK-001",
            actor_id="service:ai:worker",
            action=AuditAction.GENERIC_NOTE_RECORDED,
            details={},
        )
        forged_without_hash = replace(
            generic,
            action=AuditAction.AI_ASSESSMENT_RECORDED,
            parameter_id="temperature",
            details_json=json.dumps(
                same_assessment_details(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            event_hash="0" * 64,
        )
        forged = replace(
            forged_without_hash,
            event_hash=audit_module._calculate_event_hash(forged_without_hash),
        )
        self.path.write_text(
            json.dumps(forged.to_record(), ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(AuditIntegrityError, "semantics"):
            self.log.events()


if __name__ == "__main__":
    unittest.main()
