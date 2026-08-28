"""Run a synthetic backend workflow with real, default local Tesseract OCR.

Run from the repository root with PYTHONPATH=src and a NEW --output directory
under artifacts/. No web UI, network model, real human approval, or production
data is involved. Only the HUMAN roles are scripted; default OCR is not mocked.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
import hashlib
import json
from pathlib import Path
import platform

from PIL import __version__ as pillow_version

from paramguard.adjudication import QaDispositionOutcome
from paramguard.audit import AuditAction, EvidenceContext, JsonlAuditLog
from paramguard.identity import Actor, PrincipalKind, Role
from paramguard.image_quality import ImageQualityFlag
from paramguard.ocr import DEFAULT_TESSERACT_CONFIG, TesseractOcrEngine
from paramguard.review_policy import INTERVIEW_TARGETED_RECHECK
from paramguard.routing import ImageQuality
from paramguard.synthetic import default_clean_case, render_case
from paramguard.targeted_adjudication import (
    TargetedAdjudicationCase,
    TargetedAdjudicationState,
    TargetedApprovalBlockedError,
    TrustedTargetedSubmissionRecord,
)
from paramguard.targeted_audit_adapter import JsonlTargetedAuditAdapter
from paramguard.targeted_review import (
    LockedParameterRoutingContext,
    LockedRoutingContext,
    TargetedReviewSession,
    TargetedVerdict,
    canonical_locked_targeted_submission_record,
)
from paramguard.vision_pipeline import (
    ROUTING_RULES_VERSION,
    VisionPipelineStateError,
    build_tesseract_pipeline_spec,
    run_gated_ocr_pair,
)
from paramguard.workflow import (
    AiResultAccessDenied,
    HumanVerdict,
    IncompleteReviewError,
    InvalidTransitionError,
    ReviewTask,
)


ROOT = Path(__file__).resolve().parents[1]
HUMAN_ROLE_NOTICE = (
    "scripted demonstration of HUMAN roles, not actual human approval or timing"
)
# These are predeclared HUMAN-role observations, never OCR input or AI output.
SCRIPTED_HUMAN_OBSERVATIONS = {
    "temperature": (HumanVerdict.SAME, "Both synthetic displays show 37.0 C."),
    "pressure": (HumanVerdict.DIFFERENT, "1.20 bar and 1.25 bar remain different."),
    "speed": (HumanVerdict.DIFFERENT, "0800 rpm and 800 rpm remain different."),
    "mode": (HumanVerdict.SAME, "Both synthetic displays show AUTO."),
}


class DemoStopped(RuntimeError):
    """A real stage did not satisfy this demonstration's declared contract."""


class CountingTesseractEngine(TesseractOcrEngine):
    """Count actual crop attempts without altering the default OCR behavior."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.crop_calls = 0

    def _extract_crop(self, crop_bytes, **kwargs):
        self.crop_calls += 1
        return super()._extract_crop(crop_bytes, **kwargs)


class _RoutingResolver:
    """Local composition-root facts; no client-supplied routing decisions."""

    def __init__(self, context):
        self.context = context

    def resolve_locked_context(
        self, *, task_id, evidence_manifest_hash, expected_parameter_ids
    ):
        if (
            task_id != self.context.task_id
            or evidence_manifest_hash != self.context.evidence_manifest_hash
            or expected_parameter_ids
            != tuple(item.parameter_id for item in self.context.parameters)
        ):
            raise DemoStopped("ROUTING_CONTEXT_BINDING_MISMATCH")
        return self.context


class _SubmissionResolver:
    def __init__(self, record):
        self.record = record

    def resolve_locked_submission(self, *, task_id):
        if task_id != self.record.task_id:
            raise DemoStopped("SUBMISSION_TASK_MISMATCH")
        return self.record


def _json_value(value):
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Decimal):
        # Comparator diagnostics only; original left_raw/right_raw stay unchanged.
        return str(value)
    if is_dataclass(value):
        return _json_value(asdict(value))
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_json_value(item) for item in value]
    return value


def _write_json(path, value):
    with path.open("x", encoding="utf-8") as handle:
        json.dump(
            _json_value(value), handle, ensure_ascii=False, indent=2, allow_nan=False
        )
        handle.write("\n")


def _step(report, operation, state, **details):
    report["last_observed_state"] = state
    report["steps"].append(
        {
            "sequence": len(report["steps"]) + 1,
            "operation": operation,
            "state": state,
            **_json_value(details),
        }
    )


def _require(condition, code):
    if not condition:
        raise DemoStopped(code)


def _actor(name, role):
    # Domain actors are explicitly simulated, not authenticated real people.
    return Actor(
        actor_id=f"demo-human-{name}", kind=PrincipalKind.HUMAN, roles=frozenset({role})
    )


def _guard(report, engine, name, expected_error, action):
    before = engine.crop_calls
    try:
        action()
    except expected_error as error:
        _require(engine.crop_calls == before, "DENIED_OPERATION_INVOKED_OCR")
        report["guard_checks"].append(
            {
                "name": name,
                "rejected": True,
                "error_type": type(error).__name__,
                "crop_calls_before": before,
                "crop_calls_after": engine.crop_calls,
            }
        )
    else:
        raise DemoStopped(f"EXPECTED_REJECTION_MISSING:{name}")


def _execute(output, engine, report):
    report["current_stage"] = "GENERATE_SYNTHETIC_EVIDENCE"
    rendered = render_case(default_clean_case(), output_root=output / "evidence")
    _write_json(output / "EVIDENCE_MANIFEST.json", rendered.manifest.to_record())
    report["evidence"] = {
        "synthetic_only": True,
        "manifest_sha256": rendered.manifest.manifest_hash,
        "manifest": "EVIDENCE_MANIFEST.json",
        "left_png": rendered.left_image_path.relative_to(output).as_posix(),
        "right_png": rendered.right_image_path.relative_to(output).as_posix(),
        "case_id": rendered.spec.case_id,
    }
    report["current_stage"] = "BIND_LOCAL_ENGINE"
    spec = build_tesseract_pipeline_spec(engine=engine, template=rendered.template)
    report["ocr"].update(
        engine_version=spec.engine_version,
        config=engine.config.to_record(),
        config_sha256=engine.config.content_sha256,
        pipeline_spec=spec.to_record(),
        pipeline_spec_sha256=spec.spec_hash,
    )
    r1 = _actor("r1", Role.PRIMARY_REVIEWER)
    targeted_actor = _actor("targeted", Role.SECOND_REVIEWER)
    qa_actor = _actor("qa", Role.QA_REVIEWER)
    final_actor = _actor("final", Role.FINAL_APPROVER)
    report["scripted_human_actors"] = [
        {
            "actor_id": actor.actor_id,
            "kind": actor.kind.value,
            "roles": sorted(role.value for role in actor.roles),
            "notice": HUMAN_ROLE_NOTICE,
        }
        for actor in (r1, targeted_actor, qa_actor, final_actor)
    ]
    task = ReviewTask(
        task_id="synthetic-full-workflow-001",
        evidence_manifest=rendered.manifest,
        approved_pipeline_spec=spec,
        reviewer_id=r1.actor_id,
    )
    run_id = "demo-local-tesseract-001"
    log = JsonlAuditLog(output / "AUDIT.jsonl")
    base = EvidenceContext.from_manifest(rendered.manifest)
    context = EvidenceContext.from_manifest(
        rendered.manifest,
        rules_version=ROUTING_RULES_VERSION,
        run_id=run_id,
        pipeline_spec_hash=spec.spec_hash,
        pipeline_version=spec.pipeline_version,
        comparator_version=spec.comparator_version,
        ocr_engine=spec.engine_name,
        ocr_version=spec.engine_version,
    )
    log.append(
        task_id=task.task_id,
        actor_id="service:workflow:demo",
        action=AuditAction.TASK_CREATED,
        details={
            "expected_parameter_ids": list(task.expected_parameter_ids),
            "reviewer_id": task.reviewer_id,
        },
        evidence_context=base,
    )
    _step(report, "TASK_CREATED", task.state.value)
    queue_args = dict(
        run_id=run_id,
        evidence_manifest_hash=task.evidence_manifest_hash,
        pipeline_spec_hash=spec.spec_hash,
    )
    pipeline_args = dict(
        run_id=run_id,
        left_image_path=rendered.left_image_path,
        right_image_path=rendered.right_image_path,
        engine=engine,
        template=rendered.template,
    )
    report["current_stage"] = "PRELOCK_GUARDS"
    _guard(
        report,
        engine,
        "prelock_ai_queue",
        InvalidTransitionError,
        lambda: task.queue_ai_review(**queue_args),
    )
    _guard(
        report,
        engine,
        "prelock_ocr",
        VisionPipelineStateError,
        lambda: run_gated_ocr_pair(task, **pipeline_args),
    )
    _guard(
        report,
        engine,
        "prelock_result_access",
        AiResultAccessDenied,
        task.revealed_ai_results,
    )
    report["current_stage"] = "SCRIPTED_R1"
    for index, parameter_id in enumerate(task.expected_parameter_ids):
        verdict, observation = SCRIPTED_HUMAN_OBSERVATIONS[parameter_id]
        decision = task.record_human_decision(
            parameter_id=parameter_id,
            verdict=verdict,
            reason=f"{HUMAN_ROLE_NOTICE}. {observation}",
            evidence_manifest_hash=task.evidence_manifest_hash,
        )
        log.append(
            task_id=task.task_id,
            actor_id=decision.reviewer_id,
            parameter_id=parameter_id,
            action=AuditAction.HUMAN_DECISION_RECORDED,
            details={"verdict": decision.verdict.value},
            reason=decision.reason,
            evidence_context=base,
        )
        _step(
            report,
            "R1_FIELD_RECORDED",
            task.state.value,
            parameter_id=parameter_id,
            verdict=verdict.value,
            completed_fields=index + 1,
            total_fields=len(task.expected_parameter_ids),
            crop_calls=engine.crop_calls,
            notice=HUMAN_ROLE_NOTICE,
        )
        if index == 0:
            _guard(
                report,
                engine,
                "incomplete_r1_lock",
                IncompleteReviewError,
                lambda: task.lock_human_review(
                    evidence_manifest_hash=task.evidence_manifest_hash
                ),
            )
    task.lock_human_review(evidence_manifest_hash=task.evidence_manifest_hash)
    locked_human_snapshot = dict(task.human_decisions())
    log.append(
        task_id=task.task_id,
        actor_id=r1.actor_id,
        action=AuditAction.HUMAN_REVIEW_LOCKED,
        details={"decision_count": len(task.expected_parameter_ids)},
        evidence_context=base,
    )
    _step(
        report, "R1_ALL_FIELDS_LOCKED", task.state.value, crop_calls=engine.crop_calls
    )
    task.queue_ai_review(**queue_args)
    _step(report, "AI_QUEUED_AFTER_R1_LOCK", task.state.value)
    task.start_ai_review(
        run_id=run_id, evidence_manifest_hash=task.evidence_manifest_hash
    )
    log.append(
        task_id=task.task_id,
        actor_id="service:ai:demo-tesseract",
        action=AuditAction.AI_REVIEW_STARTED,
        details={},
        evidence_context=context,
    )
    _step(report, "LOCAL_OCR_STARTED", task.state.value)
    report["current_stage"] = "REAL_GATED_OCR"
    try:
        outcome = run_gated_ocr_pair(task, **pipeline_args)
    finally:
        report["source_workflow_state"] = task.state.value
        report["ocr"]["crop_attempts"] = engine.crop_calls
    # Mirror the actual completed aggregate, never hand-fill an AI assessment.
    for assessment in outcome.ai_assessments:
        comparison = assessment.comparison_result
        reason = assessment.reason
        if reason is None and assessment.verdict.value != "SAME":
            reason = f"Deterministic raw-string comparison: {comparison.kind.value}."
        log.append(
            task_id=task.task_id,
            actor_id="service:ai:demo-tesseract",
            parameter_id=assessment.parameter_id,
            action=AuditAction.AI_ASSESSMENT_RECORDED,
            details={
                "verdict": assessment.verdict.value,
                "left_raw": assessment.left_raw,
                "right_raw": assessment.right_raw,
                "extraction_reliable": assessment.extraction_reliable,
                "comparison_kind": None
                if comparison is None
                else comparison.kind.value,
                "exact_match": False if comparison is None else comparison.exact_match,
            },
            reason=reason,
            evidence_context=context,
        )
    log.append(
        task_id=task.task_id,
        actor_id="service:ai:demo-tesseract",
        action=AuditAction.AI_REVIEW_COMPLETED,
        details={"assessment_count": len(outcome.ai_assessments)},
        evidence_context=context,
    )
    report["ocr"].update(
        returned_crop_count=len(outcome.left_ocr) + len(outcome.right_ocr),
        left_quality=_json_value(outcome.left_quality),
        right_quality=_json_value(outcome.right_quality),
        left_crops=_json_value(outcome.left_ocr),
        right_crops=_json_value(outcome.right_ocr),
        assessments=_json_value(outcome.ai_assessments),
    )
    _step(report, "LOCAL_OCR_COMPLETED", task.state.value, crop_calls=engine.crop_calls)
    _require(
        engine.crop_calls == 8 and report["ocr"]["returned_crop_count"] == 8,
        "EXPECTED_EIGHT_REAL_CROPS_NOT_COMPLETED",
    )
    _require(
        dict(task.human_decisions()) == locked_human_snapshot, "R1_SNAPSHOT_CHANGED"
    )

    report["current_stage"] = "SCRIPTED_TARGETED_REVIEW"
    flags = set(outcome.left_quality.flags) | set(outcome.right_quality.flags)
    quality = (
        ImageQuality.UNREADABLE
        if ImageQualityFlag.DIMENSION_MISMATCH in flags
        else ImageQuality.LOW
        if flags
        else ImageQuality.ACCEPTABLE
    )
    routing_context = LockedRoutingContext(
        context_id="demo-locked-routing-001",
        context_version="synthetic-cli-v1",
        task_id=task.task_id,
        evidence_manifest_hash=task.evidence_manifest_hash,
        locked_at=datetime.now(timezone.utc),
        parameters=tuple(
            LockedParameterRoutingContext(
                parameter_id=region.parameter_id,
                is_critical=region.critical,
                image_quality=quality,
                field_issues=(),
            )
            for region in rendered.template.regions
        ),
    )
    targeted = TargetedReviewSession(
        targeted_case_id="demo-targeted-case-001",
        source_review_task=task,
        routing_context_resolver=_RoutingResolver(routing_context),
        profile=INTERVIEW_TARGETED_RECHECK,
        assignment_id="demo-targeted-assignment-001",
        assigned_reviewer=targeted_actor,
    )
    plan = targeted.queue_plan()
    report["targeted_plan"] = _json_value(plan)
    binding = dict(
        actor=targeted_actor,
        task_id=task.task_id,
        assignment_id=targeted.assignment_id,
        evidence_manifest_hash=task.evidence_manifest_hash,
        source_snapshot_sha256=targeted.source_snapshot_sha256,
    )
    for item in plan.targeted_items:
        verdict, observation = SCRIPTED_HUMAN_OBSERVATIONS[item.parameter_id]
        targeted.record_decision(
            **binding,
            parameter_id=item.parameter_id,
            verdict=TargetedVerdict(verdict.value),
            reason=f"{HUMAN_ROLE_NOTICE}. {observation} No exception is auto-closed.",
            command_id=f"demo-targeted-{item.parameter_id}",
            expected_revision=targeted.revision,
        )
        _step(
            report,
            "TARGETED_FIELD_RECORDED",
            targeted.state.value,
            parameter_id=item.parameter_id,
            verdict=verdict.value,
            revision=targeted.revision,
            notice=HUMAN_ROLE_NOTICE,
        )
    submission = targeted.lock(
        **binding, command_id="demo-targeted-lock", expected_revision=targeted.revision
    )
    _write_json(
        output / "TARGETED_SUBMISSION.json",
        canonical_locked_targeted_submission_record(submission),
    )
    record = TrustedTargetedSubmissionRecord(
        task_id=task.task_id,
        primary_reviewer_id=r1.actor_id,
        ai_run_id=run_id,
        targeted_reviewer=targeted_actor,
        assigned_qa_reviewer_id=qa_actor.actor_id,
        assigned_final_approver_id=final_actor.actor_id,
        evidence_context=context,
        submission=submission,
        expected_source_snapshot_sha256=targeted.source_snapshot_sha256,
        expected_submission_hash=submission.submission_hash,
    )
    case = TargetedAdjudicationCase(
        task_id=task.task_id,
        trusted_submission_resolver=_SubmissionResolver(record),
        audit_committer=JsonlTargetedAuditAdapter(log),
    )
    case.register_locked_submission(
        audit_head_hash=log.head_hash(),
        command_id="demo-audit-lock",
        expected_version=case.version,
    )
    _step(report, "TARGETED_LOCK_COMMITTED", case.state.value, version=case.version)
    report["current_stage"] = "SCRIPTED_QA"
    for exception in case.exception_ledger():
        if not exception.qa_required:
            continue
        if exception.parameter_id == "pressure":
            qa_outcome = QaDispositionOutcome.CONFIRMED_DIFFERENCE
            rationale = "Numeric difference 1.20 bar / 1.25 bar remains blocking."
        elif exception.parameter_id == "speed":
            qa_outcome = QaDispositionOutcome.EVIDENCE_REWORK_REQUIRED
            rationale = (
                "Leading zero 0800 rpm / 800 rpm must not be normalized away; rework."
            )
        else:
            qa_outcome = QaDispositionOutcome.EVIDENCE_REWORK_REQUIRED
            rationale = "Critical policy or other exception remains unconfirmed; no real SOP approval."
        case.record_qa_disposition(
            actor=qa_actor,
            exception_id=exception.exception_id,
            outcome=qa_outcome,
            rationale=f"{HUMAN_ROLE_NOTICE}. {rationale}",
            reference_ids=(f"synthetic-demo-{exception.parameter_id}",),
            audit_head_hash=log.head_hash(),
            command_id=f"demo-qa-{exception.exception_id}",
            expected_version=case.version,
        )
        _step(
            report,
            "QA_DISPOSITION_ACCEPTED",
            case.state.value,
            parameter_id=exception.parameter_id,
            outcome=qa_outcome.value,
            version=case.version,
            notice=HUMAN_ROLE_NOTICE,
        )
    report["exceptions_retained"] = _json_value(case.exception_ledger())
    report["qa_dispositions"] = _json_value(dict(case.qa_dispositions()))
    report["pre_final_state"] = case.state.value
    _require(
        case.state
        in {
            TargetedAdjudicationState.REWORK_REQUIRED,
            TargetedAdjudicationState.APPROVAL_BLOCKED,
        },
        "EXPECTED_QA_BLOCKERS_NOT_RETAINED",
    )
    report["current_stage"] = "SCRIPTED_FINAL_REJECT"
    old_head, old_version = log.head_hash(), case.version
    _guard(
        report,
        engine,
        "approval_with_qa_blockers",
        TargetedApprovalBlockedError,
        lambda: case.approve(
            actor=final_actor,
            rationale=f"{HUMAN_ROLE_NOTICE}. Expected denial probe.",
            audit_head_hash=old_head,
            command_id="demo-approval-denial-probe",
            expected_version=old_version,
        ),
    )
    _require(
        log.head_hash() == old_head and case.version == old_version,
        "DENIED_APPROVAL_CHANGED_STATE",
    )
    final = case.reject(
        actor=final_actor,
        rationale=f"{HUMAN_ROLE_NOTICE}. REJECT: differences and rework remain unresolved.",
        audit_head_hash=log.head_hash(),
        command_id="demo-final-reject",
        expected_version=case.version,
    )
    report["final_decision"] = _json_value(final)
    report["r1_snapshot_unchanged"] = (
        dict(task.human_decisions()) == locked_human_snapshot
    )
    _step(
        report,
        "FINAL_REJECT_COMMITTED",
        case.state.value,
        version=case.version,
        notice=HUMAN_ROLE_NOTICE,
    )


def _markdown(report):
    lines = [
        "# Synthetic full-workflow backend demonstration",
        "",
        HUMAN_ROLE_NOTICE + ".",
        "",
        f"Run status: **{report['status']}**. Automatic release: **disabled**.",
        "",
        "This is a backend CLI, not a claim that the web UI has QA/final buttons. "
        "The PNGs are generated fictional panels, not real photographs or production evidence. "
        "Actors are scripted domain-role demonstrations, not authenticated people or e-signatures. "
        "Timestamps measure script events, never human review time.",
        "",
        f"OCR mode: `{report['ocr']['mode']}`; crop attempts: "
        f"{report['ocr'].get('crop_attempts', 0)}. "
        "OCR confidence is an uncalibrated engine observation, not a probability of correctness.",
        "",
        "## Observed sequence",
        "",
        "| Step | Operation | Actual state |",
        "| --- | --- | --- |",
    ]
    for step in report["steps"]:
        lines.append(
            f"| {step['sequence']} | {step['operation']} "
            f"{step.get('parameter_id', '')} | {step['state']} |"
        )
    lines += [
        "",
        "## Actual OCR observations",
        "",
        "Raw strings below come from the local engine, not the scripted HUMAN observations. "
        "The deterministic comparator decides exact equality; no whitespace, case, numeric, "
        "or leading-zero repair is applied by this demo.",
        "",
        "| Field | Left OCR raw | Right OCR raw | Gated AI observation |",
        "| --- | --- | --- | --- |",
    ]
    for item in report["ocr"].get("assessments", []):
        left = json.dumps(item["left_raw"], ensure_ascii=False).replace("|", "\\|")
        right = json.dumps(item["right_raw"], ensure_ascii=False).replace("|", "\\|")
        lines.append(
            f"| {item['parameter_id']} | `{left}` | `{right}` | {item['verdict']} |"
        )
    lines += ["", "## Guard checks", ""]
    for guard in report["guard_checks"]:
        lines.append(
            f"- `{guard['name']}`: rejected with `{guard['error_type']}`; "
            f"crop calls {guard['crop_calls_before']} → {guard['crop_calls_after']}."
        )
    lines += [
        "",
        "## QA and final outcome",
        "",
        f"Pre-final state: `{report.get('pre_final_state', 'NOT_REACHED')}`. "
        f"Last observed state: `{report.get('last_observed_state', 'NOT_REACHED')}`.",
        "",
    ]
    for item in report.get("qa_dispositions", {}).values():
        lines.append(
            f"- `{item['exception_id']}`: `{item['outcome']}`. {item['rationale']}"
        )
    lines += [
        "",
        "No exception is erased by targeted review or final REJECT. "
        "Numeric differences stay blocking and leading-zero differences require rework. "
        "A clean noncritical field still does not authorize automatic release.",
        "",
        f"Fresh JSONL reopen and hash-chain + semantic replay: "
        f"`{report.get('audit', {}).get('verification', 'NOT_VERIFIED')}`.",
        "",
        "[Machine-readable report](REPORT.json) · [Append-only audit](AUDIT.jsonl) · "
        "[Evidence manifest](EVIDENCE_MANIFEST.json) · "
        "[Locked targeted submission](TARGETED_SUBMISSION.json)",
        "",
    ]
    evidence = report.get("evidence", {})
    for key, label in (
        ("left_png", "Generated synthetic A"),
        ("right_png", "Generated synthetic A-prime"),
    ):
        if key in evidence:
            lines += [f"![{label}]({evidence[key]})", ""]
    if "error" in report:
        lines += [
            f"Stopped at `{report['current_stage']}`: `{report['error']}`. "
            "No missing workflow stage was fabricated.",
            "",
        ]
    lines += [
        "Reproduction needs the repository's existing Python/Pillow dependencies and local "
        "Tesseract with English data. Run `PYTHONPATH=src python3 tools/full_workflow_demo.py "
        "--output artifacts/full-workflow-new-run` from the repository root with a new directory. "
        "The fixed case is reproducible, but OCR, timestamps, event IDs, and audit hashes may "
        "vary by environment/run. This is not a benchmark, human-time study, real-world accuracy "
        "claim, regulatory validation, or automatic-release workflow.",
        "",
    ]
    return "\n".join(lines)


def run_demo(output_directory, *, engine=None):
    """Create one new run. Engine injection is for trusted unit tests only."""

    output = Path(output_directory)
    if output.exists() or output.is_symlink():
        raise FileExistsError("Output must be a new, nonexistent directory")
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema_version": 1,
        "status": "INCOMPLETE",
        "human_role_notice": HUMAN_ROLE_NOTICE,
        "actual_human_approval": False,
        "human_review_seconds": None,
        "automatic_release_allowed": False,
        "backend_cli_only": True,
        "workflow_mode": "STRICT_SEQUENTIAL",
        "steps": [],
        "guard_checks": [],
        "environment": {
            "python": platform.python_version(),
            "pillow": pillow_version,
            "system": platform.system(),
            "release": platform.release(),
        },
        "ocr": {
            "mode": "REAL_TESSERACT_DEFAULT"
            if engine is None
            else "INJECTED_UNIT_TEST_ENGINE"
        },
        "source_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    active_engine = CountingTesseractEngine() if engine is None else engine
    try:
        _require(
            isinstance(active_engine, CountingTesseractEngine),
            "UNSUPPORTED_TEST_ENGINE",
        )
        _require(
            active_engine.config == DEFAULT_TESSERACT_CONFIG, "NONDEFAULT_OCR_CONFIG"
        )
        _require(active_engine.crop_calls == 0, "ENGINE_ALREADY_USED")
        _execute(output, active_engine, report)
        report["current_stage"] = "FRESH_JSONL_REPLAY"
        # A new object reads the actual on-disk JSONL and validates business semantics
        # as well as hashes. This does not authenticate actors or provide WORM storage.
        reopened = JsonlAuditLog(output / "AUDIT.jsonl")
        reopened.verify()
        events = reopened.events()
        _require(
            events[-1].action is AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
            "FINAL_REJECTION_NOT_AUDITED",
        )
        _require(
            all(
                event.action is not AuditAction.TARGETED_FINAL_APPROVAL_RECORDED
                for event in events
            ),
            "UNEXPECTED_APPROVAL_EVENT",
        )
        report["audit"] = {
            "path": "AUDIT.jsonl",
            "verification": "HASH_CHAIN_AND_SEMANTICS_VERIFIED",
            "event_count": len(events),
            "head_sha256": reopened.head_hash(),
            "events": [
                {
                    "sequence": event.sequence,
                    "action": event.action.value,
                    "parameter_id": event.parameter_id,
                    "actor_id": event.actor_id,
                    "event_sha256": event.event_hash,
                }
                for event in events
            ],
        }
        report["status"] = "COMPLETE_SAFE_REJECTION"
        report["current_stage"] = "COMPLETE"
    except Exception as error:
        # Keep real partial evidence; never fabricate later states or substitute AI.
        report["error"] = (
            str(error) if isinstance(error, DemoStopped) else type(error).__name__
        )
        report["ocr"]["crop_attempts"] = getattr(active_engine, "crop_calls", 0)
    _write_json(output / "REPORT.json", report)
    with (output / "REPORT.md").open("x", encoding="utf-8") as handle:
        handle.write(_markdown(report))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New directory below this repository's artifacts/; never overwritten",
    )
    args = parser.parse_args(argv)
    resolved = args.output.resolve()
    artifact_root = (ROOT / "artifacts").resolve()
    if not resolved.is_relative_to(artifact_root) or resolved == artifact_root:
        parser.error(
            "--output must be a new directory below this repository's artifacts/"
        )
    try:
        report = run_demo(args.output)
    except FileExistsError:
        parser.error("--output already exists; choose a new directory")
    print(
        json.dumps(
            {
                "status": report["status"],
                "output": str(args.output),
                "final_state": report.get("last_observed_state"),
                "crop_attempts": report["ocr"].get("crop_attempts", 0),
                "audit_event_count": report.get("audit", {}).get("event_count", 0),
            }
        )
    )
    return 0 if report["status"] == "COMPLETE_SAFE_REJECTION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
