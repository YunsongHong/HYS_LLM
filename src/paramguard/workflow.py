"""Strict, human-first review workflow for ParamGuard Vision.

The first reviewer must finish and lock an independent decision for every
field in one frozen evidence manifest before an AI job may even be queued.
OCR/LLM libraries stay outside this module; extracted raw strings are judged
by the deterministic ``compare_values`` function.

The in-process lock makes commands atomic inside one Python process. It does
not replace database transactions, optimistic concurrency, role-aware API
guards, separate service credentials, or a transactional outbox.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import re
from threading import RLock
from types import MappingProxyType

from .comparison import ComparisonKind, ComparisonResult, compare_values
from .evidence import EvidenceManifest
from .pipeline import PipelineSpec


class WorkflowMode(str, Enum):
    """Only the interview scenario's conservative policy is enabled."""

    STRICT_SEQUENTIAL = "STRICT_SEQUENTIAL"


class HumanVerdict(str, Enum):
    SAME = "SAME"
    DIFFERENT = "DIFFERENT"
    UNABLE_TO_JUDGE = "UNABLE_TO_JUDGE"


class AiVerdict(str, Enum):
    """Auxiliary outcomes; none authorises release."""

    SAME = "SAME"
    DIFFERENT = "DIFFERENT"
    UNABLE_TO_JUDGE = "UNABLE_TO_JUDGE"
    SYSTEM_ERROR = "SYSTEM_ERROR"


class ReviewState(str, Enum):
    HUMAN_REVIEW_OPEN = "HUMAN_REVIEW_OPEN"
    HUMAN_REVIEW_LOCKED = "HUMAN_REVIEW_LOCKED"
    AI_REVIEW_QUEUED = "AI_REVIEW_QUEUED"
    AI_REVIEW_RUNNING = "AI_REVIEW_RUNNING"
    AI_REVIEW_COMPLETE = "AI_REVIEW_COMPLETE"


class WorkflowError(Exception):
    code = "WORKFLOW_ERROR"


class UnknownParameterError(WorkflowError):
    code = "UNKNOWN_PARAMETER"


class DuplicateParameterError(WorkflowError):
    code = "DUPLICATE_PARAMETER"


class IncompleteReviewError(WorkflowError):
    code = "INCOMPLETE_REVIEW"

    def __init__(self, missing_parameter_ids: tuple[str, ...], *, phase: str) -> None:
        self.missing_parameter_ids = missing_parameter_ids
        self.phase = phase
        super().__init__(
            f"{phase} is incomplete; missing decisions for: "
            + ", ".join(missing_parameter_ids)
        )


class ReviewLockedError(WorkflowError):
    code = "REVIEW_LOCKED"


class InvalidTransitionError(WorkflowError):
    code = "INVALID_TRANSITION"


class ReasonRequiredError(WorkflowError):
    code = "REASON_REQUIRED"


class AiResultAccessDenied(WorkflowError):
    code = "AI_RESULT_ACCESS_DENIED"


class EvidenceVersionConflictError(WorkflowError):
    code = "EVIDENCE_VERSION_CONFLICT"


class AiRunIdentityError(WorkflowError):
    code = "AI_RUN_IDENTITY_ERROR"


class AiResultIntegrityError(WorkflowError):
    code = "AI_RESULT_INTEGRITY_ERROR"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_text(name: str, value: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if value.strip() == "":
        raise ValueError(f"{name} must not be empty or whitespace")
    return value


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _require_identifier(name: str, value: str) -> str:
    checked = _require_text(name, value)
    if _IDENTIFIER_PATTERN.fullmatch(checked) is None:
        raise ValueError(
            f"{name} must be 1-128 ASCII letters, digits, dot, underscore, colon, or hyphen"
        )
    return checked


def _require_manifest_hash(value: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(
            "evidence_manifest_hash must be 64 lowercase hexadecimal characters"
        )
    return value


def _require_sha256(name: str, value: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be 64 lowercase hexadecimal characters")
    return value


def _require_aware_datetime(name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include timezone information")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class HumanDecision:
    parameter_id: str
    verdict: HumanVerdict
    reviewer_id: str
    decided_at: datetime
    evidence_manifest_hash: str
    reason: str | None = None


@dataclass(frozen=True)
class AiRun:
    run_id: str
    evidence_manifest_hash: str
    engine_name: str
    engine_version: str
    pipeline_version: str
    comparator_version: str
    pipeline_spec_hash: str
    queued_at: datetime
    started_at: datetime | None = None


@dataclass(frozen=True)
class AiAssessment:
    parameter_id: str
    verdict: AiVerdict
    assessed_at: datetime
    run_id: str
    evidence_manifest_hash: str
    engine_name: str
    engine_version: str
    pipeline_version: str
    comparator_version: str
    pipeline_spec_hash: str
    left_raw: str | None
    right_raw: str | None
    extraction_reliable: bool
    comparison_result: ComparisonResult | None
    reason: str | None = None


class ReviewTask:
    """One task bound to one immutable evidence manifest and reviewer."""

    def __init__(
        self,
        *,
        task_id: str,
        evidence_manifest: EvidenceManifest,
        approved_pipeline_spec: PipelineSpec,
        reviewer_id: str,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._task_id = _require_identifier("task_id", task_id)
        self._reviewer_id = _require_identifier("reviewer_id", reviewer_id)
        if not isinstance(evidence_manifest, EvidenceManifest):
            raise TypeError("evidence_manifest must be an EvidenceManifest")
        if not isinstance(approved_pipeline_spec, PipelineSpec):
            raise TypeError("approved_pipeline_spec must be a PipelineSpec")
        if not callable(clock):
            raise TypeError("clock must be callable")

        self._evidence_manifest = evidence_manifest
        self._evidence_manifest_hash = evidence_manifest.manifest_hash
        self._approved_pipeline_spec = approved_pipeline_spec
        self._expected_parameter_ids = evidence_manifest.expected_parameter_ids
        self._expected_parameter_id_set = frozenset(self._expected_parameter_ids)
        self._clock = clock
        self._lock = RLock()
        self._mode = WorkflowMode.STRICT_SEQUENTIAL
        self._state = ReviewState.HUMAN_REVIEW_OPEN
        self._human_decisions: dict[str, HumanDecision] = {}
        self._human_locked_at: datetime | None = None
        self._ai_run: AiRun | None = None
        self._ai_results: dict[str, AiAssessment] = {}

    @property
    def task_id(self) -> str:
        return self._task_id

    @property
    def reviewer_id(self) -> str:
        return self._reviewer_id

    @property
    def mode(self) -> WorkflowMode:
        return self._mode

    @property
    def evidence_manifest(self) -> EvidenceManifest:
        return self._evidence_manifest

    @property
    def evidence_manifest_hash(self) -> str:
        return self._evidence_manifest_hash

    @property
    def approved_pipeline_spec(self) -> PipelineSpec:
        return self._approved_pipeline_spec

    @property
    def state(self) -> ReviewState:
        with self._lock:
            return self._state

    @property
    def expected_parameter_ids(self) -> tuple[str, ...]:
        return self._expected_parameter_ids

    @property
    def human_locked_at(self) -> datetime | None:
        with self._lock:
            return self._human_locked_at

    def human_decisions(self) -> Mapping[str, HumanDecision]:
        with self._lock:
            return MappingProxyType(dict(self._human_decisions))

    def missing_human_parameter_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                parameter_id
                for parameter_id in self._expected_parameter_ids
                if parameter_id not in self._human_decisions
            )

    def record_human_decision(
        self,
        *,
        parameter_id: str,
        verdict: HumanVerdict,
        evidence_manifest_hash: str,
        reason: str | None = None,
    ) -> HumanDecision:
        """Create or revise a decision before the whole review is locked."""

        with self._lock:
            if self._state is not ReviewState.HUMAN_REVIEW_OPEN:
                raise ReviewLockedError(
                    "Human decisions cannot be changed after the review is locked"
                )
            self._check_manifest_hash(evidence_manifest_hash)
            checked_id = self._check_parameter_id(parameter_id)
            if not isinstance(verdict, HumanVerdict):
                raise TypeError("verdict must be a HumanVerdict")
            checked_reason = self._check_reason(reason)
            if verdict is not HumanVerdict.SAME and checked_reason is None:
                raise ReasonRequiredError(
                    f"A reason is required for human verdict {verdict.value}"
                )

            decision = HumanDecision(
                parameter_id=checked_id,
                verdict=verdict,
                reviewer_id=self._reviewer_id,
                decided_at=self._now(),
                evidence_manifest_hash=self._evidence_manifest_hash,
                reason=checked_reason,
            )
            self._human_decisions[checked_id] = decision
            return decision

    def lock_human_review(self, *, evidence_manifest_hash: str) -> datetime:
        """Atomically freeze the complete first-review snapshot."""

        with self._lock:
            if self._state is not ReviewState.HUMAN_REVIEW_OPEN:
                raise InvalidTransitionError(
                    f"Cannot lock human review from state {self._state.value}"
                )
            self._check_manifest_hash(evidence_manifest_hash)
            missing = self.missing_human_parameter_ids()
            if missing:
                raise IncompleteReviewError(missing, phase="Human review")
            if set(self._human_decisions) != self._expected_parameter_id_set:
                raise EvidenceVersionConflictError(
                    "Human decision keys do not exactly match the frozen schema"
                )
            if any(
                key != decision.parameter_id
                or decision.reviewer_id != self._reviewer_id
                or decision.evidence_manifest_hash != self._evidence_manifest_hash
                for key, decision in self._human_decisions.items()
            ):
                raise EvidenceVersionConflictError(
                    "Human decisions are not all bound to the assigned reviewer and evidence manifest"
                )

            locked_at = self._now()
            self._human_locked_at = locked_at
            self._state = ReviewState.HUMAN_REVIEW_LOCKED
            return locked_at

    def queue_ai_review(
        self,
        *,
        run_id: str,
        evidence_manifest_hash: str,
        pipeline_spec_hash: str,
    ) -> None:
        """Queue exactly one AI run, and only after the human lock."""

        with self._lock:
            if self._state is not ReviewState.HUMAN_REVIEW_LOCKED:
                raise InvalidTransitionError(
                    "AI review can be queued only after the human review is locked; "
                    f"current state is {self._state.value}"
                )
            self._check_manifest_hash(evidence_manifest_hash)
            checked_spec_hash = _require_sha256(
                "pipeline_spec_hash", pipeline_spec_hash
            )
            if checked_spec_hash != self._approved_pipeline_spec.spec_hash:
                raise EvidenceVersionConflictError(
                    "Supplied pipeline spec does not match the task's approved spec"
                )
            spec = self._approved_pipeline_spec
            self._ai_run = AiRun(
                run_id=_require_identifier("run_id", run_id),
                evidence_manifest_hash=self._evidence_manifest_hash,
                engine_name=spec.engine_name,
                engine_version=spec.engine_version,
                pipeline_version=spec.pipeline_version,
                comparator_version=spec.comparator_version,
                pipeline_spec_hash=spec.spec_hash,
                queued_at=self._now(),
            )
            self._state = ReviewState.AI_REVIEW_QUEUED

    def start_ai_review(
        self, *, run_id: str, evidence_manifest_hash: str
    ) -> None:
        """Start the queued run after rechecking its evidence identity."""

        with self._lock:
            if self._state is not ReviewState.AI_REVIEW_QUEUED:
                raise InvalidTransitionError(
                    "AI review can start only from AI_REVIEW_QUEUED; "
                    f"current state is {self._state.value}"
                )
            run = self._require_ai_run(run_id, evidence_manifest_hash)
            if run.started_at is not None:
                raise AiResultIntegrityError(
                    "Queued AI run already contains a start timestamp"
                )
            self._ai_run = replace(run, started_at=self._now())
            self._state = ReviewState.AI_REVIEW_RUNNING

    def assert_ai_execution_authorized(
        self,
        *,
        run_id: str,
        evidence_manifest_hash: str,
        pipeline_spec_hash: str,
    ) -> None:
        """Validate an execution lease without exposing sealed run metadata.

        Image/OCR adapters call this before reading evidence bytes.  A stale or
        forged run therefore fails before potentially expensive processing can
        produce side-channel hints or results for the wrong task.
        """

        with self._lock:
            if self._state is not ReviewState.AI_REVIEW_RUNNING:
                raise InvalidTransitionError(
                    "AI evidence processing is authorised only while the approved run is active"
                )
            self._require_ai_run(run_id, evidence_manifest_hash)
            checked_spec_hash = _require_sha256(
                "pipeline_spec_hash", pipeline_spec_hash
            )
            if checked_spec_hash != self._approved_pipeline_spec.spec_hash:
                raise EvidenceVersionConflictError(
                    "Execution pipeline does not match the task's approved spec"
                )

    def record_ai_assessment(
        self,
        *,
        run_id: str,
        evidence_manifest_hash: str,
        parameter_id: str,
        left_raw: str | None,
        right_raw: str | None,
        extraction_reliable: bool,
        reason: str | None = None,
    ) -> None:
        """Derive an auxiliary verdict from raw extraction and fixed rules."""

        with self._lock:
            if self._state is not ReviewState.AI_REVIEW_RUNNING:
                raise InvalidTransitionError(
                    "AI assessments can be recorded only while AI review is running; "
                    f"current state is {self._state.value}"
                )
            run = self._require_ai_run(run_id, evidence_manifest_hash)
            checked_id = self._check_parameter_id(parameter_id)
            if checked_id in self._ai_results:
                raise DuplicateParameterError(
                    f"AI assessment already exists for parameter ID: {checked_id}"
                )
            if type(extraction_reliable) is not bool:
                raise TypeError("extraction_reliable must be bool")
            checked_reason = self._check_reason(reason)
            comparison = compare_values(left_raw, right_raw)

            if not extraction_reliable or comparison.kind is ComparisonKind.MISSING_VALUE:
                if checked_reason is None:
                    raise ReasonRequiredError(
                        "An explanation is required for unreliable or missing extraction"
                    )
                verdict = AiVerdict.UNABLE_TO_JUDGE
            elif comparison.exact_match:
                verdict = AiVerdict.SAME
            else:
                verdict = AiVerdict.DIFFERENT

            self._ai_results[checked_id] = AiAssessment(
                parameter_id=checked_id,
                verdict=verdict,
                assessed_at=self._now(),
                run_id=run.run_id,
                evidence_manifest_hash=run.evidence_manifest_hash,
                engine_name=run.engine_name,
                engine_version=run.engine_version,
                pipeline_version=run.pipeline_version,
                comparator_version=run.comparator_version,
                pipeline_spec_hash=run.pipeline_spec_hash,
                left_raw=left_raw,
                right_raw=right_raw,
                extraction_reliable=extraction_reliable,
                comparison_result=comparison,
                reason=checked_reason,
            )

    def record_ai_system_error(
        self,
        *,
        run_id: str,
        evidence_manifest_hash: str,
        parameter_id: str,
        reason: str,
    ) -> None:
        """Record a technical failure without disguising it as a match."""

        with self._lock:
            if self._state is not ReviewState.AI_REVIEW_RUNNING:
                raise InvalidTransitionError(
                    "AI system errors can be recorded only while AI review is running"
                )
            run = self._require_ai_run(run_id, evidence_manifest_hash)
            checked_id = self._check_parameter_id(parameter_id)
            if checked_id in self._ai_results:
                raise DuplicateParameterError(
                    f"AI assessment already exists for parameter ID: {checked_id}"
                )
            checked_reason = _require_text("reason", reason)
            self._ai_results[checked_id] = AiAssessment(
                parameter_id=checked_id,
                verdict=AiVerdict.SYSTEM_ERROR,
                assessed_at=self._now(),
                run_id=run.run_id,
                evidence_manifest_hash=run.evidence_manifest_hash,
                engine_name=run.engine_name,
                engine_version=run.engine_version,
                pipeline_version=run.pipeline_version,
                comparator_version=run.comparator_version,
                pipeline_spec_hash=run.pipeline_spec_hash,
                left_raw=None,
                right_raw=None,
                extraction_reliable=False,
                comparison_result=None,
                reason=checked_reason,
            )

    def complete_ai_review(
        self, *, run_id: str, evidence_manifest_hash: str
    ) -> None:
        with self._lock:
            if self._state is not ReviewState.AI_REVIEW_RUNNING:
                raise InvalidTransitionError(
                    "AI review can complete only while it is running; "
                    f"current state is {self._state.value}"
                )
            run = self._require_ai_run(run_id, evidence_manifest_hash)
            missing = tuple(
                parameter_id
                for parameter_id in self._expected_parameter_ids
                if parameter_id not in self._ai_results
            )
            if missing:
                raise IncompleteReviewError(missing, phase="AI review")
            if set(self._ai_results) != self._expected_parameter_id_set:
                raise AiResultIntegrityError(
                    "AI result keys do not exactly match the frozen schema"
                )
            for parameter_id, result in self._ai_results.items():
                self._validate_ai_result(parameter_id, result, run)
            self._state = ReviewState.AI_REVIEW_COMPLETE

    def revealed_ai_results(self) -> Mapping[str, AiAssessment]:
        with self._lock:
            if self._state is not ReviewState.AI_REVIEW_COMPLETE:
                raise AiResultAccessDenied(
                    "AI results are unavailable until the human review is locked "
                    "and the complete AI run is ready"
                )
            return MappingProxyType(dict(self._ai_results))

    def revealed_ai_run(self) -> AiRun:
        with self._lock:
            if self._state is not ReviewState.AI_REVIEW_COMPLETE:
                raise AiResultAccessDenied(
                    "AI run metadata is unavailable until AI review is complete"
                )
            assert self._ai_run is not None
            return self._ai_run

    def _check_parameter_id(self, parameter_id: str) -> str:
        checked_id = _require_identifier("parameter_id", parameter_id)
        if checked_id not in self._expected_parameter_id_set:
            raise UnknownParameterError(f"Unknown parameter ID: {checked_id}")
        return checked_id

    def _check_manifest_hash(self, supplied_hash: str) -> None:
        checked_hash = _require_manifest_hash(supplied_hash)
        if checked_hash != self._evidence_manifest_hash:
            raise EvidenceVersionConflictError(
                "Supplied evidence manifest does not match the frozen task evidence"
            )

    def _require_ai_run(
        self, run_id: str, evidence_manifest_hash: str
    ) -> AiRun:
        checked_run_id = _require_identifier("run_id", run_id)
        self._check_manifest_hash(evidence_manifest_hash)
        if not isinstance(self._ai_run, AiRun):
            raise AiRunIdentityError("No valid AI run is active")
        run = self._ai_run
        if run.run_id != checked_run_id:
            raise AiRunIdentityError("Supplied AI run does not match the active run")
        spec = self._approved_pipeline_spec
        if (
            run.evidence_manifest_hash != self._evidence_manifest_hash
            or run.pipeline_spec_hash != spec.spec_hash
            or run.engine_name != spec.engine_name
            or run.engine_version != spec.engine_version
            or run.pipeline_version != spec.pipeline_version
            or run.comparator_version != spec.comparator_version
        ):
            raise AiResultIntegrityError(
                "Active AI run is not bound to the task evidence and approved pipeline"
            )
        try:
            queued_at = _require_aware_datetime("queued_at", run.queued_at)
            started_at = (
                None
                if run.started_at is None
                else _require_aware_datetime("started_at", run.started_at)
            )
        except (TypeError, ValueError) as error:
            raise AiResultIntegrityError(
                f"Active AI run has an invalid timestamp: {error}"
            ) from error
        if started_at is not None and started_at < queued_at:
            raise AiResultIntegrityError(
                "Active AI run start timestamp precedes its queue timestamp"
            )
        return run

    def _validate_ai_result(
        self, parameter_id: str, result: AiAssessment, run: AiRun
    ) -> None:
        """Defensively re-derive every persisted result before completion."""

        if not isinstance(result, AiAssessment):
            raise AiResultIntegrityError(
                f"AI result for {parameter_id} is not an AiAssessment"
            )
        if result.parameter_id != parameter_id:
            raise AiResultIntegrityError(
                f"AI result key and parameter ID differ for {parameter_id}"
            )
        if not isinstance(result.verdict, AiVerdict):
            raise AiResultIntegrityError(
                f"AI result verdict has an invalid type for {parameter_id}"
            )
        if type(result.extraction_reliable) is not bool:
            raise AiResultIntegrityError(
                f"AI extraction reliability is not a strict boolean for {parameter_id}"
            )
        if result.reason is not None and not isinstance(result.reason, str):
            raise AiResultIntegrityError(
                f"AI result reason has an invalid type for {parameter_id}"
            )
        if (
            run.pipeline_spec_hash != self._approved_pipeline_spec.spec_hash
            or run.engine_name != self._approved_pipeline_spec.engine_name
            or run.engine_version != self._approved_pipeline_spec.engine_version
            or run.pipeline_version != self._approved_pipeline_spec.pipeline_version
            or run.comparator_version
            != self._approved_pipeline_spec.comparator_version
        ):
            raise AiResultIntegrityError(
                "Active AI run differs from the task's approved pipeline spec"
            )
        if (
            result.run_id != run.run_id
            or result.evidence_manifest_hash != run.evidence_manifest_hash
            or result.engine_name != run.engine_name
            or result.engine_version != run.engine_version
            or result.pipeline_version != run.pipeline_version
            or result.comparator_version != run.comparator_version
            or result.pipeline_spec_hash != run.pipeline_spec_hash
        ):
            raise AiResultIntegrityError(
                f"AI result metadata differs from active run for {parameter_id}"
            )
        try:
            assessed_at = _require_aware_datetime("assessed_at", result.assessed_at)
        except (TypeError, ValueError) as error:
            raise AiResultIntegrityError(
                f"AI result timestamp is invalid for {parameter_id}: {error}"
            ) from error
        if run.started_at is None or assessed_at < run.started_at:
            raise AiResultIntegrityError(
                f"AI result timestamp precedes active run for {parameter_id}"
            )

        if result.verdict is AiVerdict.SYSTEM_ERROR:
            if (
                result.comparison_result is not None
                or result.left_raw is not None
                or result.right_raw is not None
                or result.extraction_reliable
                or result.reason is None
                or result.reason.strip() == ""
            ):
                raise AiResultIntegrityError(
                    f"Malformed AI system-error result for {parameter_id}"
                )
            return

        if result.comparison_result is None:
            raise AiResultIntegrityError(
                f"AI result has no deterministic comparison for {parameter_id}"
            )
        try:
            recomputed = compare_values(result.left_raw, result.right_raw)
        except (TypeError, ValueError) as error:
            raise AiResultIntegrityError(
                f"AI raw values are invalid for {parameter_id}: {error}"
            ) from error
        if recomputed != result.comparison_result:
            raise AiResultIntegrityError(
                f"Stored comparison differs from recomputed result for {parameter_id}"
            )

        if (
            not result.extraction_reliable
            or recomputed.kind is ComparisonKind.MISSING_VALUE
        ):
            expected_verdict = AiVerdict.UNABLE_TO_JUDGE
            if result.reason is None or result.reason.strip() == "":
                raise AiResultIntegrityError(
                    f"Unreliable AI result has no reason for {parameter_id}"
                )
        elif recomputed.exact_match:
            expected_verdict = AiVerdict.SAME
        else:
            expected_verdict = AiVerdict.DIFFERENT

        if result.verdict is not expected_verdict:
            raise AiResultIntegrityError(
                f"AI verdict is inconsistent with deterministic evidence for {parameter_id}"
            )

    @staticmethod
    def _check_reason(reason: str | None) -> str | None:
        return None if reason is None else _require_text("reason", reason)

    def _now(self) -> datetime:
        return _require_aware_datetime("clock result", self._clock())
