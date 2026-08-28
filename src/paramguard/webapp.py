"""Loopback-only, human-first Web demonstration for ParamGuard.

The Web layer is intentionally small and uses :mod:`http.server`.  It is a
learning PoC, not a production, GxP-validated, Part 11-compliant, or
authentication-capable service.  Its most important boundary is structural:
before every first-human field is decided and locked, no public DTO or page
contains AI execution, OCR result, or routing data.

First-review mutations are bound to the immutable evidence-manifest hash and
an optimistic revision.  Field writes from the bundled browser additionally
use a payload-bound idempotent command ID so an exact retry after a lost
response does not become a false stale-page conflict.  Post-lock
targeted-recheck mutations additionally bind the source task, assignment, and
complete source snapshot.  These controls protect a reviewer from a stale
browser tab, but they are not a replacement for a transactional database,
append-only audit, or authenticated user sessions.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import ipaddress
import json
from pathlib import Path
import re
import secrets
from threading import BoundedSemaphore, RLock
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit

from PIL import Image

from .comparison import ComparisonKind
from .evidence import EvidenceRole
from .image_quality import (
    DEFAULT_IMAGE_QUALITY_CONFIG,
    ImageQualityAssessment,
    ImageQualityFlag,
    assess_image_quality_bytes,
)
from .identity import Actor, PrincipalKind, Role
from .ocr import OcrFieldResult, TesseractOcrEngine
from .review_policy import INTERVIEW_TARGETED_RECHECK, ReviewNextStep
from .routing import ImageQuality, ReviewSignals, RoutingDecision, route_parameter
from .synthetic import RenderedSyntheticCase, default_clean_case, render_case
from .template import FixedTemplate
from .targeted_review import (
    DuplicateTargetedCommandConflictError,
    IncompleteTargetedReviewError,
    LockedParameterRoutingContext,
    LockedRoutingContext,
    LockedTargetedReviewSubmission,
    StaleTargetedReviewRevisionError,
    TargetedAssignmentBindingError,
    TargetedEvidenceBindingError,
    TargetedReasonRequiredError,
    TargetedReviewLockedError,
    TargetedReviewSession,
    TargetedReviewState,
    TargetedSnapshotBindingError,
    TargetedTaskBindingError,
    TargetedVerdict,
    UnauthorizedTargetedReviewerError,
    UnknownTargetedParameterError,
)
from .vision_pipeline import (
    OcrPairOutcome,
    build_tesseract_pipeline_spec,
    run_gated_ocr_pair,
)
from .workflow import (
    AiAssessment,
    HumanVerdict,
    ReviewState,
    ReviewTask,
)


MAX_JSON_BODY_BYTES = 32 * 1024
MAX_HUMAN_REASON_CHARACTERS = 500
MAX_TARGETED_REASON_CHARACTERS = 500
REQUEST_IO_TIMEOUT_SECONDS = 5.0
MAX_CONCURRENT_HTTP_REQUESTS = 16
MAX_TARGETED_MUTATIONS_PER_PARAMETER = 16
MAX_FIRST_REVIEW_COMMANDS_PER_PARAMETER = 16
MIN_TARGETED_MUTATION_BUDGET = 64
TARGETED_MUTATION_BUDGET_MULTIPLIER = 4
STATIC_TEMPLATE_PATH = Path(__file__).with_name("static") / "paramguard.html"
_WEB_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class WebDemoError(Exception):
    """Base class for failures safe for the HTTP adapter to classify."""


class MutationConflictError(WebDemoError):
    """The browser used stale evidence or an obsolete optimistic revision."""


class PublicStageUnavailableError(WebDemoError):
    """The requested function is unavailable in the current public stage."""


class InvalidWebRequestError(WebDemoError):
    """The request does not conform to the deliberately small API schema."""


class AssistiveCheckFailedError(WebDemoError):
    """The post-lock execution failed and remains fail-closed."""


class TargetedReviewIncompleteWebError(WebDemoError):
    """The server-computed targeted queue still has undecided items."""


class TargetedMutationLimitError(WebDemoError):
    """The bounded learning session refused unbounded decision revisions."""


class FirstReviewMutationLimitError(WebDemoError):
    """The bounded learning session refused unbounded first-review commands."""


@dataclass(frozen=True, slots=True)
class ImageAsset:
    content: bytes
    media_type: str = "image/png"


PipelineRunner = Callable[..., OcrPairOutcome]


@dataclass(frozen=True, slots=True)
class _ServerHeldRoutingContextResolver:
    """Resolve exactly one server-created, immutable routing context.

    This object is constructed only after the completed OCR outcome has been
    validated.  It is deliberately not selected, populated, or parameterised
    by an HTTP request.  A production composition root would replace it with a
    write-once persistence adapter.
    """

    context: LockedRoutingContext

    def resolve_locked_context(
        self,
        *,
        task_id: str,
        evidence_manifest_hash: str,
        expected_parameter_ids: tuple[str, ...],
    ) -> LockedRoutingContext:
        if (
            task_id != self.context.task_id
            or evidence_manifest_hash != self.context.evidence_manifest_hash
            or expected_parameter_ids
            != tuple(item.parameter_id for item in self.context.parameters)
        ):
            raise ValueError("server-held routing context binding mismatch")
        return self.context


class ParamGuardWebSession:
    """One in-memory browser session bound to one immutable synthetic case."""

    def __init__(
        self,
        *,
        rendered_case: RenderedSyntheticCase,
        engine: TesseractOcrEngine,
        reviewer_id: str = "human:primary-reviewer",
        task_id: str | None = None,
        pipeline_runner: PipelineRunner = run_gated_ocr_pair,
        targeted_reviewer: Actor | None = None,
    ) -> None:
        if not isinstance(rendered_case, RenderedSyntheticCase):
            raise TypeError("rendered_case must be a RenderedSyntheticCase")
        if not isinstance(engine, TesseractOcrEngine):
            raise TypeError("engine must be a TesseractOcrEngine")
        if not callable(pipeline_runner):
            raise TypeError("pipeline_runner must be callable")
        if targeted_reviewer is None:
            # The interview-targeted profile does not establish identity
            # separation.  The learning demo therefore uses the same human by
            # default and labels the step accurately as a targeted recheck,
            # never as an independent or blind R2.
            targeted_reviewer = Actor(
                actor_id=reviewer_id,
                kind=PrincipalKind.HUMAN,
                roles=frozenset({Role.PRIMARY_REVIEWER}),
            )
        if type(targeted_reviewer) is not Actor:
            raise TypeError("targeted_reviewer must be an Actor")

        _validate_rendered_case_binding(rendered_case)

        self._rendered = rendered_case
        self._engine = engine
        self._template = rendered_case.template
        self._pipeline_runner = pipeline_runner
        self._targeted_reviewer = targeted_reviewer
        approved_spec = build_tesseract_pipeline_spec(
            engine=engine,
            template=self._template,
        )
        self._task = ReviewTask(
            # Synthetic benchmark case IDs may contain labels such as
            # "all-same" or "low-contrast".  Never derive a workflow identity
            # from that label, because the pre-lock browser could correlate it
            # with the expected result and lose reviewer independence.
            task_id=task_id or f"web-task-{secrets.token_hex(16)}",
            evidence_manifest=rendered_case.manifest,
            approved_pipeline_spec=approved_spec,
            reviewer_id=reviewer_id,
        )
        self._lock = RLock()
        self._revision = 0
        self._run_sequence = 0
        self._outcome: OcrPairOutcome | None = None
        self._targeted_review: TargetedReviewSession | None = None
        self._targeted_submission: LockedTargetedReviewSubmission | None = None
        self._targeted_undecided_parameter_ids: set[str] = set()
        self._targeted_parameter_ids: frozenset[str] = frozenset()
        self._targeted_successful_command_ids: set[str] = set()
        self._targeted_mutation_counts: dict[str, int] = {}
        self._targeted_mutation_budget = 0
        self._assistive_failure = False
        self._undecided_parameter_ids = set(self._task.expected_parameter_ids)
        self._first_review_command_receipts: dict[str, tuple[str, str]] = {}
        self._first_review_command_counts: dict[str, int] = {}
        self._lock_command_receipt: tuple[str, str, str] | None = None
        self._assistive_command_receipt: tuple[str, str, str] | None = None
        # A command ID identifies one logical mutation across the whole Web
        # aggregate, not merely within one endpoint.  Keeping the scope here
        # prevents a lost/late request from being reinterpreted as a different
        # side effect (for example, an R1 decision ID becoming an OCR run ID).
        self._successful_command_scopes: dict[str, str] = {}

    @property
    def task(self) -> ReviewTask:
        """Expose the domain task for tests and later application composition."""

        return self._task

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    @property
    def evidence_manifest_hash(self) -> str:
        return self._task.evidence_manifest_hash

    @property
    def is_first_review_open(self) -> bool:
        return self._task.state is ReviewState.HUMAN_REVIEW_OPEN

    def public_state(self) -> dict[str, Any]:
        """Return an allowlisted DTO appropriate to the current stage.

        The pre-lock branch is intentionally independent of all AI state.  It
        does not call any reveal method and it does not expose pipeline IDs,
        engine metadata, hidden result counts, routing, confidence, timing, or
        an inferred priority order.
        """

        with self._lock:
            if self._task.state is ReviewState.HUMAN_REVIEW_OPEN:
                return self._first_review_state()
            return self._post_lock_state()

    def record_human_decision(
        self,
        *,
        parameter_id: str,
        verdict: str,
        reason: str | None,
        evidence_manifest_hash: str,
        expected_revision: int,
        command_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            if type(parameter_id) is not str or type(verdict) is not str:
                raise InvalidWebRequestError(
                    "human parameter_id and verdict must be exact strings"
                )
            try:
                checked_verdict = HumanVerdict(verdict)
            except (TypeError, ValueError) as error:
                raise InvalidWebRequestError("invalid human verdict") from error
            if reason is not None and (
                type(reason) is not str
                or len(reason) > MAX_HUMAN_REASON_CHARACTERS
            ):
                raise InvalidWebRequestError("invalid human reason")
            if checked_verdict is HumanVerdict.SAME and reason is not None:
                raise InvalidWebRequestError("SAME verdict must not carry a reason")
            request_json: str | None = None
            if command_id is not None:
                if (
                    type(command_id) is not str
                    or _WEB_IDENTIFIER_PATTERN.fullmatch(command_id) is None
                ):
                    raise InvalidWebRequestError("invalid first-review command_id")
                self._require_command_scope(command_id, "R1_DECISION")
                request_json = json.dumps(
                    {
                        "command_id": command_id,
                        "evidence_manifest_hash": evidence_manifest_hash,
                        "expected_revision": expected_revision,
                        "parameter_id": parameter_id,
                        "reason": reason,
                        "verdict": verdict,
                    },
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                stored = self._first_review_command_receipts.get(command_id)
                if stored is not None:
                    stored_request, stored_receipt = stored
                    if stored_request != request_json:
                        raise MutationConflictError(
                            "first-review command_id payload conflict"
                        )
                    return json.loads(stored_receipt)
                if (
                    self._first_review_command_counts.get(parameter_id, 0)
                    >= MAX_FIRST_REVIEW_COMMANDS_PER_PARAMETER
                ):
                    raise FirstReviewMutationLimitError(
                        "first-review mutation limit reached"
                    )
            self._require_mutation_binding(
                evidence_manifest_hash=evidence_manifest_hash,
                expected_revision=expected_revision,
            )
            if self._task.state is not ReviewState.HUMAN_REVIEW_OPEN:
                raise PublicStageUnavailableError("stage unavailable")
            decision = self._task.record_human_decision(
                parameter_id=parameter_id,
                verdict=checked_verdict,
                reason=reason,
                evidence_manifest_hash=self._task.evidence_manifest_hash,
            )
            self._undecided_parameter_ids.discard(decision.parameter_id)
            self._revision += 1
            # A 1,000-field review must not return and repaint all 1,000 fields
            # after every click.  This fixed-schema delta is O(1) in field count
            # and contains only the reviewer's own just-recorded information.
            receipt = {
                "stage": "HUMAN_REVIEW_OPEN",
                "revision": self._revision,
                "decision": {
                    "parameter_id": decision.parameter_id,
                    "verdict": decision.verdict.value,
                    "reason": decision.reason,
                },
                "missing_count": len(self._undecided_parameter_ids),
                "lock_available": not self._undecided_parameter_ids,
            }
            if command_id is not None and request_json is not None:
                self._first_review_command_receipts[command_id] = (
                    request_json,
                    json.dumps(
                        receipt,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                )
                self._first_review_command_counts[parameter_id] = (
                    self._first_review_command_counts.get(parameter_id, 0) + 1
                )
                self._successful_command_scopes[command_id] = "R1_DECISION"
            return receipt

    def lock_human_review(
        self,
        *,
        evidence_manifest_hash: str,
        expected_revision: int,
        command_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            request_json: str | None = None
            if command_id is not None:
                if (
                    type(command_id) is not str
                    or _WEB_IDENTIFIER_PATTERN.fullmatch(command_id) is None
                ):
                    raise InvalidWebRequestError("invalid first-review lock command_id")
                self._require_command_scope(command_id, "R1_LOCK")
                request_json = json.dumps(
                    {
                        "command_id": command_id,
                        "evidence_manifest_hash": evidence_manifest_hash,
                        "expected_revision": expected_revision,
                    },
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                stored = self._lock_command_receipt
                if stored is not None and stored[0] == command_id:
                    if stored[1] != request_json:
                        raise MutationConflictError(
                            "first-review lock command_id payload conflict"
                        )
                    return json.loads(stored[2])
            self._require_mutation_binding(
                evidence_manifest_hash=evidence_manifest_hash,
                expected_revision=expected_revision,
            )
            if self._task.state is not ReviewState.HUMAN_REVIEW_OPEN:
                raise PublicStageUnavailableError("stage unavailable")
            self._task.lock_human_review(
                evidence_manifest_hash=self._task.evidence_manifest_hash
            )
            self._revision += 1
            state = self._post_lock_state()
            if command_id is not None and request_json is not None:
                self._lock_command_receipt = (
                    command_id,
                    request_json,
                    json.dumps(
                        state,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                )
                self._successful_command_scopes[command_id] = "R1_LOCK"
            return state

    def run_assistive_check(
        self,
        *,
        evidence_manifest_hash: str,
        expected_revision: int,
        command_id: str | None = None,
    ) -> dict[str, Any]:
        """Synchronously execute the real gated pipeline after the human lock."""

        with self._lock:
            request_json: str | None = None
            if command_id is not None:
                if (
                    type(command_id) is not str
                    or _WEB_IDENTIFIER_PATTERN.fullmatch(command_id) is None
                ):
                    raise InvalidWebRequestError("invalid assistive command_id")
                self._require_command_scope(command_id, "ASSISTIVE_CHECK")
                request_json = json.dumps(
                    {
                        "command_id": command_id,
                        "evidence_manifest_hash": evidence_manifest_hash,
                        "expected_revision": expected_revision,
                    },
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                stored = self._assistive_command_receipt
                if stored is not None and stored[0] == command_id:
                    if stored[1] != request_json:
                        raise MutationConflictError(
                            "assistive command_id payload conflict"
                        )
                    return json.loads(stored[2])
            self._require_mutation_binding(
                evidence_manifest_hash=evidence_manifest_hash,
                expected_revision=expected_revision,
            )
            if self._task.state is not ReviewState.HUMAN_REVIEW_LOCKED:
                raise PublicStageUnavailableError("stage unavailable")

            self._run_sequence += 1
            run_id = f"web-run-{self._run_sequence:04d}"
            try:
                self._task.queue_ai_review(
                    run_id=run_id,
                    evidence_manifest_hash=self._task.evidence_manifest_hash,
                    pipeline_spec_hash=self._task.approved_pipeline_spec.spec_hash,
                )
                self._task.start_ai_review(
                    run_id=run_id,
                    evidence_manifest_hash=self._task.evidence_manifest_hash,
                )
                outcome = self._pipeline_runner(
                    self._task,
                    run_id=run_id,
                    left_image_path=self._rendered.left_image_path,
                    right_image_path=self._rendered.right_image_path,
                    engine=self._engine,
                    template=self._template,
                )
                if not isinstance(outcome, OcrPairOutcome):
                    raise TypeError("pipeline runner returned an invalid outcome")
                self._validate_completed_outcome(outcome)
                targeted_review = self._compose_targeted_review(outcome)
            except Exception as error:
                # Queue/start may already have mutated the domain task.  Advance
                # the Web revision and latch the failure so a stale retry cannot
                # accidentally start a second execution against partial state.
                self._assistive_failure = True
                self._revision += 1
                raise AssistiveCheckFailedError(
                    "assistive check failed closed"
                ) from error

            self._outcome = outcome
            self._targeted_review = targeted_review
            self._targeted_undecided_parameter_ids = {
                item.parameter_id
                for item in targeted_review.queue_plan().targeted_items
            }
            self._targeted_parameter_ids = frozenset(
                self._targeted_undecided_parameter_ids
            )
            self._targeted_successful_command_ids.clear()
            self._targeted_mutation_counts.clear()
            self._targeted_mutation_budget = max(
                MIN_TARGETED_MUTATION_BUDGET,
                len(self._targeted_parameter_ids)
                * TARGETED_MUTATION_BUDGET_MULTIPLIER,
            )
            self._revision += 1
            state = self._post_lock_state()
            if command_id is not None and request_json is not None:
                self._assistive_command_receipt = (
                    command_id,
                    request_json,
                    json.dumps(
                        state,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                )
                self._successful_command_scopes[command_id] = "ASSISTIVE_CHECK"
            return state

    def _require_command_scope(self, command_id: str, scope: str) -> None:
        existing = self._successful_command_scopes.get(command_id)
        if existing is not None and existing != scope:
            raise MutationConflictError("command_id was already used by another mutation")

    def exception_inbox(self) -> dict[str, Any]:
        """Expose the real targeted aggregate without implying final closure."""

        with self._lock:
            if self._outcome is None or self._targeted_review is None:
                raise PublicStageUnavailableError("stage unavailable")
            targeted = self._targeted_review
            plan = targeted.queue_plan()
            decisions = targeted.own_decisions(actor=self._targeted_reviewer)
            items = [
                {
                    "parameter_id": item.parameter_id,
                    "reasons": [reason.value for reason in item.reasons],
                    "primary_verdict": item.primary_verdict.value,
                    "ai_verdict": item.ai_verdict.value,
                    "comparison_kind": item.comparison_kind.value,
                    "next_step": item.next_step.value,
                    "decision": None
                    if item.parameter_id not in decisions
                    else {
                        "verdict": decisions[item.parameter_id].verdict.value,
                        "reason": decisions[item.parameter_id].reason,
                        "closes_exception": False,
                        "automatic_release_allowed": False,
                    },
                    "automatic_release_allowed": False,
                }
                for item in plan.targeted_items
            ]
            qa_referrals = [
                {
                    "parameter_id": item.parameter_id,
                    "reasons": [reason.value for reason in item.reasons],
                    "next_step": item.next_step.value,
                    "automatic_release_allowed": False,
                }
                for item in plan.qa_referrals
            ]
            targeted_is_locked = targeted.state is TargetedReviewState.LOCKED
            has_exception = bool(items or qa_referrals)
            return {
                "status": (
                    "TARGETED_RECHECK_LOCKED_WAITING_DOWNSTREAM_HUMAN"
                    if targeted_is_locked
                    else "TARGETED_RECHECK_OPEN"
                ),
                "exception_detection": (
                    "EXCEPTIONS_DETECTED"
                    if has_exception
                    else "NO_EXCEPTION_DETECTED_WAITING_FINAL_HUMAN_CONFIRMATION"
                ),
                "targeted_component_implemented": True,
                "independent_blind_second_review": False,
                "workflow_complete": False,
                "automatic_release_allowed": False,
                "final_human_decision_required": True,
                "task_id": targeted.task_id,
                "assignment_id": targeted.assignment_id,
                "evidence_manifest_hash": targeted.evidence_manifest_hash,
                "source_snapshot_sha256": targeted.source_snapshot_sha256,
                "profile_id": plan.profile_id.value,
                "profile_version": plan.profile_version,
                "profile_content_sha256": plan.profile_content_sha256,
                "routing_context_id": plan.routing_context_id,
                "routing_context_version": plan.routing_context_version,
                "routing_context_sha256": plan.routing_context_sha256,
                "assigned_reviewer_id": plan.assigned_reviewer_id,
                # This process supplies the configured Actor to the domain, but
                # the local HTTP adapter has no login/session authenticator.  Do
                # not mistake server-held attribution for verified identity.
                "request_actor_authenticated": False,
                "actor_authentication_status": "NOT_IMPLEMENTED_LOCAL_DEMO",
                "same_reviewer_as_r1": (
                    plan.assigned_reviewer_id == self._task.reviewer_id
                ),
                "revision": targeted.revision,
                "missing_count": len(self._targeted_undecided_parameter_ids),
                "lock_available": (
                    not targeted_is_locked
                    and not self._targeted_undecided_parameter_ids
                ),
                "targeted_decision_count": len(decisions),
                "qa_referral_count": len(qa_referrals),
                "no_exception_count": len(plan.no_exception_parameter_ids),
                "notice": (
                    "This is a post-lock targeted exception recheck, not an "
                    "independent blind second review. SAME does not close an "
                    "exception. QA disposition, final human confirmation, audit, "
                    "durable storage, and real IAM are not integrated in this Web "
                    "PoC. No-exception detection is never a release decision."
                ),
                "items": items,
                "qa_referrals": qa_referrals,
                "submission": None
                if self._targeted_submission is None
                else {
                    "submission_hash": (
                        self._targeted_submission.submission_hash
                    ),
                    "requires_qa": self._targeted_submission.requires_qa,
                    "automatic_release_allowed": False,
                    "final_human_confirmation_required": True,
                },
            }

    def record_targeted_decision(
        self,
        *,
        task_id: str,
        assignment_id: str,
        evidence_manifest_hash: str,
        source_snapshot_sha256: str,
        parameter_id: str,
        verdict: str,
        reason: str,
        command_id: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """Record one targeted observation and return an O(1) delta receipt."""

        with self._lock:
            targeted = self._require_targeted_review()
            if any(
                type(value) is not str
                for value in (
                    task_id,
                    assignment_id,
                    evidence_manifest_hash,
                    source_snapshot_sha256,
                    parameter_id,
                    verdict,
                    command_id,
                )
            ):
                raise InvalidWebRequestError(
                    "targeted scalar bindings must be exact strings"
                )
            if type(reason) is not str or not 0 < len(reason) <= (
                MAX_TARGETED_REASON_CHARACTERS
            ):
                raise InvalidWebRequestError("invalid targeted reason")
            if _WEB_IDENTIFIER_PATTERN.fullmatch(command_id) is None:
                raise InvalidWebRequestError("invalid targeted command ID")
            self._require_command_scope(command_id, "TARGETED_DECISION")
            if parameter_id not in self._targeted_parameter_ids:
                raise InvalidWebRequestError("invalid targeted parameter")
            self._require_targeted_mutation_binding(
                targeted,
                task_id=task_id,
                assignment_id=assignment_id,
                evidence_manifest_hash=evidence_manifest_hash,
                source_snapshot_sha256=source_snapshot_sha256,
                expected_revision=expected_revision,
            )
            try:
                checked_verdict = TargetedVerdict(verdict)
            except (TypeError, ValueError) as error:
                raise InvalidWebRequestError("invalid targeted verdict") from error

            # TargetedReviewSession intentionally retains decision history and
            # idempotency records.  Without a Web boundary an unauthenticated
            # local process could revise one field forever and grow both maps
            # without limit.  Exact retries of already-successful commands remain
            # available even when the finite learning-session budget is reached.
            known_command = command_id in self._targeted_successful_command_ids
            if not known_command and expected_revision != targeted.revision:
                raise MutationConflictError("targeted mutation conflict")
            if not known_command and (
                len(self._targeted_successful_command_ids)
                >= self._targeted_mutation_budget
                or self._targeted_mutation_counts.get(parameter_id, 0)
                >= MAX_TARGETED_MUTATIONS_PER_PARAMETER
            ):
                raise TargetedMutationLimitError(
                    "targeted mutation limit reached; reload cannot expand it"
                )
            revision_before = targeted.revision
            try:
                decision = targeted.record_decision(
                    actor=self._targeted_reviewer,
                    task_id=task_id,
                    assignment_id=assignment_id,
                    evidence_manifest_hash=evidence_manifest_hash,
                    source_snapshot_sha256=source_snapshot_sha256,
                    parameter_id=parameter_id,
                    verdict=checked_verdict,
                    reason=reason,
                    command_id=command_id,
                    expected_revision=expected_revision,
                )
            except (
                StaleTargetedReviewRevisionError,
                DuplicateTargetedCommandConflictError,
                TargetedTaskBindingError,
                TargetedAssignmentBindingError,
                TargetedEvidenceBindingError,
                TargetedSnapshotBindingError,
            ) as error:
                raise MutationConflictError("targeted mutation conflict") from error
            except TargetedReviewLockedError as error:
                raise PublicStageUnavailableError("stage unavailable") from error
            except (
                UnknownTargetedParameterError,
                TargetedReasonRequiredError,
                TypeError,
                ValueError,
            ) as error:
                raise InvalidWebRequestError("invalid targeted request") from error

            if targeted.revision != revision_before:
                self._targeted_successful_command_ids.add(command_id)
                self._targeted_mutation_counts[decision.parameter_id] = (
                    self._targeted_mutation_counts.get(decision.parameter_id, 0)
                    + 1
                )
                self._successful_command_scopes[command_id] = (
                    "TARGETED_DECISION"
                )
            self._targeted_undecided_parameter_ids.discard(
                decision.parameter_id
            )
            return {
                "stage": "TARGETED_RECHECK_OPEN",
                "revision": targeted.revision,
                "decision": {
                    "parameter_id": decision.parameter_id,
                    "verdict": decision.verdict.value,
                    "reason": decision.reason,
                    "closes_exception": False,
                    "automatic_release_allowed": False,
                },
                "missing_count": len(self._targeted_undecided_parameter_ids),
                "lock_available": not self._targeted_undecided_parameter_ids,
                "workflow_complete": False,
                "automatic_release_allowed": False,
                "final_human_decision_required": True,
            }

    def lock_targeted_review(
        self,
        *,
        task_id: str,
        assignment_id: str,
        evidence_manifest_hash: str,
        source_snapshot_sha256: str,
        command_id: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """Freeze targeted decisions without approving or releasing the task."""

        with self._lock:
            targeted = self._require_targeted_review()
            if any(
                type(value) is not str
                for value in (
                    task_id,
                    assignment_id,
                    evidence_manifest_hash,
                    source_snapshot_sha256,
                    command_id,
                )
            ):
                raise InvalidWebRequestError(
                    "targeted scalar bindings must be exact strings"
                )
            if _WEB_IDENTIFIER_PATTERN.fullmatch(command_id) is None:
                raise InvalidWebRequestError("invalid targeted command ID")
            self._require_command_scope(command_id, "TARGETED_LOCK")
            self._require_targeted_mutation_binding(
                targeted,
                task_id=task_id,
                assignment_id=assignment_id,
                evidence_manifest_hash=evidence_manifest_hash,
                source_snapshot_sha256=source_snapshot_sha256,
                expected_revision=expected_revision,
            )
            try:
                submission = targeted.lock(
                    actor=self._targeted_reviewer,
                    task_id=task_id,
                    assignment_id=assignment_id,
                    evidence_manifest_hash=evidence_manifest_hash,
                    source_snapshot_sha256=source_snapshot_sha256,
                    command_id=command_id,
                    expected_revision=expected_revision,
                )
            except (
                StaleTargetedReviewRevisionError,
                DuplicateTargetedCommandConflictError,
                TargetedTaskBindingError,
                TargetedAssignmentBindingError,
                TargetedEvidenceBindingError,
                TargetedSnapshotBindingError,
            ) as error:
                raise MutationConflictError("targeted mutation conflict") from error
            except IncompleteTargetedReviewError as error:
                raise TargetedReviewIncompleteWebError(
                    "targeted review is incomplete"
                ) from error
            except TargetedReviewLockedError as error:
                raise PublicStageUnavailableError("stage unavailable") from error
            except (TypeError, ValueError) as error:
                raise InvalidWebRequestError("invalid targeted request") from error

            self._targeted_submission = submission
            self._successful_command_scopes[command_id] = "TARGETED_LOCK"
            plan = targeted.queue_plan()
            return {
                "stage": "TARGETED_RECHECK_LOCKED_WAITING_DOWNSTREAM_HUMAN",
                "revision": targeted.revision,
                "submission_hash": submission.submission_hash,
                "targeted_decision_count": len(submission.decisions),
                "qa_referral_count": len(plan.qa_referrals),
                "no_exception_count": len(plan.no_exception_parameter_ids),
                "requires_qa": submission.requires_qa,
                "workflow_complete": False,
                "automatic_release_allowed": False,
                "final_human_decision_required": True,
            }

    def _require_targeted_review(self) -> TargetedReviewSession:
        if self._targeted_review is None or self._outcome is None:
            raise PublicStageUnavailableError("stage unavailable")
        return self._targeted_review

    @staticmethod
    def _require_targeted_mutation_binding(
        targeted: TargetedReviewSession,
        *,
        task_id: str,
        assignment_id: str,
        evidence_manifest_hash: str,
        source_snapshot_sha256: str,
        expected_revision: int,
    ) -> None:
        if type(expected_revision) is not int or expected_revision < 0:
            raise InvalidWebRequestError(
                "expected_revision must be a non-negative exact integer"
            )
        if (
            task_id != targeted.task_id
            or assignment_id != targeted.assignment_id
            or evidence_manifest_hash != targeted.evidence_manifest_hash
            or source_snapshot_sha256 != targeted.source_snapshot_sha256
        ):
            raise MutationConflictError("targeted mutation conflict")

    def _compose_targeted_review(
        self, outcome: OcrPairOutcome
    ) -> TargetedReviewSession:
        """Composition-root wiring performed only after verified AI completion."""

        if self._task.state is not ReviewState.AI_REVIEW_COMPLETE:
            raise TypeError("targeted review requires a completed source task")
        quality = _locked_routing_quality(outcome)
        context = LockedRoutingContext(
            context_id=f"web-routing-context-{self._run_sequence:04d}",
            context_version="synthetic-web-v1",
            task_id=self._task.task_id,
            evidence_manifest_hash=self._task.evidence_manifest_hash,
            locked_at=datetime.now(timezone.utc),
            parameters=tuple(
                LockedParameterRoutingContext(
                    parameter_id=region.parameter_id,
                    is_critical=region.critical,
                    image_quality=quality,
                    # The validated fixed-template runner already proved exact
                    # schema coverage.  A future persisted registration/schema
                    # adapter must populate structural issues here.
                    field_issues=(),
                )
                for region in self._template.regions
            ),
        )
        resolver = _ServerHeldRoutingContextResolver(context)
        return TargetedReviewSession(
            targeted_case_id=f"web-targeted-case-{self._run_sequence:04d}",
            source_review_task=self._task,
            routing_context_resolver=resolver,
            profile=INTERVIEW_TARGETED_RECHECK,
            assignment_id=f"web-targeted-assignment-{self._run_sequence:04d}",
            assigned_reviewer=self._targeted_reviewer,
        )

    def image_asset(self, *, side: str, asset_name: str) -> ImageAsset:
        """Read only an explicitly allowlisted, manifest-bound image or ROI."""

        if side not in {"left", "right"}:
            raise FileNotFoundError("unknown evidence side")
        path = (
            self._rendered.left_image_path
            if side == "left"
            else self._rendered.right_image_path
        )
        role = (
            EvidenceRole.LEFT_PHOTO
            if side == "left"
            else EvidenceRole.RIGHT_SCREENSHOT
        )
        artifact = next(
            item for item in self._task.evidence_manifest.artifacts if item.role is role
        )
        content = artifact.read_verified_bytes(path)
        if asset_name == "full.png":
            return ImageAsset(content=content)

        if not asset_name.endswith(".png"):
            raise FileNotFoundError("unknown evidence asset")
        parameter_id = asset_name[:-4]
        try:
            region = self._template.region_for(parameter_id)
        except (KeyError, TypeError, ValueError) as error:
            raise FileNotFoundError("unknown evidence asset") from error
        with Image.open(BytesIO(content)) as source:
            if source.size != (self._template.width, self._template.height):
                raise ValueError("bound evidence dimensions no longer match template")
            box = region.value_box
            crop = source.crop((box.left, box.top, box.right, box.bottom))
            output = BytesIO()
            crop.save(output, format="PNG", optimize=False)
        return ImageAsset(content=output.getvalue())

    def render_first_review_html(self, *, nonce: str) -> str:
        if self._task.state is not ReviewState.HUMAN_REVIEW_OPEN:
            raise PublicStageUnavailableError("stage unavailable")
        template_text = STATIC_TEMPLATE_PATH.read_text(encoding="utf-8")
        field_rows = "\n".join(
            self._first_review_field_html(region.parameter_id, region.display_label)
            for region in self._template.regions
        )
        state = self._first_review_state()
        bootstrap = {
            "evidence_manifest_hash": state["evidence_manifest_hash"],
            "revision": state["revision"],
            "fields": state["fields"],
            "missing_count": len(state["missing_parameter_ids"]),
            "lock_available": state["lock_available"],
        }
        return (
            template_text.replace("{{CSP_NONCE}}", escape(nonce, quote=True))
            .replace("{{FIELD_ROWS}}", field_rows)
            .replace("{{BOOTSTRAP_JSON}}", _safe_embedded_json(bootstrap))
        )

    def render_post_lock_html(self, *, nonce: str) -> str:
        if self._task.state is ReviewState.HUMAN_REVIEW_OPEN:
            raise PublicStageUnavailableError("stage unavailable")
        state = self._post_lock_state()
        result_section = self._result_section_html()
        targeted_section = self._targeted_section_html()
        button = ""
        if self._task.state is ReviewState.HUMAN_REVIEW_LOCKED:
            button = (
                '<button id="run-ai-assistive-check" class="primary" type="button">'
                '运行 AI 辅助核验（锁后）</button>'
            )
        bootstrap_payload: dict[str, Any] = {
            "evidence_manifest_hash": state["evidence_manifest_hash"],
            "revision": state["revision"],
        }
        if self._targeted_review is not None:
            inbox = self.exception_inbox()
            bootstrap_payload["targeted"] = {
                key: inbox[key]
                for key in (
                    "task_id",
                    "assignment_id",
                    "evidence_manifest_hash",
                    "source_snapshot_sha256",
                    "revision",
                    "missing_count",
                    "lock_available",
                )
            }
        bootstrap = _safe_embedded_json(bootstrap_payload)
        return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ParamGuard — 锁后辅助核验</title>
  <style nonce="{escape(nonce, quote=True)}">
    :root {{ color-scheme: light; font-family: Inter, system-ui, sans-serif; }}
    body {{ margin: 0; background: #f4f6f8; color: #16202a; }}
    main {{ max-width: 1160px; margin: 0 auto; padding: 28px; }}
    .banner {{ border: 3px solid #9b2c2c; background: #fff5f5; padding: 18px;
      border-radius: 12px; font-weight: 800; font-size: 1.1rem; }}
    .panel {{ margin-top: 18px; background: white; border: 1px solid #ccd3da;
      border-radius: 12px; padding: 20px; }}
    button {{ padding: 10px 14px; border: 1px solid #77838e; border-radius: 8px;
      background: white; color: #16202a; font-weight: 700; cursor: pointer; }}
    button.primary {{ margin-top: 16px; border: 0; background: #173f67;
      color: white; font-weight: 750; }}
    button:disabled {{ cursor: not-allowed; opacity: .48; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ border-bottom: 1px solid #d9dee3; padding: 10px; text-align: left;
      vertical-align: top; }}
    .targeted-card {{ margin-top: 14px; padding: 16px; border: 1px solid #ccd3da;
      border-radius: 10px; }}
    .targeted-card input {{ width: 100%; margin: 8px 0; padding: 9px;
      border: 1px solid #8d99a4; border-radius: 7px; }}
    .verdicts {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .selected {{ border: 3px solid #173f67; }}
    code {{ overflow-wrap: anywhere; }}
    .muted {{ color: #52616f; }} .error {{ color: #8b1e1e; font-weight: 700; }}
  </style>
</head>
<body>
<main>
  <h1>锁后辅助核验</h1>
  <div class="banner">⚠ AI 只提供辅助证据，不能自动放行。最终结论必须由授权人员作出。</div>
  <section class="panel">
    <p>人工首检已经完整锁定。本地辅助处理在此之后才能启动。</p>
    {button}
    <p id="request-status" class="muted" role="status"></p>
  </section>
  {result_section}
  {targeted_section}
  <p class="muted">学习 PoC；仅使用合成数据；不是经过验证的生产系统。</p>
</main>
<script id="bootstrap" type="application/json" nonce="{escape(nonce, quote=True)}">{bootstrap}</script>
<script nonce="{escape(nonce, quote=True)}">
(() => {{
  const data = JSON.parse(document.getElementById('bootstrap').textContent);
  const runButton = document.getElementById('run-ai-assistive-check');
  if (runButton) runButton.addEventListener('click', async () => {{
    runButton.disabled = true;
    const status = document.getElementById('request-status');
    status.textContent = '正在执行本地锁后辅助核验…';
    try {{
      const payload = {{
        evidence_manifest_hash: data.evidence_manifest_hash,
        expected_revision: data.revision,
        command_id: commandId('assistive-check')
      }};
      const request = () => fetch('/api/assistive-check', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(payload)
      }});
      let response;
      try {{
        response = await request();
      }} catch (_) {{
        response = await request();
      }}
      if (!response.ok) throw new Error('request failed');
      window.location.reload();
    }} catch (_) {{
      status.textContent = '辅助核验未完成；系统已失败关闭，请转人工处理。';
      status.className = 'error';
    }}
  }});

  if (!data.targeted) return;
  let targetedRevision = data.targeted.revision;
  let targetedMutationPending = false;
  const targetedError = document.getElementById('targeted-request-error');
  const targetedCompletion = document.getElementById('targeted-completion-status');
  const targetedLock = document.getElementById('lock-targeted-review');
  const targetedCards = Array.from(document.querySelectorAll('.targeted-card'));

  function commandId(prefix) {{
    const value = globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${{Date.now()}}-${{Math.random().toString(16).slice(2)}}`;
    return `${{prefix}}-${{value}}`;
  }}

  async function postJson(path, body) {{
    const response = await fetch(path, {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(body)
    }});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'REQUEST_FAILED');
    return result;
  }}

  function bindings(command) {{
    return {{
      task_id: data.targeted.task_id,
      assignment_id: data.targeted.assignment_id,
      evidence_manifest_hash: data.targeted.evidence_manifest_hash,
      source_snapshot_sha256: data.targeted.source_snapshot_sha256,
      expected_revision: targetedRevision,
      command_id: command
    }};
  }}

  function applyTargetedReceipt(receipt, card) {{
    targetedRevision = receipt.revision;
    card.querySelectorAll('[data-targeted-verdict]').forEach(
      button => button.classList.remove('selected')
    );
    const selected = card.querySelector(
      `[data-targeted-verdict="${{receipt.decision.verdict}}"]`
    );
    if (!selected) throw new Error('UNKNOWN_TARGETED_RECEIPT_VERDICT');
    selected.classList.add('selected');
    card.querySelector('.targeted-decision-status').textContent =
      `已记录：${{receipt.decision.verdict}}；不关闭原异常`;
    if (targetedLock) targetedLock.disabled = !receipt.lock_available;
    if (targetedCompletion) targetedCompletion.textContent = receipt.lock_available
      ? '定向项已全部记录；可锁定此快照，但仍不表示放行。'
      : `还有 ${{receipt.missing_count}} 个定向异常需复核。`;
  }}

  targetedCards.forEach(card => {{
    card.querySelectorAll('[data-targeted-verdict]').forEach(button => {{
      button.addEventListener('click', async () => {{
        if (targetedMutationPending) return;
        const reason = card.querySelector('.targeted-reason').value.trim();
        if (!reason) {{
          targetedError.textContent = '定向异常的任何结论（包括 SAME）都必须填写理由。';
          return;
        }}
        targetedMutationPending = true;
        targetedError.textContent = '';
        try {{
          const result = await postJson('/api/targeted-decision', {{
            ...bindings(commandId('targeted-decision')),
            parameter_id: card.dataset.parameterId,
            verdict: button.dataset.targetedVerdict,
            reason
          }});
          applyTargetedReceipt(result.receipt, card);
        }} catch (_) {{
          targetedError.textContent = '定向复核未保存；可能是过期页面或绑定冲突，请重新加载后核对。';
        }} finally {{
          targetedMutationPending = false;
        }}
      }});
    }});
  }});

  if (targetedLock) targetedLock.addEventListener('click', async () => {{
    if (targetedMutationPending) return;
    targetedMutationPending = true;
    targetedLock.disabled = true;
    targetedError.textContent = '';
    try {{
      await postJson('/api/targeted-lock', bindings(commandId('targeted-lock')));
      window.location.reload();
    }} catch (_) {{
      targetedError.textContent = '无法锁定定向复核：请确认队列已完整、绑定正确且页面未过期。';
      targetedLock.disabled = false;
    }} finally {{
      targetedMutationPending = false;
    }}
  }});
}})();
</script>
</body>
</html>"""

    def _first_review_state(self) -> dict[str, Any]:
        decisions = self._task.human_decisions()
        fields = []
        for region in self._template.regions:
            decision = decisions.get(region.parameter_id)
            fields.append(
                {
                    "parameter_id": region.parameter_id,
                    "display_label": region.display_label,
                    "decision": None
                    if decision is None
                    else {
                        "verdict": decision.verdict.value,
                        "reason": decision.reason,
                    },
                }
            )
        missing = [
            parameter_id
            for parameter_id in self._task.expected_parameter_ids
            if parameter_id in self._undecided_parameter_ids
        ]
        return {
            "stage": "HUMAN_REVIEW_OPEN",
            "evidence_manifest_hash": self._task.evidence_manifest_hash,
            "revision": self._revision,
            "fields": fields,
            "missing_parameter_ids": missing,
            "lock_available": not missing,
        }

    def _post_lock_state(self) -> dict[str, Any]:
        human = self._task.human_decisions()
        base: dict[str, Any] = {
            "task_id": self._task.task_id,
            "stage": "HUMAN_REVIEW_LOCKED",
            "evidence_manifest_hash": self._task.evidence_manifest_hash,
            "revision": self._revision,
            "human_decisions": [
                {
                    "parameter_id": parameter_id,
                    "verdict": human[parameter_id].verdict.value,
                    "reason": human[parameter_id].reason,
                }
                for parameter_id in self._task.expected_parameter_ids
            ],
            "automatic_release_allowed": False,
            "notice": "AI is auxiliary only and cannot automatically release a task.",
        }
        if self._assistive_failure:
            base["stage"] = "POST_LOCK_PROCESSING_FAILED_CLOSED"
            base["check_available"] = False
            base["exception_inbox"] = {
                "status": "MANUAL_ESCALATION_REQUIRED",
                "targeted_component_implemented": False,
                "workflow_complete": False,
                "automatic_release_allowed": False,
                "final_human_decision_required": True,
            }
            return base
        if self._outcome is None:
            base["check_available"] = self._task.state is ReviewState.HUMAN_REVIEW_LOCKED
            return base

        base["stage"] = "ASSISTIVE_CHECK_COMPLETE"
        base["check_available"] = False
        routes = {item.parameter_id: item for item in self._outcome.routing}
        assert self._targeted_review is not None
        plan = self._targeted_review.queue_plan()
        process_steps = {
            item.parameter_id: item.next_step for item in plan.targeted_items
        }
        process_steps.update(
            {item.parameter_id: item.next_step for item in plan.qa_referrals}
        )
        process_steps.update(
            {
                parameter_id: (
                    ReviewNextStep.WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION
                )
                for parameter_id in plan.no_exception_parameter_ids
            }
        )
        base["assistive_results"] = [
            {
                "parameter_id": item.parameter_id,
                "verdict": item.verdict.value,
                "left_raw": item.left_raw,
                "right_raw": item.right_raw,
                "extraction_reliable": item.extraction_reliable,
                "comparison_kind": None
                if item.comparison_result is None
                else item.comparison_result.kind.value,
                "comparison_explanation": None
                if item.comparison_result is None
                else item.comparison_result.explanation,
                "route_reasons": [
                    reason.value for reason in routes[item.parameter_id].reasons
                ],
                "process_next_step": process_steps[item.parameter_id].value,
                "automatic_release_allowed": False,
            }
            for item in self._outcome.ai_assessments
        ]
        base["exception_inbox"] = self.exception_inbox()
        return base

    def _validate_completed_outcome(self, outcome: OcrPairOutcome) -> None:
        """Reject partial, stale, or forged runner output before publication."""

        if self._task.state is not ReviewState.AI_REVIEW_COMPLETE:
            raise TypeError("pipeline outcome was returned before domain completion")
        expected_ids = self._task.expected_parameter_ids
        if type(outcome.ai_assessments) is not tuple or type(outcome.routing) is not tuple:
            raise TypeError("pipeline outcome collections must be immutable tuples")

        persisted = self._task.revealed_ai_results()
        if any(type(item) is not AiAssessment for item in outcome.ai_assessments):
            raise TypeError("pipeline assessments contain an invalid type")
        if tuple(item.parameter_id for item in outcome.ai_assessments) != expected_ids:
            raise TypeError("pipeline assessments do not match the frozen schema")
        if any(
            item != persisted[parameter_id]
            for parameter_id, item in zip(expected_ids, outcome.ai_assessments)
        ):
            raise TypeError("pipeline assessments differ from completed domain results")
        if (
            tuple(item.parameter_id for item in outcome.routing) != expected_ids
            or any(type(item) is not RoutingDecision for item in outcome.routing)
        ):
            raise TypeError("pipeline routing does not match the frozen schema")

        actual_qualities = (outcome.left_quality, outcome.right_quality)
        for quality in actual_qualities:
            if type(quality) is not ImageQualityAssessment:
                raise TypeError("pipeline image quality has an invalid type")
            if type(quality.flags) is not tuple or any(
                not isinstance(flag, ImageQualityFlag) for flag in quality.flags
            ):
                raise TypeError("pipeline image-quality flags are invalid")

        # ImageQualityAssessment has intentionally lightweight domain fields.
        # A merely well-typed object is therefore not evidence that the approved
        # quality gate produced it. Recompute from the very bytes just checked,
        # not another opening of the same path between two digest checks.
        left_bytes, right_bytes = self._assert_current_evidence_bytes()
        expected_qualities = (
            assess_image_quality_bytes(
                left_bytes,
                template=self._template,
                config=DEFAULT_IMAGE_QUALITY_CONFIG,
            ),
            assess_image_quality_bytes(
                right_bytes,
                template=self._template,
                config=DEFAULT_IMAGE_QUALITY_CONFIG,
            ),
        )
        self._assert_current_evidence_bytes()
        if actual_qualities != expected_qualities:
            raise TypeError(
                "pipeline image quality differs from the bound quality gate"
            )

        self._validate_ocr_observations(outcome, persisted)

        quality_signal = _locked_routing_quality(outcome)

        human = self._task.human_decisions()
        regions = {
            region.parameter_id: region for region in self._template.regions
        }
        expected_routes = []
        for parameter_id in expected_ids:
            assessment = persisted[parameter_id]
            comparison_kind = (
                ComparisonKind.MISSING_VALUE
                if assessment.comparison_result is None
                else assessment.comparison_result.kind
            )
            expected_routes.append(
                route_parameter(
                    ReviewSignals(
                        parameter_id=parameter_id,
                        human_verdict=human[parameter_id].verdict,
                        ai_verdict=assessment.verdict,
                        comparison_kind=comparison_kind,
                        is_critical=regions[parameter_id].critical,
                        image_quality=quality_signal,
                    )
                )
            )
        if outcome.routing != tuple(expected_routes):
            raise TypeError("pipeline routing differs from deterministic routing")

    def _assert_current_evidence_bytes(self) -> tuple[bytes, bytes]:
        """Return immutable bytes that were actually checked against the manifest."""

        artifact_by_role = {
            artifact.role: artifact
            for artifact in self._task.evidence_manifest.artifacts
        }
        contents: list[bytes] = []
        for role, path in (
            (EvidenceRole.LEFT_PHOTO, self._rendered.left_image_path),
            (EvidenceRole.RIGHT_SCREENSHOT, self._rendered.right_image_path),
        ):
            content = artifact_by_role[role].read_verified_bytes(path)
            contents.append(content)
        return contents[0], contents[1]

    def _validate_ocr_observations(
        self,
        outcome: OcrPairOutcome,
        persisted: Mapping[str, AiAssessment],
    ) -> None:
        """Reject complete-looking outcomes with missing or replayed OCR DTOs."""

        if type(outcome.left_ocr) is not tuple or type(outcome.right_ocr) is not tuple:
            raise TypeError("pipeline OCR collections must be immutable tuples")
        left_present = bool(outcome.left_ocr)
        right_present = bool(outcome.right_ocr)
        if left_present != right_present:
            raise TypeError("pipeline returned only one side of OCR observations")
        if not left_present:
            if any(
                item.left_raw is not None
                or item.right_raw is not None
                or item.extraction_reliable
                for item in persisted.values()
            ):
                raise TypeError("pipeline omitted OCR observations used by results")
            return

        expected_ids = self._task.expected_parameter_ids
        if (
            tuple(item.parameter_id for item in outcome.left_ocr) != expected_ids
            or tuple(item.parameter_id for item in outcome.right_ocr) != expected_ids
            or any(
                type(item) is not OcrFieldResult
                for item in outcome.left_ocr + outcome.right_ocr
            )
        ):
            raise TypeError("pipeline OCR observations do not match the schema")
        if outcome.left_quality.flags or outcome.right_quality.flags:
            raise TypeError("pipeline returned OCR after the quality gate abstained")

        artifacts = {
            artifact.role: artifact
            for artifact in self._task.evidence_manifest.artifacts
        }
        expected_engine_version = self._task.approved_pipeline_spec.engine_version
        expected_config_hash = self._engine.config.content_sha256
        for left, right in zip(outcome.left_ocr, outcome.right_ocr):
            assessment = persisted[left.parameter_id]
            if (
                left.parameter_id != right.parameter_id
                or left.source_image_sha256
                != artifacts[EvidenceRole.LEFT_PHOTO].sha256
                or right.source_image_sha256
                != artifacts[EvidenceRole.RIGHT_SCREENSHOT].sha256
                or left.config_sha256 != expected_config_hash
                or right.config_sha256 != expected_config_hash
                or left.engine_version != expected_engine_version
                or right.engine_version != expected_engine_version
                or left.extracted_text != assessment.left_raw
                or right.extracted_text != assessment.right_raw
                or (left.reliable and right.reliable)
                is not assessment.extraction_reliable
            ):
                raise TypeError(
                    "pipeline OCR observations differ from bound AI results"
                )

    def _require_mutation_binding(
        self, *, evidence_manifest_hash: str, expected_revision: int
    ) -> None:
        if (
            type(evidence_manifest_hash) is not str
            or evidence_manifest_hash != self._task.evidence_manifest_hash
        ):
            raise MutationConflictError("evidence conflict")
        if type(expected_revision) is not int or expected_revision < 0:
            raise InvalidWebRequestError("expected_revision must be non-negative int")
        if expected_revision != self._revision:
            raise MutationConflictError("stale revision")

    @staticmethod
    def _first_review_field_html(parameter_id: str, display_label: str) -> str:
        safe_id = escape(parameter_id, quote=True)
        safe_label = escape(display_label)
        return f"""<article class="field-card" data-parameter-id="{safe_id}" tabindex="0">
  <h3>{safe_label} <code>{safe_id}</code></h3>
  <div class="roi-pair">
    <figure><figcaption>照片 A 对齐区域</figcaption><img loading="lazy" decoding="async" src="/evidence/left/{safe_id}.png" alt="{safe_label} 照片区域"></figure>
    <figure><figcaption>截图 A′ 对齐区域</figcaption><img loading="lazy" decoding="async" src="/evidence/right/{safe_id}.png" alt="{safe_label} 截图区域"></figure>
  </div>
  <label>异常或无法判断时填写理由
    <input class="reason" type="text" maxlength="{MAX_HUMAN_REASON_CHARACTERS}" autocomplete="off">
  </label>
  <div class="verdicts" role="group" aria-label="{safe_label} 人工判定">
    <button type="button" data-verdict="SAME">相同 (S)</button>
    <button type="button" data-verdict="DIFFERENT">不同 (D)</button>
    <button type="button" data-verdict="UNABLE_TO_JUDGE">无法判断 (U)</button>
  </div>
  <p class="decision-status" aria-live="polite">未记录</p>
</article>"""

    def _result_section_html(self) -> str:
        if self._assistive_failure:
            return """<section class="panel"><h2>失败关闭</h2>
<p class="error">锁后辅助处理没有完整产生结果。不得使用部分输出；请转人工/QA 处理。</p></section>"""
        if self._outcome is None:
            return """<section class="panel"><h2>辅助结果</h2>
<p>尚未运行。人工锁定记录不会被辅助输出覆盖。</p></section>"""

        routing = {item.parameter_id: item for item in self._outcome.routing}
        assert self._targeted_review is not None
        plan = self._targeted_review.queue_plan()
        next_steps = {
            item.parameter_id: item.next_step for item in plan.targeted_items
        }
        next_steps.update(
            {item.parameter_id: item.next_step for item in plan.qa_referrals}
        )
        next_steps.update(
            {
                parameter_id: (
                    ReviewNextStep.WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION
                )
                for parameter_id in plan.no_exception_parameter_ids
            }
        )
        rows: list[str] = []
        for item in self._outcome.ai_assessments:
            route = routing[item.parameter_id]
            comparison = (
                "SYSTEM_ERROR"
                if item.comparison_result is None
                else item.comparison_result.kind.value
            )
            reasons = ", ".join(reason.value for reason in route.reasons) or "无"
            rows.append(
                "<tr>"
                f"<td><code>{escape(item.parameter_id)}</code></td>"
                f"<td>{escape(item.left_raw if item.left_raw is not None else '∅')}</td>"
                f"<td>{escape(item.right_raw if item.right_raw is not None else '∅')}</td>"
                f"<td>{escape(item.verdict.value)}<br><small>{escape(comparison)}</small></td>"
                f"<td>{escape(next_steps[item.parameter_id].value)}"
                f"<br><small>{escape(reasons)}</small></td>"
                "<td><strong>否</strong></td>"
                "</tr>"
            )
        return """<section class="panel"><h2>辅助对比与人工路由</h2>
<p><strong>注意：</strong><code>NO_EXCEPTION_DETECTED</code> 仅表示辅助工具未检出异常，不表示已验证、已批准或已放行。</p>
<table><thead><tr><th>字段</th><th>照片提取</th><th>截图提取</th><th>确定性比较</th><th>下一人工路径</th><th>自动放行</th></tr></thead>
<tbody>""" + "".join(rows) + "</tbody></table></section>"

    def _targeted_section_html(self) -> str:
        if self._assistive_failure:
            return """<section class="panel"><h2>锁后人工处理</h2>
<p class="error">辅助处理失败后没有创建定向队列；必须转人工/QA，不得使用部分结果。</p></section>"""
        if self._targeted_review is None:
            return """<section class="panel"><h2>锁后人工异常复核</h2>
<p>尚未运行辅助核验，因此尚未生成任何锁后路由。</p></section>"""

        inbox = self.exception_inbox()
        qa_rows = "".join(
            "<tr>"
            f"<td><code>{escape(item['parameter_id'])}</code></td>"
            f"<td>{escape(item['next_step'])}</td>"
            f"<td>{escape(', '.join(item['reasons']) or '无')}</td>"
            "<td><strong>否</strong></td>"
            "</tr>"
            for item in inbox["qa_referrals"]
        )
        qa_section = (
            "<p>无 QA referral。</p>"
            if not qa_rows
            else """<table><thead><tr><th>字段</th><th>QA 路径</th><th>原因</th><th>自动放行</th></tr></thead>
<tbody>"""
            + qa_rows
            + "</tbody></table>"
        )

        if self._targeted_review.state is TargetedReviewState.LOCKED:
            decision_rows = "".join(
                "<tr>"
                f"<td><code>{escape(item['parameter_id'])}</code></td>"
                f"<td>{escape(item['decision']['verdict'])}</td>"
                f"<td>{escape(item['decision']['reason'])}</td>"
                "<td><strong>否</strong></td>"
                "</tr>"
                for item in inbox["items"]
            )
            decision_table = (
                "<p>本快照没有定向条目；这仍不是放行决定。</p>"
                if not decision_rows
                else """<table><thead><tr><th>字段</th><th>定向结论</th><th>理由</th><th>关闭异常</th></tr></thead>
<tbody>"""
                + decision_rows
                + "</tbody></table>"
            )
            return f"""<section class="panel" id="targeted-review">
<h2>定向异常复核已锁定</h2>
<p><strong>仍未闭环：</strong>这是定向复核，不是独立盲二审。<code>SAME</code> 也不关闭原异常，QA 处置和最终人工确认仍未接入 Web。</p>
<p><strong>身份边界：</strong>此快照记录的 reviewer 只是服务端演示归属；HTTP 未验证登录身份，不是电子签名。</p>
<p>锁定快照 <code>{escape(inbox['submission']['submission_hash'])}</code>；自动放行：<strong>否</strong>。</p>
{decision_table}
<h3>QA referrals</h3>{qa_section}
</section>"""

        cards: list[str] = []
        for item in inbox["items"]:
            decision = item["decision"]
            reason_value = "" if decision is None else decision["reason"]
            decision_status = (
                "未记录"
                if decision is None
                else f"已记录：{decision['verdict']}；不关闭原异常"
            )
            buttons = "".join(
                (
                    '<button type="button" '
                    f'data-targeted-verdict="{verdict}"'
                    + (
                        ' class="selected"'
                        if decision is not None
                        and decision["verdict"] == verdict
                        else ""
                    )
                    + f">{label}</button>"
                )
                for verdict, label in (
                    ("SAME", "SAME（不关闭异常）"),
                    ("DIFFERENT", "DIFFERENT"),
                    ("UNABLE_TO_JUDGE", "UNABLE TO JUDGE"),
                )
            )
            cards.append(
                '<article class="targeted-card" '
                f'data-parameter-id="{escape(item["parameter_id"], quote=True)}">'
                f'<h3><code>{escape(item["parameter_id"])}</code></h3>'
                f'<p>R1: {escape(item["primary_verdict"])} · AI: '
                f'{escape(item["ai_verdict"])} · 确定性比较: '
                f'{escape(item["comparison_kind"])}</p>'
                f'<p>入队原因：{escape(", ".join(item["reasons"]) or "无")}</p>'
                '<label>复核理由（三种结论都必填）'
                f'<input class="targeted-reason" maxlength="{MAX_TARGETED_REASON_CHARACTERS}" '
                f'autocomplete="off" value="{escape(reason_value, quote=True)}"></label>'
                f'<div class="verdicts">{buttons}</div>'
                f'<p class="targeted-decision-status">{escape(decision_status)}</p>'
                "</article>"
            )

        empty_notice = ""
        if not cards:
            empty_notice = (
                "<p><strong>未检出普通定向异常。</strong>"
                "这不是自动通过；仍需人工锁定空快照，"
                "并继续 QA/最终人工流程。</p>"
            )
        disabled = "" if inbox["lock_available"] else " disabled"
        completion = (
            "定向队列已完整；可锁定快照，但仍不表示放行。"
            if inbox["lock_available"]
            else f"还有 {inbox['missing_count']} 个定向异常需复核。"
        )
        same_actor_notice = (
            "本合成 demo 由 R1 同一演示 actor 处理定向队列；"
            "因此不能称为独立二审。"
            if inbox["same_reviewer_as_r1"]
            else "本次定向复核指派给另一演示 reviewer，但仍不是盲 R2。"
        )
        return f"""<section class="panel" id="targeted-review">
<h2>定向异常人工复核</h2>
<p><strong>实现状态：</strong>定向 inbox/决定/锁定已接入。{same_actor_notice}</p>
<p><strong>身份边界：</strong>HTTP 还没有登录或会话认证；页面上的 reviewer ID 只是服务端演示归属，不是已验证身份或电子签名。</p>
<p><code>SAME</code> 只是新的人工观察，不会改写 R1/AI，不会关闭异常，不会自动放行。</p>
<p>服务端锁定 profile: <code>{escape(inbox['profile_id'])}</code> v{escape(inbox['profile_version'])}；HTTP 客户端不能选择 profile 或 routing context。</p>
{empty_notice}{''.join(cards)}
<h3>QA referrals（本 Web 尚无 QA 处置功能）</h3>{qa_section}
<p id="targeted-completion-status">{escape(completion)}</p>
<p id="targeted-request-error" class="error" role="alert"></p>
<button id="lock-targeted-review" class="primary" type="button"{disabled}>锁定定向复核快照（不放行）</button>
<p class="muted">R2、QA、最终人工决定、追加式审计、真实 IAM 和持久化仍未接入 Web；任务始终未闭环。</p>
</section>"""


class ParamGuardHttpServer(ThreadingHTTPServer):
    """Threaded local demo server with a finite slow-client worker budget."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = MAX_CONCURRENT_HTTP_REQUESTS

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[BaseHTTPRequestHandler],
        *,
        max_concurrent_requests: int = MAX_CONCURRENT_HTTP_REQUESTS,
    ) -> None:
        if (
            type(max_concurrent_requests) is not int
            or max_concurrent_requests <= 0
            or max_concurrent_requests > 256
        ):
            raise ValueError("max_concurrent_requests must be an integer from 1 to 256")
        self._request_slots = BoundedSemaphore(max_concurrent_requests)
        self._request_count_lock = RLock()
        self._active_request_count = 0
        super().__init__(server_address, request_handler_class)

    @property
    def active_request_count(self) -> int:
        with self._request_count_lock:
            return self._active_request_count

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            self._send_busy_and_close(request)
            return
        with self._request_count_lock:
            self._active_request_count += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._release_request_slot()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release_request_slot()

    def _release_request_slot(self) -> None:
        with self._request_count_lock:
            self._active_request_count -= 1
        self._request_slots.release()

    def _send_busy_and_close(self, request: Any) -> None:
        body = b'{"error":"SERVER_BUSY"}'
        response = (
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"Content-Type: application/json; charset=utf-8\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Cache-Control: no-store, max-age=0\r\n"
            b"Pragma: no-cache\r\n"
            b"Expires: 0\r\n"
            b"Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'\r\n"
            b"X-Content-Type-Options: nosniff\r\n"
            b"X-Frame-Options: DENY\r\n"
            b"Referrer-Policy: no-referrer\r\n"
            b"Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n"
            b"Cross-Origin-Opener-Policy: same-origin\r\n"
            b"Cross-Origin-Resource-Policy: same-origin\r\n"
            b"Connection: close\r\n\r\n"
            + body
        )
        try:
            request.sendall(response)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)


def make_handler(
    session: ParamGuardWebSession,
) -> type[BaseHTTPRequestHandler]:
    if not isinstance(session, ParamGuardWebSession):
        raise TypeError("session must be a ParamGuardWebSession")

    class ParamGuardRequestHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "ParamGuardDemo"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            # A loopback-only PoC is still reachable by other local processes.
            # Bound the time one incomplete request may occupy a worker thread.
            self.connection.settimeout(REQUEST_IO_TIMEOUT_SECONDS)

        def send_error(
            self,
            code: int,
            message: str | None = None,
            explain: str | None = None,
        ) -> None:
            """Replace stdlib diagnostic HTML, Server, and Date disclosures."""

            del message, explain
            try:
                status = HTTPStatus(code)
            except ValueError:
                status = HTTPStatus.INTERNAL_SERVER_ERROR
            error_code = (
                "NOT_ALLOWED"
                if status
                in {HTTPStatus.METHOD_NOT_ALLOWED, HTTPStatus.NOT_IMPLEMENTED}
                else "INVALID_REQUEST"
            )
            self.close_connection = True
            self._send_json(
                status,
                {"error": error_code},
                send_body=getattr(self, "command", None) != "HEAD",
            )

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            if not self._host_is_loopback():
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "INVALID_REQUEST"})
                return
            try:
                segments = _safe_path_segments(self.path)
            except ValueError:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
                return

            try:
                if segments in ((), ("index.html",)):
                    if not session.is_first_review_open:
                        self._send_redirect("/post-lock")
                        return
                    nonce = secrets.token_urlsafe(24)
                    self._send_html(
                        HTTPStatus.OK,
                        session.render_first_review_html(nonce=nonce),
                        nonce=nonce,
                    )
                    return
                if segments == ("api", "state"):
                    self._send_json(HTTPStatus.OK, session.public_state())
                    return
                if segments == ("api", "exception-inbox"):
                    self._send_json(HTTPStatus.OK, session.exception_inbox())
                    return
                if segments == ("post-lock",):
                    nonce = secrets.token_urlsafe(24)
                    self._send_html(
                        HTTPStatus.OK,
                        session.render_post_lock_html(nonce=nonce),
                        nonce=nonce,
                    )
                    return
                if len(segments) == 3 and segments[0] == "evidence":
                    asset = session.image_asset(
                        side=segments[1], asset_name=segments[2]
                    )
                    self._send_bytes(
                        HTTPStatus.OK,
                        asset.content,
                        content_type=asset.media_type,
                    )
                    return
            except (FileNotFoundError, ValueError):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
                return
            except PublicStageUnavailableError:
                self._send_json(
                    HTTPStatus.CONFLICT, {"error": "STAGE_NOT_AVAILABLE"}
                )
                return
            except Exception:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "INTERNAL_FAILURE"},
                )
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            if not self._host_is_loopback():
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "INVALID_REQUEST"})
                return
            if not self._browser_mutation_is_same_origin():
                self.close_connection = True
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "INVALID_REQUEST"})
                return
            try:
                segments = _safe_path_segments(self.path)
            except ValueError:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
                return
            allowed_mutations = {
                ("api", "decision"),
                ("api", "lock"),
                ("api", "assistive-check"),
                ("api", "targeted-decision"),
                ("api", "targeted-lock"),
            }
            if segments not in allowed_mutations:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
                return
            try:
                body = self._read_json_object()
                if segments == ("api", "decision"):
                    _require_object_keys(
                        body,
                        required={
                            "parameter_id",
                            "verdict",
                            "evidence_manifest_hash",
                            "expected_revision",
                        },
                        optional={"reason", "command_id"},
                    )
                    receipt = session.record_human_decision(
                        parameter_id=body["parameter_id"],
                        verdict=body["verdict"],
                        reason=body.get("reason"),
                        evidence_manifest_hash=body["evidence_manifest_hash"],
                        expected_revision=body["expected_revision"],
                        command_id=body.get("command_id"),
                    )
                    self._send_json(HTTPStatus.OK, {"receipt": receipt})
                    return
                if segments == ("api", "lock"):
                    _require_object_keys(
                        body,
                        required={"evidence_manifest_hash", "expected_revision"},
                        optional={"command_id"},
                    )
                    state = session.lock_human_review(
                        evidence_manifest_hash=body["evidence_manifest_hash"],
                        expected_revision=body["expected_revision"],
                        command_id=body.get("command_id"),
                    )
                    self._send_json(
                        HTTPStatus.OK,
                        {"next": "/post-lock", "revision": state["revision"]},
                    )
                    return
                if segments == ("api", "assistive-check"):
                    _require_object_keys(
                        body,
                        required={"evidence_manifest_hash", "expected_revision"},
                        optional={"command_id"},
                    )
                    state = session.run_assistive_check(
                        evidence_manifest_hash=body["evidence_manifest_hash"],
                        expected_revision=body["expected_revision"],
                        command_id=body.get("command_id"),
                    )
                    self._send_json(HTTPStatus.OK, {"state": state})
                    return
                if segments == ("api", "targeted-decision"):
                    _require_object_keys(
                        body,
                        required={
                            "task_id",
                            "assignment_id",
                            "evidence_manifest_hash",
                            "source_snapshot_sha256",
                            "parameter_id",
                            "verdict",
                            "reason",
                            "command_id",
                            "expected_revision",
                        },
                    )
                    receipt = session.record_targeted_decision(
                        task_id=body["task_id"],
                        assignment_id=body["assignment_id"],
                        evidence_manifest_hash=body["evidence_manifest_hash"],
                        source_snapshot_sha256=body["source_snapshot_sha256"],
                        parameter_id=body["parameter_id"],
                        verdict=body["verdict"],
                        reason=body["reason"],
                        command_id=body["command_id"],
                        expected_revision=body["expected_revision"],
                    )
                    self._send_json(HTTPStatus.OK, {"receipt": receipt})
                    return
                if segments == ("api", "targeted-lock"):
                    _require_object_keys(
                        body,
                        required={
                            "task_id",
                            "assignment_id",
                            "evidence_manifest_hash",
                            "source_snapshot_sha256",
                            "command_id",
                            "expected_revision",
                        },
                    )
                    receipt = session.lock_targeted_review(
                        task_id=body["task_id"],
                        assignment_id=body["assignment_id"],
                        evidence_manifest_hash=body["evidence_manifest_hash"],
                        source_snapshot_sha256=body["source_snapshot_sha256"],
                        command_id=body["command_id"],
                        expected_revision=body["expected_revision"],
                    )
                    self._send_json(HTTPStatus.OK, {"receipt": receipt})
                    return
            except MutationConflictError:
                self._send_json(
                    HTTPStatus.CONFLICT, {"error": "MUTATION_CONFLICT"}
                )
                return
            except PublicStageUnavailableError:
                self._send_json(
                    HTTPStatus.CONFLICT, {"error": "STAGE_NOT_AVAILABLE"}
                )
                return
            except AssistiveCheckFailedError:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "POST_LOCK_PROCESSING_FAILED_CLOSED"},
                )
                return
            except TargetedReviewIncompleteWebError:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {"error": "TARGETED_REVIEW_INCOMPLETE"},
                )
                return
            except TargetedMutationLimitError:
                self._send_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"error": "TARGETED_MUTATION_LIMIT_REACHED"},
                )
                return
            except FirstReviewMutationLimitError:
                self._send_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"error": "FIRST_REVIEW_MUTATION_LIMIT_REACHED"},
                )
                return
            except InvalidWebRequestError:
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": "INVALID_REQUEST"}
                )
                return
            except Exception as error:
                # Domain errors intentionally map to compact fixed codes.  No
                # stack, engine message, timing, or partial result reaches the
                # first-review browser.
                code = getattr(error, "code", None)
                if code == "INCOMPLETE_REVIEW":
                    self._send_json(
                        HTTPStatus.CONFLICT,
                        {"error": "HUMAN_REVIEW_INCOMPLETE"},
                    )
                elif code == "REASON_REQUIRED":
                    self._send_json(
                        HTTPStatus.UNPROCESSABLE_ENTITY,
                        {"error": "REASON_REQUIRED"},
                    )
                elif code in {
                    "UNKNOWN_PARAMETER",
                    "EVIDENCE_VERSION_CONFLICT",
                    "INVALID_TRANSITION",
                    "REVIEW_LOCKED",
                }:
                    self._send_json(
                        HTTPStatus.CONFLICT, {"error": "MUTATION_CONFLICT"}
                    )
                else:
                    self._send_json(
                        HTTPStatus.BAD_REQUEST, {"error": "INVALID_REQUEST"}
                    )
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})

        def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler API
            # No CORS grant: browser requests from another origin fail closed.
            if not self._host_is_loopback():
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "INVALID_REQUEST"})
                return
            self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "NOT_ALLOWED"})

        def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API
            if not self._host_is_loopback():
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "INVALID_REQUEST"},
                    send_body=False,
                )
                return
            self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "NOT_ALLOWED"},
                send_body=False,
            )

        def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
            self._reject_unsupported_mutation_method()

        def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler API
            self._reject_unsupported_mutation_method()

        def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
            self._reject_unsupported_mutation_method()

        def do_TRACE(self) -> None:  # noqa: N802 - stdlib handler API
            self._reject_unsupported_mutation_method()

        def do_CONNECT(self) -> None:  # noqa: N802 - stdlib handler API
            self._reject_unsupported_mutation_method()

        def _reject_unsupported_mutation_method(self) -> None:
            self.close_connection = True
            if not self._host_is_loopback():
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "INVALID_REQUEST"})
                return
            self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED, {"error": "NOT_ALLOWED"}
            )

        def log_message(self, format: str, *args: object) -> None:
            # Avoid request bodies, evidence IDs, and timestamped terminal noise.
            return

        def _read_json_object(self) -> dict[str, Any]:
            content_types = self.headers.get_all("Content-Type", [])
            if len(content_types) != 1:
                self._reject_request_body("exactly one content type is required")
            content_type = content_types[0]
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                self._reject_request_body("JSON content type required")
            if self.headers.get_all("Transfer-Encoding", []):
                self._reject_request_body("transfer encoding is unsupported")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1:
                self._reject_request_body("exactly one body length is required")
            raw_length = lengths[0]
            try:
                if not raw_length.isascii() or not raw_length.isdecimal():
                    raise ValueError
                length = int(raw_length)
            except ValueError as error:
                self.close_connection = True
                raise InvalidWebRequestError("invalid body length") from error
            if length <= 0 or length > MAX_JSON_BODY_BYTES:
                self._reject_request_body("invalid body length")
            try:
                raw = self.rfile.read(length)
            except TimeoutError as error:
                self.close_connection = True
                raise InvalidWebRequestError("request body timed out") from error
            if len(raw) != length:
                self._reject_request_body("incomplete request body")
            try:
                value = json.loads(
                    raw.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_json_keys,
                    parse_constant=_reject_nonfinite_json_number,
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise InvalidWebRequestError("invalid JSON") from error
            if not isinstance(value, dict):
                raise InvalidWebRequestError("JSON body must be object")
            return value

        def _reject_request_body(self, message: str) -> None:
            # Closing prevents unread or ambiguously framed bytes from being
            # interpreted as a second request on this HTTP/1.1 connection.
            self.close_connection = True
            raise InvalidWebRequestError(message)

        def _host_is_loopback(self) -> bool:
            host_headers = self.headers.get_all("Host", [])
            if len(host_headers) != 1:
                return False
            host_header = host_headers[0]
            if (
                not host_header
                or host_header != host_header.strip()
                or "@" in host_header
            ):
                return False
            try:
                parsed = urlsplit("//" + host_header)
                hostname = parsed.hostname
                if (
                    hostname is None
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.path
                    or parsed.query
                    or parsed.fragment
                ):
                    return False
                listener_host, listener_port = self.server.server_address[:2]
                allowed_names = {str(listener_host).lower()}
                if str(listener_host) == "127.0.0.1":
                    allowed_names.add("localhost")
                request_port = parsed.port
                if request_port is None:
                    request_port = 80
                return (
                    hostname.lower() in allowed_names
                    and request_port == int(listener_port)
                )
            except ValueError:
                return False

        def _browser_mutation_is_same_origin(self) -> bool:
            """Reject browser cross-origin mutation signals; CLI tools may omit them."""

            fetch_sites = self.headers.get_all("Sec-Fetch-Site", [])
            if len(fetch_sites) > 1 or (
                fetch_sites
                and fetch_sites[0].strip().lower() not in {"same-origin", "none"}
            ):
                return False
            origins = self.headers.get_all("Origin", [])
            if not origins:
                return True
            if len(origins) != 1:
                return False
            host_headers = self.headers.get_all("Host", [])
            if len(host_headers) != 1:
                return False
            try:
                origin = urlsplit(origins[0])
                host = urlsplit("//" + host_headers[0])
                if (
                    origin.scheme.lower() != "http"
                    or origin.username is not None
                    or origin.password is not None
                    or origin.path
                    or origin.query
                    or origin.fragment
                    or origin.hostname is None
                    or host.hostname is None
                ):
                    return False
                origin_port = 80 if origin.port is None else origin.port
                host_port = 80 if host.port is None else host.port
                return (
                    origin.hostname.lower() == host.hostname.lower()
                    and origin_port == host_port
                )
            except ValueError:
                return False

        def _send_redirect(self, location: str) -> None:
            body = b""
            self.send_response_only(HTTPStatus.SEE_OTHER)
            self._security_headers("default-src 'none'; frame-ancestors 'none'")
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _send_html(self, status: HTTPStatus, html: str, *, nonce: str) -> None:
            csp = (
                "default-src 'none'; "
                f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                "img-src 'self'; connect-src 'self'; "
                "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
            )
            self._send_bytes(
                status,
                html.encode("utf-8"),
                content_type="text/html; charset=utf-8",
                csp=csp,
            )

        def _send_json(
            self,
            status: HTTPStatus,
            value: Mapping[str, Any],
            *,
            send_body: bool = True,
        ) -> None:
            body = json.dumps(
                dict(value),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            self._send_bytes(
                status,
                body,
                content_type="application/json; charset=utf-8",
                csp="default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
                send_body=send_body,
            )

        def _send_bytes(
            self,
            status: HTTPStatus,
            body: bytes,
            *,
            content_type: str,
            csp: str = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            send_body: bool = True,
        ) -> None:
            try:
                self.send_response_only(status)
                self._security_headers(csp)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                if self.close_connection:
                    self.send_header("Connection", "close")
                self.end_headers()
                if send_body:
                    self.wfile.write(body)
            except OSError:
                # A browser may close while the bounded handler is rejecting an
                # incomplete or timed-out request.  The response is already
                # fixed at this point and no domain mutation is pending, so an
                # expected transport failure should only close the connection,
                # not reach socketserver.handle_error and amplify tracebacks.
                self.close_connection = True

        def _security_headers(self, csp: str) -> None:
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.send_header("Content-Security-Policy", csp)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
            )
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    return ParamGuardRequestHandler


def create_demo_server(
    session: ParamGuardWebSession,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    max_concurrent_requests: int = MAX_CONCURRENT_HTTP_REQUESTS,
) -> ParamGuardHttpServer:
    """Create a server only when the requested bind address is loopback."""

    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise ValueError("host must be an explicit loopback IP address") from error
    if not address.is_loopback or address.version != 4:
        raise ValueError("the learning Web demo may bind only to IPv4 loopback")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 to 65535")
    return ParamGuardHttpServer(
        (host, port),
        make_handler(session),
        max_concurrent_requests=max_concurrent_requests,
    )


def build_default_demo_session(
    *,
    output_root: str | Path,
    engine: TesseractOcrEngine | None = None,
) -> ParamGuardWebSession:
    """Render fictional evidence and prepare the local human-first session."""

    rendered = render_case(default_clean_case(), output_root=output_root)
    return ParamGuardWebSession(
        rendered_case=rendered,
        engine=TesseractOcrEngine() if engine is None else engine,
    )


def _validate_rendered_case_binding(rendered: RenderedSyntheticCase) -> None:
    """Fail during composition when template/schema metadata is inconsistent.

    This is configuration validation only.  It deliberately does not invoke
    OCR, image-quality analysis, or read evidence bytes before the human stage.
    Byte integrity is checked whenever an image is served and again by the
    gated post-lock pipeline.
    """

    if not isinstance(rendered.template, FixedTemplate):
        raise TypeError("rendered template must be a FixedTemplate")
    if not isinstance(rendered.left_image_path, Path) or not isinstance(
        rendered.right_image_path, Path
    ):
        raise TypeError("rendered evidence paths must be Path values")
    rendered.spec.assert_matches_template(rendered.template)
    manifest = rendered.manifest
    template = rendered.template
    if (
        manifest.template_id != template.template_id
        or manifest.template_version != template.version
        or manifest.template_sha256 != template.content_sha256
        or manifest.expected_parameter_ids != template.expected_parameter_ids
    ):
        raise ValueError("rendered evidence manifest does not match its template")


def _safe_path_segments(raw_target: str) -> tuple[str, ...]:
    if not isinstance(raw_target, str):
        raise ValueError("request target must be text")
    parsed = urlsplit(raw_target)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("only a canonical origin-form path is accepted")
    try:
        decoded = unquote_to_bytes(parsed.path).decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("invalid encoded path") from error
    if not decoded.startswith("/") or "\\" in decoded or "\x00" in decoded:
        raise ValueError("unsafe path")
    if decoded == "/":
        return ()
    if decoded.endswith("/") or "//" in decoded:
        raise ValueError("non-canonical path")
    segments = tuple(decoded[1:].split("/"))
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ValueError("unsafe path segment")
    return segments


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise InvalidWebRequestError("duplicate JSON object key")
        value[key] = item
    return value


def _reject_nonfinite_json_number(token: str) -> None:
    raise InvalidWebRequestError(f"non-finite JSON number is forbidden: {token}")


def _require_object_keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    optional = set() if optional is None else optional
    actual = set(value)
    if actual != required | (actual & optional) or not required.issubset(actual):
        raise InvalidWebRequestError("request fields do not match fixed schema")


def _safe_embedded_json(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return (
        encoded.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _locked_routing_quality(outcome: OcrPairOutcome) -> ImageQuality:
    """Project only validated server-side quality evidence into routing."""

    if not isinstance(outcome, OcrPairOutcome):
        raise TypeError("outcome must be an OcrPairOutcome")
    quality_flags = set(outcome.left_quality.flags) | set(
        outcome.right_quality.flags
    )
    if ImageQualityFlag.DIMENSION_MISMATCH in quality_flags:
        return ImageQuality.UNREADABLE
    if quality_flags:
        return ImageQuality.LOW
    return ImageQuality.ACCEPTABLE


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the loopback-only ParamGuard learning Web demo"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("artifacts/web-demo"),
    )
    args = parser.parse_args(argv)
    session = build_default_demo_session(output_root=args.output_root)
    server = create_demo_server(session, host=args.host, port=args.port)
    host, port = server.server_address[:2]
    print(f"ParamGuard learning PoC: http://{host}:{port}/")
    print("Synthetic data only; not a validated production system.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised manually
    raise SystemExit(main())
