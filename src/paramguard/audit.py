"""Append-only, hash-chained audit evidence for the learning PoC.

The JSONL store makes accidental edits and simple tampering detectable, but it
is not a WORM archive, digital signature, trusted timestamp service, database
transaction layer, or Part 11 certification.  Production use would require
validated infrastructure, access controls, backup/restore, retention,
independent hash anchoring, and organisation-specific procedures.

Actor prefixes in this module are a fail-closed PoC role boundary, not an
authentication system.  A production API must supply ``actor_id`` from a
verified principal and must never accept it from a request body.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any
from uuid import uuid4

from .comparison import ComparisonKind, compare_values
from .evidence import EvidenceManifest, EvidenceRole
from .review_policy import INTERVIEW_TARGETED_RECHECK


AUDIT_SCHEMA_VERSION = 2
GENESIS_HASH = "0" * 64
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class AuditAction(str, Enum):
    TASK_CREATED = "TASK_CREATED"
    HUMAN_DECISION_RECORDED = "HUMAN_DECISION_RECORDED"
    HUMAN_DECISION_REVISED = "HUMAN_DECISION_REVISED"
    HUMAN_REVIEW_LOCKED = "HUMAN_REVIEW_LOCKED"
    AI_REVIEW_STARTED = "AI_REVIEW_STARTED"
    AI_ASSESSMENT_RECORDED = "AI_ASSESSMENT_RECORDED"
    AI_REVIEW_COMPLETED = "AI_REVIEW_COMPLETED"
    ROUTE_ASSIGNED = "ROUTE_ASSIGNED"
    SECOND_REVIEW_ASSIGNED = "SECOND_REVIEW_ASSIGNED"
    SECOND_REVIEW_DECISION_RECORDED = "SECOND_REVIEW_DECISION_RECORDED"
    SECOND_REVIEW_DECISION_REVISED = "SECOND_REVIEW_DECISION_REVISED"
    SECOND_REVIEW_LOCKED = "SECOND_REVIEW_LOCKED"
    QA_CASE_OPENED = "QA_CASE_OPENED"
    QA_DISPOSITION_RECORDED = "QA_DISPOSITION_RECORDED"
    QA_DISPOSITION_COMPLETED = "QA_DISPOSITION_COMPLETED"
    FINAL_APPROVAL_RECORDED = "FINAL_APPROVAL_RECORDED"
    FINAL_REJECTION_RECORDED = "FINAL_REJECTION_RECORDED"
    # The targeted interview profile is a separate adjudication branch from
    # the structurally blind full-field second review above.  Its lock, QA
    # acceptance, and final events are admitted only by typed CAS methods.
    TARGETED_REVIEW_LOCKED = "TARGETED_REVIEW_LOCKED"
    TARGETED_QA_DISPOSITION_ACCEPTED = "TARGETED_QA_DISPOSITION_ACCEPTED"
    TARGETED_FINAL_APPROVAL_RECORDED = "TARGETED_FINAL_APPROVAL_RECORDED"
    TARGETED_FINAL_REJECTION_RECORDED = "TARGETED_FINAL_REJECTION_RECORDED"
    # Compatibility-only evidence from the first PoC.  It is deliberately not
    # counted as an assignment, a full-field blind review, or a lock and can
    # therefore never satisfy the adjudication gates below.
    SECOND_REVIEW_RECORDED = "SECOND_REVIEW_RECORDED"
    CORRECTION_RECORDED = "CORRECTION_RECORDED"
    GENERIC_NOTE_RECORDED = "GENERIC_NOTE_RECORDED"


class AuditError(Exception):
    """Base class for expected audit-log failures."""


class AuditIntegrityError(AuditError):
    """Raised when stored events cannot be verified exactly."""


class DuplicateAuditEventError(AuditError):
    """Raised when an event ID would be reused."""


class UnknownCorrectedEventError(AuditError):
    """Raised when a correction points to an event outside the log."""


class AuditPolicyError(AuditError):
    """Raised when a proposed event violates the controlled event contract."""


def _require_text(name: str, value: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if value.strip() == "":
        raise ValueError(f"{name} must not be empty or whitespace")
    return value


def _require_identifier(name: str, value: str) -> str:
    checked = _require_text(name, value)
    if _IDENTIFIER_PATTERN.fullmatch(checked) is None:
        raise ValueError(
            f"{name} must be 1-128 ASCII letters, digits, dot, underscore, colon, or hyphen"
        )
    return checked


def _require_sha256(name: str, value: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"{name} must contain 64 lowercase hexadecimal characters"
        )
    return value


def _normalise_utc(name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include timezone information")
    return value.astimezone(timezone.utc)


def _validate_json_value(value: Any, *, path: str = "details") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite float")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} contains a non-string object key")
            _validate_json_value(item, path=f"{path}.{key}")
        return
    raise TypeError(
        f"{path} contains unsupported JSON value of type {type(value).__name__}"
    )


def _canonical_json(value: Any) -> str:
    _validate_json_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _json_object_rejecting_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """Build one decoded object while rejecting ambiguous duplicate names."""

    record: dict[str, Any] = {}
    for key, value in pairs:
        if key in record:
            raise ValueError(f"duplicate JSON object key: {key}")
        record[key] = value
    return record


_FINAL_COMMIT_RECORD_KEYS = frozenset(
    {
        "task_id",
        "decision",
        "actor_id",
        "rationale",
        "evidence_manifest_hash",
        "second_submission_hash",
        "primary_reviewer_id",
        "ai_run_id",
        "expected_parameter_ids",
        "exception_ids",
        "qa_disposition_exception_ids",
        "resolution_digest",
        "expected_adjudication_version",
        "expected_previous_head_hash",
        "required_prior_actions",
        "command_id",
    }
)

_TARGETED_LOCK_REQUEST_KEYS = frozenset(
    {
        "task_id",
        "actor_id",
        "primary_reviewer_id",
        "ai_run_id",
        "targeted_reviewer_kind",
        "targeted_reviewer_roles",
        "assigned_qa_reviewer_id",
        "assigned_final_approver_id",
        "evidence_context",
        "submission",
        "submission_hash",
        "expected_previous_head_hash",
        "command_id",
    }
)
_TARGETED_QA_REQUEST_KEYS = frozenset(
    {
        "task_id",
        "actor_id",
        "targeted_submission_hash",
        "exception_id",
        "outcome",
        "rationale",
        "reference_ids",
        "expected_adjudication_version",
        "expected_previous_head_hash",
        "command_id",
    }
)
_TARGETED_FINAL_REQUEST_KEYS = frozenset(
    {
        "task_id",
        "decision",
        "actor_id",
        "rationale",
        "evidence_manifest_hash",
        "targeted_submission_hash",
        "primary_reviewer_id",
        "ai_run_id",
        "expected_parameter_ids",
        "exception_ids",
        "qa_required_exception_ids",
        "qa_disposition_exception_ids",
        "resolution_digest",
        "expected_adjudication_version",
        "expected_previous_head_hash",
        "command_id",
    }
)


def _calculate_exact_mapping_hash(
    record: Mapping[str, Any], *, expected_keys: frozenset[str], name: str
) -> str:
    if not isinstance(record, Mapping):
        raise TypeError(f"{name} must be a mapping")
    snapshot = dict(record)
    if set(snapshot) != expected_keys:
        missing = expected_keys - set(snapshot)
        unknown = set(snapshot) - expected_keys
        pieces: list[str] = []
        if missing:
            pieces.append("missing=" + ",".join(sorted(missing)))
        if unknown:
            pieces.append("unknown=" + ",".join(sorted(unknown)))
        raise ValueError(f"Invalid {name} fields: " + "; ".join(pieces))
    return hashlib.sha256(_canonical_json(snapshot).encode("utf-8")).hexdigest()


def calculate_targeted_lock_request_hash(record: Mapping[str, Any]) -> str:
    return _calculate_exact_mapping_hash(
        record,
        expected_keys=_TARGETED_LOCK_REQUEST_KEYS,
        name="targeted lock request",
    )


def calculate_targeted_qa_request_hash(record: Mapping[str, Any]) -> str:
    return _calculate_exact_mapping_hash(
        record,
        expected_keys=_TARGETED_QA_REQUEST_KEYS,
        name="targeted QA request",
    )


def calculate_targeted_final_request_hash(record: Mapping[str, Any]) -> str:
    return _calculate_exact_mapping_hash(
        record,
        expected_keys=_TARGETED_FINAL_REQUEST_KEYS,
        name="targeted final request",
    )


def calculate_final_commit_request_hash(record: Mapping[str, Any]) -> str:
    """Hash the shared domain/audit final-commit contract.

    Both the domain request and the durable audit event use this one canonical
    function so a receipt cannot claim to represent a different request.
    """

    if not isinstance(record, Mapping):
        raise TypeError("final commit record must be a mapping")
    snapshot = dict(record)
    if set(snapshot) != _FINAL_COMMIT_RECORD_KEYS:
        missing = _FINAL_COMMIT_RECORD_KEYS - set(snapshot)
        unknown = set(snapshot) - _FINAL_COMMIT_RECORD_KEYS
        pieces: list[str] = []
        if missing:
            pieces.append("missing=" + ",".join(sorted(missing)))
        if unknown:
            pieces.append("unknown=" + ",".join(sorted(unknown)))
        raise ValueError("Invalid final commit fields: " + "; ".join(pieces))
    return hashlib.sha256(_canonical_json(snapshot).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceContext:
    """Exact evidence identity carried by every controlled audit event.

    The two image roles are explicit rather than represented by an unordered
    list.  AI-related fields are optional at construction time because human
    events use the same type; the action policy requires all of them for AI,
    routing, and second-review events.
    """

    manifest_hash: str
    source_artifact_sha256_by_role: tuple[tuple[str, str], ...]
    schema_id: str
    schema_version: str
    schema_sha256: str
    template_id: str
    template_version: str
    template_sha256: str
    rules_version: str | None = None
    run_id: str | None = None
    pipeline_spec_hash: str | None = None
    pipeline_version: str | None = None
    comparator_version: str | None = None
    ocr_engine: str | None = None
    ocr_version: str | None = None
    model_name: str | None = None
    model_version: str | None = None

    def __post_init__(self) -> None:
        _require_sha256("manifest_hash", self.manifest_hash)
        _require_sha256("schema_sha256", self.schema_sha256)
        _require_sha256("template_sha256", self.template_sha256)
        for name in (
            "schema_id",
            "schema_version",
            "template_id",
            "template_version",
        ):
            _require_text(name, getattr(self, name))

        if not isinstance(self.source_artifact_sha256_by_role, tuple):
            raise TypeError("source_artifact_sha256_by_role must be a tuple")
        for item in self.source_artifact_sha256_by_role:
            if not isinstance(item, tuple) or len(item) != 2:
                raise TypeError(
                    "each source artifact binding must be a (role, sha256) tuple"
                )
        expected_roles = (
            EvidenceRole.LEFT_PHOTO.value,
            EvidenceRole.RIGHT_SCREENSHOT.value,
        )
        if tuple(item[0] for item in self.source_artifact_sha256_by_role) != expected_roles:
            raise ValueError(
                "source_artifact_sha256_by_role must contain exactly one "
                "LEFT_PHOTO and one RIGHT_SCREENSHOT in canonical order"
            )
        for item in self.source_artifact_sha256_by_role:
            role, digest = item
            _require_text("evidence role", role)
            _require_sha256(f"{role} sha256", digest)

        for name in (
            "rules_version",
            "run_id",
            "pipeline_version",
            "comparator_version",
            "ocr_engine",
            "ocr_version",
            "model_name",
            "model_version",
        ):
            value = getattr(self, name)
            if value is not None:
                _require_text(name, value)

        if self.run_id is not None:
            _require_identifier("run_id", self.run_id)
        if self.pipeline_spec_hash is not None:
            _require_sha256("pipeline_spec_hash", self.pipeline_spec_hash)

        if (self.ocr_engine is None) != (self.ocr_version is None):
            raise ValueError("ocr_engine and ocr_version must be provided together")
        if (self.model_name is None) != (self.model_version is None):
            raise ValueError("model_name and model_version must be provided together")

    @classmethod
    def from_manifest(
        cls,
        manifest: EvidenceManifest,
        **changes: Any,
    ) -> EvidenceContext:
        """Build the base binding from a validated immutable manifest."""

        if not isinstance(manifest, EvidenceManifest):
            raise TypeError("manifest must be an EvidenceManifest")
        artifacts = {artifact.role: artifact.sha256 for artifact in manifest.artifacts}
        values: dict[str, Any] = {
            "manifest_hash": manifest.manifest_hash,
            "source_artifact_sha256_by_role": (
                (EvidenceRole.LEFT_PHOTO.value, artifacts[EvidenceRole.LEFT_PHOTO]),
                (
                    EvidenceRole.RIGHT_SCREENSHOT.value,
                    artifacts[EvidenceRole.RIGHT_SCREENSHOT],
                ),
            ),
            "schema_id": manifest.schema_id,
            "schema_version": manifest.schema_version,
            "schema_sha256": manifest.schema_sha256,
            "template_id": manifest.template_id,
            "template_version": manifest.template_version,
            "template_sha256": manifest.template_sha256,
        }
        values.update(changes)
        return cls(**values)

    def to_record(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "manifest_hash": self.manifest_hash,
            "source_artifact_sha256_by_role": dict(
                self.source_artifact_sha256_by_role
            ),
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "schema_sha256": self.schema_sha256,
            "template_id": self.template_id,
            "template_version": self.template_version,
            "template_sha256": self.template_sha256,
        }
        for name in (
            "rules_version",
            "run_id",
            "pipeline_spec_hash",
            "pipeline_version",
            "comparator_version",
            "ocr_engine",
            "ocr_version",
            "model_name",
            "model_version",
        ):
            value = getattr(self, name)
            if value is not None:
                record[name] = value
        return record

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> EvidenceContext:
        allowed = {
            "manifest_hash",
            "source_artifact_sha256_by_role",
            "schema_id",
            "schema_version",
            "schema_sha256",
            "rules_version",
            "template_id",
            "template_version",
            "template_sha256",
            "run_id",
            "pipeline_spec_hash",
            "pipeline_version",
            "comparator_version",
            "ocr_engine",
            "ocr_version",
            "model_name",
            "model_version",
        }
        unknown = set(record) - allowed
        if unknown:
            raise AuditIntegrityError(
                "Unknown evidence-context keys: " + ", ".join(sorted(unknown))
            )
        required = {
            "manifest_hash",
            "source_artifact_sha256_by_role",
            "schema_id",
            "schema_version",
            "schema_sha256",
            "template_id",
            "template_version",
            "template_sha256",
        }
        missing = required - set(record)
        if missing:
            raise AuditIntegrityError(
                "Missing evidence-context keys: " + ", ".join(sorted(missing))
            )
        bindings = record["source_artifact_sha256_by_role"]
        if not isinstance(bindings, dict):
            raise AuditIntegrityError(
                "source_artifact_sha256_by_role must be a JSON object"
            )
        required_roles = {
            EvidenceRole.LEFT_PHOTO.value,
            EvidenceRole.RIGHT_SCREENSHOT.value,
        }
        if set(bindings) != required_roles:
            raise AuditIntegrityError(
                "source_artifact_sha256_by_role must contain exactly LEFT_PHOTO "
                "and RIGHT_SCREENSHOT"
            )
        try:
            return cls(
                manifest_hash=record["manifest_hash"],
                source_artifact_sha256_by_role=(
                    (
                        EvidenceRole.LEFT_PHOTO.value,
                        bindings[EvidenceRole.LEFT_PHOTO.value],
                    ),
                    (
                        EvidenceRole.RIGHT_SCREENSHOT.value,
                        bindings[EvidenceRole.RIGHT_SCREENSHOT.value],
                    ),
                ),
                schema_id=record["schema_id"],
                schema_version=record["schema_version"],
                schema_sha256=record["schema_sha256"],
                rules_version=record.get("rules_version"),
                template_id=record["template_id"],
                template_version=record["template_version"],
                template_sha256=record["template_sha256"],
                run_id=record.get("run_id"),
                pipeline_spec_hash=record.get("pipeline_spec_hash"),
                pipeline_version=record.get("pipeline_version"),
                comparator_version=record.get("comparator_version"),
                ocr_engine=record.get("ocr_engine"),
                ocr_version=record.get("ocr_version"),
                model_name=record.get("model_name"),
                model_version=record.get("model_version"),
            )
        except (TypeError, ValueError, KeyError) as error:
            raise AuditIntegrityError(f"Invalid evidence context: {error}") from error


@dataclass(frozen=True, slots=True)
class FinalAuditWriteRequest:
    """Typed input for the only supported final-event write path."""

    task_id: str
    action: AuditAction
    actor_id: str
    rationale: str
    evidence_manifest_hash: str
    second_submission_hash: str | None
    primary_reviewer_id: str
    ai_run_id: str
    expected_parameter_ids: tuple[str, ...]
    exception_ids: tuple[str, ...]
    qa_disposition_exception_ids: tuple[str, ...]
    resolution_digest: str
    expected_adjudication_version: int
    expected_previous_head_hash: str
    required_prior_actions: tuple[AuditAction, ...]
    command_id: str
    commit_request_hash: str

    def __post_init__(self) -> None:
        if self.action not in {
            AuditAction.FINAL_APPROVAL_RECORDED,
            AuditAction.FINAL_REJECTION_RECORDED,
        }:
            raise ValueError("action must be a final approval or rejection")
        for name in (
            "task_id",
            "actor_id",
            "primary_reviewer_id",
            "ai_run_id",
            "command_id",
        ):
            _require_identifier(name, getattr(self, name))
        _require_text("rationale", self.rationale)
        for name in (
            "evidence_manifest_hash",
            "resolution_digest",
            "expected_previous_head_hash",
            "commit_request_hash",
        ):
            _require_sha256(name, getattr(self, name))
        if self.second_submission_hash is not None:
            _require_sha256(
                "second_submission_hash", self.second_submission_hash
            )
        if (
            type(self.expected_adjudication_version) is not int
            or self.expected_adjudication_version < 0
        ):
            raise ValueError(
                "expected_adjudication_version must be a non-negative integer"
            )
        for name in (
            "expected_parameter_ids",
            "exception_ids",
            "qa_disposition_exception_ids",
        ):
            value = getattr(self, name)
            if not isinstance(value, tuple):
                raise TypeError(f"{name} must be a tuple")
            for item in value:
                _require_identifier(name[:-1], item)
            if len(set(value)) != len(value):
                raise ValueError(f"{name} must not contain duplicates")
        if not self.expected_parameter_ids:
            raise ValueError("expected_parameter_ids must not be empty")
        if set(self.exception_ids) != set(self.qa_disposition_exception_ids):
            raise ValueError(
                "exception_ids and qa_disposition_exception_ids must be equal sets"
            )
        if not isinstance(self.required_prior_actions, tuple) or any(
            not isinstance(item, AuditAction)
            for item in self.required_prior_actions
        ):
            raise TypeError("required_prior_actions must be a tuple of AuditAction")
        if len(set(self.required_prior_actions)) != len(
            self.required_prior_actions
        ):
            raise ValueError("required_prior_actions must not contain duplicates")
        if self.calculated_request_hash() != self.commit_request_hash:
            raise ValueError(
                "commit_request_hash does not match the typed final request"
            )

    def to_commit_record(self) -> dict[str, Any]:
        decision = (
            "APPROVED"
            if self.action is AuditAction.FINAL_APPROVAL_RECORDED
            else "REJECTED"
        )
        return {
            "task_id": self.task_id,
            "decision": decision,
            "actor_id": self.actor_id,
            "rationale": self.rationale,
            "evidence_manifest_hash": self.evidence_manifest_hash,
            "second_submission_hash": self.second_submission_hash,
            "primary_reviewer_id": self.primary_reviewer_id,
            "ai_run_id": self.ai_run_id,
            "expected_parameter_ids": list(self.expected_parameter_ids),
            "exception_ids": list(self.exception_ids),
            "qa_disposition_exception_ids": list(
                self.qa_disposition_exception_ids
            ),
            "resolution_digest": self.resolution_digest,
            "expected_adjudication_version": (
                self.expected_adjudication_version
            ),
            "expected_previous_head_hash": self.expected_previous_head_hash,
            "required_prior_actions": [
                item.value for item in self.required_prior_actions
            ],
            "command_id": self.command_id,
        }

    def calculated_request_hash(self) -> str:
        return calculate_final_commit_request_hash(self.to_commit_record())


@dataclass(frozen=True, slots=True)
class TargetedLockAuditWriteRequest:
    """Immutable input for the targeted branch's atomic lock acceptance."""

    task_id: str
    actor_id: str
    primary_reviewer_id: str
    ai_run_id: str
    targeted_reviewer_kind: str
    targeted_reviewer_roles: tuple[str, ...]
    assigned_qa_reviewer_id: str | None
    assigned_final_approver_id: str
    evidence_context: EvidenceContext
    submission_json: str
    submission_hash: str
    expected_previous_head_hash: str
    command_id: str
    request_hash: str

    def __post_init__(self) -> None:
        for name in (
            "task_id",
            "actor_id",
            "primary_reviewer_id",
            "ai_run_id",
            "command_id",
        ):
            _require_identifier(name, getattr(self, name))
        if self.targeted_reviewer_kind != "HUMAN":
            raise ValueError("targeted_reviewer_kind must be HUMAN")
        if self.assigned_qa_reviewer_id is not None:
            _require_identifier(
                "assigned_qa_reviewer_id",
                self.assigned_qa_reviewer_id,
            )
        _require_identifier(
            "assigned_final_approver_id",
            self.assigned_final_approver_id,
        )
        if (
            not isinstance(self.targeted_reviewer_roles, tuple)
            or not self.targeted_reviewer_roles
            or any(
                type(value) is not str
                or value not in {"PRIMARY_REVIEWER", "SECOND_REVIEWER"}
                for value in self.targeted_reviewer_roles
            )
            or len(set(self.targeted_reviewer_roles))
            != len(self.targeted_reviewer_roles)
            or tuple(sorted(self.targeted_reviewer_roles))
            != self.targeted_reviewer_roles
        ):
            raise ValueError(
                "targeted_reviewer_roles must be unique reviewer-role strings"
            )
        for name in (
            "submission_hash",
            "expected_previous_head_hash",
            "request_hash",
        ):
            _require_sha256(name, getattr(self, name))
        if type(self.evidence_context) is not EvidenceContext:
            raise TypeError("evidence_context must be an exact EvidenceContext")
        if not isinstance(self.submission_json, str):
            raise TypeError("submission_json must be str")
        try:
            submission = json.loads(self.submission_json)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("submission_json must contain valid JSON") from error
        if not isinstance(submission, dict):
            raise ValueError("submission_json must contain a JSON object")
        canonical = _canonical_json(submission)
        if canonical != self.submission_json:
            raise ValueError("submission_json must use canonical JSON encoding")
        _validate_targeted_submission_record(
            submission, expected_submission_hash=self.submission_hash
        )
        if self.calculated_request_hash() != self.request_hash:
            raise ValueError("request_hash does not match targeted lock request")

    @property
    def submission_record(self) -> dict[str, Any]:
        value = json.loads(self.submission_json)
        assert isinstance(value, dict)
        return value

    def to_commit_record(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "actor_id": self.actor_id,
            "primary_reviewer_id": self.primary_reviewer_id,
            "ai_run_id": self.ai_run_id,
            "targeted_reviewer_kind": self.targeted_reviewer_kind,
            "targeted_reviewer_roles": list(self.targeted_reviewer_roles),
            "assigned_qa_reviewer_id": self.assigned_qa_reviewer_id,
            "assigned_final_approver_id": self.assigned_final_approver_id,
            "evidence_context": self.evidence_context.to_record(),
            "submission": self.submission_record,
            "submission_hash": self.submission_hash,
            "expected_previous_head_hash": self.expected_previous_head_hash,
            "command_id": self.command_id,
        }

    def calculated_request_hash(self) -> str:
        return calculate_targeted_lock_request_hash(self.to_commit_record())


@dataclass(frozen=True, slots=True)
class TargetedQaAuditWriteRequest:
    """Typed compare-and-swap acceptance of one immutable QA disposition."""

    task_id: str
    actor_id: str
    targeted_submission_hash: str
    exception_id: str
    outcome: str
    rationale: str
    reference_ids: tuple[str, ...]
    expected_adjudication_version: int
    expected_previous_head_hash: str
    command_id: str
    request_hash: str

    def __post_init__(self) -> None:
        for name in ("task_id", "actor_id", "exception_id", "command_id"):
            _require_identifier(name, getattr(self, name))
        _require_sha256(
            "targeted_submission_hash", self.targeted_submission_hash
        )
        _require_sha256(
            "expected_previous_head_hash", self.expected_previous_head_hash
        )
        _require_sha256("request_hash", self.request_hash)
        _require_text("rationale", self.rationale)
        if self.outcome not in _QA_OUTCOMES:
            raise ValueError("outcome is not an allowed QA outcome")
        if not isinstance(self.reference_ids, tuple):
            raise TypeError("reference_ids must be a tuple")
        for value in self.reference_ids:
            _require_identifier("reference_id", value)
        if len(set(self.reference_ids)) != len(self.reference_ids):
            raise ValueError("reference_ids must not contain duplicates")
        if (
            type(self.expected_adjudication_version) is not int
            or self.expected_adjudication_version < 1
        ):
            raise ValueError(
                "expected_adjudication_version must be a positive integer"
            )
        if self.calculated_request_hash() != self.request_hash:
            raise ValueError("request_hash does not match targeted QA request")

    def to_commit_record(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "actor_id": self.actor_id,
            "targeted_submission_hash": self.targeted_submission_hash,
            "exception_id": self.exception_id,
            "outcome": self.outcome,
            "rationale": self.rationale,
            "reference_ids": list(self.reference_ids),
            "expected_adjudication_version": self.expected_adjudication_version,
            "expected_previous_head_hash": self.expected_previous_head_hash,
            "command_id": self.command_id,
        }

    def calculated_request_hash(self) -> str:
        return calculate_targeted_qa_request_hash(self.to_commit_record())


@dataclass(frozen=True, slots=True)
class TargetedFinalAuditWriteRequest:
    """Typed input for the targeted branch's globally unique final CAS."""

    task_id: str
    action: AuditAction
    actor_id: str
    rationale: str
    evidence_manifest_hash: str
    targeted_submission_hash: str
    primary_reviewer_id: str
    ai_run_id: str
    expected_parameter_ids: tuple[str, ...]
    exception_ids: tuple[str, ...]
    qa_required_exception_ids: tuple[str, ...]
    qa_disposition_exception_ids: tuple[str, ...]
    resolution_digest: str
    expected_adjudication_version: int
    expected_previous_head_hash: str
    command_id: str
    request_hash: str

    def __post_init__(self) -> None:
        if self.action not in {
            AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
            AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
        }:
            raise ValueError("action must be a targeted final action")
        for name in (
            "task_id",
            "actor_id",
            "primary_reviewer_id",
            "ai_run_id",
            "command_id",
        ):
            _require_identifier(name, getattr(self, name))
        _require_text("rationale", self.rationale)
        for name in (
            "evidence_manifest_hash",
            "targeted_submission_hash",
            "resolution_digest",
            "expected_previous_head_hash",
            "request_hash",
        ):
            _require_sha256(name, getattr(self, name))
        for name in (
            "expected_parameter_ids",
            "exception_ids",
            "qa_required_exception_ids",
            "qa_disposition_exception_ids",
        ):
            values = getattr(self, name)
            if not isinstance(values, tuple):
                raise TypeError(f"{name} must be a tuple")
            for value in values:
                _require_identifier(name[:-1], value)
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must not contain duplicates")
        if not self.expected_parameter_ids:
            raise ValueError("expected_parameter_ids must not be empty")
        if set(self.qa_required_exception_ids) != set(
            self.qa_disposition_exception_ids
        ):
            raise ValueError(
                "QA dispositions must cover exactly the QA-required exceptions"
            )
        if not set(self.qa_required_exception_ids) <= set(self.exception_ids):
            raise ValueError("QA-required exceptions must belong to the ledger")
        if (
            type(self.expected_adjudication_version) is not int
            or self.expected_adjudication_version < 1
        ):
            raise ValueError(
                "expected_adjudication_version must be a positive integer"
            )
        if self.calculated_request_hash() != self.request_hash:
            raise ValueError("request_hash does not match targeted final request")

    def to_commit_record(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "decision": (
                "APPROVED"
                if self.action is AuditAction.TARGETED_FINAL_APPROVAL_RECORDED
                else "REJECTED"
            ),
            "actor_id": self.actor_id,
            "rationale": self.rationale,
            "evidence_manifest_hash": self.evidence_manifest_hash,
            "targeted_submission_hash": self.targeted_submission_hash,
            "primary_reviewer_id": self.primary_reviewer_id,
            "ai_run_id": self.ai_run_id,
            "expected_parameter_ids": list(self.expected_parameter_ids),
            "exception_ids": list(self.exception_ids),
            "qa_required_exception_ids": list(
                self.qa_required_exception_ids
            ),
            "qa_disposition_exception_ids": list(
                self.qa_disposition_exception_ids
            ),
            "resolution_digest": self.resolution_digest,
            "expected_adjudication_version": (
                self.expected_adjudication_version
            ),
            "expected_previous_head_hash": self.expected_previous_head_hash,
            "command_id": self.command_id,
        }

    def calculated_request_hash(self) -> str:
        return calculate_targeted_final_request_hash(self.to_commit_record())


_CONTROLLED_ACTIONS = frozenset(
    action
    for action in AuditAction
    if action is not AuditAction.GENERIC_NOTE_RECORDED
)
_AI_SERVICE_ACTIONS = frozenset(
    {
        AuditAction.AI_REVIEW_STARTED,
        AuditAction.AI_ASSESSMENT_RECORDED,
        AuditAction.AI_REVIEW_COMPLETED,
    }
)
_AI_CONTEXT_ACTIONS = frozenset(
    {
        *_AI_SERVICE_ACTIONS,
        AuditAction.ROUTE_ASSIGNED,
        AuditAction.SECOND_REVIEW_ASSIGNED,
        AuditAction.SECOND_REVIEW_DECISION_RECORDED,
        AuditAction.SECOND_REVIEW_DECISION_REVISED,
        AuditAction.SECOND_REVIEW_LOCKED,
        AuditAction.QA_CASE_OPENED,
        AuditAction.QA_DISPOSITION_RECORDED,
        AuditAction.QA_DISPOSITION_COMPLETED,
        AuditAction.FINAL_APPROVAL_RECORDED,
        AuditAction.FINAL_REJECTION_RECORDED,
        AuditAction.TARGETED_REVIEW_LOCKED,
        AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED,
        AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
        AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
        AuditAction.SECOND_REVIEW_RECORDED,
    }
)
_HUMAN_ACTIONS = frozenset(
    {
        AuditAction.HUMAN_DECISION_RECORDED,
        AuditAction.HUMAN_DECISION_REVISED,
        AuditAction.HUMAN_REVIEW_LOCKED,
        AuditAction.SECOND_REVIEW_DECISION_RECORDED,
        AuditAction.SECOND_REVIEW_DECISION_REVISED,
        AuditAction.SECOND_REVIEW_LOCKED,
        AuditAction.QA_DISPOSITION_RECORDED,
        AuditAction.QA_DISPOSITION_COMPLETED,
        AuditAction.FINAL_APPROVAL_RECORDED,
        AuditAction.FINAL_REJECTION_RECORDED,
        AuditAction.TARGETED_REVIEW_LOCKED,
        AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED,
        AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
        AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
        AuditAction.SECOND_REVIEW_RECORDED,
        AuditAction.CORRECTION_RECORDED,
    }
)
_TARGETED_TYPED_ACTIONS = frozenset(
    {
        AuditAction.TARGETED_REVIEW_LOCKED,
        AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED,
        AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
        AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
    }
)
_HUMAN_VERDICTS = frozenset({"SAME", "DIFFERENT", "UNABLE_TO_JUDGE"})
_AI_VERDICTS = frozenset(
    {"SAME", "DIFFERENT", "UNABLE_TO_JUDGE", "SYSTEM_ERROR"}
)
_ROUTES = frozenset(
    {
        "NO_EXCEPTION_DETECTED",
        "INDEPENDENT_SECOND_REVIEW_REQUIRED",
        "QA_REVIEW_REQUIRED",
    }
)
_ROUTE_REASONS = frozenset(
    {
        "MISSING_EXPECTED_FIELD",
        "DUPLICATE_EXPECTED_FIELD",
        "UNKNOWN_FIELD",
        "LOW_IMAGE_QUALITY",
        "UNREADABLE_IMAGE",
        "CRITICAL_PARAMETER",
        "HUMAN_UNABLE_TO_JUDGE",
        "AI_UNABLE_TO_JUDGE",
        "AI_SYSTEM_ERROR",
        "HUMAN_AI_DISAGREEMENT",
        "HUMAN_DETECTED_DIFFERENCE",
        "AI_DETECTED_DIFFERENCE",
        "DETERMINISTIC_COMPARISON_NOT_EXACT",
    }
)
_EXCEPTION_SOURCES = frozenset(
    {"ROUTING", "SECOND_REVIEW_RECONCILIATION"}
)
_RECONCILIATION_REASONS = frozenset(
    {
        "PRIMARY_SECOND_DISAGREEMENT",
        "AI_SECOND_DISAGREEMENT",
        "SECOND_REVIEW_UNABLE_TO_JUDGE",
    }
)
_QA_OUTCOMES = frozenset(
    {
        "RESOLVED_NO_BLOCKING_EXCEPTION",
        "CONFIRMED_DIFFERENCE",
        "EVIDENCE_REWORK_REQUIRED",
        "EXTERNAL_DEVIATION_CONTROL_REQUIRED",
        "TASK_INVALIDATED",
    }
)
_QA_RESULT_STATES = frozenset(
    {
        "READY_FOR_FINAL_HUMAN_DECISION",
        "APPROVAL_BLOCKED",
        "REWORK_REQUIRED",
    }
)
_REWORK_OUTCOMES = frozenset(
    {"EVIDENCE_REWORK_REQUIRED", "TASK_INVALIDATED"}
)
_BLOCKING_OUTCOMES = frozenset(
    {"CONFIRMED_DIFFERENCE", "EXTERNAL_DEVIATION_CONTROL_REQUIRED"}
)
_NON_HUMAN_ACTOR_TOKEN = re.compile(
    r"(?:^|[:._-])(?:ai|system|service|admin)(?:$|[:._-])",
    flags=re.IGNORECASE,
)
_AUTOMATED_ACTOR_TOKEN = re.compile(
    r"(?:^|[:._-])(?:ai|system|service)(?:$|[:._-])",
    flags=re.IGNORECASE,
)
_BASE_CONTEXT_KEYS = (
    "manifest_hash",
    "source_artifact_sha256_by_role",
    "schema_id",
    "schema_version",
    "schema_sha256",
    "template_id",
    "template_version",
    "template_sha256",
)

_TARGETED_SUBMISSION_KEYS = frozenset(
    {
        "targeted_submission_version",
        "targeted_case_id",
        "task_id",
        "assignment_id",
        "reviewer_id",
        "evidence_manifest_hash",
        "expected_parameter_ids",
        "routing_context_id",
        "routing_context_version",
        "routing_context_sha256",
        "source_snapshot_sha256",
        "profile_id",
        "profile_version",
        "profile_content_sha256",
        "targeted_items",
        "decisions",
        "qa_referrals",
        "no_exception_parameter_ids",
        "locked_at",
        "automatic_release_allowed",
        "final_human_confirmation_required",
    }
)
_TARGETED_ITEM_KEYS = frozenset(
    {
        "parameter_id",
        "reasons",
        "primary_verdict",
        "ai_verdict",
        "comparison_kind",
        "next_step",
    }
)
_TARGETED_DECISION_KEYS = frozenset(
    {
        "parameter_id",
        "verdict",
        "reason",
        "reviewer_id",
        "decided_at",
        "task_id",
        "assignment_id",
        "evidence_manifest_hash",
        "source_snapshot_sha256",
    }
)
_TARGETED_QA_REFERRAL_KEYS = frozenset(
    {"parameter_id", "reasons", "next_step"}
)
_TARGETED_VERDICTS = frozenset({"SAME", "DIFFERENT", "UNABLE_TO_JUDGE"})
_TARGETED_AI_VERDICTS = frozenset(
    {"SAME", "DIFFERENT", "UNABLE_TO_JUDGE", "SYSTEM_ERROR"}
)
_TARGETED_COMPARISON_KINDS = frozenset(
    {
        "EXACT_MATCH",
        "MISSING_VALUE",
        "FORMAT_DIFFERENCE",
        "VALUE_MISMATCH",
        "UNIT_MISMATCH",
        "VALUE_AND_UNIT_MISMATCH",
        "UNPARSEABLE_DIFFERENCE",
        "NORMALIZATION_COLLISION",
        "TEXT_MISMATCH",
    }
)
_TARGETED_STEP = "TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK"
_TARGETED_QA_STEPS = frozenset(
    {"QA_STRUCTURAL_OR_SYSTEM_REVIEW", "QA_CRITICAL_POLICY_CONFIRMATION"}
)


def _parse_audit_timestamp(name: str, value: Any) -> datetime:
    if not isinstance(value, str):
        raise AuditPolicyError(f"{name} must be an ISO timestamp string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise AuditPolicyError(f"{name} is not a valid ISO timestamp") from error
    try:
        return _normalise_utc(name, parsed)
    except (TypeError, ValueError) as error:
        raise AuditPolicyError(str(error)) from error


def _require_record_keys(
    record: Any, expected: frozenset[str], *, name: str
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise AuditPolicyError(f"{name} must be an object")
    if set(record) != expected:
        missing = expected - set(record)
        unknown = set(record) - expected
        parts: list[str] = []
        if missing:
            parts.append("missing=" + ",".join(sorted(missing)))
        if unknown:
            parts.append("unknown=" + ",".join(sorted(unknown)))
        raise AuditPolicyError(
            f"{name} violates its fixed schema: " + "; ".join(parts)
        )
    return record


def _require_targeted_reason_list(value: Any, *, name: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or item not in _ROUTE_REASONS for item in value)
    ):
        raise AuditPolicyError(f"{name} must be a non-empty fixed-reason list")
    if len(set(value)) != len(value):
        raise AuditPolicyError(f"{name} must not contain duplicates")
    return tuple(value)


def _validate_targeted_submission_record(
    record: Mapping[str, Any], *, expected_submission_hash: str
) -> dict[str, Any]:
    """Validate the complete targeted hand-off without trusting its digest."""

    snapshot = _require_record_keys(
        dict(record), _TARGETED_SUBMISSION_KEYS, name="targeted submission"
    )
    if snapshot["targeted_submission_version"] != 2:
        raise AuditPolicyError("targeted submission version must be 2")
    for name in (
        "targeted_case_id",
        "task_id",
        "assignment_id",
        "reviewer_id",
        "routing_context_id",
        "routing_context_version",
        "profile_version",
    ):
        try:
            _require_identifier(name, snapshot[name])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
    for name in (
        "evidence_manifest_hash",
        "routing_context_sha256",
        "source_snapshot_sha256",
        "profile_content_sha256",
    ):
        try:
            _require_sha256(name, snapshot[name])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
    if (
        snapshot["profile_id"]
        != INTERVIEW_TARGETED_RECHECK.profile_id.value
        or snapshot["profile_version"]
        != INTERVIEW_TARGETED_RECHECK.policy_version
        or snapshot["profile_content_sha256"]
        != INTERVIEW_TARGETED_RECHECK.content_sha256
    ):
        raise AuditPolicyError("targeted submission uses an unapproved profile")
    if snapshot["automatic_release_allowed"] is not False:
        raise AuditPolicyError("targeted submission cannot permit automatic release")
    if snapshot["final_human_confirmation_required"] is not True:
        raise AuditPolicyError("targeted submission must require a final human")
    locked_at = _parse_audit_timestamp("locked_at", snapshot["locked_at"])

    expected = snapshot["expected_parameter_ids"]
    if not isinstance(expected, list) or not expected:
        raise AuditPolicyError("expected_parameter_ids must be a non-empty list")
    try:
        expected_ids = tuple(
            _require_identifier("parameter_id", value) for value in expected
        )
    except (TypeError, ValueError) as error:
        raise AuditPolicyError(str(error)) from error
    if len(set(expected_ids)) != len(expected_ids):
        raise AuditPolicyError("expected_parameter_ids must be unique")

    targeted_ids: list[str] = []
    targeted_items = snapshot["targeted_items"]
    if not isinstance(targeted_items, list):
        raise AuditPolicyError("targeted_items must be a list")
    for index, raw in enumerate(targeted_items):
        item = _require_record_keys(
            raw, _TARGETED_ITEM_KEYS, name=f"targeted_items[{index}]"
        )
        try:
            parameter_id = _require_identifier("parameter_id", item["parameter_id"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        _require_targeted_reason_list(item["reasons"], name="targeted reasons")
        if item["primary_verdict"] not in _HUMAN_VERDICTS:
            raise AuditPolicyError("targeted item has invalid primary verdict")
        if item["ai_verdict"] not in _TARGETED_AI_VERDICTS:
            raise AuditPolicyError("targeted item has invalid AI verdict")
        if item["comparison_kind"] not in _TARGETED_COMPARISON_KINDS:
            raise AuditPolicyError("targeted item has invalid comparison kind")
        if item["next_step"] != _TARGETED_STEP:
            raise AuditPolicyError("targeted item has a non-targeted next step")
        targeted_ids.append(parameter_id)

    decisions = snapshot["decisions"]
    if not isinstance(decisions, list):
        raise AuditPolicyError("targeted decisions must be a list")
    decision_ids: list[str] = []
    for index, raw in enumerate(decisions):
        item = _require_record_keys(
            raw, _TARGETED_DECISION_KEYS, name=f"decisions[{index}]"
        )
        try:
            parameter_id = _require_identifier("parameter_id", item["parameter_id"])
            _require_identifier("reviewer_id", item["reviewer_id"])
            _require_text("reason", item["reason"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        if item["verdict"] not in _TARGETED_VERDICTS:
            raise AuditPolicyError("targeted decision has invalid verdict")
        if _parse_audit_timestamp("decided_at", item["decided_at"]) > locked_at:
            raise AuditPolicyError("targeted decision occurs after its lock")
        if (
            item["reviewer_id"] != snapshot["reviewer_id"]
            or item["task_id"] != snapshot["task_id"]
            or item["assignment_id"] != snapshot["assignment_id"]
            or item["evidence_manifest_hash"]
            != snapshot["evidence_manifest_hash"]
            or item["source_snapshot_sha256"]
            != snapshot["source_snapshot_sha256"]
        ):
            raise AuditPolicyError("targeted decision binding is inconsistent")
        decision_ids.append(parameter_id)
    if decision_ids != targeted_ids:
        raise AuditPolicyError(
            "targeted decisions must exactly cover items in frozen order"
        )

    qa_ids: list[str] = []
    referrals = snapshot["qa_referrals"]
    if not isinstance(referrals, list):
        raise AuditPolicyError("qa_referrals must be a list")
    for index, raw in enumerate(referrals):
        item = _require_record_keys(
            raw, _TARGETED_QA_REFERRAL_KEYS, name=f"qa_referrals[{index}]"
        )
        try:
            parameter_id = _require_identifier("parameter_id", item["parameter_id"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        _require_targeted_reason_list(item["reasons"], name="QA referral reasons")
        if item["next_step"] not in _TARGETED_QA_STEPS:
            raise AuditPolicyError("QA referral has a non-QA next step")
        qa_ids.append(parameter_id)

    clean = snapshot["no_exception_parameter_ids"]
    if not isinstance(clean, list):
        raise AuditPolicyError("no_exception_parameter_ids must be a list")
    try:
        clean_ids = [
            _require_identifier("parameter_id", value) for value in clean
        ]
    except (TypeError, ValueError) as error:
        raise AuditPolicyError(str(error)) from error
    partition = [*targeted_ids, *qa_ids, *clean_ids]
    if len(partition) != len(set(partition)) or set(partition) != set(expected_ids):
        raise AuditPolicyError(
            "targeted, QA, and clean partitions must be disjoint and complete"
        )
    schema_index = {value: index for index, value in enumerate(expected_ids)}
    for name, values in (
        ("targeted", targeted_ids),
        ("QA", qa_ids),
        ("clean", clean_ids),
    ):
        positions = [schema_index[value] for value in values]
        if positions != sorted(positions):
            raise AuditPolicyError(f"{name} partition is not in schema order")

    try:
        trusted_hash = _require_sha256(
            "expected_submission_hash", expected_submission_hash
        )
    except (TypeError, ValueError) as error:
        raise AuditPolicyError(str(error)) from error
    calculated = hashlib.sha256(_canonical_json(snapshot).encode("utf-8")).hexdigest()
    if calculated != trusted_hash:
        raise AuditPolicyError(
            "targeted submission content differs from its trusted hash"
        )
    return snapshot


def calculate_targeted_exception_records(
    submission_record: Mapping[str, Any], *, submission_hash: str
) -> tuple[dict[str, Any], ...]:
    """Build the canonical exception ledger from a validated submission."""

    snapshot = _validate_targeted_submission_record(
        submission_record, expected_submission_hash=submission_hash
    )
    result: list[dict[str, Any]] = []

    def add(parameter_id: str, origin: str, verdict: str | None) -> None:
        exception_id = "texc-" + hashlib.sha256(
            _canonical_json(
                {
                    "task_id": snapshot["task_id"],
                    "targeted_submission_hash": submission_hash,
                    "parameter_id": parameter_id,
                    "origin": origin,
                }
            ).encode("utf-8")
        ).hexdigest()[:24]
        result.append(
            {
                "exception_id": exception_id,
                "parameter_id": parameter_id,
                "origin": origin,
                "targeted_verdict": verdict,
                "qa_required": origin == "PROFILE_QA_REFERRAL" or verdict != "SAME",
            }
        )

    for decision in snapshot["decisions"]:
        add(decision["parameter_id"], "TARGETED_RECHECK", decision["verdict"])
    for referral in snapshot["qa_referrals"]:
        add(referral["parameter_id"], "PROFILE_QA_REFERRAL", None)
    return tuple(result)


def calculate_targeted_resolution_digest(
    *,
    task_id: str,
    submission_hash: str,
    exceptions: Sequence[Mapping[str, Any]],
    dispositions: Sequence[Mapping[str, Any]],
) -> str:
    """Canonical targeted-domain resolution digest shared with audit replay."""

    _require_identifier("task_id", task_id)
    _require_sha256("submission_hash", submission_hash)
    body = {
        "task_id": task_id,
        "targeted_submission_hash": submission_hash,
        "exceptions": [dict(item) for item in exceptions],
        "qa_dispositions": sorted(
            (dict(item) for item in dispositions),
            key=lambda item: item["exception_id"],
        ),
        "automatic_release_allowed": False,
        "final_human_confirmation_required": True,
    }
    return hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()


def _context_from_json_record(record: Mapping[str, Any] | None) -> EvidenceContext | None:
    if record is None:
        return None
    return EvidenceContext.from_record(record)


def _base_context_record(context: EvidenceContext) -> dict[str, Any]:
    record = context.to_record()
    return {key: record[key] for key in _BASE_CONTEXT_KEYS}


def _has_ai_binding(context: EvidenceContext) -> bool:
    required = (
        context.run_id,
        context.pipeline_spec_hash,
        context.pipeline_version,
        context.comparator_version,
    )
    return all(value is not None for value in required) and (
        context.ocr_engine is not None or context.model_name is not None
    )


def _has_any_ai_metadata(context: EvidenceContext) -> bool:
    return any(
        value is not None
        for value in (
            context.run_id,
            context.pipeline_spec_hash,
            context.pipeline_version,
            context.comparator_version,
            context.ocr_engine,
            context.ocr_version,
            context.model_name,
            context.model_version,
        )
    )


def _require_exact_detail_keys(
    details: Mapping[str, Any], expected: set[str], *, action: AuditAction
) -> None:
    actual = set(details)
    if actual != expected:
        missing = expected - actual
        unknown = actual - expected
        pieces: list[str] = []
        if missing:
            pieces.append("missing=" + ",".join(sorted(missing)))
        if unknown:
            pieces.append("unknown=" + ",".join(sorted(unknown)))
        raise AuditPolicyError(
            f"{action.value} details violate the fixed schema: " + "; ".join(pieces)
        )


def _require_reason_for_exception(
    verdict: str, reason: str | None, *, action: AuditAction
) -> None:
    if verdict not in {"SAME"} and reason is None:
        raise AuditPolicyError(f"{action.value} verdict {verdict} requires a reason")


def _require_no_parameter(
    parameter_id: str | None, *, action: AuditAction
) -> None:
    if parameter_id is not None:
        raise AuditPolicyError(f"{action.value} must not name a parameter")


def _require_no_reason(reason: str | None, *, action: AuditAction) -> None:
    if reason is not None:
        raise AuditPolicyError(
            f"{action.value} uses its fixed details schema and must not use reason"
        )


def _validate_exception_records(value: Any) -> tuple[dict[str, str], ...]:
    if not isinstance(value, list) or not value:
        raise AuditPolicyError("QA_CASE_OPENED exceptions must be a non-empty list")
    result: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    seen_facts: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise AuditPolicyError(
                f"QA_CASE_OPENED exceptions[{index}] must be an object"
            )
        _require_exact_detail_keys(
            raw,
            {"exception_id", "parameter_id", "source", "reason_code"},
            action=AuditAction.QA_CASE_OPENED,
        )
        try:
            exception_id = _require_identifier("exception_id", raw["exception_id"])
            parameter_id = _require_identifier("parameter_id", raw["parameter_id"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        source = raw["source"]
        reason_code = raw["reason_code"]
        if not isinstance(source, str) or source not in _EXCEPTION_SOURCES:
            raise AuditPolicyError("QA_CASE_OPENED contains an invalid exception source")
        allowed_reasons = (
            _ROUTE_REASONS
            if source == "ROUTING"
            else _RECONCILIATION_REASONS
        )
        if not isinstance(reason_code, str) or reason_code not in allowed_reasons:
            raise AuditPolicyError(
                "QA_CASE_OPENED contains an invalid reason for its exception source"
            )
        fact = (parameter_id, source, reason_code)
        if exception_id in seen_ids or fact in seen_facts:
            raise AuditPolicyError(
                "QA_CASE_OPENED exceptions must not contain duplicate IDs or facts"
            )
        seen_ids.add(exception_id)
        seen_facts.add(fact)
        result.append(
            {
                "exception_id": exception_id,
                "parameter_id": parameter_id,
                "source": source,
                "reason_code": reason_code,
            }
        )
    return tuple(result)


def _validate_reference_ids(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AuditPolicyError("reference_ids must be a list")
    try:
        checked = tuple(_require_identifier("reference_id", item) for item in value)
    except (TypeError, ValueError) as error:
        raise AuditPolicyError(str(error)) from error
    if len(set(checked)) != len(checked):
        raise AuditPolicyError("reference_ids must not contain duplicates")
    return checked


def _require_sha256_or_none(name: str, value: Any) -> str | None:
    if value is None:
        return None
    try:
        return _require_sha256(name, value)
    except (TypeError, ValueError) as error:
        raise AuditPolicyError(str(error)) from error


def _is_final_human_actor(actor_id: str) -> bool:
    """PoC-only fail-closed check; production must inject verified roles."""

    return _NON_HUMAN_ACTOR_TOKEN.search(actor_id) is None


def _is_human_actor(actor_id: str) -> bool:
    return _AUTOMATED_ACTOR_TOKEN.search(actor_id) is None


def _validate_ai_assessment_details(
    details: Mapping[str, Any], reason: str | None
) -> None:
    action = AuditAction.AI_ASSESSMENT_RECORDED
    _require_exact_detail_keys(
        details,
        {
            "verdict",
            "left_raw",
            "right_raw",
            "extraction_reliable",
            "comparison_kind",
            "exact_match",
        },
        action=action,
    )
    verdict = details["verdict"]
    if not isinstance(verdict, str) or verdict not in _AI_VERDICTS:
        raise AuditPolicyError("AI assessment verdict is not an allowed fixed value")
    if type(details["extraction_reliable"]) is not bool:
        raise AuditPolicyError("AI assessment extraction_reliable must be bool")
    if type(details["exact_match"]) is not bool:
        raise AuditPolicyError("AI assessment exact_match must be bool")

    left_raw = details["left_raw"]
    right_raw = details["right_raw"]
    comparison_kind = details["comparison_kind"]
    extraction_reliable = details["extraction_reliable"]

    if verdict == "SYSTEM_ERROR":
        if (
            left_raw is not None
            or right_raw is not None
            or extraction_reliable
            or comparison_kind is not None
            or details["exact_match"]
            or reason is None
        ):
            raise AuditPolicyError("Malformed SYSTEM_ERROR assessment details")
        return

    try:
        comparison = compare_values(left_raw, right_raw)
    except (TypeError, ValueError) as error:
        raise AuditPolicyError(f"Invalid AI raw values: {error}") from error
    if comparison_kind != comparison.kind.value:
        raise AuditPolicyError(
            "AI comparison_kind differs from the deterministic comparison"
        )
    if details["exact_match"] is not comparison.exact_match:
        raise AuditPolicyError(
            "AI exact_match differs from the deterministic comparison"
        )

    if not extraction_reliable or comparison.kind is ComparisonKind.MISSING_VALUE:
        expected_verdict = "UNABLE_TO_JUDGE"
    elif comparison.exact_match:
        expected_verdict = "SAME"
    else:
        expected_verdict = "DIFFERENT"
    if verdict != expected_verdict:
        raise AuditPolicyError(
            "AI verdict differs from the deterministic comparison and quality gate"
        )
    _require_reason_for_exception(verdict, reason, action=action)


def _validate_action_contract(
    *,
    actor_id: str,
    action: AuditAction,
    details: Mapping[str, Any],
    parameter_id: str | None,
    reason: str | None,
    evidence_context: EvidenceContext | None,
) -> None:
    """Validate fixed event shapes before any record reaches the log."""

    if action in _CONTROLLED_ACTIONS and evidence_context is None:
        raise AuditPolicyError(
            f"{action.value} requires a frozen evidence manifest context"
        )
    if action in _AI_CONTEXT_ACTIONS:
        assert evidence_context is not None
        if not _has_ai_binding(evidence_context):
            raise AuditPolicyError(
                f"{action.value} requires run, pipeline, comparator, and engine identity"
            )
    elif action in _CONTROLLED_ACTIONS and action is not AuditAction.CORRECTION_RECORDED:
        assert evidence_context is not None
        if _has_any_ai_metadata(evidence_context):
            raise AuditPolicyError(
                f"{action.value} must not carry AI-run metadata"
            )

    if action in _AI_SERVICE_ACTIONS:
        if not actor_id.startswith("service:ai:"):
            raise AuditPolicyError(
                f"{action.value} requires an authenticated AI-service actor"
            )
    elif action is AuditAction.ROUTE_ASSIGNED:
        if not actor_id.startswith("service:rules:"):
            raise AuditPolicyError(
                "ROUTE_ASSIGNED requires an authenticated rules-service actor"
            )
    elif action in {
        AuditAction.SECOND_REVIEW_ASSIGNED,
        AuditAction.QA_CASE_OPENED,
    }:
        if not actor_id.startswith("service:workflow:"):
            raise AuditPolicyError(
                f"{action.value} requires an authenticated workflow-service actor"
            )
    elif action in _HUMAN_ACTIONS and not _is_human_actor(actor_id):
        raise AuditPolicyError(f"{action.value} requires a human actor")
    if action in {
        AuditAction.FINAL_APPROVAL_RECORDED,
        AuditAction.FINAL_REJECTION_RECORDED,
        AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
        AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
    } and not _is_final_human_actor(actor_id):
        raise AuditPolicyError(
            f"{action.value} requires a non-service, non-AI, non-system, non-admin human actor"
        )

    if action is AuditAction.TARGETED_REVIEW_LOCKED:
        _require_no_parameter(parameter_id, action=action)
        _require_no_reason(reason, action=action)
        _require_exact_detail_keys(
            details,
            {
                "submission",
                "submission_hash",
                "primary_reviewer_id",
                "ai_run_id",
                "targeted_reviewer_kind",
                "targeted_reviewer_roles",
                "assigned_qa_reviewer_id",
                "assigned_final_approver_id",
                "audit_head_predecessor",
                "command_id",
                "request_hash",
            },
            action=action,
        )
        try:
            submission_hash = _require_sha256(
                "submission_hash", details["submission_hash"]
            )
            _require_identifier(
                "primary_reviewer_id", details["primary_reviewer_id"]
            )
            _require_identifier("ai_run_id", details["ai_run_id"])
            if details["assigned_qa_reviewer_id"] is not None:
                _require_identifier(
                    "assigned_qa_reviewer_id",
                    details["assigned_qa_reviewer_id"],
                )
            _require_identifier(
                "assigned_final_approver_id",
                details["assigned_final_approver_id"],
            )
            _require_sha256(
                "audit_head_predecessor", details["audit_head_predecessor"]
            )
            _require_identifier("command_id", details["command_id"])
            _require_sha256("request_hash", details["request_hash"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        if details["targeted_reviewer_kind"] != "HUMAN":
            raise AuditPolicyError("targeted reviewer kind must be HUMAN")
        roles = details["targeted_reviewer_roles"]
        if (
            not isinstance(roles, list)
            or not roles
            or any(
                type(value) is not str
                or value not in {"PRIMARY_REVIEWER", "SECOND_REVIEWER"}
                for value in roles
            )
            or len(set(roles)) != len(roles)
            or roles != sorted(roles)
        ):
            raise AuditPolicyError(
                "targeted reviewer roles must be unique reviewer roles"
            )
        _validate_targeted_submission_record(
            details["submission"], expected_submission_hash=submission_hash
        )
        return
    if action is AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED:
        _require_no_parameter(parameter_id, action=action)
        _require_no_reason(reason, action=action)
        _require_exact_detail_keys(
            details,
            {
                "targeted_submission_hash",
                "exception_id",
                "outcome",
                "rationale",
                "reference_ids",
                "adjudication_version",
                "audit_head_predecessor",
                "command_id",
                "request_hash",
            },
            action=action,
        )
        try:
            _require_sha256(
                "targeted_submission_hash",
                details["targeted_submission_hash"],
            )
            _require_identifier("exception_id", details["exception_id"])
            _require_text("rationale", details["rationale"])
            _require_sha256(
                "audit_head_predecessor", details["audit_head_predecessor"]
            )
            _require_identifier("command_id", details["command_id"])
            _require_sha256("request_hash", details["request_hash"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        if details["outcome"] not in _QA_OUTCOMES:
            raise AuditPolicyError("targeted QA outcome is invalid")
        _validate_reference_ids(details["reference_ids"])
        if (
            type(details["adjudication_version"]) is not int
            or details["adjudication_version"] < 1
        ):
            raise AuditPolicyError(
                "targeted QA adjudication_version must be positive"
            )
        return
    if action in {
        AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
        AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
    }:
        _require_no_parameter(parameter_id, action=action)
        _require_no_reason(reason, action=action)
        _require_exact_detail_keys(
            details,
            {
                "evidence_manifest_hash",
                "targeted_submission_hash",
                "resolution_digest",
                "audit_head_predecessor",
                "rationale",
                "commit_request_hash",
                "command_id",
                "adjudication_version",
            },
            action=action,
        )
        try:
            for name in (
                "evidence_manifest_hash",
                "targeted_submission_hash",
                "resolution_digest",
                "audit_head_predecessor",
                "commit_request_hash",
            ):
                _require_sha256(name, details[name])
            _require_identifier("command_id", details["command_id"])
            _require_text("rationale", details["rationale"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        if (
            type(details["adjudication_version"]) is not int
            or details["adjudication_version"] < 1
        ):
            raise AuditPolicyError(
                "targeted final adjudication_version must be positive"
            )
        return
    if action is AuditAction.GENERIC_NOTE_RECORDED:
        return
    if action is AuditAction.TASK_CREATED:
        if parameter_id is not None:
            raise AuditPolicyError("TASK_CREATED must not name a parameter")
        _require_exact_detail_keys(
            details, {"expected_parameter_ids", "reviewer_id"}, action=action
        )
        expected_ids = details["expected_parameter_ids"]
        if not isinstance(expected_ids, list) or not expected_ids:
            raise AuditPolicyError(
                "TASK_CREATED expected_parameter_ids must be a non-empty list"
            )
        try:
            checked_ids = [
                _require_identifier("parameter_id", value) for value in expected_ids
            ]
            _require_identifier("reviewer_id", details["reviewer_id"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        if len(set(checked_ids)) != len(checked_ids):
            raise AuditPolicyError(
                "TASK_CREATED expected_parameter_ids must not contain duplicates"
            )
        return
    if action in {
        AuditAction.HUMAN_DECISION_RECORDED,
        AuditAction.HUMAN_DECISION_REVISED,
        AuditAction.SECOND_REVIEW_RECORDED,
    }:
        if parameter_id is None:
            raise AuditPolicyError(f"{action.value} requires parameter_id")
        _require_exact_detail_keys(details, {"verdict"}, action=action)
        verdict = details["verdict"]
        if not isinstance(verdict, str) or verdict not in _HUMAN_VERDICTS:
            raise AuditPolicyError(f"{action.value} has an invalid verdict")
        _require_reason_for_exception(verdict, reason, action=action)
        return
    if action is AuditAction.HUMAN_REVIEW_LOCKED:
        if parameter_id is not None:
            raise AuditPolicyError("HUMAN_REVIEW_LOCKED must not name a parameter")
        _require_exact_detail_keys(details, {"decision_count"}, action=action)
        if type(details["decision_count"]) is not int or details["decision_count"] <= 0:
            raise AuditPolicyError("decision_count must be a positive integer")
        return
    if action is AuditAction.AI_REVIEW_STARTED:
        if parameter_id is not None:
            raise AuditPolicyError("AI_REVIEW_STARTED must not name a parameter")
        _require_exact_detail_keys(details, set(), action=action)
        return
    if action is AuditAction.AI_ASSESSMENT_RECORDED:
        if parameter_id is None:
            raise AuditPolicyError("AI_ASSESSMENT_RECORDED requires parameter_id")
        _validate_ai_assessment_details(details, reason)
        return
    if action is AuditAction.AI_REVIEW_COMPLETED:
        if parameter_id is not None:
            raise AuditPolicyError("AI_REVIEW_COMPLETED must not name a parameter")
        _require_exact_detail_keys(details, {"assessment_count"}, action=action)
        if type(details["assessment_count"]) is not int or details["assessment_count"] <= 0:
            raise AuditPolicyError("assessment_count must be a positive integer")
        return
    if action is AuditAction.ROUTE_ASSIGNED:
        if parameter_id is None:
            raise AuditPolicyError("ROUTE_ASSIGNED requires parameter_id")
        _require_exact_detail_keys(details, {"route", "reasons"}, action=action)
        route = details["route"]
        reasons = details["reasons"]
        if not isinstance(route, str) or route not in _ROUTES:
            raise AuditPolicyError("ROUTE_ASSIGNED contains an invalid route")
        if not isinstance(reasons, list) or any(
            not isinstance(item, str) or item.strip() == "" for item in reasons
        ):
            raise AuditPolicyError("ROUTE_ASSIGNED reasons must be a list of strings")
        if len(set(reasons)) != len(reasons):
            raise AuditPolicyError("ROUTE_ASSIGNED reasons must not contain duplicates")
        if any(reason not in _ROUTE_REASONS for reason in reasons):
            raise AuditPolicyError("ROUTE_ASSIGNED contains an invalid fixed reason")
        if route == "NO_EXCEPTION_DETECTED" and reasons:
            raise AuditPolicyError("NO_EXCEPTION_DETECTED must not contain reasons")
        if route != "NO_EXCEPTION_DETECTED" and not reasons:
            raise AuditPolicyError("A review-required route must contain a reason")
        return
    if action is AuditAction.SECOND_REVIEW_ASSIGNED:
        _require_no_parameter(parameter_id, action=action)
        _require_no_reason(reason, action=action)
        _require_exact_detail_keys(
            details, {"blind_case_id", "assigned_reviewer_id"}, action=action
        )
        try:
            _require_identifier("blind_case_id", details["blind_case_id"])
            assigned_reviewer_id = _require_identifier(
                "assigned_reviewer_id", details["assigned_reviewer_id"]
            )
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        if not _is_human_actor(assigned_reviewer_id):
            raise AuditPolicyError(
                "SECOND_REVIEW_ASSIGNED requires a human assigned reviewer"
            )
        return
    if action in {
        AuditAction.SECOND_REVIEW_DECISION_RECORDED,
        AuditAction.SECOND_REVIEW_DECISION_REVISED,
    }:
        if parameter_id is None:
            raise AuditPolicyError(f"{action.value} requires parameter_id")
        _require_exact_detail_keys(
            details, {"blind_case_id", "verdict"}, action=action
        )
        try:
            _require_identifier("blind_case_id", details["blind_case_id"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        verdict = details["verdict"]
        if not isinstance(verdict, str) or verdict not in _HUMAN_VERDICTS:
            raise AuditPolicyError(f"{action.value} has an invalid verdict")
        _require_reason_for_exception(verdict, reason, action=action)
        return
    if action is AuditAction.SECOND_REVIEW_LOCKED:
        _require_no_parameter(parameter_id, action=action)
        _require_no_reason(reason, action=action)
        _require_exact_detail_keys(
            details,
            {"blind_case_id", "decision_count", "second_submission_hash"},
            action=action,
        )
        try:
            _require_identifier("blind_case_id", details["blind_case_id"])
            _require_sha256(
                "second_submission_hash", details["second_submission_hash"]
            )
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        if type(details["decision_count"]) is not int or details["decision_count"] <= 0:
            raise AuditPolicyError("decision_count must be a positive integer")
        return
    if action is AuditAction.QA_CASE_OPENED:
        _require_no_parameter(parameter_id, action=action)
        _require_no_reason(reason, action=action)
        _require_exact_detail_keys(
            details, {"exceptions", "second_submission_hash"}, action=action
        )
        _validate_exception_records(details["exceptions"])
        _require_sha256_or_none(
            "second_submission_hash", details["second_submission_hash"]
        )
        return
    if action is AuditAction.QA_DISPOSITION_RECORDED:
        _require_no_parameter(parameter_id, action=action)
        _require_no_reason(reason, action=action)
        _require_exact_detail_keys(
            details,
            {"exception_id", "outcome", "rationale", "reference_ids"},
            action=action,
        )
        try:
            _require_identifier("exception_id", details["exception_id"])
            _require_text("rationale", details["rationale"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        outcome = details["outcome"]
        if not isinstance(outcome, str) or outcome not in _QA_OUTCOMES:
            raise AuditPolicyError("QA_DISPOSITION_RECORDED has an invalid outcome")
        _validate_reference_ids(details["reference_ids"])
        return
    if action is AuditAction.QA_DISPOSITION_COMPLETED:
        _require_no_parameter(parameter_id, action=action)
        _require_no_reason(reason, action=action)
        _require_exact_detail_keys(
            details,
            {"disposition_count", "result_state", "resolution_digest"},
            action=action,
        )
        if (
            type(details["disposition_count"]) is not int
            or details["disposition_count"] <= 0
        ):
            raise AuditPolicyError("disposition_count must be a positive integer")
        if (
            not isinstance(details["result_state"], str)
            or details["result_state"] not in _QA_RESULT_STATES
        ):
            raise AuditPolicyError("QA_DISPOSITION_COMPLETED has an invalid result_state")
        try:
            _require_sha256("resolution_digest", details["resolution_digest"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        return
    if action in {
        AuditAction.FINAL_APPROVAL_RECORDED,
        AuditAction.FINAL_REJECTION_RECORDED,
    }:
        _require_no_parameter(parameter_id, action=action)
        _require_no_reason(reason, action=action)
        _require_exact_detail_keys(
            details,
            {
                "evidence_manifest_hash",
                "second_submission_hash",
                "resolution_digest",
                "audit_head_predecessor",
                "rationale",
                "commit_request_hash",
                "command_id",
                "adjudication_version",
            },
            action=action,
        )
        try:
            _require_sha256(
                "evidence_manifest_hash", details["evidence_manifest_hash"]
            )
            _require_sha256("resolution_digest", details["resolution_digest"])
            _require_sha256(
                "audit_head_predecessor", details["audit_head_predecessor"]
            )
            _require_sha256(
                "commit_request_hash", details["commit_request_hash"]
            )
            _require_identifier("command_id", details["command_id"])
            _require_text("rationale", details["rationale"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        if (
            type(details["adjudication_version"]) is not int
            or details["adjudication_version"] < 0
        ):
            raise AuditPolicyError(
                "adjudication_version must be a non-negative integer"
            )
        _require_sha256_or_none(
            "second_submission_hash", details["second_submission_hash"]
        )
        return
    if action is AuditAction.CORRECTION_RECORDED:
        _require_exact_detail_keys(
            details,
            {"corrects_event_id", "original_event_hash", "corrected_details"},
            action=action,
        )
        try:
            _require_identifier("corrects_event_id", details["corrects_event_id"])
            _require_sha256("original_event_hash", details["original_event_hash"])
        except (TypeError, ValueError) as error:
            raise AuditPolicyError(str(error)) from error
        if not isinstance(details["corrected_details"], dict):
            raise AuditPolicyError("corrected_details must be a JSON object")
        if reason is None:
            raise AuditPolicyError("CORRECTION_RECORDED requires a reason")
        return
    raise AuditPolicyError(f"No controlled schema is defined for {action.value}")


@dataclass(frozen=True)
class AuditEvent:
    audit_schema_version: int
    sequence: int
    event_id: str
    task_id: str
    parameter_id: str | None
    actor_id: str
    occurred_at: datetime
    action: AuditAction
    reason: str | None
    details_json: str
    evidence_context_json: str | None
    previous_hash: str
    event_hash: str

    @property
    def details(self) -> dict[str, Any]:
        return json.loads(self.details_json)

    @property
    def evidence_context(self) -> dict[str, Any] | None:
        if self.evidence_context_json is None:
            return None
        return json.loads(self.evidence_context_json)

    def to_record(self) -> dict[str, Any]:
        return {
            **_event_hash_body(self),
            "event_hash": self.event_hash,
        }


def _event_hash_body(event: AuditEvent) -> dict[str, Any]:
    return {
        "audit_schema_version": event.audit_schema_version,
        "sequence": event.sequence,
        "event_id": event.event_id,
        "task_id": event.task_id,
        "parameter_id": event.parameter_id,
        "actor_id": event.actor_id,
        "occurred_at": event.occurred_at.isoformat(),
        "action": event.action.value,
        "reason": event.reason,
        "details": event.details,
        "evidence_context": event.evidence_context,
        "previous_hash": event.previous_hash,
    }


def _calculate_event_hash(event: AuditEvent) -> str:
    body = _canonical_json(_event_hash_body(event)).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _event_context(event: AuditEvent) -> EvidenceContext | None:
    record = event.evidence_context
    return _context_from_json_record(record)


def _same_full_context(
    left: EvidenceContext | None, right: EvidenceContext | None
) -> bool:
    if left is None or right is None:
        return left is right
    return left.to_record() == right.to_record()


def _latest_verdicts(
    events: Sequence[AuditEvent], actions: frozenset[AuditAction]
) -> dict[str, str]:
    result: dict[str, str] = {}
    for event in events:
        if event.action in actions:
            assert event.parameter_id is not None
            result[event.parameter_id] = event.details["verdict"]
    return result


def _route_events_by_parameter(
    events: Sequence[AuditEvent],
) -> dict[str, AuditEvent]:
    return {
        event.parameter_id: event
        for event in events
        if event.action is AuditAction.ROUTE_ASSIGNED
        and event.parameter_id is not None
    }


def _require_complete_routes(
    events: Sequence[AuditEvent], expected_id_set: frozenset[str]
) -> dict[str, AuditEvent]:
    routes = _route_events_by_parameter(events)
    actual = frozenset(routes)
    if actual != expected_id_set:
        missing = expected_id_set - actual
        extra = actual - expected_id_set
        pieces: list[str] = []
        if missing:
            pieces.append("missing=" + ",".join(sorted(missing)))
        if extra:
            pieces.append("extra=" + ",".join(sorted(extra)))
        raise AuditPolicyError(
            "Adjudication requires exactly one route for every frozen parameter; "
            + "; ".join(pieces)
        )
    return routes


def _make_exception_record(
    *, task_id: str, parameter_id: str, source: str, reason_code: str
) -> dict[str, str]:
    digest = hashlib.sha256(
        _canonical_json(
            {
                "task_id": task_id,
                "parameter_id": parameter_id,
                "source": source,
                "reason_code": reason_code,
            }
        ).encode("utf-8")
    ).hexdigest()
    return {
        "exception_id": "exc-" + digest[:24],
        "parameter_id": parameter_id,
        "source": source,
        "reason_code": reason_code,
    }


def _expected_exception_records(
    *,
    task_id: str,
    expected_ids: Sequence[str],
    task_events: Sequence[AuditEvent],
    include_second_review: bool,
) -> tuple[dict[str, str], ...]:
    """Rebuild the adjudication ledger from frozen routing and review facts."""

    routes = _route_events_by_parameter(task_events)
    result: list[dict[str, str]] = []
    for parameter_id in expected_ids:
        route = routes[parameter_id]
        for reason_code in route.details["reasons"]:
            result.append(
                _make_exception_record(
                    task_id=task_id,
                    parameter_id=parameter_id,
                    source="ROUTING",
                    reason_code=reason_code,
                )
            )

    if include_second_review:
        primary = _latest_verdicts(
            task_events,
            frozenset(
                {
                    AuditAction.HUMAN_DECISION_RECORDED,
                    AuditAction.HUMAN_DECISION_REVISED,
                }
            ),
        )
        ai = _latest_verdicts(
            task_events, frozenset({AuditAction.AI_ASSESSMENT_RECORDED})
        )
        second = _latest_verdicts(
            task_events,
            frozenset(
                {
                    AuditAction.SECOND_REVIEW_DECISION_RECORDED,
                    AuditAction.SECOND_REVIEW_DECISION_REVISED,
                }
            ),
        )
        for parameter_id in expected_ids:
            second_verdict = second[parameter_id]
            reasons: list[str] = []
            if second_verdict == "UNABLE_TO_JUDGE":
                reasons.append("SECOND_REVIEW_UNABLE_TO_JUDGE")
            if primary[parameter_id] != second_verdict:
                reasons.append("PRIMARY_SECOND_DISAGREEMENT")
            if (
                ai[parameter_id] not in {"UNABLE_TO_JUDGE", "SYSTEM_ERROR"}
                and ai[parameter_id] != second_verdict
            ):
                reasons.append("AI_SECOND_DISAGREEMENT")
            for reason_code in reasons:
                result.append(
                    _make_exception_record(
                        task_id=task_id,
                        parameter_id=parameter_id,
                        source="SECOND_REVIEW_RECONCILIATION",
                        reason_code=reason_code,
                    )
                )
    return tuple(result)


def _qa_result_state(dispositions: Sequence[AuditEvent]) -> str:
    outcomes = {event.details["outcome"] for event in dispositions}
    if outcomes & _REWORK_OUTCOMES:
        return "REWORK_REQUIRED"
    if outcomes & _BLOCKING_OUTCOMES:
        return "APPROVAL_BLOCKED"
    return "READY_FOR_FINAL_HUMAN_DECISION"


_BASE_FINAL_PRIOR_ACTIONS = (
    AuditAction.TASK_CREATED,
    AuditAction.HUMAN_DECISION_RECORDED,
    AuditAction.HUMAN_REVIEW_LOCKED,
    AuditAction.AI_REVIEW_STARTED,
    AuditAction.AI_ASSESSMENT_RECORDED,
    AuditAction.AI_REVIEW_COMPLETED,
    AuditAction.ROUTE_ASSIGNED,
)


def _canonical_final_prior_actions(
    *, has_second_review: bool, has_exceptions: bool
) -> tuple[AuditAction, ...]:
    actions = list(_BASE_FINAL_PRIOR_ACTIONS)
    if has_second_review:
        actions.extend(
            (
                AuditAction.SECOND_REVIEW_ASSIGNED,
                AuditAction.SECOND_REVIEW_DECISION_RECORDED,
                AuditAction.SECOND_REVIEW_LOCKED,
            )
        )
    if has_exceptions:
        actions.extend(
            (
                AuditAction.QA_CASE_OPENED,
                AuditAction.QA_DISPOSITION_RECORDED,
                AuditAction.QA_DISPOSITION_COMPLETED,
            )
        )
    return tuple(actions)


def _canonical_adjudication_version(
    *, has_second_review: bool, qa_disposition_count: int
) -> int:
    # record_routing + optional reconcile + each disposition + QA completion.
    return (
        1
        + (1 if has_second_review else 0)
        + qa_disposition_count
        + (1 if qa_disposition_count else 0)
    )


def _final_commit_record_from_prior_events(
    *,
    task_id: str,
    action: AuditAction,
    actor_id: str,
    details: Mapping[str, Any],
    expected_ids: Sequence[str],
    assigned_reviewer: str,
    task_events: Sequence[AuditEvent],
) -> dict[str, Any]:
    completed = next(
        event
        for event in task_events
        if event.action is AuditAction.AI_REVIEW_COMPLETED
    )
    completed_context = _event_context(completed)
    assert completed_context is not None and completed_context.run_id is not None
    qa_open = next(
        (
            event
            for event in task_events
            if event.action is AuditAction.QA_CASE_OPENED
        ),
        None,
    )
    exception_ids = (
        ()
        if qa_open is None
        else tuple(
            sorted(
                item["exception_id"] for item in qa_open.details["exceptions"]
            )
        )
    )
    disposition_ids = tuple(
        sorted(
            event.details["exception_id"]
            for event in task_events
            if event.action is AuditAction.QA_DISPOSITION_RECORDED
        )
    )
    has_second = details["second_submission_hash"] is not None
    required = _canonical_final_prior_actions(
        has_second_review=has_second,
        has_exceptions=bool(exception_ids),
    )
    return {
        "task_id": task_id,
        "decision": (
            "APPROVED"
            if action is AuditAction.FINAL_APPROVAL_RECORDED
            else "REJECTED"
        ),
        "actor_id": actor_id,
        "rationale": details["rationale"],
        "evidence_manifest_hash": details["evidence_manifest_hash"],
        "second_submission_hash": details["second_submission_hash"],
        "primary_reviewer_id": assigned_reviewer,
        "ai_run_id": completed_context.run_id,
        "expected_parameter_ids": list(expected_ids),
        "exception_ids": list(exception_ids),
        "qa_disposition_exception_ids": list(disposition_ids),
        "resolution_digest": details["resolution_digest"],
        "expected_adjudication_version": details["adjudication_version"],
        "expected_previous_head_hash": details["audit_head_predecessor"],
        "required_prior_actions": [item.value for item in required],
        "command_id": details["command_id"],
    }


def _validate_final_commit_coverage(
    events: Sequence[AuditEvent], request: FinalAuditWriteRequest
) -> EvidenceContext:
    """Validate task-level and field-level coverage while the file is locked."""

    task_events = [
        event
        for event in events
        if event.task_id == request.task_id
        and event.action is not AuditAction.GENERIC_NOTE_RECORDED
    ]
    created = [
        event for event in task_events if event.action is AuditAction.TASK_CREATED
    ]
    if len(created) != 1:
        raise AuditPolicyError(
            "Atomic final commit requires exactly one audited TASK_CREATED"
        )
    created_event = created[0]
    if tuple(created_event.details["expected_parameter_ids"]) != (
        request.expected_parameter_ids
    ):
        raise AuditPolicyError(
            "Final request expected_parameter_ids differ from the audited task"
        )
    if created_event.details["reviewer_id"] != request.primary_reviewer_id:
        raise AuditPolicyError(
            "Final request primary_reviewer_id differs from the audited task"
        )
    created_context = _event_context(created_event)
    assert created_context is not None
    if request.evidence_manifest_hash != created_context.manifest_hash:
        raise AuditPolicyError(
            "Final request manifest differs from the audited frozen evidence"
        )

    completed = [
        event
        for event in task_events
        if event.action is AuditAction.AI_REVIEW_COMPLETED
    ]
    if len(completed) != 1:
        raise AuditPolicyError(
            "Atomic final commit requires exactly one completed AI run"
        )
    completed_context = _event_context(completed[0])
    assert completed_context is not None
    if completed_context.run_id != request.ai_run_id:
        raise AuditPolicyError(
            "Final request ai_run_id differs from the audited completed run"
        )

    has_second = request.second_submission_hash is not None
    has_exceptions = bool(request.exception_ids)
    canonical_actions = _canonical_final_prior_actions(
        has_second_review=has_second,
        has_exceptions=has_exceptions,
    )
    if request.required_prior_actions != canonical_actions:
        raise AuditPolicyError(
            "Final request required_prior_actions are not the canonical lifecycle"
        )
    actual_actions = {event.action for event in task_events}
    missing_actions = set(canonical_actions) - actual_actions
    if missing_actions:
        raise AuditPolicyError(
            "Final audit coverage is missing actions: "
            + ",".join(sorted(item.value for item in missing_actions))
        )

    expected_set = frozenset(request.expected_parameter_ids)
    parameter_actions = {
        AuditAction.HUMAN_DECISION_RECORDED,
        AuditAction.AI_ASSESSMENT_RECORDED,
        AuditAction.ROUTE_ASSIGNED,
    }
    for action in parameter_actions:
        actual_ids = {
            event.parameter_id for event in task_events if event.action is action
        }
        if actual_ids != expected_set:
            raise AuditPolicyError(
                f"{action.value} does not exactly cover the frozen parameter set"
            )

    formal_second_actions = {
        AuditAction.SECOND_REVIEW_ASSIGNED,
        AuditAction.SECOND_REVIEW_DECISION_RECORDED,
        AuditAction.SECOND_REVIEW_DECISION_REVISED,
        AuditAction.SECOND_REVIEW_LOCKED,
    }
    formal_second_events = [
        event for event in task_events if event.action in formal_second_actions
    ]
    if has_second:
        assignments = [
            event
            for event in task_events
            if event.action is AuditAction.SECOND_REVIEW_ASSIGNED
        ]
        locks = [
            event
            for event in task_events
            if event.action is AuditAction.SECOND_REVIEW_LOCKED
        ]
        recorded_ids = {
            event.parameter_id
            for event in task_events
            if event.action is AuditAction.SECOND_REVIEW_DECISION_RECORDED
        }
        if len(assignments) != 1 or len(locks) != 1 or recorded_ids != expected_set:
            raise AuditPolicyError(
                "Formal second-review audit coverage is incomplete"
            )
        if (
            locks[0].details["second_submission_hash"]
            != request.second_submission_hash
        ):
            raise AuditPolicyError(
                "Final request second_submission_hash differs from the audited lock"
            )
    elif formal_second_events:
        raise AuditPolicyError(
            "Final request omitted an audited formal second-review lifecycle"
        )

    qa_open = [
        event for event in task_events if event.action is AuditAction.QA_CASE_OPENED
    ]
    dispositions = [
        event
        for event in task_events
        if event.action is AuditAction.QA_DISPOSITION_RECORDED
    ]
    qa_complete = [
        event
        for event in task_events
        if event.action is AuditAction.QA_DISPOSITION_COMPLETED
    ]
    if has_exceptions:
        if len(qa_open) != 1 or len(qa_complete) != 1:
            raise AuditPolicyError(
                "Exception-bearing final request requires one complete QA lifecycle"
            )
        audited_exception_ids = tuple(
            sorted(
                item["exception_id"]
                for item in qa_open[0].details["exceptions"]
            )
        )
        audited_disposition_ids = tuple(
            sorted(event.details["exception_id"] for event in dispositions)
        )
        if audited_exception_ids != request.exception_ids:
            raise AuditPolicyError(
                "Final request exception_ids differ from the audited QA case"
            )
        if audited_disposition_ids != request.qa_disposition_exception_ids:
            raise AuditPolicyError(
                "Final request QA disposition IDs differ from audited dispositions"
            )
        if qa_complete[0].details["resolution_digest"] != request.resolution_digest:
            raise AuditPolicyError(
                "Final request resolution_digest differs from audited QA completion"
            )
    elif qa_open or dispositions or qa_complete:
        raise AuditPolicyError(
            "No-exception final request conflicts with audited QA events"
        )

    expected_version = _canonical_adjudication_version(
        has_second_review=has_second,
        qa_disposition_count=len(dispositions),
    )
    if request.expected_adjudication_version != expected_version:
        raise AuditPolicyError(
            "Final request adjudication version differs from audited transitions"
        )
    return completed_context


def _validate_semantic_transition(
    existing_events: Sequence[AuditEvent],
    *,
    task_id: str,
    actor_id: str,
    action: AuditAction,
    details: Mapping[str, Any],
    parameter_id: str | None,
    evidence_context: EvidenceContext | None,
) -> None:
    """Replay the controlled task state and reject impossible transitions."""

    if action is AuditAction.GENERIC_NOTE_RECORDED:
        created = next(
            (
                event
                for event in existing_events
                if event.task_id == task_id
                and event.action is AuditAction.TASK_CREATED
            ),
            None,
        )
        if created is not None and evidence_context is not None:
            created_context = _event_context(created)
            assert created_context is not None
            if _base_context_record(evidence_context) != _base_context_record(
                created_context
            ):
                raise AuditPolicyError(
                    "Generic note evidence differs from the task manifest"
                )
        return

    task_events = [
        event
        for event in existing_events
        if event.task_id == task_id
        and event.action is not AuditAction.GENERIC_NOTE_RECORDED
    ]
    created_events = [
        event for event in task_events if event.action is AuditAction.TASK_CREATED
    ]

    if action is AuditAction.TASK_CREATED:
        if created_events:
            raise AuditPolicyError(f"Task {task_id} already has a TASK_CREATED event")
        return
    if len(created_events) != 1:
        raise AuditPolicyError(
            f"{action.value} requires exactly one prior TASK_CREATED event"
        )

    created = created_events[0]
    created_context = _event_context(created)
    assert created_context is not None and evidence_context is not None
    if _base_context_record(evidence_context) != _base_context_record(created_context):
        raise AuditPolicyError(
            f"{action.value} evidence differs from the task's frozen manifest"
        )

    expected_ids = tuple(created.details["expected_parameter_ids"])
    expected_id_set = frozenset(expected_ids)
    if parameter_id is not None and parameter_id not in expected_id_set:
        raise AuditPolicyError(
            f"{action.value} names a parameter outside the frozen schema"
        )
    assigned_reviewer = created.details["reviewer_id"]

    human_events = [
        event
        for event in task_events
        if event.action
        in {
            AuditAction.HUMAN_DECISION_RECORDED,
            AuditAction.HUMAN_DECISION_REVISED,
        }
    ]
    human_locked = any(
        event.action is AuditAction.HUMAN_REVIEW_LOCKED for event in task_events
    )
    ai_started_events = [
        event for event in task_events if event.action is AuditAction.AI_REVIEW_STARTED
    ]
    ai_completed_events = [
        event
        for event in task_events
        if event.action is AuditAction.AI_REVIEW_COMPLETED
    ]
    second_assignment_events = [
        event
        for event in task_events
        if event.action is AuditAction.SECOND_REVIEW_ASSIGNED
    ]
    second_decision_events = [
        event
        for event in task_events
        if event.action
        in {
            AuditAction.SECOND_REVIEW_DECISION_RECORDED,
            AuditAction.SECOND_REVIEW_DECISION_REVISED,
        }
    ]
    second_lock_events = [
        event
        for event in task_events
        if event.action is AuditAction.SECOND_REVIEW_LOCKED
    ]
    qa_open_events = [
        event for event in task_events if event.action is AuditAction.QA_CASE_OPENED
    ]
    qa_disposition_events = [
        event
        for event in task_events
        if event.action is AuditAction.QA_DISPOSITION_RECORDED
    ]
    qa_completed_events = [
        event
        for event in task_events
        if event.action is AuditAction.QA_DISPOSITION_COMPLETED
    ]
    targeted_lock_events = [
        event
        for event in task_events
        if event.action is AuditAction.TARGETED_REVIEW_LOCKED
    ]
    targeted_qa_events = [
        event
        for event in task_events
        if event.action is AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED
    ]
    targeted_final_events = [
        event
        for event in task_events
        if event.action
        in {
            AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
            AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
        }
    ]
    final_events = [
        event
        for event in task_events
        if event.action
        in {
            AuditAction.FINAL_APPROVAL_RECORDED,
            AuditAction.FINAL_REJECTION_RECORDED,
            AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
            AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
        }
    ]

    if (
        final_events
        and action is not AuditAction.CORRECTION_RECORDED
    ):
        raise AuditPolicyError("A final human decision is already recorded")

    adjudication_actions = frozenset(
        {
            AuditAction.SECOND_REVIEW_ASSIGNED,
            AuditAction.SECOND_REVIEW_DECISION_RECORDED,
            AuditAction.SECOND_REVIEW_DECISION_REVISED,
            AuditAction.SECOND_REVIEW_LOCKED,
            AuditAction.QA_CASE_OPENED,
            AuditAction.QA_DISPOSITION_RECORDED,
            AuditAction.QA_DISPOSITION_COMPLETED,
            AuditAction.FINAL_APPROVAL_RECORDED,
            AuditAction.FINAL_REJECTION_RECORDED,
            AuditAction.TARGETED_REVIEW_LOCKED,
            AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED,
            AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
            AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
        }
    )
    if action in adjudication_actions:
        if len(ai_completed_events) != 1:
            raise AuditPolicyError(
                f"{action.value} requires a completed AI review"
            )
        if not _same_full_context(
            evidence_context, _event_context(ai_completed_events[0])
        ):
            raise AuditPolicyError(
                f"{action.value} uses a different evidence, run, or pipeline"
            )

    blind_branch_actions = frozenset(
        {
            AuditAction.ROUTE_ASSIGNED,
            AuditAction.SECOND_REVIEW_ASSIGNED,
            AuditAction.SECOND_REVIEW_DECISION_RECORDED,
            AuditAction.SECOND_REVIEW_DECISION_REVISED,
            AuditAction.SECOND_REVIEW_LOCKED,
            AuditAction.QA_CASE_OPENED,
            AuditAction.QA_DISPOSITION_RECORDED,
            AuditAction.QA_DISPOSITION_COMPLETED,
            AuditAction.FINAL_APPROVAL_RECORDED,
            AuditAction.FINAL_REJECTION_RECORDED,
            AuditAction.SECOND_REVIEW_RECORDED,
        }
    )
    existing_blind_branch = any(
        event.action in blind_branch_actions for event in task_events
    )
    if action in blind_branch_actions and targeted_lock_events:
        raise AuditPolicyError(
            "The targeted and blind/legacy adjudication branches are exclusive"
        )

    if action is AuditAction.TARGETED_REVIEW_LOCKED:
        if targeted_lock_events:
            raise AuditPolicyError("The targeted review is already audited as locked")
        if existing_blind_branch:
            raise AuditPolicyError(
                "The targeted branch cannot start after blind/legacy adjudication"
            )
        submission = _validate_targeted_submission_record(
            details["submission"],
            expected_submission_hash=details["submission_hash"],
        )
        if submission["task_id"] != task_id:
            raise AuditPolicyError("targeted submission belongs to another task")
        if submission["reviewer_id"] != actor_id:
            raise AuditPolicyError(
                "Only the assigned targeted reviewer may lock this submission"
            )
        if details["primary_reviewer_id"] != assigned_reviewer:
            raise AuditPolicyError(
                "targeted lock primary reviewer differs from the audited task"
            )
        prior_actor_ids = {assigned_reviewer, submission["reviewer_id"]}
        assigned_qa_reviewer_id = details["assigned_qa_reviewer_id"]
        assigned_final_approver_id = details["assigned_final_approver_id"]
        if (
            assigned_qa_reviewer_id is not None
            and assigned_qa_reviewer_id in prior_actor_ids
        ):
            raise AuditPolicyError(
                "targeted QA assignment must be independent of prior reviewers"
            )
        if assigned_final_approver_id in {
            *prior_actor_ids,
            assigned_qa_reviewer_id,
        }:
            raise AuditPolicyError(
                "targeted final assignment must be independent of earlier roles"
            )
        if submission["evidence_manifest_hash"] != created_context.manifest_hash:
            raise AuditPolicyError(
                "targeted submission differs from the frozen evidence manifest"
            )
        if tuple(submission["expected_parameter_ids"]) != expected_ids:
            raise AuditPolicyError(
                "targeted submission partitions differ from the frozen schema"
            )
        completed_context = _event_context(ai_completed_events[0])
        assert completed_context is not None
        if details["ai_run_id"] != completed_context.run_id:
            raise AuditPolicyError(
                "targeted lock AI run differs from the audited completed run"
            )
        exceptions = calculate_targeted_exception_records(
            submission,
            submission_hash=details["submission_hash"],
        )
        if (
            any(item["qa_required"] for item in exceptions)
            and assigned_qa_reviewer_id is None
        ):
            raise AuditPolicyError(
                "QA-required targeted exceptions need an audited QA assignment"
            )
        expected_predecessor = (
            existing_events[-1].event_hash if existing_events else GENESIS_HASH
        )
        if details["audit_head_predecessor"] != expected_predecessor:
            raise AuditPolicyError(
                "targeted lock audit_head_predecessor is not the current head"
            )
        lock_record = {
            "task_id": task_id,
            "actor_id": actor_id,
            "primary_reviewer_id": details["primary_reviewer_id"],
            "ai_run_id": details["ai_run_id"],
            "targeted_reviewer_kind": details["targeted_reviewer_kind"],
            "targeted_reviewer_roles": details["targeted_reviewer_roles"],
            "assigned_qa_reviewer_id": assigned_qa_reviewer_id,
            "assigned_final_approver_id": assigned_final_approver_id,
            "evidence_context": evidence_context.to_record(),
            "submission": submission,
            "submission_hash": details["submission_hash"],
            "expected_previous_head_hash": details["audit_head_predecessor"],
            "command_id": details["command_id"],
        }
        if details["request_hash"] != calculate_targeted_lock_request_hash(
            lock_record
        ):
            raise AuditPolicyError(
                "targeted lock request hash differs from its audited facts"
            )
        return

    if action is AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED:
        if len(targeted_lock_events) != 1 or targeted_final_events:
            raise AuditPolicyError(
                "targeted QA requires one locked, non-final targeted branch"
            )
        lock_event = targeted_lock_events[0]
        lock_details = lock_event.details
        submission_hash = lock_details["submission_hash"]
        if details["targeted_submission_hash"] != submission_hash:
            raise AuditPolicyError(
                "targeted QA disposition uses a different submission"
            )
        exceptions = calculate_targeted_exception_records(
            lock_details["submission"], submission_hash=submission_hash
        )
        qa_by_id = {
            item["exception_id"]: item
            for item in exceptions
            if item["qa_required"]
        }
        exception_id = details["exception_id"]
        if exception_id not in qa_by_id:
            raise AuditPolicyError(
                "targeted QA disposition names an unknown or non-QA exception"
            )
        if any(
            event.details["exception_id"] == exception_id
            for event in targeted_qa_events
        ):
            raise AuditPolicyError(
                "targeted QA exception already has an immutable disposition"
            )
        if actor_id != lock_details["assigned_qa_reviewer_id"]:
            raise AuditPolicyError(
                "targeted QA actor differs from the audited assignment"
            )
        expected_version = 1 + len(targeted_qa_events)
        if details["adjudication_version"] != expected_version:
            raise AuditPolicyError(
                "targeted QA adjudication_version differs from audited transitions"
            )
        expected_predecessor = (
            existing_events[-1].event_hash if existing_events else GENESIS_HASH
        )
        if details["audit_head_predecessor"] != expected_predecessor:
            raise AuditPolicyError(
                "targeted QA audit_head_predecessor is not the current head"
            )
        qa_record = {
            "task_id": task_id,
            "actor_id": actor_id,
            "targeted_submission_hash": submission_hash,
            "exception_id": exception_id,
            "outcome": details["outcome"],
            "rationale": details["rationale"],
            "reference_ids": details["reference_ids"],
            "expected_adjudication_version": details["adjudication_version"],
            "expected_previous_head_hash": details["audit_head_predecessor"],
            "command_id": details["command_id"],
        }
        if details["request_hash"] != calculate_targeted_qa_request_hash(
            qa_record
        ):
            raise AuditPolicyError(
                "targeted QA request hash differs from its audited facts"
            )
        return

    if action in {
        AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
        AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
    }:
        if len(targeted_lock_events) != 1:
            raise AuditPolicyError(
                "targeted final requires exactly one targeted lock"
            )
        lock_event = targeted_lock_events[0]
        lock_details = lock_event.details
        submission = lock_details["submission"]
        submission_hash = lock_details["submission_hash"]
        exceptions = calculate_targeted_exception_records(
            submission, submission_hash=submission_hash
        )
        exception_ids = tuple(sorted(item["exception_id"] for item in exceptions))
        qa_required_ids = tuple(
            sorted(
                item["exception_id"]
                for item in exceptions
                if item["qa_required"]
            )
        )
        disposition_ids = tuple(
            sorted(event.details["exception_id"] for event in targeted_qa_events)
        )
        if disposition_ids != qa_required_ids:
            raise AuditPolicyError(
                "targeted final requires complete QA coverage for QA-required exceptions"
            )
        if actor_id != lock_details["assigned_final_approver_id"]:
            raise AuditPolicyError(
                "targeted final actor differs from the audited assignment"
            )
        if details["evidence_manifest_hash"] != created_context.manifest_hash:
            raise AuditPolicyError(
                "targeted final differs from the frozen evidence manifest"
            )
        if details["targeted_submission_hash"] != submission_hash:
            raise AuditPolicyError(
                "targeted final differs from the locked targeted submission"
            )
        if (
            action is AuditAction.TARGETED_FINAL_APPROVAL_RECORDED
            and any(
                event.details["outcome"] != "RESOLVED_NO_BLOCKING_EXCEPTION"
                for event in targeted_qa_events
            )
        ):
            raise AuditPolicyError(
                "targeted final approval is blocked by QA outcomes"
            )
        disposition_records = [
            {
                "exception_id": event.details["exception_id"],
                "outcome": event.details["outcome"],
                "rationale": event.details["rationale"],
                "reference_ids": event.details["reference_ids"],
                "qa_actor_id": event.actor_id,
            }
            for event in targeted_qa_events
        ]
        resolution_digest = calculate_targeted_resolution_digest(
            task_id=task_id,
            submission_hash=submission_hash,
            exceptions=exceptions,
            dispositions=disposition_records,
        )
        if details["resolution_digest"] != resolution_digest:
            raise AuditPolicyError(
                "targeted final resolution_digest differs from audited evidence"
            )
        expected_version = 1 + len(targeted_qa_events)
        if details["adjudication_version"] != expected_version:
            raise AuditPolicyError(
                "targeted final adjudication_version differs from audited transitions"
            )
        expected_predecessor = (
            existing_events[-1].event_hash if existing_events else GENESIS_HASH
        )
        if details["audit_head_predecessor"] != expected_predecessor:
            raise AuditPolicyError(
                "targeted final audit_head_predecessor is not the current head"
            )
        completed_context = _event_context(ai_completed_events[0])
        assert completed_context is not None and completed_context.run_id is not None
        final_record = {
            "task_id": task_id,
            "decision": (
                "APPROVED"
                if action is AuditAction.TARGETED_FINAL_APPROVAL_RECORDED
                else "REJECTED"
            ),
            "actor_id": actor_id,
            "rationale": details["rationale"],
            "evidence_manifest_hash": details["evidence_manifest_hash"],
            "targeted_submission_hash": submission_hash,
            "primary_reviewer_id": assigned_reviewer,
            "ai_run_id": completed_context.run_id,
            "expected_parameter_ids": list(expected_ids),
            "exception_ids": list(exception_ids),
            "qa_required_exception_ids": list(qa_required_ids),
            "qa_disposition_exception_ids": list(disposition_ids),
            "resolution_digest": resolution_digest,
            "expected_adjudication_version": expected_version,
            "expected_previous_head_hash": details["audit_head_predecessor"],
            "command_id": details["command_id"],
        }
        if details["commit_request_hash"] != calculate_targeted_final_request_hash(
            final_record
        ):
            raise AuditPolicyError(
                "targeted final request hash differs from its audited facts"
            )
        return

    if action in {
        AuditAction.HUMAN_DECISION_RECORDED,
        AuditAction.HUMAN_DECISION_REVISED,
    }:
        if actor_id != assigned_reviewer:
            raise AuditPolicyError(
                "Only the assigned first reviewer may record human decisions"
            )
        if human_locked:
            raise AuditPolicyError("Human decisions cannot change after lock")
        decided_ids = {event.parameter_id for event in human_events}
        if action is AuditAction.HUMAN_DECISION_RECORDED:
            if parameter_id in decided_ids:
                raise AuditPolicyError(
                    "An existing human decision must use HUMAN_DECISION_REVISED"
                )
        elif parameter_id not in decided_ids:
            raise AuditPolicyError(
                "HUMAN_DECISION_REVISED requires an earlier decision"
            )
        return

    if action is AuditAction.HUMAN_REVIEW_LOCKED:
        if actor_id != assigned_reviewer:
            raise AuditPolicyError(
                "Only the assigned first reviewer may lock the human review"
            )
        if human_locked:
            raise AuditPolicyError("Human review is already locked")
        decided_ids = {event.parameter_id for event in human_events}
        if decided_ids != expected_id_set:
            missing = expected_id_set - decided_ids
            raise AuditPolicyError(
                "Human review cannot lock before every frozen parameter is decided; "
                "missing=" + ",".join(sorted(missing))
            )
        if details["decision_count"] != len(expected_ids):
            raise AuditPolicyError(
                "HUMAN_REVIEW_LOCKED decision_count differs from the frozen schema"
            )
        return

    if action is AuditAction.AI_REVIEW_STARTED:
        if not human_locked:
            raise AuditPolicyError("AI review cannot start before human lock")
        if ai_started_events or ai_completed_events:
            raise AuditPolicyError("The task already has an AI run")
        return

    if action in {
        AuditAction.AI_ASSESSMENT_RECORDED,
        AuditAction.AI_REVIEW_COMPLETED,
    }:
        if len(ai_started_events) != 1 or ai_completed_events:
            raise AuditPolicyError(
                f"{action.value} requires one active, incomplete AI run"
            )
        started = ai_started_events[0]
        started_context = _event_context(started)
        if not _same_full_context(evidence_context, started_context):
            raise AuditPolicyError(
                f"{action.value} run or pipeline identity differs from AI_REVIEW_STARTED"
            )
        if actor_id != started.actor_id:
            raise AuditPolicyError(
                f"{action.value} actor differs from the service that started the run"
            )

        assessments = [
            event
            for event in task_events
            if event.action is AuditAction.AI_ASSESSMENT_RECORDED
        ]
        if action is AuditAction.AI_ASSESSMENT_RECORDED:
            if any(event.parameter_id == parameter_id for event in assessments):
                raise AuditPolicyError(
                    "An AI assessment already exists for this run and parameter"
                )
        else:
            assessed_ids = {event.parameter_id for event in assessments}
            if assessed_ids != expected_id_set:
                missing = expected_id_set - assessed_ids
                raise AuditPolicyError(
                    "AI review cannot complete before every frozen parameter is assessed; "
                    "missing=" + ",".join(sorted(missing))
                )
            if details["assessment_count"] != len(expected_ids):
                raise AuditPolicyError(
                    "AI_REVIEW_COMPLETED assessment_count differs from the frozen schema"
                )
        return

    if action is AuditAction.ROUTE_ASSIGNED:
        if len(ai_completed_events) != 1:
            raise AuditPolicyError("Routing requires a completed AI review")
        completed_context = _event_context(ai_completed_events[0])
        if not _same_full_context(evidence_context, completed_context):
            raise AuditPolicyError("Routing uses a different AI run or pipeline")
        if any(
            event.action is AuditAction.ROUTE_ASSIGNED
            and event.parameter_id == parameter_id
            for event in task_events
        ):
            raise AuditPolicyError("A route already exists for this parameter")
        return

    if action is AuditAction.SECOND_REVIEW_ASSIGNED:
        routes = _require_complete_routes(task_events, expected_id_set)
        if not any(
            event.details["route"] == "INDEPENDENT_SECOND_REVIEW_REQUIRED"
            for event in routes.values()
        ):
            raise AuditPolicyError(
                "Second-review assignment requires an independent route"
            )
        if second_assignment_events:
            raise AuditPolicyError("A second-review assignment already exists")
        if second_decision_events or second_lock_events or qa_open_events:
            raise AuditPolicyError(
                "Second-review assignment must precede review and QA events"
            )
        if details["assigned_reviewer_id"] == assigned_reviewer:
            raise AuditPolicyError(
                "The assigned second reviewer must differ from the first reviewer"
            )
        return

    if action in {
        AuditAction.SECOND_REVIEW_DECISION_RECORDED,
        AuditAction.SECOND_REVIEW_DECISION_REVISED,
    }:
        if len(second_assignment_events) != 1:
            raise AuditPolicyError(
                f"{action.value} requires one bound second-review assignment"
            )
        if second_lock_events:
            raise AuditPolicyError("Second-review decisions cannot change after lock")
        if qa_open_events:
            raise AuditPolicyError("Second-review decisions must precede QA")
        assignment = second_assignment_events[0]
        if actor_id != assignment.details["assigned_reviewer_id"]:
            raise AuditPolicyError(
                "Only the assigned independent second reviewer may record decisions"
            )
        if actor_id == assigned_reviewer:
            raise AuditPolicyError(
                "The independent second reviewer must differ from the first reviewer"
            )
        if details["blind_case_id"] != assignment.details["blind_case_id"]:
            raise AuditPolicyError(
                "Second-review decision uses a different blind case"
            )
        decided_ids = {event.parameter_id for event in second_decision_events}
        if action is AuditAction.SECOND_REVIEW_DECISION_RECORDED:
            if parameter_id in decided_ids:
                raise AuditPolicyError(
                    "An existing second-review decision must use SECOND_REVIEW_DECISION_REVISED"
                )
        elif parameter_id not in decided_ids:
            raise AuditPolicyError(
                "SECOND_REVIEW_DECISION_REVISED requires an earlier decision"
            )
        return

    if action is AuditAction.SECOND_REVIEW_LOCKED:
        if len(second_assignment_events) != 1:
            raise AuditPolicyError(
                "SECOND_REVIEW_LOCKED requires one bound assignment"
            )
        if second_lock_events:
            raise AuditPolicyError("The second review is already locked")
        if qa_open_events:
            raise AuditPolicyError("Second review must lock before QA opens")
        assignment = second_assignment_events[0]
        if actor_id != assignment.details["assigned_reviewer_id"]:
            raise AuditPolicyError(
                "Only the assigned independent second reviewer may lock the review"
            )
        if actor_id == assigned_reviewer:
            raise AuditPolicyError(
                "The independent second reviewer must differ from the first reviewer"
            )
        if details["blind_case_id"] != assignment.details["blind_case_id"]:
            raise AuditPolicyError("Second-review lock uses a different blind case")
        decided_ids = {event.parameter_id for event in second_decision_events}
        if decided_ids != expected_id_set:
            missing = expected_id_set - decided_ids
            extra = decided_ids - expected_id_set
            pieces: list[str] = []
            if missing:
                pieces.append("missing=" + ",".join(sorted(missing)))
            if extra:
                pieces.append("extra=" + ",".join(sorted(extra)))
            raise AuditPolicyError(
                "Second review cannot lock before the full frozen manifest is decided; "
                + "; ".join(pieces)
            )
        if details["decision_count"] != len(expected_ids):
            raise AuditPolicyError(
                "SECOND_REVIEW_LOCKED decision_count differs from the frozen schema"
            )
        return

    if action is AuditAction.QA_CASE_OPENED:
        routes = _require_complete_routes(task_events, expected_id_set)
        needs_second = any(
            event.details["route"] == "INDEPENDENT_SECOND_REVIEW_REQUIRED"
            for event in routes.values()
        )
        if qa_open_events:
            raise AuditPolicyError("A QA case already exists")
        if qa_disposition_events or qa_completed_events:
            raise AuditPolicyError("QA_CASE_OPENED must precede QA dispositions")
        if needs_second and len(second_lock_events) != 1:
            raise AuditPolicyError(
                "QA cannot open until the full-field second review is locked"
            )
        if not needs_second and (second_assignment_events or second_lock_events):
            raise AuditPolicyError(
                "A second-review lifecycle exists without an independent route"
            )
        expected_second_hash = (
            second_lock_events[0].details["second_submission_hash"]
            if needs_second
            else None
        )
        if details["second_submission_hash"] != expected_second_hash:
            raise AuditPolicyError(
                "QA case second_submission_hash differs from the locked review"
            )
        expected_exceptions = _expected_exception_records(
            task_id=task_id,
            expected_ids=expected_ids,
            task_events=task_events,
            include_second_review=needs_second,
        )
        if not expected_exceptions:
            raise AuditPolicyError("A no-exception task must not open a QA case")
        supplied_exceptions = _validate_exception_records(details["exceptions"])
        expected_set = {
            (
                item["exception_id"],
                item["parameter_id"],
                item["source"],
                item["reason_code"],
            )
            for item in expected_exceptions
        }
        supplied_set = {
            (
                item["exception_id"],
                item["parameter_id"],
                item["source"],
                item["reason_code"],
            )
            for item in supplied_exceptions
        }
        if supplied_set != expected_set:
            raise AuditPolicyError(
                "QA exception ledger must exactly equal routing and reconciliation exceptions"
            )
        return

    if action is AuditAction.QA_DISPOSITION_RECORDED:
        if len(qa_open_events) != 1 or qa_completed_events:
            raise AuditPolicyError(
                "QA disposition requires one open, incomplete QA case"
            )
        known_ids = {
            item["exception_id"] for item in qa_open_events[0].details["exceptions"]
        }
        exception_id = details["exception_id"]
        if exception_id not in known_ids:
            raise AuditPolicyError("QA disposition names an unknown exception_id")
        if any(
            event.details["exception_id"] == exception_id
            for event in qa_disposition_events
        ):
            raise AuditPolicyError(
                "An exception already has an immutable QA disposition"
            )
        return

    if action is AuditAction.QA_DISPOSITION_COMPLETED:
        if len(qa_open_events) != 1 or qa_completed_events:
            raise AuditPolicyError(
                "QA completion requires one open, incomplete QA case"
            )
        expected_exception_ids = {
            item["exception_id"] for item in qa_open_events[0].details["exceptions"]
        }
        disposition_ids = {
            event.details["exception_id"] for event in qa_disposition_events
        }
        if disposition_ids != expected_exception_ids:
            missing = expected_exception_ids - disposition_ids
            extra = disposition_ids - expected_exception_ids
            pieces: list[str] = []
            if missing:
                pieces.append("missing=" + ",".join(sorted(missing)))
            if extra:
                pieces.append("extra=" + ",".join(sorted(extra)))
            raise AuditPolicyError(
                "QA dispositions must exactly cover the exception ledger; "
                + "; ".join(pieces)
            )
        if details["disposition_count"] != len(expected_exception_ids):
            raise AuditPolicyError(
                "QA_DISPOSITION_COMPLETED count differs from the exception ledger"
            )
        expected_state = _qa_result_state(qa_disposition_events)
        if details["result_state"] != expected_state:
            raise AuditPolicyError(
                "QA_DISPOSITION_COMPLETED result_state contradicts its outcomes"
            )
        return

    if action in {
        AuditAction.FINAL_APPROVAL_RECORDED,
        AuditAction.FINAL_REJECTION_RECORDED,
    }:
        routes = _require_complete_routes(task_events, expected_id_set)
        needs_second = any(
            event.details["route"] == "INDEPENDENT_SECOND_REVIEW_REQUIRED"
            for event in routes.values()
        )
        if details["evidence_manifest_hash"] != evidence_context.manifest_hash:
            raise AuditPolicyError(
                "Final decision evidence_manifest_hash differs from its context"
            )
        expected_predecessor = (
            existing_events[-1].event_hash if existing_events else GENESIS_HASH
        )
        if details["audit_head_predecessor"] != expected_predecessor:
            raise AuditPolicyError(
                "Final decision audit_head_predecessor is not the current audit head"
            )
        if needs_second:
            if len(second_lock_events) != 1:
                raise AuditPolicyError(
                    "Final decision requires a locked full-field second review"
                )
            expected_second_hash: str | None = second_lock_events[0].details[
                "second_submission_hash"
            ]
        else:
            expected_second_hash = None
        if details["second_submission_hash"] != expected_second_hash:
            raise AuditPolicyError(
                "Final decision second_submission_hash differs from adjudication"
            )

        expected_exceptions = _expected_exception_records(
            task_id=task_id,
            expected_ids=expected_ids,
            task_events=task_events,
            include_second_review=needs_second,
        )
        if expected_exceptions:
            if len(qa_open_events) != 1 or len(qa_completed_events) != 1:
                raise AuditPolicyError(
                    "Final decision requires completed per-exception QA disposition"
                )
            completion = qa_completed_events[0]
            if details["resolution_digest"] != completion.details["resolution_digest"]:
                raise AuditPolicyError(
                    "Final decision resolution_digest differs from QA completion"
                )
            if (
                action is AuditAction.FINAL_APPROVAL_RECORDED
                and completion.details["result_state"]
                != "READY_FOR_FINAL_HUMAN_DECISION"
            ):
                raise AuditPolicyError(
                    "Final approval is blocked by unresolved or rework QA outcomes"
                )
        elif qa_open_events or qa_completed_events or qa_disposition_events:
            raise AuditPolicyError(
                "A no-exception final decision cannot rely on a fabricated QA lifecycle"
            )
        expected_version = _canonical_adjudication_version(
            has_second_review=needs_second,
            qa_disposition_count=len(qa_disposition_events),
        )
        if details["adjudication_version"] != expected_version:
            raise AuditPolicyError(
                "Final decision adjudication_version differs from audited transitions"
            )
        commit_record = _final_commit_record_from_prior_events(
            task_id=task_id,
            action=action,
            actor_id=actor_id,
            details=details,
            expected_ids=expected_ids,
            assigned_reviewer=assigned_reviewer,
            task_events=task_events,
        )
        expected_request_hash = calculate_final_commit_request_hash(commit_record)
        if details["commit_request_hash"] != expected_request_hash:
            raise AuditPolicyError(
                "Final event commit_request_hash differs from its audited request"
            )
        return

    if action is AuditAction.SECOND_REVIEW_RECORDED:
        if actor_id == assigned_reviewer:
            raise AuditPolicyError(
                "The independent second reviewer must differ from the first reviewer"
            )
        route = next(
            (
                event
                for event in task_events
                if event.action is AuditAction.ROUTE_ASSIGNED
                and event.parameter_id == parameter_id
            ),
            None,
        )
        if route is None or route.details["route"] == "NO_EXCEPTION_DETECTED":
            raise AuditPolicyError(
                "Second review requires a review-required route for the parameter"
            )
        if not _same_full_context(evidence_context, _event_context(route)):
            raise AuditPolicyError("Second review uses a different AI run or pipeline")
        if any(
            event.action is AuditAction.SECOND_REVIEW_RECORDED
            and event.parameter_id == parameter_id
            for event in task_events
        ):
            raise AuditPolicyError(
                "An independent second review already exists for this parameter"
            )
        return

    if action is AuditAction.CORRECTION_RECORDED:
        target = next(
            (
                event
                for event in existing_events
                if event.event_id == details["corrects_event_id"]
            ),
            None,
        )
        if target is None or target.task_id != task_id:
            raise UnknownCorrectedEventError(
                "Correction target is unknown or belongs to another task"
            )
        if details["original_event_hash"] != target.event_hash:
            raise AuditPolicyError(
                "Correction original_event_hash differs from its target"
            )
        if parameter_id != target.parameter_id:
            raise AuditPolicyError(
                "Correction parameter_id must equal the target parameter_id"
            )
        if not _same_full_context(evidence_context, _event_context(target)):
            raise AuditPolicyError(
                "Correction must retain the target event's complete evidence context"
            )
        return

    raise AuditPolicyError(f"No semantic transition is defined for {action.value}")


def _verify_audit_semantics(events: Sequence[AuditEvent]) -> None:
    prior: list[AuditEvent] = []
    for event in events:
        try:
            if event.action is AuditAction.TARGETED_REVIEW_LOCKED:
                locked_at = _parse_audit_timestamp(
                    "targeted submission locked_at",
                    event.details["submission"]["locked_at"],
                )
                if event.occurred_at < locked_at:
                    raise AuditPolicyError(
                        "targeted lock audit time cannot predate the locked submission"
                    )
            context = _event_context(event)
            _validate_action_contract(
                actor_id=event.actor_id,
                action=event.action,
                details=event.details,
                parameter_id=event.parameter_id,
                reason=event.reason,
                evidence_context=context,
            )
            _validate_semantic_transition(
                prior,
                task_id=event.task_id,
                actor_id=event.actor_id,
                action=event.action,
                details=event.details,
                parameter_id=event.parameter_id,
                evidence_context=context,
            )
        except (AuditPolicyError, UnknownCorrectedEventError, TypeError, ValueError) as error:
            raise AuditIntegrityError(
                f"Invalid audit semantics at sequence {event.sequence}: {error}"
            ) from error
        prior.append(event)


def _event_from_record(record: Mapping[str, Any]) -> AuditEvent:
    required = {
        "audit_schema_version",
        "sequence",
        "event_id",
        "task_id",
        "parameter_id",
        "actor_id",
        "occurred_at",
        "action",
        "reason",
        "details",
        "evidence_context",
        "previous_hash",
        "event_hash",
    }
    if set(record) != required:
        missing = required - set(record)
        unknown = set(record) - required
        pieces = []
        if missing:
            pieces.append("missing=" + ",".join(sorted(missing)))
        if unknown:
            pieces.append("unknown=" + ",".join(sorted(unknown)))
        raise AuditIntegrityError("Invalid audit event fields: " + "; ".join(pieces))

    try:
        if type(record["audit_schema_version"]) is not int:
            raise TypeError("audit_schema_version must be an integer")
        if type(record["sequence"]) is not int:
            raise TypeError("sequence must be an integer")
        occurred_at = _normalise_utc(
            "occurred_at", datetime.fromisoformat(record["occurred_at"])
        )
        action = AuditAction(record["action"])
        details = record["details"]
        if not isinstance(details, dict):
            raise TypeError("details must be a JSON object")
        details_json = _canonical_json(details)

        raw_context = record["evidence_context"]
        context_json: str | None = None
        if raw_context is not None:
            if not isinstance(raw_context, dict):
                raise TypeError("evidence_context must be a JSON object or null")
            context = EvidenceContext.from_record(raw_context)
            context_json = _canonical_json(context.to_record())

        parameter_id = record["parameter_id"]
        if parameter_id is not None:
            _require_identifier("parameter_id", parameter_id)
        reason = record["reason"]
        if reason is not None:
            _require_text("reason", reason)

        return AuditEvent(
            audit_schema_version=record["audit_schema_version"],
            sequence=record["sequence"],
            event_id=_require_identifier("event_id", record["event_id"]),
            task_id=_require_identifier("task_id", record["task_id"]),
            parameter_id=parameter_id,
            actor_id=_require_identifier("actor_id", record["actor_id"]),
            occurred_at=occurred_at,
            action=action,
            reason=reason,
            details_json=details_json,
            evidence_context_json=context_json,
            previous_hash=_require_sha256("previous_hash", record["previous_hash"]),
            event_hash=_require_sha256("event_hash", record["event_hash"]),
        )
    except (TypeError, ValueError, KeyError) as error:
        if isinstance(error, AuditIntegrityError):
            raise
        raise AuditIntegrityError(f"Invalid audit event value: {error}") from error


def verify_audit_chain(events: Sequence[AuditEvent]) -> None:
    """Fail closed if ordering, hashes, timestamps, or IDs are inconsistent."""

    previous_hash = GENESIS_HASH
    previous_time: datetime | None = None
    event_ids: set[str] = set()

    for expected_sequence, event in enumerate(events, start=1):
        if not isinstance(event, AuditEvent):
            raise AuditIntegrityError(
                f"Item {expected_sequence} is not an AuditEvent"
            )
        if event.audit_schema_version != AUDIT_SCHEMA_VERSION:
            raise AuditIntegrityError(
                f"Unsupported audit schema at sequence {expected_sequence}"
            )
        if event.sequence != expected_sequence:
            raise AuditIntegrityError(
                f"Unexpected sequence {event.sequence}; expected {expected_sequence}"
            )
        if event.event_id in event_ids:
            raise AuditIntegrityError(f"Duplicate event ID: {event.event_id}")
        event_ids.add(event.event_id)
        if event.previous_hash != previous_hash:
            raise AuditIntegrityError(
                f"Broken previous-hash link at sequence {expected_sequence}"
            )
        if _SHA256_PATTERN.fullmatch(event.event_hash) is None:
            raise AuditIntegrityError(
                f"Malformed event hash at sequence {expected_sequence}"
            )
        calculated_hash = _calculate_event_hash(event)
        if event.event_hash != calculated_hash:
            raise AuditIntegrityError(
                f"Event hash mismatch at sequence {expected_sequence}"
            )
        occurred_at = _normalise_utc("occurred_at", event.occurred_at)
        if previous_time is not None and occurred_at < previous_time:
            raise AuditIntegrityError(
                f"Timestamp moved backwards at sequence {expected_sequence}"
            )
        previous_time = occurred_at
        previous_hash = event.event_hash


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def _default_event_id() -> str:
    return str(uuid4())


class JsonlAuditLog:
    """A process-safe append API backed by one hash-chained JSONL file."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        clock: Callable[[], datetime] = _default_clock,
        event_id_factory: Callable[[], str] = _default_event_id,
    ) -> None:
        self.path = Path(path)
        if not self.path.parent.exists():
            raise FileNotFoundError(
                f"Audit-log parent directory does not exist: {self.path.parent}"
            )
        if not callable(clock):
            raise TypeError("clock must be callable")
        if not callable(event_id_factory):
            raise TypeError("event_id_factory must be callable")
        self._clock = clock
        self._event_id_factory = event_id_factory

    def append(
        self,
        *,
        task_id: str,
        actor_id: str,
        action: AuditAction,
        details: Mapping[str, Any],
        parameter_id: str | None = None,
        reason: str | None = None,
        evidence_context: EvidenceContext | None = None,
    ) -> AuditEvent:
        checked_task_id = _require_identifier("task_id", task_id)
        checked_actor_id = _require_identifier("actor_id", actor_id)
        if not isinstance(action, AuditAction):
            raise TypeError("action must be an AuditAction")
        if action in {
            AuditAction.FINAL_APPROVAL_RECORDED,
            AuditAction.FINAL_REJECTION_RECORDED,
        }:
            raise AuditPolicyError(
                "Final events must use commit_final_cas, not the generic append API"
            )
        if action in {
            AuditAction.TARGETED_REVIEW_LOCKED,
            AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED,
            AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
            AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
        }:
            raise AuditPolicyError(
                "Targeted lock, QA acceptance, and final events require their typed CAS APIs"
            )
        if not isinstance(details, Mapping):
            raise TypeError("details must be a mapping")
        details_json = _canonical_json(dict(details))
        # Validate and persist the same deep snapshot even if caller-owned
        # nested containers are mutated concurrently after this point.
        details_record = json.loads(details_json)
        if parameter_id is not None:
            parameter_id = _require_identifier("parameter_id", parameter_id)
        if reason is not None:
            reason = _require_text("reason", reason)
        if evidence_context is not None and not isinstance(
            evidence_context, EvidenceContext
        ):
            raise TypeError("evidence_context must be an EvidenceContext or None")
        _validate_action_contract(
            actor_id=checked_actor_id,
            action=action,
            details=details_record,
            parameter_id=parameter_id,
            reason=reason,
            evidence_context=evidence_context,
        )
        context_json = (
            None
            if evidence_context is None
            else _canonical_json(evidence_context.to_record())
        )

        with self._locked_file(exclusive=True) as handle:
            events = self._read_locked(handle)
            occurred_at = _normalise_utc("clock result", self._clock())
            event_id = _require_identifier("event_id", self._event_id_factory())
            if any(event.event_id == event_id for event in events):
                raise DuplicateAuditEventError(f"Duplicate event ID: {event_id}")
            if events and occurred_at < events[-1].occurred_at:
                raise ValueError("clock result moved backwards relative to the audit log")
            _validate_semantic_transition(
                events,
                task_id=checked_task_id,
                actor_id=checked_actor_id,
                action=action,
                details=details_record,
                parameter_id=parameter_id,
                evidence_context=evidence_context,
            )

            event_without_hash = AuditEvent(
                audit_schema_version=AUDIT_SCHEMA_VERSION,
                sequence=len(events) + 1,
                event_id=event_id,
                task_id=checked_task_id,
                parameter_id=parameter_id,
                actor_id=checked_actor_id,
                occurred_at=occurred_at,
                action=action,
                reason=reason,
                details_json=details_json,
                evidence_context_json=context_json,
                previous_hash=events[-1].event_hash if events else GENESIS_HASH,
                event_hash=GENESIS_HASH,
            )
            event = AuditEvent(
                **{
                    **event_without_hash.__dict__,
                    "event_hash": _calculate_event_hash(event_without_hash),
                }
            )

            line = _canonical_json(event.to_record()) + "\n"
            handle.seek(0, os.SEEK_END)
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
            return event

    def commit_final_cas(
        self, request: FinalAuditWriteRequest
    ) -> AuditEvent:
        """Atomically verify coverage, compare the head, and append final.

        Chain verification, semantic replay, task/field/exception coverage,
        compare-and-swap, timestamp/ID generation, append and ``fsync`` all
        occur while the same exclusive file lock is held.
        """

        if not isinstance(request, FinalAuditWriteRequest):
            raise TypeError("request must be a FinalAuditWriteRequest")
        details_record = {
            "evidence_manifest_hash": request.evidence_manifest_hash,
            "second_submission_hash": request.second_submission_hash,
            "resolution_digest": request.resolution_digest,
            "audit_head_predecessor": request.expected_previous_head_hash,
            "rationale": request.rationale,
            "commit_request_hash": request.commit_request_hash,
            "command_id": request.command_id,
            "adjudication_version": request.expected_adjudication_version,
        }
        details_json = _canonical_json(details_record)

        with self._locked_file(exclusive=True) as handle:
            events = self._read_locked(handle)
            existing_final = next(
                (
                    event
                    for event in events
                    if event.task_id == request.task_id
                    and event.action
                    in {
                        AuditAction.FINAL_APPROVAL_RECORDED,
                        AuditAction.FINAL_REJECTION_RECORDED,
                        AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
                        AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
                    }
                ),
                None,
            )
            if existing_final is not None:
                if (
                    existing_final.action
                    in {
                        AuditAction.FINAL_APPROVAL_RECORDED,
                        AuditAction.FINAL_REJECTION_RECORDED,
                    }
                    and existing_final.details["command_id"] == request.command_id
                    and existing_final.details["commit_request_hash"]
                    == request.commit_request_hash
                ):
                    return existing_final
                if existing_final.details["command_id"] == request.command_id:
                    raise AuditPolicyError(
                        "Final command_id was already used with another request"
                    )
                raise AuditPolicyError(
                    "A different final human decision is already recorded"
                )

            current_head = events[-1].event_hash if events else GENESIS_HASH
            if current_head != request.expected_previous_head_hash:
                raise AuditPolicyError(
                    "Final audit compare-and-swap failed: current head changed"
                )
            completed_context = _validate_final_commit_coverage(events, request)
            _validate_action_contract(
                actor_id=request.actor_id,
                action=request.action,
                details=details_record,
                parameter_id=None,
                reason=None,
                evidence_context=completed_context,
            )
            _validate_semantic_transition(
                events,
                task_id=request.task_id,
                actor_id=request.actor_id,
                action=request.action,
                details=details_record,
                parameter_id=None,
                evidence_context=completed_context,
            )

            occurred_at = _normalise_utc("clock result", self._clock())
            event_id = _require_identifier("event_id", self._event_id_factory())
            if any(event.event_id == event_id for event in events):
                raise DuplicateAuditEventError(f"Duplicate event ID: {event_id}")
            if events and occurred_at < events[-1].occurred_at:
                raise ValueError(
                    "clock result moved backwards relative to the audit log"
                )
            context_json = _canonical_json(completed_context.to_record())
            event_without_hash = AuditEvent(
                audit_schema_version=AUDIT_SCHEMA_VERSION,
                sequence=len(events) + 1,
                event_id=event_id,
                task_id=request.task_id,
                parameter_id=None,
                actor_id=request.actor_id,
                occurred_at=occurred_at,
                action=request.action,
                reason=None,
                details_json=details_json,
                evidence_context_json=context_json,
                previous_hash=current_head,
                event_hash=GENESIS_HASH,
            )
            event = AuditEvent(
                **{
                    **event_without_hash.__dict__,
                    "event_hash": _calculate_event_hash(event_without_hash),
                }
            )
            handle.seek(0, os.SEEK_END)
            handle.write(_canonical_json(event.to_record()) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            return event

    def commit_targeted_lock_cas(
        self, request: TargetedLockAuditWriteRequest
    ) -> AuditEvent:
        """Atomically accept one trusted locked targeted submission."""

        if not isinstance(request, TargetedLockAuditWriteRequest):
            raise TypeError("request must be a TargetedLockAuditWriteRequest")
        details_record = {
            "submission": request.submission_record,
            "submission_hash": request.submission_hash,
            "primary_reviewer_id": request.primary_reviewer_id,
            "ai_run_id": request.ai_run_id,
            "targeted_reviewer_kind": request.targeted_reviewer_kind,
            "targeted_reviewer_roles": list(request.targeted_reviewer_roles),
            "assigned_qa_reviewer_id": request.assigned_qa_reviewer_id,
            "assigned_final_approver_id": (
                request.assigned_final_approver_id
            ),
            "audit_head_predecessor": request.expected_previous_head_hash,
            "command_id": request.command_id,
            "request_hash": request.request_hash,
        }
        return self._commit_targeted_typed_cas(
            task_id=request.task_id,
            actor_id=request.actor_id,
            action=AuditAction.TARGETED_REVIEW_LOCKED,
            details_record=details_record,
            evidence_context=request.evidence_context,
            expected_previous_head_hash=request.expected_previous_head_hash,
            command_id=request.command_id,
            request_hash=request.request_hash,
        )

    def accept_targeted_qa_disposition_cas(
        self, request: TargetedQaAuditWriteRequest
    ) -> AuditEvent:
        """Atomically accept one immutable targeted-branch QA disposition."""

        if not isinstance(request, TargetedQaAuditWriteRequest):
            raise TypeError("request must be a TargetedQaAuditWriteRequest")
        details_record = {
            "targeted_submission_hash": request.targeted_submission_hash,
            "exception_id": request.exception_id,
            "outcome": request.outcome,
            "rationale": request.rationale,
            "reference_ids": list(request.reference_ids),
            "adjudication_version": request.expected_adjudication_version,
            "audit_head_predecessor": request.expected_previous_head_hash,
            "command_id": request.command_id,
            "request_hash": request.request_hash,
        }
        with self._locked_file(exclusive=True) as handle:
            events = self._read_locked(handle)
            lock_event = next(
                (
                    event
                    for event in events
                    if event.task_id == request.task_id
                    and event.action is AuditAction.TARGETED_REVIEW_LOCKED
                ),
                None,
            )
            if lock_event is None:
                raise AuditPolicyError(
                    "Targeted QA disposition requires an audited targeted lock"
                )
            context = _event_context(lock_event)
            assert context is not None
            return self._commit_targeted_typed_cas_locked(
                handle=handle,
                events=events,
                task_id=request.task_id,
                actor_id=request.actor_id,
                action=AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED,
                details_record=details_record,
                evidence_context=context,
                expected_previous_head_hash=request.expected_previous_head_hash,
                command_id=request.command_id,
                request_hash=request.request_hash,
            )

    def commit_targeted_final_cas(
        self, request: TargetedFinalAuditWriteRequest
    ) -> AuditEvent:
        """Atomically verify targeted coverage and append one global final."""

        if not isinstance(request, TargetedFinalAuditWriteRequest):
            raise TypeError("request must be a TargetedFinalAuditWriteRequest")
        details_record = {
            "evidence_manifest_hash": request.evidence_manifest_hash,
            "targeted_submission_hash": request.targeted_submission_hash,
            "resolution_digest": request.resolution_digest,
            "audit_head_predecessor": request.expected_previous_head_hash,
            "rationale": request.rationale,
            "commit_request_hash": request.request_hash,
            "command_id": request.command_id,
            "adjudication_version": request.expected_adjudication_version,
        }
        with self._locked_file(exclusive=True) as handle:
            events = self._read_locked(handle)
            existing_final = next(
                (
                    event
                    for event in events
                    if event.task_id == request.task_id
                    and event.action
                    in {
                        AuditAction.FINAL_APPROVAL_RECORDED,
                        AuditAction.FINAL_REJECTION_RECORDED,
                        AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
                        AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
                    }
                ),
                None,
            )
            if existing_final is not None:
                if (
                    existing_final.action
                    in {
                        AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
                        AuditAction.TARGETED_FINAL_REJECTION_RECORDED,
                    }
                    and existing_final.details["command_id"] == request.command_id
                    and existing_final.details["commit_request_hash"]
                    == request.request_hash
                ):
                    return existing_final
                if existing_final.details["command_id"] == request.command_id:
                    raise AuditPolicyError(
                        "Final command_id was already used with another request"
                    )
                raise AuditPolicyError(
                    "A different final human decision is already recorded"
                )
            lock_event = next(
                (
                    event
                    for event in events
                    if event.task_id == request.task_id
                    and event.action is AuditAction.TARGETED_REVIEW_LOCKED
                ),
                None,
            )
            if lock_event is None:
                raise AuditPolicyError(
                    "Targeted final requires an audited targeted lock"
                )
            submission = lock_event.details["submission"]
            submission_hash = lock_event.details["submission_hash"]
            exceptions = calculate_targeted_exception_records(
                submission, submission_hash=submission_hash
            )
            qa_events = [
                event
                for event in events
                if event.task_id == request.task_id
                and event.action
                is AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED
            ]
            expected_exception_ids = tuple(
                sorted(item["exception_id"] for item in exceptions)
            )
            expected_qa_ids = tuple(
                sorted(
                    item["exception_id"]
                    for item in exceptions
                    if item["qa_required"]
                )
            )
            actual_qa_ids = tuple(
                sorted(event.details["exception_id"] for event in qa_events)
            )
            completed_context = _event_context(lock_event)
            assert completed_context is not None
            if (
                request.evidence_manifest_hash
                != submission["evidence_manifest_hash"]
                or request.targeted_submission_hash != submission_hash
                or request.primary_reviewer_id
                != lock_event.details["primary_reviewer_id"]
                or request.ai_run_id != lock_event.details["ai_run_id"]
                or request.expected_parameter_ids
                != tuple(submission["expected_parameter_ids"])
                or request.exception_ids != expected_exception_ids
                or request.qa_required_exception_ids != expected_qa_ids
                or request.qa_disposition_exception_ids != actual_qa_ids
            ):
                raise AuditPolicyError(
                    "Targeted final request differs from audited trusted facts"
                )
            return self._commit_targeted_typed_cas_locked(
                handle=handle,
                events=events,
                task_id=request.task_id,
                actor_id=request.actor_id,
                action=request.action,
                details_record=details_record,
                evidence_context=completed_context,
                expected_previous_head_hash=request.expected_previous_head_hash,
                command_id=request.command_id,
                request_hash=request.request_hash,
            )

    def _commit_targeted_typed_cas(
        self,
        *,
        task_id: str,
        actor_id: str,
        action: AuditAction,
        details_record: dict[str, Any],
        evidence_context: EvidenceContext,
        expected_previous_head_hash: str,
        command_id: str,
        request_hash: str,
    ) -> AuditEvent:
        with self._locked_file(exclusive=True) as handle:
            events = self._read_locked(handle)
            return self._commit_targeted_typed_cas_locked(
                handle=handle,
                events=events,
                task_id=task_id,
                actor_id=actor_id,
                action=action,
                details_record=details_record,
                evidence_context=evidence_context,
                expected_previous_head_hash=expected_previous_head_hash,
                command_id=command_id,
                request_hash=request_hash,
            )

    def _commit_targeted_typed_cas_locked(
        self,
        *,
        handle,
        events: list[AuditEvent],
        task_id: str,
        actor_id: str,
        action: AuditAction,
        details_record: dict[str, Any],
        evidence_context: EvidenceContext,
        expected_previous_head_hash: str,
        command_id: str,
        request_hash: str,
    ) -> AuditEvent:
        """Write one targeted typed event while the caller holds the file lock."""

        existing_command = next(
            (
                event
                for event in events
                if event.task_id == task_id
                and event.action in _TARGETED_TYPED_ACTIONS
                and event.details.get("command_id") == command_id
            ),
            None,
        )
        if existing_command is not None:
            stored_hash = existing_command.details.get(
                "commit_request_hash",
                existing_command.details.get("request_hash"),
            )
            if existing_command.action is action and stored_hash == request_hash:
                if (
                    action is AuditAction.TARGETED_REVIEW_LOCKED
                    and any(
                        event.task_id == task_id
                        and event.action in _TARGETED_TYPED_ACTIONS
                        and event.sequence > existing_command.sequence
                        for event in events
                    )
                ):
                    raise AuditPolicyError(
                        "Targeted lock cannot be replayed after later targeted "
                        "transitions; verified state rehydration is required"
                    )
                return existing_command
            raise AuditPolicyError(
                "Targeted command_id was already used with another request"
            )
        current_head = events[-1].event_hash if events else GENESIS_HASH
        if current_head != expected_previous_head_hash:
            raise AuditPolicyError(
                "Targeted audit compare-and-swap failed: current head changed"
            )
        _validate_action_contract(
            actor_id=actor_id,
            action=action,
            details=details_record,
            parameter_id=None,
            reason=None,
            evidence_context=evidence_context,
        )
        _validate_semantic_transition(
            events,
            task_id=task_id,
            actor_id=actor_id,
            action=action,
            details=details_record,
            parameter_id=None,
            evidence_context=evidence_context,
        )
        occurred_at = _normalise_utc("clock result", self._clock())
        if action is AuditAction.TARGETED_REVIEW_LOCKED:
            locked_at = _parse_audit_timestamp(
                "targeted submission locked_at",
                details_record["submission"]["locked_at"],
            )
            if occurred_at < locked_at:
                raise AuditPolicyError(
                    "targeted lock audit time cannot predate the locked submission"
                )
        event_id = _require_identifier("event_id", self._event_id_factory())
        if any(event.event_id == event_id for event in events):
            raise DuplicateAuditEventError(f"Duplicate event ID: {event_id}")
        if events and occurred_at < events[-1].occurred_at:
            raise ValueError("clock result moved backwards relative to the audit log")
        details_json = _canonical_json(details_record)
        context_json = _canonical_json(evidence_context.to_record())
        event_without_hash = AuditEvent(
            audit_schema_version=AUDIT_SCHEMA_VERSION,
            sequence=len(events) + 1,
            event_id=event_id,
            task_id=task_id,
            parameter_id=None,
            actor_id=actor_id,
            occurred_at=occurred_at,
            action=action,
            reason=None,
            details_json=details_json,
            evidence_context_json=context_json,
            previous_hash=current_head,
            event_hash=GENESIS_HASH,
        )
        event = AuditEvent(
            **{
                **event_without_hash.__dict__,
                "event_hash": _calculate_event_hash(event_without_hash),
            }
        )
        handle.seek(0, os.SEEK_END)
        handle.write(_canonical_json(event.to_record()) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        return event

    def record_correction(
        self,
        *,
        task_id: str,
        actor_id: str,
        corrects_event_id: str,
        reason: str,
        corrected_details: Mapping[str, Any],
        parameter_id: str | None = None,
    ) -> AuditEvent:
        checked_task_id = _require_identifier("task_id", task_id)
        checked_target = _require_identifier("corrects_event_id", corrects_event_id)
        if not isinstance(corrected_details, Mapping):
            raise TypeError("corrected_details must be a mapping")
        existing = self.events()
        target = next(
            (event for event in existing if event.event_id == checked_target), None
        )
        if target is None:
            raise UnknownCorrectedEventError(
                f"Unknown corrected event ID: {checked_target}"
            )
        if target.task_id != checked_task_id:
            raise UnknownCorrectedEventError(
                "The corrected event does not belong to the supplied task"
            )
        target_context = _event_context(target)
        if target_context is None:
            raise AuditPolicyError(
                "Only evidence-bound controlled events may be corrected"
            )
        effective_parameter_id = (
            target.parameter_id if parameter_id is None else parameter_id
        )
        details = {
            "corrects_event_id": checked_target,
            "original_event_hash": target.event_hash,
            "corrected_details": dict(corrected_details),
        }
        return self.append(
            task_id=checked_task_id,
            actor_id=actor_id,
            action=AuditAction.CORRECTION_RECORDED,
            details=details,
            parameter_id=effective_parameter_id,
            reason=reason,
            evidence_context=target_context,
        )

    def events(self, *, task_id: str | None = None) -> tuple[AuditEvent, ...]:
        if task_id is not None:
            task_id = _require_identifier("task_id", task_id)
        with self._locked_file(exclusive=False) as handle:
            events = self._read_locked(handle)
        if task_id is None:
            return tuple(events)
        return tuple(event for event in events if event.task_id == task_id)

    def head_hash(self) -> str:
        events = self.events()
        return events[-1].event_hash if events else GENESIS_HASH

    def verify(self) -> None:
        self.events()

    def _locked_file(self, *, exclusive: bool):
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o600)
        handle = os.fdopen(descriptor, "r+", encoding="utf-8")

        class _LockContext:
            def __enter__(inner_self):
                fcntl.flock(
                    handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                )
                return handle

            def __exit__(inner_self, exc_type, exc_value, traceback):
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                finally:
                    handle.close()
                return False

        return _LockContext()

    @staticmethod
    def _read_locked(handle) -> list[AuditEvent]:
        handle.seek(0)
        events: list[AuditEvent] = []
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.endswith("\n"):
                raise AuditIntegrityError(
                    f"Audit log has a truncated line at line {line_number}"
                )
            try:
                record = json.loads(
                    raw_line,
                    object_pairs_hook=_json_object_rejecting_duplicate_keys,
                )
            except (json.JSONDecodeError, ValueError) as error:
                raise AuditIntegrityError(
                    f"Invalid JSON at audit-log line {line_number}: {error}"
                ) from error
            if not isinstance(record, dict):
                raise AuditIntegrityError(
                    f"Audit-log line {line_number} must contain a JSON object"
                )
            events.append(_event_from_record(record))
        verify_audit_chain(events)
        _verify_audit_semantics(events)
        return events
