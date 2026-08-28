"""A structurally isolated, full-field blind second review.

This module intentionally does not import primary-review, AI, or routing types.
The second reviewer receives the same frozen evidence and complete Schema order,
but no hint about which fields were flagged or what any earlier reviewer said.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from threading import RLock
from types import MappingProxyType
from typing import Any

from .evidence import EvidenceManifest
from .identity import Actor, PrincipalKind, Role


class BlindVerdict(str, Enum):
    SAME = "SAME"
    DIFFERENT = "DIFFERENT"
    UNABLE_TO_JUDGE = "UNABLE_TO_JUDGE"


class BlindReviewState(str, Enum):
    OPEN = "OPEN"
    LOCKED = "LOCKED"


class BlindReviewError(Exception):
    code = "BLIND_REVIEW_ERROR"


class UnauthorizedBlindReviewerError(BlindReviewError):
    code = "UNAUTHORIZED_BLIND_REVIEWER"


class ReviewerSeparationError(BlindReviewError):
    code = "REVIEWER_SEPARATION_REQUIRED"


class BlindReviewLockedError(BlindReviewError):
    code = "BLIND_REVIEW_LOCKED"


class UnknownBlindParameterError(BlindReviewError):
    code = "UNKNOWN_BLIND_PARAMETER"


class IncompleteSecondReviewError(BlindReviewError):
    code = "INCOMPLETE_SECOND_REVIEW"

    def __init__(self, missing_parameter_ids: tuple[str, ...]) -> None:
        self.missing_parameter_ids = missing_parameter_ids
        super().__init__(
            "Second review is incomplete; missing: "
            + ", ".join(missing_parameter_ids)
        )


class BlindReasonRequiredError(BlindReviewError):
    code = "BLIND_REASON_REQUIRED"


class StaleBlindReviewVersionError(BlindReviewError):
    code = "STALE_BLIND_REVIEW_VERSION"


class BlindEvidenceBindingError(BlindReviewError):
    """The command was created from evidence other than this session's evidence."""

    code = "BLIND_EVIDENCE_BINDING_ERROR"


class DuplicateBlindCommandConflictError(BlindReviewError):
    code = "DUPLICATE_BLIND_COMMAND_CONFLICT"


class InvalidBlindTransitionError(BlindReviewError):
    code = "INVALID_BLIND_TRANSITION"


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _require_identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe 1-128 character identifier")
    return value


def _require_reason(reason: str | None) -> str | None:
    if reason is None:
        return None
    if not isinstance(reason, str) or reason.strip() == "":
        raise ValueError("reason must be non-empty text")
    return reason


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware_utc(name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include timezone information")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class BlindReviewPacket:
    """The explicit allowlist DTO sent to the second-review UI."""

    blind_case_id: str
    evidence_manifest: EvidenceManifest
    expected_parameter_ids: tuple[str, ...]
    assigned_reviewer_id: str


@dataclass(frozen=True, slots=True)
class SecondReviewDecision:
    parameter_id: str
    verdict: BlindVerdict
    reviewer_id: str
    decided_at: datetime
    evidence_manifest_hash: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class LockedSecondReviewSubmission:
    blind_case_id: str
    evidence_manifest_hash: str
    reviewer_id: str
    decisions: tuple[SecondReviewDecision, ...]
    locked_at: datetime
    submission_hash: str


@dataclass(frozen=True, slots=True)
class _StoredCommand:
    payload_hash: str
    result: Any


class BlindReviewSession:
    """Contains only evidence, the assignee, and the assignee's own work."""

    def __init__(
        self,
        *,
        blind_case_id: str,
        evidence_manifest: EvidenceManifest,
        primary_reviewer_id: str,
        assigned_reviewer: Actor,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._blind_case_id = _require_identifier("blind_case_id", blind_case_id)
        if not isinstance(evidence_manifest, EvidenceManifest):
            raise TypeError("evidence_manifest must be an EvidenceManifest")
        self._primary_reviewer_id = _require_identifier(
            "primary_reviewer_id", primary_reviewer_id
        )
        self._validate_assignee(assigned_reviewer)
        if assigned_reviewer.actor_id == self._primary_reviewer_id:
            raise ReviewerSeparationError(
                "Primary and second reviewer must be different actors"
            )
        if not callable(clock):
            raise TypeError("clock must be callable")

        self._manifest = evidence_manifest
        self._manifest_hash = evidence_manifest.manifest_hash
        self._expected_parameter_ids = evidence_manifest.expected_parameter_ids
        self._expected_parameter_id_set = frozenset(self._expected_parameter_ids)
        self._assigned_reviewer_id = assigned_reviewer.actor_id
        self._clock = clock
        self._lock = RLock()
        self._state = BlindReviewState.OPEN
        self._version = 0
        self._decisions: dict[str, SecondReviewDecision] = {}
        self._decision_history: list[SecondReviewDecision] = []
        self._commands: dict[str, _StoredCommand] = {}
        self._locked_submission: LockedSecondReviewSubmission | None = None

    @property
    def state(self) -> BlindReviewState:
        with self._lock:
            return self._state

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    def packet(self, *, actor: Actor) -> BlindReviewPacket:
        with self._lock:
            self._authorize(actor)
            return BlindReviewPacket(
                blind_case_id=self._blind_case_id,
                evidence_manifest=self._manifest,
                expected_parameter_ids=self._expected_parameter_ids,
                assigned_reviewer_id=self._assigned_reviewer_id,
            )

    def own_decisions(
        self, *, actor: Actor
    ) -> Mapping[str, SecondReviewDecision]:
        with self._lock:
            self._authorize(actor)
            return MappingProxyType(dict(self._decisions))

    def own_decision_history(
        self, *, actor: Actor
    ) -> tuple[SecondReviewDecision, ...]:
        with self._lock:
            self._authorize(actor)
            return tuple(self._decision_history)

    def missing_parameter_ids(self, *, actor: Actor) -> tuple[str, ...]:
        with self._lock:
            self._authorize(actor)
            return tuple(
                parameter_id
                for parameter_id in self._expected_parameter_ids
                if parameter_id not in self._decisions
            )

    def record_decision(
        self,
        *,
        actor: Actor,
        evidence_manifest_hash: str,
        parameter_id: str,
        verdict: BlindVerdict,
        command_id: str,
        expected_version: int,
        reason: str | None = None,
    ) -> SecondReviewDecision:
        with self._lock:
            self._authorize(actor)
            checked_manifest_hash = self._require_evidence_manifest_hash(
                evidence_manifest_hash
            )
            checked_parameter_id = _require_identifier("parameter_id", parameter_id)
            if checked_parameter_id not in self._expected_parameter_id_set:
                raise UnknownBlindParameterError(
                    f"Parameter is outside this blind review: {checked_parameter_id}"
                )
            if not isinstance(verdict, BlindVerdict):
                raise TypeError("verdict must be a BlindVerdict")
            checked_reason = _require_reason(reason)
            if verdict is not BlindVerdict.SAME and checked_reason is None:
                raise BlindReasonRequiredError(
                    f"A reason is required for verdict {verdict.value}"
                )
            payload = {
                "operation": "record_decision",
                "actor_id": actor.actor_id,
                "evidence_manifest_hash": checked_manifest_hash,
                "parameter_id": checked_parameter_id,
                "verdict": verdict.value,
                "reason": checked_reason,
                "expected_version": expected_version,
            }
            stored = self._idempotent_result(command_id, payload)
            if stored is not None:
                assert isinstance(stored, SecondReviewDecision)
                return stored
            self._require_open()
            self._require_version(expected_version)

            decision = SecondReviewDecision(
                parameter_id=checked_parameter_id,
                verdict=verdict,
                reviewer_id=self._assigned_reviewer_id,
                decided_at=self._now(),
                evidence_manifest_hash=self._manifest_hash,
                reason=checked_reason,
            )
            self._decisions[checked_parameter_id] = decision
            self._decision_history.append(decision)
            self._version += 1
            self._remember_command(command_id, payload, decision)
            return decision

    def lock(
        self,
        *,
        actor: Actor,
        evidence_manifest_hash: str,
        command_id: str,
        expected_version: int,
    ) -> LockedSecondReviewSubmission:
        with self._lock:
            self._authorize(actor)
            checked_manifest_hash = self._require_evidence_manifest_hash(
                evidence_manifest_hash
            )
            payload = {
                "operation": "lock",
                "actor_id": actor.actor_id,
                "evidence_manifest_hash": checked_manifest_hash,
                "expected_version": expected_version,
            }
            stored = self._idempotent_result(command_id, payload)
            if stored is not None:
                assert isinstance(stored, LockedSecondReviewSubmission)
                return stored
            self._require_open()
            self._require_version(expected_version)
            missing = tuple(
                parameter_id
                for parameter_id in self._expected_parameter_ids
                if parameter_id not in self._decisions
            )
            if missing:
                raise IncompleteSecondReviewError(missing)
            if set(self._decisions) != self._expected_parameter_id_set:
                raise BlindReviewError(
                    "Second-review decisions do not exactly match the frozen Schema"
                )
            if any(
                key != decision.parameter_id
                or decision.reviewer_id != self._assigned_reviewer_id
                or decision.evidence_manifest_hash != self._manifest_hash
                for key, decision in self._decisions.items()
            ):
                raise BlindReviewError(
                    "Second-review snapshot has inconsistent identity or evidence"
                )

            locked_at = self._now()
            ordered = tuple(
                self._decisions[parameter_id]
                for parameter_id in self._expected_parameter_ids
            )
            submission = LockedSecondReviewSubmission(
                blind_case_id=self._blind_case_id,
                evidence_manifest_hash=self._manifest_hash,
                reviewer_id=self._assigned_reviewer_id,
                decisions=ordered,
                locked_at=locked_at,
                submission_hash=self._submission_hash(ordered, locked_at),
            )
            self._locked_submission = submission
            self._state = BlindReviewState.LOCKED
            self._version += 1
            self._remember_command(command_id, payload, submission)
            return submission

    def _authorize(self, actor: Actor) -> None:
        self._validate_assignee(actor)
        if (
            actor.actor_id != self._assigned_reviewer_id
            or actor.actor_id == self._primary_reviewer_id
        ):
            raise UnauthorizedBlindReviewerError(
                "Actor is not the assigned independent second reviewer"
            )

    @staticmethod
    def _validate_assignee(actor: Actor) -> None:
        if not isinstance(actor, Actor):
            raise TypeError("actor must be an Actor")
        if actor.kind is not PrincipalKind.HUMAN or not actor.has_role(
            Role.SECOND_REVIEWER
        ):
            raise UnauthorizedBlindReviewerError(
                "Blind review requires a human SECOND_REVIEWER"
            )

    def _require_open(self) -> None:
        if self._state is not BlindReviewState.OPEN:
            raise BlindReviewLockedError("Blind review is already locked")

    def _require_version(self, expected_version: int) -> None:
        if type(expected_version) is not int or expected_version < 0:
            raise ValueError("expected_version must be a non-negative integer")
        if expected_version != self._version:
            raise StaleBlindReviewVersionError(
                f"Expected version {expected_version}, current version {self._version}"
            )

    def _require_evidence_manifest_hash(self, value: str) -> str:
        """Fail before command replay or mutation when the displayed evidence is stale."""

        if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
            raise BlindEvidenceBindingError(
                "A valid evidence manifest hash is required for this blind review"
            )
        if value != self._manifest_hash:
            raise BlindEvidenceBindingError(
                "Evidence manifest hash does not match this blind review"
            )
        return value

    def _idempotent_result(self, command_id: str, payload: dict[str, Any]) -> Any | None:
        checked_command_id = _require_identifier("command_id", command_id)
        stored = self._commands.get(checked_command_id)
        if stored is None:
            return None
        payload_hash = self._payload_hash(payload)
        if stored.payload_hash != payload_hash:
            raise DuplicateBlindCommandConflictError(
                "The command ID was already used with a different payload"
            )
        return stored.result

    def _remember_command(
        self, command_id: str, payload: dict[str, Any], result: Any
    ) -> None:
        checked_command_id = _require_identifier("command_id", command_id)
        self._commands[checked_command_id] = _StoredCommand(
            payload_hash=self._payload_hash(payload), result=result
        )

    @staticmethod
    def _payload_hash(payload: dict[str, Any]) -> str:
        canonical = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _submission_hash(
        self,
        decisions: tuple[SecondReviewDecision, ...],
        locked_at: datetime,
    ) -> str:
        body = {
            "blind_case_id": self._blind_case_id,
            "evidence_manifest_hash": self._manifest_hash,
            "reviewer_id": self._assigned_reviewer_id,
            "locked_at": locked_at.isoformat(),
            "decisions": [
                {
                    "parameter_id": decision.parameter_id,
                    "verdict": decision.verdict.value,
                    "reason": decision.reason,
                    "decided_at": decision.decided_at.isoformat(),
                    "evidence_manifest_hash": decision.evidence_manifest_hash,
                }
                for decision in decisions
            ],
        }
        return self._payload_hash(body)

    def _now(self) -> datetime:
        return _aware_utc("clock result", self._clock())
