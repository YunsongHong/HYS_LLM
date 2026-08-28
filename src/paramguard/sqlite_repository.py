"""Durable SQLite registration and first-review (R1) repository.

Scope is intentionally P1: synthetic task registration, independent R1
decisions and the atomic R1 lock.  There is no AI queue, targeted review, QA,
final decision, electronic signature, authentication, or release operation in
this module.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import re
import sqlite3

from .canonical_json import (
    JsonValue,
    canonical_json_sha256,
    canonical_json_text,
    load_json_strict,
)
from .db import (
    DEFAULT_BUSY_TIMEOUT_MS,
    DEFAULT_JOURNAL_MODE,
    DatabaseHealth,
    connect_database,
    consistent_read_transaction,
    immediate_transaction,
    migrate_database,
    verify_database_integrity,
)
from .evidence import EvidenceArtifact, EvidenceManifest, EvidenceRole
from .pipeline import PipelineSpec
from .workflow import HumanVerdict, WorkflowMode


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_REASON_LENGTH = 4_000
_MAX_PAGE_SIZE = 500

_MANIFEST_KEYS = frozenset(
    {
        "manifest_version",
        "manifest_id",
        "schema_id",
        "schema_version",
        "schema_sha256",
        "template_id",
        "template_version",
        "template_sha256",
        "expected_parameter_ids",
        "artifacts",
    }
)
_ARTIFACT_KEYS = frozenset(
    {"artifact_id", "role", "sha256", "byte_length", "media_type"}
)
_PIPELINE_KEYS = frozenset(
    {
        "spec_id",
        "engine_name",
        "engine_version",
        "pipeline_version",
        "comparator_version",
        "configuration_sha256",
    }
)

_COMMON_RECEIPT_KEYS = frozenset(
    {
        "command_id",
        "command_type",
        "committed_at",
        "evidence_manifest_hash",
        "missing_count",
        "state",
        "task_id",
        "task_revision",
    }
)
_RECEIPT_KEYS_BY_VALUE = {
    "REGISTER_TASK": _COMMON_RECEIPT_KEYS,
    "RECORD_R1_DECISION": _COMMON_RECEIPT_KEYS
    | frozenset({"decision_revision", "parameter_id", "verdict"}),
    "LOCK_R1": _COMMON_RECEIPT_KEYS | frozenset({"locked_at", "snapshot_sha256"}),
}
_EVENT_BY_COMMAND = {
    "REGISTER_TASK": "TASK_REGISTERED",
    "RECORD_R1_DECISION": "R1_DECISION_RECORDED",
    "LOCK_R1": "R1_LOCKED",
}


class PersistenceContractError(RuntimeError):
    """Base error for rejected repository commands or corrupt rows."""


class SyntheticEvidenceRequiredError(PersistenceContractError):
    pass


class TaskAlreadyExistsError(PersistenceContractError):
    pass


class TaskNotFoundError(PersistenceContractError):
    pass


class ParameterNotFoundError(PersistenceContractError):
    pass


class CommandConflictError(PersistenceContractError):
    pass


class RevisionConflictError(PersistenceContractError):
    pass


class R1LockedError(PersistenceContractError):
    pass


class R1IncompleteError(PersistenceContractError):
    def __init__(self, missing_parameter_ids: tuple[str, ...]) -> None:
        self.missing_parameter_ids = missing_parameter_ids
        super().__init__(
            "R1 is incomplete; missing decisions for: "
            + ", ".join(missing_parameter_ids)
        )


class R1ReasonRequiredError(PersistenceContractError):
    pass


class StoredDataIntegrityError(PersistenceContractError):
    pass


class DataClassification(str, Enum):
    SYNTHETIC = "SYNTHETIC"


class CommandType(str, Enum):
    REGISTER_TASK = "REGISTER_TASK"
    RECORD_R1_DECISION = "RECORD_R1_DECISION"
    LOCK_R1 = "LOCK_R1"


@dataclass(frozen=True, slots=True)
class CommandReceipt:
    command_id: str
    task_id: str
    command_type: CommandType
    request_sha256: str
    response_json: str
    response_sha256: str
    task_revision: int
    committed_at: str

    @property
    def response(self) -> dict[str, JsonValue]:
        expected_keys = _RECEIPT_KEYS_BY_VALUE[self.command_type.value]
        parsed = load_json_strict(
            self.response_json,
            allowed_keys=expected_keys,
            required_keys=expected_keys,
        )
        if type(parsed) is not dict:
            raise StoredDataIntegrityError("stored receipt response is not an object")
        return parsed


@dataclass(frozen=True, slots=True)
class TaskSnapshot:
    task_id: str
    state: str
    revision: int
    evidence_manifest_hash: str
    pipeline_spec_hash: str
    reviewer_id: str
    parameter_count: int
    registered_at: str
    r1_locked_at: str | None


@dataclass(frozen=True, slots=True)
class ParameterRecord:
    ordinal: int
    parameter_id: str


@dataclass(frozen=True, slots=True)
class ParameterPage:
    items: tuple[ParameterRecord, ...]
    next_after_ordinal: int | None


@dataclass(frozen=True, slots=True)
class R1DecisionRecord:
    ordinal: int
    parameter_id: str
    decision_revision: int
    task_revision: int
    verdict: HumanVerdict
    reason: str | None
    reviewer_id: str
    evidence_manifest_hash: str
    decided_at: str
    command_id: str


@dataclass(frozen=True, slots=True)
class R1DecisionPage:
    items: tuple[R1DecisionRecord, ...]
    next_after_ordinal: int | None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _identifier(name: str, value: str) -> str:
    if type(value) is not str or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be an exact safe 1-128 character identifier")
    return value


def _sha256(name: str, value: str) -> str:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be 64 lowercase hexadecimal characters")
    return value


def _exact_revision(value: int) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("expected_revision must be a non-negative exact integer")
    return value


def _reason(verdict: HumanVerdict, value: str | None) -> str | None:
    if value is not None and type(value) is not str:
        raise TypeError("reason must be an exact str or None")
    checked = None if value is None else value.strip()
    if checked == "":
        checked = None
    if checked is not None and len(checked) > _MAX_REASON_LENGTH:
        raise ValueError(f"reason must be at most {_MAX_REASON_LENGTH} characters")
    if verdict is not HumanVerdict.SAME and checked is None:
        raise R1ReasonRequiredError(
            f"reason is required for R1 verdict {verdict.value}"
        )
    return checked


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime):
        raise TypeError("clock must return datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _stored_timestamp(name: str, value: object) -> str:
    if type(value) is not str or not value.endswith("Z"):
        raise StoredDataIntegrityError(
            f"stored {name} is not a canonical UTC timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise StoredDataIntegrityError(
            f"stored {name} is not a valid timestamp"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise StoredDataIntegrityError(f"stored {name} is not UTC")
    if _timestamp(parsed) != value:
        raise StoredDataIntegrityError(f"stored {name} is not canonically encoded")
    return value


def _require_non_decreasing_task_time(
    connection: sqlite3.Connection, *, task_id: str, candidate: str
) -> None:
    """Reject a clock value older than the task's latest durable command."""

    row = connection.execute(
        "SELECT committed_at FROM command_receipts WHERE task_id=? "
        "ORDER BY task_revision DESC LIMIT 1",
        (task_id,),
    ).fetchone()
    if row is None:
        return
    previous = _stored_timestamp("previous receipt committed_at", row["committed_at"])
    if candidate < previous:
        raise ValueError("clock result moved backwards relative to the task history")


def _manifest_from_stored_json(source: object) -> EvidenceManifest:
    if type(source) is not str:
        raise StoredDataIntegrityError("stored EvidenceManifest JSON must be text")
    value = load_json_strict(
        source, allowed_keys=_MANIFEST_KEYS, required_keys=_MANIFEST_KEYS
    )
    if type(value) is not dict or canonical_json_text(value) != source:
        raise StoredDataIntegrityError("stored EvidenceManifest JSON is not canonical")
    if type(value["manifest_version"]) is not int or value["manifest_version"] != 1:
        raise StoredDataIntegrityError("stored EvidenceManifest version is unsupported")
    parameter_values = value["expected_parameter_ids"]
    artifact_values = value["artifacts"]
    if type(parameter_values) is not list or any(
        type(item) is not str for item in parameter_values
    ):
        raise StoredDataIntegrityError("stored parameter IDs are malformed")
    if type(artifact_values) is not list:
        raise StoredDataIntegrityError("stored evidence artifacts are malformed")
    artifacts: list[EvidenceArtifact] = []
    for artifact_value in artifact_values:
        if type(artifact_value) is not dict or set(artifact_value) != set(
            _ARTIFACT_KEYS
        ):
            raise StoredDataIntegrityError("stored evidence artifact schema is invalid")
        try:
            artifacts.append(
                EvidenceArtifact(
                    artifact_id=artifact_value["artifact_id"],  # type: ignore[arg-type]
                    role=EvidenceRole(artifact_value["role"]),  # type: ignore[arg-type]
                    sha256=artifact_value["sha256"],  # type: ignore[arg-type]
                    byte_length=artifact_value["byte_length"],  # type: ignore[arg-type]
                    media_type=artifact_value["media_type"],  # type: ignore[arg-type]
                )
            )
        except (TypeError, ValueError) as error:
            raise StoredDataIntegrityError(
                "stored evidence artifact values are invalid"
            ) from error
    try:
        return EvidenceManifest(
            manifest_id=value["manifest_id"],  # type: ignore[arg-type]
            schema_id=value["schema_id"],  # type: ignore[arg-type]
            schema_version=value["schema_version"],  # type: ignore[arg-type]
            schema_sha256=value["schema_sha256"],  # type: ignore[arg-type]
            template_id=value["template_id"],  # type: ignore[arg-type]
            template_version=value["template_version"],  # type: ignore[arg-type]
            template_sha256=value["template_sha256"],  # type: ignore[arg-type]
            expected_parameter_ids=tuple(parameter_values),
            artifacts=tuple(artifacts),
        )
    except (TypeError, ValueError) as error:
        raise StoredDataIntegrityError(
            "stored EvidenceManifest values are invalid"
        ) from error


def _pipeline_from_stored_json(source: object) -> PipelineSpec:
    if type(source) is not str:
        raise StoredDataIntegrityError("stored PipelineSpec JSON must be text")
    value = load_json_strict(
        source, allowed_keys=_PIPELINE_KEYS, required_keys=_PIPELINE_KEYS
    )
    if type(value) is not dict or canonical_json_text(value) != source:
        raise StoredDataIntegrityError("stored PipelineSpec JSON is not canonical")
    try:
        return PipelineSpec(
            spec_id=value["spec_id"],  # type: ignore[arg-type]
            engine_name=value["engine_name"],  # type: ignore[arg-type]
            engine_version=value["engine_version"],  # type: ignore[arg-type]
            pipeline_version=value["pipeline_version"],  # type: ignore[arg-type]
            comparator_version=value["comparator_version"],  # type: ignore[arg-type]
            configuration_sha256=value["configuration_sha256"],  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise StoredDataIntegrityError(
            "stored PipelineSpec values are invalid"
        ) from error


def _page_arguments(after_ordinal: int, limit: int) -> tuple[int, int]:
    if type(after_ordinal) is not int or after_ordinal < -1:
        raise ValueError("after_ordinal must be an integer of -1 or greater")
    if type(limit) is not int or not 1 <= limit <= _MAX_PAGE_SIZE:
        raise ValueError(f"limit must be an integer from 1 to {_MAX_PAGE_SIZE}")
    return after_ordinal, limit


def _validate_receipt_response_types(
    command_type: CommandType, response: dict[str, JsonValue]
) -> None:
    """Reject JSON scalar coercion before comparing replayed receipt values."""

    try:
        _identifier("stored receipt command_id", response["command_id"])  # type: ignore[arg-type]
        _identifier("stored receipt task_id", response["task_id"])  # type: ignore[arg-type]
        _sha256(
            "stored receipt evidence_manifest_hash",
            response["evidence_manifest_hash"],  # type: ignore[arg-type]
        )
        _stored_timestamp("receipt response committed_at", response["committed_at"])
    except (KeyError, TypeError, ValueError, PersistenceContractError) as error:
        raise StoredDataIntegrityError(
            "stored receipt response scalar types are invalid"
        ) from error
    if (
        type(response["command_type"]) is not str
        or response["command_type"] != command_type.value
        or type(response["state"]) is not str
        or type(response["missing_count"]) is not int
        or response["missing_count"] < 0
        or type(response["task_revision"]) is not int
        or response["task_revision"] < 0
    ):
        raise StoredDataIntegrityError(
            "stored receipt response scalar types are invalid"
        )
    if command_type is CommandType.RECORD_R1_DECISION:
        try:
            _identifier(
                "stored receipt parameter_id", response["parameter_id"]  # type: ignore[arg-type]
            )
            HumanVerdict(response["verdict"])
        except (KeyError, TypeError, ValueError) as error:
            raise StoredDataIntegrityError(
                "stored R1 decision receipt response types are invalid"
            ) from error
        if (
            type(response["decision_revision"]) is not int
            or response["decision_revision"] <= 0
        ):
            raise StoredDataIntegrityError(
                "stored R1 decision receipt response types are invalid"
            )
    elif command_type is CommandType.LOCK_R1:
        try:
            _stored_timestamp("receipt response locked_at", response["locked_at"])
            _sha256(
                "stored receipt snapshot_sha256",
                response["snapshot_sha256"],  # type: ignore[arg-type]
            )
        except (KeyError, TypeError, ValueError, PersistenceContractError) as error:
            raise StoredDataIntegrityError(
                "stored R1 lock receipt response types are invalid"
            ) from error


class SQLiteR1Repository:
    """A connection-per-command repository with SQL CAS and durable receipts."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        journal_mode: str = DEFAULT_JOURNAL_MODE,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        clock: Callable[[], datetime] = _utc_now,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        if type(database_path) is str:
            self._database_path: str | Path = database_path
        elif isinstance(database_path, Path):
            self._database_path = database_path
        else:
            raise TypeError("database_path must be an exact str or pathlib.Path")
        if type(journal_mode) is not str:
            raise TypeError("journal_mode must be an exact str")
        if type(busy_timeout_ms) is not int:
            raise TypeError("busy_timeout_ms must be an exact int")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if fault_injector is not None and not callable(fault_injector):
            raise TypeError("fault_injector must be callable or None")
        self._journal_mode = journal_mode
        self._busy_timeout_ms = busy_timeout_ms
        self._clock = clock
        self._fault_injector = fault_injector
        with closing(self._connect()) as connection:
            migrate_database(connection)
            with consistent_read_transaction(connection):
                verify_database_integrity(connection)
                self._verify_semantics(connection)

    def _connect(self) -> sqlite3.Connection:
        return connect_database(
            self._database_path,
            journal_mode=self._journal_mode,
            busy_timeout_ms=self._busy_timeout_ms,
        )

    def _fault(self, point: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(point)

    def verify_integrity(self) -> DatabaseHealth:
        with closing(self._connect()) as connection:
            with consistent_read_transaction(connection):
                health = verify_database_integrity(connection)
                self._verify_semantics(connection)
            return health

    def _verify_semantics(self, connection: sqlite3.Connection) -> None:
        """Replay P1 storage invariants instead of trusting physical hashes alone."""

        receipt_rows = tuple(
            connection.execute(
                "SELECT * FROM command_receipts ORDER BY task_id, task_revision, command_id"
            ).fetchall()
        )
        receipts: dict[str, CommandReceipt] = {}
        for row in receipt_rows:
            receipt = self._receipt_from_row(row)
            if receipt.command_id in receipts:
                raise StoredDataIntegrityError("duplicate command receipt identity")
            _stored_timestamp("receipt committed_at", receipt.committed_at)
            receipts[receipt.command_id] = receipt

        outbox_rows = tuple(
            connection.execute(
                "SELECT * FROM audit_outbox ORDER BY outbox_id"
            ).fetchall()
        )
        if len(outbox_rows) != len(receipts):
            raise StoredDataIntegrityError(
                "every command receipt must have exactly one P1 outbox row"
            )
        outbox_commands: set[str] = set()
        for row in outbox_rows:
            command_id = str(row["command_id"])
            if command_id in outbox_commands or command_id not in receipts:
                raise StoredDataIntegrityError("outbox command binding is invalid")
            outbox_commands.add(command_id)
            receipt = receipts[command_id]
            self._verify_outbox_row(row, receipt)

        for task in connection.execute("SELECT * FROM tasks ORDER BY task_id"):
            self._verify_task_semantics(connection, task, receipts)

    @staticmethod
    def _verify_outbox_row(row: sqlite3.Row, receipt: CommandReceipt) -> None:
        payload_json = str(row["payload_json"])
        payload = load_json_strict(payload_json)
        if (
            row["command_id"] != receipt.command_id
            or payload_json != receipt.response_json
            or canonical_json_text(payload) != payload_json
            or canonical_json_sha256(payload) != row["payload_sha256"]
            or row["task_id"] != receipt.task_id
            or int(row["aggregate_revision"]) != receipt.task_revision
            or row["event_type"] != _EVENT_BY_COMMAND[receipt.command_type.value]
            or row["created_at"] != receipt.committed_at
            or row["published_at"] is not None
        ):
            raise StoredDataIntegrityError(
                "outbox row does not exactly mirror its durable command receipt"
            )

    @staticmethod
    def _verify_decision_response(
        receipt: CommandReceipt, decision: sqlite3.Row, manifest_hash: str
    ) -> None:
        response = receipt.response
        if (
            response.get("evidence_manifest_hash") != manifest_hash
            or response.get("parameter_id") != decision["parameter_id"]
            or response.get("verdict") != decision["verdict"]
            or response.get("decision_revision") != int(decision["decision_revision"])
            or response.get("state") != "HUMAN_REVIEW_OPEN"
        ):
            raise StoredDataIntegrityError(
                "R1 decision row does not match its receipt response"
            )

    def _verify_task_semantics(
        self,
        connection: sqlite3.Connection,
        task: sqlite3.Row,
        receipts: dict[str, CommandReceipt],
    ) -> None:
        task_id = str(task["task_id"])
        if (
            task["workflow_mode"] != WorkflowMode.STRICT_SEQUENTIAL.value
            or task["data_classification"] != DataClassification.SYNTHETIC.value
        ):
            raise StoredDataIntegrityError("task mode or classification is invalid")
        _stored_timestamp("task registered_at", task["registered_at"])
        manifest = _manifest_from_stored_json(task["evidence_manifest_json"])
        pipeline = _pipeline_from_stored_json(task["pipeline_spec_json"])
        if (
            manifest.manifest_id != task["evidence_manifest_id"]
            or manifest.manifest_hash != task["evidence_manifest_hash"]
            or pipeline.spec_id != task["pipeline_spec_id"]
            or pipeline.spec_hash != task["pipeline_spec_hash"]
        ):
            raise StoredDataIntegrityError(
                "task columns disagree with frozen manifest or pipeline JSON"
            )
        parameter_rows = tuple(
            connection.execute(
                "SELECT ordinal, parameter_id FROM task_parameters "
                "WHERE task_id=? ORDER BY ordinal",
                (task_id,),
            ).fetchall()
        )
        if tuple(int(row["ordinal"]) for row in parameter_rows) != tuple(
            range(len(parameter_rows))
        ) or tuple(str(row["parameter_id"]) for row in parameter_rows) != (
            manifest.expected_parameter_ids
        ):
            raise StoredDataIntegrityError(
                "normalized task parameter rows disagree with frozen manifest order"
            )
        artifact_rows = tuple(
            connection.execute(
                "SELECT artifact_id, role, sha256, byte_length, media_type "
                "FROM evidence_artifacts WHERE task_id=? ORDER BY artifact_id",
                (task_id,),
            ).fetchall()
        )
        observed_artifacts = tuple(
            (
                str(row["artifact_id"]),
                str(row["role"]),
                str(row["sha256"]),
                int(row["byte_length"]),
                str(row["media_type"]),
            )
            for row in artifact_rows
        )
        expected_artifacts = tuple(
            sorted(
                (
                    item.artifact_id,
                    item.role.value,
                    item.sha256,
                    item.byte_length,
                    item.media_type,
                )
                for item in manifest.artifacts
            )
        )
        if observed_artifacts != expected_artifacts:
            raise StoredDataIntegrityError(
                "normalized evidence artifacts disagree with frozen manifest"
            )
        assignment_rows = tuple(
            connection.execute(
                "SELECT phase, actor_id, actor_role, assigned_at "
                "FROM task_assignments WHERE task_id=?",
                (task_id,),
            ).fetchall()
        )
        if (
            len(assignment_rows) != 1
            or assignment_rows[0]["phase"] != "R1"
            or assignment_rows[0]["actor_role"] != "R1_REVIEWER"
        ):
            raise StoredDataIntegrityError(
                "task must have exactly one valid R1 assignment"
            )
        reviewer_id = str(assignment_rows[0]["actor_id"])
        _identifier("stored reviewer_id", reviewer_id)
        assigned_at = _stored_timestamp(
            "assignment assigned_at", assignment_rows[0]["assigned_at"]
        )
        if assigned_at != task["registered_at"]:
            raise StoredDataIntegrityError(
                "R1 assignment timestamp does not match task registration"
            )

        task_receipts = sorted(
            (item for item in receipts.values() if item.task_id == task_id),
            key=lambda item: item.task_revision,
        )
        revision = int(task["revision"])
        if len(task_receipts) != revision + 1 or any(
            item.task_revision != expected_revision
            for expected_revision, item in enumerate(task_receipts)
        ):
            raise StoredDataIntegrityError(
                "task revisions are not exactly covered by durable receipts"
            )
        if any(
            current.committed_at < previous.committed_at
            for previous, current in zip(task_receipts, task_receipts[1:])
        ):
            raise StoredDataIntegrityError(
                "task receipt timestamp sequence moved backwards"
            )
        if (
            not task_receipts
            or task_receipts[0].command_type is not CommandType.REGISTER_TASK
            or any(
                item.command_type is CommandType.REGISTER_TASK
                for item in task_receipts[1:]
            )
        ):
            raise StoredDataIntegrityError(
                "task registration receipt sequence is invalid"
            )
        registration_response = task_receipts[0].response
        registration_request: dict[str, JsonValue] = {
            "command_id": task_receipts[0].command_id,
            "command_type": CommandType.REGISTER_TASK.value,
            "data_classification": DataClassification.SYNTHETIC.value,
            "evidence_manifest": manifest.to_record(),  # type: ignore[dict-item]
            "pipeline_spec": pipeline.to_record(),  # type: ignore[dict-item]
            "reviewer_id": reviewer_id,
            "task_id": task_id,
        }
        if (
            task_receipts[0].committed_at != task["registered_at"]
            or task_receipts[0].request_sha256
            != canonical_json_sha256(registration_request)
            or registration_response.get("evidence_manifest_hash")
            != manifest.manifest_hash
            or registration_response.get("missing_count")
            != len(manifest.expected_parameter_ids)
            or registration_response.get("state") != "HUMAN_REVIEW_OPEN"
        ):
            raise StoredDataIntegrityError(
                "task registration row and receipt do not share one frozen identity"
            )

        decision_rows = tuple(
            connection.execute(
                "SELECT * FROM r1_decisions WHERE task_id=? " "ORDER BY task_revision",
                (task_id,),
            ).fetchall()
        )
        revisions_by_parameter: dict[str, list[int]] = {}
        decisions_by_task_revision: dict[int, sqlite3.Row] = {}
        for row in decision_rows:
            task_revision = int(row["task_revision"])
            if task_revision in decisions_by_task_revision:
                raise StoredDataIntegrityError(
                    "more than one R1 decision claims the same task revision"
                )
            decisions_by_task_revision[task_revision] = row
            parameter_id = str(row["parameter_id"])
            revisions_by_parameter.setdefault(parameter_id, []).append(
                int(row["decision_revision"])
            )
            try:
                verdict = HumanVerdict(str(row["verdict"]))
            except ValueError as error:
                raise StoredDataIntegrityError(
                    "stored R1 verdict is invalid"
                ) from error
            try:
                normalized_reason = _reason(verdict, row["reason"])
            except (TypeError, ValueError, PersistenceContractError) as error:
                raise StoredDataIntegrityError(
                    "stored R1 reason is invalid for its verdict"
                ) from error
            if normalized_reason != row["reason"]:
                raise StoredDataIntegrityError(
                    "stored R1 reason is not canonically normalized"
                )
            _stored_timestamp("decision decided_at", row["decided_at"])
            command_id = str(row["command_id"])
            receipt = receipts.get(command_id)
            request: dict[str, JsonValue] = {
                "command_id": command_id,
                "command_type": CommandType.RECORD_R1_DECISION.value,
                "evidence_manifest_hash": manifest.manifest_hash,
                "expected_revision": task_revision - 1,
                "parameter_id": parameter_id,
                "reason": row["reason"],
                "reviewer_id": reviewer_id,
                "task_id": task_id,
                "verdict": verdict.value,
            }
            if (
                receipt is None
                or receipt.command_type is not CommandType.RECORD_R1_DECISION
                or receipt.task_id != task_id
                or receipt.task_revision != int(row["task_revision"])
                or receipt.committed_at != row["decided_at"]
                or receipt.request_sha256 != canonical_json_sha256(request)
                or row["reviewer_id"] != reviewer_id
                or row["evidence_manifest_hash"] != manifest.manifest_hash
            ):
                raise StoredDataIntegrityError(
                    "R1 decision row does not match assignment, manifest, and receipt"
                )
            self._verify_decision_response(receipt, row, manifest.manifest_hash)

        seen_parameters: set[str] = set()
        lock_seen = False
        for receipt in task_receipts[1:]:
            response = receipt.response
            if receipt.command_type is CommandType.RECORD_R1_DECISION:
                if lock_seen:
                    raise StoredDataIntegrityError(
                        "R1 decision receipt appears after the lock receipt"
                    )
                row = decisions_by_task_revision.pop(receipt.task_revision, None)
                if row is None or row["command_id"] != receipt.command_id:
                    raise StoredDataIntegrityError(
                        "every R1 decision receipt must match exactly one decision row"
                    )
                seen_parameters.add(str(row["parameter_id"]))
                expected_missing = len(manifest.expected_parameter_ids) - len(
                    seen_parameters
                )
                if (
                    response.get("missing_count") != expected_missing
                    or response.get("state") != "HUMAN_REVIEW_OPEN"
                ):
                    raise StoredDataIntegrityError(
                        "R1 decision receipt does not match replayed task completeness"
                    )
            elif receipt.command_type is CommandType.LOCK_R1:
                if lock_seen or receipt is not task_receipts[-1]:
                    raise StoredDataIntegrityError(
                        "R1 lock receipt must be unique and last"
                    )
                lock_seen = True
                if (
                    response.get("missing_count") != 0
                    or response.get("state") != "HUMAN_REVIEW_LOCKED"
                ):
                    raise StoredDataIntegrityError(
                        "R1 lock receipt does not describe a complete locked task"
                    )
        if decisions_by_task_revision:
            raise StoredDataIntegrityError(
                "every R1 decision row must match exactly one decision receipt"
            )
        if any(
            values != list(range(1, len(values) + 1))
            for values in revisions_by_parameter.values()
        ):
            raise StoredDataIntegrityError(
                "per-parameter R1 decision revisions are not contiguous"
            )

        lock_rows = tuple(
            connection.execute(
                "SELECT * FROM r1_locks WHERE task_id=?", (task_id,)
            ).fetchall()
        )
        if task["state"] == "HUMAN_REVIEW_OPEN":
            if (
                lock_rows
                or task["r1_locked_at"] is not None
                or any(
                    item.command_type is CommandType.LOCK_R1 for item in task_receipts
                )
            ):
                raise StoredDataIntegrityError("open R1 task contains a lock artifact")
        elif task["state"] == "HUMAN_REVIEW_LOCKED":
            if len(lock_rows) != 1:
                raise StoredDataIntegrityError(
                    "locked R1 task must contain one lock row"
                )
            self._verify_lock_semantics(
                connection,
                task=task,
                lock=lock_rows[0],
                manifest=manifest,
                reviewer_id=reviewer_id,
                receipts=receipts,
            )
        else:
            raise StoredDataIntegrityError("stored task state is invalid")

    def _verify_lock_semantics(
        self,
        connection: sqlite3.Connection,
        *,
        task: sqlite3.Row,
        lock: sqlite3.Row,
        manifest: EvidenceManifest,
        reviewer_id: str,
        receipts: dict[str, CommandReceipt],
    ) -> None:
        task_id = str(task["task_id"])
        locked_at = _stored_timestamp("R1 locked_at", lock["locked_at"])
        rows = self._latest_decision_rows(connection, task_id)
        if any(row["decision_revision"] is None for row in rows):
            raise StoredDataIntegrityError("locked R1 snapshot is incomplete")
        snapshot: dict[str, JsonValue] = {
            "evidence_manifest_hash": manifest.manifest_hash,
            "reviewer_id": reviewer_id,
            "task_id": task_id,
            "decisions": [
                {
                    "decision_revision": int(row["decision_revision"]),
                    "decided_at": str(row["decided_at"]),
                    "parameter_id": str(row["parameter_id"]),
                    "reason": row["reason"],
                    "task_revision": int(row["task_revision"]),
                    "verdict": str(row["verdict"]),
                }
                for row in rows
            ],
        }
        command_id = str(lock["command_id"])
        receipt = receipts.get(command_id)
        request: dict[str, JsonValue] = {
            "command_id": command_id,
            "command_type": CommandType.LOCK_R1.value,
            "evidence_manifest_hash": manifest.manifest_hash,
            "expected_revision": int(task["revision"]) - 1,
            "reviewer_id": reviewer_id,
            "task_id": task_id,
        }
        if (
            int(lock["task_revision"]) != int(task["revision"])
            or int(lock["decision_count"]) != len(rows)
            or lock["snapshot_sha256"] != canonical_json_sha256(snapshot)
            or lock["evidence_manifest_hash"] != manifest.manifest_hash
            or lock["reviewer_id"] != reviewer_id
            or task["r1_locked_at"] != locked_at
            or receipt is None
            or receipt.command_type is not CommandType.LOCK_R1
            or receipt.request_sha256 != canonical_json_sha256(request)
            or receipt.task_revision != int(task["revision"])
            or receipt.committed_at != locked_at
            or receipt.response.get("evidence_manifest_hash") != manifest.manifest_hash
            or receipt.response.get("snapshot_sha256") != lock["snapshot_sha256"]
            or receipt.response.get("locked_at") != locked_at
            or receipt.response.get("missing_count") != 0
            or receipt.response.get("state") != "HUMAN_REVIEW_LOCKED"
        ):
            raise StoredDataIntegrityError(
                "R1 lock does not match its task, latest snapshot, and receipt"
            )

    def register_task(
        self,
        *,
        task_id: str,
        evidence_manifest: EvidenceManifest,
        pipeline_spec: PipelineSpec,
        reviewer_id: str,
        command_id: str,
        data_classification: DataClassification,
    ) -> CommandReceipt:
        checked_task = _identifier("task_id", task_id)
        checked_reviewer = _identifier("reviewer_id", reviewer_id)
        checked_command = _identifier("command_id", command_id)
        if not isinstance(evidence_manifest, EvidenceManifest):
            raise TypeError("evidence_manifest must be EvidenceManifest")
        if not isinstance(pipeline_spec, PipelineSpec):
            raise TypeError("pipeline_spec must be PipelineSpec")
        if data_classification is not DataClassification.SYNTHETIC:
            raise SyntheticEvidenceRequiredError(
                "this learning repository accepts explicitly classified synthetic evidence only"
            )
        manifest_record = evidence_manifest.to_record()
        pipeline_record = pipeline_spec.to_record()
        manifest_json = canonical_json_text(manifest_record)  # type: ignore[arg-type]
        pipeline_json = canonical_json_text(pipeline_record)  # type: ignore[arg-type]
        manifest_hash = canonical_json_sha256(manifest_record)  # type: ignore[arg-type]
        pipeline_hash = canonical_json_sha256(pipeline_record)  # type: ignore[arg-type]
        if manifest_hash != evidence_manifest.manifest_hash:
            raise StoredDataIntegrityError(
                "EvidenceManifest hash disagrees with canonical persistence encoding"
            )
        if pipeline_hash != pipeline_spec.spec_hash:
            raise StoredDataIntegrityError(
                "PipelineSpec hash disagrees with canonical persistence encoding"
            )
        request: dict[str, JsonValue] = {
            "command_id": checked_command,
            "command_type": CommandType.REGISTER_TASK.value,
            "data_classification": data_classification.value,
            "evidence_manifest": manifest_record,  # type: ignore[dict-item]
            "pipeline_spec": pipeline_record,  # type: ignore[dict-item]
            "reviewer_id": checked_reviewer,
            "task_id": checked_task,
        }
        request_hash = canonical_json_sha256(request)
        with closing(self._connect()) as connection, immediate_transaction(connection):
            stored = self._idempotent_receipt(
                connection,
                command_id=checked_command,
                task_id=checked_task,
                command_type=CommandType.REGISTER_TASK,
                request_sha256=request_hash,
            )
            if stored is not None:
                return stored
            if (
                connection.execute(
                    "SELECT 1 FROM tasks WHERE task_id=?", (checked_task,)
                ).fetchone()
                is not None
            ):
                raise TaskAlreadyExistsError(f"task already exists: {checked_task}")

            now = _timestamp(self._clock())

            connection.execute(
                "INSERT INTO tasks("
                "task_id, workflow_mode, state, revision, data_classification, "
                "evidence_manifest_id, evidence_manifest_hash, evidence_manifest_json, "
                "pipeline_spec_id, pipeline_spec_hash, pipeline_spec_json, registered_at"
                ") VALUES (?, ?, 'HUMAN_REVIEW_OPEN', 0, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    checked_task,
                    WorkflowMode.STRICT_SEQUENTIAL.value,
                    data_classification.value,
                    evidence_manifest.manifest_id,
                    manifest_hash,
                    manifest_json,
                    pipeline_spec.spec_id,
                    pipeline_hash,
                    pipeline_json,
                    now,
                ),
            )
            self._fault("register.after_task")
            connection.executemany(
                "INSERT INTO task_parameters(task_id, ordinal, parameter_id) "
                "VALUES (?, ?, ?)",
                (
                    (checked_task, ordinal, parameter_id)
                    for ordinal, parameter_id in enumerate(
                        evidence_manifest.expected_parameter_ids
                    )
                ),
            )
            self._fault("register.after_parameters")
            connection.executemany(
                "INSERT INTO evidence_artifacts("
                "task_id, artifact_id, role, sha256, byte_length, media_type"
                ") VALUES (?, ?, ?, ?, ?, ?)",
                (
                    (
                        checked_task,
                        artifact.artifact_id,
                        artifact.role.value,
                        artifact.sha256,
                        artifact.byte_length,
                        artifact.media_type,
                    )
                    for artifact in evidence_manifest.artifacts
                ),
            )
            self._fault("register.after_artifacts")
            connection.execute(
                "INSERT INTO task_assignments("
                "task_id, phase, actor_id, actor_role, assigned_at"
                ") VALUES (?, 'R1', ?, 'R1_REVIEWER', ?)",
                (checked_task, checked_reviewer, now),
            )
            self._fault("register.after_assignment")
            response: dict[str, JsonValue] = {
                "command_id": checked_command,
                "command_type": CommandType.REGISTER_TASK.value,
                "committed_at": now,
                "evidence_manifest_hash": manifest_hash,
                "missing_count": len(evidence_manifest.expected_parameter_ids),
                "state": "HUMAN_REVIEW_OPEN",
                "task_id": checked_task,
                "task_revision": 0,
            }
            receipt = self._insert_receipt(
                connection,
                command_id=checked_command,
                task_id=checked_task,
                command_type=CommandType.REGISTER_TASK,
                request_sha256=request_hash,
                response=response,
                task_revision=0,
                committed_at=now,
            )
            self._insert_outbox(
                connection,
                task_id=checked_task,
                revision=0,
                event_type="TASK_REGISTERED",
                command_id=checked_command,
                payload=response,
                created_at=now,
            )
            self._fault("register.before_commit")
            return receipt

    def record_r1_decision(
        self,
        *,
        task_id: str,
        parameter_id: str,
        verdict: HumanVerdict,
        reviewer_id: str,
        evidence_manifest_hash: str,
        reason: str | None,
        command_id: str,
        expected_revision: int,
    ) -> CommandReceipt:
        checked_task = _identifier("task_id", task_id)
        checked_parameter = _identifier("parameter_id", parameter_id)
        checked_reviewer = _identifier("reviewer_id", reviewer_id)
        checked_manifest = _sha256("evidence_manifest_hash", evidence_manifest_hash)
        checked_command = _identifier("command_id", command_id)
        expected = _exact_revision(expected_revision)
        if not isinstance(verdict, HumanVerdict):
            raise TypeError("verdict must be HumanVerdict")
        checked_reason = _reason(verdict, reason)
        request: dict[str, JsonValue] = {
            "command_id": checked_command,
            "command_type": CommandType.RECORD_R1_DECISION.value,
            "evidence_manifest_hash": checked_manifest,
            "expected_revision": expected,
            "parameter_id": checked_parameter,
            "reason": checked_reason,
            "reviewer_id": checked_reviewer,
            "task_id": checked_task,
            "verdict": verdict.value,
        }
        request_hash = canonical_json_sha256(request)
        with closing(self._connect()) as connection, immediate_transaction(connection):
            stored = self._idempotent_receipt(
                connection,
                command_id=checked_command,
                task_id=checked_task,
                command_type=CommandType.RECORD_R1_DECISION,
                request_sha256=request_hash,
            )
            if stored is not None:
                return stored
            task = self._task_row(connection, checked_task)
            self._require_open_and_bound(
                connection,
                task=task,
                reviewer_id=checked_reviewer,
                manifest_hash=checked_manifest,
                expected_revision=expected,
            )
            if (
                connection.execute(
                    "SELECT 1 FROM task_parameters WHERE task_id=? AND parameter_id=?",
                    (checked_task, checked_parameter),
                ).fetchone()
                is None
            ):
                raise ParameterNotFoundError(
                    f"unknown parameter {checked_parameter} for task {checked_task}"
                )
            now = _timestamp(self._clock())
            _require_non_decreasing_task_time(
                connection, task_id=checked_task, candidate=now
            )
            row = connection.execute(
                "SELECT COALESCE(MAX(decision_revision), 0) + 1 "
                "FROM r1_decisions WHERE task_id=? AND parameter_id=?",
                (checked_task, checked_parameter),
            ).fetchone()
            decision_revision = int(row[0])
            next_revision = expected + 1
            connection.execute(
                "INSERT INTO r1_decisions("
                "task_id, parameter_id, decision_revision, task_revision, verdict, "
                "reason, reviewer_id, evidence_manifest_hash, decided_at, command_id"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    checked_task,
                    checked_parameter,
                    decision_revision,
                    next_revision,
                    verdict.value,
                    checked_reason,
                    checked_reviewer,
                    checked_manifest,
                    now,
                    checked_command,
                ),
            )
            self._fault("decision.after_insert")
            changed = connection.execute(
                "UPDATE tasks SET revision=? "
                "WHERE task_id=? AND revision=? AND state='HUMAN_REVIEW_OPEN'",
                (next_revision, checked_task, expected),
            ).rowcount
            if changed != 1:
                raise RevisionConflictError("R1 decision lost its SQL CAS")
            self._fault("decision.after_cas")
            missing_count = self._missing_count(connection, checked_task)
            response: dict[str, JsonValue] = {
                "command_id": checked_command,
                "command_type": CommandType.RECORD_R1_DECISION.value,
                "committed_at": now,
                "decision_revision": decision_revision,
                "evidence_manifest_hash": checked_manifest,
                "missing_count": missing_count,
                "parameter_id": checked_parameter,
                "state": "HUMAN_REVIEW_OPEN",
                "task_id": checked_task,
                "task_revision": next_revision,
                "verdict": verdict.value,
            }
            receipt = self._insert_receipt(
                connection,
                command_id=checked_command,
                task_id=checked_task,
                command_type=CommandType.RECORD_R1_DECISION,
                request_sha256=request_hash,
                response=response,
                task_revision=next_revision,
                committed_at=now,
            )
            self._insert_outbox(
                connection,
                task_id=checked_task,
                revision=next_revision,
                event_type="R1_DECISION_RECORDED",
                command_id=checked_command,
                payload=response,
                created_at=now,
            )
            self._fault("decision.after_outbox")
            self._fault("decision.before_commit")
            return receipt

    def lock_r1(
        self,
        *,
        task_id: str,
        reviewer_id: str,
        evidence_manifest_hash: str,
        command_id: str,
        expected_revision: int,
    ) -> CommandReceipt:
        checked_task = _identifier("task_id", task_id)
        checked_reviewer = _identifier("reviewer_id", reviewer_id)
        checked_manifest = _sha256("evidence_manifest_hash", evidence_manifest_hash)
        checked_command = _identifier("command_id", command_id)
        expected = _exact_revision(expected_revision)
        request: dict[str, JsonValue] = {
            "command_id": checked_command,
            "command_type": CommandType.LOCK_R1.value,
            "evidence_manifest_hash": checked_manifest,
            "expected_revision": expected,
            "reviewer_id": checked_reviewer,
            "task_id": checked_task,
        }
        request_hash = canonical_json_sha256(request)
        with closing(self._connect()) as connection, immediate_transaction(connection):
            stored = self._idempotent_receipt(
                connection,
                command_id=checked_command,
                task_id=checked_task,
                command_type=CommandType.LOCK_R1,
                request_sha256=request_hash,
            )
            if stored is not None:
                return stored
            task = self._task_row(connection, checked_task)
            self._require_open_and_bound(
                connection,
                task=task,
                reviewer_id=checked_reviewer,
                manifest_hash=checked_manifest,
                expected_revision=expected,
            )
            decision_rows = self._latest_decision_rows(connection, checked_task)
            missing = tuple(
                str(row["parameter_id"])
                for row in decision_rows
                if row["decision_revision"] is None
            )
            if missing:
                raise R1IncompleteError(missing)
            if any(
                row["reviewer_id"] != checked_reviewer
                or row["evidence_manifest_hash"] != checked_manifest
                for row in decision_rows
            ):
                raise StoredDataIntegrityError(
                    "latest R1 snapshot is not wholly bound to reviewer and manifest"
                )
            snapshot: dict[str, JsonValue] = {
                "evidence_manifest_hash": checked_manifest,
                "reviewer_id": checked_reviewer,
                "task_id": checked_task,
                "decisions": [
                    {
                        "decision_revision": int(row["decision_revision"]),
                        "decided_at": str(row["decided_at"]),
                        "parameter_id": str(row["parameter_id"]),
                        "reason": row["reason"],
                        "task_revision": int(row["task_revision"]),
                        "verdict": str(row["verdict"]),
                    }
                    for row in decision_rows
                ],
            }
            snapshot_hash = canonical_json_sha256(snapshot)
            next_revision = expected + 1
            now = _timestamp(self._clock())
            _require_non_decreasing_task_time(
                connection, task_id=checked_task, candidate=now
            )
            connection.execute(
                "INSERT INTO r1_locks("
                "task_id, task_revision, decision_count, snapshot_sha256, "
                "evidence_manifest_hash, reviewer_id, locked_at, command_id"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    checked_task,
                    next_revision,
                    len(decision_rows),
                    snapshot_hash,
                    checked_manifest,
                    checked_reviewer,
                    now,
                    checked_command,
                ),
            )
            self._fault("lock.after_lock")
            changed = connection.execute(
                "UPDATE tasks SET state='HUMAN_REVIEW_LOCKED', revision=?, r1_locked_at=? "
                "WHERE task_id=? AND revision=? AND state='HUMAN_REVIEW_OPEN'",
                (next_revision, now, checked_task, expected),
            ).rowcount
            if changed != 1:
                raise RevisionConflictError("R1 lock lost its SQL CAS")
            self._fault("lock.after_cas")
            response: dict[str, JsonValue] = {
                "command_id": checked_command,
                "command_type": CommandType.LOCK_R1.value,
                "committed_at": now,
                "evidence_manifest_hash": checked_manifest,
                "locked_at": now,
                "missing_count": 0,
                "snapshot_sha256": snapshot_hash,
                "state": "HUMAN_REVIEW_LOCKED",
                "task_id": checked_task,
                "task_revision": next_revision,
            }
            receipt = self._insert_receipt(
                connection,
                command_id=checked_command,
                task_id=checked_task,
                command_type=CommandType.LOCK_R1,
                request_sha256=request_hash,
                response=response,
                task_revision=next_revision,
                committed_at=now,
            )
            self._insert_outbox(
                connection,
                task_id=checked_task,
                revision=next_revision,
                event_type="R1_LOCKED",
                command_id=checked_command,
                payload=response,
                created_at=now,
            )
            self._fault("lock.after_outbox")
            self._fault("lock.before_commit")
            return receipt

    def get_task(self, task_id: str) -> TaskSnapshot:
        checked_task = _identifier("task_id", task_id)
        with closing(self._connect()) as connection:
            task = self._task_row(connection, checked_task)
            assignment = connection.execute(
                "SELECT actor_id FROM task_assignments WHERE task_id=? AND phase='R1'",
                (checked_task,),
            ).fetchone()
            if assignment is None:
                raise StoredDataIntegrityError("R1 assignment is missing")
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM task_parameters WHERE task_id=?",
                    (checked_task,),
                ).fetchone()[0]
            )
            return TaskSnapshot(
                task_id=checked_task,
                state=str(task["state"]),
                revision=int(task["revision"]),
                evidence_manifest_hash=str(task["evidence_manifest_hash"]),
                pipeline_spec_hash=str(task["pipeline_spec_hash"]),
                reviewer_id=str(assignment["actor_id"]),
                parameter_count=count,
                registered_at=str(task["registered_at"]),
                r1_locked_at=(
                    None if task["r1_locked_at"] is None else str(task["r1_locked_at"])
                ),
            )

    def list_parameters(
        self,
        task_id: str,
        *,
        after_ordinal: int = -1,
        limit: int = 100,
    ) -> ParameterPage:
        checked_task = _identifier("task_id", task_id)
        after, checked_limit = _page_arguments(after_ordinal, limit)
        with closing(self._connect()) as connection:
            self._task_row(connection, checked_task)
            rows = connection.execute(
                "SELECT ordinal, parameter_id FROM task_parameters "
                "WHERE task_id=? AND ordinal>? ORDER BY ordinal LIMIT ?",
                (checked_task, after, checked_limit + 1),
            ).fetchall()
        has_more = len(rows) > checked_limit
        selected = rows[:checked_limit]
        items = tuple(
            ParameterRecord(
                ordinal=int(row["ordinal"]), parameter_id=row["parameter_id"]
            )
            for row in selected
        )
        return ParameterPage(
            items=items,
            next_after_ordinal=(items[-1].ordinal if has_more and items else None),
        )

    def list_current_r1_decisions(
        self,
        task_id: str,
        *,
        after_ordinal: int = -1,
        limit: int = 100,
    ) -> R1DecisionPage:
        checked_task = _identifier("task_id", task_id)
        after, checked_limit = _page_arguments(after_ordinal, limit)
        with closing(self._connect()) as connection:
            self._task_row(connection, checked_task)
            rows = connection.execute(
                "SELECT p.ordinal, p.parameter_id, d.decision_revision, "
                "d.task_revision, d.verdict, d.reason, d.reviewer_id, "
                "d.evidence_manifest_hash, d.decided_at, d.command_id "
                "FROM task_parameters p JOIN r1_decisions d "
                "ON d.task_id=p.task_id AND d.parameter_id=p.parameter_id "
                "AND d.decision_revision=("
                "SELECT MAX(d2.decision_revision) FROM r1_decisions d2 "
                "WHERE d2.task_id=p.task_id AND d2.parameter_id=p.parameter_id"
                ") WHERE p.task_id=? AND p.ordinal>? "
                "ORDER BY p.ordinal LIMIT ?",
                (checked_task, after, checked_limit + 1),
            ).fetchall()
        has_more = len(rows) > checked_limit
        selected = rows[:checked_limit]
        items = tuple(self._decision_record(row) for row in selected)
        return R1DecisionPage(
            items=items,
            next_after_ordinal=(items[-1].ordinal if has_more and items else None),
        )

    def get_command_receipt(self, command_id: str) -> CommandReceipt | None:
        checked_command = _identifier("command_id", command_id)
        with closing(self._connect()) as connection, consistent_read_transaction(
            connection
        ):
            row = connection.execute(
                "SELECT * FROM command_receipts WHERE command_id=?",
                (checked_command,),
            ).fetchone()
            if row is None:
                return None
            receipt = self._receipt_from_row(row)
            self._verify_retry_request(connection, receipt)
            return receipt

    @staticmethod
    def _task_row(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if row is None:
            raise TaskNotFoundError(f"unknown task: {task_id}")
        return row

    @staticmethod
    def _missing_count(connection: sqlite3.Connection, task_id: str) -> int:
        return int(
            connection.execute(
                "SELECT COUNT(*) FROM task_parameters p WHERE p.task_id=? "
                "AND NOT EXISTS (SELECT 1 FROM r1_decisions d "
                "WHERE d.task_id=p.task_id AND d.parameter_id=p.parameter_id)",
                (task_id,),
            ).fetchone()[0]
        )

    @staticmethod
    def _latest_decision_rows(
        connection: sqlite3.Connection, task_id: str
    ) -> tuple[sqlite3.Row, ...]:
        return tuple(
            connection.execute(
                "SELECT p.ordinal, p.parameter_id, d.decision_revision, "
                "d.task_revision, d.verdict, d.reason, d.reviewer_id, "
                "d.evidence_manifest_hash, d.decided_at, d.command_id "
                "FROM task_parameters p LEFT JOIN r1_decisions d "
                "ON d.task_id=p.task_id AND d.parameter_id=p.parameter_id "
                "AND d.decision_revision=("
                "SELECT MAX(d2.decision_revision) FROM r1_decisions d2 "
                "WHERE d2.task_id=p.task_id AND d2.parameter_id=p.parameter_id"
                ") WHERE p.task_id=? ORDER BY p.ordinal",
                (task_id,),
            ).fetchall()
        )

    @staticmethod
    def _require_open_and_bound(
        connection: sqlite3.Connection,
        *,
        task: sqlite3.Row,
        reviewer_id: str,
        manifest_hash: str,
        expected_revision: int,
    ) -> None:
        if task["state"] != "HUMAN_REVIEW_OPEN":
            raise R1LockedError("R1 is already locked")
        if int(task["revision"]) != expected_revision:
            raise RevisionConflictError(
                f"expected revision {expected_revision}, current revision {task['revision']}"
            )
        if task["evidence_manifest_hash"] != manifest_hash:
            raise StoredDataIntegrityError(
                "command evidence manifest does not match frozen task manifest"
            )
        assignment = connection.execute(
            "SELECT actor_id, actor_role FROM task_assignments "
            "WHERE task_id=? AND phase='R1'",
            (task["task_id"],),
        ).fetchone()
        if (
            assignment is None
            or assignment["actor_id"] != reviewer_id
            or assignment["actor_role"] != "R1_REVIEWER"
        ):
            raise StoredDataIntegrityError(
                "R1 command actor does not match the server-held assignment"
            )

    def _idempotent_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        command_id: str,
        task_id: str,
        command_type: CommandType,
        request_sha256: str,
    ) -> CommandReceipt | None:
        row = connection.execute(
            "SELECT * FROM command_receipts WHERE command_id=?", (command_id,)
        ).fetchone()
        if row is None:
            return None
        if (
            row["task_id"] != task_id
            or row["command_type"] != command_type.value
            or row["request_sha256"] != request_sha256
        ):
            raise CommandConflictError(
                "command_id was already committed with a different exact request"
            )
        receipt = self._receipt_from_row(row)
        self._verify_retry_request(connection, receipt)
        return receipt

    def _verify_retry_request(
        self, connection: sqlite3.Connection, receipt: CommandReceipt
    ) -> None:
        """Bind a retry/readback to its command, response and outbox row.

        The caller holds a transaction (IMMEDIATE for retry, read snapshot for
        readback). Historical decisions and completeness use the committed
        revision, not current state. Full history replay is a separate check.
        """

        outbox_rows = connection.execute(
            "SELECT * FROM audit_outbox WHERE command_id=?", (receipt.command_id,)
        ).fetchall()
        if len(outbox_rows) != 1:
            raise StoredDataIntegrityError(
                "every command receipt must have exactly one P1 outbox row"
            )
        self._verify_outbox_row(outbox_rows[0], receipt)
        task = self._task_row(connection, receipt.task_id)
        assignment = connection.execute(
            "SELECT actor_id, actor_role FROM task_assignments "
            "WHERE task_id=? AND phase='R1'",
            (receipt.task_id,),
        ).fetchone()
        if (
            assignment is None
            or assignment["actor_role"] != "R1_REVIEWER"
            or task["workflow_mode"] != WorkflowMode.STRICT_SEQUENTIAL.value
            or task["data_classification"] != DataClassification.SYNTHETIC.value
        ):
            raise StoredDataIntegrityError("retry task or assignment is invalid")
        reviewer_id = str(assignment["actor_id"])
        request: dict[str, JsonValue] = {
            "command_id": receipt.command_id,
            "command_type": receipt.command_type.value,
            "reviewer_id": reviewer_id,
            "task_id": receipt.task_id,
        }
        if receipt.command_type is CommandType.REGISTER_TASK:
            manifest = _manifest_from_stored_json(task["evidence_manifest_json"])
            pipeline = _pipeline_from_stored_json(task["pipeline_spec_json"])
            request.update(
                data_classification=DataClassification.SYNTHETIC.value,
                evidence_manifest=manifest.to_record(),
                pipeline_spec=pipeline.to_record(),
            )
            if (
                receipt.task_revision != 0
                or receipt.committed_at != task["registered_at"]
                or manifest.manifest_hash != task["evidence_manifest_hash"]
                or pipeline.spec_hash != task["pipeline_spec_hash"]
                or receipt.response.get("evidence_manifest_hash")
                != manifest.manifest_hash
                or receipt.response.get("missing_count")
                != len(manifest.expected_parameter_ids)
                or receipt.response.get("state") != "HUMAN_REVIEW_OPEN"
            ):
                raise StoredDataIntegrityError("retry registration binding is invalid")
        elif receipt.command_type is CommandType.RECORD_R1_DECISION:
            decision = connection.execute(
                "SELECT * FROM r1_decisions WHERE command_id=?", (receipt.command_id,)
            ).fetchone()
            if (
                decision is None
                or decision["task_id"] != receipt.task_id
                or decision["task_revision"] != receipt.task_revision
                or decision["reviewer_id"] != reviewer_id
                or decision["evidence_manifest_hash"] != task["evidence_manifest_hash"]
                or decision["decided_at"] != receipt.committed_at
            ):
                raise StoredDataIntegrityError("retry decision row binding is invalid")
            request.update(
                evidence_manifest_hash=task["evidence_manifest_hash"],
                expected_revision=int(decision["task_revision"]) - 1,
                parameter_id=decision["parameter_id"],
                reason=decision["reason"],
                verdict=decision["verdict"],
            )
            self._verify_decision_response(
                receipt, decision, str(task["evidence_manifest_hash"])
            )
            # Count only fields decided by this command's historical revision.
            # A later revision or lock must not change an earlier receipt.
            expected_missing = connection.execute(
                "SELECT COUNT(*) FROM task_parameters p WHERE p.task_id=? "
                "AND NOT EXISTS (SELECT 1 FROM r1_decisions d "
                "WHERE d.task_id=p.task_id AND d.parameter_id=p.parameter_id "
                "AND d.task_revision<=?)",
                (receipt.task_id, receipt.task_revision),
            ).fetchone()[0]
            if receipt.response.get("missing_count") != expected_missing:
                raise StoredDataIntegrityError(
                    "R1 decision receipt does not match historical task completeness"
                )
        else:
            lock = connection.execute(
                "SELECT * FROM r1_locks WHERE command_id=?", (receipt.command_id,)
            ).fetchone()
            if lock is None or lock["task_id"] != receipt.task_id:
                raise StoredDataIntegrityError("retry lock row binding is invalid")
            self._verify_lock_semantics(
                connection,
                task=task,
                lock=lock,
                manifest=_manifest_from_stored_json(task["evidence_manifest_json"]),
                reviewer_id=reviewer_id,
                receipts={receipt.command_id: receipt},
            )
            return
        if canonical_json_sha256(request) != receipt.request_sha256:
            raise StoredDataIntegrityError(
                "retry request hash does not match its committed domain command"
            )

    @staticmethod
    def _insert_receipt(
        connection: sqlite3.Connection,
        *,
        command_id: str,
        task_id: str,
        command_type: CommandType,
        request_sha256: str,
        response: dict[str, JsonValue],
        task_revision: int,
        committed_at: str,
    ) -> CommandReceipt:
        response_json = canonical_json_text(
            response,
            allowed_keys=_RECEIPT_KEYS_BY_VALUE[command_type.value],
            required_keys=_RECEIPT_KEYS_BY_VALUE[command_type.value],
        )
        response_hash = canonical_json_sha256(
            response,
            allowed_keys=_RECEIPT_KEYS_BY_VALUE[command_type.value],
            required_keys=_RECEIPT_KEYS_BY_VALUE[command_type.value],
        )
        connection.execute(
            "INSERT INTO command_receipts("
            "command_id, task_id, command_type, request_sha256, response_json, "
            "response_sha256, task_revision, committed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                command_id,
                task_id,
                command_type.value,
                request_sha256,
                response_json,
                response_hash,
                task_revision,
                committed_at,
            ),
        )
        return CommandReceipt(
            command_id=command_id,
            task_id=task_id,
            command_type=command_type,
            request_sha256=request_sha256,
            response_json=response_json,
            response_sha256=response_hash,
            task_revision=task_revision,
            committed_at=committed_at,
        )

    @staticmethod
    def _insert_outbox(
        connection: sqlite3.Connection,
        *,
        task_id: str,
        revision: int,
        event_type: str,
        command_id: str,
        payload: dict[str, JsonValue],
        created_at: str,
    ) -> None:
        payload_json = canonical_json_text(payload)
        payload_hash = canonical_json_sha256(payload)
        connection.execute(
            "INSERT INTO audit_outbox("
            "task_id, aggregate_revision, event_type, command_id, payload_json, "
            "payload_sha256, created_at, published_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
            (
                task_id,
                revision,
                event_type,
                command_id,
                payload_json,
                payload_hash,
                created_at,
            ),
        )

    @staticmethod
    def _receipt_from_row(row: sqlite3.Row) -> CommandReceipt:
        try:
            command_type = CommandType(str(row["command_type"]))
        except ValueError as error:
            raise StoredDataIntegrityError("stored command type is invalid") from error
        response_json = str(row["response_json"])
        expected_keys = _RECEIPT_KEYS_BY_VALUE[command_type.value]
        parsed = load_json_strict(
            response_json,
            allowed_keys=expected_keys,
            required_keys=expected_keys,
        )
        actual_hash = canonical_json_sha256(parsed)
        if response_json != canonical_json_text(parsed):
            raise StoredDataIntegrityError("stored receipt JSON is not canonical")
        if actual_hash != row["response_sha256"]:
            raise StoredDataIntegrityError("stored receipt hash is invalid")
        if type(parsed) is not dict:
            raise StoredDataIntegrityError("stored receipt response is not an object")
        _validate_receipt_response_types(command_type, parsed)
        receipt = CommandReceipt(
            command_id=str(row["command_id"]),
            task_id=str(row["task_id"]),
            command_type=command_type,
            request_sha256=_sha256("request_sha256", str(row["request_sha256"])),
            response_json=response_json,
            response_sha256=_sha256("response_sha256", str(row["response_sha256"])),
            task_revision=int(row["task_revision"]),
            committed_at=str(row["committed_at"]),
        )
        if (
            parsed.get("command_id") != receipt.command_id
            or parsed.get("command_type") != receipt.command_type.value
            or parsed.get("task_id") != receipt.task_id
            or parsed.get("task_revision") != receipt.task_revision
            or parsed.get("committed_at") != receipt.committed_at
        ):
            raise StoredDataIntegrityError(
                "stored receipt columns and canonical response disagree"
            )
        return receipt

    @staticmethod
    def _decision_record(row: sqlite3.Row) -> R1DecisionRecord:
        try:
            verdict = HumanVerdict(str(row["verdict"]))
        except ValueError as error:
            raise StoredDataIntegrityError("stored R1 verdict is invalid") from error
        return R1DecisionRecord(
            ordinal=int(row["ordinal"]),
            parameter_id=str(row["parameter_id"]),
            decision_revision=int(row["decision_revision"]),
            task_revision=int(row["task_revision"]),
            verdict=verdict,
            reason=None if row["reason"] is None else str(row["reason"]),
            reviewer_id=str(row["reviewer_id"]),
            evidence_manifest_hash=str(row["evidence_manifest_hash"]),
            decided_at=str(row["decided_at"]),
            command_id=str(row["command_id"]),
        )
