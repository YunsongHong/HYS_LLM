from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from paramguard.canonical_json import canonical_json_sha256, canonical_json_text
from paramguard.db import (
    DatabaseIntegrityError,
    SQLiteConfigurationError,
    connect_database,
    consistent_read_transaction,
    immediate_transaction,
    verify_database_integrity,
    wal_reset_fix_present,
)
from paramguard.evidence import (
    EvidenceArtifact,
    EvidenceManifest,
    EvidenceRole,
    content_sha256,
)
from paramguard.pipeline import PipelineSpec
from paramguard.sqlite_repository import (
    CommandConflictError,
    DataClassification,
    ParameterNotFoundError,
    R1IncompleteError,
    R1LockedError,
    R1ReasonRequiredError,
    RevisionConflictError,
    SQLiteR1Repository,
    StoredDataIntegrityError,
    SyntheticEvidenceRequiredError,
)
from paramguard.workflow import HumanVerdict


class AdvancingClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 8, 26, 1, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        result = self.current
        self.current += timedelta(microseconds=1)
        return result


def make_manifest(
    parameter_ids: tuple[str, ...] = ("temperature", "pressure"),
) -> EvidenceManifest:
    return EvidenceManifest(
        manifest_id="synthetic-manifest-001",
        schema_id="synthetic-schema",
        schema_version="1.0",
        schema_sha256=content_sha256(b"synthetic-schema"),
        template_id="synthetic-template",
        template_version="1.0",
        template_sha256=content_sha256(b"synthetic-template"),
        expected_parameter_ids=parameter_ids,
        artifacts=(
            EvidenceArtifact.from_bytes(
                artifact_id="synthetic-left",
                role=EvidenceRole.LEFT_PHOTO,
                content=b"synthetic-left-image",
                media_type="image/png",
            ),
            EvidenceArtifact.from_bytes(
                artifact_id="synthetic-right",
                role=EvidenceRole.RIGHT_SCREENSHOT,
                content=b"synthetic-right-image",
                media_type="image/png",
            ),
        ),
    )


def make_pipeline() -> PipelineSpec:
    return PipelineSpec(
        spec_id="synthetic-pipeline",
        engine_name="synthetic-ocr",
        engine_version="1.0",
        pipeline_version="1.0",
        comparator_version="1.0",
        configuration_sha256=content_sha256(b"synthetic-config"),
    )


@contextmanager
def temporarily_disable_triggers(connection: sqlite3.Connection, *trigger_names: str):
    """Permit a forged row while preserving the trigger-integrity contract."""

    statements: list[str] = []
    for name in trigger_names:
        row = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?", (name,)
        ).fetchone()
        if row is None or type(row[0]) is not str:
            raise AssertionError(f"required test trigger is unavailable: {name}")
        statements.append(row[0])
        connection.execute(f'DROP TRIGGER "{name}"')
    try:
        yield
    finally:
        for statement in statements:
            connection.execute(statement)


class SQLiteRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "paramguard.db"
        self.clock = AdvancingClock()
        self.repository = SQLiteR1Repository(self.path, clock=self.clock)
        self.manifest = make_manifest()
        self.pipeline = make_pipeline()

    def test_startup_and_integrity_do_not_mix_two_invalid_committed_states(
        self,
    ) -> None:
        modes = ["DELETE"]
        if wal_reset_fix_present(sqlite3.sqlite_version_info):
            modes.append("WAL")
        for mode in modes:
            for entrypoint in ("startup", "explicit"):
                with self.subTest(mode=mode, entrypoint=entrypoint):
                    path = (
                        Path(self.temporary.name) / f"snapshot-{mode}-{entrypoint}.db"
                    )
                    repository = SQLiteR1Repository(
                        path, journal_mode=mode, clock=self.clock
                    )
                    repository.register_task(
                        task_id="TASK-SNAPSHOT",
                        evidence_manifest=self.manifest,
                        pipeline_spec=self.pipeline,
                        reviewer_id="reviewer-001",
                        command_id="register-snapshot",
                        data_classification=DataClassification.SYNTHETIC,
                    )
                    with closing(
                        connect_database(path, journal_mode=mode)
                    ) as connection:
                        with temporarily_disable_triggers(
                            connection, "task_assignments_no_update"
                        ):
                            connection.execute(
                                "UPDATE task_assignments SET actor_id='wrong-synthetic-reviewer'"
                            )
                        self.assertEqual(
                            verify_database_integrity(connection).user_version, 2
                        )
                        with consistent_read_transaction(connection):
                            with self.assertRaisesRegex(
                                StoredDataIntegrityError, "registration row and receipt"
                            ):
                                repository._verify_semantics(connection)

                    reader_transactions: list[bool] = []
                    writer_committed = False

                    def verify_then_atomic_swap(reader):
                        nonlocal writer_committed
                        health = verify_database_integrity(reader)
                        reader_transactions.append(reader.in_transaction)
                        try:
                            with closing(
                                connect_database(
                                    path, journal_mode=mode, busy_timeout_ms=30
                                )
                            ) as writer:
                                with immediate_transaction(writer):
                                    with temporarily_disable_triggers(
                                        writer, "task_assignments_no_update"
                                    ):
                                        writer.execute(
                                            "UPDATE task_assignments SET actor_id='reviewer-001'"
                                        )
                                    writer.execute(
                                        "CREATE TABLE unapproved_snapshot_marker(note TEXT) STRICT"
                                    )
                            writer_committed = True
                        except sqlite3.OperationalError as error:
                            self.assertIn("locked", str(error).lower())
                        return health

                    with patch(
                        "paramguard.sqlite_repository.verify_database_integrity",
                        side_effect=verify_then_atomic_swap,
                    ):
                        with self.assertRaisesRegex(
                            StoredDataIntegrityError, "registration row and receipt"
                        ):
                            if entrypoint == "startup":
                                SQLiteR1Repository(
                                    path, journal_mode=mode, clock=self.clock
                                )
                            else:
                                repository.verify_integrity()
                    self.assertEqual(reader_transactions, [True])
                    self.assertEqual(writer_committed, mode == "WAL")
                    with closing(
                        connect_database(path, journal_mode=mode)
                    ) as connection:
                        if writer_committed:
                            with self.assertRaisesRegex(
                                DatabaseIntegrityError, "table definition drift"
                            ):
                                verify_database_integrity(connection)
                            with consistent_read_transaction(connection):
                                repository._verify_semantics(connection)
                        else:
                            self.assertEqual(
                                verify_database_integrity(connection).user_version, 2
                            )
                            with consistent_read_transaction(connection):
                                with self.assertRaisesRegex(
                                    StoredDataIntegrityError,
                                    "registration row and receipt",
                                ):
                                    repository._verify_semantics(connection)

    def test_integrity_accepts_one_valid_snapshot_during_a_legal_concurrent_write(
        self,
    ) -> None:
        modes = ["DELETE"]
        if wal_reset_fix_present(sqlite3.sqlite_version_info):
            modes.append("WAL")
        for mode in modes:
            with self.subTest(mode=mode):
                path = Path(self.temporary.name) / f"valid-snapshot-{mode}.db"
                repository = SQLiteR1Repository(
                    path, journal_mode=mode, busy_timeout_ms=30, clock=self.clock
                )
                repository.register_task(
                    task_id="TASK-VALID-SNAPSHOT",
                    evidence_manifest=self.manifest,
                    pipeline_spec=self.pipeline,
                    reviewer_id="reviewer-001",
                    command_id="register-valid-snapshot",
                    data_classification=DataClassification.SYNTHETIC,
                )

                def record_decision():
                    return repository.record_r1_decision(
                        task_id="TASK-VALID-SNAPSHOT",
                        parameter_id="temperature",
                        verdict=HumanVerdict.SAME,
                        reviewer_id="reviewer-001",
                        evidence_manifest_hash=self.manifest.manifest_hash,
                        reason=None,
                        command_id="valid-concurrent-decision",
                        expected_revision=0,
                    )

                writer_committed = False
                reader_revisions: list[int] = []

                def verify_then_record(reader):
                    nonlocal writer_committed
                    health = verify_database_integrity(reader)
                    self.assertTrue(reader.in_transaction)
                    try:
                        self.assertEqual(record_decision().task_revision, 1)
                        writer_committed = True
                    except sqlite3.OperationalError as error:
                        self.assertIn("locked", str(error).lower())
                    reader_revisions.append(
                        reader.execute("SELECT revision FROM tasks").fetchone()[0]
                    )
                    return health

                with patch(
                    "paramguard.sqlite_repository.verify_database_integrity",
                    side_effect=verify_then_record,
                ):
                    self.assertEqual(repository.verify_integrity().user_version, 2)
                self.assertEqual(reader_revisions, [0])
                self.assertEqual(writer_committed, mode == "WAL")
                if not writer_committed:
                    self.assertEqual(
                        repository.get_task("TASK-VALID-SNAPSHOT").revision, 0
                    )
                    self.assertEqual(record_decision().task_revision, 1)
                self.assertEqual(repository.get_task("TASK-VALID-SNAPSHOT").revision, 1)
                self.assertEqual(repository.verify_integrity().user_version, 2)

    def register(self, *, command_id: str = "register-001"):
        return self.repository.register_task(
            task_id="TASK-001",
            evidence_manifest=self.manifest,
            pipeline_spec=self.pipeline,
            reviewer_id="reviewer-001",
            command_id=command_id,
            data_classification=DataClassification.SYNTHETIC,
        )

    def test_integrity_rejects_connection_shadow_before_semantic_replay(self) -> None:
        self.register()
        with closing(connect_database(self.path)) as connection:
            with temporarily_disable_triggers(connection, "task_assignments_no_update"):
                connection.execute(
                    "UPDATE main.task_assignments SET actor_id='wrong-synthetic-reviewer'"
                )
            with self.assertRaisesRegex(
                StoredDataIntegrityError, "registration row and receipt"
            ):
                self.repository._verify_semantics(connection)

            statement = connection.execute(
                "SELECT sql FROM main.sqlite_schema WHERE name='task_assignments'"
            ).fetchone()[0]
            # This test deliberately contaminates one connection. The factory
            # does not accept user SQL or carry TEMP state across connections.
            statement = statement.replace(
                "CREATE TABLE task_assignments", "CREATE TEMP TABLE task_assignments", 1
            ).replace(" REFERENCES tasks(task_id)", "", 1)
            connection.execute(statement)
            connection.execute(
                "INSERT INTO temp.task_assignments SELECT * FROM main.task_assignments"
            )
            connection.execute(
                "UPDATE temp.task_assignments SET actor_id='reviewer-001'"
            )
            self.assertEqual(
                connection.execute("SELECT actor_id FROM task_assignments").fetchone()[
                    0
                ],
                "reviewer-001",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT actor_id FROM main.task_assignments"
                ).fetchone()[0],
                "wrong-synthetic-reviewer",
            )
            # Unqualified semantic reads alone cannot distinguish this shadow.
            self.repository._verify_semantics(connection)
            with patch.object(self.repository, "_connect", return_value=connection):
                with patch.object(
                    self.repository,
                    "_verify_semantics",
                    wraps=self.repository._verify_semantics,
                ) as semantic_check:
                    with self.assertRaisesRegex(SQLiteConfigurationError, "schema"):
                        self.repository.verify_integrity()
                    semantic_check.assert_not_called()

        with closing(connect_database(self.path)) as fresh:
            self.assertEqual(verify_database_integrity(fresh).user_version, 2)
            self.assertEqual(
                fresh.execute("SELECT COUNT(*) FROM temp.sqlite_schema").fetchone()[0],
                0,
            )
            with self.assertRaisesRegex(
                StoredDataIntegrityError, "registration row and receipt"
            ):
                self.repository._verify_semantics(fresh)

    def test_startup_and_integrity_reject_persisted_unapproved_view(self) -> None:
        self.register()
        with closing(connect_database(self.path)) as connection:
            connection.execute(
                "CREATE VIEW unapproved_view AS SELECT task_id FROM main.tasks"
            )
        for entrypoint in (
            self.repository.verify_integrity,
            lambda: SQLiteR1Repository(self.path),
        ):
            with self.subTest(entrypoint=entrypoint):
                with self.assertRaisesRegex(
                    DatabaseIntegrityError, "view definition drift"
                ):
                    entrypoint()

    def decide(
        self,
        parameter_id: str,
        verdict: HumanVerdict,
        *,
        expected_revision: int,
        command_id: str,
        reason: str | None = None,
    ):
        return self.repository.record_r1_decision(
            task_id="TASK-001",
            parameter_id=parameter_id,
            verdict=verdict,
            reviewer_id="reviewer-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
            reason=reason,
            command_id=command_id,
            expected_revision=expected_revision,
        )

    def test_registers_frozen_manifest_pipeline_assignment_and_outbox_atomically(
        self,
    ) -> None:
        receipt = self.register()
        snapshot = self.repository.get_task("TASK-001")

        self.assertEqual(receipt.task_revision, 0)
        self.assertEqual(snapshot.evidence_manifest_hash, self.manifest.manifest_hash)
        self.assertEqual(snapshot.pipeline_spec_hash, self.pipeline.spec_hash)
        self.assertEqual(snapshot.reviewer_id, "reviewer-001")
        self.assertEqual(snapshot.parameter_count, 2)
        self.assertEqual(snapshot.state, "HUMAN_REVIEW_OPEN")
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM evidence_artifacts"
                ).fetchone()[0],
                2,
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM audit_outbox").fetchone()[0],
                1,
            )
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table'"
                )
            }
            self.assertFalse(
                {"ai_runs", "targeted_reviews", "qa_decisions", "final_decisions"}
                & tables
            )

    def test_synthetic_classification_is_an_exact_required_capability(self) -> None:
        for classification in ("SYNTHETIC", True, None):
            with self.subTest(classification=classification):
                with self.assertRaises(SyntheticEvidenceRequiredError):
                    self.repository.register_task(
                        task_id="TASK-001",
                        evidence_manifest=self.manifest,
                        pipeline_spec=self.pipeline,
                        reviewer_id="reviewer-001",
                        command_id="register-001",
                        data_classification=classification,  # type: ignore[arg-type]
                    )

    def test_decision_revisions_are_append_only_and_global_revision_uses_cas(
        self,
    ) -> None:
        self.register()
        first = self.decide(
            "temperature",
            HumanVerdict.SAME,
            expected_revision=0,
            command_id="decision-001",
        )
        revised = self.decide(
            "temperature",
            HumanVerdict.DIFFERENT,
            reason="Synthetic values differ on second inspection",
            expected_revision=1,
            command_id="decision-002",
        )

        self.assertEqual(first.response["decision_revision"], 1)
        self.assertEqual(revised.response["decision_revision"], 2)
        self.assertEqual(self.repository.get_task("TASK-001").revision, 2)
        current = self.repository.list_current_r1_decisions("TASK-001")
        self.assertEqual(len(current.items), 1)
        self.assertEqual(current.items[0].decision_revision, 2)
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM r1_decisions").fetchone()[0],
                2,
            )

    def test_non_same_needs_reason_and_unknown_parameter_is_rejected(self) -> None:
        self.register()
        with self.assertRaises(R1ReasonRequiredError):
            self.decide(
                "temperature",
                HumanVerdict.DIFFERENT,
                expected_revision=0,
                command_id="decision-no-reason",
            )
        with self.assertRaises(ParameterNotFoundError):
            self.decide(
                "unknown",
                HumanVerdict.SAME,
                expected_revision=0,
                command_id="decision-unknown",
            )
        self.assertEqual(self.repository.get_task("TASK-001").revision, 0)

    def test_stale_revision_wrong_assignment_and_manifest_fail_closed(self) -> None:
        self.register()
        self.decide(
            "temperature",
            HumanVerdict.SAME,
            expected_revision=0,
            command_id="decision-001",
        )
        with self.assertRaises(RevisionConflictError):
            self.decide(
                "pressure",
                HumanVerdict.SAME,
                expected_revision=0,
                command_id="decision-stale",
            )
        with self.assertRaises(StoredDataIntegrityError):
            self.repository.record_r1_decision(
                task_id="TASK-001",
                parameter_id="pressure",
                verdict=HumanVerdict.SAME,
                reviewer_id="other-reviewer",
                evidence_manifest_hash=self.manifest.manifest_hash,
                reason=None,
                command_id="decision-wrong-actor",
                expected_revision=1,
            )
        with self.assertRaises(StoredDataIntegrityError):
            self.repository.record_r1_decision(
                task_id="TASK-001",
                parameter_id="pressure",
                verdict=HumanVerdict.SAME,
                reviewer_id="reviewer-001",
                evidence_manifest_hash="f" * 64,
                reason=None,
                command_id="decision-wrong-manifest",
                expected_revision=1,
            )

    def test_backwards_clock_is_rejected_without_mutating_task_history(self) -> None:
        self.register()
        self.clock.current = datetime(2025, 8, 26, 1, 0, tzinfo=timezone.utc)

        with self.assertRaisesRegex(ValueError, "clock result moved backwards"):
            self.decide(
                "temperature",
                HumanVerdict.SAME,
                expected_revision=0,
                command_id="decision-backwards",
            )

        self.assertEqual(self.repository.get_task("TASK-001").revision, 0)
        self.assertIsNone(self.repository.get_command_receipt("decision-backwards"))

    def test_lock_requires_exact_complete_latest_snapshot_then_freezes_r1(self) -> None:
        self.register()
        self.decide(
            "temperature",
            HumanVerdict.SAME,
            expected_revision=0,
            command_id="decision-001",
        )
        with self.assertRaises(R1IncompleteError) as context:
            self.repository.lock_r1(
                task_id="TASK-001",
                reviewer_id="reviewer-001",
                evidence_manifest_hash=self.manifest.manifest_hash,
                command_id="lock-incomplete",
                expected_revision=1,
            )
        self.assertEqual(context.exception.missing_parameter_ids, ("pressure",))
        self.decide(
            "pressure",
            HumanVerdict.UNABLE_TO_JUDGE,
            reason="Synthetic image intentionally unreadable",
            expected_revision=1,
            command_id="decision-002",
        )
        receipt = self.repository.lock_r1(
            task_id="TASK-001",
            reviewer_id="reviewer-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
            command_id="lock-001",
            expected_revision=2,
        )
        self.assertEqual(receipt.task_revision, 3)
        self.assertEqual(receipt.response["state"], "HUMAN_REVIEW_LOCKED")
        self.assertEqual(len(receipt.response["snapshot_sha256"]), 64)
        with self.assertRaises(R1LockedError):
            self.decide(
                "pressure",
                HumanVerdict.SAME,
                expected_revision=3,
                command_id="decision-after-lock",
            )

    def test_task_local_lock_revisions_do_not_conflict_across_tasks(self) -> None:
        manifest = make_manifest(("parameter",))
        pipeline = make_pipeline()

        for suffix in ("A", "B"):
            task_id = f"TASK-{suffix}"
            reviewer_id = f"reviewer-{suffix}"
            self.repository.register_task(
                task_id=task_id,
                evidence_manifest=manifest,
                pipeline_spec=pipeline,
                reviewer_id=reviewer_id,
                command_id=f"register-{suffix}",
                data_classification=DataClassification.SYNTHETIC,
            )
            self.repository.record_r1_decision(
                task_id=task_id,
                parameter_id="parameter",
                verdict=HumanVerdict.SAME,
                reviewer_id=reviewer_id,
                evidence_manifest_hash=manifest.manifest_hash,
                reason=None,
                command_id=f"decision-{suffix}",
                expected_revision=0,
            )
            receipt = self.repository.lock_r1(
                task_id=task_id,
                reviewer_id=reviewer_id,
                evidence_manifest_hash=manifest.manifest_hash,
                command_id=f"lock-{suffix}",
                expected_revision=1,
            )
            self.assertEqual(receipt.task_revision, 2)

        with closing(connect_database(self.path)) as connection:
            revisions = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT task_revision FROM r1_locks ORDER BY task_id"
                )
            )
        self.assertEqual(revisions, (2, 2))

    def test_exact_retry_after_repository_restart_returns_identical_receipt(
        self,
    ) -> None:
        first = self.register()

        def clock_must_not_run():
            raise AssertionError(
                "an exact durable retry must not allocate a new timestamp"
            )

        restarted = SQLiteR1Repository(self.path, clock=clock_must_not_run)
        retry = restarted.register_task(
            task_id="TASK-001",
            evidence_manifest=self.manifest,
            pipeline_spec=self.pipeline,
            reviewer_id="reviewer-001",
            command_id="register-001",
            data_classification=DataClassification.SYNTHETIC,
        )

        self.assertEqual(retry, first)
        self.assertEqual(restarted.get_command_receipt("register-001"), first)
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 1
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM audit_outbox").fetchone()[0],
                1,
            )

    def test_command_id_reuse_with_changed_request_is_rejected(self) -> None:
        self.register()
        with self.assertRaises(CommandConflictError):
            self.repository.register_task(
                task_id="TASK-001",
                evidence_manifest=self.manifest,
                pipeline_spec=self.pipeline,
                reviewer_id="different-reviewer",
                command_id="register-001",
                data_classification=DataClassification.SYNTHETIC,
            )

    def test_live_retry_rejects_forged_request_hash_for_each_command(self) -> None:
        registration = self.register()
        decision = self.decide(
            "temperature",
            HumanVerdict.DIFFERENT,
            expected_revision=0,
            command_id="decision-a",
            reason="original synthetic reason",
        )
        self.decide(
            "pressure",
            HumanVerdict.SAME,
            expected_revision=1,
            command_id="decision-b",
        )
        lock_args = dict(
            task_id="TASK-001",
            reviewer_id="reviewer-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
            command_id="lock-001",
            expected_revision=2,
        )
        lock = self.repository.lock_r1(**lock_args)
        registration_request = dict(
            command_id="register-001",
            command_type="REGISTER_TASK",
            data_classification="SYNTHETIC",
            evidence_manifest=self.manifest.to_record(),
            pipeline_spec=self.pipeline.to_record(),
            reviewer_id="forged-reviewer",
            task_id="TASK-001",
        )
        decision_request = dict(
            command_id="decision-a",
            command_type="RECORD_R1_DECISION",
            evidence_manifest_hash=self.manifest.manifest_hash,
            expected_revision=0,
            parameter_id="temperature",
            reason="changed synthetic reason",
            reviewer_id="reviewer-001",
            task_id="TASK-001",
            verdict="DIFFERENT",
        )
        forged_lock_args = dict(lock_args, expected_revision=3)
        cases = (
            (
                registration,
                registration_request,
                lambda: self.repository.register_task(
                    task_id="TASK-001",
                    evidence_manifest=self.manifest,
                    pipeline_spec=self.pipeline,
                    reviewer_id="forged-reviewer",
                    command_id="register-001",
                    data_classification=DataClassification.SYNTHETIC,
                ),
            ),
            (
                decision,
                decision_request,
                lambda: self.decide(
                    "temperature",
                    HumanVerdict.DIFFERENT,
                    expected_revision=0,
                    command_id="decision-a",
                    reason="changed synthetic reason",
                ),
            ),
            (
                lock,
                dict(forged_lock_args, command_type="LOCK_R1"),
                lambda: self.repository.lock_r1(**forged_lock_args),
            ),
        )
        clock_before = self.clock.current
        for receipt, forged_request, retry in cases:
            with self.subTest(command_type=receipt.command_type):
                with closing(connect_database(self.path)) as connection:
                    with temporarily_disable_triggers(
                        connection, "command_receipts_no_update"
                    ):
                        connection.execute(
                            "UPDATE command_receipts SET request_sha256=? WHERE command_id=?",
                            (canonical_json_sha256(forged_request), receipt.command_id),
                        )
                try:
                    with self.assertRaises(StoredDataIntegrityError):
                        retry()
                finally:
                    with closing(connect_database(self.path)) as connection:
                        with temporarily_disable_triggers(
                            connection, "command_receipts_no_update"
                        ):
                            connection.execute(
                                "UPDATE command_receipts SET request_sha256=? WHERE command_id=?",
                                (receipt.request_sha256, receipt.command_id),
                            )
        self.assertEqual(self.clock.current, clock_before)
        self.assertEqual(self.repository.get_task("TASK-001").revision, 3)
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM audit_outbox").fetchone()[0], 4
            )

    def test_live_historical_retries_after_revision_and_lock_do_not_write_or_replay(
        self,
    ) -> None:
        registration = self.register()
        first = self.decide(
            "temperature",
            HumanVerdict.SAME,
            expected_revision=0,
            command_id="decision-first",
        )
        self.decide(
            "temperature",
            HumanVerdict.DIFFERENT,
            expected_revision=1,
            command_id="decision-revised",
            reason="new synthetic observation",
        )
        self.decide(
            "pressure",
            HumanVerdict.SAME,
            expected_revision=2,
            command_id="decision-pressure",
        )
        lock_args = dict(
            task_id="TASK-001",
            reviewer_id="reviewer-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
            command_id="lock-001",
            expected_revision=3,
        )
        lock = self.repository.lock_r1(**lock_args)
        with patch.object(
            self.repository, "_clock", side_effect=AssertionError("retry clock")
        ), patch.object(
            self.repository,
            "_verify_semantics",
            side_effect=AssertionError("full replay"),
        ), patch.object(
            self.repository,
            "_verify_task_semantics",
            side_effect=AssertionError("task replay"),
        ):
            self.assertEqual(self.register(), registration)
            self.assertEqual(
                self.decide(
                    "temperature",
                    HumanVerdict.SAME,
                    expected_revision=0,
                    command_id="decision-first",
                ),
                first,
            )
            self.assertEqual(self.repository.lock_r1(**lock_args), lock)
            for receipt in (registration, first, lock):
                self.assertEqual(
                    self.repository.get_command_receipt(receipt.command_id), receipt
                )
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM audit_outbox").fetchone()[0], 5
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM command_receipts").fetchone()[
                    0
                ],
                5,
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM r1_decisions").fetchone()[0], 3
            )
        self.assertEqual(self.repository.get_task("TASK-001").revision, 4)

    def test_live_retry_rejects_missing_historical_decision(self) -> None:
        self.register()
        self.decide(
            "temperature",
            HumanVerdict.SAME,
            expected_revision=0,
            command_id="decision-001",
        )
        with closing(connect_database(self.path)) as connection:
            with temporarily_disable_triggers(connection, "r1_decisions_no_delete"):
                connection.execute(
                    "DELETE FROM r1_decisions WHERE command_id='decision-001'"
                )
        with self.assertRaisesRegex(StoredDataIntegrityError, "retry decision row"):
            self.decide(
                "temperature",
                HumanVerdict.SAME,
                expected_revision=0,
                command_id="decision-001",
            )

    def test_live_retry_and_readback_reject_self_consistent_response_forgery(
        self,
    ) -> None:
        attacks = (
            ("verdict", "SAME", False),
            ("verdict", "SAME", True),
            ("missing_count", 0, True),
            ("parameter_id", "pressure", True),
            ("decision_revision", 2, True),
            ("evidence_manifest_hash", "f" * 64, True),
            ("state", "HUMAN_REVIEW_LOCKED", True),
        )
        for index, (field, value, mirror) in enumerate(attacks):
            with self.subTest(field=field, mirror=mirror):
                self.path = Path(self.temporary.name) / f"response-{index}.db"
                self.repository = SQLiteR1Repository(self.path, clock=self.clock)
                self.register()
                original = self.decide(
                    "temperature",
                    HumanVerdict.DIFFERENT,
                    expected_revision=0,
                    command_id="decision-001",
                    reason="original synthetic reason",
                )
                forged = original.response
                forged[field] = value
                with closing(connect_database(self.path)) as connection:
                    with temporarily_disable_triggers(
                        connection,
                        "command_receipts_no_update",
                        "audit_outbox_no_update",
                    ):
                        connection.execute(
                            "UPDATE command_receipts SET response_json=?, response_sha256=? "
                            "WHERE command_id='decision-001'",
                            (
                                canonical_json_text(forged),
                                canonical_json_sha256(forged),
                            ),
                        )
                        if mirror:
                            connection.execute(
                                "UPDATE audit_outbox SET payload_json=?, payload_sha256=? "
                                "WHERE command_id='decision-001'",
                                (
                                    canonical_json_text(forged),
                                    canonical_json_sha256(forged),
                                ),
                            )
                clock_before = self.clock.current
                for operation in (
                    lambda: self.decide(
                        "temperature",
                        HumanVerdict.DIFFERENT,
                        expected_revision=0,
                        command_id="decision-001",
                        reason="original synthetic reason",
                    ),
                    lambda: self.repository.get_command_receipt("decision-001"),
                    lambda: SQLiteR1Repository(self.path),
                ):
                    with self.assertRaises(StoredDataIntegrityError):
                        operation()
                self.assertEqual(self.clock.current, clock_before)
                with closing(connect_database(self.path)) as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT verdict FROM r1_decisions WHERE command_id='decision-001'"
                        ).fetchone()[0],
                        "DIFFERENT",
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM audit_outbox"
                        ).fetchone()[0],
                        2,
                    )

    def test_live_retry_and_readback_reject_missing_or_mismatched_outbox(self) -> None:
        attacks = (
            (None, None),
            ("event_type", "R1_LOCKED"),
            ("aggregate_revision", 2),
            ("created_at", "2099-01-01T00:00:00.000000Z"),
            ("published_at", "2099-01-01T00:00:00.000000Z"),
            ("payload_sha256", "f" * 64),
        )
        for index, (field, value) in enumerate(attacks):
            with self.subTest(field=field):
                self.path = Path(self.temporary.name) / f"outbox-{index}.db"
                self.repository = SQLiteR1Repository(self.path, clock=self.clock)
                self.register()
                self.decide(
                    "temperature",
                    HumanVerdict.SAME,
                    expected_revision=0,
                    command_id="decision-001",
                )
                with closing(connect_database(self.path)) as connection:
                    with temporarily_disable_triggers(
                        connection, "audit_outbox_no_update", "audit_outbox_no_delete"
                    ):
                        if field is None:
                            connection.execute(
                                "DELETE FROM audit_outbox WHERE command_id='decision-001'"
                            )
                        else:
                            # Field names above are fixed test constants, not external input.
                            connection.execute(
                                f"UPDATE audit_outbox SET {field}=? WHERE command_id='decision-001'",
                                (value,),
                            )
                for operation in (
                    lambda: self.decide(
                        "temperature",
                        HumanVerdict.SAME,
                        expected_revision=0,
                        command_id="decision-001",
                    ),
                    lambda: self.repository.get_command_receipt("decision-001"),
                    lambda: SQLiteR1Repository(self.path),
                ):
                    with self.assertRaises(StoredDataIntegrityError):
                        operation()

    def test_readback_verifies_cross_table_binding_inside_read_transaction(
        self,
    ) -> None:
        original = self.register()
        verify = self.repository._verify_retry_request
        transaction_states = []

        def observe(connection, receipt):
            transaction_states.append(connection.in_transaction)
            return verify(connection, receipt)

        with patch.object(
            self.repository, "_verify_retry_request", side_effect=observe
        ):
            self.assertEqual(
                self.repository.get_command_receipt("register-001"), original
            )
            self.assertIsNone(self.repository.get_command_receipt("never-committed"))
        self.assertEqual(transaction_states, [True])

    def test_live_registration_and_lock_responses_remain_bound_after_lock(self) -> None:
        registration = self.register()
        for revision, parameter in enumerate(("temperature", "pressure")):
            self.decide(
                parameter,
                HumanVerdict.SAME,
                expected_revision=revision,
                command_id=f"decision-{revision}",
            )
        lock_args = dict(
            task_id="TASK-001",
            reviewer_id="reviewer-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
            command_id="lock-001",
            expected_revision=2,
        )
        lock = self.repository.lock_r1(**lock_args)
        cases = (
            (registration, "missing_count", 0, self.register),
            (registration, "state", "HUMAN_REVIEW_LOCKED", self.register),
            (lock, "missing_count", 1, lambda: self.repository.lock_r1(**lock_args)),
            (
                lock,
                "state",
                "HUMAN_REVIEW_OPEN",
                lambda: self.repository.lock_r1(**lock_args),
            ),
        )

        def replace_response(receipt, response):
            with closing(connect_database(self.path)) as connection:
                with temporarily_disable_triggers(
                    connection, "command_receipts_no_update", "audit_outbox_no_update"
                ):
                    values = (
                        canonical_json_text(response),
                        canonical_json_sha256(response),
                        receipt.command_id,
                    )
                    connection.execute(
                        "UPDATE command_receipts SET response_json=?, response_sha256=? WHERE command_id=?",
                        values,
                    )
                    connection.execute(
                        "UPDATE audit_outbox SET payload_json=?, payload_sha256=? WHERE command_id=?",
                        values,
                    )

        for receipt, field, value, retry in cases:
            with self.subTest(command=receipt.command_type, field=field):
                forged = receipt.response
                forged[field] = value
                replace_response(receipt, forged)
                try:
                    with self.assertRaises(StoredDataIntegrityError):
                        retry()
                    with self.assertRaises(StoredDataIntegrityError):
                        self.repository.get_command_receipt(receipt.command_id)
                finally:
                    replace_response(receipt, receipt.response)

    def test_locked_restart_returns_original_decision_and_lock_receipts(self) -> None:
        self.register()
        decision_a = self.decide(
            "temperature",
            HumanVerdict.SAME,
            expected_revision=0,
            command_id="decision-a",
        )
        self.decide(
            "pressure",
            HumanVerdict.DIFFERENT,
            reason="Synthetic values differ",
            expected_revision=1,
            command_id="decision-b",
        )
        lock = self.repository.lock_r1(
            task_id="TASK-001",
            reviewer_id="reviewer-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
            command_id="lock-001",
            expected_revision=2,
        )

        def clock_must_not_run():
            raise AssertionError("durable retries must use the committed timestamps")

        restarted = SQLiteR1Repository(self.path, clock=clock_must_not_run)
        retried_decision = restarted.record_r1_decision(
            task_id="TASK-001",
            parameter_id="temperature",
            verdict=HumanVerdict.SAME,
            reviewer_id="reviewer-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
            reason=None,
            command_id="decision-a",
            expected_revision=0,
        )
        retried_lock = restarted.lock_r1(
            task_id="TASK-001",
            reviewer_id="reviewer-001",
            evidence_manifest_hash=self.manifest.manifest_hash,
            command_id="lock-001",
            expected_revision=2,
        )
        self.assertEqual(retried_decision, decision_a)
        self.assertEqual(retried_lock, lock)
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM audit_outbox").fetchone()[0],
                4,
            )

    def test_write_once_triggers_reject_update_and_delete(self) -> None:
        self.register()
        with closing(connect_database(self.path)) as connection:
            for sql in (
                "UPDATE task_parameters SET parameter_id='forged' WHERE task_id='TASK-001'",
                "DELETE FROM evidence_artifacts WHERE task_id='TASK-001'",
                "UPDATE command_receipts SET response_json='{}' WHERE command_id='register-001'",
                "DELETE FROM audit_outbox WHERE task_id='TASK-001'",
                "DELETE FROM tasks WHERE task_id='TASK-001'",
            ):
                with self.subTest(sql=sql):
                    with self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(sql)

    def test_restart_rejects_missing_write_once_trigger(self) -> None:
        self.register()
        with closing(connect_database(self.path)) as connection:
            connection.execute("DROP TRIGGER tasks_no_delete")

        with self.assertRaisesRegex(
            DatabaseIntegrityError,
            "required integrity trigger missing: tasks_no_delete",
        ):
            SQLiteR1Repository(self.path)

    def test_restart_semantic_replay_rejects_hash_consistent_cross_row_forgery(
        self,
    ) -> None:
        self.register()
        receipt = self.decide(
            "temperature",
            HumanVerdict.SAME,
            expected_revision=0,
            command_id="decision-001",
        )
        forged = receipt.response
        forged["parameter_id"] = "pressure"
        forged_json = canonical_json_text(forged)
        forged_hash = canonical_json_sha256(forged)
        with closing(connect_database(self.path)) as connection:
            with temporarily_disable_triggers(
                connection,
                "command_receipts_no_update",
                "audit_outbox_no_update",
            ):
                connection.execute(
                    "UPDATE command_receipts SET response_json=?, response_sha256=? "
                    "WHERE command_id='decision-001'",
                    (forged_json, forged_hash),
                )
                connection.execute(
                    "UPDATE audit_outbox SET payload_json=?, payload_sha256=? "
                    "WHERE command_id='decision-001'",
                    (forged_json, forged_hash),
                )

        with self.assertRaisesRegex(StoredDataIntegrityError, "decision row"):
            SQLiteR1Repository(self.path)

    def test_restart_and_integrity_reject_boolean_manifest_version(self) -> None:
        self.register()
        with closing(connect_database(self.path)) as connection:
            original = connection.execute(
                "SELECT evidence_manifest_json FROM tasks WHERE task_id='TASK-001'"
            ).fetchone()[0]
            forged = original.replace('"manifest_version":1', '"manifest_version":true')
            self.assertNotEqual(forged, original)
            with temporarily_disable_triggers(
                connection, "tasks_immutable_fields", "tasks_valid_transition"
            ):
                connection.execute(
                    "UPDATE tasks SET evidence_manifest_json=? WHERE task_id='TASK-001'",
                    (forged,),
                )

        for verify in (
            self.repository.verify_integrity,
            lambda: SQLiteR1Repository(self.path),
        ):
            with self.subTest(verify=verify):
                with self.assertRaisesRegex(StoredDataIntegrityError, "version"):
                    verify()

    def test_restart_rejects_same_name_weakened_trigger(self) -> None:
        self.register()
        with closing(connect_database(self.path)) as connection:
            connection.execute("DROP TRIGGER tasks_no_delete")
            connection.execute(
                "CREATE TRIGGER tasks_no_delete BEFORE DELETE ON tasks "
                "BEGIN SELECT 1; END"
            )
        with self.assertRaisesRegex(DatabaseIntegrityError, "trigger definition drift"):
            SQLiteR1Repository(self.path)

    def test_restart_attests_all_packaged_triggers(self) -> None:
        self.register()
        with closing(connect_database(self.path)) as connection:
            connection.execute("DROP TRIGGER command_receipts_no_update")
        with self.assertRaisesRegex(
            DatabaseIntegrityError,
            "required integrity trigger missing: command_receipts_no_update",
        ):
            SQLiteR1Repository(self.path)

    def test_restart_rejects_unapproved_additional_trigger(self) -> None:
        self.register()
        with closing(connect_database(self.path)) as connection:
            connection.execute(
                "CREATE TRIGGER unexpected_hook BEFORE DELETE ON tasks "
                "BEGIN SELECT 1; END"
            )
        with self.assertRaisesRegex(DatabaseIntegrityError, "trigger definition drift"):
            SQLiteR1Repository(self.path)

    def test_restart_rejects_boolean_missing_count_receipt_forgery(self) -> None:
        self.manifest = make_manifest(("only-field",))
        receipt = self.register()
        forged = receipt.response
        forged["missing_count"] = True
        forged_json = canonical_json_text(forged)
        forged_hash = canonical_json_sha256(forged)
        with closing(connect_database(self.path)) as connection:
            with temporarily_disable_triggers(
                connection,
                "command_receipts_no_update",
                "audit_outbox_no_update",
            ):
                connection.execute(
                    "UPDATE command_receipts SET response_json=?, response_sha256=? "
                    "WHERE command_id='register-001'",
                    (forged_json, forged_hash),
                )
                connection.execute(
                    "UPDATE audit_outbox SET payload_json=?, payload_sha256=? "
                    "WHERE command_id='register-001'",
                    (forged_json, forged_hash),
                )

        with self.assertRaisesRegex(StoredDataIntegrityError, "scalar types"):
            SQLiteR1Repository(self.path)

    def test_restart_rejects_orphan_decision_receipt_and_outbox(self) -> None:
        self.register()
        self.decide(
            "temperature",
            HumanVerdict.SAME,
            expected_revision=0,
            command_id="decision-001",
        )
        with closing(connect_database(self.path)) as connection:
            with temporarily_disable_triggers(connection, "r1_decisions_no_delete"):
                connection.execute(
                    "DELETE FROM r1_decisions WHERE command_id='decision-001'"
                )

        with self.assertRaisesRegex(
            StoredDataIntegrityError,
            "every R1 decision receipt must match exactly one decision row",
        ):
            SQLiteR1Repository(self.path)

    def test_restart_rejects_self_consistent_backwards_receipt_time(self) -> None:
        self.register()
        receipt = self.decide(
            "temperature",
            HumanVerdict.SAME,
            expected_revision=0,
            command_id="decision-001",
        )
        backwards = "2025-08-26T01:00:00.000000Z"
        forged = receipt.response
        forged["committed_at"] = backwards
        forged_json = canonical_json_text(forged)
        forged_hash = canonical_json_sha256(forged)
        with closing(connect_database(self.path)) as connection:
            with temporarily_disable_triggers(
                connection,
                "r1_decisions_no_update",
                "command_receipts_no_update",
                "audit_outbox_no_update",
            ):
                connection.execute(
                    "UPDATE r1_decisions SET decided_at=? WHERE command_id='decision-001'",
                    (backwards,),
                )
                connection.execute(
                    "UPDATE command_receipts SET committed_at=?, response_json=?, "
                    "response_sha256=? WHERE command_id='decision-001'",
                    (backwards, forged_json, forged_hash),
                )
                connection.execute(
                    "UPDATE audit_outbox SET created_at=?, payload_json=?, payload_sha256=? "
                    "WHERE command_id='decision-001'",
                    (backwards, forged_json, forged_hash),
                )

        with self.assertRaisesRegex(StoredDataIntegrityError, "timestamp sequence"):
            SQLiteR1Repository(self.path)

    def test_restart_rejects_request_hash_that_disagrees_with_domain_row(self) -> None:
        self.register()
        self.decide(
            "temperature",
            HumanVerdict.DIFFERENT,
            reason="Original synthetic reason",
            expected_revision=0,
            command_id="decision-001",
        )
        forged_request = {
            "command_id": "decision-001",
            "command_type": "RECORD_R1_DECISION",
            "evidence_manifest_hash": self.manifest.manifest_hash,
            "expected_revision": 0,
            "parameter_id": "temperature",
            "reason": "Forged retry reason",
            "reviewer_id": "reviewer-001",
            "task_id": "TASK-001",
            "verdict": "DIFFERENT",
        }
        with closing(connect_database(self.path)) as connection:
            with temporarily_disable_triggers(connection, "command_receipts_no_update"):
                connection.execute(
                    "UPDATE command_receipts SET request_sha256=? "
                    "WHERE command_id='decision-001'",
                    (canonical_json_sha256(forged_request),),
                )

        with self.assertRaisesRegex(StoredDataIntegrityError, "decision row"):
            SQLiteR1Repository(self.path)

    def test_restart_rejects_self_consistent_noncanonical_reason(self) -> None:
        self.register()
        self.decide(
            "temperature",
            HumanVerdict.DIFFERENT,
            reason="Original synthetic reason",
            expected_revision=0,
            command_id="decision-001",
        )
        forged_reason = "  Original synthetic reason  "
        forged_request = {
            "command_id": "decision-001",
            "command_type": "RECORD_R1_DECISION",
            "evidence_manifest_hash": self.manifest.manifest_hash,
            "expected_revision": 0,
            "parameter_id": "temperature",
            "reason": forged_reason,
            "reviewer_id": "reviewer-001",
            "task_id": "TASK-001",
            "verdict": "DIFFERENT",
        }
        with closing(connect_database(self.path)) as connection:
            with temporarily_disable_triggers(
                connection,
                "r1_decisions_no_update",
                "command_receipts_no_update",
            ):
                connection.execute(
                    "UPDATE r1_decisions SET reason=? WHERE command_id='decision-001'",
                    (forged_reason,),
                )
                connection.execute(
                    "UPDATE command_receipts SET request_sha256=? "
                    "WHERE command_id='decision-001'",
                    (canonical_json_sha256(forged_request),),
                )

        with self.assertRaisesRegex(StoredDataIntegrityError, "canonically normalized"):
            SQLiteR1Repository(self.path)

    def test_restart_rejects_huge_forged_revision_without_range_allocation(
        self,
    ) -> None:
        self.register()
        with closing(connect_database(self.path)) as connection:
            with temporarily_disable_triggers(connection, "tasks_valid_transition"):
                connection.execute(
                    "UPDATE tasks SET revision=? WHERE task_id='TASK-001'",
                    (2**63 - 1,),
                )

        with self.assertRaisesRegex(
            StoredDataIntegrityError,
            "task revisions are not exactly covered",
        ):
            SQLiteR1Repository(self.path)

    def test_restart_rejects_forged_r1_assignment_timestamp(self) -> None:
        self.register()
        with closing(connect_database(self.path)) as connection:
            with temporarily_disable_triggers(connection, "task_assignments_no_update"):
                connection.execute(
                    "UPDATE task_assignments SET assigned_at=? WHERE task_id='TASK-001'",
                    ("2099-01-01T00:00:00.000000Z",),
                )

        with self.assertRaisesRegex(StoredDataIntegrityError, "assignment timestamp"):
            SQLiteR1Repository(self.path)


if __name__ == "__main__":
    unittest.main()
