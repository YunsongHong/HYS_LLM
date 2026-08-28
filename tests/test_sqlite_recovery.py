from __future__ import annotations

from contextlib import closing
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest

from paramguard.db import connect_database
from paramguard.evidence import (
    EvidenceArtifact,
    EvidenceManifest,
    EvidenceRole,
    content_sha256,
)
from paramguard.pipeline import PipelineSpec
from paramguard.sqlite_repository import DataClassification, SQLiteR1Repository
from paramguard.workflow import HumanVerdict


class InjectedFault(RuntimeError):
    pass


def _manifest() -> EvidenceManifest:
    return EvidenceManifest(
        manifest_id="synthetic-recovery-manifest",
        schema_id="synthetic-schema",
        schema_version="1",
        schema_sha256=content_sha256(b"schema"),
        template_id="synthetic-template",
        template_version="1",
        template_sha256=content_sha256(b"template"),
        expected_parameter_ids=("a", "b"),
        artifacts=(
            EvidenceArtifact.from_bytes(
                artifact_id="left",
                role=EvidenceRole.LEFT_PHOTO,
                content=b"synthetic-left",
                media_type="image/png",
            ),
            EvidenceArtifact.from_bytes(
                artifact_id="right",
                role=EvidenceRole.RIGHT_SCREENSHOT,
                content=b"synthetic-right",
                media_type="image/png",
            ),
        ),
    )


def _pipeline() -> PipelineSpec:
    return PipelineSpec(
        spec_id="synthetic-pipeline",
        engine_name="synthetic-ocr",
        engine_version="1",
        pipeline_version="1",
        comparator_version="1",
        configuration_sha256=content_sha256(b"config"),
    )


def _crash_during_update(database_path: str) -> None:
    connection = connect_database(database_path)
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        "INSERT INTO r1_decisions("
        "task_id, parameter_id, decision_revision, task_revision, verdict, reason, "
        "reviewer_id, evidence_manifest_hash, decided_at, command_id"
        ") SELECT task_id, 'a', 1, 1, 'SAME', NULL, 'reviewer-001', "
        "evidence_manifest_hash, '2026-08-26T00:00:00.000000Z', 'crash-command' "
        "FROM tasks WHERE task_id='TASK-RECOVERY'"
    )
    connection.execute("UPDATE tasks SET revision=1 WHERE task_id='TASK-RECOVERY'")
    os._exit(17)


class SQLiteRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "paramguard.db"
        self.manifest = _manifest()
        self.pipeline = _pipeline()

    def _register(
        self, repository: SQLiteR1Repository, command_id: str = "register-001"
    ):
        return repository.register_task(
            task_id="TASK-RECOVERY",
            evidence_manifest=self.manifest,
            pipeline_spec=self.pipeline,
            reviewer_id="reviewer-001",
            command_id=command_id,
            data_classification=DataClassification.SYNTHETIC,
        )

    def test_registration_fault_rolls_back_every_domain_receipt_and_outbox_row(
        self,
    ) -> None:
        def fail(point: str) -> None:
            if point == "register.after_parameters":
                raise InjectedFault(point)

        repository = SQLiteR1Repository(self.path, fault_injector=fail)
        with self.assertRaises(InjectedFault):
            self._register(repository)
        with closing(connect_database(self.path)) as connection:
            for table in (
                "tasks",
                "task_parameters",
                "evidence_artifacts",
                "task_assignments",
                "command_receipts",
                "audit_outbox",
            ):
                with self.subTest(table=table):
                    self.assertEqual(
                        connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[
                            0
                        ],
                        0,
                    )
        recovered = SQLiteR1Repository(self.path)
        receipt = self._register(recovered)
        self.assertEqual(receipt.task_revision, 0)

    def test_decision_fault_after_sql_cas_rolls_back_revision_and_history(self) -> None:
        base = SQLiteR1Repository(self.path)
        self._register(base)

        def fail(point: str) -> None:
            if point == "decision.after_cas":
                raise InjectedFault(point)

        faulty = SQLiteR1Repository(self.path, fault_injector=fail)
        with self.assertRaises(InjectedFault):
            faulty.record_r1_decision(
                task_id="TASK-RECOVERY",
                parameter_id="a",
                verdict=HumanVerdict.SAME,
                reviewer_id="reviewer-001",
                evidence_manifest_hash=self.manifest.manifest_hash,
                reason=None,
                command_id="decision-001",
                expected_revision=0,
            )
        recovered = SQLiteR1Repository(self.path)
        self.assertEqual(recovered.get_task("TASK-RECOVERY").revision, 0)
        self.assertEqual(recovered.list_current_r1_decisions("TASK-RECOVERY").items, ())
        self.assertIsNone(recovered.get_command_receipt("decision-001"))

    def test_lock_fault_after_outbox_rolls_back_state_lock_receipt_and_event(
        self,
    ) -> None:
        base = SQLiteR1Repository(self.path)
        self._register(base)
        for revision, parameter_id in enumerate(("a", "b")):
            base.record_r1_decision(
                task_id="TASK-RECOVERY",
                parameter_id=parameter_id,
                verdict=HumanVerdict.SAME,
                reviewer_id="reviewer-001",
                evidence_manifest_hash=self.manifest.manifest_hash,
                reason=None,
                command_id=f"decision-{parameter_id}",
                expected_revision=revision,
            )

        def fail(point: str) -> None:
            if point == "lock.after_outbox":
                raise InjectedFault(point)

        faulty = SQLiteR1Repository(self.path, fault_injector=fail)
        with self.assertRaises(InjectedFault):
            faulty.lock_r1(
                task_id="TASK-RECOVERY",
                reviewer_id="reviewer-001",
                evidence_manifest_hash=self.manifest.manifest_hash,
                command_id="lock-001",
                expected_revision=2,
            )
        recovered = SQLiteR1Repository(self.path)
        snapshot = recovered.get_task("TASK-RECOVERY")
        self.assertEqual(snapshot.state, "HUMAN_REVIEW_OPEN")
        self.assertEqual(snapshot.revision, 2)
        self.assertIsNone(recovered.get_command_receipt("lock-001"))
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM r1_locks").fetchone()[0], 0
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM audit_outbox WHERE event_type='R1_LOCKED'"
                ).fetchone()[0],
                0,
            )

    def test_process_death_leaves_hot_delete_journal_that_reopens_to_last_commit(
        self,
    ) -> None:
        repository = SQLiteR1Repository(self.path)
        self._register(repository)
        context = multiprocessing.get_context("spawn")
        process = context.Process(target=_crash_during_update, args=(str(self.path),))
        process.start()
        process.join(20)
        if process.is_alive():
            process.terminate()
            process.join(5)
        self.assertEqual(process.exitcode, 17)

        recovered = SQLiteR1Repository(self.path)
        self.assertEqual(recovered.get_task("TASK-RECOVERY").revision, 0)
        self.assertEqual(recovered.verify_integrity().journal_mode, "DELETE")


if __name__ == "__main__":
    unittest.main()
