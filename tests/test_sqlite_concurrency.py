from __future__ import annotations

from contextlib import closing
import multiprocessing
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
from paramguard.sqlite_repository import (
    DataClassification,
    SQLiteR1Repository,
)
from paramguard.workflow import HumanVerdict


def _manifest(parameter_ids: tuple[str, ...]) -> EvidenceManifest:
    return EvidenceManifest(
        manifest_id="synthetic-manifest-concurrency",
        schema_id="synthetic-schema",
        schema_version="1.0",
        schema_sha256=content_sha256(b"synthetic-schema"),
        template_id="synthetic-template",
        template_version="1.0",
        template_sha256=content_sha256(b"synthetic-template"),
        expected_parameter_ids=parameter_ids,
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
        engine_version="1.0",
        pipeline_version="1.0",
        comparator_version="1.0",
        configuration_sha256=content_sha256(b"synthetic-pipeline"),
    )


def _decision_worker(
    database_path: str,
    parameter_id: str,
    command_id: str,
    start_event,
    output_queue,
) -> None:
    try:
        repository = SQLiteR1Repository(database_path, busy_timeout_ms=10_000)
        manifest = _manifest(("p0000", "p0001"))
        start_event.wait(10)
        receipt = repository.record_r1_decision(
            task_id="TASK-CONCURRENT",
            parameter_id=parameter_id,
            verdict=HumanVerdict.SAME,
            reviewer_id="reviewer-001",
            evidence_manifest_hash=manifest.manifest_hash,
            reason=None,
            command_id=command_id,
            expected_revision=0,
        )
        output_queue.put(("ok", receipt.response_json))
    except BaseException as error:
        output_queue.put(("error", type(error).__name__))


class SQLiteConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "paramguard.db"

    def _register_two_parameter_task(self) -> None:
        SQLiteR1Repository(self.path).register_task(
            task_id="TASK-CONCURRENT",
            evidence_manifest=_manifest(("p0000", "p0001")),
            pipeline_spec=_pipeline(),
            reviewer_id="reviewer-001",
            command_id="register-concurrent",
            data_classification=DataClassification.SYNTHETIC,
        )

    def _run_workers(
        self,
        command_ids: tuple[str, str],
        *,
        parameter_ids: tuple[str, str] = ("p0000", "p0001"),
    ) -> list[tuple[str, str]]:
        context = multiprocessing.get_context("spawn")
        start_event = context.Event()
        output_queue = context.Queue()
        processes = [
            context.Process(
                target=_decision_worker,
                args=(
                    str(self.path),
                    parameter_ids[index],
                    command_ids[index],
                    start_event,
                    output_queue,
                ),
            )
            for index in range(2)
        ]
        for process in processes:
            process.start()
        start_event.set()
        for process in processes:
            process.join(20)
            if process.is_alive():
                process.terminate()
                process.join(5)
            self.assertEqual(process.exitcode, 0)
        return [output_queue.get(timeout=5) for _ in processes]

    def test_two_process_writers_cannot_both_win_same_expected_revision(self) -> None:
        self._register_two_parameter_task()
        results = self._run_workers(("decision-a", "decision-b"))

        self.assertEqual(sum(status == "ok" for status, _ in results), 1)
        self.assertEqual(
            [detail for status, detail in results if status == "error"],
            ["RevisionConflictError"],
        )
        repository = SQLiteR1Repository(self.path)
        self.assertEqual(repository.get_task("TASK-CONCURRENT").revision, 1)
        self.assertEqual(
            len(repository.list_current_r1_decisions("TASK-CONCURRENT").items), 1
        )

    def test_two_process_exact_same_command_receive_one_durable_result(self) -> None:
        self._register_two_parameter_task()
        results = self._run_workers(
            ("decision-same", "decision-same"),
            parameter_ids=("p0000", "p0000"),
        )

        self.assertEqual([status for status, _ in results], ["ok", "ok"])
        self.assertEqual(results[0][1], results[1][1])
        repository = SQLiteR1Repository(self.path)
        self.assertEqual(repository.get_task("TASK-CONCURRENT").revision, 1)
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM r1_decisions").fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM audit_outbox "
                    "WHERE event_type='R1_DECISION_RECORDED'"
                ).fetchone()[0],
                1,
            )

    def test_1001_fields_use_ordinal_keyset_pagination_without_offset(self) -> None:
        parameter_ids = tuple(f"p{index:04d}" for index in range(1001))
        repository = SQLiteR1Repository(self.path)
        repository.register_task(
            task_id="TASK-1001",
            evidence_manifest=_manifest(parameter_ids),
            pipeline_spec=_pipeline(),
            reviewer_id="reviewer-001",
            command_id="register-1001",
            data_classification=DataClassification.SYNTHETIC,
        )

        observed: list[str] = []
        after = -1
        while True:
            page = repository.list_parameters(
                "TASK-1001", after_ordinal=after, limit=137
            )
            observed.extend(item.parameter_id for item in page.items)
            if page.next_after_ordinal is None:
                break
            self.assertGreater(page.next_after_ordinal, after)
            after = page.next_after_ordinal
        self.assertEqual(observed, list(parameter_ids))
        with closing(connect_database(self.path)) as connection:
            plan = " ".join(
                str(row[3])
                for row in connection.execute(
                    "EXPLAIN QUERY PLAN SELECT ordinal, parameter_id "
                    "FROM task_parameters WHERE task_id=? AND ordinal>? "
                    "ORDER BY ordinal LIMIT ?",
                    ("TASK-1001", 500, 137),
                )
            ).upper()
        self.assertIn("INDEX", plan)
        self.assertNotIn("TEMP B-TREE", plan)


if __name__ == "__main__":
    unittest.main()
