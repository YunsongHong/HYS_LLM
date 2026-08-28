from __future__ import annotations

from datetime import datetime, timezone
import json
import subprocess
from tempfile import TemporaryDirectory
import unittest

from paramguard.benchmark_runner import run_synthetic_benchmark
from paramguard.evaluation import DatasetSplit
from paramguard.ocr import TesseractOcrEngine


TSV = (
    "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\t"
    "left\ttop\twidth\theight\tconf\ttext\n"
    "5\t1\t1\t1\t1\t1\t10\t8\t90\t30\t95\tAUTO\n"
)


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(
        self, command: list[str], **_: object
    ) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(command)
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, b"tesseract 5.5.1\n", b"")
        return subprocess.CompletedProcess(command, 0, TSV.encode("utf-8"), b"")


class IncrementingTimer:
    def __init__(self, *, step: float = 2.0) -> None:
        self.value = 0.0
        self.step = step

    def __call__(self) -> float:
        current = self.value
        self.value += self.step
        return current


class BenchmarkRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)

    def test_development_case_runs_through_locked_workflow_and_serializes(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            execution = run_synthetic_benchmark(
                output_root=directory,
                splits=(DatasetSplit.DEVELOPMENT,),
                engine=engine,
                clock=lambda: self.now,
                timer=IncrementingTimer(step=2.0),
            )

        self.assertEqual(len(execution.records), 4)
        self.assertEqual(len(execution.reports), 1)
        report = execution.reports[0]
        self.assertEqual(report.field_count, 4)
        self.assertEqual(report.true_difference_count, 2)
        self.assertEqual(report.false_negative_rate.value, 1.0)
        self.assertEqual(report.escalation_recall.value, 1.0)
        self.assertTrue(
            all(row.human_review_seconds is None for row in execution.records)
        )
        self.assertTrue(
            all(row.ai_processing_seconds == 0.5 for row in execution.records)
        )
        crop_commands = [command for command in runner.commands if "tsv" in command]
        self.assertEqual(len(crop_commands), 8)

        payload = json.loads(execution.to_json())
        self.assertEqual(payload["evaluated_splits"], ["DEVELOPMENT"])
        self.assertIsNone(payload["field_records"][0]["human_review_seconds"])
        self.assertNotIn("overall_accuracy", payload["reports"][0])
        runtime = payload["runtime_environment"]
        self.assertEqual(runtime["processing_location"], "LOCAL")
        self.assertFalse(runtime["network_required"])
        self.assertEqual(len(runtime["source_tree_sha256"]), 64)
        self.assertEqual(len(runtime["template_sha256"]), 64)
        self.assertNotIn("/Users/", execution.to_json())
        self.assertTrue(
            any("simulated" in note.lower() for note in payload["method_notes"])
        )

    def test_challenge_quality_gate_abstains_without_ocr_crop_commands(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            execution = run_synthetic_benchmark(
                output_root=directory,
                splits=(DatasetSplit.CHALLENGE,),
                engine=engine,
                clock=lambda: self.now,
                timer=IncrementingTimer(),
            )

        report = execution.reports[0]
        self.assertEqual(report.field_count, 8)
        self.assertEqual(report.overall_abstention_rate.value, 1.0)
        self.assertEqual(
            [command for command in runner.commands if "tsv" in command],
            [],
        )

    def test_duplicate_or_non_tuple_splits_fail_closed(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                run_synthetic_benchmark(
                    output_root=directory,
                    splits=(
                        DatasetSplit.HIDDEN_TEST,
                        DatasetSplit.HIDDEN_TEST,
                    ),
                    engine=engine,
                )
            with self.assertRaises(ValueError):
                run_synthetic_benchmark(
                    output_root=directory,
                    splits=[],  # type: ignore[arg-type]
                    engine=engine,
                )

    def test_timer_moving_backwards_is_rejected(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        values = iter((2.0, 1.0))
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "moved backwards"):
                run_synthetic_benchmark(
                    output_root=directory,
                    splits=(DatasetSplit.DEVELOPMENT,),
                    engine=engine,
                    clock=lambda: self.now,
                    timer=lambda: next(values),
                )


if __name__ == "__main__":
    unittest.main()
