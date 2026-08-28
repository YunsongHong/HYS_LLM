"""Synthetic, bounded checks for local OCR output capture."""

from contextlib import contextmanager
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import paramguard.ocr as ocr
from paramguard.ocr import (
    OcrExecutionError,
    OcrOutputError,
    OcrUnavailableError,
    TesseractConfig,
    TesseractOcrEngine,
)
from paramguard.routing import ReviewRoute
from paramguard.synthetic import default_clean_case, render_case
from paramguard.template import SYNTHETIC_PANEL_TEMPLATE
from paramguard.vision_pipeline import (
    VisionPipelineBindingError,
    build_tesseract_pipeline_spec,
    run_gated_ocr_pair,
)
from paramguard.workflow import AiVerdict, ReviewTask
from tests.test_vision_pipeline import (
    FakeRunner,
    complete_and_start_human_first,
    make_task,
)


DEFAULT_OUTPUT_BUDGET = 1024 * 1024


@contextmanager
def tracked_children():
    real_popen = subprocess.Popen
    children = []
    output_fds = set()

    def start(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        output_fds.update((child.stdout.fileno(), child.stderr.fileno()))
        return child

    try:
        with patch("paramguard.ocr.subprocess.Popen", side_effect=start):
            yield children, output_fds
    finally:
        # Test-owned fallback only: a failing assertion must not leave a child.
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait()
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()


class OcrOutputBudgetTests(unittest.TestCase):
    def test_injected_runner_rejects_combined_output_over_default_budget(self):
        for stdout, stderr in (
            (b"x" * (DEFAULT_OUTPUT_BUDGET + 1), b""),
            (b"", b"x" * (DEFAULT_OUTPUT_BUDGET + 1)),
            (b"x" * DEFAULT_OUTPUT_BUDGET, b"x"),
        ):
            with self.subTest(stdout=len(stdout), stderr=len(stderr)):

                def runner(command, **kwargs):
                    return subprocess.CompletedProcess(command, 0, stdout, stderr)

                engine = TesseractOcrEngine(binary="python3", runner=runner)
                with self.assertRaises(OcrOutputError):
                    engine._run(("synthetic-test-command",))

    @unittest.skipUnless(os.name == "posix", "POSIX pipe capture")
    def test_default_runner_rejects_finite_excess_output(self):
        # A finite 1 MiB + 1 byte child, not an unbounded producer or OOM test.
        script = (
            "import sys; "
            f"sys.stdout.buffer.write(b'x' * {DEFAULT_OUTPUT_BUDGET + 1})"
        )
        engine = TesseractOcrEngine(binary=sys.executable)
        with self.assertRaises(OcrOutputError):
            engine._run((sys.executable, "-c", script))

    def test_budget_is_strict_positive_int_and_part_of_config_identity(self):
        class IntSubclass(int):
            pass

        for value in (True, False, 0, -1, 1.0, "1024", None, IntSubclass(1)):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "max_output_bytes"):
                    TesseractConfig(max_output_bytes=value)
        config = TesseractConfig()
        self.assertEqual(config.max_output_bytes, DEFAULT_OUTPUT_BUDGET)
        self.assertEqual(config.to_record()["max_output_bytes"], DEFAULT_OUTPUT_BUDGET)
        self.assertNotEqual(
            config.content_sha256,
            replace(config, max_output_bytes=DEFAULT_OUTPUT_BUDGET + 1).content_sha256,
        )

    def test_budget_counts_utf8_bytes_before_decode_without_normalization(self):
        stdout = 'µ"A"\r\n'.encode("utf-8")
        stderr = b"note\r\n"

        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, stdout, stderr)

        exact = len(stdout) + len(stderr)
        engine = TesseractOcrEngine(
            runner=runner, config=TesseractConfig(max_output_bytes=exact)
        )
        result = engine._run(("synthetic",))
        self.assertEqual(result.stdout, stdout.decode("utf-8"))
        self.assertEqual(result.stderr, stderr.decode("utf-8"))
        smaller = TesseractOcrEngine(
            runner=runner, config=TesseractConfig(max_output_bytes=exact - 1)
        )
        with self.assertRaisesRegex(OcrOutputError, "byte budget"):
            smaller._run(("synthetic",))

    def test_excess_output_is_rejected_before_utf8_or_diagnostic_handling(self):
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 2, b"", b"\xff" * 9)

        engine = TesseractOcrEngine(
            runner=runner, config=TesseractConfig(max_output_bytes=8)
        )
        with self.assertRaisesRegex(OcrOutputError, "byte budget"):
            engine._run(("synthetic",))

    def test_non_posix_default_runner_fails_before_creating_process(self):
        with (
            patch("paramguard.ocr.os.name", "nt"),
            patch("paramguard.ocr.subprocess.Popen") as start,
        ):
            with self.assertRaises(OcrUnavailableError):
                TesseractOcrEngine()._run(("synthetic",))
        start.assert_not_called()

    def test_process_lookup_race_does_not_skip_reaping(self):
        class ExitedDuringKill:
            waited = False

            def poll(self):
                return None

            def kill(self):
                raise ProcessLookupError("synthetic exit race")

            def wait(self):
                self.waited = True

        child = ExitedDuringKill()
        ocr._stop_and_reap(child)
        self.assertTrue(child.waited)

    def test_late_pair_overflow_discards_both_sides_and_preserves_humans(self):
        runner = FakeRunner(right_tsv_output="x" * (DEFAULT_OUTPUT_BUDGET + 1))
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            task = make_task(rendered, engine)
            complete_and_start_human_first(task)
            before = task.human_decisions()
            outcome = run_gated_ocr_pair(
                task,
                run_id="run-001",
                left_image_path=rendered.left_image_path,
                right_image_path=rendered.right_image_path,
                engine=engine,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )
        self.assertEqual(task.human_decisions(), before)
        self.assertEqual(outcome.left_ocr, ())
        self.assertEqual(outcome.right_ocr, ())
        self.assertEqual(len(outcome.ai_assessments), 4)
        for assessment in outcome.ai_assessments:
            self.assertIs(assessment.verdict, AiVerdict.SYSTEM_ERROR)
            self.assertIsNone(assessment.left_raw)
            self.assertIsNone(assessment.right_raw)
        self.assertTrue(
            all(
                item.route is ReviewRoute.QA_REVIEW_REQUIRED for item in outcome.routing
            )
        )
        self.assertEqual(sum(command[-1] == "tsv" for command in runner.commands), 5)

    def test_old_pipeline_or_changed_budget_is_rejected_before_source_reads(self):
        for old_version in (True, False):
            with self.subTest(
                old_version=old_version
            ), TemporaryDirectory() as directory:
                rendered = render_case(default_clean_case(), output_root=directory)
                runner = FakeRunner()
                engine = TesseractOcrEngine(binary="python3", runner=runner)
                spec = build_tesseract_pipeline_spec(
                    engine=engine, template=SYNTHETIC_PANEL_TEMPLATE
                )
                if old_version:
                    spec = replace(spec, pipeline_version="1.6")
                task = ReviewTask(
                    task_id="synthetic-output-budget",
                    evidence_manifest=rendered.manifest,
                    approved_pipeline_spec=spec,
                    reviewer_id="primary-reviewer",
                )
                complete_and_start_human_first(task)
                if not old_version:
                    engine = TesseractOcrEngine(
                        binary="python3",
                        runner=runner,
                        config=TesseractConfig(
                            max_output_bytes=DEFAULT_OUTPUT_BUDGET + 1
                        ),
                    )
                calls_before = len(runner.commands)
                with (
                    patch.object(
                        Path, "open", side_effect=AssertionError("source read")
                    ),
                    self.assertRaises(VisionPipelineBindingError),
                ):
                    run_gated_ocr_pair(
                        task,
                        run_id="run-001",
                        left_image_path=rendered.left_image_path,
                        right_image_path=rendered.right_image_path,
                        engine=engine,
                        template=SYNTHETIC_PANEL_TEMPLATE,
                    )
                self.assertEqual(len(runner.commands), calls_before + 1)
                self.assertFalse(
                    any(command[-1] == "tsv" for command in runner.commands)
                )


@unittest.skipUnless(os.name == "posix", "POSIX pipe capture")
class BoundedProcessTests(unittest.TestCase):
    def assert_child_closed(self, child):
        # Inspect before tracked_children's independent fallback cleanup.
        self.assertIsNotNone(child.returncode)
        self.assertTrue(
            all(
                stream is None or stream.closed
                for stream in (child.stdin, child.stdout, child.stderr)
            )
        )

    def test_stdout_and_stderr_share_n_plus_one_read_budget(self):
        for stdout_size, stderr_size in ((4097, 0), (0, 4097), (32, 33)):
            with self.subTest(stdout=stdout_size, stderr=stderr_size):
                script = (
                    "import sys; "
                    f"sys.stdout.buffer.write(b'x' * {stdout_size}); sys.stdout.buffer.flush(); "
                    f"sys.stderr.buffer.write(b'y' * {stderr_size}); sys.stderr.buffer.flush()"
                )
                real_read = os.read
                received = []
                with tracked_children() as (children, output_fds):

                    def read(fd, size):
                        chunk = real_read(fd, size)
                        if fd in output_fds:
                            received.append((size, len(chunk)))
                        return chunk

                    engine = TesseractOcrEngine(
                        config=TesseractConfig(max_output_bytes=64)
                    )
                    with (
                        patch("paramguard.ocr.os.read", side_effect=read),
                        self.assertRaises(OcrOutputError),
                    ):
                        engine._run((sys.executable, "-c", script))
                    self.assertEqual(sum(size for _, size in received), 65)
                    self.assertTrue(all(request <= 65 for request, _ in received))
                    self.assert_child_closed(children[0])

    def test_exact_budget_and_binary_stdin_are_preserved(self):
        payload = 'µ"A"\r\n'.encode("utf-8")
        script = "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.stderr.buffer.write(b'!')"
        engine = TesseractOcrEngine(
            config=TesseractConfig(max_output_bytes=len(payload) + 1)
        )
        with tracked_children() as (children, _):
            result = engine._run((sys.executable, "-c", script), input_bytes=payload)
            self.assertEqual(result.stdout, payload.decode("utf-8"))
            self.assertEqual(result.stderr, "!")
            self.assert_child_closed(children[0])

    def test_duplex_backpressure_does_not_deadlock(self):
        payload = b"synthetic input " * 16384
        prefix_size = 131072
        script = (
            "import sys,hashlib; "
            f"sys.stdout.buffer.write(b'o'*{prefix_size}); sys.stdout.buffer.flush(); "
            f"sys.stderr.buffer.write(b'e'*{prefix_size}); sys.stderr.buffer.flush(); "
            "data=sys.stdin.buffer.read(); sys.stdout.write(hashlib.sha256(data).hexdigest())"
        )
        engine = TesseractOcrEngine(config=TesseractConfig(timeout_seconds=3))
        with tracked_children() as (children, _):
            result = engine._run((sys.executable, "-c", script), input_bytes=payload)
            self.assertEqual(
                result.stdout, "o" * prefix_size + hashlib.sha256(payload).hexdigest()
            )
            self.assertEqual(result.stderr, "e" * prefix_size)
            self.assert_child_closed(children[0])

    def test_temporary_nonblocking_reads_and_short_writes_resume(self):
        real_read, real_write = os.read, os.write
        blocked_reads = set()
        blocked_write = False
        short_write = False
        payload = b"synthetic short write" * 32
        with tracked_children() as (children, output_fds):

            def read(fd, size):
                if fd in output_fds:
                    if fd not in blocked_reads:
                        blocked_reads.add(fd)
                        raise BlockingIOError("synthetic EAGAIN")
                    size = min(size, 3)
                return real_read(fd, size)

            def write(fd, data):
                nonlocal blocked_write, short_write
                if (
                    children
                    and children[0].stdin is not None
                    and fd == children[0].stdin.fileno()
                ):
                    if not blocked_write:
                        blocked_write = True
                        raise BlockingIOError("synthetic EAGAIN")
                    short_write = True
                    data = data[:5]
                return real_write(fd, data)

            with (
                patch("paramguard.ocr.os.read", side_effect=read),
                patch("paramguard.ocr.os.write", side_effect=write),
            ):
                result = TesseractOcrEngine()._run(
                    (
                        sys.executable,
                        "-c",
                        "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
                    ),
                    input_bytes=payload,
                )
            self.assertEqual(result.stdout.encode("utf-8"), payload)
            self.assertEqual(len(blocked_reads), 2)
            self.assertTrue(blocked_write and short_write)
            self.assert_child_closed(children[0])

    def test_timeout_covers_open_pipes_and_process_after_pipe_eof(self):
        for close_pipes in (False, True):
            with self.subTest(close_pipes=close_pipes), tracked_children() as (
                children,
                _,
            ):
                script = "import os,time; "
                if close_pipes:
                    script += "os.close(1); os.close(2); "
                script += "time.sleep(2)"
                engine = TesseractOcrEngine(
                    config=TesseractConfig(timeout_seconds=0.15)
                )
                with self.assertRaises(OcrExecutionError):
                    engine._run((sys.executable, "-c", script))
                self.assert_child_closed(children[0])

    def test_read_failure_closes_pipes_and_reaps_child(self):
        real_read = os.read
        with tracked_children() as (children, output_fds):

            def fail(fd, size):
                if fd in output_fds:
                    raise OSError("synthetic read failure")
                return real_read(fd, size)

            with (
                patch("paramguard.ocr.os.read", side_effect=fail),
                self.assertRaises(OcrExecutionError),
            ):
                TesseractOcrEngine()._run((sys.executable, "-c", "print('synthetic')"))
            self.assert_child_closed(children[0])

    def test_early_stdin_close_does_not_hide_nonzero_exit(self):
        with tracked_children() as (children, _):
            with self.assertRaisesRegex(OcrExecutionError, "status 2"):
                TesseractOcrEngine()._run(
                    (
                        sys.executable,
                        "-c",
                        "import os; os.close(0); raise SystemExit(2)",
                    ),
                    input_bytes=b"synthetic" * 32768,
                )
            self.assert_child_closed(children[0])
