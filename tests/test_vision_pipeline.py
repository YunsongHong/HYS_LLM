"""Integration and adversarial tests for post-lock image/OCR execution."""

from dataclasses import replace
import hashlib
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import paramguard.vision_pipeline as vision_pipeline

from paramguard.image_quality import ImageQualityConfig
from paramguard.ocr import TesseractOcrEngine
from paramguard.routing import ReviewRoute, RouteReason
from paramguard.synthetic import (
    SyntheticDegradation,
    default_clean_case,
    render_case,
)
from paramguard.template import SYNTHETIC_PANEL_TEMPLATE
from paramguard.vision_pipeline import (
    VisionPipelineBindingError,
    VisionPipelineStateError,
    build_tesseract_pipeline_spec,
    run_gated_ocr_pair,
)
from paramguard.workflow import AiRunIdentityError, AiVerdict, HumanVerdict, ReviewTask


TSV = (
    "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\t"
    "left\ttop\twidth\theight\tconf\ttext\n"
    "5\t1\t1\t1\t1\t1\t10\t8\t90\t30\t95\tAUTO\n"
)


class FakeRunner:
    def __init__(
        self,
        *,
        fail_ocr: bool = False,
        tsv_output: str = TSV,
        right_tsv_output: str | None = None,
    ) -> None:
        self.fail_ocr = fail_ocr
        self.tsv_output = tsv_output
        self.right_tsv_output = right_tsv_output
        self.commands: list[list[str]] = []

    def __call__(
        self, command: list[str], **_: object
    ) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(command)
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, b"tesseract 5.5.1\n", b"")
        if self.fail_ocr:
            return subprocess.CompletedProcess(command, 2, b"", b"synthetic failure")
        crop_count = sum("tsv" in item for item in self.commands)
        output = self.tsv_output
        if self.right_tsv_output is not None and crop_count > len(
            SYNTHETIC_PANEL_TEMPLATE.regions
        ):
            output = self.right_tsv_output
        return subprocess.CompletedProcess(command, 0, output.encode("utf-8"), b"")


def make_task(rendered, engine: TesseractOcrEngine) -> ReviewTask:
    spec = build_tesseract_pipeline_spec(
        engine=engine, template=SYNTHETIC_PANEL_TEMPLATE
    )
    return ReviewTask(
        task_id=f"task-{rendered.spec.case_id}",
        evidence_manifest=rendered.manifest,
        approved_pipeline_spec=spec,
        reviewer_id="primary-reviewer",
    )


def complete_and_start_human_first(task: ReviewTask) -> None:
    decisions = {
        "temperature": (HumanVerdict.SAME, None),
        "pressure": (HumanVerdict.DIFFERENT, "Visual values differ"),
        "speed": (HumanVerdict.DIFFERENT, "Displayed precision differs"),
        "mode": (HumanVerdict.SAME, None),
    }
    for parameter_id in task.expected_parameter_ids:
        verdict, reason = decisions[parameter_id]
        task.record_human_decision(
            parameter_id=parameter_id,
            verdict=verdict,
            reason=reason,
            evidence_manifest_hash=task.evidence_manifest_hash,
        )
    task.lock_human_review(evidence_manifest_hash=task.evidence_manifest_hash)
    task.queue_ai_review(
        run_id="run-001",
        evidence_manifest_hash=task.evidence_manifest_hash,
        pipeline_spec_hash=task.approved_pipeline_spec.spec_hash,
    )
    task.start_ai_review(
        run_id="run-001", evidence_manifest_hash=task.evidence_manifest_hash
    )


class GatedVisionPipelineTests(unittest.TestCase):
    def test_early_call_fails_before_reading_images_or_invoking_engine(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            task = make_task(rendered, engine)
            calls_before = len(runner.commands)
            with self.assertRaises(VisionPipelineStateError):
                run_gated_ocr_pair(
                    task,
                    run_id="run-001",
                    left_image_path="does-not-exist-left.png",
                    right_image_path="does-not-exist-right.png",
                    engine=engine,
                    template=SYNTHETIC_PANEL_TEMPLATE,
                )

        self.assertEqual(len(runner.commands), calls_before)

    def test_low_quality_abstains_without_sending_crops_to_ocr(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        low_case = replace(
            default_clean_case(),
            case_id="low-quality-gate",
            left_degradation=SyntheticDegradation.LOW_CONTRAST,
        )
        with TemporaryDirectory() as directory:
            rendered = render_case(low_case, output_root=directory)
            task = make_task(rendered, engine)
            complete_and_start_human_first(task)
            outcome = run_gated_ocr_pair(
                task,
                run_id="run-001",
                left_image_path=rendered.left_image_path,
                right_image_path=rendered.right_image_path,
                engine=engine,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )

        crop_commands = [command for command in runner.commands if "tsv" in command]
        self.assertEqual(crop_commands, [])
        self.assertTrue(
            all(
                assessment.verdict is AiVerdict.UNABLE_TO_JUDGE
                for assessment in outcome.ai_assessments
            )
        )
        self.assertTrue(
            all(
                RouteReason.LOW_IMAGE_QUALITY in item.reasons
                for item in outcome.routing
            )
        )

    def test_wrong_run_id_fails_before_image_or_ocr_access(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            task = make_task(rendered, engine)
            complete_and_start_human_first(task)
            calls_before = len(runner.commands)
            with self.assertRaises(AiRunIdentityError):
                run_gated_ocr_pair(
                    task,
                    run_id="run-forged",
                    left_image_path="does-not-exist-left.png",
                    right_image_path="does-not-exist-right.png",
                    engine=engine,
                    template=SYNTHETIC_PANEL_TEMPLATE,
                )

        self.assertEqual(len(runner.commands), calls_before)

    def test_ocr_execution_error_becomes_qa_system_error_not_match(self) -> None:
        runner = FakeRunner(fail_ocr=True)
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            task = make_task(rendered, engine)
            complete_and_start_human_first(task)
            outcome = run_gated_ocr_pair(
                task,
                run_id="run-001",
                left_image_path=rendered.left_image_path,
                right_image_path=rendered.right_image_path,
                engine=engine,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )

        self.assertTrue(
            all(
                assessment.verdict is AiVerdict.SYSTEM_ERROR
                for assessment in outcome.ai_assessments
            )
        )
        self.assertTrue(
            all(
                item.route is ReviewRoute.QA_REVIEW_REQUIRED for item in outcome.routing
            )
        )
        self.assertTrue(
            all(RouteReason.AI_SYSTEM_ERROR in item.reasons for item in outcome.routing)
        )

    def test_changed_image_bytes_fail_before_ocr_assessment(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            task = make_task(rendered, engine)
            complete_and_start_human_first(task)
            rendered.left_image_path.write_bytes(
                rendered.left_image_path.read_bytes() + b"tampered"
            )
            with self.assertRaises(VisionPipelineBindingError):
                run_gated_ocr_pair(
                    task,
                    run_id="run-001",
                    left_image_path=rendered.left_image_path,
                    right_image_path=rendered.right_image_path,
                    engine=engine,
                    template=SYNTHETIC_PANEL_TEMPLATE,
                )

        self.assertEqual(task._ai_results, {})

    def test_ocr_uses_bytes_verified_before_source_path_is_replaced(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            original_hash = hashlib.sha256(
                rendered.left_image_path.read_bytes()
            ).hexdigest()
            replacement_bytes = rendered.right_image_path.read_bytes()
            task = make_task(rendered, engine)
            complete_and_start_human_first(task)
            human_before = task.human_decisions()
            verify = vision_pipeline._verify_bindings

            def replace_after_binding(**kwargs):
                bound = verify(**kwargs)
                rendered.left_image_path.write_bytes(replacement_bytes)
                return bound

            with patch.object(
                vision_pipeline, "_verify_bindings", side_effect=replace_after_binding
            ):
                outcome = run_gated_ocr_pair(
                    task,
                    run_id="run-001",
                    left_image_path=rendered.left_image_path,
                    right_image_path=rendered.right_image_path,
                    engine=engine,
                    template=SYNTHETIC_PANEL_TEMPLATE,
                )
            self.assertEqual(
                {item.source_image_sha256 for item in outcome.left_ocr}, {original_hash}
            )
            self.assertEqual(task.human_decisions(), human_before)
            self.assertTrue(
                all(not item.automatic_release_allowed for item in outcome.routing)
            )

    def test_replacing_low_quality_file_after_binding_cannot_enable_ocr(self) -> None:
        for side in ("left", "right"):
            with self.subTest(side=side), TemporaryDirectory() as directory:
                runner = FakeRunner()
                engine = TesseractOcrEngine(binary="python3", runner=runner)
                spec = replace(
                    default_clean_case(),
                    case_id=f"snapshot-low-{side}",
                    **{f"{side}_degradation": SyntheticDegradation.LOW_CONTRAST},
                )
                rendered = render_case(spec, output_root=directory)
                bad_path = getattr(rendered, f"{side}_image_path")
                clean_path = (
                    rendered.right_image_path
                    if side == "left"
                    else rendered.left_image_path
                )
                clean_bytes = clean_path.read_bytes()
                task = make_task(rendered, engine)
                complete_and_start_human_first(task)
                human_before = task.human_decisions()
                verify = vision_pipeline._verify_bindings

                def replace_after_binding(**kwargs):
                    bound = verify(**kwargs)
                    bad_path.write_bytes(clean_bytes)
                    return bound

                with patch.object(
                    vision_pipeline,
                    "_verify_bindings",
                    side_effect=replace_after_binding,
                ):
                    outcome = run_gated_ocr_pair(
                        task,
                        run_id="run-001",
                        left_image_path=rendered.left_image_path,
                        right_image_path=rendered.right_image_path,
                        engine=engine,
                        template=SYNTHETIC_PANEL_TEMPLATE,
                    )
                self.assertTrue(
                    all(
                        item.verdict is AiVerdict.UNABLE_TO_JUDGE
                        for item in outcome.ai_assessments
                    )
                )
                self.assertFalse(any("tsv" in command for command in runner.commands))
                self.assertEqual(task.human_decisions(), human_before)
                self.assertTrue(
                    all(not item.automatic_release_allowed for item in outcome.routing)
                )

    def test_pre_snapshot_pipeline_identity_is_not_silently_reused(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            current = build_tesseract_pipeline_spec(
                engine=engine, template=SYNTHETIC_PANEL_TEMPLATE
            )
            task = ReviewTask(
                task_id="pre-snapshot-pipeline",
                evidence_manifest=rendered.manifest,
                approved_pipeline_spec=replace(current, pipeline_version="1.1"),
                reviewer_id="primary-reviewer",
            )
            complete_and_start_human_first(task)
            with self.assertRaises(VisionPipelineBindingError):
                run_gated_ocr_pair(
                    task,
                    run_id="run-001",
                    left_image_path="unread-before-binding-left.png",
                    right_image_path="unread-before-binding-right.png",
                    engine=engine,
                    template=SYNTHETIC_PANEL_TEMPLATE,
                )
        self.assertEqual(task._ai_results, {})
        self.assertFalse(any("tsv" in command for command in runner.commands))

    def test_malformed_ocr_output_routes_to_qa_without_altering_humans(self) -> None:
        header, row = TSV.splitlines(keepends=True)
        malformed = (
            TSV.replace("\t95\t", "\tnan\t"),
            TSV.replace("\t95\t", "\tinf\t"),
            TSV.replace("\t95\t", "\t101\t"),
            header.rstrip("\n") + "\ttext\n" + row.rstrip("\n") + "\tMANUAL\n",
            TSV.rstrip("\n") + "\tignored-cell\n",
        )
        for index, output in enumerate(malformed):
            with self.subTest(index=index), TemporaryDirectory() as directory:
                runner = FakeRunner(tsv_output=output)
                engine = TesseractOcrEngine(binary="python3", runner=runner)
                rendered = render_case(default_clean_case(), output_root=directory)
                task = make_task(rendered, engine)
                complete_and_start_human_first(task)
                human_before = task.human_decisions()
                outcome = run_gated_ocr_pair(
                    task,
                    run_id="run-001",
                    left_image_path=rendered.left_image_path,
                    right_image_path=rendered.right_image_path,
                    engine=engine,
                    template=SYNTHETIC_PANEL_TEMPLATE,
                )
                self.assertTrue(
                    all(
                        item.verdict is AiVerdict.SYSTEM_ERROR
                        for item in outcome.ai_assessments
                    )
                )
                self.assertTrue(
                    all(
                        item.route is ReviewRoute.QA_REVIEW_REQUIRED
                        and not item.automatic_release_allowed
                        for item in outcome.routing
                    )
                )
                self.assertEqual(task.human_decisions(), human_before)

    def test_invalid_utf8_discards_partial_ocr_and_routes_all_fields_to_qa(
        self,
    ) -> None:
        calls = []

        def capture(command, **kwargs):
            if command[-1] == "--version":
                version = "tesseract 5.5.1\n"
                return subprocess.CompletedProcess(
                    command,
                    0,
                    version if kwargs.get("text") else version.encode(),
                    "" if kwargs.get("text") else b"",
                )
            calls.append(command)
            output = TSV.encode("utf-8") if len(calls) == 1 else b"\xff"
            return subprocess.CompletedProcess(command, 0, output, b"")

        with TemporaryDirectory() as directory:
            engine = TesseractOcrEngine(binary="python3", runner=capture)
            rendered = render_case(default_clean_case(), output_root=directory)
            task = make_task(rendered, engine)
            complete_and_start_human_first(task)
            human_before = task.human_decisions()
            outcome = run_gated_ocr_pair(
                task,
                run_id="run-001",
                left_image_path=rendered.left_image_path,
                right_image_path=rendered.right_image_path,
                engine=engine,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )
        self.assertEqual(len(calls), 2)
        self.assertEqual(outcome.left_ocr, ())
        self.assertEqual(outcome.right_ocr, ())
        self.assertEqual(len(outcome.ai_assessments), 4)
        self.assertTrue(
            all(
                item.verdict is AiVerdict.SYSTEM_ERROR
                for item in outcome.ai_assessments
            )
        )
        self.assertTrue(
            all(
                item.route is ReviewRoute.QA_REVIEW_REQUIRED
                and not item.automatic_release_allowed
                for item in outcome.routing
            )
        )
        self.assertEqual(task.human_decisions(), human_before)

    def test_pre_stdin_pipeline_is_rejected_before_image_read(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            current = build_tesseract_pipeline_spec(
                engine=engine, template=SYNTHETIC_PANEL_TEMPLATE
            )
            task = ReviewTask(
                task_id="pre-stdin-pipeline",
                evidence_manifest=rendered.manifest,
                approved_pipeline_spec=replace(current, pipeline_version="1.3"),
                reviewer_id="primary-reviewer",
            )
            complete_and_start_human_first(task)
            human_before = task.human_decisions()
            calls_before = len(runner.commands)
            with patch(
                "paramguard.vision_pipeline.Path.open",
                side_effect=AssertionError("source must not be read"),
            ) as read:
                with self.assertRaises(VisionPipelineBindingError):
                    run_gated_ocr_pair(
                        task,
                        run_id="run-001",
                        left_image_path=rendered.left_image_path,
                        right_image_path=rendered.right_image_path,
                        engine=engine,
                        template=SYNTHETIC_PANEL_TEMPLATE,
                    )
                read.assert_not_called()
        self.assertEqual(len(runner.commands), calls_before + 1)
        self.assertEqual(task._ai_results, {})
        self.assertEqual(task.human_decisions(), human_before)
        self.assertFalse(any("tsv" in command for command in runner.commands))

    def test_quoted_and_unquoted_observations_are_not_same(self) -> None:
        runner = FakeRunner(
            tsv_output=TSV.replace("\tAUTO\n", '\t"AUTO"\n'),
            right_tsv_output=TSV,
        )
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            task = make_task(rendered, engine)
            complete_and_start_human_first(task)
            outcome = run_gated_ocr_pair(
                task,
                run_id="run-001",
                left_image_path=rendered.left_image_path,
                right_image_path=rendered.right_image_path,
                engine=engine,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )
        self.assertTrue(
            all(
                item.verdict is AiVerdict.DIFFERENT
                and item.comparison_result.left_raw == '"AUTO"'
                and item.comparison_result.right_raw == "AUTO"
                for item in outcome.ai_assessments
            )
        )
        self.assertTrue(
            all(not item.automatic_release_allowed for item in outcome.routing)
        )

    def test_runtime_quality_config_must_equal_approved_pipeline(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            task = make_task(rendered, engine)
            complete_and_start_human_first(task)
            changed = ImageQualityConfig(minimum_contrast_stddev=19.0)
            with self.assertRaises(VisionPipelineBindingError):
                run_gated_ocr_pair(
                    task,
                    run_id="run-001",
                    left_image_path=rendered.left_image_path,
                    right_image_path=rendered.right_image_path,
                    engine=engine,
                    template=SYNTHETIC_PANEL_TEMPLATE,
                    quality_config=changed,
                )

    def test_legacy_parser_pipeline_identity_is_not_silently_reused(self) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            current = build_tesseract_pipeline_spec(
                engine=engine, template=SYNTHETIC_PANEL_TEMPLATE
            )
            legacy = replace(current, pipeline_version="1.0", comparator_version="1.0")
            task = ReviewTask(
                task_id="legacy-parser-task",
                evidence_manifest=rendered.manifest,
                approved_pipeline_spec=legacy,
                reviewer_id="primary-reviewer",
            )
            complete_and_start_human_first(task)
            with self.assertRaises(VisionPipelineBindingError):
                run_gated_ocr_pair(
                    task,
                    run_id="run-001",
                    left_image_path=rendered.left_image_path,
                    right_image_path=rendered.right_image_path,
                    engine=engine,
                    template=SYNTHETIC_PANEL_TEMPLATE,
                )
        self.assertEqual(task._ai_results, {})
        self.assertFalse(any("tsv" in command for command in runner.commands))

    @unittest.skipUnless(shutil.which("tesseract"), "local Tesseract is not installed")
    def test_real_clean_pair_completes_and_routes_without_auto_release(self) -> None:
        engine = TesseractOcrEngine()
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            task = make_task(rendered, engine)
            complete_and_start_human_first(task)
            outcome = run_gated_ocr_pair(
                task,
                run_id="run-001",
                left_image_path=rendered.left_image_path,
                right_image_path=rendered.right_image_path,
                engine=engine,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )

        by_id = {item.parameter_id: item for item in outcome.ai_assessments}
        routes = {item.parameter_id: item for item in outcome.routing}
        self.assertEqual(by_id["temperature"].verdict, AiVerdict.SAME)
        self.assertEqual(by_id["pressure"].verdict, AiVerdict.DIFFERENT)
        self.assertEqual(by_id["speed"].verdict, AiVerdict.DIFFERENT)
        self.assertEqual(by_id["mode"].verdict, AiVerdict.SAME)
        self.assertEqual(routes["mode"].route, ReviewRoute.NO_EXCEPTION_DETECTED)
        self.assertEqual(
            routes["temperature"].route,
            ReviewRoute.INDEPENDENT_SECOND_REVIEW_REQUIRED,
        )
        self.assertTrue(
            all(not item.automatic_release_allowed for item in outcome.routing)
        )


if __name__ == "__main__":
    unittest.main()
