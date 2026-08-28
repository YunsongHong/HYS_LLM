"""Finite numeric configuration and strict hashing boundaries."""

from dataclasses import replace
import json
import math
import subprocess
from tempfile import TemporaryDirectory
import unittest

from paramguard.image_quality import ImageQualityConfig
from paramguard.ocr import TesseractConfig, TesseractOcrEngine
from paramguard.synthetic import default_clean_case, render_case
from paramguard.template import SYNTHETIC_PANEL_TEMPLATE
from paramguard.vision_pipeline import (
    VisionPipelineBindingError,
    build_tesseract_pipeline_spec,
    run_gated_ocr_pair,
)
from paramguard.workflow import ReviewTask
from tests.test_vision_pipeline import FakeRunner, complete_and_start_human_first


class FloatSubclass(float):
    pass


class IntSubclass(int):
    pass


class NumericConfigurationTests(unittest.TestCase):
    def test_quality_thresholds_require_finite_builtin_numbers(self) -> None:
        invalid = (
            float("nan"),
            float("inf"),
            -float("inf"),
            1 << 1024,
            -1,
            True,
            False,
            "18",
            None,
            FloatSubclass(18),
            IntSubclass(18),
        )
        for name in ("minimum_contrast_stddev", "minimum_edge_variance"):
            for value in invalid:
                with self.subTest(field=name, value=value):
                    with self.assertRaisesRegex(ValueError, name):
                        ImageQualityConfig(**{name: value})

    def test_quality_hash_rejects_nonfinite_internal_state(self) -> None:
        for name in ("minimum_contrast_stddev", "minimum_edge_variance"):
            for value in (float("nan"), float("inf"), -float("inf")):
                with self.subTest(field=name, value=value):
                    config = ImageQualityConfig()
                    # Test serialization separately from the constructor.
                    object.__setattr__(config, name, value)
                    with self.assertRaises(ValueError):
                        _ = config.content_sha256

    def test_valid_quality_numbers_remain_serializable_and_hash_compatible(
        self,
    ) -> None:
        for value in (0, -0.0, 0.25, 18, 250.0, 1 << 1023):
            config = ImageQualityConfig(
                minimum_contrast_stddev=value, minimum_edge_variance=value
            )
            with self.subTest(value=value):
                encoded = json.dumps(config.to_record(), allow_nan=False)
                self.assertTrue(
                    math.isfinite(json.loads(encoded)["minimum_edge_variance"])
                )
                self.assertEqual(len(config.content_sha256), 64)
        self.assertEqual(
            ImageQualityConfig().content_sha256,
            "94b3fd667d474c38aacbe2943ec90c1c023f5075efe4c2e2c35066141bb10baa",
        )
        self.assertEqual(
            ImageQualityConfig(minimum_contrast_stddev=18).content_sha256,
            ImageQualityConfig(minimum_contrast_stddev=18.0).content_sha256,
        )

    def test_ocr_timeout_and_confidence_reject_invalid_numbers_at_construction(
        self,
    ) -> None:
        common = (
            float("nan"),
            float("inf"),
            -float("inf"),
            1 << 1024,
            -1,
            True,
            False,
            "15",
            None,
            FloatSubclass(15),
            IntSubclass(15),
        )
        for name, invalid in (
            ("timeout_seconds", common + (0, -0.0)),
            ("minimum_mean_confidence", common + (100.01,)),
        ):
            for value in invalid:
                with self.subTest(field=name, value=value):
                    with self.assertRaisesRegex(ValueError, name):
                        TesseractConfig(**{name: value})

    def test_ocr_hash_rejects_nonfinite_internal_state(self) -> None:
        for name in ("minimum_mean_confidence", "timeout_seconds"):
            for value in (float("nan"), float("inf"), -float("inf")):
                with self.subTest(field=name, value=value):
                    config = TesseractConfig()
                    object.__setattr__(config, name, value)
                    with self.assertRaises(ValueError):
                        _ = config.content_sha256

    def test_valid_ocr_numbers_preserve_hash_and_runner_timeout(self) -> None:
        observed: list[float] = []

        def capture(command, **kwargs):
            observed.append(kwargs["timeout"])
            return subprocess.CompletedProcess(command, 0, b"tesseract 5.5.1\n", b"")

        for timeout in (0.25, 1, 15.0):
            for confidence in (0, -0.0, 70, 100.0):
                config = TesseractConfig(
                    timeout_seconds=timeout, minimum_mean_confidence=confidence
                )
                json.dumps(config.to_record(), allow_nan=False)
                engine = TesseractOcrEngine(
                    binary="python3", config=config, runner=capture
                )
                self.assertEqual(engine.engine_version(), "5.5.1")
                self.assertEqual(observed[-1], float(timeout))
                self.assertTrue(math.isfinite(observed[-1]))
        self.assertEqual(len(observed), 12)
        self.assertEqual(
            TesseractConfig().content_sha256,
            "601fd637b9771eee8c579a3e060f3fb795f76870278b8aa9048e021719dd228a",
        )
        self.assertEqual(
            TesseractConfig(timeout_seconds=15).content_sha256,
            TesseractConfig(timeout_seconds=15.0).content_sha256,
        )

    def test_pre_finite_configuration_pipeline_is_rejected_before_image_read(
        self,
    ) -> None:
        runner = FakeRunner()
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            current = build_tesseract_pipeline_spec(
                engine=engine, template=SYNTHETIC_PANEL_TEMPLATE
            )
            task = ReviewTask(
                task_id="pre-finite-configuration",
                evidence_manifest=rendered.manifest,
                approved_pipeline_spec=replace(current, pipeline_version="1.2"),
                reviewer_id="primary-reviewer",
            )
            complete_and_start_human_first(task)
            human_before = task.human_decisions()
            with self.assertRaises(VisionPipelineBindingError):
                run_gated_ocr_pair(
                    task,
                    run_id="run-001",
                    left_image_path="unread-before-finite-left.png",
                    right_image_path="unread-before-finite-right.png",
                    engine=engine,
                    template=SYNTHETIC_PANEL_TEMPLATE,
                )
        self.assertEqual(task._ai_results, {})
        self.assertEqual(task.human_decisions(), human_before)
        self.assertFalse(any("tsv" in command for command in runner.commands))


if __name__ == "__main__":
    unittest.main()
