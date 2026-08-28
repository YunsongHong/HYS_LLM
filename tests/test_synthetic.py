"""Tests for deterministic, company-independent synthetic image evidence."""

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from PIL import Image

from paramguard.comparison import ComparisonKind
from paramguard.image_quality import (
    ImageQualityFlag,
    assess_image_quality,
    assess_image_quality_bytes,
)
from paramguard.synthetic import (
    SyntheticCaseSpec,
    SyntheticDegradation,
    SyntheticValuePair,
    default_clean_case,
    render_case,
)
from paramguard.template import SYNTHETIC_PANEL_TEMPLATE


class SyntheticImageTests(unittest.TestCase):
    def test_clean_case_renders_two_frozen_images_and_ground_truth(self) -> None:
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)

            self.assertTrue(rendered.left_image_path.is_file())
            self.assertTrue(rendered.right_image_path.is_file())
            self.assertNotEqual(
                rendered.left_image_path.read_bytes(),
                rendered.right_image_path.read_bytes(),
            )
            with Image.open(rendered.left_image_path) as image:
                self.assertEqual(
                    image.size,
                    (
                        SYNTHETIC_PANEL_TEMPLATE.width,
                        SYNTHETIC_PANEL_TEMPLATE.height,
                    ),
                )
            self.assertEqual(
                rendered.manifest.expected_parameter_ids,
                SYNTHETIC_PANEL_TEMPLATE.expected_parameter_ids,
            )
            self.assertEqual(
                rendered.manifest.template_sha256,
                SYNTHETIC_PANEL_TEMPLATE.content_sha256,
            )
            rendered.manifest.assert_artifact_content(
                artifact_id="clean-demo-001-photo-a",
                content=rendered.left_image_path.read_bytes(),
            )

            comparisons = {
                item.parameter_id: item.expected_comparison
                for item in rendered.spec.values
            }
            self.assertEqual(
                comparisons["temperature"].kind, ComparisonKind.EXACT_MATCH
            )
            self.assertEqual(
                comparisons["pressure"].kind, ComparisonKind.VALUE_MISMATCH
            )
            self.assertEqual(
                comparisons["speed"].kind, ComparisonKind.FORMAT_DIFFERENCE
            )

    def test_schema_order_must_exactly_match_template_before_render(self) -> None:
        original = default_clean_case()
        wrong_order = replace(
            original,
            case_id="wrong-order",
            values=(original.values[1], original.values[0]) + original.values[2:],
        )
        with TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                render_case(wrong_order, output_root=directory)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_missing_value_is_explicit_ground_truth_not_empty_string(self) -> None:
        case = SyntheticCaseSpec(
            case_id="missing-field",
            values=(
                SyntheticValuePair("temperature", None, "37.0 C"),
                SyntheticValuePair("pressure", "1.2 bar", "1.2 bar"),
                SyntheticValuePair("speed", "800 rpm", "800 rpm"),
                SyntheticValuePair("mode", "AUTO", "AUTO"),
            ),
        )
        self.assertEqual(
            case.values[0].expected_comparison.kind,
            ComparisonKind.MISSING_VALUE,
        )

    def test_quality_gate_flags_low_contrast_and_blur_reduces_edge_detail(self) -> None:
        clean = default_clean_case()
        low_contrast = replace(
            clean,
            case_id="low-contrast",
            left_degradation=SyntheticDegradation.LOW_CONTRAST,
        )
        blurred = replace(
            clean,
            case_id="blurred",
            left_degradation=SyntheticDegradation.BLUR,
        )
        with TemporaryDirectory() as directory:
            clean_rendered = render_case(clean, output_root=directory)
            low_rendered = render_case(low_contrast, output_root=directory)
            blur_rendered = render_case(blurred, output_root=directory)
            clean_quality = assess_image_quality(
                clean_rendered.left_image_path,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )
            low_quality = assess_image_quality(
                low_rendered.left_image_path,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )
            blur_quality = assess_image_quality(
                blur_rendered.left_image_path,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )

        self.assertTrue(clean_quality.acceptable_for_ocr)
        self.assertIn(ImageQualityFlag.LOW_CONTRAST, low_quality.flags)
        self.assertLess(blur_quality.edge_variance, clean_quality.edge_variance)

    def test_quality_bytes_api_matches_path_and_requires_immutable_input(self) -> None:
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            content = rendered.left_image_path.read_bytes()
            expected = assess_image_quality(
                rendered.left_image_path, template=SYNTHETIC_PANEL_TEMPLATE
            )
        actual = assess_image_quality_bytes(content, template=SYNTHETIC_PANEL_TEMPLATE)
        self.assertEqual(actual, expected)
        for invalid in (bytearray(content), memoryview(content), None, "image.png"):
            with self.subTest(kind=type(invalid).__name__), self.assertRaises(
                TypeError
            ):
                assess_image_quality_bytes(invalid, template=SYNTHETIC_PANEL_TEMPLATE)
        with self.assertRaises(ValueError):
            assess_image_quality_bytes(b"", template=SYNTHETIC_PANEL_TEMPLATE)


if __name__ == "__main__":
    unittest.main()
