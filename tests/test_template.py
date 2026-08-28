"""Tests for versioned fixed-layout OCR templates."""

from dataclasses import FrozenInstanceError, replace
import unittest

from paramguard.template import (
    BoundingBox,
    FixedTemplate,
    ParameterRegion,
    SYNTHETIC_PANEL_TEMPLATE,
)


class FixedTemplateTests(unittest.TestCase):
    def test_default_template_has_stable_order_and_digest(self) -> None:
        template = SYNTHETIC_PANEL_TEMPLATE
        self.assertEqual(
            template.expected_parameter_ids,
            ("temperature", "pressure", "speed", "mode"),
        )
        self.assertEqual(template.region_for("pressure").display_label, "Pressure")
        self.assertEqual(len(template.content_sha256), 64)
        self.assertEqual(template.content_sha256, template.content_sha256)

    def test_geometry_or_criticality_change_changes_digest(self) -> None:
        template = SYNTHETIC_PANEL_TEMPLATE
        moved_region = replace(
            template.regions[0], value_box=BoundingBox(671, 174, 1110, 246)
        )
        moved = replace(template, regions=(moved_region,) + template.regions[1:])
        changed_criticality = replace(
            template,
            regions=(replace(template.regions[0], critical=False),)
            + template.regions[1:],
        )

        self.assertNotEqual(moved.content_sha256, template.content_sha256)
        self.assertNotEqual(
            changed_criticality.content_sha256, template.content_sha256
        )

    def test_rejects_duplicate_or_out_of_canvas_regions(self) -> None:
        template = SYNTHETIC_PANEL_TEMPLATE
        with self.assertRaises(ValueError):
            replace(template, regions=(template.regions[0], template.regions[0]))
        with self.assertRaises(ValueError):
            FixedTemplate(
                template_id="bad-template",
                version="1.0",
                width=100,
                height=100,
                regions=(
                    ParameterRegion(
                        "field-1", "Field", BoundingBox(20, 20, 120, 60)
                    ),
                ),
            )

    def test_template_and_regions_are_frozen(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            SYNTHETIC_PANEL_TEMPLATE.width = 1  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            SYNTHETIC_PANEL_TEMPLATE.regions[0].critical = False  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
