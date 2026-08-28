"""Adversarial tests for the dependency-free registration quality gate."""

from dataclasses import replace
import math
import unittest

from paramguard.registration import (
    Point,
    RegistrationConfig,
    RegistrationEvidence,
    RegistrationFlag,
    RegistrationModel,
    RoiVisibility,
    assess_registration,
)


IDS = ("temperature", "pressure", "speed", "mode")
SOURCE_SHA256 = "a" * 64
TARGET_SHA256 = "b" * 64
TEMPLATE_SHA256 = "c" * 64
CORRESPONDENCE_SHA256 = "d" * 64


def good_evidence(**changes: object) -> RegistrationEvidence:
    values: dict[str, object] = {
        "source_image_sha256": SOURCE_SHA256,
        "target_image_sha256": TARGET_SHA256,
        "template_sha256": TEMPLATE_SHA256,
        "correspondence_set_sha256": CORRESPONDENCE_SHA256,
        "adapter_id": "future-registration-adapter",
        "adapter_version": "contract-only-2",
        "model": RegistrationModel.HOMOGRAPHY,
        "source_width": 1200,
        "source_height": 620,
        "target_width": 1200,
        "target_height": 620,
        "matched_points": 40,
        "inlier_count": 34,
        "median_reprojection_error_px": 1.2,
        "p95_reprojection_error_px": 3.5,
        "transform_matrix": (
            1.0,
            0.0,
            0.0,
            0.0,
            1.0,
            0.0,
            0.0,
            0.0,
            1.0,
        ),
        # Semantic order is source TL, TR, BR, BL after mapping.
        "mapped_source_corners": (
            Point(0.0, 0.0),
            Point(1200.0, 0.0),
            Point(1200.0, 620.0),
            Point(0.0, 620.0),
        ),
        "roi_visibility": tuple(RoiVisibility(item, 1.0) for item in IDS),
    }
    values.update(changes)
    return RegistrationEvidence(**values)  # type: ignore[arg-type]


def assess(
    evidence: RegistrationEvidence,
    *,
    expected_parameter_ids: tuple[str, ...] = IDS,
    config: RegistrationConfig = RegistrationConfig(),
    expected_source_image_sha256: str = SOURCE_SHA256,
    expected_target_image_sha256: str = TARGET_SHA256,
    expected_source_dimensions: tuple[int, int] = (1200, 620),
    expected_target_dimensions: tuple[int, int] = (1200, 620),
    expected_template_sha256: str = TEMPLATE_SHA256,
    expected_config_sha256: str | None = None,
):  # type: ignore[no-untyped-def]
    if expected_config_sha256 is None:
        expected_config_sha256 = config.content_sha256
    return assess_registration(
        evidence,
        expected_source_image_sha256=expected_source_image_sha256,
        expected_target_image_sha256=expected_target_image_sha256,
        expected_source_dimensions=expected_source_dimensions,
        expected_target_dimensions=expected_target_dimensions,
        expected_template_sha256=expected_template_sha256,
        expected_config_sha256=expected_config_sha256,
        expected_parameter_ids=expected_parameter_ids,
        config=config,
    )


class RegistrationValueObjectTests(unittest.TestCase):
    def test_good_evidence_is_ocr_eligible_but_never_release_authority(self) -> None:
        result = assess(good_evidence())

        self.assertTrue(result.acceptable_for_ocr)
        self.assertFalse(result.automatic_release_allowed)
        self.assertEqual(result.flags, ())
        self.assertAlmostEqual(result.inlier_ratio, 0.85)
        self.assertAlmostEqual(result.transform_determinant, 1.0)
        self.assertAlmostEqual(result.mapped_area_ratio or 0.0, 1.0)
        self.assertEqual(result.maximum_corner_consistency_error_px, 0.0)
        self.assertEqual(result.minimum_roi_visible_fraction, 1.0)
        self.assertRegex(result.expected_parameter_ids_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(result.content_sha256, r"^[0-9a-f]{64}$")
        self.assertFalse(result.to_record()["automatic_release_allowed"])

    def test_hashes_bind_provenance_geometry_thresholds_and_versions(self) -> None:
        evidence = good_evidence()
        moved = replace(
            evidence,
            mapped_source_corners=(
                Point(1.0, 0.0),
                *evidence.mapped_source_corners[1:],
            ),
        )
        changed_correspondences = replace(
            evidence, correspondence_set_sha256="e" * 64
        )
        config = RegistrationConfig()
        changed_config = replace(config, minimum_inlier_ratio=0.70)

        self.assertRegex(evidence.content_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(config.content_sha256, r"^[0-9a-f]{64}$")
        self.assertNotEqual(evidence.content_sha256, moved.content_sha256)
        self.assertNotEqual(
            evidence.content_sha256, changed_correspondences.content_sha256
        )
        self.assertNotEqual(config.content_sha256, changed_config.content_sha256)

    def test_hash_is_stable_for_negative_zero_and_homogeneous_matrix_scale(self) -> None:
        baseline = good_evidence()
        equivalent = good_evidence(
            transform_matrix=(
                -2.0,
                -0.0,
                -0.0,
                -0.0,
                -2.0,
                -0.0,
                -0.0,
                -0.0,
                -2.0,
            ),
            mapped_source_corners=(
                Point(-0.0, -0.0),
                Point(1200.0, -0.0),
                Point(1200.0, 620.0),
                Point(-0.0, 620.0),
            ),
        )

        self.assertEqual(baseline.transform_matrix, equivalent.transform_matrix)
        self.assertEqual(baseline.content_sha256, equivalent.content_sha256)
        self.assertEqual(
            RegistrationConfig(maximum_corner_outside_px=-0.0).content_sha256,
            RegistrationConfig(maximum_corner_outside_px=0.0).content_sha256,
        )

    def test_extreme_finite_homogeneous_scale_is_normalised_without_overflow(self) -> None:
        evidence = good_evidence(
            transform_matrix=(
                1e308,
                0.0,
                0.0,
                0.0,
                1e308,
                0.0,
                0.0,
                0.0,
                1e308,
            )
        )

        result = assess(evidence)
        self.assertTrue(result.acceptable_for_ocr)
        self.assertTrue(math.isfinite(result.transform_determinant))

    def test_malformed_types_nonfinite_values_and_impossible_counts_fail_early(self) -> None:
        with self.assertRaises(TypeError):
            Point(True, 1.0)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            Point(math.nan, 1.0)
        with self.assertRaises(ValueError):
            Point(1e20, 1.0)
        with self.assertRaises(ValueError):
            Point(10**10_000, 1.0)
        with self.assertRaises(ValueError):
            RoiVisibility("pressure", 1.01)
        with self.assertRaises(TypeError):
            RoiVisibility("pressure", True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            good_evidence(inlier_count=41)
        with self.assertRaises(ValueError):
            good_evidence(p95_reprojection_error_px=1.0)
        with self.assertRaises(ValueError):
            good_evidence(transform_matrix=(1.0,) * 8)
        with self.assertRaises(ValueError):
            good_evidence(transform_matrix=(math.inf,) + (0.0,) * 8)
        with self.assertRaises(TypeError):
            good_evidence(mapped_source_corners=(Point(0, 0),) * 3)
        with self.assertRaises(ValueError):
            good_evidence(source_width=True)
        with self.assertRaises(ValueError):
            good_evidence(matched_points=True)
        with self.assertRaises(ValueError):
            good_evidence(target_height=1_000_001)

    def test_duplicate_roi_ids_and_invalid_provenance_digests_fail_early(self) -> None:
        with self.assertRaises(ValueError):
            good_evidence(
                roi_visibility=(
                    RoiVisibility("temperature", 1.0),
                    RoiVisibility("temperature", 1.0),
                )
            )
        with self.assertRaises(ValueError):
            good_evidence(correspondence_set_sha256="not-a-digest")
        with self.assertRaises(ValueError):
            good_evidence(template_sha256="A" * 64)

    def test_threshold_config_cannot_be_weakened_below_safety_envelope(self) -> None:
        unsafe_changes = (
            {"minimum_matched_points": 11},
            {"minimum_inlier_points": 7},
            {"minimum_inlier_ratio": 0.64},
            {"maximum_median_reprojection_error_px": 2.51},
            {"maximum_p95_reprojection_error_px": 6.01},
            {"minimum_absolute_determinant": 0.0},
            {"minimum_mapped_area_ratio": 0.24},
            {"maximum_mapped_area_ratio": 1.76},
            {"maximum_corner_outside_px": 8.01},
            {"minimum_roi_visible_fraction": 0.97},
            {"maximum_corner_consistency_error_px": 0.011},
        )
        for changes in unsafe_changes:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                RegistrationConfig(**changes)  # type: ignore[arg-type]

    def test_config_relationships_bool_and_nonfinite_values_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            RegistrationConfig(minimum_matched_points=True)
        with self.assertRaises(ValueError):
            RegistrationConfig(minimum_inlier_points=8.0)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            RegistrationConfig(
                maximum_median_reprojection_error_px=2.0,
                maximum_p95_reprojection_error_px=1.0,
            )
        with self.assertRaises(ValueError):
            RegistrationConfig(
                minimum_mapped_area_ratio=1.5,
                maximum_mapped_area_ratio=1.4,
            )
        with self.assertRaises(ValueError):
            RegistrationConfig(minimum_inlier_ratio=math.nan)
        with self.assertRaises(TypeError):
            RegistrationConfig(allowed_model="HOMOGRAPHY")  # type: ignore[arg-type]


class RegistrationGateTests(unittest.TestCase):
    def test_manifest_image_template_and_adapter_bindings_are_mandatory(self) -> None:
        evidence = good_evidence(
            source_image_sha256="e" * 64,
            template_sha256="f" * 64,
            adapter_version="forged-version",
        )
        result = assess(evidence)

        self.assertEqual(
            result.flags[:3],
            (
                RegistrationFlag.IMAGE_BINDING_MISMATCH,
                RegistrationFlag.TEMPLATE_BINDING_MISMATCH,
                RegistrationFlag.ADAPTER_BINDING_MISMATCH,
            ),
        )
        self.assertFalse(result.acceptable_for_ocr)

    def test_decoded_dimensions_and_frozen_config_hash_are_bound(self) -> None:
        result = assess(
            good_evidence(),
            expected_source_dimensions=(1199, 620),
            expected_config_sha256="0" * 64,
        )

        self.assertIn(
            RegistrationFlag.IMAGE_DIMENSION_BINDING_MISMATCH, result.flags
        )
        self.assertIn(RegistrationFlag.CONFIG_BINDING_MISMATCH, result.flags)
        self.assertFalse(result.acceptable_for_ocr)
        self.assertEqual(result.expected_config_sha256, "0" * 64)
        self.assertEqual(result.expected_source_dimensions, (1199, 620))

    def test_expected_binding_values_are_strictly_validated(self) -> None:
        evidence = good_evidence()
        with self.assertRaises(ValueError):
            assess(evidence, expected_source_image_sha256="bad")
        with self.assertRaises(ValueError):
            assess(evidence, expected_template_sha256="F" * 64)
        with self.assertRaises(TypeError):
            assess(  # type: ignore[arg-type]
                evidence, expected_source_dimensions=[1200, 620]
            )
        with self.assertRaises(ValueError):
            assess(evidence, expected_target_dimensions=(1200, True))

    def test_model_mismatch_is_not_silently_coerced(self) -> None:
        result = assess(good_evidence(model=RegistrationModel.AFFINE))
        self.assertIn(RegistrationFlag.TRANSFORM_MODEL_MISMATCH, result.flags)
        self.assertFalse(result.acceptable_for_ocr)

    def test_declared_model_must_match_matrix_semantics(self) -> None:
        translation_config = replace(
            RegistrationConfig(), allowed_model=RegistrationModel.TRANSLATION
        )
        scaled_matrix = (
            2.0,
            0.0,
            0.0,
            0.0,
            2.0,
            0.0,
            0.0,
            0.0,
            1.0,
        )
        result = assess(
            good_evidence(
                model=RegistrationModel.TRANSLATION,
                transform_matrix=scaled_matrix,
                mapped_source_corners=(
                    Point(0.0, 0.0),
                    Point(2400.0, 0.0),
                    Point(2400.0, 1240.0),
                    Point(0.0, 1240.0),
                ),
            ),
            config=translation_config,
        )

        self.assertIn(
            RegistrationFlag.MODEL_MATRIX_SEMANTICS_MISMATCH, result.flags
        )

    def test_identity_requires_real_quality_evidence_not_zero_correspondences(self) -> None:
        identity_config = replace(
            RegistrationConfig(), allowed_model=RegistrationModel.IDENTITY
        )
        result = assess(
            good_evidence(
                model=RegistrationModel.IDENTITY,
                matched_points=0,
                inlier_count=0,
                median_reprojection_error_px=0.0,
                p95_reprojection_error_px=0.0,
            ),
            config=identity_config,
        )

        self.assertIn(RegistrationFlag.INSUFFICIENT_MATCHES, result.flags)
        self.assertIn(RegistrationFlag.INSUFFICIENT_INLIERS, result.flags)
        self.assertIn(RegistrationFlag.LOW_INLIER_RATIO, result.flags)
        self.assertNotIn(
            RegistrationFlag.MODEL_MATRIX_SEMANTICS_MISMATCH, result.flags
        )

    def test_identity_rejects_hidden_translation_even_when_corners_are_forged(self) -> None:
        identity_config = replace(
            RegistrationConfig(), allowed_model=RegistrationModel.IDENTITY
        )
        result = assess(
            good_evidence(
                model=RegistrationModel.IDENTITY,
                transform_matrix=(
                    1.0,
                    0.0,
                    5.0,
                    0.0,
                    1.0,
                    0.0,
                    0.0,
                    0.0,
                    1.0,
                ),
            ),
            config=identity_config,
        )

        self.assertIn(
            RegistrationFlag.MODEL_MATRIX_SEMANTICS_MISMATCH, result.flags
        )
        self.assertIn(RegistrationFlag.REPORTED_CORNER_MISMATCH, result.flags)

    def test_insufficient_matches_inliers_and_ratio_are_independent_flags(self) -> None:
        result = assess(good_evidence(matched_points=10, inlier_count=4))
        self.assertIn(RegistrationFlag.INSUFFICIENT_MATCHES, result.flags)
        self.assertIn(RegistrationFlag.INSUFFICIENT_INLIERS, result.flags)
        self.assertIn(RegistrationFlag.LOW_INLIER_RATIO, result.flags)

    def test_reprojection_error_limits_are_both_enforced(self) -> None:
        result = assess(
            good_evidence(
                median_reprojection_error_px=3.0,
                p95_reprojection_error_px=7.0,
            )
        )
        self.assertIn(
            RegistrationFlag.HIGH_MEDIAN_REPROJECTION_ERROR, result.flags
        )
        self.assertIn(RegistrationFlag.HIGH_P95_REPROJECTION_ERROR, result.flags)

    def test_degenerate_matrix_and_projective_pole_fail_closed(self) -> None:
        zero = assess(good_evidence(transform_matrix=(0.0,) * 9))
        pole = assess(
            good_evidence(
                transform_matrix=(
                    1.0,
                    0.0,
                    0.0,
                    0.0,
                    1.0,
                    0.0,
                    0.0,
                    0.0,
                    1e-20,
                )
            )
        )

        for result in (zero, pole):
            self.assertIn(RegistrationFlag.DEGENERATE_TRANSFORM, result.flags)
            self.assertIn(
                RegistrationFlag.TRANSFORM_MAPPING_INVALID, result.flags
            )
            self.assertIsNone(result.mapped_area_ratio)

    def test_projective_horizon_crossing_inside_source_is_invalid(self) -> None:
        result = assess(
            good_evidence(
                transform_matrix=(
                    1.0,
                    0.0,
                    0.0,
                    0.0,
                    1.0,
                    0.0,
                    -0.002,
                    0.0,
                    1.0,
                )
            )
        )

        self.assertIn(RegistrationFlag.TRANSFORM_MAPPING_INVALID, result.flags)
        self.assertIsNone(result.mapped_area_ratio)

    def test_reported_corners_are_recomputed_from_matrix(self) -> None:
        result = assess(
            good_evidence(
                mapped_source_corners=(
                    Point(1.0, 0.0),
                    Point(1200.0, 0.0),
                    Point(1200.0, 620.0),
                    Point(0.0, 620.0),
                )
            )
        )

        self.assertIn(RegistrationFlag.REPORTED_CORNER_MISMATCH, result.flags)
        self.assertEqual(result.maximum_corner_consistency_error_px, 1.0)

    def test_self_intersecting_concave_and_zero_area_quads_are_rejected(self) -> None:
        malformed_quads = (
            (
                Point(0.0, 0.0),
                Point(1200.0, 620.0),
                Point(1200.0, 0.0),
                Point(0.0, 620.0),
            ),
            (
                Point(0.0, 0.0),
                Point(1200.0, 0.0),
                Point(600.0, 300.0),
                Point(0.0, 620.0),
            ),
            (
                Point(0.0, 0.0),
                Point(1200.0, 0.0),
                Point(1200.0, 0.0),
                Point(0.0, 0.0),
            ),
        )
        for corners in malformed_quads:
            with self.subTest(corners=corners):
                result = assess(good_evidence(mapped_source_corners=corners))
                self.assertIn(
                    RegistrationFlag.MALFORMED_MAPPED_QUADRILATERAL,
                    result.flags,
                )
                self.assertIn(
                    RegistrationFlag.REPORTED_CORNER_MISMATCH, result.flags
                )

    def test_wrong_clockwise_corner_order_and_reflection_are_rejected(self) -> None:
        wrong_order = assess(
            good_evidence(
                mapped_source_corners=(
                    Point(0.0, 0.0),
                    Point(0.0, 620.0),
                    Point(1200.0, 620.0),
                    Point(1200.0, 0.0),
                )
            )
        )
        reflected = assess(
            good_evidence(
                transform_matrix=(
                    -1.0,
                    0.0,
                    1200.0,
                    0.0,
                    1.0,
                    0.0,
                    0.0,
                    0.0,
                    1.0,
                ),
                mapped_source_corners=(
                    Point(1200.0, 0.0),
                    Point(0.0, 0.0),
                    Point(0.0, 620.0),
                    Point(1200.0, 620.0),
                ),
            )
        )

        self.assertIn(RegistrationFlag.ORIENTATION_FLIPPED, wrong_order.flags)
        self.assertIn(RegistrationFlag.REPORTED_CORNER_MISMATCH, wrong_order.flags)
        self.assertIn(RegistrationFlag.ORIENTATION_FLIPPED, reflected.flags)

    def test_implausible_area_is_computed_from_matrix_not_reported_corners(self) -> None:
        result = assess(
            good_evidence(
                transform_matrix=(
                    0.01,
                    0.0,
                    0.0,
                    0.0,
                    0.01,
                    0.0,
                    0.0,
                    0.0,
                    1.0,
                )
            )
        )

        self.assertIn(RegistrationFlag.REPORTED_CORNER_MISMATCH, result.flags)
        self.assertIn(RegistrationFlag.IMPLAUSIBLE_MAPPED_AREA, result.flags)
        self.assertAlmostEqual(result.mapped_area_ratio or 0.0, 0.0001)

    def test_continuous_edge_boundary_is_inclusive_then_rejects_epsilon_outside(self) -> None:
        inclusive_matrix = (
            1.0,
            0.0,
            -8.0,
            0.0,
            1.0,
            0.0,
            0.0,
            0.0,
            1.0,
        )
        inclusive_corners = (
            Point(-8.0, 0.0),
            Point(1192.0, 0.0),
            Point(1192.0, 620.0),
            Point(-8.0, 620.0),
        )
        outside_matrix = (*inclusive_matrix[:2], -8.0001, *inclusive_matrix[3:])
        outside_corners = (
            Point(-8.0001, 0.0),
            Point(1191.9999, 0.0),
            Point(1191.9999, 620.0),
            Point(-8.0001, 620.0),
        )

        inclusive = assess(
            good_evidence(
                transform_matrix=inclusive_matrix,
                mapped_source_corners=inclusive_corners,
            )
        )
        outside = assess(
            good_evidence(
                transform_matrix=outside_matrix,
                mapped_source_corners=outside_corners,
            )
        )

        self.assertNotIn(
            RegistrationFlag.MAPPED_CORNERS_OUT_OF_BOUNDS, inclusive.flags
        )
        self.assertIn(
            RegistrationFlag.MAPPED_CORNERS_OUT_OF_BOUNDS, outside.flags
        )

    def test_missing_extra_reordered_or_low_visibility_roi_fails_closed(self) -> None:
        missing = assess(
            good_evidence(
                roi_visibility=tuple(
                    RoiVisibility(item, 1.0) for item in IDS[:-1]
                )
            )
        )
        extra = assess(
            good_evidence(
                roi_visibility=tuple(RoiVisibility(item, 1.0) for item in IDS)
                + (RoiVisibility("unexpected", 1.0),)
            )
        )
        reordered = assess(
            good_evidence(
                roi_visibility=tuple(
                    RoiVisibility(item, 1.0) for item in reversed(IDS)
                )
            )
        )
        low = assess(
            good_evidence(
                roi_visibility=tuple(
                    RoiVisibility(item, 0.50 if item == "pressure" else 1.0)
                    for item in IDS
                )
            )
        )

        self.assertIn(RegistrationFlag.ROI_COVERAGE_INCOMPLETE, missing.flags)
        self.assertIsNone(missing.minimum_roi_visible_fraction)
        self.assertIn(RegistrationFlag.ROI_COVERAGE_INCOMPLETE, extra.flags)
        self.assertIn(RegistrationFlag.ROI_ORDER_MISMATCH, reordered.flags)
        self.assertIn(RegistrationFlag.LOW_ROI_VISIBILITY, low.flags)
        self.assertEqual(low.minimum_roi_visible_fraction, 0.5)

    def test_expected_schema_must_be_frozen_exact_and_nonempty(self) -> None:
        evidence = good_evidence()
        with self.assertRaises(ValueError):
            assess(evidence, expected_parameter_ids=())
        with self.assertRaises(ValueError):
            assess(
                evidence,
                expected_parameter_ids=("temperature", "temperature"),
            )
        with self.assertRaises(ValueError):
            assess(evidence, expected_parameter_ids=("unsafe id",))
        with self.assertRaises(TypeError):
            assess(  # type: ignore[arg-type]
                evidence,
                expected_parameter_ids=[*IDS],
            )

    def test_expected_schema_order_is_bound_into_assessment_digest(self) -> None:
        forward = assess(good_evidence())
        reversed_ids = tuple(reversed(IDS))
        reverse = assess(
            good_evidence(
                roi_visibility=tuple(
                    RoiVisibility(item, 1.0) for item in reversed_ids
                )
            ),
            expected_parameter_ids=reversed_ids,
        )

        self.assertNotEqual(
            forward.expected_parameter_ids_sha256,
            reverse.expected_parameter_ids_sha256,
        )

    def test_1001_roi_contract_is_linear_exact_and_ordered(self) -> None:
        parameter_ids = tuple(f"p{index:04d}" for index in range(1001))
        evidence = good_evidence(
            roi_visibility=tuple(
                RoiVisibility(parameter_id, 1.0)
                for parameter_id in parameter_ids
            )
        )

        result = assess(evidence, expected_parameter_ids=parameter_ids)
        self.assertTrue(result.acceptable_for_ocr)
        self.assertEqual(result.minimum_roi_visible_fraction, 1.0)

    def test_combined_failure_flags_have_stable_declared_order(self) -> None:
        result = assess(
            good_evidence(
                source_image_sha256="e" * 64,
                template_sha256="f" * 64,
                adapter_id="forged-adapter",
                model=RegistrationModel.AFFINE,
                matched_points=1,
                inlier_count=0,
                median_reprojection_error_px=20.0,
                p95_reprojection_error_px=30.0,
                transform_matrix=(0.0,) * 9,
                mapped_source_corners=(
                    Point(0.0, 0.0),
                    Point(1200.0, 620.0),
                    Point(1200.0, 0.0),
                    Point(0.0, 620.0),
                ),
                roi_visibility=tuple(
                    RoiVisibility(item, 1.0) for item in reversed(IDS)
                ),
            ),
            expected_source_dimensions=(1199, 620),
            expected_config_sha256="0" * 64,
        )

        self.assertEqual(
            result.flags,
            (
                RegistrationFlag.IMAGE_BINDING_MISMATCH,
                RegistrationFlag.IMAGE_DIMENSION_BINDING_MISMATCH,
                RegistrationFlag.TEMPLATE_BINDING_MISMATCH,
                RegistrationFlag.CONFIG_BINDING_MISMATCH,
                RegistrationFlag.ADAPTER_BINDING_MISMATCH,
                RegistrationFlag.TRANSFORM_MODEL_MISMATCH,
                RegistrationFlag.INSUFFICIENT_MATCHES,
                RegistrationFlag.INSUFFICIENT_INLIERS,
                RegistrationFlag.LOW_INLIER_RATIO,
                RegistrationFlag.HIGH_MEDIAN_REPROJECTION_ERROR,
                RegistrationFlag.HIGH_P95_REPROJECTION_ERROR,
                RegistrationFlag.MODEL_MATRIX_SEMANTICS_MISMATCH,
                RegistrationFlag.DEGENERATE_TRANSFORM,
                RegistrationFlag.TRANSFORM_MAPPING_INVALID,
                RegistrationFlag.MALFORMED_MAPPED_QUADRILATERAL,
                RegistrationFlag.IMPLAUSIBLE_MAPPED_AREA,
                RegistrationFlag.ROI_ORDER_MISMATCH,
            ),
        )
        self.assertFalse(result.automatic_release_allowed)


if __name__ == "__main__":
    unittest.main()
