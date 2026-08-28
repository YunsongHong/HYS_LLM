"""Versioned, fail-closed quality gate for future image registration.

This module intentionally does *not* estimate a transform.  A future, separately
reviewed adapter may produce :class:`RegistrationEvidence`; this domain layer
validates that evidence and decides whether aligned crops are even eligible for
OCR.  It never changes original evidence, compares parameter values, or
authorises release.

The adapter remains a trust boundary: without the original correspondence and
ROI artifacts, this module cannot prove that its reported metrics came from the
bound images.  It does, however, bind the report to expected hashes, recompute
all geometry that can be derived from the matrix, enforce a non-weakenable
safety envelope, and reject malformed or internally inconsistent evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
import re


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

# These bounds are input-safety limits, not claims about camera performance.
_MAX_IMAGE_DIMENSION = 1_000_000
_MAX_MATCHED_POINTS = 10_000_000
_MAX_ABSOLUTE_COORDINATE = 1_000_000_000.0
_MATRIX_STRUCTURE_TOLERANCE = 1e-9
_PROJECTIVE_DENOMINATOR_TOLERANCE = 1e-12

# A caller may make a configuration stricter, but cannot make it weaker than
# this versioned PoC envelope.  The values still require challenge-set
# calibration before any real deployment.
_SAFETY_MIN_MATCHED_POINTS = 12
_SAFETY_MIN_INLIER_POINTS = 8
_SAFETY_MIN_INLIER_RATIO = 0.65
_SAFETY_MAX_MEDIAN_ERROR_PX = 2.5
_SAFETY_MAX_P95_ERROR_PX = 6.0
_SAFETY_MIN_ABSOLUTE_DETERMINANT = 1e-8
_SAFETY_MIN_MAPPED_AREA_RATIO = 0.25
_SAFETY_MAX_MAPPED_AREA_RATIO = 1.75
_SAFETY_MAX_CORNER_OUTSIDE_PX = 8.0
_SAFETY_MIN_ROI_VISIBLE_FRACTION = 0.98
_SAFETY_MAX_CORNER_CONSISTENCY_ERROR_PX = 0.01


class RegistrationModel(str, Enum):
    """Closed set of transform families an approved adapter may report."""

    IDENTITY = "IDENTITY"
    TRANSLATION = "TRANSLATION"
    EUCLIDEAN = "EUCLIDEAN"
    AFFINE = "AFFINE"
    HOMOGRAPHY = "HOMOGRAPHY"


class RegistrationFlag(str, Enum):
    """Stable, ordered reasons that prevent evidence from reaching OCR."""

    IMAGE_BINDING_MISMATCH = "IMAGE_BINDING_MISMATCH"
    IMAGE_DIMENSION_BINDING_MISMATCH = "IMAGE_DIMENSION_BINDING_MISMATCH"
    TEMPLATE_BINDING_MISMATCH = "TEMPLATE_BINDING_MISMATCH"
    CONFIG_BINDING_MISMATCH = "CONFIG_BINDING_MISMATCH"
    ADAPTER_BINDING_MISMATCH = "ADAPTER_BINDING_MISMATCH"
    TRANSFORM_MODEL_MISMATCH = "TRANSFORM_MODEL_MISMATCH"
    INSUFFICIENT_MATCHES = "INSUFFICIENT_MATCHES"
    INSUFFICIENT_INLIERS = "INSUFFICIENT_INLIERS"
    LOW_INLIER_RATIO = "LOW_INLIER_RATIO"
    HIGH_MEDIAN_REPROJECTION_ERROR = "HIGH_MEDIAN_REPROJECTION_ERROR"
    HIGH_P95_REPROJECTION_ERROR = "HIGH_P95_REPROJECTION_ERROR"
    MODEL_MATRIX_SEMANTICS_MISMATCH = "MODEL_MATRIX_SEMANTICS_MISMATCH"
    DEGENERATE_TRANSFORM = "DEGENERATE_TRANSFORM"
    TRANSFORM_MAPPING_INVALID = "TRANSFORM_MAPPING_INVALID"
    REPORTED_CORNER_MISMATCH = "REPORTED_CORNER_MISMATCH"
    MALFORMED_MAPPED_QUADRILATERAL = "MALFORMED_MAPPED_QUADRILATERAL"
    ORIENTATION_FLIPPED = "ORIENTATION_FLIPPED"
    IMPLAUSIBLE_MAPPED_AREA = "IMPLAUSIBLE_MAPPED_AREA"
    MAPPED_CORNERS_OUT_OF_BOUNDS = "MAPPED_CORNERS_OUT_OF_BOUNDS"
    ROI_COVERAGE_INCOMPLETE = "ROI_COVERAGE_INCOMPLETE"
    ROI_ORDER_MISMATCH = "ROI_ORDER_MISMATCH"
    LOW_ROI_VISIBILITY = "LOW_ROI_VISIBILITY"


_MINIMUM_CORRESPONDENCES = {
    RegistrationModel.IDENTITY: 0,
    RegistrationModel.TRANSLATION: 1,
    RegistrationModel.EUCLIDEAN: 2,
    RegistrationModel.AFFINE: 3,
    RegistrationModel.HOMOGRAPHY: 4,
}


def _require_identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe 1-128 character identifier")
    return value


def _require_sha256(name: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _require_image_dimensions(name: str, value: object) -> tuple[int, int]:
    if not isinstance(value, tuple) or len(value) != 2:
        raise TypeError(f"{name} must be a (width, height) tuple")
    width, height = value
    if (
        type(width) is not int
        or type(height) is not int
        or not 1 <= width <= _MAX_IMAGE_DIMENSION
        or not 1 <= height <= _MAX_IMAGE_DIMENSION
    ):
        raise ValueError(f"{name} must contain positive ints within the safety bound")
    return width, height


def _require_finite_number(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a finite number")
    try:
        checked = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be a finite number") from exc
    if not math.isfinite(checked):
        raise ValueError(f"{name} must be a finite number")
    # JSON has two spellings for a floating-point zero.  Canonicalising here
    # prevents semantically identical evidence from receiving different hashes.
    return 0.0 if checked == 0.0 else checked


def _canonical_sha256(record: object) -> str:
    encoded = json.dumps(
        record,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _determinant(matrix: tuple[float, ...]) -> float:
    a, b, c, d, e, f, g, h, i = matrix
    return (
        a * (e * i - f * h)
        - b * (d * i - f * g)
        + c * (d * h - e * g)
    )


def _canonical_projective_matrix(
    matrix: tuple[float, ...],
) -> tuple[float, ...]:
    """Remove arbitrary homogeneous scale without overflowing arithmetic."""

    maximum = max(abs(value) for value in matrix)
    if maximum == 0.0:
        return (0.0,) * 9
    normalised = tuple(
        0.0 if (value / maximum) == 0.0 else value / maximum
        for value in matrix
    )
    first_nonzero = next(value for value in normalised if value != 0.0)
    if first_nonzero < 0.0:
        normalised = tuple(0.0 if value == 0.0 else -value for value in normalised)
    return normalised


def _bottom_right_normalised_matrix(
    matrix: tuple[float, ...],
) -> tuple[float, ...] | None:
    scale = matrix[8]
    if abs(scale) <= _MATRIX_STRUCTURE_TOLERANCE:
        return None
    return tuple(0.0 if value / scale == 0.0 else value / scale for value in matrix)


def _is_close(left: float, right: float) -> bool:
    return math.isclose(
        left,
        right,
        rel_tol=_MATRIX_STRUCTURE_TOLERANCE,
        abs_tol=_MATRIX_STRUCTURE_TOLERANCE,
    )


def _matrix_has_model_semantics(
    matrix: tuple[float, ...], model: RegistrationModel
) -> bool:
    """Check that the coefficients actually belong to the declared family."""

    if model is RegistrationModel.HOMOGRAPHY:
        return True
    normalised = _bottom_right_normalised_matrix(matrix)
    if normalised is None:
        return False
    a, b, _c, d, e, _f, g, h, i = normalised
    if not (_is_close(g, 0.0) and _is_close(h, 0.0) and _is_close(i, 1.0)):
        return False
    if model is RegistrationModel.AFFINE:
        return True
    if model is RegistrationModel.IDENTITY:
        return (
            _is_close(a, 1.0)
            and _is_close(b, 0.0)
            and _is_close(d, 0.0)
            and _is_close(e, 1.0)
            and _is_close(normalised[2], 0.0)
            and _is_close(normalised[5], 0.0)
        )
    if model is RegistrationModel.TRANSLATION:
        return (
            _is_close(a, 1.0)
            and _is_close(b, 0.0)
            and _is_close(d, 0.0)
            and _is_close(e, 1.0)
        )
    # A Euclidean transform is a proper rotation plus translation; reflection
    # and scale/shear are intentionally excluded.
    return (
        _is_close(e, a)
        and _is_close(b, -d)
        and _is_close(a * a + d * d, 1.0)
    )


@dataclass(frozen=True, slots=True)
class Point:
    """One finite point in continuous target-image edge coordinates."""

    x: float
    y: float

    def __post_init__(self) -> None:
        x = _require_finite_number("x", self.x)
        y = _require_finite_number("y", self.y)
        if abs(x) > _MAX_ABSOLUTE_COORDINATE or abs(y) > _MAX_ABSOLUTE_COORDINATE:
            raise ValueError("point coordinate exceeds the input-safety bound")
        object.__setattr__(self, "x", x)
        object.__setattr__(self, "y", y)

    def to_record(self) -> dict[str, float]:
        return {"x": self.x, "y": self.y}


@dataclass(frozen=True, slots=True)
class RoiVisibility:
    """Adapter-measured visible fraction for one frozen parameter ROI."""

    parameter_id: str
    visible_fraction: float

    def __post_init__(self) -> None:
        _require_identifier("parameter_id", self.parameter_id)
        checked = _require_finite_number("visible_fraction", self.visible_fraction)
        if not 0.0 <= checked <= 1.0:
            raise ValueError("visible_fraction must be in [0, 1]")
        object.__setattr__(self, "visible_fraction", checked)

    def to_record(self) -> dict[str, object]:
        return {
            "parameter_id": self.parameter_id,
            "visible_fraction": self.visible_fraction,
        }


@dataclass(frozen=True, slots=True)
class RegistrationConfig:
    """Required adapter labels and non-weakenable transform thresholds."""

    config_id: str = "fixed-panel-registration-gate"
    version: str = "2.0"
    required_adapter_id: str = "future-registration-adapter"
    required_adapter_version: str = "contract-only-2"
    allowed_model: RegistrationModel = RegistrationModel.HOMOGRAPHY
    minimum_matched_points: int = _SAFETY_MIN_MATCHED_POINTS
    minimum_inlier_points: int = _SAFETY_MIN_INLIER_POINTS
    minimum_inlier_ratio: float = _SAFETY_MIN_INLIER_RATIO
    maximum_median_reprojection_error_px: float = _SAFETY_MAX_MEDIAN_ERROR_PX
    maximum_p95_reprojection_error_px: float = _SAFETY_MAX_P95_ERROR_PX
    minimum_absolute_determinant: float = _SAFETY_MIN_ABSOLUTE_DETERMINANT
    minimum_mapped_area_ratio: float = _SAFETY_MIN_MAPPED_AREA_RATIO
    maximum_mapped_area_ratio: float = _SAFETY_MAX_MAPPED_AREA_RATIO
    maximum_corner_outside_px: float = _SAFETY_MAX_CORNER_OUTSIDE_PX
    minimum_roi_visible_fraction: float = _SAFETY_MIN_ROI_VISIBLE_FRACTION
    maximum_corner_consistency_error_px: float = (
        _SAFETY_MAX_CORNER_CONSISTENCY_ERROR_PX
    )

    def __post_init__(self) -> None:
        _require_identifier("config_id", self.config_id)
        _require_identifier("version", self.version)
        _require_identifier("required_adapter_id", self.required_adapter_id)
        _require_identifier("required_adapter_version", self.required_adapter_version)
        if not isinstance(self.allowed_model, RegistrationModel):
            raise TypeError("allowed_model must be a RegistrationModel")
        for name in ("minimum_matched_points", "minimum_inlier_points"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= _MAX_MATCHED_POINTS:
                raise ValueError(
                    f"{name} must be a non-negative int within the safety bound"
                )
        if self.minimum_matched_points < max(
            _SAFETY_MIN_MATCHED_POINTS,
            _MINIMUM_CORRESPONDENCES[self.allowed_model],
        ):
            raise ValueError("minimum_matched_points weakens the safety envelope")
        if self.minimum_inlier_points < max(
            _SAFETY_MIN_INLIER_POINTS,
            _MINIMUM_CORRESPONDENCES[self.allowed_model],
        ):
            raise ValueError("minimum_inlier_points weakens the safety envelope")

        ratio_names = ("minimum_inlier_ratio", "minimum_roi_visible_fraction")
        for name in ratio_names:
            checked = _require_finite_number(name, getattr(self, name))
            if not 0.0 <= checked <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]")
            object.__setattr__(self, name, checked)

        nonnegative_names = (
            "maximum_median_reprojection_error_px",
            "maximum_p95_reprojection_error_px",
            "minimum_absolute_determinant",
            "minimum_mapped_area_ratio",
            "maximum_mapped_area_ratio",
            "maximum_corner_outside_px",
            "maximum_corner_consistency_error_px",
        )
        for name in nonnegative_names:
            checked = _require_finite_number(name, getattr(self, name))
            if checked < 0.0:
                raise ValueError(f"{name} must be non-negative")
            object.__setattr__(self, name, checked)

        if self.minimum_inlier_ratio < _SAFETY_MIN_INLIER_RATIO:
            raise ValueError("minimum_inlier_ratio weakens the safety envelope")
        if self.maximum_median_reprojection_error_px > _SAFETY_MAX_MEDIAN_ERROR_PX:
            raise ValueError(
                "maximum_median_reprojection_error_px weakens the safety envelope"
            )
        if self.maximum_p95_reprojection_error_px > _SAFETY_MAX_P95_ERROR_PX:
            raise ValueError("maximum_p95_reprojection_error_px weakens the safety envelope")
        if self.minimum_absolute_determinant < _SAFETY_MIN_ABSOLUTE_DETERMINANT:
            raise ValueError("minimum_absolute_determinant weakens the safety envelope")
        if self.minimum_mapped_area_ratio < _SAFETY_MIN_MAPPED_AREA_RATIO:
            raise ValueError("minimum_mapped_area_ratio weakens the safety envelope")
        if self.maximum_mapped_area_ratio > _SAFETY_MAX_MAPPED_AREA_RATIO:
            raise ValueError("maximum_mapped_area_ratio weakens the safety envelope")
        if self.maximum_corner_outside_px > _SAFETY_MAX_CORNER_OUTSIDE_PX:
            raise ValueError("maximum_corner_outside_px weakens the safety envelope")
        if self.minimum_roi_visible_fraction < _SAFETY_MIN_ROI_VISIBLE_FRACTION:
            raise ValueError("minimum_roi_visible_fraction weakens the safety envelope")
        if (
            self.maximum_corner_consistency_error_px
            > _SAFETY_MAX_CORNER_CONSISTENCY_ERROR_PX
        ):
            raise ValueError(
                "maximum_corner_consistency_error_px weakens the safety envelope"
            )
        if (
            self.maximum_p95_reprojection_error_px
            < self.maximum_median_reprojection_error_px
        ):
            raise ValueError(
                "maximum_p95_reprojection_error_px must be at least the median limit"
            )
        if self.maximum_mapped_area_ratio < self.minimum_mapped_area_ratio:
            raise ValueError(
                "maximum_mapped_area_ratio must be at least the minimum"
            )

    def to_record(self) -> dict[str, object]:
        return {
            "registration_config_schema_version": 2,
            "config_id": self.config_id,
            "version": self.version,
            "required_adapter_id": self.required_adapter_id,
            "required_adapter_version": self.required_adapter_version,
            "allowed_model": self.allowed_model.value,
            "minimum_matched_points": self.minimum_matched_points,
            "minimum_inlier_points": self.minimum_inlier_points,
            "minimum_inlier_ratio": self.minimum_inlier_ratio,
            "maximum_median_reprojection_error_px": (
                self.maximum_median_reprojection_error_px
            ),
            "maximum_p95_reprojection_error_px": (
                self.maximum_p95_reprojection_error_px
            ),
            "minimum_absolute_determinant": self.minimum_absolute_determinant,
            "minimum_mapped_area_ratio": self.minimum_mapped_area_ratio,
            "maximum_mapped_area_ratio": self.maximum_mapped_area_ratio,
            "maximum_corner_outside_px": self.maximum_corner_outside_px,
            "minimum_roi_visible_fraction": self.minimum_roi_visible_fraction,
            "maximum_corner_consistency_error_px": (
                self.maximum_corner_consistency_error_px
            ),
            "failure_action": "ABSTAIN_AND_ESCALATE_QA",
            "automatic_release_allowed": False,
        }

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_record())


DEFAULT_REGISTRATION_CONFIG = RegistrationConfig()


@dataclass(frozen=True, slots=True)
class RegistrationEvidence:
    """Canonical adapter report plus digest binding to retained raw artifacts."""

    source_image_sha256: str
    target_image_sha256: str
    template_sha256: str
    correspondence_set_sha256: str
    adapter_id: str
    adapter_version: str
    model: RegistrationModel
    source_width: int
    source_height: int
    target_width: int
    target_height: int
    matched_points: int
    inlier_count: int
    median_reprojection_error_px: float
    p95_reprojection_error_px: float
    transform_matrix: tuple[float, ...]
    mapped_source_corners: tuple[Point, Point, Point, Point]
    roi_visibility: tuple[RoiVisibility, ...]

    def __post_init__(self) -> None:
        _require_sha256("source_image_sha256", self.source_image_sha256)
        _require_sha256("target_image_sha256", self.target_image_sha256)
        _require_sha256("template_sha256", self.template_sha256)
        _require_sha256("correspondence_set_sha256", self.correspondence_set_sha256)
        _require_identifier("adapter_id", self.adapter_id)
        _require_identifier("adapter_version", self.adapter_version)
        if not isinstance(self.model, RegistrationModel):
            raise TypeError("model must be a RegistrationModel")
        for name in (
            "source_width",
            "source_height",
            "target_width",
            "target_height",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= _MAX_IMAGE_DIMENSION:
                raise ValueError(
                    f"{name} must be a positive int within the safety bound"
                )
        for name in ("matched_points", "inlier_count"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= _MAX_MATCHED_POINTS:
                raise ValueError(
                    f"{name} must be a non-negative int within the safety bound"
                )
        if self.inlier_count > self.matched_points:
            raise ValueError("inlier_count cannot exceed matched_points")

        median = _require_finite_number(
            "median_reprojection_error_px", self.median_reprojection_error_px
        )
        p95 = _require_finite_number(
            "p95_reprojection_error_px", self.p95_reprojection_error_px
        )
        if median < 0.0 or p95 < 0.0:
            raise ValueError("reprojection errors must be non-negative")
        if p95 < median:
            raise ValueError("p95 reprojection error cannot be below the median")
        object.__setattr__(self, "median_reprojection_error_px", median)
        object.__setattr__(self, "p95_reprojection_error_px", p95)

        if not isinstance(self.transform_matrix, tuple) or len(
            self.transform_matrix
        ) != 9:
            raise ValueError("transform_matrix must be a tuple of 9 numbers")
        checked_matrix = tuple(
            _require_finite_number("transform coefficient", value)
            for value in self.transform_matrix
        )
        object.__setattr__(
            self,
            "transform_matrix",
            _canonical_projective_matrix(checked_matrix),
        )

        if (
            not isinstance(self.mapped_source_corners, tuple)
            or len(self.mapped_source_corners) != 4
            or any(not isinstance(point, Point) for point in self.mapped_source_corners)
        ):
            raise TypeError(
                "mapped_source_corners must contain exactly four Point values"
            )
        if not isinstance(self.roi_visibility, tuple):
            raise TypeError("roi_visibility must be a tuple")
        if any(not isinstance(item, RoiVisibility) for item in self.roi_visibility):
            raise TypeError("roi_visibility must contain RoiVisibility values")
        ids = tuple(item.parameter_id for item in self.roi_visibility)
        if len(ids) != len(set(ids)):
            raise ValueError("roi_visibility parameter IDs must not repeat")

    @property
    def inlier_ratio(self) -> float:
        if self.matched_points == 0:
            return 0.0
        return self.inlier_count / self.matched_points

    @property
    def dimensionless_transform_matrix(self) -> tuple[float, ...]:
        """Return the transform in normalised source/target coordinates."""

        a, b, c, d, e, f, g, h, i = self.transform_matrix
        sw = float(self.source_width)
        sh = float(self.source_height)
        tw = float(self.target_width)
        th = float(self.target_height)
        converted = (
            a * sw / tw,
            b * sh / tw,
            c / tw,
            d * sw / th,
            e * sh / th,
            f / th,
            g * sw,
            h * sh,
            i,
        )
        return _canonical_projective_matrix(converted)

    @property
    def transform_determinant(self) -> float:
        return _determinant(self.dimensionless_transform_matrix)

    @property
    def derived_mapped_source_corners(
        self,
    ) -> tuple[Point, Point, Point, Point] | None:
        """Map TL, TR, BR, BL source edges locally from the matrix."""

        source_corners = (
            (0.0, 0.0),
            (float(self.source_width), 0.0),
            (float(self.source_width), float(self.source_height)),
            (0.0, float(self.source_height)),
        )
        a, b, c, d, e, f, g, h, i = self.transform_matrix
        mapped: list[Point] = []
        denominators: list[float] = []
        for x, y in source_corners:
            denominator_terms = (g * x, h * y, i)
            denominator = sum(denominator_terms)
            scale = max(1.0, *(abs(value) for value in denominator_terms))
            if abs(denominator) <= _PROJECTIVE_DENOMINATOR_TOLERANCE * scale:
                return None
            denominators.append(denominator)
            mapped_x = (a * x + b * y + c) / denominator
            mapped_y = (d * x + e * y + f) / denominator
            if (
                not math.isfinite(mapped_x)
                or not math.isfinite(mapped_y)
                or abs(mapped_x) > _MAX_ABSOLUTE_COORDINATE
                or abs(mapped_y) > _MAX_ABSOLUTE_COORDINATE
            ):
                return None
            mapped.append(Point(mapped_x, mapped_y))
        # The homogeneous denominator is linear over the source rectangle.  If
        # its sign differs at any corner, it is zero somewhere on or inside the
        # rectangle: the warp crosses the projective horizon even when all four
        # endpoint divisions happened to be finite.
        if any(value > 0.0 for value in denominators) and any(
            value < 0.0 for value in denominators
        ):
            return None
        return (mapped[0], mapped[1], mapped[2], mapped[3])

    def to_record(self) -> dict[str, object]:
        return {
            "registration_evidence_schema_version": 2,
            "source_image_sha256": self.source_image_sha256,
            "target_image_sha256": self.target_image_sha256,
            "template_sha256": self.template_sha256,
            "correspondence_set_sha256": self.correspondence_set_sha256,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "model": self.model.value,
            "source_width": self.source_width,
            "source_height": self.source_height,
            "target_width": self.target_width,
            "target_height": self.target_height,
            "matched_points": self.matched_points,
            "inlier_count": self.inlier_count,
            "median_reprojection_error_px": self.median_reprojection_error_px,
            "p95_reprojection_error_px": self.p95_reprojection_error_px,
            "transform_matrix": list(self.transform_matrix),
            "mapped_source_corners": [
                point.to_record() for point in self.mapped_source_corners
            ],
            "roi_visibility": [item.to_record() for item in self.roi_visibility],
        }

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_record())


def _signed_polygon_area(points: tuple[Point, Point, Point, Point]) -> float:
    twice_area = 0.0
    for index, current in enumerate(points):
        following = points[(index + 1) % len(points)]
        twice_area += current.x * following.y - following.x * current.y
    return twice_area / 2.0


def _quadrilateral_winding(
    points: tuple[Point, Point, Point, Point],
) -> str:
    """Return ``CCW``, ``CW``, or ``MALFORMED`` for strict convex ordering."""

    min_x = min(point.x for point in points)
    max_x = max(point.x for point in points)
    min_y = min(point.y for point in points)
    max_y = max(point.y for point in points)
    scale = max(1.0, (max_x - min_x) * (max_y - min_y))
    tolerance = 1e-12 * scale
    crosses: list[float] = []
    for index, current in enumerate(points):
        following = points[(index + 1) % 4]
        after = points[(index + 2) % 4]
        crosses.append(
            (following.x - current.x) * (after.y - following.y)
            - (following.y - current.y) * (after.x - following.x)
        )
    if all(value > tolerance for value in crosses):
        return "CCW"
    if all(value < -tolerance for value in crosses):
        return "CW"
    return "MALFORMED"


def _maximum_corner_error(
    reported: tuple[Point, Point, Point, Point],
    derived: tuple[Point, Point, Point, Point],
) -> float:
    return max(
        math.hypot(left.x - right.x, left.y - right.y)
        for left, right in zip(reported, derived, strict=True)
    )


@dataclass(frozen=True, slots=True)
class RegistrationAssessment:
    """Deterministic gate result; acceptance means OCR eligibility only."""

    evidence_sha256: str
    config_sha256: str
    expected_config_sha256: str
    expected_source_image_sha256: str
    expected_target_image_sha256: str
    expected_source_dimensions: tuple[int, int]
    expected_target_dimensions: tuple[int, int]
    expected_template_sha256: str
    expected_parameter_ids_sha256: str
    inlier_ratio: float
    transform_determinant: float
    signed_mapped_area_px: float | None
    mapped_area_ratio: float | None
    maximum_corner_consistency_error_px: float | None
    minimum_roi_visible_fraction: float | None
    flags: tuple[RegistrationFlag, ...]

    @property
    def acceptable_for_ocr(self) -> bool:
        return not self.flags

    @property
    def automatic_release_allowed(self) -> bool:
        return False

    def to_record(self) -> dict[str, object]:
        return {
            "registration_assessment_schema_version": 1,
            "evidence_sha256": self.evidence_sha256,
            "config_sha256": self.config_sha256,
            "expected_config_sha256": self.expected_config_sha256,
            "expected_source_image_sha256": self.expected_source_image_sha256,
            "expected_target_image_sha256": self.expected_target_image_sha256,
            "expected_source_dimensions": list(self.expected_source_dimensions),
            "expected_target_dimensions": list(self.expected_target_dimensions),
            "expected_template_sha256": self.expected_template_sha256,
            "expected_parameter_ids_sha256": self.expected_parameter_ids_sha256,
            "inlier_ratio": self.inlier_ratio,
            "transform_determinant": self.transform_determinant,
            "signed_mapped_area_px": self.signed_mapped_area_px,
            "mapped_area_ratio": self.mapped_area_ratio,
            "maximum_corner_consistency_error_px": (
                self.maximum_corner_consistency_error_px
            ),
            "minimum_roi_visible_fraction": self.minimum_roi_visible_fraction,
            "flags": [flag.value for flag in self.flags],
            "acceptable_for_ocr": self.acceptable_for_ocr,
            "automatic_release_allowed": False,
        }

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_record())


def assess_registration(
    evidence: RegistrationEvidence,
    *,
    expected_source_image_sha256: str,
    expected_target_image_sha256: str,
    expected_source_dimensions: tuple[int, int],
    expected_target_dimensions: tuple[int, int],
    expected_template_sha256: str,
    expected_config_sha256: str,
    expected_parameter_ids: tuple[str, ...],
    config: RegistrationConfig = DEFAULT_REGISTRATION_CONFIG,
) -> RegistrationAssessment:
    """Apply the fixed gate to adapter evidence without trusting its verdict.

    Expected hashes, decoded dimensions, configuration hash, and parameter order
    must come from a frozen, trusted pipeline/manifest.  Checking these values
    binds this report to that context, but does not attest that an untrusted
    adapter really computed the metrics from those bytes; production integration
    still needs a trusted execution boundary and retained raw artifacts.
    """

    if not isinstance(evidence, RegistrationEvidence):
        raise TypeError("evidence must be RegistrationEvidence")
    if not isinstance(config, RegistrationConfig):
        raise TypeError("config must be RegistrationConfig")
    _require_sha256("expected_source_image_sha256", expected_source_image_sha256)
    _require_sha256("expected_target_image_sha256", expected_target_image_sha256)
    checked_source_dimensions = _require_image_dimensions(
        "expected_source_dimensions", expected_source_dimensions
    )
    checked_target_dimensions = _require_image_dimensions(
        "expected_target_dimensions", expected_target_dimensions
    )
    _require_sha256("expected_template_sha256", expected_template_sha256)
    _require_sha256("expected_config_sha256", expected_config_sha256)
    if not isinstance(expected_parameter_ids, tuple):
        raise TypeError("expected_parameter_ids must be a tuple")
    if not expected_parameter_ids:
        raise ValueError("expected_parameter_ids must be a non-empty tuple")
    for parameter_id in expected_parameter_ids:
        _require_identifier("expected parameter ID", parameter_id)
    if len(expected_parameter_ids) != len(set(expected_parameter_ids)):
        raise ValueError("expected_parameter_ids must not contain duplicates")

    flags: list[RegistrationFlag] = []
    if (
        evidence.source_image_sha256 != expected_source_image_sha256
        or evidence.target_image_sha256 != expected_target_image_sha256
    ):
        flags.append(RegistrationFlag.IMAGE_BINDING_MISMATCH)
    if (
        (evidence.source_width, evidence.source_height)
        != checked_source_dimensions
        or (evidence.target_width, evidence.target_height)
        != checked_target_dimensions
    ):
        flags.append(RegistrationFlag.IMAGE_DIMENSION_BINDING_MISMATCH)
    if evidence.template_sha256 != expected_template_sha256:
        flags.append(RegistrationFlag.TEMPLATE_BINDING_MISMATCH)
    if config.content_sha256 != expected_config_sha256:
        flags.append(RegistrationFlag.CONFIG_BINDING_MISMATCH)
    if (
        evidence.adapter_id != config.required_adapter_id
        or evidence.adapter_version != config.required_adapter_version
    ):
        flags.append(RegistrationFlag.ADAPTER_BINDING_MISMATCH)
    if evidence.model is not config.allowed_model:
        flags.append(RegistrationFlag.TRANSFORM_MODEL_MISMATCH)
    if evidence.matched_points < config.minimum_matched_points:
        flags.append(RegistrationFlag.INSUFFICIENT_MATCHES)
    if evidence.inlier_count < max(
        config.minimum_inlier_points,
        _MINIMUM_CORRESPONDENCES[evidence.model],
    ):
        flags.append(RegistrationFlag.INSUFFICIENT_INLIERS)
    if evidence.inlier_ratio < config.minimum_inlier_ratio:
        flags.append(RegistrationFlag.LOW_INLIER_RATIO)
    if (
        evidence.median_reprojection_error_px
        > config.maximum_median_reprojection_error_px
    ):
        flags.append(RegistrationFlag.HIGH_MEDIAN_REPROJECTION_ERROR)
    if evidence.p95_reprojection_error_px > config.maximum_p95_reprojection_error_px:
        flags.append(RegistrationFlag.HIGH_P95_REPROJECTION_ERROR)
    if not _matrix_has_model_semantics(evidence.transform_matrix, evidence.model):
        flags.append(RegistrationFlag.MODEL_MATRIX_SEMANTICS_MISMATCH)
    if abs(evidence.transform_determinant) < config.minimum_absolute_determinant:
        flags.append(RegistrationFlag.DEGENERATE_TRANSFORM)

    derived_corners = evidence.derived_mapped_source_corners
    if derived_corners is None:
        flags.append(RegistrationFlag.TRANSFORM_MAPPING_INVALID)
        maximum_corner_error = None
        signed_area = None
        mapped_area_ratio = None
        geometry_sets = (evidence.mapped_source_corners,)
    else:
        maximum_corner_error = _maximum_corner_error(
            evidence.mapped_source_corners, derived_corners
        )
        if maximum_corner_error > config.maximum_corner_consistency_error_px:
            flags.append(RegistrationFlag.REPORTED_CORNER_MISMATCH)
        signed_area = _signed_polygon_area(derived_corners)
        mapped_area_ratio = abs(signed_area) / float(
            evidence.target_width * evidence.target_height
        )
        geometry_sets = (evidence.mapped_source_corners, derived_corners)

    windings = tuple(_quadrilateral_winding(points) for points in geometry_sets)
    if "MALFORMED" in windings:
        flags.append(RegistrationFlag.MALFORMED_MAPPED_QUADRILATERAL)
    if "CW" in windings:
        flags.append(RegistrationFlag.ORIENTATION_FLIPPED)
    if mapped_area_ratio is None or not (
        config.minimum_mapped_area_ratio
        <= mapped_area_ratio
        <= config.maximum_mapped_area_ratio
    ):
        flags.append(RegistrationFlag.IMPLAUSIBLE_MAPPED_AREA)

    outside = config.maximum_corner_outside_px
    corners_for_bounds = (
        evidence.mapped_source_corners if derived_corners is None else derived_corners
    )
    # Coordinates describe continuous pixel edges: (0, 0) and (width, height)
    # are valid outer boundaries.  The configured allowance is inclusive.
    if any(
        point.x < -outside
        or point.y < -outside
        or point.x > evidence.target_width + outside
        or point.y > evidence.target_height + outside
        for point in corners_for_bounds
    ):
        flags.append(RegistrationFlag.MAPPED_CORNERS_OUT_OF_BOUNDS)

    visibility_by_id = {
        item.parameter_id: item.visible_fraction for item in evidence.roi_visibility
    }
    expected_set = set(expected_parameter_ids)
    reported_ids = tuple(item.parameter_id for item in evidence.roi_visibility)
    if set(visibility_by_id) != expected_set:
        flags.append(RegistrationFlag.ROI_COVERAGE_INCOMPLETE)
        minimum_visibility = None
    else:
        if reported_ids != expected_parameter_ids:
            flags.append(RegistrationFlag.ROI_ORDER_MISMATCH)
        minimum_visibility = min(
            visibility_by_id[item] for item in expected_parameter_ids
        )
        if minimum_visibility < config.minimum_roi_visible_fraction:
            flags.append(RegistrationFlag.LOW_ROI_VISIBILITY)

    expected_parameter_ids_sha256 = _canonical_sha256(
        {
            "expected_parameter_ids_schema_version": 1,
            "expected_parameter_ids": list(expected_parameter_ids),
        }
    )
    return RegistrationAssessment(
        evidence_sha256=evidence.content_sha256,
        config_sha256=config.content_sha256,
        expected_config_sha256=expected_config_sha256,
        expected_source_image_sha256=expected_source_image_sha256,
        expected_target_image_sha256=expected_target_image_sha256,
        expected_source_dimensions=checked_source_dimensions,
        expected_target_dimensions=checked_target_dimensions,
        expected_template_sha256=expected_template_sha256,
        expected_parameter_ids_sha256=expected_parameter_ids_sha256,
        inlier_ratio=evidence.inlier_ratio,
        transform_determinant=evidence.transform_determinant,
        signed_mapped_area_px=signed_area,
        mapped_area_ratio=mapped_area_ratio,
        maximum_corner_consistency_error_px=maximum_corner_error,
        minimum_roi_visible_fraction=minimum_visibility,
        flags=tuple(flags),
    )


__all__ = [
    "DEFAULT_REGISTRATION_CONFIG",
    "Point",
    "RegistrationAssessment",
    "RegistrationConfig",
    "RegistrationEvidence",
    "RegistrationFlag",
    "RegistrationModel",
    "RoiVisibility",
    "assess_registration",
]
