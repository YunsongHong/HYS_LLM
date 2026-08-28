"""Versioned fixed-layout templates used by the local OCR demonstration.

The first image milestone intentionally uses an explicit template instead of
asking a vision model to guess where critical values are.  Every crop is bound
to a stable template digest, which makes alignment deterministic and testable.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _require_identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe 1-128 character identifier")
    return value


def _require_nonempty_text(name: str, value: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str")
    if value.strip() == "":
        raise ValueError(f"{name} must not be empty or whitespace")
    return value


@dataclass(frozen=True, slots=True)
class BoundingBox:
    """A left/top/right/bottom rectangle in source-image pixels."""

    left: int
    top: int
    right: int
    bottom: int

    def __post_init__(self) -> None:
        for name in ("left", "top", "right", "bottom"):
            if type(getattr(self, name)) is not int:
                raise TypeError(f"{name} must be int")
        if self.left < 0 or self.top < 0:
            raise ValueError("bounding-box coordinates must be non-negative")
        if self.right <= self.left or self.bottom <= self.top:
            raise ValueError("bounding box must have positive width and height")

    @property
    def width(self) -> int:
        return self.right - self.left

    @property
    def height(self) -> int:
        return self.bottom - self.top

    def to_record(self) -> dict[str, int]:
        return {
            "left": self.left,
            "top": self.top,
            "right": self.right,
            "bottom": self.bottom,
        }


@dataclass(frozen=True, slots=True)
class ParameterRegion:
    """One schema parameter and the exact rectangle containing its value."""

    parameter_id: str
    display_label: str
    value_box: BoundingBox
    critical: bool = False

    def __post_init__(self) -> None:
        _require_identifier("parameter_id", self.parameter_id)
        _require_nonempty_text("display_label", self.display_label)
        if not isinstance(self.value_box, BoundingBox):
            raise TypeError("value_box must be a BoundingBox")
        if type(self.critical) is not bool:
            raise TypeError("critical must be bool")

    def to_record(self) -> dict[str, object]:
        return {
            "parameter_id": self.parameter_id,
            "display_label": self.display_label,
            "value_box": self.value_box.to_record(),
            "critical": self.critical,
        }


@dataclass(frozen=True, slots=True)
class FixedTemplate:
    """Immutable image geometry and ordered field schema."""

    template_id: str
    version: str
    width: int
    height: int
    regions: tuple[ParameterRegion, ...]

    def __post_init__(self) -> None:
        _require_identifier("template_id", self.template_id)
        _require_identifier("version", self.version)
        if type(self.width) is not int or self.width <= 0:
            raise ValueError("width must be a positive integer")
        if type(self.height) is not int or self.height <= 0:
            raise ValueError("height must be a positive integer")
        if not isinstance(self.regions, tuple):
            raise TypeError("regions must be a tuple")
        if not self.regions:
            raise ValueError("regions must not be empty")
        if any(not isinstance(region, ParameterRegion) for region in self.regions):
            raise TypeError("regions must contain only ParameterRegion values")
        ids = tuple(region.parameter_id for region in self.regions)
        if len(set(ids)) != len(ids):
            raise ValueError("template parameter IDs must not contain duplicates")
        for region in self.regions:
            box = region.value_box
            if box.right > self.width or box.bottom > self.height:
                raise ValueError(
                    f"value box for {region.parameter_id} exceeds template canvas"
                )

    @property
    def expected_parameter_ids(self) -> tuple[str, ...]:
        return tuple(region.parameter_id for region in self.regions)

    def region_for(self, parameter_id: str) -> ParameterRegion:
        checked_id = _require_identifier("parameter_id", parameter_id)
        for region in self.regions:
            if region.parameter_id == checked_id:
                return region
        raise KeyError(f"Unknown template parameter ID: {checked_id}")

    def to_record(self) -> dict[str, object]:
        return {
            "template_schema_version": 1,
            "template_id": self.template_id,
            "version": self.version,
            "width": self.width,
            "height": self.height,
            "regions": [region.to_record() for region in self.regions],
        }

    @property
    def content_bytes(self) -> bytes:
        return json.dumps(
            self.to_record(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.content_bytes).hexdigest()


SYNTHETIC_PANEL_TEMPLATE = FixedTemplate(
    template_id="synthetic-panel",
    version="1.0",
    width=1200,
    height=620,
    regions=(
        ParameterRegion(
            parameter_id="temperature",
            display_label="Temperature",
            value_box=BoundingBox(670, 174, 1110, 246),
            critical=True,
        ),
        ParameterRegion(
            parameter_id="pressure",
            display_label="Pressure",
            value_box=BoundingBox(670, 278, 1110, 350),
            critical=True,
        ),
        ParameterRegion(
            parameter_id="speed",
            display_label="Pump speed",
            value_box=BoundingBox(670, 382, 1110, 454),
        ),
        ParameterRegion(
            parameter_id="mode",
            display_label="Operating mode",
            value_box=BoundingBox(670, 486, 1110, 558),
        ),
    ),
)
