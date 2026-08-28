"""Deterministic synthetic image pairs for the interview-inspired PoC.

No company image, parameter list, or internal workflow data is used here.
The generated panels are intentionally fictional and are suitable for tests,
demonstrations, and hidden challenge-set construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import re

from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageFont

from .comparison import ComparisonResult, compare_values
from .evidence import EvidenceArtifact, EvidenceManifest, EvidenceRole
from .template import FixedTemplate, SYNTHETIC_PANEL_TEMPLATE


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe 1-128 character identifier")
    return value


class PanelStyle(str, Enum):
    PHOTO = "PHOTO"
    SCREENSHOT = "SCREENSHOT"


class SyntheticDegradation(str, Enum):
    NONE = "NONE"
    LOW_CONTRAST = "LOW_CONTRAST"
    BLUR = "BLUR"


@dataclass(frozen=True, slots=True)
class SyntheticValuePair:
    parameter_id: str
    left_raw: str | None
    right_raw: str | None

    def __post_init__(self) -> None:
        _identifier("parameter_id", self.parameter_id)
        for name in ("left_raw", "right_raw"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{name} must be str or None")

    @property
    def expected_comparison(self) -> ComparisonResult:
        return compare_values(self.left_raw, self.right_raw)


@dataclass(frozen=True, slots=True)
class SyntheticCaseSpec:
    case_id: str
    values: tuple[SyntheticValuePair, ...]
    left_degradation: SyntheticDegradation = SyntheticDegradation.NONE
    right_degradation: SyntheticDegradation = SyntheticDegradation.NONE

    def __post_init__(self) -> None:
        _identifier("case_id", self.case_id)
        if not isinstance(self.values, tuple) or not self.values:
            raise ValueError("values must be a non-empty tuple")
        if any(not isinstance(item, SyntheticValuePair) for item in self.values):
            raise TypeError("values must contain only SyntheticValuePair values")
        ids = tuple(item.parameter_id for item in self.values)
        if len(set(ids)) != len(ids):
            raise ValueError("synthetic parameter IDs must not contain duplicates")
        if not isinstance(self.left_degradation, SyntheticDegradation):
            raise TypeError("left_degradation must be SyntheticDegradation")
        if not isinstance(self.right_degradation, SyntheticDegradation):
            raise TypeError("right_degradation must be SyntheticDegradation")

    def assert_matches_template(self, template: FixedTemplate) -> None:
        if tuple(item.parameter_id for item in self.values) != (
            template.expected_parameter_ids
        ):
            raise ValueError(
                "synthetic values must exactly match the template's ordered schema"
            )

    def schema_bytes(self, template: FixedTemplate) -> bytes:
        self.assert_matches_template(template)
        record = {
            "schema_version": 1,
            "parameters": [
                {
                    "parameter_id": region.parameter_id,
                    "critical": region.critical,
                }
                for region in template.regions
            ],
        }
        return json.dumps(
            record, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class RenderedSyntheticCase:
    spec: SyntheticCaseSpec
    template: FixedTemplate
    left_image_path: Path
    right_image_path: Path
    manifest: EvidenceManifest


def default_clean_case() -> SyntheticCaseSpec:
    """Return a small case with exact, numeric, and formatting differences."""

    return SyntheticCaseSpec(
        case_id="clean-demo-001",
        values=(
            SyntheticValuePair("temperature", "37.0 C", "37.0 C"),
            SyntheticValuePair("pressure", "1.20 bar", "1.25 bar"),
            SyntheticValuePair("speed", "0800 rpm", "800 rpm"),
            SyntheticValuePair("mode", "AUTO", "AUTO"),
        ),
    )


def render_case(
    spec: SyntheticCaseSpec,
    *,
    output_root: str | Path,
    template: FixedTemplate = SYNTHETIC_PANEL_TEMPLATE,
) -> RenderedSyntheticCase:
    """Render a synthetic photo/screenshot pair and freeze its evidence manifest."""

    if not isinstance(spec, SyntheticCaseSpec):
        raise TypeError("spec must be a SyntheticCaseSpec")
    if not isinstance(template, FixedTemplate):
        raise TypeError("template must be a FixedTemplate")
    spec.assert_matches_template(template)

    case_directory = Path(output_root) / spec.case_id
    case_directory.mkdir(parents=True, exist_ok=True)
    left_path = case_directory / "photo_a.png"
    right_path = case_directory / "screenshot_a_prime.png"
    values_by_id = {item.parameter_id: item for item in spec.values}

    _render_panel(
        output_path=left_path,
        template=template,
        values={key: item.left_raw for key, item in values_by_id.items()},
        style=PanelStyle.PHOTO,
        degradation=spec.left_degradation,
    )
    _render_panel(
        output_path=right_path,
        template=template,
        values={key: item.right_raw for key, item in values_by_id.items()},
        style=PanelStyle.SCREENSHOT,
        degradation=spec.right_degradation,
    )

    schema_sha256 = hashlib.sha256(spec.schema_bytes(template)).hexdigest()
    manifest = EvidenceManifest(
        manifest_id=f"{spec.case_id}-manifest",
        schema_id="synthetic-parameter-schema",
        schema_version="1.0",
        schema_sha256=schema_sha256,
        template_id=template.template_id,
        template_version=template.version,
        template_sha256=template.content_sha256,
        expected_parameter_ids=template.expected_parameter_ids,
        artifacts=(
            EvidenceArtifact.from_file(
                artifact_id=f"{spec.case_id}-photo-a",
                role=EvidenceRole.LEFT_PHOTO,
                path=left_path,
                media_type="image/png",
            ),
            EvidenceArtifact.from_file(
                artifact_id=f"{spec.case_id}-screenshot-a-prime",
                role=EvidenceRole.RIGHT_SCREENSHOT,
                path=right_path,
                media_type="image/png",
            ),
        ),
    )
    return RenderedSyntheticCase(
        spec=spec,
        template=template,
        left_image_path=left_path,
        right_image_path=right_path,
        manifest=manifest,
    )


def _font(size: int) -> ImageFont.ImageFont | ImageFont.FreeTypeFont:
    """Use Pillow's bundled font so generated tests do not depend on OS fonts."""

    return ImageFont.load_default(size=size)


def _render_panel(
    *,
    output_path: Path,
    template: FixedTemplate,
    values: dict[str, str | None],
    style: PanelStyle,
    degradation: SyntheticDegradation,
) -> None:
    if set(values) != set(template.expected_parameter_ids):
        raise ValueError("render values must exactly match the template schema")

    if style is PanelStyle.PHOTO:
        background = (226, 224, 216)
        panel_fill = (246, 244, 237)
        header_fill = (72, 78, 82)
        title = "SYNTHETIC EQUIPMENT PANEL - PHOTO A"
        text_fill = (25, 27, 29)
    else:
        background = (231, 238, 248)
        panel_fill = (250, 252, 255)
        header_fill = (29, 82, 145)
        title = "SYNTHETIC CONTROL VIEW - SCREENSHOT A'"
        text_fill = (20, 35, 55)

    image = Image.new("RGB", (template.width, template.height), background)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (45, 35, template.width - 45, template.height - 35),
        radius=18,
        fill=panel_fill,
        outline=(95, 101, 108),
        width=3,
    )
    draw.rounded_rectangle(
        (45, 35, template.width - 45, 130),
        radius=18,
        fill=header_fill,
    )
    draw.rectangle((45, 110, template.width - 45, 130), fill=header_fill)
    draw.text((82, 80), title, font=_font(32), fill=(255, 255, 255), anchor="lm")

    label_font = _font(31)
    value_font = _font(38)
    for region in template.regions:
        box = region.value_box
        row_top = box.top - 18
        row_bottom = box.bottom + 18
        draw.line((82, row_bottom, template.width - 82, row_bottom), fill=(180, 184, 188), width=2)
        label = region.display_label + (" *" if region.critical else "")
        draw.text(
            (100, (row_top + row_bottom) // 2),
            label,
            font=label_font,
            fill=text_fill,
            anchor="lm",
        )
        draw.rounded_rectangle(
            (box.left, box.top, box.right, box.bottom),
            radius=9,
            fill=(255, 255, 255),
            outline=(122, 130, 138),
            width=2,
        )
        value = values[region.parameter_id]
        if value is not None:
            draw.text(
                (box.left + 22, (box.top + box.bottom) // 2),
                value,
                font=value_font,
                fill=(12, 15, 18),
                anchor="lm",
            )

    if degradation is SyntheticDegradation.LOW_CONTRAST:
        image = ImageEnhance.Contrast(image).enhance(0.12)
    elif degradation is SyntheticDegradation.BLUR:
        image = image.filter(ImageFilter.GaussianBlur(radius=3.2))
    elif degradation is not SyntheticDegradation.NONE:
        raise ValueError(f"Unsupported synthetic degradation: {degradation}")

    image.save(output_path, format="PNG", optimize=False)
