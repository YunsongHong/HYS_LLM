"""Transparent image-quality heuristics for the fixed-template OCR demo.

These checks are deliberately called heuristics, not validated universal
quality measures.  Their thresholds are versioned and their only authority is
to abstain/escalate; they can never approve a parameter comparison.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import io
import json
import math
from pathlib import Path

from PIL import Image, ImageFilter, ImageStat

from .template import FixedTemplate


class ImageQualityFlag(str, Enum):
    DIMENSION_MISMATCH = "DIMENSION_MISMATCH"
    LOW_CONTRAST = "LOW_CONTRAST"
    LOW_EDGE_DETAIL = "LOW_EDGE_DETAIL"


@dataclass(frozen=True, slots=True)
class ImageQualityConfig:
    config_id: str = "fixed-panel-quality"
    version: str = "1.0"
    minimum_contrast_stddev: float = 18.0
    minimum_edge_variance: float = 250.0

    def __post_init__(self) -> None:
        for name in ("config_id", "version"):
            value = getattr(self, name)
            if not isinstance(value, str) or value.strip() == "":
                raise ValueError(f"{name} must be non-empty text")
        for name in ("minimum_contrast_stddev", "minimum_edge_variance"):
            value = getattr(self, name)
            if type(value) not in (float, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative number")
            try:
                finite = math.isfinite(value)
            except OverflowError:
                finite = False
            if not finite:
                raise ValueError(f"{name} must be finite and representable as a float")

    def to_record(self) -> dict[str, object]:
        return {
            "config_id": self.config_id,
            "version": self.version,
            "minimum_contrast_stddev": float(self.minimum_contrast_stddev),
            "minimum_edge_variance": float(self.minimum_edge_variance),
        }

    @property
    def content_sha256(self) -> str:
        encoded = json.dumps(
            self.to_record(), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ImageQualityAssessment:
    width: int
    height: int
    # None means pixels were not decoded, not a measured zero-quality score.
    contrast_stddev: float | None
    edge_variance: float | None
    flags: tuple[ImageQualityFlag, ...]
    config_sha256: str

    @property
    def acceptable_for_ocr(self) -> bool:
        return not self.flags


DEFAULT_IMAGE_QUALITY_CONFIG = ImageQualityConfig()


def assess_image_quality(
    image_path: str | Path,
    *,
    template: FixedTemplate,
    config: ImageQualityConfig = DEFAULT_IMAGE_QUALITY_CONFIG,
) -> ImageQualityAssessment:
    """Measure a source image and conservatively flag weak OCR inputs."""

    if not isinstance(template, FixedTemplate):
        raise TypeError("template must be a FixedTemplate")
    if not isinstance(config, ImageQualityConfig):
        raise TypeError("config must be an ImageQualityConfig")

    return assess_image_quality_bytes(
        Path(image_path).read_bytes(), template=template, config=config
    )


def assess_image_quality_bytes(
    source_bytes: bytes,
    *,
    template: FixedTemplate,
    config: ImageQualityConfig = DEFAULT_IMAGE_QUALITY_CONFIG,
) -> ImageQualityAssessment:
    """Measure only the supplied immutable bytes, never a reopened path."""

    if type(source_bytes) is not bytes:
        raise TypeError("source_bytes must be immutable built-in bytes")
    if not source_bytes:
        raise ValueError("source image is empty")
    if not isinstance(template, FixedTemplate):
        raise TypeError("template must be a FixedTemplate")
    if not isinstance(config, ImageQualityConfig):
        raise TypeError("config must be an ImageQualityConfig")

    with Image.open(io.BytesIO(source_bytes)) as source:
        width, height = source.size
        if (width, height) != (template.width, template.height):
            # Header geometry is enough to reject this input. Do not allocate
            # pixel buffers or compute statistics for an unusable template.
            return ImageQualityAssessment(
                width=width,
                height=height,
                contrast_stddev=None,
                edge_variance=None,
                flags=(ImageQualityFlag.DIMENSION_MISMATCH,),
                config_sha256=config.content_sha256,
            )
        grayscale = source.convert("L")
        contrast_stddev = float(ImageStat.Stat(grayscale).stddev[0])
        edges = grayscale.filter(ImageFilter.FIND_EDGES)
        if width > 12 and height > 12:
            edges = edges.crop((6, 6, width - 6, height - 6))
        edge_variance = float(ImageStat.Stat(edges).var[0])

    flags: list[ImageQualityFlag] = []
    if contrast_stddev < config.minimum_contrast_stddev:
        flags.append(ImageQualityFlag.LOW_CONTRAST)
    if edge_variance < config.minimum_edge_variance:
        flags.append(ImageQualityFlag.LOW_EDGE_DETAIL)

    return ImageQualityAssessment(
        width=width,
        height=height,
        contrast_stddev=contrast_stddev,
        edge_variance=edge_variance,
        flags=tuple(flags),
        config_sha256=config.content_sha256,
    )
