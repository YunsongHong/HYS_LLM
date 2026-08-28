"""Human-gated local image/OCR execution and deterministic routing.

This module will not inspect image bytes or invoke Tesseract unless the bound
``ReviewTask`` is already in ``AI_REVIEW_RUNNING``.  The workflow state remains
the authority: direct early calls fail before image quality, OCR, or routing is
computed, preventing those outputs from becoming first-review hints.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from .comparison import ComparisonKind
from .evidence import EvidenceRole
from .image_quality import (
    DEFAULT_IMAGE_QUALITY_CONFIG,
    ImageQualityAssessment,
    ImageQualityConfig,
    ImageQualityFlag,
    assess_image_quality_bytes,
)
from .ocr import OcrError, OcrFieldResult, TesseractOcrEngine
from .pipeline import PipelineSpec
from .routing import (
    ImageQuality,
    ReviewSignals,
    RoutingDecision,
    route_parameter,
)
from .template import FixedTemplate
from .workflow import AiAssessment, ReviewState, ReviewTask


VISION_PIPELINE_VERSION = "1.7"
COMPARATOR_VERSION = "1.1"
ROUTING_RULES_VERSION = "1.0"


class VisionPipelineError(Exception):
    code = "VISION_PIPELINE_ERROR"


class VisionPipelineBindingError(VisionPipelineError):
    code = "VISION_PIPELINE_BINDING_ERROR"


class VisionPipelineStateError(VisionPipelineError):
    code = "VISION_PIPELINE_STATE_ERROR"


@dataclass(frozen=True, slots=True)
class OcrPairOutcome:
    left_quality: ImageQualityAssessment
    right_quality: ImageQualityAssessment
    left_ocr: tuple[OcrFieldResult, ...]
    right_ocr: tuple[OcrFieldResult, ...]
    ai_assessments: tuple[AiAssessment, ...]
    routing: tuple[RoutingDecision, ...]


def build_tesseract_pipeline_spec(
    *,
    engine: TesseractOcrEngine,
    template: FixedTemplate,
    quality_config: ImageQualityConfig = DEFAULT_IMAGE_QUALITY_CONFIG,
) -> PipelineSpec:
    """Bind every executable OCR/quality/routing input into one approved spec."""

    if not isinstance(engine, TesseractOcrEngine):
        raise TypeError("engine must be a TesseractOcrEngine")
    if not isinstance(template, FixedTemplate):
        raise TypeError("template must be a FixedTemplate")
    if not isinstance(quality_config, ImageQualityConfig):
        raise TypeError("quality_config must be an ImageQualityConfig")
    configuration = {
        "configuration_schema_version": 1,
        "template_sha256": template.content_sha256,
        "ocr_config_sha256": engine.config.content_sha256,
        "quality_config_sha256": quality_config.content_sha256,
        "routing_rules_version": ROUTING_RULES_VERSION,
        "comparator_version": COMPARATOR_VERSION,
    }
    configuration_sha256 = hashlib.sha256(
        json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return PipelineSpec(
        spec_id="local-tesseract-fixed-template",
        engine_name="tesseract",
        engine_version=engine.engine_version(),
        pipeline_version=VISION_PIPELINE_VERSION,
        comparator_version=COMPARATOR_VERSION,
        configuration_sha256=configuration_sha256,
    )


def run_gated_ocr_pair(
    task: ReviewTask,
    *,
    run_id: str,
    left_image_path: str | Path,
    right_image_path: str | Path,
    engine: TesseractOcrEngine,
    template: FixedTemplate,
    quality_config: ImageQualityConfig = DEFAULT_IMAGE_QUALITY_CONFIG,
) -> OcrPairOutcome:
    """Run one complete post-lock OCR pass and return only completed results."""

    if not isinstance(task, ReviewTask):
        raise TypeError("task must be a ReviewTask")
    if task.state is not ReviewState.AI_REVIEW_RUNNING:
        raise VisionPipelineStateError(
            "Image quality and OCR may run only after the human lock and AI start"
        )
    task.assert_ai_execution_authorized(
        run_id=run_id,
        evidence_manifest_hash=task.evidence_manifest_hash,
        pipeline_spec_hash=task.approved_pipeline_spec.spec_hash,
    )
    if not isinstance(engine, TesseractOcrEngine):
        raise TypeError("engine must be a TesseractOcrEngine")
    if not isinstance(template, FixedTemplate):
        raise TypeError("template must be a FixedTemplate")
    if not isinstance(quality_config, ImageQualityConfig):
        raise TypeError("quality_config must be an ImageQualityConfig")

    left_bytes, right_bytes = _verify_bindings(
        task=task,
        left_image_path=Path(left_image_path),
        right_image_path=Path(right_image_path),
        engine=engine,
        template=template,
        quality_config=quality_config,
    )

    left_quality = assess_image_quality_bytes(
        left_bytes, template=template, config=quality_config
    )
    right_quality = assess_image_quality_bytes(
        right_bytes, template=template, config=quality_config
    )
    quality_signal = _routing_quality(left_quality, right_quality)
    left_ocr: tuple[OcrFieldResult, ...] = ()
    right_ocr: tuple[OcrFieldResult, ...] = ()

    if not left_quality.acceptable_for_ocr or not right_quality.acceptable_for_ocr:
        reason = _quality_reason(left_quality, right_quality)
        for parameter_id in task.expected_parameter_ids:
            task.record_ai_assessment(
                run_id=run_id,
                evidence_manifest_hash=task.evidence_manifest_hash,
                parameter_id=parameter_id,
                left_raw=None,
                right_raw=None,
                extraction_reliable=False,
                reason=reason,
            )
    else:
        try:
            left_results = engine.extract_template_bytes(left_bytes, template=template)
            right_results = engine.extract_template_bytes(
                right_bytes, template=template
            )
        except OcrError as error:
            for parameter_id in task.expected_parameter_ids:
                task.record_ai_system_error(
                    run_id=run_id,
                    evidence_manifest_hash=task.evidence_manifest_hash,
                    parameter_id=parameter_id,
                    reason=f"Local OCR execution failed: {error}",
                )
        else:
            if (
                tuple(left_results) != task.expected_parameter_ids
                or tuple(right_results) != task.expected_parameter_ids
            ):
                raise VisionPipelineBindingError(
                    "OCR field order does not exactly match the frozen schema"
                )
            left_ocr = tuple(left_results[item] for item in task.expected_parameter_ids)
            right_ocr = tuple(
                right_results[item] for item in task.expected_parameter_ids
            )
            for parameter_id in task.expected_parameter_ids:
                left = left_results[parameter_id]
                right = right_results[parameter_id]
                reliable = left.reliable and right.reliable
                reasons = tuple(
                    reason
                    for reason in (left.reason, right.reason)
                    if reason is not None
                )
                task.record_ai_assessment(
                    run_id=run_id,
                    evidence_manifest_hash=task.evidence_manifest_hash,
                    parameter_id=parameter_id,
                    left_raw=left.extracted_text,
                    right_raw=right.extracted_text,
                    extraction_reliable=reliable,
                    reason=("; ".join(reasons) if reasons else None),
                )

    task.complete_ai_review(
        run_id=run_id,
        evidence_manifest_hash=task.evidence_manifest_hash,
    )
    ai_by_id = task.revealed_ai_results()
    human_by_id = task.human_decisions()
    region_by_id = {region.parameter_id: region for region in template.regions}
    routing: list[RoutingDecision] = []
    for parameter_id in task.expected_parameter_ids:
        assessment = ai_by_id[parameter_id]
        comparison_kind = (
            ComparisonKind.MISSING_VALUE
            if assessment.comparison_result is None
            else assessment.comparison_result.kind
        )
        routing.append(
            route_parameter(
                ReviewSignals(
                    parameter_id=parameter_id,
                    human_verdict=human_by_id[parameter_id].verdict,
                    ai_verdict=assessment.verdict,
                    comparison_kind=comparison_kind,
                    is_critical=region_by_id[parameter_id].critical,
                    image_quality=quality_signal,
                )
            )
        )

    return OcrPairOutcome(
        left_quality=left_quality,
        right_quality=right_quality,
        left_ocr=left_ocr,
        right_ocr=right_ocr,
        ai_assessments=tuple(ai_by_id[item] for item in task.expected_parameter_ids),
        routing=tuple(routing),
    )


def _verify_bindings(
    *,
    task: ReviewTask,
    left_image_path: Path,
    right_image_path: Path,
    engine: TesseractOcrEngine,
    template: FixedTemplate,
    quality_config: ImageQualityConfig,
) -> tuple[bytes, bytes]:
    """Validate identities before reading and retain the exact verified bytes."""

    manifest = task.evidence_manifest
    if (
        manifest.template_id != template.template_id
        or manifest.template_version != template.version
        or manifest.template_sha256 != template.content_sha256
        or manifest.expected_parameter_ids != template.expected_parameter_ids
    ):
        raise VisionPipelineBindingError(
            "Runtime template differs from the frozen evidence manifest"
        )
    expected_pipeline = build_tesseract_pipeline_spec(
        engine=engine, template=template, quality_config=quality_config
    )
    if task.approved_pipeline_spec != expected_pipeline:
        raise VisionPipelineBindingError(
            "Runtime OCR/quality/routing configuration differs from the approved pipeline"
        )

    artifact_by_role = {artifact.role: artifact for artifact in manifest.artifacts}
    contents: list[bytes] = []
    for role, path in (
        (EvidenceRole.LEFT_PHOTO, left_image_path),
        (EvidenceRole.RIGHT_SCREENSHOT, right_image_path),
    ):
        artifact = artifact_by_role[role]
        try:
            content = artifact.read_verified_bytes(path)
        except ValueError as error:
            raise VisionPipelineBindingError(
                f"Runtime {role.value} bytes differ from the frozen evidence"
            ) from error
        contents.append(content)
    return contents[0], contents[1]


def _routing_quality(
    left: ImageQualityAssessment, right: ImageQualityAssessment
) -> ImageQuality:
    flags = set(left.flags) | set(right.flags)
    if ImageQualityFlag.DIMENSION_MISMATCH in flags:
        return ImageQuality.UNREADABLE
    if flags:
        return ImageQuality.LOW
    return ImageQuality.ACCEPTABLE


def _quality_reason(left: ImageQualityAssessment, right: ImageQualityAssessment) -> str:
    left_codes = ",".join(flag.value for flag in left.flags) or "NONE"
    right_codes = ",".join(flag.value for flag in right.flags) or "NONE"
    return (
        "Image-quality gate abstained before OCR; "
        f"left_flags={left_codes}; right_flags={right_codes}"
    )
