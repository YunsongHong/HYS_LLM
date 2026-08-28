"""Execute the frozen synthetic benchmark through the real human-first path.

The first-review decisions in this harness are *simulated from synthetic ground
truth*.  They are test fixtures, not measurements of a person and therefore do
not populate the human-time metric.  Evidence processing still cannot begin
until those decisions are complete and locked in ``ReviewTask``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import sys
from time import perf_counter

from PIL import __version__ as pillow_version

from .benchmark import SYNTHETIC_BENCHMARK_V1, SyntheticBenchmark
from .comparison import ComparisonKind
from .evaluation import (
    DatasetSplit,
    EvaluationReport,
    FieldEvaluationRecord,
    evaluate_fields,
)
from .image_quality import (
    DEFAULT_IMAGE_QUALITY_CONFIG,
    ImageQualityConfig,
)
from .ocr import TesseractOcrEngine
from .synthetic import render_case
from .template import FixedTemplate, SYNTHETIC_PANEL_TEMPLATE
from .vision_pipeline import build_tesseract_pipeline_spec, run_gated_ocr_pair
from .workflow import HumanVerdict, ReviewTask


BENCHMARK_RUN_SCHEMA_VERSION = 1
DEFAULT_EVALUATION_SPLITS = (
    DatasetSplit.HIDDEN_TEST,
    DatasetSplit.CHALLENGE,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class RuntimeEnvironment:
    """Allowlisted, path-free runtime facts needed to interpret one run."""

    python_version: str
    python_implementation: str
    operating_system: str
    operating_system_release: str
    machine: str
    pillow_version: str
    template_sha256: str
    ocr_config_sha256: str
    quality_config_sha256: str
    source_tree_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "python_version",
            "python_implementation",
            "operating_system",
            "operating_system_release",
            "machine",
            "pillow_version",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or value.strip() == "":
                raise ValueError(f"{name} must be non-empty text")
        for name in (
            "template_sha256",
            "ocr_config_sha256",
            "quality_config_sha256",
            "source_tree_sha256",
        ):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(
                    f"{name} must contain 64 lowercase hexadecimal characters"
                )

    def to_record(self) -> dict[str, object]:
        return {
            "python_version": self.python_version,
            "python_implementation": self.python_implementation,
            "operating_system": self.operating_system,
            "operating_system_release": self.operating_system_release,
            "machine": self.machine,
            "pillow_version": self.pillow_version,
            "template_sha256": self.template_sha256,
            "ocr_config_sha256": self.ocr_config_sha256,
            "quality_config_sha256": self.quality_config_sha256,
            "source_tree_sha256": self.source_tree_sha256,
            "processing_location": "LOCAL",
            "network_required": False,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkExecution:
    """Serializable evidence produced by one local benchmark execution."""

    benchmark_id: str
    benchmark_version: str
    benchmark_sha256: str
    pipeline_spec_hash: str
    engine_name: str
    engine_version: str
    runtime_environment: RuntimeEnvironment
    generated_at: datetime
    evaluated_splits: tuple[DatasetSplit, ...]
    records: tuple[FieldEvaluationRecord, ...]
    reports: tuple[EvaluationReport, ...]

    def __post_init__(self) -> None:
        for name in (
            "benchmark_id",
            "benchmark_version",
            "benchmark_sha256",
            "pipeline_spec_hash",
            "engine_name",
            "engine_version",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or value.strip() == "":
                raise ValueError(f"{name} must be non-empty text")
        if not isinstance(self.generated_at, datetime):
            raise TypeError("generated_at must be datetime")
        if not isinstance(self.runtime_environment, RuntimeEnvironment):
            raise TypeError("runtime_environment must be RuntimeEnvironment")
        if (
            self.generated_at.tzinfo is None
            or self.generated_at.utcoffset() is None
        ):
            raise ValueError("generated_at must include timezone information")
        _validate_splits(self.evaluated_splits)
        if not isinstance(self.records, tuple) or not self.records:
            raise ValueError("records must be a non-empty tuple")
        if any(not isinstance(row, FieldEvaluationRecord) for row in self.records):
            raise TypeError("records must contain FieldEvaluationRecord values")
        if any(row.split not in self.evaluated_splits for row in self.records):
            raise ValueError("record split is outside evaluated_splits")
        if not isinstance(self.reports, tuple) or not self.reports:
            raise ValueError("reports must be a non-empty tuple")
        if tuple(report.split for report in self.reports) != self.evaluated_splits:
            raise ValueError("reports must exactly follow evaluated_splits")

    def to_record(self) -> dict[str, object]:
        return {
            "benchmark_run_schema_version": BENCHMARK_RUN_SCHEMA_VERSION,
            "benchmark": {
                "benchmark_id": self.benchmark_id,
                "version": self.benchmark_version,
                "content_sha256": self.benchmark_sha256,
            },
            "pipeline": {
                "spec_hash": self.pipeline_spec_hash,
                "engine_name": self.engine_name,
                "engine_version": self.engine_version,
            },
            "runtime_environment": self.runtime_environment.to_record(),
            "generated_at": self.generated_at.astimezone(timezone.utc).isoformat(),
            "evaluated_splits": [item.value for item in self.evaluated_splits],
            "method_notes": [
                "All images and labels are synthetic; no company data is used.",
                "First-review decisions are simulated from synthetic ground truth and locked before OCR.",
                "Human review time is not measured and is reported as null.",
                "AI/OCR results are auxiliary; no benchmark route authorises release.",
                "HIDDEN_TEST means a frozen held-out split for this PoC, not a secret external test set.",
            ],
            "reports": [report.to_record() for report in self.reports],
            "field_records": [row.to_record() for row in self.records],
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_record(),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )


def run_synthetic_benchmark(
    *,
    output_root: str | Path,
    benchmark: SyntheticBenchmark = SYNTHETIC_BENCHMARK_V1,
    splits: tuple[DatasetSplit, ...] = DEFAULT_EVALUATION_SPLITS,
    engine: TesseractOcrEngine | None = None,
    template: FixedTemplate = SYNTHETIC_PANEL_TEMPLATE,
    quality_config: ImageQualityConfig = DEFAULT_IMAGE_QUALITY_CONFIG,
    clock: Callable[[], datetime] = _utc_now,
    timer: Callable[[], float] = perf_counter,
) -> BenchmarkExecution:
    """Render selected cases, lock simulated human review, then run local OCR."""

    if not isinstance(benchmark, SyntheticBenchmark):
        raise TypeError("benchmark must be a SyntheticBenchmark")
    _validate_splits(splits)
    if engine is None:
        engine = TesseractOcrEngine()
    if not isinstance(engine, TesseractOcrEngine):
        raise TypeError("engine must be a TesseractOcrEngine")
    if not isinstance(template, FixedTemplate):
        raise TypeError("template must be a FixedTemplate")
    if not isinstance(quality_config, ImageQualityConfig):
        raise TypeError("quality_config must be an ImageQualityConfig")
    if not callable(clock):
        raise TypeError("clock must be callable")
    if not callable(timer):
        raise TypeError("timer must be callable")

    output_path = Path(output_root)
    output_path.mkdir(parents=True, exist_ok=True)
    pipeline_spec = build_tesseract_pipeline_spec(
        engine=engine,
        template=template,
        quality_config=quality_config,
    )
    rows: list[FieldEvaluationRecord] = []

    selected_cases = tuple(
        case for case in benchmark.cases if case.split in splits
    )
    if not selected_cases:
        raise ValueError("No benchmark cases exist for the requested splits")

    for case in selected_cases:
        rendered = render_case(
            case.spec,
            output_root=output_path / "images",
            template=template,
        )
        task = ReviewTask(
            task_id=f"benchmark-task-{case.spec.case_id}",
            evidence_manifest=rendered.manifest,
            approved_pipeline_spec=pipeline_spec,
            reviewer_id="synthetic-human-simulator",
            clock=clock,
        )

        for pair in case.spec.values:
            exact = pair.expected_comparison.kind is ComparisonKind.EXACT_MATCH
            task.record_human_decision(
                parameter_id=pair.parameter_id,
                verdict=(HumanVerdict.SAME if exact else HumanVerdict.DIFFERENT),
                reason=(
                    None
                    if exact
                    else "Synthetic ground truth contains a non-exact pair"
                ),
                evidence_manifest_hash=task.evidence_manifest_hash,
            )
        task.lock_human_review(
            evidence_manifest_hash=task.evidence_manifest_hash
        )

        run_id = f"benchmark-run-{case.spec.case_id}"
        task.queue_ai_review(
            run_id=run_id,
            evidence_manifest_hash=task.evidence_manifest_hash,
            pipeline_spec_hash=pipeline_spec.spec_hash,
        )
        task.start_ai_review(
            run_id=run_id,
            evidence_manifest_hash=task.evidence_manifest_hash,
        )
        started = _timer_value(timer())
        outcome = run_gated_ocr_pair(
            task,
            run_id=run_id,
            left_image_path=rendered.left_image_path,
            right_image_path=rendered.right_image_path,
            engine=engine,
            template=template,
            quality_config=quality_config,
        )
        finished = _timer_value(timer())
        elapsed = finished - started
        if elapsed < 0:
            raise ValueError("timer moved backwards during benchmark execution")
        allocated_field_seconds = elapsed / len(case.spec.values)

        truth_by_id = {pair.parameter_id: pair for pair in case.spec.values}
        assessment_by_id = {
            item.parameter_id: item for item in outcome.ai_assessments
        }
        route_by_id = {item.parameter_id: item for item in outcome.routing}
        for parameter_id in template.expected_parameter_ids:
            truth = truth_by_id[parameter_id]
            assessment = assessment_by_id[parameter_id]
            route = route_by_id[parameter_id]
            rows.append(
                FieldEvaluationRecord(
                    case_id=case.spec.case_id,
                    parameter_id=parameter_id,
                    split=case.split,
                    left_truth=truth.left_raw,
                    right_truth=truth.right_raw,
                    left_extracted=assessment.left_raw,
                    right_extracted=assessment.right_raw,
                    ai_verdict=assessment.verdict,
                    route=route.route,
                    human_review_seconds=None,
                    ai_processing_seconds=allocated_field_seconds,
                )
            )

    records = tuple(rows)
    reports = tuple(evaluate_fields(records, split=split) for split in splits)
    generated_at = clock()
    if not isinstance(generated_at, datetime):
        raise TypeError("clock must return datetime")
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("clock must return timezone-aware datetime")
    return BenchmarkExecution(
        benchmark_id=benchmark.benchmark_id,
        benchmark_version=benchmark.version,
        benchmark_sha256=benchmark.content_sha256,
        pipeline_spec_hash=pipeline_spec.spec_hash,
        engine_name=pipeline_spec.engine_name,
        engine_version=pipeline_spec.engine_version,
        runtime_environment=_runtime_environment(
            template=template,
            engine=engine,
            quality_config=quality_config,
        ),
        generated_at=generated_at,
        evaluated_splits=splits,
        records=records,
        reports=reports,
    )


def _validate_splits(splits: tuple[DatasetSplit, ...]) -> None:
    if not isinstance(splits, tuple) or not splits:
        raise ValueError("splits must be a non-empty tuple")
    if any(not isinstance(split, DatasetSplit) for split in splits):
        raise TypeError("splits must contain DatasetSplit values")
    if len(set(splits)) != len(splits):
        raise ValueError("splits must not contain duplicates")


def _timer_value(value: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(float(value)):
        raise ValueError("timer must return a finite number")
    return float(value)


def _runtime_environment(
    *,
    template: FixedTemplate,
    engine: TesseractOcrEngine,
    quality_config: ImageQualityConfig,
) -> RuntimeEnvironment:
    return RuntimeEnvironment(
        python_version=(
            f"{sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
        python_implementation=platform.python_implementation(),
        operating_system=platform.system(),
        operating_system_release=platform.release(),
        machine=platform.machine(),
        pillow_version=pillow_version,
        template_sha256=template.content_sha256,
        ocr_config_sha256=engine.config.content_sha256,
        quality_config_sha256=quality_config.content_sha256,
        source_tree_sha256=_source_tree_sha256(),
    )


def _source_tree_sha256() -> str:
    """Hash relative Python source names and bytes without leaking local paths."""

    package_root = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    source_files = tuple(sorted(package_root.glob("*.py"), key=lambda item: item.name))
    if not source_files:
        raise RuntimeError("No ParamGuard Python source files were found")
    for source_file in source_files:
        content = source_file.read_bytes()
        digest.update(source_file.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(content).to_bytes(8, byteorder="big"))
        digest.update(content)
    return digest.hexdigest()
