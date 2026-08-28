"""Development-only comparison of local OCR observations on identical crops.

Run with PYTHONPATH=src. This is not a production adapter or a human-time
study. Each engine gets a separate, explicitly simulated, locked R1 task.
The native helper receives PNG bytes and configuration, never reference text.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import math
from pathlib import Path
import platform
import random
import re
from time import perf_counter

from PIL import Image, __version__ as pillow_version

from paramguard.evidence import EvidenceRole
from paramguard.image_quality import (
    DEFAULT_IMAGE_QUALITY_CONFIG,
    assess_image_quality_bytes,
)
from paramguard.ocr import OcrError, OcrOutputError, TesseractConfig, TesseractOcrEngine
from paramguard.pipeline import PipelineSpec
from paramguard.synthetic import (
    RenderedSyntheticCase,
    SyntheticCaseSpec,
    SyntheticDegradation,
    SyntheticValuePair,
    render_case,
)
from paramguard.template import SYNTHETIC_PANEL_TEMPLATE
from paramguard.tool_comparison import (
    ComparisonTruth,
    ObservationStatus,
    ToolObservation,
    compare_development,
)
from paramguard.vision_pipeline import (
    COMPARATOR_VERSION,
    build_tesseract_pipeline_spec,
    run_gated_ocr_pair,
)
from paramguard.workflow import AiVerdict, HumanVerdict, ReviewTask


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = SYNTHETIC_PANEL_TEMPLATE
SEED = 2026082801
MAX_JSON_BYTES = 2 * 1024 * 1024
FAMILIES = (
    "EXACT",
    "NUMERIC_STATE",
    "NEGATIVE_SIGN",
    "DECIMAL_PRECISION",
    "LEADING_ZERO",
    "UNIT_CASE",
    "MISSING_STRUCTURE",
    "IMAGE_QUALITY",
)
TESSERACT_LANES = ("paramguard_psm7", "tesseract_psm13_development")
APPLE_LANES = ("apple_accurate_correction_on", "apple_accurate_correction_off")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def write_new_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(canonical(value) + b"\n")


def strict_json(text: str) -> dict:
    if type(text) is not str or len(text) > MAX_JSON_BYTES:
        raise OcrOutputError("Invalid or oversized benchmark response")
    try:
        encoded_length = len(text.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise OcrOutputError("Benchmark response is not valid UTF-8") from error
    if encoded_length > MAX_JSON_BYTES:
        raise OcrOutputError("Invalid or oversized benchmark response")

    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise OcrOutputError("Duplicate benchmark JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise OcrOutputError("Non-finite benchmark JSON number")

    try:
        value = json.loads(
            text, object_pairs_hook=pairs, parse_constant=reject_constant
        )
    except (ValueError, RecursionError) as error:
        raise OcrOutputError("Malformed benchmark JSON") from error
    if type(value) is not dict:
        raise OcrOutputError("Benchmark response must be an object")
    return value


def generated_cases() -> tuple[tuple[str, SyntheticCaseSpec], ...]:
    """Fixed development design; no engine results influence generation."""
    rng = random.Random(SEED)
    cases = []
    for family in FAMILIES:
        for variant in range(4):
            temperature = rng.randrange(20, 80)
            pressure = rng.randrange(1, 10)
            speed = rng.randrange(100, 900)
            left = [f"{temperature}.0 C", f"{pressure}.20 bar", f"0{speed} rpm", "AUTO"]
            right = list(left)
            degradation = SyntheticDegradation.NONE
            if family == "NUMERIC_STATE":
                right = [
                    f"{temperature}.1 C",
                    f"{pressure}.25 bar",
                    f"0{speed+1} rpm",
                    "MANUAL",
                ]
            elif family == "NEGATIVE_SIGN":
                right[0], right[1] = "-" + left[0], "-" + left[1]
            elif family == "DECIMAL_PRECISION":
                right[0], right[1] = f"{temperature}.00 C", f"{pressure}.2 bar"
            elif family == "LEADING_ZERO":
                right[2] = f"{speed} rpm"
            elif family == "UNIT_CASE":
                right = [
                    f"{temperature}.0 F",
                    f"{pressure}.20 Bar",
                    f"0{speed} RPM",
                    "auto",
                ]
            elif family == "MISSING_STRUCTURE":
                left[0], right[1], left[2], right[2] = None, None, None, None
            elif family == "IMAGE_QUALITY":
                right[0], right[1] = f"{temperature}.1 C", f"{pressure}.25 bar"
                degradation = (
                    SyntheticDegradation.LOW_CONTRAST
                    if variant < 2
                    else SyntheticDegradation.BLUR
                )
            values = tuple(
                SyntheticValuePair(key, a, b)
                for key, a, b in zip(TEMPLATE.expected_parameter_ids, left, right)
            )
            cases.append(
                (
                    family,
                    SyntheticCaseSpec(
                        case_id=f"dev-{len(cases)+1:03d}",
                        values=values,
                        left_degradation=degradation,
                    ),
                )
            )
    return tuple(cases)


def crop_bytes(source: bytes) -> dict[str, bytes]:
    """Use the exact current Tesseract inset and PNG encoding, not a new ROI."""
    result = {}
    with Image.open(io.BytesIO(source)) as image:
        if image.size != (TEMPLATE.width, TEMPLATE.height):
            raise ValueError("Unexpected synthetic image dimensions")
        for region in TEMPLATE.regions:
            box = region.value_box
            with image.crop(
                (box.left + 8, box.top + 8, box.right - 8, box.bottom - 8)
            ) as crop:
                with io.BytesIO() as buffer:
                    crop.save(buffer, format="PNG", optimize=False)
                    result[region.parameter_id] = buffer.getvalue()
    return result


def verified_images(rendered: RenderedSyntheticCase) -> tuple[bytes, bytes]:
    artifacts = {item.role: item for item in rendered.manifest.artifacts}
    return (
        artifacts[EvidenceRole.LEFT_PHOTO].read_verified_bytes(
            rendered.left_image_path
        ),
        artifacts[EvidenceRole.RIGHT_SCREENSHOT].read_verified_bytes(
            rendered.right_image_path
        ),
    )


def simulated_task(rendered: RenderedSyntheticCase, spec: PipelineSpec) -> ReviewTask:
    task = ReviewTask(
        task_id=f"diagnostic-{rendered.spec.case_id}",
        evidence_manifest=rendered.manifest,
        approved_pipeline_spec=spec,
        reviewer_id="synthetic-r1-simulator-not-a-participant",
    )
    for pair in rendered.spec.values:
        missing = pair.left_raw is None or pair.right_raw is None
        verdict = (
            HumanVerdict.UNABLE_TO_JUDGE
            if missing
            else HumanVerdict.SAME
            if pair.left_raw == pair.right_raw
            else HumanVerdict.DIFFERENT
        )
        task.record_human_decision(
            parameter_id=pair.parameter_id,
            verdict=verdict,
            reason=None
            if verdict is HumanVerdict.SAME
            else "Simulated reference decision; no human timing",
            evidence_manifest_hash=task.evidence_manifest_hash,
        )
    task.lock_human_review(evidence_manifest_hash=task.evidence_manifest_hash)
    return task


def start_task(task: ReviewTask, run_id: str) -> None:
    task.queue_ai_review(
        run_id=run_id,
        evidence_manifest_hash=task.evidence_manifest_hash,
        pipeline_spec_hash=task.approved_pipeline_spec.spec_hash,
    )
    task.start_ai_review(
        run_id=run_id, evidence_manifest_hash=task.evidence_manifest_hash
    )


def observations(task: ReviewTask, case_id: str) -> tuple[ToolObservation, ...]:
    result = []
    for key, assessment in task.revealed_ai_results().items():
        if assessment.verdict in (AiVerdict.SAME, AiVerdict.DIFFERENT):
            status = ObservationStatus.VALID
        elif assessment.verdict is AiVerdict.SYSTEM_ERROR:
            status = ObservationStatus.ERROR
        else:
            status = ObservationStatus.ABSTAIN
        result.append(
            ToolObservation(
                case_id, key, assessment.left_raw, assessment.right_raw, status
            )
        )
    return tuple(result)


@dataclass(frozen=True)
class AppleConfig:
    helper: Path
    helper_sha256: str
    revision: int
    os_version: str
    language_correction: bool

    def __post_init__(self) -> None:
        if type(self.revision) is not int or self.revision <= 0:
            raise ValueError("Invalid Apple revision")
        if type(self.language_correction) is not bool:
            raise TypeError("language_correction must be bool")
        if (
            type(self.helper_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.helper_sha256) is None
        ):
            raise ValueError("Invalid helper digest")
        if type(self.os_version) is not str or not self.os_version:
            raise ValueError("Missing Apple OS identity")

    def settings(self) -> dict:
        return {
            "helper_sha256": self.helper_sha256,
            "revision": self.revision,
            "os_version": self.os_version,
            "level": "accurate",
            "language_correction": self.language_correction,
            "recognition_languages": ["en-US"],
            "custom_words": [],
            "confidence_cutoff": None,
            "crop_inset_pixels": 8,
            "quality_config_sha256": DEFAULT_IMAGE_QUALITY_CONFIG.content_sha256,
            "template_sha256": TEMPLATE.content_sha256,
            "timeout_seconds_per_helper_batch": 15,
            "max_combined_output_bytes": 1024 * 1024,
        }

    def pipeline_spec(self) -> PipelineSpec:
        return PipelineSpec(
            spec_id="apple-vision-development-only",
            engine_name="apple-vision",
            engine_version=f"revision-{self.revision}",
            pipeline_version="comparison-dev-1",
            comparator_version=COMPARATOR_VERSION,
            configuration_sha256=digest_bytes(canonical(self.settings())),
        )


def parse_apple_response(
    text: str, revision: int, expected_ids: tuple[str, ...]
) -> dict[str, dict]:
    response = strict_json(text)
    if set(response) != {"schema_version", "revision", "crops"}:
        raise OcrOutputError("Unexpected Apple response keys")
    if type(response["schema_version"]) is not int or response["schema_version"] != 1:
        raise OcrOutputError("Invalid Apple response schema")
    if type(response["revision"]) is not int or response["revision"] != revision:
        raise OcrOutputError("Wrong Apple revision")
    if type(response["crops"]) is not list or len(response["crops"]) != len(
        expected_ids
    ):
        raise OcrOutputError("Incomplete Apple batch")
    rows = {}
    for row in response["crops"]:
        if type(row) is not dict or set(row) != {
            "id",
            "text",
            "confidence",
            "observation_count",
        }:
            raise OcrOutputError("Unexpected Apple crop schema")
        key = row["id"]
        if type(key) is not str or key not in expected_ids or key in rows:
            raise OcrOutputError("Invalid or duplicate Apple crop id")
        value, confidence, count = (
            row["text"],
            row["confidence"],
            row["observation_count"],
        )
        if value is not None and (
            type(value) is not str or not value or len(value) > 4096
        ):
            raise OcrOutputError("Invalid Apple text")
        if value is not None:
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as error:
                raise OcrOutputError("Apple text is not valid UTF-8") from error
        if (value is None) != (confidence is None):
            raise OcrOutputError("Incomplete Apple observation")
        if confidence is not None and (
            type(confidence) not in (int, float)
            or not 0 <= confidence <= 1
            or not math.isfinite(confidence)
        ):
            raise OcrOutputError("Invalid Apple confidence")
        if (
            type(count) is not int
            or not 0 <= count <= 4096
            or (value is not None and count == 0)
        ):
            raise OcrOutputError("Invalid Apple observation count")
        rows[key] = row
    return rows


def run_apple(
    task: ReviewTask,
    run_id: str,
    rendered: RenderedSyntheticCase,
    config: AppleConfig,
) -> tuple[tuple[ToolObservation, ...], dict]:
    # All binding/state checks precede file reads, image decoding and helper execution.
    task.assert_ai_execution_authorized(
        run_id=run_id,
        evidence_manifest_hash=rendered.manifest.manifest_hash,
        pipeline_spec_hash=config.pipeline_spec().spec_hash,
    )
    if task.evidence_manifest != rendered.manifest or rendered.template != TEMPLATE:
        raise ValueError("Apple diagnostic evidence/template mismatch")
    if digest_bytes(config.helper.read_bytes()) != config.helper_sha256:
        raise ValueError("Native helper changed after configuration freeze")
    left, right = verified_images(rendered)
    left_quality = assess_image_quality_bytes(left, template=TEMPLATE)
    right_quality = assess_image_quality_bytes(right, template=TEMPLATE)
    crop_map = {
        f"{side}:{key}": data
        for side, image in (("left", left), ("right", right))
        for key, data in crop_bytes(image).items()
    }
    detail = {
        "crop_sha256": {key: digest_bytes(data) for key, data in crop_map.items()},
        "helper_invoked": False,
        "quality_rejected": False,
        "raw_rows": [],
    }
    rows = None
    execution_error = False
    if left_quality.acceptable_for_ocr and right_quality.acceptable_for_ocr:
        request = {
            "schema_version": 1,
            "revision": config.revision,
            "language_correction": config.language_correction,
            "crops": [
                {"id": key, "png_base64": base64.b64encode(data).decode("ascii")}
                for key, data in crop_map.items()
            ],
        }
        payload = canonical(request)
        if len(payload) > MAX_JSON_BYTES:
            raise ValueError("Native request exceeds frozen budget")
        try:
            detail["helper_invoked"] = True
            # Reuse the project's N+1 bounded POSIX collector and child cleanup.
            completed = TesseractOcrEngine()._run(
                (str(config.helper),), input_bytes=payload
            )
            rows = parse_apple_response(
                completed.stdout, config.revision, tuple(crop_map)
            )
            detail["raw_rows"] = list(rows.values())
        except OcrError as error:
            execution_error = True
            detail["error_code"] = error.code
    else:
        detail["quality_rejected"] = True
    for key in task.expected_parameter_ids:
        if execution_error:
            task.record_ai_system_error(
                run_id=run_id,
                evidence_manifest_hash=task.evidence_manifest_hash,
                parameter_id=key,
                reason="Development native helper failed; no partial output used",
            )
        else:
            a = None if rows is None else rows[f"left:{key}"]["text"]
            b = None if rows is None else rows[f"right:{key}"]["text"]
            reliable = (
                a is not None and b is not None and bool(a.strip()) and bool(b.strip())
            )
            task.record_ai_assessment(
                run_id=run_id,
                evidence_manifest_hash=task.evidence_manifest_hash,
                parameter_id=key,
                left_raw=a,
                right_raw=b,
                extraction_reliable=reliable,
                reason=None
                if reliable
                else "Shared quality gate or missing native observation",
            )
    task.complete_ai_review(
        run_id=run_id, evidence_manifest_hash=task.evidence_manifest_hash
    )
    return observations(task, rendered.spec.case_id), detail


def run_development(output_root: Path, helper: Path) -> dict:
    output_root = output_root.resolve()
    if not output_root.is_relative_to((ROOT / "artifacts" / "comparison").resolve()):
        raise ValueError(
            "Diagnostic output must be under this project's artifacts/comparison"
        )
    helper = helper.resolve(strict=True)
    if not helper.is_relative_to((ROOT / "artifacts" / "comparison").resolve()):
        raise ValueError("Use a reviewed helper compiled inside artifacts/comparison")
    descriptor = strict_json(
        TesseractOcrEngine()._run((str(helper), "--describe")).stdout
    )
    if (
        descriptor.get("engine") != "apple-vision"
        or type(descriptor.get("revision")) is not int
        or descriptor.get("schema_version") != 1
    ):
        raise ValueError("Invalid native descriptor")
    helper_hash = digest_bytes(helper.read_bytes())
    apple_configs = {
        name: AppleConfig(
            helper,
            helper_hash,
            descriptor["revision"],
            descriptor["os_version"],
            correction,
        )
        for name, correction in zip(APPLE_LANES, (True, False))
    }
    engines = {
        name: TesseractOcrEngine(config=TesseractConfig(page_segmentation_mode=mode))
        for name, mode in zip(TESSERACT_LANES, (7, 13))
    }
    specs = {
        name: build_tesseract_pipeline_spec(engine=engine, template=TEMPLATE)
        for name, engine in engines.items()
    }
    specs.update(
        {name: config.pipeline_spec() for name, config in apple_configs.items()}
    )
    language_list = (
        engines[TESSERACT_LANES[0]]
        ._run((engines[TESSERACT_LANES[0]].resolved_binary(), "--list-langs"))
        .stdout
    )
    match = re.search(r'List of available languages in "([^"]+)"', language_list)
    if match is None:
        raise ValueError("Cannot identify active Tesseract language data")
    language_file = (Path(match.group(1)) / "eng.traineddata").resolve(strict=True)
    source_paths = sorted((ROOT / "src" / "paramguard").glob("*.py")) + [
        Path(__file__).resolve(),
        ROOT / "tools" / "apple_vision_ocr.swift",
        ROOT / "docs" / "COMPARISON_PROTOCOL.md",
    ]
    source_hashes = {
        str(path.relative_to(ROOT)): digest_bytes(path.read_bytes())
        for path in source_paths
    }
    output_root.mkdir(parents=True, exist_ok=False)
    write_new_json(
        output_root / "EXECUTION_STARTED.json",
        {
            "started_at_utc": utc_now(),
            "run_state": "IN_PROGRESS",
            "purpose": "DEVELOPMENT_ONLY",
        },
    )
    rendered_cases = tuple(
        (family, render_case(spec, output_root=output_root / "images"))
        for family, spec in generated_cases()
    )
    corpus = []
    for family, rendered in rendered_cases:
        a, b = verified_images(rendered)
        corpus.append(
            {
                "case_id": rendered.spec.case_id,
                "family": family,
                "truth": [asdict(pair) for pair in rendered.spec.values],
                "manifest": rendered.manifest.to_record(),
                "manifest_sha256": rendered.manifest.manifest_hash,
                "crop_sha256": {
                    f"{side}:{key}": digest_bytes(data)
                    for side, image in (("left", a), ("right", b))
                    for key, data in crop_bytes(image).items()
                },
            }
        )
    write_new_json(output_root / "CORPUS.json", corpus)
    frozen = {
        "schema_version": 1,
        "purpose": "DEVELOPMENT_ONLY",
        "frozen_before_ocr_at_utc": utc_now(),
        "seed": SEED,
        "panels": 32,
        "fields": 128,
        "human_review_seconds": None,
        "primary_metric": "supported_difference_recall",
        "relative_target": 0.05,
        "corpus_sha256": digest_bytes((output_root / "CORPUS.json").read_bytes()),
        "source_hashes": source_hashes,
        "native_descriptor": descriptor,
        "helper_sha256": helper_hash,
        "tesseract_binary_sha256": digest_bytes(
            Path(engines[TESSERACT_LANES[0]].resolved_binary()).read_bytes()
        ),
        "eng_traineddata_sha256": digest_bytes(language_file.read_bytes()),
        "pipeline_specs": {name: spec.to_record() for name, spec in specs.items()},
        "tesseract_settings": {
            name: engine.config.to_record() for name, engine in engines.items()
        },
        "apple_settings": {
            name: config.settings() for name, config in apple_configs.items()
        },
        "runtime": {
            "python": platform.python_version(),
            "pillow": pillow_version,
            "os": platform.platform(),
            "machine": platform.machine(),
        },
        "timing_claim": "diagnostic only; accelerator and per-process scopes differ",
        "lane_order": "rotate four prespecified lanes once per panel; no result-dependent order",
    }
    write_new_json(output_root / "FROZEN_PROTOCOL.json", frozen)
    frozen_hash = digest_bytes((output_root / "FROZEN_PROTOCOL.json").read_bytes())
    truth = tuple(
        ComparisonTruth(
            rendered.spec.case_id, pair.parameter_id, pair.left_raw, pair.right_raw
        )
        for _, rendered in rendered_cases
        for pair in rendered.spec.values
    )
    results = {name: [] for name in specs}
    records = []
    lane_names = tuple(specs)
    with (output_root / "OBSERVATIONS.jsonl").open("x", encoding="utf-8") as log:
        for index, (_, rendered) in enumerate(rendered_cases):
            offset = index % len(lane_names)
            for name in lane_names[offset:] + lane_names[:offset]:
                task = simulated_task(rendered, specs[name])
                human_before = tuple(task.human_decisions().items())
                run_id = f"run-{name}-{rendered.spec.case_id}"
                start_task(task, run_id)
                started = perf_counter()
                if name in engines:
                    outcome = run_gated_ocr_pair(
                        task,
                        run_id=run_id,
                        left_image_path=rendered.left_image_path,
                        right_image_path=rendered.right_image_path,
                        engine=engines[name],
                        template=TEMPLATE,
                    )
                    observed = observations(task, rendered.spec.case_id)
                    hashes = {
                        f"{side}:{item.parameter_id}": item.crop_sha256
                        for side, items in (
                            ("left", outcome.left_ocr),
                            ("right", outcome.right_ocr),
                        )
                        for item in items
                    }
                    detail = {
                        "crop_sha256": hashes,
                        "quality_rejected": not (
                            outcome.left_quality.acceptable_for_ocr
                            and outcome.right_quality.acceptable_for_ocr
                        ),
                    }
                else:
                    observed, detail = run_apple(
                        task, run_id, rendered, apple_configs[name]
                    )
                elapsed = perf_counter() - started
                for key, crop_hash in detail["crop_sha256"].items():
                    if crop_hash != corpus[index]["crop_sha256"][key]:
                        raise ValueError("Engine received different crop bytes")
                if human_before != tuple(task.human_decisions().items()):
                    raise ValueError("An engine altered a simulated human decision")
                record = {
                    "case_id": rendered.spec.case_id,
                    "lane": name,
                    "manifest_sha256": task.evidence_manifest_hash,
                    "pipeline_spec_sha256": specs[name].spec_hash,
                    "simulated_r1": True,
                    "state_after": task.state.value,
                    "elapsed_seconds": elapsed,
                    "observations": [asdict(row) for row in observed],
                    "detail": detail,
                }
                log.write(canonical(record).decode("utf-8") + "\n")
                log.flush()
                records.append(record)
                results[name].extend(observed)
            print(
                json.dumps({"completed_panels": index + 1, "total_panels": 32}),
                flush=True,
            )
    for relative, source_hash in source_hashes.items():
        if digest_bytes((ROOT / relative).read_bytes()) != source_hash:
            raise ValueError("Source changed during comparison; results not finalized")
    if digest_bytes((output_root / "FROZEN_PROTOCOL.json").read_bytes()) != frozen_hash:
        raise ValueError("Protocol changed during comparison")
    if (
        digest_bytes((output_root / "CORPUS.json").read_bytes())
        != frozen["corpus_sha256"]
    ):
        raise ValueError("Corpus changed during comparison")
    report = compare_development(
        truth,
        {name: tuple(rows) for name, rows in results.items()},
        candidate=TESSERACT_LANES[0],
    )
    report.update(
        {
            "frozen_protocol_sha256": frozen_hash,
            "completed_at_utc": utc_now(),
            "total_panels": 32,
            "independent_engine_families": 2,
            "native_helper_sha256": helper_hash,
            "confirmed_superiority": False,
            "human_review_seconds": None,
            "resource_comparison": "NOT_CONTROLLED",
            "supply_chain_status": "SEPARATE_GATE_NOT_WAIVED",
            "raw_observations_sha256": digest_bytes(
                (output_root / "OBSERVATIONS.jsonl").read_bytes()
            ),
        }
    )
    write_new_json(output_root / "RESULTS.json", report)
    print(
        json.dumps(
            {"status": report["status"], "results": str(output_root / "RESULTS.json")}
        )
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--apple-helper", required=True, type=Path)
    args = parser.parse_args()
    run_development(args.output, args.apple_helper)


if __name__ == "__main__":
    main()
