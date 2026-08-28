"""Command-line demonstration of the strict human-first workflow."""

from paramguard import (
    AiResultAccessDenied,
    EvidenceArtifact,
    EvidenceManifest,
    EvidenceRole,
    HumanVerdict,
    IncompleteReviewError,
    InvalidTransitionError,
    PipelineSpec,
    ReviewTask,
    content_sha256,
)


def synthetic_manifest() -> EvidenceManifest:
    return EvidenceManifest(
        manifest_id="synthetic-manifest-001",
        schema_id="synthetic-schema",
        schema_version="1.0",
        schema_sha256=content_sha256(b"synthetic-schema-content-v1"),
        template_id="synthetic-template",
        template_version="1.0",
        template_sha256=content_sha256(b"synthetic-template-content-v1"),
        expected_parameter_ids=("temperature", "pressure", "mode"),
        artifacts=(
            EvidenceArtifact.from_bytes(
                artifact_id="photo-a",
                role=EvidenceRole.LEFT_PHOTO,
                content=b"synthetic-photo-placeholder",
                media_type="image/png",
            ),
            EvidenceArtifact.from_bytes(
                artifact_id="screenshot-a-prime",
                role=EvidenceRole.RIGHT_SCREENSHOT,
                content=b"synthetic-screenshot-placeholder",
                media_type="image/png",
            ),
        ),
    )


def main() -> None:
    manifest = synthetic_manifest()
    pipeline = PipelineSpec(
        spec_id="synthetic-pipeline",
        engine_name="synthetic-ocr",
        engine_version="0.1",
        pipeline_version="0.1",
        comparator_version="0.1",
        configuration_sha256=content_sha256(b"synthetic-pipeline-config-v1"),
    )
    task = ReviewTask(
        task_id="SYNTHETIC-TASK-001",
        evidence_manifest=manifest,
        approved_pipeline_spec=pipeline,
        reviewer_id="training-reviewer",
    )
    print(f"1. Initial state: {task.state.value}")

    try:
        task.queue_ai_review(
            run_id="run-001",
            evidence_manifest_hash=task.evidence_manifest_hash,
            pipeline_spec_hash=pipeline.spec_hash,
        )
    except InvalidTransitionError as error:
        print(f"2. AI before human lock: BLOCKED ({error})")

    task.record_human_decision(
        parameter_id="temperature",
        verdict=HumanVerdict.SAME,
        evidence_manifest_hash=task.evidence_manifest_hash,
    )
    task.record_human_decision(
        parameter_id="pressure",
        verdict=HumanVerdict.DIFFERENT,
        evidence_manifest_hash=task.evidence_manifest_hash,
        reason="The displayed pressure values differ",
    )
    try:
        task.lock_human_review(
            evidence_manifest_hash=task.evidence_manifest_hash
        )
    except IncompleteReviewError as error:
        print(f"3. Incomplete human lock: BLOCKED (missing {error.missing_parameter_ids})")

    task.record_human_decision(
        parameter_id="mode",
        verdict=HumanVerdict.SAME,
        evidence_manifest_hash=task.evidence_manifest_hash,
    )
    task.lock_human_review(evidence_manifest_hash=task.evidence_manifest_hash)
    print(f"4. Human review locked: {task.state.value}")

    task.queue_ai_review(
        run_id="run-001",
        evidence_manifest_hash=task.evidence_manifest_hash,
        pipeline_spec_hash=pipeline.spec_hash,
    )
    try:
        task.revealed_ai_results()
    except AiResultAccessDenied as error:
        print(f"5. Queued AI reveal: BLOCKED ({error})")

    task.start_ai_review(
        run_id="run-001", evidence_manifest_hash=task.evidence_manifest_hash
    )
    pairs = {
        "temperature": ("37.0 °C", "37.0 °C"),
        "pressure": ("1.0 bar", "1.1 bar"),
        "mode": ("AUTO", "AUTO"),
    }
    for parameter_id, (left_raw, right_raw) in pairs.items():
        task.record_ai_assessment(
            run_id="run-001",
            evidence_manifest_hash=task.evidence_manifest_hash,
            parameter_id=parameter_id,
            left_raw=left_raw,
            right_raw=right_raw,
            extraction_reliable=True,
        )
    task.complete_ai_review(
        run_id="run-001", evidence_manifest_hash=task.evidence_manifest_hash
    )

    print(f"6. AI review complete: {task.state.value}")
    for parameter_id, result in task.revealed_ai_results().items():
        print(f"   {parameter_id}: {result.verdict.value}")
    print("7. AI output is auxiliary; no release decision was made.")


if __name__ == "__main__":
    main()
