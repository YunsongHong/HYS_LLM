"""Small synthetic probes for manifest-bounded evidence reads."""

from dataclasses import replace
import hashlib
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from paramguard.evidence import EvidenceArtifact, EvidenceRole
from paramguard.synthetic import default_clean_case, render_case
from paramguard.vision_pipeline import (
    VisionPipelineBindingError,
    VisionPipelineStateError,
    run_gated_ocr_pair,
)
from paramguard.webapp import ParamGuardWebSession, PublicStageUnavailableError
from paramguard.workflow import ReviewState, ReviewTask
from tests.test_vision_pipeline import complete_and_start_human_first, make_task
from tests.test_webapp import FakeTesseractEngine


class TrackingStream(BytesIO):
    def __init__(self, content: bytes, *, max_chunk: int | None = None) -> None:
        super().__init__(content)
        self.requests: list[int] = []
        self.consumed = 0
        self.max_chunk = max_chunk

    def read(self, size: int = -1) -> bytes:
        self.requests.append(size)
        effective = size
        if self.max_chunk is not None:
            effective = self.max_chunk if size < 0 else min(size, self.max_chunk)
        result = super().read(effective)
        self.consumed += len(result)
        return result


class EvidenceReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.rendered = render_case(
            default_clean_case(), output_root=self.directory.name
        )
        self.original = {
            self.rendered.left_image_path: self.rendered.left_image_path.read_bytes(),
            self.rendered.right_image_path: self.rendered.right_image_path.read_bytes(),
        }

    def _one_byte_evidence(self, side: str):
        role = (
            EvidenceRole.LEFT_PHOTO if side == "left" else EvidenceRole.RIGHT_SCREENSHOT
        )
        artifacts = tuple(
            replace(item, byte_length=1, sha256=hashlib.sha256(b"x").hexdigest())
            if item.role is role
            else item
            for item in self.rendered.manifest.artifacts
        )
        return replace(
            self.rendered,
            manifest=replace(self.rendered.manifest, artifacts=artifacts),
        )

    def _consumer(self, rendered, side: str, kind: str):
        engine = FakeTesseractEngine()
        session = ParamGuardWebSession(rendered_case=rendered, engine=engine)
        if kind == "pipeline":
            task = make_task(rendered, engine)
            complete_and_start_human_first(task)
            return (
                lambda: run_gated_ocr_pair(
                    task,
                    run_id="run-001",
                    left_image_path=rendered.left_image_path,
                    right_image_path=rendered.right_image_path,
                    engine=engine,
                    template=rendered.template,
                ),
                VisionPipelineBindingError,
                engine,
            )
        if kind == "web-recheck":
            return session._assert_current_evidence_bytes, ValueError, engine
        asset = "full.png" if kind == "human-full" else "temperature.png"
        return (
            lambda: session.image_asset(side=side, asset_name=asset),
            ValueError,
            engine,
        )

    def test_all_consumers_stop_at_frozen_length_plus_one(self) -> None:
        for side in ("left", "right"):
            for kind in ("pipeline", "web-recheck", "human-full", "human-roi"):
                with self.subTest(side=side, consumer=kind):
                    rendered = self._one_byte_evidence(side)
                    source = getattr(rendered, f"{side}_image_path")
                    payloads = dict(self.original)
                    payloads[source] = b"x" * 4097
                    streams = {}
                    call, error_type, engine = self._consumer(rendered, side, kind)

                    def open_source(path, *args, **kwargs):
                        stream = TrackingStream(payloads[path])
                        streams[path] = stream
                        return stream

                    with patch.object(
                        Path, "open", autospec=True, side_effect=open_source
                    ):
                        with patch(
                            "PIL.Image.open", side_effect=AssertionError("no decode")
                        ):
                            with self.assertRaises(error_type):
                                call()
                    self.assertEqual(engine.extract_calls, 0)
                    self.assertTrue(all(stream.closed for stream in streams.values()))
                    self.assertLessEqual(streams[source].consumed, 2)
                    self.assertTrue(all(size > 0 for size in streams[source].requests))

    def test_short_and_same_length_substitution_fail_before_decode(self) -> None:
        for content in (b"", b"y"):
            for kind in ("pipeline", "web-recheck", "human-full", "human-roi"):
                with self.subTest(content=content, consumer=kind):
                    rendered = self._one_byte_evidence("left")
                    stream = TrackingStream(content)
                    call, error_type, engine = self._consumer(rendered, "left", kind)
                    with patch.object(Path, "open", return_value=stream):
                        with patch(
                            "PIL.Image.open", side_effect=AssertionError("no decode")
                        ):
                            with self.assertRaises(error_type):
                                call()
                    self.assertTrue(stream.closed)
                    self.assertEqual(engine.extract_calls, 0)

    def test_early_ai_calls_do_not_open_sources(self) -> None:
        engine = FakeTesseractEngine()
        task = make_task(self.rendered, engine)
        session = ParamGuardWebSession(rendered_case=self.rendered, engine=engine)
        version_calls = engine.version_calls
        with patch.object(
            Path, "open", side_effect=AssertionError("early read")
        ) as opened:
            with self.assertRaises(VisionPipelineStateError):
                run_gated_ocr_pair(
                    task,
                    run_id="run-001",
                    left_image_path=self.rendered.left_image_path,
                    right_image_path=self.rendered.right_image_path,
                    engine=engine,
                    template=self.rendered.template,
                )
            with self.assertRaises(PublicStageUnavailableError):
                session.run_assistive_check(
                    evidence_manifest_hash=session.evidence_manifest_hash,
                    expected_revision=0,
                )
            opened.assert_not_called()
        self.assertEqual(engine.version_calls, version_calls)
        self.assertEqual(engine.extract_calls, 0)

    def test_human_images_remain_available_before_r1_lock_without_ai(self) -> None:
        engine = FakeTesseractEngine()
        session = ParamGuardWebSession(rendered_case=self.rendered, engine=engine)
        for side in ("left", "right"):
            full = session.image_asset(side=side, asset_name="full.png")
            source = getattr(self.rendered, f"{side}_image_path")
            self.assertEqual(full.content, self.original[source])
            crop = session.image_asset(side=side, asset_name="temperature.png")
            self.assertTrue(crop.content.startswith(b"\x89PNG"))
        self.assertEqual(session.task.state, ReviewState.HUMAN_REVIEW_OPEN)
        self.assertEqual(engine.extract_calls, 0)

    def test_verified_reader_handles_short_reads_and_multiple_chunks(self) -> None:
        cases = ((b"synthetic bytes", 2), (b"x" * (128 * 1024 + 17), 1023))
        for content, max_chunk in cases:
            with self.subTest(length=len(content), max_chunk=max_chunk):
                artifact = EvidenceArtifact.from_bytes(
                    artifact_id="bounded-source",
                    role=EvidenceRole.LEFT_PHOTO,
                    content=content,
                    media_type="image/png",
                )
                stream = TrackingStream(content, max_chunk=max_chunk)
                with patch.object(
                    Path, "open", autospec=True, return_value=stream
                ) as opened:
                    snapshot = artifact.read_verified_bytes("synthetic.png")
                opened.assert_called_once_with(Path("synthetic.png"), "rb", buffering=0)
                self.assertIs(type(snapshot), bytes)
                self.assertEqual(snapshot, content)
                self.assertEqual(stream.consumed, len(content))
                self.assertTrue(stream.closed)
                self.assertTrue(all(0 < size <= 64 * 1024 for size in stream.requests))
                self.assertEqual(stream.requests[-1], 1)

    def test_growth_at_chunk_boundary_reads_only_one_extra_byte(self) -> None:
        expected = b"x" * (64 * 1024)
        artifact = EvidenceArtifact.from_bytes(
            artifact_id="chunk-boundary",
            role=EvidenceRole.LEFT_PHOTO,
            content=expected,
            media_type="image/png",
        )
        stream = TrackingStream(expected + b"y" * 4097)
        with patch.object(Path, "open", return_value=stream):
            with self.assertRaises(ValueError):
                artifact.read_verified_bytes("synthetic.png")
        self.assertEqual(stream.requests, [64 * 1024, 1])
        self.assertEqual(stream.consumed, len(expected) + 1)
        self.assertTrue(stream.closed)

    def test_huge_declared_length_does_not_allocate_from_that_integer(self) -> None:
        artifact = EvidenceArtifact(
            artifact_id="huge-declaration",
            role=EvidenceRole.LEFT_PHOTO,
            sha256=hashlib.sha256(b"tiny").hexdigest(),
            byte_length=1 << 80,
            media_type="image/png",
        )
        stream = TrackingStream(b"tiny")
        with patch.object(Path, "open", return_value=stream):
            with self.assertRaises(ValueError):
                artifact.read_verified_bytes("synthetic.png")
        self.assertEqual(stream.requests, [64 * 1024, 64 * 1024])
        self.assertEqual(stream.consumed, 4)
        self.assertTrue(stream.closed)

    def test_invalid_read_results_are_not_eof_or_trusted_bytes(self) -> None:
        class DerivedBytes(bytes):
            pass

        artifact = EvidenceArtifact.from_bytes(
            artifact_id="invalid-stream-result",
            role=EvidenceRole.LEFT_PHOTO,
            content=b"expected",
            media_type="image/png",
        )
        for result in (
            None,
            "x",
            False,
            bytearray(b"x"),
            DerivedBytes(b"x"),
            b"x" * 10,
        ):
            with self.subTest(result_type=type(result).__name__):
                stream = TrackingStream(b"")
                with patch.object(Path, "open", return_value=stream):
                    with patch.object(stream, "read", return_value=result) as read:
                        with self.assertRaisesRegex(ValueError, "invalid bounded read"):
                            artifact.read_verified_bytes("synthetic.png")
                        read.assert_called_once_with(9)
                self.assertTrue(stream.closed)

    def test_io_failure_closes_handle_without_returning_partial_content(self) -> None:
        artifact = EvidenceArtifact.from_bytes(
            artifact_id="interrupted-stream",
            role=EvidenceRole.LEFT_PHOTO,
            content=b"expected",
            media_type="image/png",
        )
        stream = TrackingStream(b"")
        with patch.object(Path, "open", return_value=stream):
            with patch.object(
                stream, "read", side_effect=[b"ex", OSError("synthetic read failure")]
            ):
                with self.assertRaisesRegex(OSError, "synthetic read failure"):
                    artifact.read_verified_bytes("synthetic.png")
        self.assertTrue(stream.closed)

    def test_pre_bounded_read_pipeline_is_rejected_before_source_open(self) -> None:
        engine = FakeTesseractEngine()
        current = make_task(self.rendered, engine).approved_pipeline_spec
        task = ReviewTask(
            task_id="old-unbounded-read-pipeline",
            evidence_manifest=self.rendered.manifest,
            approved_pipeline_spec=replace(current, pipeline_version="1.5"),
            reviewer_id="primary-reviewer",
        )
        complete_and_start_human_first(task)
        human_before = task.human_decisions()
        version_calls = engine.version_calls
        with patch.object(
            Path, "open", side_effect=AssertionError("old pipeline read")
        ) as opened:
            with self.assertRaises(VisionPipelineBindingError):
                run_gated_ocr_pair(
                    task,
                    run_id="run-001",
                    left_image_path=self.rendered.left_image_path,
                    right_image_path=self.rendered.right_image_path,
                    engine=engine,
                    template=self.rendered.template,
                )
            opened.assert_not_called()
        self.assertEqual(engine.version_calls, version_calls + 1)
        self.assertEqual(engine.extract_calls, 0)
        self.assertEqual(task.human_decisions(), human_before)
        self.assertEqual(task._ai_results, {})


if __name__ == "__main__":
    unittest.main()
