from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import hashlib
import http.client
from io import BytesIO
import json
from pathlib import Path
import re
import socket
from tempfile import TemporaryDirectory
from threading import Barrier, Thread
import time
from types import MappingProxyType
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from PIL import Image

from paramguard.ocr import OcrExecutionError, OcrFieldResult, TesseractOcrEngine
from paramguard.routing import ReviewRoute, RoutingDecision
from paramguard.synthetic import (
    SyntheticCaseSpec,
    SyntheticValuePair,
    default_clean_case,
    render_case,
)
from paramguard.template import BoundingBox, FixedTemplate, ParameterRegion
from paramguard.vision_pipeline import OcrPairOutcome, run_gated_ocr_pair
from paramguard.webapp import (
    AssistiveCheckFailedError,
    MAX_HUMAN_REASON_CHARACTERS,
    MAX_JSON_BODY_BYTES,
    MAX_TARGETED_REASON_CHARACTERS,
    MAX_TARGETED_MUTATIONS_PER_PARAMETER,
    InvalidWebRequestError,
    MutationConflictError,
    ParamGuardWebSession,
    PublicStageUnavailableError,
    REQUEST_IO_TIMEOUT_SECONDS,
    STATIC_TEMPLATE_PATH,
    TargetedReviewIncompleteWebError,
    TargetedMutationLimitError,
    create_demo_server,
)
from paramguard.workflow import (
    HumanVerdict,
    IncompleteReviewError,
    ReviewState,
)


class FakeTesseractEngine(TesseractOcrEngine):
    """A local, deterministic adapter that still uses the real gated runner."""

    def __init__(self) -> None:
        super().__init__(binary="not-used-by-this-fake")
        self.extract_calls = 0
        self.version_calls = 0

    def engine_version(self) -> str:
        self.version_calls += 1
        return "fake-1.0"

    def extract_template_bytes(self, source_bytes, *, template):
        self.extract_calls += 1
        source_hash = hashlib.sha256(source_bytes).hexdigest()
        # The gated pair calls the left snapshot first, then the right snapshot.
        if self.extract_calls % 2 == 1:
            values = {
                "temperature": "37.0 C",
                "pressure": "1.20 bar",
                "speed": "0800 rpm",
                "mode": "AUTO",
            }
        else:
            values = {
                "temperature": "37.0 C",
                "pressure": "1.25 bar",
                "speed": "800 rpm",
                "mode": "AUTO",
            }
        results = {
            region.parameter_id: OcrFieldResult(
                parameter_id=region.parameter_id,
                extracted_text=values[region.parameter_id],
                mean_confidence=99.0,
                reliable=True,
                reason=None,
                tokens=(),
                source_image_sha256=source_hash,
                crop_sha256="1" * 64,
                engine_version="fake-1.0",
                config_sha256=self.config.content_sha256,
            )
            for region in template.regions
        }
        return MappingProxyType(results)


class FailingTesseractEngine(FakeTesseractEngine):
    def extract_template_bytes(self, source_bytes, *, template):
        self.extract_calls += 1
        raise OcrExecutionError("deliberate local OCR failure")


class MarkupTesseractEngine(FakeTesseractEngine):
    def extract_template_bytes(self, source_bytes, *, template):
        original = dict(super().extract_template_bytes(source_bytes, template=template))
        if self.extract_calls % 2 == 0 and "mode" in original:
            original["mode"] = replace(
                original["mode"],
                extracted_text='<img src=x onerror="globalThis.pwned=1">',
            )
        return MappingProxyType(original)


class UniformTesseractEngine(FakeTesseractEngine):
    """Synthetic scale adapter that returns the same raw value for every ID."""

    def extract_template_bytes(self, source_bytes, *, template):
        self.extract_calls += 1
        source_hash = hashlib.sha256(source_bytes).hexdigest()
        return MappingProxyType(
            {
                region.parameter_id: OcrFieldResult(
                    parameter_id=region.parameter_id,
                    extracted_text="1",
                    mean_confidence=99.0,
                    reliable=True,
                    reason=None,
                    tokens=(),
                    source_image_sha256=source_hash,
                    crop_sha256="2" * 64,
                    engine_version="fake-1.0",
                    config_sha256=self.config.content_sha256,
                )
                for region in template.regions
            }
        )


def complete_first_review(session: ParamGuardWebSession) -> None:
    decisions = (
        ("temperature", "SAME", None),
        ("pressure", "DIFFERENT", "displayed pressure differs"),
        ("speed", "DIFFERENT", "leading zero differs"),
        ("mode", "SAME", None),
    )
    for parameter_id, verdict, reason in decisions:
        session.record_human_decision(
            parameter_id=parameter_id,
            verdict=verdict,
            reason=reason,
            evidence_manifest_hash=session.evidence_manifest_hash,
            expected_revision=session.revision,
        )


def complete_default_assistive_check(
    session: ParamGuardWebSession,
) -> dict[str, object]:
    complete_first_review(session)
    session.lock_human_review(
        evidence_manifest_hash=session.evidence_manifest_hash,
        expected_revision=4,
    )
    return session.run_assistive_check(
        evidence_manifest_hash=session.evidence_manifest_hash,
        expected_revision=5,
    )


def targeted_bindings(inbox: dict[str, object]) -> dict[str, object]:
    return {
        "task_id": inbox["task_id"],
        "assignment_id": inbox["assignment_id"],
        "evidence_manifest_hash": inbox["evidence_manifest_hash"],
        "source_snapshot_sha256": inbox["source_snapshot_sha256"],
    }


@contextmanager
def running_server(session: ParamGuardWebSession):
    server = create_demo_server(session, port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}", host, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def http_request(
    base_url: str,
    method: str,
    path: str,
    payload: dict[str, object] | None = None,
):
    data = None
    headers: dict[str, str] = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(base_url + path, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, response.headers, response.read()
    except HTTPError as error:
        return error.code, error.headers, error.read()


def raw_http_request(
    host: str,
    port: int,
    method: str,
    target: str,
    *,
    headers: tuple[tuple[str, str], ...],
    body: bytes = b"",
):
    connection = http.client.HTTPConnection(host, port, timeout=10)
    connection.putrequest(
        method,
        target,
        skip_host=True,
        skip_accept_encoding=True,
    )
    for name, value in headers:
        connection.putheader(name, value)
    connection.endheaders(body)
    response = connection.getresponse()
    result = (response.status, response.headers, response.read())
    connection.close()
    return result


class WebSessionTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.rendered = render_case(
            default_clean_case(), output_root=self.temporary.name
        )
        self.engine = FakeTesseractEngine()
        self.session = ParamGuardWebSession(
            rendered_case=self.rendered,
            engine=self.engine,
        )

    def test_prelock_state_has_a_strict_human_only_allowlist(self) -> None:
        state = self.session.public_state()
        self.assertEqual(
            set(state),
            {
                "stage",
                "evidence_manifest_hash",
                "revision",
                "fields",
                "missing_parameter_ids",
                "lock_available",
            },
        )
        self.assertNotIn(self.rendered.spec.case_id, json.dumps(state))
        self.assertNotIn(self.session.task.task_id, json.dumps(state))
        self.assertEqual(state["stage"], "HUMAN_REVIEW_OPEN")
        self.assertEqual(
            [item["parameter_id"] for item in state["fields"]],
            list(self.rendered.template.expected_parameter_ids),
        )
        encoded = json.dumps(state, sort_keys=True).lower()
        for forbidden in (
            "run_id",
            "pipeline",
            "engine",
            "tesseract",
            "ocr",
            "confidence",
            "routing",
            "route_reasons",
            "assistive_results",
            "comparison_kind",
            "targeted",
            "profile",
            "routing_context",
            "source_snapshot",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(self.engine.extract_calls, 0)

        semantically_named = ParamGuardWebSession(
            rendered_case=self.rendered,
            engine=FakeTesseractEngine(),
            task_id="hidden-all-same",
        )
        named_state = json.dumps(semantically_named.public_state())
        named_page = semantically_named.render_first_review_html(nonce="safe")
        self.assertNotIn("hidden-all-same", named_state)
        self.assertNotIn("hidden-all-same", named_page)

    def test_prelock_composition_probes_only_engine_configuration_not_evidence(self) -> None:
        second_engine = FakeTesseractEngine()
        with patch.object(
            Path,
            "open",
            side_effect=AssertionError("pre-lock composition read evidence bytes"),
        ):
            session = ParamGuardWebSession(
                rendered_case=self.rendered,
                engine=second_engine,
            )
        self.assertEqual(second_engine.version_calls, 1)
        self.assertEqual(second_engine.extract_calls, 0)
        self.assertEqual(session.public_state()["stage"], "HUMAN_REVIEW_OPEN")
        self.assertEqual(second_engine.version_calls, 1)
        self.assertEqual(second_engine.extract_calls, 0)

    def test_session_composition_rejects_template_manifest_mismatch(self) -> None:
        changed_template = replace(self.rendered.template, version="2.0")
        inconsistent = replace(self.rendered, template=changed_template)
        with self.assertRaisesRegex(ValueError, "manifest does not match"):
            ParamGuardWebSession(
                rendered_case=inconsistent,
                engine=FakeTesseractEngine(),
            )

    def test_every_mutation_requires_manifest_and_current_revision(self) -> None:
        receipt = self.session.record_human_decision(
            parameter_id="temperature",
            verdict="SAME",
            reason=None,
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=0,
        )
        self.assertEqual(
            set(receipt),
            {
                "stage",
                "revision",
                "decision",
                "missing_count",
                "lock_available",
            },
        )
        self.assertEqual(receipt["missing_count"], 3)
        revised_receipt = self.session.record_human_decision(
            parameter_id="temperature",
            verdict="DIFFERENT",
            reason="reconsidered after visual inspection",
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=1,
        )
        self.assertEqual(revised_receipt["missing_count"], 3)
        self.assertEqual(revised_receipt["revision"], 2)
        with self.assertRaises(MutationConflictError):
            self.session.record_human_decision(
                parameter_id="pressure",
                verdict="DIFFERENT",
                reason="difference",
                evidence_manifest_hash=self.session.evidence_manifest_hash,
                expected_revision=0,
            )
        with self.assertRaises(MutationConflictError):
            self.session.record_human_decision(
                parameter_id="pressure",
                verdict="DIFFERENT",
                reason="difference",
                evidence_manifest_hash="0" * 64,
                expected_revision=2,
            )
        decisions = self.session.task.human_decisions()
        self.assertEqual(set(decisions), {"temperature"})
        self.assertEqual(self.session.revision, 2)

    def test_two_concurrent_writes_with_one_revision_cannot_both_commit(self) -> None:
        barrier = Barrier(3)
        outcomes: list[str] = []

        def write(verdict: str, reason: str | None) -> None:
            barrier.wait()
            try:
                self.session.record_human_decision(
                    parameter_id="pressure",
                    verdict=verdict,
                    reason=reason,
                    evidence_manifest_hash=self.session.evidence_manifest_hash,
                    expected_revision=0,
                )
            except MutationConflictError:
                outcomes.append("conflict")
            else:
                outcomes.append("committed")

        threads = (
            Thread(target=write, args=("SAME", None)),
            Thread(target=write, args=("DIFFERENT", "observed mismatch")),
        )
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(sorted(outcomes), ["committed", "conflict"])
        self.assertEqual(self.session.revision, 1)
        self.assertEqual(set(self.session.task.human_decisions()), {"pressure"})

    def test_web_reason_limit_is_enforced_server_side(self) -> None:
        class TextSubclass(str):
            pass

        with self.assertRaisesRegex(InvalidWebRequestError, "exact strings"):
            self.session.record_human_decision(
                parameter_id="temperature",
                verdict=TextSubclass("SAME"),
                reason=None,
                evidence_manifest_hash=self.session.evidence_manifest_hash,
                expected_revision=0,
            )
        with self.assertRaisesRegex(InvalidWebRequestError, "human reason"):
            self.session.record_human_decision(
                parameter_id="pressure",
                verdict="DIFFERENT",
                reason="x" * (MAX_HUMAN_REASON_CHARACTERS + 1),
                evidence_manifest_hash=self.session.evidence_manifest_hash,
                expected_revision=0,
            )
        with self.assertRaisesRegex(InvalidWebRequestError, "must not carry"):
            self.session.record_human_decision(
                parameter_id="temperature",
                verdict="SAME",
                reason="hidden payload",
                evidence_manifest_hash=self.session.evidence_manifest_hash,
                expected_revision=0,
            )
        self.assertEqual(self.session.revision, 0)

    def test_1001_field_mutation_receipt_is_constant_size(self) -> None:
        field_count = 1001
        regions = tuple(
            ParameterRegion(
                parameter_id=f"p{index:04d}",
                display_label=f"Parameter {index}",
                value_box=BoundingBox(670, 174, 1110, 246),
            )
            for index in range(field_count)
        )
        template = FixedTemplate(
            template_id="scale-template",
            version="1.0",
            width=1200,
            height=620,
            regions=regions,
        )
        spec = SyntheticCaseSpec(
            case_id="scale-1001",
            values=tuple(
                SyntheticValuePair(f"p{index:04d}", "1", "1")
                for index in range(field_count)
            ),
        )
        with TemporaryDirectory() as output:
            rendered = render_case(spec, output_root=output, template=template)
            session = ParamGuardWebSession(
                rendered_case=rendered,
                engine=FakeTesseractEngine(),
            )
            receipt = session.record_human_decision(
                parameter_id="p0000",
                verdict="SAME",
                reason=None,
                evidence_manifest_hash=session.evidence_manifest_hash,
                expected_revision=0,
            )

        encoded = json.dumps(
            {"receipt": receipt}, separators=(",", ":")
        ).encode("utf-8")
        self.assertLess(len(encoded), 512)
        self.assertLess(len(encoded) * field_count, 512 * 1024)
        self.assertNotIn(b'"fields"', encoded)
        self.assertNotIn(b'"missing_parameter_ids"', encoded)
        self.assertEqual(receipt["missing_count"], 1000)
        self.assertFalse(receipt["lock_available"])

    def test_incomplete_human_review_cannot_lock(self) -> None:
        self.session.record_human_decision(
            parameter_id="temperature",
            verdict="SAME",
            reason=None,
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=0,
        )
        with self.assertRaises(IncompleteReviewError):
            self.session.lock_human_review(
                evidence_manifest_hash=self.session.evidence_manifest_hash,
                expected_revision=1,
            )
        self.assertEqual(self.session.task.state, ReviewState.HUMAN_REVIEW_OPEN)
        self.assertEqual(self.session.revision, 1)
        self.assertEqual(self.engine.extract_calls, 0)

    def test_completed_review_locks_immutable_human_snapshot(self) -> None:
        complete_first_review(self.session)
        state = self.session.lock_human_review(
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=4,
        )
        self.assertEqual(self.session.task.state, ReviewState.HUMAN_REVIEW_LOCKED)
        self.assertEqual(state["stage"], "HUMAN_REVIEW_LOCKED")
        self.assertFalse(state["automatic_release_allowed"])
        self.assertEqual(self.engine.extract_calls, 0)
        with self.assertRaises(PublicStageUnavailableError):
            self.session.record_human_decision(
                parameter_id="mode",
                verdict="DIFFERENT",
                reason="late edit",
                evidence_manifest_hash=self.session.evidence_manifest_hash,
                expected_revision=5,
            )

    def test_real_gated_runner_uses_fake_engine_only_after_lock(self) -> None:
        complete_first_review(self.session)
        self.session.lock_human_review(
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=4,
        )
        self.assertEqual(self.engine.extract_calls, 0)
        state = self.session.run_assistive_check(
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=5,
        )
        self.assertEqual(self.engine.extract_calls, 2)
        self.assertEqual(self.session.task.state, ReviewState.AI_REVIEW_COMPLETE)
        self.assertEqual(state["stage"], "ASSISTIVE_CHECK_COMPLETE")
        self.assertFalse(state["automatic_release_allowed"])
        self.assertEqual(
            [item["parameter_id"] for item in state["assistive_results"]],
            list(self.rendered.template.expected_parameter_ids),
        )
        self.assertTrue(
            all(
                item["automatic_release_allowed"] is False
                for item in state["assistive_results"]
            )
        )
        self.assertTrue(
            state["exception_inbox"]["targeted_component_implemented"]
        )
        self.assertFalse(
            state["exception_inbox"]["independent_blind_second_review"]
        )
        self.assertFalse(state["exception_inbox"]["workflow_complete"])
        self.assertTrue(state["exception_inbox"]["items"])
        self.assertFalse(
            state["exception_inbox"]["automatic_release_allowed"]
        )
        self.assertTrue(
            state["exception_inbox"]["final_human_decision_required"]
        )

    def test_partial_runner_output_is_failed_closed_not_marked_complete(self) -> None:
        def partial_runner(*_args, **_kwargs):
            return OcrPairOutcome(
                left_quality=None,  # type: ignore[arg-type]
                right_quality=None,  # type: ignore[arg-type]
                left_ocr=(),
                right_ocr=(),
                ai_assessments=(),
                routing=(),
            )

        session = ParamGuardWebSession(
            rendered_case=self.rendered,
            engine=FakeTesseractEngine(),
            pipeline_runner=partial_runner,
        )
        complete_first_review(session)
        session.lock_human_review(
            evidence_manifest_hash=session.evidence_manifest_hash,
            expected_revision=4,
        )
        with self.assertRaises(AssistiveCheckFailedError):
            session.run_assistive_check(
                evidence_manifest_hash=session.evidence_manifest_hash,
                expected_revision=5,
            )
        state = session.public_state()
        self.assertEqual(state["stage"], "POST_LOCK_PROCESSING_FAILED_CLOSED")
        self.assertNotIn("assistive_results", state)
        self.assertFalse(state["automatic_release_allowed"])
        self.assertEqual(
            state["exception_inbox"]["status"], "MANUAL_ESCALATION_REQUIRED"
        )
        self.assertFalse(
            state["exception_inbox"]["targeted_component_implemented"]
        )
        with self.assertRaises(PublicStageUnavailableError):
            session.exception_inbox()

    def test_pipeline_and_web_quality_decode_only_captured_evidence_bytes(
        self,
    ) -> None:
        complete_first_review(self.session)
        self.session.lock_human_review(
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=4,
        )
        human_before = self.session.task.human_decisions()
        evidence_paths = {
            self.rendered.left_image_path,
            self.rendered.right_image_path,
        }
        source_path_opens = []
        original_open = Image.open

        def track_source_reopen(source, *args, **kwargs):
            if isinstance(source, (str, Path)) and Path(source) in evidence_paths:
                source_path_opens.append(Path(source))
            return original_open(source, *args, **kwargs)

        with patch.object(Image, "open", side_effect=track_source_reopen):
            state = self.session.run_assistive_check(
                evidence_manifest_hash=self.session.evidence_manifest_hash,
                expected_revision=5,
            )
        self.assertEqual(state["stage"], "ASSISTIVE_CHECK_COMPLETE")
        self.assertEqual(source_path_opens, [])
        self.assertEqual(self.session.task.human_decisions(), human_before)
        self.assertFalse(state["automatic_release_allowed"])

    def test_complete_results_with_partial_ocr_dtos_are_failed_closed(self) -> None:
        def partial_ocr_runner(*args, **kwargs):
            outcome = run_gated_ocr_pair(*args, **kwargs)
            return replace(
                outcome,
                left_ocr=outcome.left_ocr[:1],
                right_ocr=(),
            )

        session = ParamGuardWebSession(
            rendered_case=self.rendered,
            engine=FakeTesseractEngine(),
            pipeline_runner=partial_ocr_runner,
        )
        complete_first_review(session)
        session.lock_human_review(
            evidence_manifest_hash=session.evidence_manifest_hash,
            expected_revision=4,
        )
        with self.assertRaises(AssistiveCheckFailedError):
            session.run_assistive_check(
                evidence_manifest_hash=session.evidence_manifest_hash,
                expected_revision=5,
            )
        self.assertEqual(
            session.public_state()["stage"],
            "POST_LOCK_PROCESSING_FAILED_CLOSED",
        )

    def test_forged_quality_dto_is_recomputed_and_failed_closed(self) -> None:
        def forged_quality_runner(*args, **kwargs):
            outcome = run_gated_ocr_pair(*args, **kwargs)
            poison = lambda quality: replace(
                quality,
                width=1,
                height=1,
                contrast_stddev=float("nan"),
                edge_variance=-1.0,
                config_sha256="0" * 64,
            )
            return replace(
                outcome,
                left_quality=poison(outcome.left_quality),
                right_quality=poison(outcome.right_quality),
            )

        session = ParamGuardWebSession(
            rendered_case=self.rendered,
            engine=FakeTesseractEngine(),
            pipeline_runner=forged_quality_runner,
        )
        complete_first_review(session)
        session.lock_human_review(
            evidence_manifest_hash=session.evidence_manifest_hash,
            expected_revision=4,
        )
        with self.assertRaises(AssistiveCheckFailedError):
            session.run_assistive_check(
                evidence_manifest_hash=session.evidence_manifest_hash,
                expected_revision=5,
            )
        self.assertNotIn("assistive_results", session.public_state())

    def test_queue_or_start_failure_is_also_latched_failed_closed(self) -> None:
        session = ParamGuardWebSession(
            rendered_case=self.rendered,
            engine=FakeTesseractEngine(),
        )
        complete_first_review(session)
        session.lock_human_review(
            evidence_manifest_hash=session.evidence_manifest_hash,
            expected_revision=4,
        )
        with patch.object(
            session.task,
            "queue_ai_review",
            side_effect=RuntimeError("deliberate queue failure"),
        ):
            with self.assertRaises(AssistiveCheckFailedError):
                session.run_assistive_check(
                    evidence_manifest_hash=session.evidence_manifest_hash,
                    expected_revision=5,
                )
        state = session.public_state()
        self.assertEqual(state["stage"], "POST_LOCK_PROCESSING_FAILED_CLOSED")
        self.assertEqual(state["revision"], 6)
        self.assertFalse(state["check_available"])
        self.assertNotIn("assistive_results", state)

    def test_forged_runner_routing_is_failed_closed(self) -> None:
        def forged_routing_runner(*args, **kwargs):
            outcome = run_gated_ocr_pair(*args, **kwargs)
            forged = tuple(
                RoutingDecision(
                    parameter_id=parameter_id,
                    route=ReviewRoute.NO_EXCEPTION_DETECTED,
                    reasons=(),
                )
                for parameter_id in self.rendered.template.expected_parameter_ids
            )
            return replace(outcome, routing=forged)

        session = ParamGuardWebSession(
            rendered_case=self.rendered,
            engine=FakeTesseractEngine(),
            pipeline_runner=forged_routing_runner,
        )
        complete_first_review(session)
        session.lock_human_review(
            evidence_manifest_hash=session.evidence_manifest_hash,
            expected_revision=4,
        )
        with self.assertRaises(AssistiveCheckFailedError):
            session.run_assistive_check(
                evidence_manifest_hash=session.evidence_manifest_hash,
                expected_revision=5,
            )
        self.assertEqual(
            session.public_state()["stage"],
            "POST_LOCK_PROCESSING_FAILED_CLOSED",
        )

    def test_ocr_execution_error_becomes_qa_exception_never_success(self) -> None:
        session = ParamGuardWebSession(
            rendered_case=self.rendered,
            engine=FailingTesseractEngine(),
        )
        complete_first_review(session)
        session.lock_human_review(
            evidence_manifest_hash=session.evidence_manifest_hash,
            expected_revision=4,
        )
        state = session.run_assistive_check(
            evidence_manifest_hash=session.evidence_manifest_hash,
            expected_revision=5,
        )
        self.assertEqual(state["stage"], "ASSISTIVE_CHECK_COMPLETE")
        self.assertTrue(state["assistive_results"])
        self.assertTrue(
            all(
                item["verdict"] == "SYSTEM_ERROR"
                and item["process_next_step"]
                == "QA_STRUCTURAL_OR_SYSTEM_REVIEW"
                and item["automatic_release_allowed"] is False
                for item in state["assistive_results"]
            )
        )
        inbox = state["exception_inbox"]
        self.assertEqual(inbox["exception_detection"], "EXCEPTIONS_DETECTED")
        self.assertFalse(inbox["automatic_release_allowed"])
        self.assertFalse(inbox["workflow_complete"])

    def test_post_lock_ocr_markup_is_html_escaped(self) -> None:
        session = ParamGuardWebSession(
            rendered_case=self.rendered,
            engine=MarkupTesseractEngine(),
        )
        complete_first_review(session)
        session.lock_human_review(
            evidence_manifest_hash=session.evidence_manifest_hash,
            expected_revision=4,
        )
        session.run_assistive_check(
            evidence_manifest_hash=session.evidence_manifest_hash,
            expected_revision=5,
        )
        html = session.render_post_lock_html(nonce="trusted-nonce")
        self.assertNotIn('<img src=x onerror="globalThis.pwned=1">', html)
        self.assertIn(
            '&lt;img src=x onerror=&quot;globalThis.pwned=1&quot;&gt;',
            html,
        )

    def test_no_exception_detection_never_becomes_release_status(self) -> None:
        template = FixedTemplate(
            template_id="one-field-template",
            version="1.0",
            width=1200,
            height=620,
            regions=(
                ParameterRegion(
                    parameter_id="mode",
                    display_label="Mode",
                    value_box=BoundingBox(670, 486, 1110, 558),
                    critical=False,
                ),
            ),
        )
        spec = SyntheticCaseSpec(
            case_id="one-field-same",
            values=(SyntheticValuePair("mode", "AUTO", "AUTO"),),
        )
        with TemporaryDirectory() as output:
            rendered = render_case(spec, output_root=output, template=template)
            session = ParamGuardWebSession(
                rendered_case=rendered,
                engine=FakeTesseractEngine(),
            )
            session.record_human_decision(
                parameter_id="mode",
                verdict="SAME",
                reason=None,
                evidence_manifest_hash=session.evidence_manifest_hash,
                expected_revision=0,
            )
            session.lock_human_review(
                evidence_manifest_hash=session.evidence_manifest_hash,
                expected_revision=1,
            )
            state = session.run_assistive_check(
                evidence_manifest_hash=session.evidence_manifest_hash,
                expected_revision=2,
            )

        inbox = state["exception_inbox"]
        self.assertEqual(inbox["status"], "TARGETED_RECHECK_OPEN")
        self.assertEqual(
            inbox["exception_detection"],
            "NO_EXCEPTION_DETECTED_WAITING_FINAL_HUMAN_CONFIRMATION",
        )
        self.assertFalse(inbox["workflow_complete"])
        self.assertFalse(inbox["automatic_release_allowed"])
        self.assertTrue(inbox["final_human_decision_required"])
        self.assertEqual(inbox["items"], [])

    def test_command_id_cannot_be_reused_across_web_side_effects(self) -> None:
        shared_command_id = "shared-cross-endpoint-command"
        parameter_ids = self.rendered.template.expected_parameter_ids
        for revision, parameter_id in enumerate(parameter_ids):
            self.session.record_human_decision(
                parameter_id=parameter_id,
                verdict="SAME",
                reason=None,
                evidence_manifest_hash=self.session.evidence_manifest_hash,
                expected_revision=revision,
                command_id=(
                    shared_command_id if revision == 0 else f"decision-{revision}"
                ),
            )

        with self.assertRaisesRegex(MutationConflictError, "another mutation"):
            self.session.lock_human_review(
                evidence_manifest_hash=self.session.evidence_manifest_hash,
                expected_revision=len(parameter_ids),
                command_id=shared_command_id,
            )
        self.assertEqual(self.session.task.state, ReviewState.HUMAN_REVIEW_OPEN)
        self.assertEqual(self.session.revision, len(parameter_ids))

        self.session.lock_human_review(
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=len(parameter_ids),
            command_id="unique-lock-command",
        )
        with self.assertRaisesRegex(MutationConflictError, "another mutation"):
            self.session.run_assistive_check(
                evidence_manifest_hash=self.session.evidence_manifest_hash,
                expected_revision=len(parameter_ids) + 1,
                command_id="unique-lock-command",
            )
        self.assertEqual(self.session.task.state, ReviewState.HUMAN_REVIEW_LOCKED)
        self.assertEqual(self.engine.extract_calls, 0)

        assistive_command_id = "shared-assistive-targeted-command"
        self.session.run_assistive_check(
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=len(parameter_ids) + 1,
            command_id=assistive_command_id,
        )
        inbox = self.session.exception_inbox()
        with self.assertRaisesRegex(MutationConflictError, "another mutation"):
            self.session.record_targeted_decision(
                **targeted_bindings(inbox),
                parameter_id="speed",
                verdict="SAME",
                reason="Synthetic cross-stage replay must fail",
                command_id=assistive_command_id,
                expected_revision=0,
            )
        self.assertEqual(
            self.session.exception_inbox()["targeted_decision_count"], 0
        )

        targeted_command_id = "shared-targeted-decision-lock-command"
        self.session.record_targeted_decision(
            **targeted_bindings(inbox),
            parameter_id="speed",
            verdict="SAME",
            reason="Synthetic independent targeted observation",
            command_id=targeted_command_id,
            expected_revision=0,
        )
        with self.assertRaisesRegex(MutationConflictError, "another mutation"):
            self.session.lock_targeted_review(
                **targeted_bindings(inbox),
                command_id=targeted_command_id,
                expected_revision=1,
            )
        self.assertEqual(
            self.session.exception_inbox()["status"], "TARGETED_RECHECK_OPEN"
        )

    def test_bound_image_asset_detects_post_manifest_tampering(self) -> None:
        self.rendered.left_image_path.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.session.image_asset(side="left", asset_name="full.png")

    def test_targeted_recheck_is_real_but_never_closes_or_releases(self) -> None:
        state = complete_default_assistive_check(self.session)
        inbox = state["exception_inbox"]
        self.assertEqual(
            [item["parameter_id"] for item in inbox["items"]], ["speed"]
        )
        self.assertEqual(
            [item["parameter_id"] for item in inbox["qa_referrals"]],
            ["temperature", "pressure"],
        )
        self.assertEqual(inbox["no_exception_count"], 1)
        self.assertTrue(inbox["same_reviewer_as_r1"])
        self.assertFalse(inbox["independent_blind_second_review"])

        bindings = targeted_bindings(inbox)
        with self.assertRaises(TargetedReviewIncompleteWebError):
            self.session.lock_targeted_review(
                **bindings,
                command_id="targeted-lock-too-early",
                expected_revision=0,
            )

        receipt = self.session.record_targeted_decision(
            **bindings,
            parameter_id="speed",
            verdict="SAME",
            reason="Synthetic ROI was checked again character by character",
            command_id="targeted-decision-speed-1",
            expected_revision=0,
        )
        self.assertEqual(
            set(receipt),
            {
                "stage",
                "revision",
                "decision",
                "missing_count",
                "lock_available",
                "workflow_complete",
                "automatic_release_allowed",
                "final_human_decision_required",
            },
        )
        self.assertFalse(receipt["decision"]["closes_exception"])
        self.assertFalse(receipt["decision"]["automatic_release_allowed"])
        self.assertFalse(receipt["workflow_complete"])
        self.assertTrue(receipt["final_human_decision_required"])
        self.assertTrue(receipt["lock_available"])

        locked = self.session.lock_targeted_review(
            **bindings,
            command_id="targeted-lock-complete",
            expected_revision=1,
        )
        self.assertEqual(
            locked["stage"],
            "TARGETED_RECHECK_LOCKED_WAITING_DOWNSTREAM_HUMAN",
        )
        self.assertFalse(locked["workflow_complete"])
        self.assertFalse(locked["automatic_release_allowed"])
        self.assertTrue(locked["final_human_decision_required"])
        self.assertTrue(locked["requires_qa"])
        locked_inbox = self.session.exception_inbox()
        self.assertEqual(
            locked_inbox["status"],
            "TARGETED_RECHECK_LOCKED_WAITING_DOWNSTREAM_HUMAN",
        )
        self.assertFalse(
            locked_inbox["items"][0]["decision"]["closes_exception"]
        )
        with self.assertRaises(PublicStageUnavailableError):
            self.session.record_targeted_decision(
                **bindings,
                parameter_id="speed",
                verdict="DIFFERENT",
                reason="late edit",
                command_id="targeted-late-edit",
                expected_revision=2,
            )

    def test_targeted_mutations_reject_every_stale_or_forged_binding(self) -> None:
        complete_default_assistive_check(self.session)
        inbox = self.session.exception_inbox()
        valid = {
            **targeted_bindings(inbox),
            "parameter_id": "speed",
            "verdict": "DIFFERENT",
            "reason": "Synthetic leading zero differs",
            "command_id": "targeted-binding-probe",
            "expected_revision": 0,
        }
        attacks = (
            {**valid, "task_id": "wrong-task"},
            {**valid, "assignment_id": "wrong-assignment"},
            {**valid, "evidence_manifest_hash": "0" * 64},
            {**valid, "source_snapshot_sha256": "0" * 64},
            {**valid, "expected_revision": 99},
        )
        for attack in attacks:
            with self.assertRaises(MutationConflictError):
                self.session.record_targeted_decision(**attack)
        with self.assertRaises(InvalidWebRequestError):
            self.session.record_targeted_decision(
                **{**valid, "expected_revision": True}
            )
        with self.assertRaises(InvalidWebRequestError):
            self.session.record_targeted_decision(
                **{
                    **valid,
                    "reason": "x" * (MAX_TARGETED_REASON_CHARACTERS + 1),
                }
            )
        class TextSubclass(str):
            pass

        with self.assertRaises(InvalidWebRequestError):
            self.session.record_targeted_decision(
                **{**valid, "task_id": TextSubclass(str(valid["task_id"]))}
            )
        self.assertEqual(self.session.exception_inbox()["revision"], 0)
        self.assertEqual(
            self.session.exception_inbox()["targeted_decision_count"], 0
        )

    def test_targeted_command_id_is_idempotent_and_payload_bound(self) -> None:
        complete_default_assistive_check(self.session)
        inbox = self.session.exception_inbox()
        payload = {
            **targeted_bindings(inbox),
            "parameter_id": "speed",
            "verdict": "DIFFERENT",
            "reason": "Synthetic leading zero remains different",
            "command_id": "targeted-idempotent-command",
            "expected_revision": 0,
        }
        first = self.session.record_targeted_decision(**payload)
        retried = self.session.record_targeted_decision(**payload)
        self.assertEqual(first, retried)
        self.assertEqual(self.session.exception_inbox()["revision"], 1)
        with self.assertRaises(MutationConflictError):
            self.session.record_targeted_decision(
                **{
                    **payload,
                    "verdict": "SAME",
                    "reason": "changed payload",
                }
            )
        self.assertEqual(self.session.exception_inbox()["revision"], 1)

    def test_targeted_revision_history_is_bounded_but_exact_retry_survives(self) -> None:
        complete_default_assistive_check(self.session)
        inbox = self.session.exception_inbox()
        bindings = targeted_bindings(inbox)
        last_payload: dict[str, object] | None = None
        last_receipt: dict[str, object] | None = None
        for revision in range(MAX_TARGETED_MUTATIONS_PER_PARAMETER):
            last_payload = {
                **bindings,
                "parameter_id": "speed",
                "verdict": "SAME",
                "reason": f"Synthetic bounded revision {revision}",
                "command_id": f"targeted-bounded-{revision}",
                "expected_revision": revision,
            }
            last_receipt = self.session.record_targeted_decision(**last_payload)

        assert last_payload is not None and last_receipt is not None
        self.assertEqual(
            self.session.record_targeted_decision(**last_payload), last_receipt
        )
        with self.assertRaises(TargetedMutationLimitError):
            self.session.record_targeted_decision(
                **bindings,
                parameter_id="speed",
                verdict="DIFFERENT",
                reason="Synthetic attempt beyond finite history budget",
                command_id="targeted-bounded-overflow",
                expected_revision=MAX_TARGETED_MUTATIONS_PER_PARAMETER,
            )
        with running_server(self.session) as (base, _host, _port):
            status, _, body = http_request(
                base,
                "POST",
                "/api/targeted-decision",
                {
                    **bindings,
                    "parameter_id": "speed",
                    "verdict": "DIFFERENT",
                    "reason": "Synthetic HTTP attempt beyond history budget",
                    "command_id": "targeted-bounded-http-overflow",
                    "expected_revision": MAX_TARGETED_MUTATIONS_PER_PARAMETER,
                },
            )
        self.assertEqual(status, 429)
        self.assertEqual(
            json.loads(body), {"error": "TARGETED_MUTATION_LIMIT_REACHED"}
        )
        self.assertEqual(
            self.session.exception_inbox()["revision"],
            MAX_TARGETED_MUTATIONS_PER_PARAMETER,
        )
        assert self.session._targeted_review is not None
        self.assertEqual(
            len(self.session._targeted_review.own_decision_history(
                actor=self.session._targeted_reviewer
            )),
            MAX_TARGETED_MUTATIONS_PER_PARAMETER,
        )

    def test_two_concurrent_targeted_writes_with_one_revision_use_cas(self) -> None:
        complete_default_assistive_check(self.session)
        inbox = self.session.exception_inbox()
        bindings = targeted_bindings(inbox)
        barrier = Barrier(3)
        outcomes: list[str] = []

        def write(verdict: str, command_id: str) -> None:
            barrier.wait()
            try:
                self.session.record_targeted_decision(
                    **bindings,
                    parameter_id="speed",
                    verdict=verdict,
                    reason=f"Synthetic concurrency decision {verdict}",
                    command_id=command_id,
                    expected_revision=0,
                )
            except MutationConflictError:
                outcomes.append("conflict")
            else:
                outcomes.append("committed")

        threads = (
            Thread(target=write, args=("SAME", "targeted-thread-a")),
            Thread(target=write, args=("DIFFERENT", "targeted-thread-b")),
        )
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(sorted(outcomes), ["committed", "conflict"])
        self.assertEqual(self.session.exception_inbox()["revision"], 1)
        self.assertEqual(
            self.session.exception_inbox()["targeted_decision_count"], 1
        )

    def test_targeted_reason_markup_is_escaped_in_html_and_bootstrap(self) -> None:
        complete_default_assistive_check(self.session)
        inbox = self.session.exception_inbox()
        attack = '</script><img src=x onerror="globalThis.pwned=1">'
        self.session.record_targeted_decision(
            **targeted_bindings(inbox),
            parameter_id="speed",
            verdict="SAME",
            reason=attack,
            command_id="targeted-markup-reason",
            expected_revision=0,
        )
        html = self.session.render_post_lock_html(nonce="trusted-nonce")
        self.assertNotIn(attack, html)
        self.assertNotIn('<img src=x onerror="globalThis.pwned=1">', html)
        self.assertIn(
            "&lt;/script&gt;&lt;img src=x onerror=&quot;globalThis.pwned=1&quot;&gt;",
            html,
        )

    def test_1001_targeted_mutation_receipt_remains_constant_size(self) -> None:
        field_count = 1001
        template = FixedTemplate(
            template_id="targeted-scale-template",
            version="1.0",
            width=1200,
            height=620,
            regions=tuple(
                ParameterRegion(
                    parameter_id=f"p{index:04d}",
                    display_label=f"Parameter {index}",
                    value_box=BoundingBox(670, 174, 1110, 246),
                )
                for index in range(field_count)
            ),
        )
        spec = SyntheticCaseSpec(
            case_id="targeted-scale-1001",
            values=tuple(
                SyntheticValuePair(f"p{index:04d}", "1", "1")
                for index in range(field_count)
            ),
        )
        with TemporaryDirectory() as output:
            session = ParamGuardWebSession(
                rendered_case=render_case(
                    spec, output_root=output, template=template
                ),
                engine=UniformTesseractEngine(),
            )
            for index in range(field_count):
                session.record_human_decision(
                    parameter_id=f"p{index:04d}",
                    verdict="DIFFERENT",
                    reason="Synthetic R1 difference",
                    evidence_manifest_hash=session.evidence_manifest_hash,
                    expected_revision=index,
                )
            session.lock_human_review(
                evidence_manifest_hash=session.evidence_manifest_hash,
                expected_revision=field_count,
            )
            session.run_assistive_check(
                evidence_manifest_hash=session.evidence_manifest_hash,
                expected_revision=field_count + 1,
            )
            inbox = session.exception_inbox()
            self.assertEqual(len(inbox["items"]), field_count)
            receipt = session.record_targeted_decision(
                **targeted_bindings(inbox),
                parameter_id="p0000",
                verdict="SAME",
                reason="Synthetic targeted recheck",
                command_id="targeted-scale-decision-0000",
                expected_revision=0,
            )

        encoded = json.dumps(
            {"receipt": receipt}, separators=(",", ":")
        ).encode("utf-8")
        self.assertLess(len(encoded), 768)
        self.assertNotIn(b'"items"', encoded)
        self.assertNotIn(b'"qa_referrals"', encoded)
        self.assertNotIn(b'"no_exception_parameter_ids"', encoded)
        self.assertEqual(receipt["missing_count"], 1000)
        self.assertFalse(receipt["lock_available"])


class WebHttpTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        rendered = render_case(default_clean_case(), output_root=self.temporary.name)
        self.engine = FakeTesseractEngine()
        self.session = ParamGuardWebSession(
            rendered_case=rendered,
            engine=self.engine,
        )

    def test_prelock_html_and_errors_do_not_leak_post_lock_clues(self) -> None:
        forbidden = (
            b"run_id",
            b"pipeline",
            b"tesseract",
            b"ocr",
            b"confidence",
            b"routing",
            b"assistive_results",
            b"run-ai-assistive-check",
            b"targeted",
            b"profile",
            b"routing_context",
            b"source_snapshot",
        )
        with running_server(self.session) as (base, _host, _port):
            status, headers, body = http_request(base, "GET", "/")
            self.assertEqual(status, 200)
            lowered = body.lower()
            for token in forbidden:
                self.assertNotIn(token, lowered)
            self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")
            self.assertEqual(headers["Pragma"], "no-cache")
            self.assertNotIn("ETag", headers)
            self.assertNotIn("Last-Modified", headers)
            self.assertNotIn("Server", headers)
            self.assertNotIn("Date", headers)

            status, error_headers, error_body = http_request(
                base,
                "POST",
                "/api/assistive-check",
                {
                    "evidence_manifest_hash": self.session.evidence_manifest_hash,
                    "expected_revision": 0,
                },
            )
            self.assertEqual(status, 409)
            self.assertEqual(
                json.loads(error_body), {"error": "STAGE_NOT_AVAILABLE"}
            )
            joined_headers = "\n".join(
                f"{key}:{value}" for key, value in error_headers.items()
            ).lower().encode()
            for token in forbidden:
                self.assertNotIn(token, error_body.lower() + joined_headers)
            self.assertEqual(self.engine.extract_calls, 0)

            status, _, body = http_request(base, "GET", "/post-lock")
            self.assertEqual(status, 409)
            self.assertEqual(json.loads(body), {"error": "STAGE_NOT_AVAILABLE"})

    def test_page_has_side_by_side_full_evidence_rois_and_keyboard_controls(self) -> None:
        with running_server(self.session) as (base, _host, _port):
            status, _, body = http_request(base, "GET", "/")
            self.assertEqual(status, 200)
            text = body.decode("utf-8")
            self.assertIn('/evidence/left/full.png', text)
            self.assertIn('/evidence/right/full.png', text)
            self.assertIn("event.key.toLowerCase()", text)
            self.assertIn("s: 'SAME'", text)
            self.assertIn("d: 'DIFFERENT'", text)
            self.assertIn("u: 'UNABLE_TO_JUDGE'", text)
            self.assertIn("applyReceipt(result.receipt)", text)
            self.assertIn("cardsById.get(decision.parameter_id)", text)
            self.assertIn("loading=\"lazy\"", text)
            for parameter_id in self.session.task.expected_parameter_ids:
                self.assertIn(f'/evidence/left/{parameter_id}.png', text)
                self.assertIn(f'/evidence/right/{parameter_id}.png', text)

    def test_csp_nonce_covers_every_inline_style_and_script(self) -> None:
        with running_server(self.session) as (base, _host, _port):
            status, headers, body = http_request(base, "GET", "/")
        self.assertEqual(status, 200)
        csp = headers["Content-Security-Policy"]
        match = re.search(r"script-src 'nonce-([^']+)'", csp)
        self.assertIsNotNone(match)
        assert match is not None
        nonce = match.group(1)
        self.assertIn(f"style-src 'nonce-{nonce}'", csp)
        self.assertNotIn("unsafe-inline", csp)
        html = body.decode("utf-8")
        self.assertNotIn("{{CSP_NONCE}}", html)
        self.assertNotIn("{{BOOTSTRAP_JSON}}", html)
        self.assertNotIn("{{FIELD_ROWS}}", html)
        tag_nonces = re.findall(r"<(?:style|script)[^>]* nonce=\"([^\"]+)\"", html)
        self.assertGreaterEqual(len(tag_nonces), 3)
        self.assertEqual(set(tag_nonces), {nonce})

    def test_saved_human_reason_cannot_break_embedded_json_script(self) -> None:
        payload = '</script><script nonce="stolen">globalThis.pwned=1</script>'
        self.session.record_human_decision(
            parameter_id="pressure",
            verdict="DIFFERENT",
            reason=payload,
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=0,
        )
        html = self.session.render_first_review_html(nonce="trusted-nonce")
        self.assertNotIn(payload, html)
        self.assertIn("\\u003c/script\\u003e", html)
        self.assertNotIn('nonce="stolen"', html)

    def test_image_allowlist_serves_bound_full_image_and_exact_roi(self) -> None:
        with running_server(self.session) as (base, _host, _port):
            status, headers, full = http_request(
                base, "GET", "/evidence/left/full.png"
            )
            self.assertEqual(status, 200)
            self.assertEqual(headers.get_content_type(), "image/png")
            with Image.open(BytesIO(full)) as image:
                self.assertEqual(image.size, (1200, 620))

            status, _, roi = http_request(
                base, "GET", "/evidence/right/pressure.png"
            )
            self.assertEqual(status, 200)
            with Image.open(BytesIO(roi)) as image:
                region = self.session.task.evidence_manifest.expected_parameter_ids
                self.assertIn("pressure", region)
                self.assertEqual(image.size, (440, 72))

    def test_path_traversal_and_unknown_assets_fail_closed(self) -> None:
        with running_server(self.session) as (_base, host, port):
            for path in (
                "/evidence/left/%2e%2e/full.png",
                "/evidence/left/..%2ffull.png",
                "/evidence/left/%252e%252e/full.png",
                "/evidence/left/%c0%ae%c0%ae/full.png",
                "/evidence/left/unknown.png",
                "/evidence/right/pressure.png?hint=1",
                "/evidence\\left\\full.png",
            ):
                connection = http.client.HTTPConnection(host, port, timeout=10)
                connection.request("GET", path)
                response = connection.getresponse()
                body = response.read()
                connection.close()
                self.assertEqual(response.status, 404, path)
                self.assertEqual(json.loads(body), {"error": "NOT_FOUND"})

    def test_http_stale_revision_and_wrong_manifest_do_not_mutate(self) -> None:
        with running_server(self.session) as (base, _host, _port):
            status, _, body = http_request(
                base,
                "POST",
                "/api/decision",
                {
                    "parameter_id": "temperature",
                    "verdict": "SAME",
                    "reason": None,
                    "evidence_manifest_hash": self.session.evidence_manifest_hash,
                    "expected_revision": 0,
                },
            )
            self.assertEqual(status, 200)
            receipt = json.loads(body)["receipt"]
            self.assertEqual(receipt["revision"], 1)
            self.assertEqual(receipt["decision"]["parameter_id"], "temperature")
            self.assertNotIn("fields", receipt)

            status, _, body = http_request(
                base,
                "POST",
                "/api/decision",
                {
                    "parameter_id": "pressure",
                    "verdict": "DIFFERENT",
                    "reason": "difference",
                    "evidence_manifest_hash": self.session.evidence_manifest_hash,
                    "expected_revision": 0,
                },
            )
            self.assertEqual(status, 409)
            self.assertEqual(json.loads(body), {"error": "MUTATION_CONFLICT"})

            status, _, _ = http_request(
                base,
                "POST",
                "/api/decision",
                {
                    "parameter_id": "pressure",
                    "verdict": "DIFFERENT",
                    "reason": "difference",
                    "evidence_manifest_hash": "0" * 64,
                    "expected_revision": 1,
                },
            )
            self.assertEqual(status, 409)
            self.assertEqual(
                set(self.session.task.human_decisions()), {"temperature"}
            )

    def test_http_first_review_exact_retry_is_payload_bound_and_idempotent(
        self,
    ) -> None:
        payload = {
            "parameter_id": "temperature",
            "verdict": "SAME",
            "reason": None,
            "evidence_manifest_hash": self.session.evidence_manifest_hash,
            "expected_revision": 0,
            "command_id": "first-review-response-loss-001",
        }
        with running_server(self.session) as (base, _host, _port):
            first_status, _, first_body = http_request(
                base, "POST", "/api/decision", payload
            )
            retry_status, _, retry_body = http_request(
                base, "POST", "/api/decision", payload
            )
            conflict_status, _, conflict_body = http_request(
                base,
                "POST",
                "/api/decision",
                {
                    **payload,
                    "verdict": "DIFFERENT",
                    "reason": "same command, different payload",
                },
            )

        self.assertEqual(first_status, 200)
        self.assertEqual(retry_status, 200)
        self.assertEqual(first_body, retry_body)
        self.assertEqual(conflict_status, 409)
        self.assertEqual(
            json.loads(conflict_body), {"error": "MUTATION_CONFLICT"}
        )
        self.assertEqual(self.session.revision, 1)
        self.assertEqual(len(self.session.task.human_decisions()), 1)
        self.assertEqual(self.engine.extract_calls, 0)

    def test_host_header_absolute_target_and_dns_rebinding_forms_fail_closed(self) -> None:
        with running_server(self.session) as (_base, host, port):
            invalid_header_sets = (
                (("Host", f"localhost:{port + 1}"),),
                (("Host", f"127.0.0.1:{port + 1}"),),
                (("Host", f"evil.example:{port}"),),
                (("Host", f"localhost.evil.example:{port}"),),
                (
                    ("Host", f"{host}:{port}"),
                    ("Host", f"evil.example:{port}"),
                ),
            )
            for headers in invalid_header_sets:
                status, _, body = raw_http_request(
                    host,
                    port,
                    "GET",
                    "/api/state",
                    headers=headers,
                )
                self.assertEqual(status, 400, headers)
                self.assertEqual(json.loads(body), {"error": "INVALID_REQUEST"})

            status, _, body = raw_http_request(
                host,
                port,
                "GET",
                f"http://{host}:{port}/api/state",
                headers=(("Host", f"{host}:{port}"),),
            )
            self.assertEqual(status, 404)
            self.assertEqual(json.loads(body), {"error": "NOT_FOUND"})

            status, _, body = raw_http_request(
                host,
                port,
                "GET",
                "/api/state",
                headers=(("Host", f"localhost:{port}"),),
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["stage"], "HUMAN_REVIEW_OPEN")

    def test_unsupported_methods_do_not_use_stdlib_diagnostic_responses(self) -> None:
        with running_server(self.session) as (_base, host, port):
            for method, expected_status, expected_body in (
                ("HEAD", 405, b""),
                ("TRACE", 405, b'{"error":"NOT_ALLOWED"}'),
                ("BREW", 501, b'{"error":"NOT_ALLOWED"}'),
            ):
                status, headers, body = raw_http_request(
                    host,
                    port,
                    method,
                    "/",
                    headers=(("Host", f"{host}:{port}"),),
                )
                self.assertEqual(status, expected_status, method)
                self.assertEqual(body, expected_body, method)
                self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")
                self.assertIsNone(headers.get("Server"), method)
                self.assertIsNone(headers.get("Date"), method)
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_slow_clients_have_a_finite_worker_budget(self) -> None:
        server = create_demo_server(
            self.session,
            port=0,
            max_concurrent_requests=2,
        )
        handle_error_patcher = patch.object(
            server,
            "handle_error",
            wraps=server.handle_error,
        )
        handle_error = handle_error_patcher.start()
        self.addCleanup(handle_error_patcher.stop)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address[:2]
        slow_clients: list[socket.socket] = []
        try:
            partial = (
                f"POST /api/decision HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 10\r\n\r\n{"
            ).encode("ascii")
            for _ in range(2):
                client = socket.create_connection((host, port), timeout=2)
                client.sendall(partial)
                slow_clients.append(client)

            deadline = time.monotonic() + 2
            while server.active_request_count != 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(server.active_request_count, 2)

            status, headers, body = raw_http_request(
                host,
                port,
                "GET",
                "/api/state",
                headers=(("Host", f"{host}:{port}"),),
            )
            self.assertEqual(status, 503)
            self.assertEqual(json.loads(body), {"error": "SERVER_BUSY"})
            self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")
            self.assertIsNone(headers.get("Server"))
            self.assertLessEqual(server.active_request_count, 2)
        finally:
            for client in slow_clients:
                client.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(handle_error.call_count, 0)

    def test_cross_origin_mutations_and_cors_preflight_are_rejected(self) -> None:
        payload = json.dumps(
            {
                "parameter_id": "temperature",
                "verdict": "SAME",
                "reason": None,
                "evidence_manifest_hash": self.session.evidence_manifest_hash,
                "expected_revision": 0,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        with running_server(self.session) as (_base, host, port):
            common = (
                ("Host", f"{host}:{port}"),
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(payload))),
            )
            for extra in (
                (("Origin", "https://evil.example"),),
                (("Sec-Fetch-Site", "cross-site"),),
                (("Origin", f"http://localhost:{port}"),),
            ):
                status, headers, body = raw_http_request(
                    host,
                    port,
                    "POST",
                    "/api/decision",
                    headers=common + extra,
                    body=payload,
                )
                self.assertEqual(status, 400, extra)
                self.assertEqual(json.loads(body), {"error": "INVALID_REQUEST"})
                self.assertIsNone(headers.get("Access-Control-Allow-Origin"))
            self.assertEqual(self.session.revision, 0)

            status, headers, _ = raw_http_request(
                host,
                port,
                "OPTIONS",
                "/api/decision",
                headers=(
                    ("Host", f"{host}:{port}"),
                    ("Origin", "https://evil.example"),
                    ("Access-Control-Request-Method", "POST"),
                ),
            )
            self.assertEqual(status, 405)
            self.assertIsNone(headers.get("Access-Control-Allow-Origin"))

            status, _, body = raw_http_request(
                host,
                port,
                "POST",
                "/api/decision",
                headers=common + (("Origin", f"http://{host}:{port}"),),
                body=payload,
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["receipt"]["revision"], 1)

    def test_json_parser_rejects_duplicates_nan_ambiguous_framing_and_large_body(self) -> None:
        manifest = self.session.evidence_manifest_hash
        duplicate = (
            '{"parameter_id":"temperature","verdict":"SAME","reason":null,'
            f'"evidence_manifest_hash":"{manifest}",'
            '"expected_revision":999,"expected_revision":0}'
        ).encode("utf-8")
        nonfinite = (
            '{"parameter_id":"temperature","verdict":"SAME","reason":null,'
            f'"evidence_manifest_hash":"{manifest}","expected_revision":NaN}}'
        ).encode("utf-8")
        with running_server(self.session) as (_base, host, port):
            for body in (duplicate, nonfinite):
                status, _, response = raw_http_request(
                    host,
                    port,
                    "POST",
                    "/api/decision",
                    headers=(
                        ("Host", f"{host}:{port}"),
                        ("Content-Type", "application/json"),
                        ("Content-Length", str(len(body))),
                    ),
                    body=body,
                )
                self.assertEqual(status, 400)
                self.assertEqual(
                    json.loads(response), {"error": "INVALID_REQUEST"}
                )

            valid = b"{}"
            status, headers, response = raw_http_request(
                host,
                port,
                "POST",
                "/api/decision",
                headers=(
                    ("Host", f"{host}:{port}"),
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(valid))),
                    ("Content-Length", str(len(valid))),
                ),
                body=valid,
            )
            self.assertEqual(status, 400)
            self.assertEqual(headers["Connection"], "close")
            self.assertEqual(json.loads(response), {"error": "INVALID_REQUEST"})

            valid_decision = json.dumps(
                {
                    "parameter_id": "temperature",
                    "verdict": "SAME",
                    "reason": None,
                    "evidence_manifest_hash": manifest,
                    "expected_revision": 0,
                },
                separators=(",", ":"),
            ).encode("utf-8")
            for ambiguous_headers, wire_body in (
                (
                    (
                        ("Content-Type", "application/json"),
                        ("Content-Type", "text/plain"),
                        ("Content-Length", str(len(valid_decision))),
                    ),
                    valid_decision,
                ),
                (
                    (
                        ("Content-Type", "application/json"),
                        ("Content-Length", str(len(valid_decision))),
                        ("Transfer-Encoding", "chunked"),
                    ),
                    valid_decision,
                ),
            ):
                status, headers, response = raw_http_request(
                    host,
                    port,
                    "POST",
                    "/api/decision",
                    headers=(("Host", f"{host}:{port}"),) + ambiguous_headers,
                    body=wire_body,
                )
                self.assertEqual(status, 400)
                self.assertEqual(headers["Connection"], "close")
                self.assertEqual(
                    json.loads(response), {"error": "INVALID_REQUEST"}
                )

            oversized = b" " * (MAX_JSON_BODY_BYTES + 1)
            status, headers, response = raw_http_request(
                host,
                port,
                "POST",
                "/api/decision",
                headers=(
                    ("Host", f"{host}:{port}"),
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(oversized))),
                ),
                body=oversized,
            )
            self.assertEqual(status, 400)
            self.assertEqual(headers["Connection"], "close")
            self.assertEqual(json.loads(response), {"error": "INVALID_REQUEST"})
        self.assertEqual(self.session.revision, 0)

    def test_backend_rejects_type_confusion_and_oversized_reason(self) -> None:
        base_payload: dict[str, object] = {
            "parameter_id": "temperature",
            "verdict": "SAME",
            "reason": None,
            "evidence_manifest_hash": self.session.evidence_manifest_hash,
            "expected_revision": 0,
        }
        attacks = (
            {**base_payload, "expected_revision": True},
            {**base_payload, "parameter_id": ["temperature"]},
            {**base_payload, "verdict": {"value": "SAME"}},
            {**base_payload, "reason": "hidden payload"},
            {
                **base_payload,
                "verdict": "DIFFERENT",
                "reason": "x" * (MAX_HUMAN_REASON_CHARACTERS + 1),
            },
        )
        with running_server(self.session) as (base, _host, _port):
            for payload in attacks:
                status, _, body = http_request(
                    base, "POST", "/api/decision", payload
                )
                self.assertEqual(status, 400, payload)
                self.assertEqual(json.loads(body), {"error": "INVALID_REQUEST"})
        self.assertEqual(self.session.revision, 0)

    def test_http_lock_requires_complete_human_review(self) -> None:
        with running_server(self.session) as (base, _host, _port):
            status, _, body = http_request(
                base,
                "POST",
                "/api/lock",
                {
                    "evidence_manifest_hash": self.session.evidence_manifest_hash,
                    "expected_revision": 0,
                },
            )
            self.assertEqual(status, 409)
            self.assertEqual(
                json.loads(body), {"error": "HUMAN_REVIEW_INCOMPLETE"}
            )
            self.assertEqual(self.session.revision, 0)
            self.assertEqual(self.session.task.state, ReviewState.HUMAN_REVIEW_OPEN)

    def test_http_lock_exact_retry_is_payload_bound_and_idempotent(self) -> None:
        complete_first_review(self.session)
        payload = {
            "evidence_manifest_hash": self.session.evidence_manifest_hash,
            "expected_revision": 4,
            "command_id": "first-review-lock-response-loss-001",
        }
        with running_server(self.session) as (base, _host, _port):
            invalid_status, _, invalid_body = http_request(
                base, "POST", "/api/lock", {**payload, "command_id": True}
            )
            first_status, _, first_body = http_request(
                base, "POST", "/api/lock", payload
            )
            retry_status, _, retry_body = http_request(
                base, "POST", "/api/lock", payload
            )
            conflict_status, _, conflict_body = http_request(
                base,
                "POST",
                "/api/lock",
                {**payload, "expected_revision": 3},
            )

        self.assertEqual(invalid_status, 400)
        self.assertEqual(json.loads(invalid_body), {"error": "INVALID_REQUEST"})
        self.assertEqual(first_status, 200)
        self.assertEqual(retry_status, 200)
        self.assertEqual(first_body, retry_body)
        self.assertEqual(conflict_status, 409)
        self.assertEqual(
            json.loads(conflict_body), {"error": "MUTATION_CONFLICT"}
        )
        self.assertEqual(self.session.revision, 5)
        self.assertEqual(self.session.task.state, ReviewState.HUMAN_REVIEW_LOCKED)
        self.assertEqual(self.engine.extract_calls, 0)

    def test_ai_button_appears_only_after_lock(self) -> None:
        with running_server(self.session) as (base, _host, _port):
            status, _, body = http_request(base, "GET", "/")
            self.assertEqual(status, 200)
            self.assertNotIn(b"run-ai-assistive-check", body.lower())

            complete_first_review(self.session)
            self.session.lock_human_review(
                evidence_manifest_hash=self.session.evidence_manifest_hash,
                expected_revision=4,
            )
            status, _, body = http_request(base, "GET", "/post-lock")
            self.assertEqual(status, 200)
            self.assertIn(b'id="run-ai-assistive-check"', body.lower())
            self.assertIn("不能自动放行".encode("utf-8"), body)
            self.assertEqual(self.engine.extract_calls, 0)

    def test_http_post_lock_check_returns_auxiliary_results_and_open_inbox(self) -> None:
        complete_first_review(self.session)
        self.session.lock_human_review(
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=4,
        )
        with running_server(self.session) as (base, _host, _port):
            status, _, body = http_request(
                base,
                "POST",
                "/api/assistive-check",
                {
                    "evidence_manifest_hash": self.session.evidence_manifest_hash,
                    "expected_revision": 5,
                },
            )
            self.assertEqual(status, 200)
            state = json.loads(body)["state"]
            self.assertEqual(state["stage"], "ASSISTIVE_CHECK_COMPLETE")
            self.assertEqual(self.engine.extract_calls, 2)
            self.assertFalse(state["automatic_release_allowed"])
            self.assertTrue(state["assistive_results"])
            self.assertTrue(
                all(
                    item["automatic_release_allowed"] is False
                    for item in state["assistive_results"]
                )
            )

            status, _, inbox_body = http_request(
                base, "GET", "/api/exception-inbox"
            )
            self.assertEqual(status, 200)
            inbox = json.loads(inbox_body)
            self.assertTrue(inbox["targeted_component_implemented"])
            self.assertFalse(inbox["independent_blind_second_review"])
            self.assertFalse(inbox["workflow_complete"])
            self.assertEqual(inbox["status"], "TARGETED_RECHECK_OPEN")
            self.assertEqual(inbox["exception_detection"], "EXCEPTIONS_DETECTED")
            self.assertFalse(inbox["request_actor_authenticated"])
            self.assertEqual(
                inbox["actor_authentication_status"],
                "NOT_IMPLEMENTED_LOCAL_DEMO",
            )
            self.assertFalse(inbox["automatic_release_allowed"])
            self.assertTrue(inbox["final_human_decision_required"])

            status, _, page = http_request(base, "GET", "/post-lock")
            self.assertEqual(status, 200)
            self.assertNotIn(b'id="run-ai-assistive-check"', page.lower())
            self.assertIn("不能自动放行".encode("utf-8"), page)
            self.assertIn(
                b"TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK", page
            )
            self.assertNotIn(b"FULL_MANIFEST_BLIND_SECOND_REVIEW", page)
            self.assertIn(
                "不表示已验证、已批准或已放行".encode("utf-8"), page
            )
            self.assertIn("不是已验证身份或电子签名".encode("utf-8"), page)

    def test_http_assistive_exact_retry_replays_without_duplicate_ocr(self) -> None:
        complete_first_review(self.session)
        self.session.lock_human_review(
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=4,
        )
        payload = {
            "evidence_manifest_hash": self.session.evidence_manifest_hash,
            "expected_revision": 5,
            "command_id": "assistive-response-loss-001",
        }
        with running_server(self.session) as (base, _host, _port):
            invalid_status, _, invalid_body = http_request(
                base,
                "POST",
                "/api/assistive-check",
                {**payload, "command_id": True},
            )
            first_status, _, first_body = http_request(
                base, "POST", "/api/assistive-check", payload
            )
            retry_status, _, retry_body = http_request(
                base, "POST", "/api/assistive-check", payload
            )
            conflict_status, _, conflict_body = http_request(
                base,
                "POST",
                "/api/assistive-check",
                {**payload, "expected_revision": 4},
            )

        self.assertEqual(invalid_status, 400)
        self.assertEqual(json.loads(invalid_body), {"error": "INVALID_REQUEST"})
        self.assertEqual(first_status, 200)
        self.assertEqual(retry_status, 200)
        self.assertEqual(first_body, retry_body)
        self.assertEqual(conflict_status, 409)
        self.assertEqual(
            json.loads(conflict_body), {"error": "MUTATION_CONFLICT"}
        )
        self.assertEqual(self.session.revision, 6)
        self.assertEqual(self.session.task.state, ReviewState.AI_REVIEW_COMPLETE)
        self.assertEqual(self.engine.extract_calls, 2)

    def test_http_targeted_decision_and_lock_use_full_frozen_bindings(self) -> None:
        complete_default_assistive_check(self.session)
        with running_server(self.session) as (base, _host, _port):
            status, _, body = http_request(base, "GET", "/api/exception-inbox")
            self.assertEqual(status, 200)
            inbox = json.loads(body)
            self.assertEqual(inbox["status"], "TARGETED_RECHECK_OPEN")
            self.assertEqual(
                [item["parameter_id"] for item in inbox["items"]], ["speed"]
            )
            payload = {
                **targeted_bindings(inbox),
                "parameter_id": "speed",
                "verdict": "SAME",
                "reason": "Synthetic post-lock visual recheck completed",
                "command_id": "http-targeted-decision-speed",
                "expected_revision": 0,
            }
            status, _, body = http_request(
                base, "POST", "/api/targeted-decision", payload
            )
            self.assertEqual(status, 200)
            receipt = json.loads(body)["receipt"]
            self.assertEqual(receipt["revision"], 1)
            self.assertTrue(receipt["lock_available"])
            self.assertFalse(receipt["decision"]["closes_exception"])
            self.assertFalse(receipt["automatic_release_allowed"])
            self.assertNotIn("items", receipt)

            # An exact network retry is idempotent even though its expected
            # revision is now old; the command ID and complete payload bind it.
            status, _, retry_body = http_request(
                base, "POST", "/api/targeted-decision", payload
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(retry_body)["receipt"], receipt)

            lock_payload = {
                **targeted_bindings(inbox),
                "command_id": "http-targeted-lock-complete",
                "expected_revision": 1,
            }
            status, _, body = http_request(
                base, "POST", "/api/targeted-lock", lock_payload
            )
            self.assertEqual(status, 200)
            locked = json.loads(body)["receipt"]
            self.assertEqual(
                locked["stage"],
                "TARGETED_RECHECK_LOCKED_WAITING_DOWNSTREAM_HUMAN",
            )
            self.assertFalse(locked["workflow_complete"])
            self.assertFalse(locked["automatic_release_allowed"])
            self.assertTrue(locked["final_human_decision_required"])

            status, _, page = http_request(base, "GET", "/post-lock")
            self.assertEqual(status, 200)
            self.assertIn("定向异常复核已锁定".encode("utf-8"), page)
            self.assertIn("SAME".encode("utf-8"), page)
            self.assertIn("不关闭原异常".encode("utf-8"), page)
            self.assertIn("仍未闭环".encode("utf-8"), page)

    def test_http_client_cannot_choose_profile_signals_context_or_resolver(self) -> None:
        complete_default_assistive_check(self.session)
        inbox = self.session.exception_inbox()
        valid = {
            **targeted_bindings(inbox),
            "parameter_id": "speed",
            "verdict": "DIFFERENT",
            "reason": "Synthetic leading zero differs",
            "command_id": "http-context-injection-probe",
            "expected_revision": 0,
        }
        injections = (
            {"profile_id": "CONSERVATIVE_BLIND_R2"},
            {"trusted_routing_signals": []},
            {"routing_context": {}},
            {"routing_context_sha256": "0" * 64},
            {"resolver": "client-selected"},
        )
        with running_server(self.session) as (base, _host, _port):
            for injected in injections:
                status, _, body = http_request(
                    base,
                    "POST",
                    "/api/targeted-decision",
                    {**valid, **injected},
                )
                self.assertEqual(status, 400, injected)
                self.assertEqual(json.loads(body), {"error": "INVALID_REQUEST"})
            self.assertEqual(self.session.exception_inbox()["revision"], 0)

    def test_http_targeted_schema_and_stale_conflicts_fail_closed(self) -> None:
        complete_default_assistive_check(self.session)
        inbox = self.session.exception_inbox()
        valid = {
            **targeted_bindings(inbox),
            "parameter_id": "speed",
            "verdict": "SAME",
            "reason": "Synthetic visual recheck",
            "command_id": "http-targeted-schema-probe",
            "expected_revision": 0,
        }
        with running_server(self.session) as (base, host, port):
            for payload in (
                {key: value for key, value in valid.items() if key != "task_id"},
                {**valid, "reason": None},
                {**valid, "reason": "x" * (MAX_TARGETED_REASON_CHARACTERS + 1)},
                {**valid, "expected_revision": True},
                {**valid, "task_id": [valid["task_id"]]},
                {**valid, "evidence_manifest_hash": True},
                {**valid, "parameter_id": {"value": "speed"}},
                {**valid, "verdict": {"value": "SAME"}},
                {**valid, "command_id": ["http-targeted-schema-probe"]},
            ):
                status, _, body = http_request(
                    base, "POST", "/api/targeted-decision", payload
                )
                self.assertEqual(status, 400, payload)
                self.assertEqual(json.loads(body), {"error": "INVALID_REQUEST"})

            for key, forged in (
                ("task_id", "wrong-task"),
                ("assignment_id", "wrong-assignment"),
                ("evidence_manifest_hash", "0" * 64),
                ("source_snapshot_sha256", "0" * 64),
                ("expected_revision", 12),
            ):
                status, _, body = http_request(
                    base,
                    "POST",
                    "/api/targeted-decision",
                    {**valid, key: forged},
                )
                self.assertEqual(status, 409, key)
                self.assertEqual(json.loads(body), {"error": "MUTATION_CONFLICT"})

            duplicate = json.dumps(valid, separators=(",", ":"))[:-1]
            duplicate += ',"expected_revision":99}'
            wire = duplicate.encode("utf-8")
            status, _, body = raw_http_request(
                host,
                port,
                "POST",
                "/api/targeted-decision",
                headers=(
                    ("Host", f"{host}:{port}"),
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(wire))),
                ),
                body=wire,
            )
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(body), {"error": "INVALID_REQUEST"})
        self.assertEqual(self.session.exception_inbox()["revision"], 0)

    def test_http_targeted_mutation_rejects_cross_origin_browser(self) -> None:
        complete_default_assistive_check(self.session)
        inbox = self.session.exception_inbox()
        payload = json.dumps(
            {
                **targeted_bindings(inbox),
                "parameter_id": "speed",
                "verdict": "SAME",
                "reason": "Synthetic browser origin probe",
                "command_id": "http-targeted-origin-probe",
                "expected_revision": 0,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        with running_server(self.session) as (_base, host, port):
            status, headers, body = raw_http_request(
                host,
                port,
                "POST",
                "/api/targeted-decision",
                headers=(
                    ("Host", f"{host}:{port}"),
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(payload))),
                    ("Origin", "https://evil.example"),
                    ("Sec-Fetch-Site", "cross-site"),
                ),
                body=payload,
            )
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(body), {"error": "INVALID_REQUEST"})
            self.assertIsNone(headers.get("Access-Control-Allow-Origin"))
        self.assertEqual(self.session.exception_inbox()["revision"], 0)

    def test_targeted_endpoints_are_unavailable_before_ai_without_leakage(self) -> None:
        body = {
            "task_id": "opaque-task",
            "assignment_id": "opaque-assignment",
            "evidence_manifest_hash": self.session.evidence_manifest_hash,
            "source_snapshot_sha256": "0" * 64,
            "parameter_id": "speed",
            "verdict": "SAME",
            "reason": "synthetic",
            "command_id": "prelock-targeted-probe",
            "expected_revision": 0,
        }
        with running_server(self.session) as (base, _host, _port):
            status, headers, response = http_request(
                base, "POST", "/api/targeted-decision", body
            )
            self.assertEqual(status, 409)
            self.assertEqual(json.loads(response), {"error": "STAGE_NOT_AVAILABLE"})
            combined = response.lower() + "\n".join(
                f"{key}:{value}" for key, value in headers.items()
            ).lower().encode("utf-8")
            for forbidden in (
                b"profile",
                b"routing_context",
                b"source_snapshot",
                b"targeted_recheck_open",
                b"ai_review",
            ):
                self.assertNotIn(forbidden, combined)
        self.assertEqual(self.engine.extract_calls, 0)
        self.assertEqual(self.session.revision, 0)

    def test_post_lock_evidence_replacement_fails_closed_without_partial_results(self) -> None:
        complete_first_review(self.session)
        self.session.lock_human_review(
            evidence_manifest_hash=self.session.evidence_manifest_hash,
            expected_revision=4,
        )
        self.session._rendered.left_image_path.write_bytes(b"replaced")
        with running_server(self.session) as (base, _host, _port):
            status, _, body = http_request(
                base,
                "POST",
                "/api/assistive-check",
                {
                    "evidence_manifest_hash": self.session.evidence_manifest_hash,
                    "expected_revision": 5,
                },
            )
            self.assertEqual(status, 500)
            self.assertEqual(
                json.loads(body),
                {"error": "POST_LOCK_PROCESSING_FAILED_CLOSED"},
            )
            status, _, state_body = http_request(base, "GET", "/api/state")
            self.assertEqual(status, 200)
            state = json.loads(state_body)
            self.assertEqual(
                state["stage"], "POST_LOCK_PROCESSING_FAILED_CLOSED"
            )
            self.assertNotIn("assistive_results", state)
            self.assertFalse(state["automatic_release_allowed"])

    def test_request_schema_rejects_missing_binding_unknown_keys_and_bad_reason(self) -> None:
        with running_server(self.session) as (base, _host, _port):
            status, _, _ = http_request(
                base,
                "POST",
                "/api/decision",
                {
                    "parameter_id": "pressure",
                    "verdict": "DIFFERENT",
                    "reason": None,
                    "evidence_manifest_hash": self.session.evidence_manifest_hash,
                    "expected_revision": 0,
                },
            )
            self.assertEqual(status, 422)
            status, _, _ = http_request(
                base,
                "POST",
                "/api/lock",
                {"expected_revision": 0},
            )
            self.assertEqual(status, 400)
            status, _, _ = http_request(
                base,
                "POST",
                "/api/lock",
                {
                    "evidence_manifest_hash": self.session.evidence_manifest_hash,
                    "expected_revision": 0,
                    "unexpected": "field",
                },
            )
            self.assertEqual(status, 400)

    def test_server_refuses_non_loopback_bind_addresses(self) -> None:
        for host in ("0.0.0.0", "192.168.1.20", "localhost", "::1"):
            with self.assertRaises(ValueError, msg=host):
                create_demo_server(self.session, host=host, port=0)

    def test_static_first_review_template_itself_has_no_post_lock_button(self) -> None:
        text = STATIC_TEMPLATE_PATH.read_text(encoding="utf-8").lower()
        self.assertNotIn("run-ai-assistive-check", text)
        self.assertNotIn("assistive_results", text)
        self.assertNotIn("routing", text)
        self.assertNotIn("targeted", text)
        self.assertNotIn("profile", text)
        self.assertNotIn("source_snapshot", text)


if __name__ == "__main__":
    unittest.main()
