"""Security, blindness, concurrency, and integrity tests for second review."""

import ast
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Thread
import unittest

from paramguard.blind_review import (
    BlindEvidenceBindingError,
    BlindReasonRequiredError,
    BlindReviewLockedError,
    BlindReviewSession,
    BlindReviewState,
    BlindVerdict,
    DuplicateBlindCommandConflictError,
    IncompleteSecondReviewError,
    ReviewerSeparationError,
    StaleBlindReviewVersionError,
    UnauthorizedBlindReviewerError,
    UnknownBlindParameterError,
)
from paramguard.identity import Actor, PrincipalKind, Role
from test_workflow import make_manifest


class AdvancingClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 8, 25, 14, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        result = self.current
        self.current += timedelta(seconds=1)
        return result


def second_actor(actor_id: str = "reviewer-002") -> Actor:
    return Actor(
        actor_id=actor_id,
        kind=PrincipalKind.HUMAN,
        roles=frozenset({Role.SECOND_REVIEWER}),
    )


def different_sha256(value: str) -> str:
    """Return a valid SHA-256-shaped value that cannot equal ``value``."""

    replacement = "0" if value[0] != "0" else "1"
    return replacement + value[1:]


class BlindReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.actor = second_actor()
        self.clock = AdvancingClock()
        self.manifest = make_manifest()
        self.manifest_hash = self.manifest.manifest_hash
        self.session = BlindReviewSession(
            blind_case_id="blind-case-001",
            evidence_manifest=self.manifest,
            primary_reviewer_id="reviewer-001",
            assigned_reviewer=self.actor,
            clock=self.clock,
        )

    def _complete(self) -> None:
        self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="temperature",
            verdict=BlindVerdict.SAME,
            command_id="command-001",
            expected_version=0,
        )
        self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="pressure",
            verdict=BlindVerdict.DIFFERENT,
            reason="Values differ",
            command_id="command-002",
            expected_version=1,
        )

    def test_primary_and_second_reviewer_must_differ(self) -> None:
        with self.assertRaises(ReviewerSeparationError):
            BlindReviewSession(
                blind_case_id="blind-case-002",
                evidence_manifest=self.manifest,
                primary_reviewer_id="reviewer-001",
                assigned_reviewer=second_actor("reviewer-001"),
            )

    def test_only_assigned_human_second_reviewer_can_access(self) -> None:
        wrong_person = second_actor("reviewer-003")
        ai_actor = Actor(
            actor_id="ai-worker-001",
            kind=PrincipalKind.AI_SERVICE,
            roles=frozenset({Role.SECOND_REVIEWER}),
        )
        no_role = Actor(
            actor_id="reviewer-002",
            kind=PrincipalKind.HUMAN,
            roles=frozenset(),
        )
        for actor in (wrong_person, ai_actor, no_role):
            with self.subTest(actor=actor):
                with self.assertRaises(UnauthorizedBlindReviewerError):
                    self.session.packet(actor=actor)

    def test_packet_is_full_schema_allowlist_without_prior_result_hints(self) -> None:
        packet = self.session.packet(actor=self.actor)
        record = asdict(packet)

        self.assertEqual(
            set(record),
            {
                "blind_case_id",
                "evidence_manifest",
                "expected_parameter_ids",
                "assigned_reviewer_id",
            },
        )
        self.assertEqual(packet.expected_parameter_ids, self.manifest.expected_parameter_ids)
        flattened_keys = set()

        def collect(value):
            if isinstance(value, dict):
                flattened_keys.update(value)
                for nested in value.values():
                    collect(nested)
            elif isinstance(value, (list, tuple)):
                for nested in value:
                    collect(nested)

        collect(record)
        forbidden = ("ai", "route", "confidence", "score", "progress", "primary")
        for key in flattened_keys:
            self.assertFalse(any(word in key.lower() for word in forbidden), key)

    def test_module_does_not_import_workflow_or_routing(self) -> None:
        path = Path(__file__).parents[1] / "src/paramguard/blind_review.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
            elif isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
        self.assertFalse(any("workflow" in item for item in imports))
        self.assertFalse(any("routing" in item for item in imports))

    def test_evidence_manifest_hash_is_required_for_writes_and_lock(self) -> None:
        with self.assertRaises(TypeError):
            self.session.record_decision(
                actor=self.actor,
                parameter_id="temperature",
                verdict=BlindVerdict.SAME,
                command_id="command-without-evidence",
                expected_version=0,
            )
        with self.assertRaises(TypeError):
            self.session.lock(
                actor=self.actor,
                command_id="lock-without-evidence",
                expected_version=0,
            )

        self.assertEqual(self.session.state, BlindReviewState.OPEN)
        self.assertEqual(self.session.version, 0)
        self.assertEqual(dict(self.session.own_decisions(actor=self.actor)), {})
        self.assertEqual(self.session.own_decision_history(actor=self.actor), ())

    def test_record_decision_rejects_wrong_hash_without_consuming_command(self) -> None:
        wrong_hash = different_sha256(self.manifest_hash)

        with self.assertRaises(BlindEvidenceBindingError):
            self.session.record_decision(
                actor=self.actor,
                evidence_manifest_hash=wrong_hash,
                parameter_id="temperature",
                verdict=BlindVerdict.SAME,
                command_id="command-evidence-bound",
                expected_version=0,
            )

        self.assertEqual(self.session.state, BlindReviewState.OPEN)
        self.assertEqual(self.session.version, 0)
        self.assertEqual(dict(self.session.own_decisions(actor=self.actor)), {})
        self.assertEqual(self.session.own_decision_history(actor=self.actor), ())

        decision = self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="temperature",
            verdict=BlindVerdict.SAME,
            command_id="command-evidence-bound",
            expected_version=0,
        )
        self.assertEqual(decision.evidence_manifest_hash, self.manifest_hash)
        self.assertEqual(self.session.version, 1)

    def test_malformed_hashes_fail_closed_before_write(self) -> None:
        for bad_hash in ("", "A" * 64, "0" * 63, None):
            with self.subTest(bad_hash=bad_hash):
                with self.assertRaises(BlindEvidenceBindingError):
                    self.session.record_decision(
                        actor=self.actor,
                        evidence_manifest_hash=bad_hash,
                        parameter_id="temperature",
                        verdict=BlindVerdict.SAME,
                        command_id="command-malformed-hash",
                        expected_version=0,
                    )
                self.assertEqual(self.session.version, 0)
                self.assertEqual(
                    self.session.own_decision_history(actor=self.actor), ()
                )

    def test_wrong_hash_cannot_replay_an_idempotent_write(self) -> None:
        first = self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="temperature",
            verdict=BlindVerdict.SAME,
            command_id="command-001",
            expected_version=0,
        )

        with self.assertRaises(BlindEvidenceBindingError):
            self.session.record_decision(
                actor=self.actor,
                evidence_manifest_hash=different_sha256(self.manifest_hash),
                parameter_id="temperature",
                verdict=BlindVerdict.SAME,
                command_id="command-001",
                expected_version=0,
            )

        retry = self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="temperature",
            verdict=BlindVerdict.SAME,
            command_id="command-001",
            expected_version=0,
        )
        self.assertIs(retry, first)
        self.assertEqual(self.session.version, 1)
        self.assertEqual(len(self.session.own_decision_history(actor=self.actor)), 1)

    def test_lock_rejects_wrong_hash_without_state_change_or_command_use(self) -> None:
        self._complete()
        before = dict(self.session.own_decisions(actor=self.actor))

        with self.assertRaises(BlindEvidenceBindingError):
            self.session.lock(
                actor=self.actor,
                evidence_manifest_hash=different_sha256(self.manifest_hash),
                command_id="lock-evidence-bound",
                expected_version=2,
            )

        self.assertEqual(self.session.state, BlindReviewState.OPEN)
        self.assertEqual(self.session.version, 2)
        self.assertEqual(dict(self.session.own_decisions(actor=self.actor)), before)
        self.assertIsNone(self.session._locked_submission)

        submission = self.session.lock(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            command_id="lock-evidence-bound",
            expected_version=2,
        )
        self.assertEqual(submission.evidence_manifest_hash, self.manifest_hash)
        self.assertEqual(self.session.state, BlindReviewState.LOCKED)

    def test_wrong_hash_cannot_replay_an_idempotent_lock(self) -> None:
        self._complete()
        first = self.session.lock(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            command_id="lock-001",
            expected_version=2,
        )

        with self.assertRaises(BlindEvidenceBindingError):
            self.session.lock(
                actor=self.actor,
                evidence_manifest_hash=different_sha256(self.manifest_hash),
                command_id="lock-001",
                expected_version=2,
            )

        retry = self.session.lock(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            command_id="lock-001",
            expected_version=2,
        )
        self.assertIs(retry, first)
        self.assertEqual(self.session.version, 3)

    def test_unknown_parameter_and_exception_without_reason_are_rejected(self) -> None:
        with self.assertRaises(UnknownBlindParameterError):
            self.session.record_decision(
                actor=self.actor,
                evidence_manifest_hash=self.manifest_hash,
                parameter_id="unknown",
                verdict=BlindVerdict.SAME,
                command_id="command-001",
                expected_version=0,
            )
        for verdict in (BlindVerdict.DIFFERENT, BlindVerdict.UNABLE_TO_JUDGE):
            with self.subTest(verdict=verdict):
                with self.assertRaises(BlindReasonRequiredError):
                    self.session.record_decision(
                        actor=self.actor,
                        evidence_manifest_hash=self.manifest_hash,
                        parameter_id="temperature",
                        verdict=verdict,
                        command_id="command-001",
                        expected_version=0,
                    )

    def test_revision_preserves_history_and_latest_snapshot(self) -> None:
        first = self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="temperature",
            verdict=BlindVerdict.SAME,
            command_id="command-001",
            expected_version=0,
        )
        revised = self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="temperature",
            verdict=BlindVerdict.DIFFERENT,
            reason="Second look found a difference",
            command_id="command-002",
            expected_version=1,
        )

        self.assertEqual(
            self.session.own_decisions(actor=self.actor)["temperature"], revised
        )
        self.assertEqual(
            self.session.own_decision_history(actor=self.actor), (first, revised)
        )

    def test_incomplete_review_cannot_lock(self) -> None:
        self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="temperature",
            verdict=BlindVerdict.SAME,
            command_id="command-001",
            expected_version=0,
        )
        with self.assertRaises(IncompleteSecondReviewError) as context:
            self.session.lock(
                actor=self.actor,
                evidence_manifest_hash=self.manifest_hash,
                command_id="lock-001",
                expected_version=1,
            )

        self.assertEqual(context.exception.missing_parameter_ids, ("pressure",))
        self.assertEqual(self.session.state, BlindReviewState.OPEN)

    def test_lock_orders_decisions_by_schema_and_binds_manifest(self) -> None:
        self._complete()
        submission = self.session.lock(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            command_id="lock-001",
            expected_version=2,
        )

        self.assertEqual(self.session.state, BlindReviewState.LOCKED)
        self.assertEqual(
            tuple(item.parameter_id for item in submission.decisions),
            self.manifest.expected_parameter_ids,
        )
        self.assertEqual(submission.evidence_manifest_hash, self.manifest.manifest_hash)
        self.assertEqual(len(submission.submission_hash), 64)
        with self.assertRaises(BlindReviewLockedError):
            self.session.record_decision(
                actor=self.actor,
                evidence_manifest_hash=self.manifest_hash,
                parameter_id="temperature",
                verdict=BlindVerdict.SAME,
                command_id="command-after-lock",
                expected_version=3,
            )

    def test_stale_version_is_rejected(self) -> None:
        self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="temperature",
            verdict=BlindVerdict.SAME,
            command_id="command-001",
            expected_version=0,
        )
        with self.assertRaises(StaleBlindReviewVersionError):
            self.session.record_decision(
                actor=self.actor,
                evidence_manifest_hash=self.manifest_hash,
                parameter_id="pressure",
                verdict=BlindVerdict.SAME,
                command_id="command-002",
                expected_version=0,
            )

    def test_idempotent_retry_returns_original_without_new_history(self) -> None:
        first = self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="temperature",
            verdict=BlindVerdict.SAME,
            command_id="command-001",
            expected_version=0,
        )
        retry = self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="temperature",
            verdict=BlindVerdict.SAME,
            command_id="command-001",
            expected_version=0,
        )

        self.assertIs(first, retry)
        self.assertEqual(self.session.version, 1)
        self.assertEqual(len(self.session.own_decision_history(actor=self.actor)), 1)

    def test_same_command_with_different_payload_conflicts(self) -> None:
        self.session.record_decision(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            parameter_id="temperature",
            verdict=BlindVerdict.SAME,
            command_id="command-001",
            expected_version=0,
        )
        with self.assertRaises(DuplicateBlindCommandConflictError):
            self.session.record_decision(
                actor=self.actor,
                evidence_manifest_hash=self.manifest_hash,
                parameter_id="temperature",
                verdict=BlindVerdict.DIFFERENT,
                reason="Changed payload",
                command_id="command-001",
                expected_version=0,
            )

    def test_lock_retry_is_idempotent(self) -> None:
        self._complete()
        first = self.session.lock(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            command_id="lock-001",
            expected_version=2,
        )
        retry = self.session.lock(
            actor=self.actor,
            evidence_manifest_hash=self.manifest_hash,
            command_id="lock-001",
            expected_version=2,
        )
        self.assertIs(first, retry)
        self.assertEqual(self.session.version, 3)

    def test_naive_clock_fails_before_write(self) -> None:
        session = BlindReviewSession(
            blind_case_id="blind-case-002",
            evidence_manifest=self.manifest,
            primary_reviewer_id="reviewer-001",
            assigned_reviewer=self.actor,
            clock=lambda: datetime(2026, 8, 25, 14, 0),
        )
        with self.assertRaises(ValueError):
            session.record_decision(
                actor=self.actor,
                evidence_manifest_hash=self.manifest_hash,
                parameter_id="temperature",
                verdict=BlindVerdict.SAME,
                command_id="command-001",
                expected_version=0,
            )
        self.assertEqual(session.version, 0)

    def test_concurrent_write_and_lock_are_serialised(self) -> None:
        self._complete()
        entered_clock = Event()
        release_writer = Event()
        original_clock = self.session._clock

        def blocking_clock() -> datetime:
            entered_clock.set()
            if not release_writer.wait(timeout=2):
                raise TimeoutError("test did not release writer")
            return original_clock()

        self.session._clock = blocking_clock
        writer_errors = []
        lock_errors = []
        lock_finished = Event()

        def revise() -> None:
            try:
                self.session.record_decision(
                    actor=self.actor,
                    evidence_manifest_hash=self.manifest_hash,
                    parameter_id="temperature",
                    verdict=BlindVerdict.DIFFERENT,
                    reason="Concurrent revision",
                    command_id="command-003",
                    expected_version=2,
                )
            except Exception as error:  # pragma: no cover
                writer_errors.append(error)

        def lock_review() -> None:
            try:
                self.session.lock(
                    actor=self.actor,
                    evidence_manifest_hash=self.manifest_hash,
                    command_id="lock-001",
                    expected_version=3,
                )
            except Exception as error:  # pragma: no cover
                lock_errors.append(error)
            finally:
                lock_finished.set()

        writer = Thread(target=revise)
        locker = Thread(target=lock_review)
        writer.start()
        self.assertTrue(entered_clock.wait(timeout=2))
        locker.start()
        self.assertFalse(lock_finished.wait(timeout=0.05))
        release_writer.set()
        writer.join(timeout=2)
        locker.join(timeout=2)

        self.assertEqual(writer_errors, [])
        self.assertEqual(lock_errors, [])
        self.assertEqual(self.session.state, BlindReviewState.LOCKED)

    def test_concurrent_stale_and_current_evidence_writes_fail_closed(self) -> None:
        start = Event()
        results = []
        errors = []

        def write(evidence_manifest_hash: str) -> None:
            start.wait(timeout=2)
            try:
                results.append(
                    self.session.record_decision(
                        actor=self.actor,
                        evidence_manifest_hash=evidence_manifest_hash,
                        parameter_id="temperature",
                        verdict=BlindVerdict.SAME,
                        command_id="concurrent-evidence-command",
                        expected_version=0,
                    )
                )
            except Exception as error:  # pragma: no cover - asserted below
                errors.append(error)

        current = Thread(target=write, args=(self.manifest_hash,))
        stale = Thread(
            target=write, args=(different_sha256(self.manifest_hash),)
        )
        current.start()
        stale.start()
        start.set()
        current.join(timeout=2)
        stale.join(timeout=2)

        self.assertFalse(current.is_alive())
        self.assertFalse(stale.is_alive())
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], BlindEvidenceBindingError)
        self.assertEqual(results[0].evidence_manifest_hash, self.manifest_hash)
        self.assertEqual(self.session.version, 1)
        self.assertEqual(len(self.session.own_decision_history(actor=self.actor)), 1)


if __name__ == "__main__":
    unittest.main()
