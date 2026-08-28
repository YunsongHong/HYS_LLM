"""Tests for versioned targeted-recheck and blind-R2 process profiles."""

from dataclasses import replace
import re
import unittest

from paramguard.comparison import ComparisonKind
from paramguard.review_policy import (
    CONSERVATIVE_BLIND_R2,
    INTERVIEW_TARGETED_RECHECK,
    REVIEW_POLICY_SCHEMA_VERSION,
    ReviewNextStep,
    ReviewPolicyId,
    ReviewPolicyProfile,
    decide_post_lock_next_step,
)
from paramguard.routing import FieldIssue, ImageQuality, ReviewSignals, RouteReason
from paramguard.workflow import AiVerdict, HumanVerdict


def safe_signals(**changes: object) -> ReviewSignals:
    values: dict[str, object] = {
        "parameter_id": "temperature",
        "human_verdict": HumanVerdict.SAME,
        "ai_verdict": AiVerdict.SAME,
        "comparison_kind": ComparisonKind.EXACT_MATCH,
        "is_critical": False,
        "image_quality": ImageQuality.ACCEPTABLE,
        "field_issues": (),
    }
    values.update(changes)
    return ReviewSignals(**values)  # type: ignore[arg-type]


class ReviewPolicyProfileTests(unittest.TestCase):
    def test_profiles_are_versioned_and_content_hashed(self) -> None:
        record = INTERVIEW_TARGETED_RECHECK.to_record()

        self.assertEqual(
            record["review_policy_schema_version"],
            REVIEW_POLICY_SCHEMA_VERSION,
        )
        self.assertEqual(record["policy_version"], "1.0")
        self.assertTrue(record["r1_lock_required_before_ai"])
        self.assertFalse(record["automatic_release_allowed"])
        self.assertRegex(
            INTERVIEW_TARGETED_RECHECK.content_sha256,
            re.compile(r"^[0-9a-f]{64}$"),
        )
        self.assertEqual(
            INTERVIEW_TARGETED_RECHECK.content_sha256,
            INTERVIEW_TARGETED_RECHECK.content_sha256,
        )

    def test_version_or_material_rule_change_changes_content_hash(self) -> None:
        changed_version = replace(
            INTERVIEW_TARGETED_RECHECK,
            policy_version="1.1",
        )
        changed_critical_rule = replace(
            INTERVIEW_TARGETED_RECHECK,
            critical_parameter_next_step=(
                ReviewNextStep.FULL_MANIFEST_BLIND_SECOND_REVIEW
            ),
        )

        self.assertNotEqual(
            INTERVIEW_TARGETED_RECHECK.content_sha256,
            changed_version.content_sha256,
        )
        self.assertNotEqual(
            INTERVIEW_TARGETED_RECHECK.content_sha256,
            changed_critical_rule.content_sha256,
        )

    def test_unknown_and_unsafe_profile_types_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            ReviewPolicyProfile(  # type: ignore[arg-type]
                profile_id="INTERVIEW_TARGETED_RECHECK",
                policy_version="1.0",
                exception_next_step=(
                    ReviewNextStep.TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK
                ),
                critical_parameter_next_step=(
                    ReviewNextStep.QA_CRITICAL_POLICY_CONFIRMATION
                ),
            )
        with self.assertRaises(TypeError):
            replace(
                INTERVIEW_TARGETED_RECHECK,
                exception_next_step="TARGETED",  # type: ignore[arg-type]
            )
        with self.assertRaises(TypeError):
            replace(
                INTERVIEW_TARGETED_RECHECK,
                critical_parameter_next_step="QA",  # type: ignore[arg-type]
            )
        with self.assertRaises(ValueError):
            replace(INTERVIEW_TARGETED_RECHECK, policy_version="bad version")

    def test_profiles_cannot_configure_wait_as_exception_or_critical_action(self) -> None:
        with self.assertRaises(ValueError):
            replace(
                INTERVIEW_TARGETED_RECHECK,
                exception_next_step=(
                    ReviewNextStep.WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION
                ),
            )
        with self.assertRaises(ValueError):
            replace(
                INTERVIEW_TARGETED_RECHECK,
                critical_parameter_next_step=(
                    ReviewNextStep.WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION
                ),
            )


class InterviewTargetedPolicyTests(unittest.TestCase):
    def decide(self, **changes: object):  # type: ignore[no-untyped-def]
        return decide_post_lock_next_step(
            safe_signals(**changes),
            INTERVIEW_TARGETED_RECHECK,
        )

    def test_clean_noncritical_case_waits_for_final_human_confirmation(self) -> None:
        decision = self.decide()

        self.assertEqual(
            decision.next_step,
            ReviewNextStep.WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION,
        )
        self.assertEqual(decision.reasons, ())
        self.assertFalse(decision.automatic_release_allowed)

    def test_ai_same_never_turns_human_difference_or_nonexact_text_into_release(self) -> None:
        human_difference = self.decide(
            human_verdict=HumanVerdict.DIFFERENT,
            ai_verdict=AiVerdict.SAME,
        )
        hidden_format_difference = self.decide(
            human_verdict=HumanVerdict.SAME,
            ai_verdict=AiVerdict.SAME,
            comparison_kind=ComparisonKind.FORMAT_DIFFERENCE,
        )

        for decision in (human_difference, hidden_format_difference):
            with self.subTest(reasons=decision.reasons):
                self.assertEqual(
                    decision.next_step,
                    ReviewNextStep.TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK,
                )
                self.assertFalse(decision.automatic_release_allowed)

    def test_every_nonstructural_exception_signal_gets_targeted_recheck(self) -> None:
        cases = (
            {"human_verdict": HumanVerdict.DIFFERENT},
            {"human_verdict": HumanVerdict.UNABLE_TO_JUDGE},
            {"ai_verdict": AiVerdict.DIFFERENT},
            {"ai_verdict": AiVerdict.UNABLE_TO_JUDGE},
            {"image_quality": ImageQuality.LOW},
            {"image_quality": ImageQuality.UNREADABLE},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                decision = self.decide(**changes)
                self.assertEqual(
                    decision.next_step,
                    ReviewNextStep.TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK,
                )
                self.assertTrue(decision.reasons)
                self.assertFalse(decision.automatic_release_allowed)

        for comparison_kind in ComparisonKind:
            if comparison_kind is ComparisonKind.EXACT_MATCH:
                continue
            with self.subTest(comparison_kind=comparison_kind):
                decision = self.decide(comparison_kind=comparison_kind)
                self.assertEqual(
                    decision.next_step,
                    ReviewNextStep.TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK,
                )
                self.assertIn(
                    RouteReason.DETERMINISTIC_COMPARISON_NOT_EXACT,
                    decision.reasons,
                )

    def test_each_structural_issue_and_ai_system_error_goes_to_qa(self) -> None:
        for issue in FieldIssue:
            with self.subTest(issue=issue):
                decision = self.decide(field_issues=(issue,))
                self.assertEqual(
                    decision.next_step,
                    ReviewNextStep.QA_STRUCTURAL_OR_SYSTEM_REVIEW,
                )
                self.assertFalse(decision.automatic_release_allowed)

        system_error = self.decide(ai_verdict=AiVerdict.SYSTEM_ERROR)
        self.assertEqual(
            system_error.next_step,
            ReviewNextStep.QA_STRUCTURAL_OR_SYSTEM_REVIEW,
        )
        self.assertIn(RouteReason.AI_SYSTEM_ERROR, system_error.reasons)

    def test_unknown_real_critical_sop_fails_closed_to_qa_policy_confirmation(self) -> None:
        decision = self.decide(is_critical=True)

        self.assertEqual(
            decision.next_step,
            ReviewNextStep.QA_CRITICAL_POLICY_CONFIRMATION,
        )
        self.assertEqual(decision.reasons, (RouteReason.CRITICAL_PARAMETER,))
        self.assertFalse(decision.automatic_release_allowed)

    def test_critical_policy_hold_wins_over_targeted_exception_recheck(self) -> None:
        decision = self.decide(
            is_critical=True,
            ai_verdict=AiVerdict.DIFFERENT,
            comparison_kind=ComparisonKind.VALUE_MISMATCH,
        )

        self.assertEqual(
            decision.next_step,
            ReviewNextStep.QA_CRITICAL_POLICY_CONFIRMATION,
        )
        self.assertIn(RouteReason.CRITICAL_PARAMETER, decision.reasons)
        self.assertIn(RouteReason.AI_DETECTED_DIFFERENCE, decision.reasons)
        self.assertIn(
            RouteReason.DETERMINISTIC_COMPARISON_NOT_EXACT,
            decision.reasons,
        )

    def test_structural_qa_wins_over_critical_policy_and_exception_steps(self) -> None:
        decision = self.decide(
            is_critical=True,
            human_verdict=HumanVerdict.DIFFERENT,
            ai_verdict=AiVerdict.DIFFERENT,
            comparison_kind=ComparisonKind.VALUE_MISMATCH,
            field_issues=(FieldIssue.MISSING_EXPECTED_FIELD,),
        )

        self.assertEqual(
            decision.next_step,
            ReviewNextStep.QA_STRUCTURAL_OR_SYSTEM_REVIEW,
        )
        self.assertIn(RouteReason.MISSING_EXPECTED_FIELD, decision.reasons)
        self.assertIn(RouteReason.CRITICAL_PARAMETER, decision.reasons)


class ConservativeBlindPolicyTests(unittest.TestCase):
    def test_clean_noncritical_case_does_not_trigger_second_review_or_release(self) -> None:
        decision = decide_post_lock_next_step(
            safe_signals(),
            CONSERVATIVE_BLIND_R2,
        )

        self.assertEqual(
            decision.next_step,
            ReviewNextStep.WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION,
        )
        self.assertFalse(decision.automatic_release_allowed)

    def test_any_ordinary_exception_or_critical_flag_triggers_full_manifest_blind_r2(self) -> None:
        cases = (
            {"human_verdict": HumanVerdict.DIFFERENT},
            {"ai_verdict": AiVerdict.UNABLE_TO_JUDGE},
            {"image_quality": ImageQuality.LOW},
            {"comparison_kind": ComparisonKind.TEXT_MISMATCH},
            {"is_critical": True},
            {
                "is_critical": True,
                "ai_verdict": AiVerdict.DIFFERENT,
                "comparison_kind": ComparisonKind.VALUE_MISMATCH,
            },
        )
        for changes in cases:
            with self.subTest(changes=changes):
                decision = decide_post_lock_next_step(
                    safe_signals(**changes),
                    CONSERVATIVE_BLIND_R2,
                )
                self.assertEqual(
                    decision.next_step,
                    ReviewNextStep.FULL_MANIFEST_BLIND_SECOND_REVIEW,
                )
                self.assertFalse(decision.automatic_release_allowed)

    def test_qa_priority_wins_over_full_blind_r2(self) -> None:
        decision = decide_post_lock_next_step(
            safe_signals(
                is_critical=True,
                human_verdict=HumanVerdict.DIFFERENT,
                field_issues=(FieldIssue.UNKNOWN_FIELD,),
            ),
            CONSERVATIVE_BLIND_R2,
        )

        self.assertEqual(
            decision.next_step,
            ReviewNextStep.QA_STRUCTURAL_OR_SYSTEM_REVIEW,
        )
        self.assertIn(RouteReason.UNKNOWN_FIELD, decision.reasons)
        self.assertIn(RouteReason.CRITICAL_PARAMETER, decision.reasons)
        self.assertIn(RouteReason.HUMAN_DETECTED_DIFFERENCE, decision.reasons)


class PolicyFunctionBoundaryTests(unittest.TestCase):
    def test_decision_binds_profile_identity_version_and_hash(self) -> None:
        decision = decide_post_lock_next_step(
            safe_signals(),
            CONSERVATIVE_BLIND_R2,
        )

        self.assertEqual(
            decision.profile_id,
            ReviewPolicyId.CONSERVATIVE_BLIND_R2,
        )
        self.assertEqual(decision.profile_version, "1.0")
        self.assertEqual(
            decision.profile_content_sha256,
            CONSERVATIVE_BLIND_R2.content_sha256,
        )

    def test_wrong_signal_or_profile_type_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            decide_post_lock_next_step("not signals")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            decide_post_lock_next_step(
                safe_signals(),
                "INTERVIEW_TARGETED_RECHECK",  # type: ignore[arg-type]
            )

    def test_malformed_route_fact_inputs_are_rejected_not_guessed(self) -> None:
        with self.assertRaises(TypeError):
            decide_post_lock_next_step(
                safe_signals(image_quality="LOW")  # type: ignore[arg-type]
            )
        with self.assertRaises(ValueError):
            decide_post_lock_next_step(
                safe_signals(
                    field_issues=(
                        FieldIssue.UNKNOWN_FIELD,
                        FieldIssue.UNKNOWN_FIELD,
                    )
                )
            )

    def test_all_reachable_next_steps_for_both_profiles_never_auto_release(self) -> None:
        signals = (
            safe_signals(),
            safe_signals(ai_verdict=AiVerdict.DIFFERENT),
            safe_signals(is_critical=True),
            safe_signals(field_issues=(FieldIssue.UNKNOWN_FIELD,)),
        )
        for profile in (INTERVIEW_TARGETED_RECHECK, CONSERVATIVE_BLIND_R2):
            for item in signals:
                with self.subTest(profile=profile.profile_id, signals=item):
                    self.assertFalse(
                        decide_post_lock_next_step(
                            item,
                            profile,
                        ).automatic_release_allowed
                    )


if __name__ == "__main__":
    unittest.main()
