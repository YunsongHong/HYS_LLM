"""Synthetic regression cases for strict development comparison scoring."""

from dataclasses import FrozenInstanceError
from enum import Enum
import json
import unittest

from paramguard.tool_comparison import (
    ComparisonTruth,
    ObservationStatus,
    ToolObservation,
    compare_development,
    score_tool,
)


class StringSubclass(str):
    pass


class TupleSubclass(tuple):
    pass


class DictSubclass(dict):
    pass


class OtherStatus(str, Enum):
    VALID = "VALID"


class TruthSubclass(ComparisonTruth):
    pass


class ObservationSubclass(ToolObservation):
    pass


def truth_row(
    parameter: str = "field",
    left: str | None = "1.20",
    right: str | None = "1.25",
    case: str = "synthetic-case",
) -> ComparisonTruth:
    return ComparisonTruth(case, parameter, left, right)


def observation(
    row: ComparisonTruth,
    status: ObservationStatus = ObservationStatus.VALID,
) -> ToolObservation:
    return ToolObservation(
        row.case_id, row.parameter_id, row.left_raw, row.right_raw, status
    )


def difference_cohort(count: int) -> tuple[ComparisonTruth, ...]:
    return tuple(truth_row(case=f"synthetic-{index}") for index in range(count))


def observations_with_successes(
    truth: tuple[ComparisonTruth, ...], successes: int
) -> tuple[ToolObservation, ...]:
    return tuple(
        observation(row)
        if index < successes
        else ToolObservation(
            row.case_id, row.parameter_id, None, None, ObservationStatus.ABSTAIN
        )
        for index, row in enumerate(truth)
    )


class ComparisonRecordTests(unittest.TestCase):
    def test_records_are_frozen_and_keys_include_case_and_parameter(self) -> None:
        row = truth_row()
        observed = observation(row)
        self.assertEqual(row.key, ("synthetic-case", "field"))
        self.assertEqual(observed.key, row.key)
        with self.assertRaises(FrozenInstanceError):
            row.left_raw = "changed"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            observed.status = ObservationStatus.ERROR  # type: ignore[misc]

    def test_identifier_limits_and_supported_ascii_characters(self) -> None:
        for identifier in ("a", "a" * 128, "case:01.field-name_version"):
            with self.subTest(identifier_length=len(identifier)):
                row = ComparisonTruth(identifier, identifier, "1", "2")
                self.assertEqual(observation(row).key, row.key)

    def test_identifier_types_are_strict_on_both_record_classes(self) -> None:
        for bad in (
            True,
            False,
            1,
            1.0,
            float("nan"),
            None,
            b"case",
            StringSubclass("case"),
        ):
            for cls in (ComparisonTruth, ToolObservation):
                for field in ("case_id", "parameter_id"):
                    with self.subTest(
                        cls=cls.__name__, field=field, bad_type=type(bad)
                    ):
                        args = dict(
                            case_id="case",
                            parameter_id="field",
                            left_raw="1",
                            right_raw="2",
                        )
                        args[field] = bad
                        if cls is ToolObservation:
                            args["status"] = ObservationStatus.VALID
                        with self.assertRaises(TypeError):
                            cls(**args)

    def test_unsafe_or_overlong_identifiers_are_rejected(self) -> None:
        for bad in (
            "",
            "a" * 129,
            "../case",
            "a/b",
            "a\\b",
            "a\n",
            "a\x00",
            "a b",
            "é",
        ):
            for cls in (ComparisonTruth, ToolObservation):
                with self.subTest(cls=cls.__name__, bad=repr(bad[:8])):
                    args = [bad, "field", "1", "2"]
                    if cls is ToolObservation:
                        args.append(ObservationStatus.VALID)
                    with self.assertRaises(ValueError):
                        cls(*args)

    def test_raw_types_reject_booleans_nan_bytes_and_string_subclasses(self) -> None:
        for bad in (
            True,
            False,
            1,
            1.0,
            float("nan"),
            float("inf"),
            b"1",
            StringSubclass("1"),
        ):
            for cls in (ComparisonTruth, ToolObservation):
                for field in ("left_raw", "right_raw"):
                    with self.subTest(
                        cls=cls.__name__, field=field, bad_type=type(bad)
                    ):
                        args = dict(
                            case_id="case",
                            parameter_id="field",
                            left_raw="1",
                            right_raw="2",
                        )
                        args[field] = bad
                        if cls is ToolObservation:
                            args["status"] = ObservationStatus.VALID
                        with self.assertRaises(TypeError):
                            cls(**args)

    def test_empty_and_overlong_raw_strings_are_rejected(self) -> None:
        for bad in ("", "x" * 4097):
            for cls in (ComparisonTruth, ToolObservation):
                for field in ("left_raw", "right_raw"):
                    with self.subTest(cls=cls.__name__, field=field, length=len(bad)):
                        args = dict(
                            case_id="case",
                            parameter_id="field",
                            left_raw="1",
                            right_raw="2",
                        )
                        args[field] = bad
                        if cls is ToolObservation:
                            args["status"] = ObservationStatus.VALID
                        with self.assertRaises(ValueError):
                            cls(**args)

    def test_raw_boundary_is_characters_and_text_is_not_trimmed(self) -> None:
        row = truth_row(left="é" * 4096, right=" \t1.20\n")
        observed = observation(row)
        self.assertEqual(observed.left_raw, "é" * 4096)
        self.assertEqual(observed.right_raw, " \t1.20\n")
        self.assertEqual(
            score_tool((row,), (observed,))["accepted_pair_exact_rate"]["value"], 1.0
        )
        self.assertEqual(truth_row(left=" ").left_raw, " ")

    def test_status_requires_the_exact_enum(self) -> None:
        for bad in (
            "VALID",
            StringSubclass("VALID"),
            OtherStatus.VALID,
            True,
            None,
            float("nan"),
        ):
            with self.subTest(bad_type=type(bad)):
                with self.assertRaises(TypeError):
                    ToolObservation("case", "field", "1", "2", bad)

    def test_valid_status_requires_both_raw_strings(self) -> None:
        for left, right in ((None, None), (None, "1"), ("1", None)):
            with self.subTest(left=left, right=right):
                with self.assertRaises(ValueError):
                    ToolObservation(
                        "case", "field", left, right, ObservationStatus.VALID
                    )
                for status in (ObservationStatus.ABSTAIN, ObservationStatus.ERROR):
                    self.assertEqual(
                        ToolObservation("case", "field", left, right, status).status,
                        status,
                    )


class CohortValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.truth = difference_cohort(2)
        self.observations = tuple(observation(row) for row in self.truth)

    def test_collections_require_builtin_tuples(self) -> None:
        for bad in (
            list(self.truth),
            TupleSubclass(self.truth),
            None,
            True,
            "rows",
            iter(self.truth),
        ):
            with self.subTest(collection="truth", bad_type=type(bad)):
                with self.assertRaises(TypeError):
                    score_tool(bad, self.observations)
        for bad in (
            list(self.observations),
            TupleSubclass(self.observations),
            None,
            False,
            "rows",
            iter(self.observations),
        ):
            with self.subTest(collection="observations", bad_type=type(bad)):
                with self.assertRaises(TypeError):
                    score_tool(self.truth, bad)

    def test_empty_truth_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            score_tool((), ())

    def test_wrong_row_types_and_subclasses_are_rejected(self) -> None:
        for bad in (
            True,
            {},
            self.observations[0],
            TruthSubclass("case", "field", "1", "2"),
        ):
            with self.subTest(collection="truth", bad_type=type(bad)):
                with self.assertRaises(TypeError):
                    score_tool((bad,), self.observations)
        for bad in (
            False,
            {},
            self.truth[0],
            ObservationSubclass("case", "field", "1", "2", ObservationStatus.VALID),
        ):
            with self.subTest(collection="observations", bad_type=type(bad)):
                with self.assertRaises(TypeError):
                    score_tool(self.truth, (bad,))

    def test_duplicate_truth_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            score_tool((self.truth[0], self.truth[0]), self.observations)

    def test_repeating_a_success_cannot_inflate_a_score(self) -> None:
        accepted = self.observations[0]
        failed = ToolObservation(
            self.truth[1].case_id, "field", None, None, ObservationStatus.ABSTAIN
        )
        score = score_tool(self.truth, (accepted, failed))
        self.assertEqual(score["supported_difference_recall"]["value"], 0.5)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            score_tool(self.truth, (accepted,) * 10 + (failed,))

    def test_missing_and_unknown_keys_are_rejected(self) -> None:
        unknown = observation(truth_row(case="not-in-truth"))
        for rows, pattern in (
            ((), "missing=2"),
            (self.observations[:1], "missing=1"),
            (self.observations + (unknown,), "unknown=1"),
            ((self.observations[0], unknown), "missing=1, unknown=1"),
        ):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, pattern):
                    score_tool(self.truth, rows)

    def test_same_parameter_in_distinct_cases_is_not_a_duplicate(self) -> None:
        self.assertEqual(score_tool(self.truth, self.observations)["field_count"], 2)

    def test_observation_order_does_not_change_scores(self) -> None:
        self.assertEqual(
            score_tool(self.truth, self.observations),
            score_tool(tuple(reversed(self.truth)), tuple(reversed(self.observations))),
        )

    def test_forged_frozen_records_are_revalidated(self) -> None:
        row = truth_row()
        object.__setattr__(row, "left_raw", True)
        with self.assertRaises(TypeError):
            score_tool((row,), (observation(truth_row()),))
        observed = observation(truth_row())
        object.__setattr__(observed, "status", "VALID")
        with self.assertRaises(TypeError):
            score_tool((truth_row(),), (observed,))
        observed = observation(truth_row())
        object.__setattr__(observed, "right_raw", None)
        with self.assertRaises(ValueError):
            score_tool((truth_row(),), (observed,))


class ScoringTests(unittest.TestCase):
    def assertRate(
        self, score: dict, name: str, numerator: int, denominator: int
    ) -> None:
        self.assertEqual(
            score[name],
            {
                "numerator": numerator,
                "denominator": denominator,
                "value": numerator / denominator if denominator else None,
            },
        )
        self.assertIs(type(score[name]["numerator"]), int)
        self.assertIs(type(score[name]["denominator"]), int)
        if denominator:
            self.assertIs(type(score[name]["value"]), float)

    def test_1001_fields_are_counted_without_dropping_failures(self) -> None:
        truth = difference_cohort(1001)
        score = score_tool(truth, observations_with_successes(truth, 777))
        self.assertEqual(score["field_count"], 1001)
        self.assertRate(score, "supported_difference_recall", 777, 1001)
        self.assertRate(score, "unresolved_difference_rate", 224, 1001)
        self.assertRate(score, "abstention_rate", 224, 1001)

    def test_risk_counts_and_denominators_on_a_mixed_cohort(self) -> None:
        truth = (
            truth_row("supported", "1.0", "2.0"),
            truth_row("false-same", "-1", "1"),
            truth_row("abstained", "010", "10"),
            truth_row("false-positive", "ON", "ON"),
            truth_row("error", "1.0", "1.0"),
            truth_row("missing", None, "1"),
        )
        rows = (
            observation(truth[0]),
            ToolObservation(
                "synthetic-case", "false-same", "1", "1", ObservationStatus.VALID
            ),
            observation(truth[2], ObservationStatus.ABSTAIN),
            ToolObservation(
                "synthetic-case", "false-positive", "ON", "OFF", ObservationStatus.VALID
            ),
            observation(truth[4], ObservationStatus.ERROR),
            observation(truth[5], ObservationStatus.ABSTAIN),
        )
        score = score_tool(truth, rows)
        for name, value in (
            ("field_count", 6),
            ("present_pair_count", 5),
            ("structural_pair_count", 1),
            ("true_difference_count", 3),
            ("true_same_count", 2),
        ):
            self.assertEqual(score[name], value)
            self.assertIs(type(score[name]), int)
        for name, numerator, denominator in (
            ("supported_difference_recall", 1, 3),
            ("ordinary_difference_recall", 1, 3),
            ("false_same_rate", 1, 3),
            ("false_positive_rate", 1, 2),
            ("unresolved_difference_rate", 1, 3),
            ("raw_pair_exact_rate", 3, 5),
            ("accepted_pair_exact_rate", 1, 5),
            ("abstention_rate", 2, 6),
            ("error_rate", 1, 6),
            ("structural_rejection_rate", 1, 1),
        ):
            self.assertRate(score, name, numerator, denominator)
        self.assertEqual(score["wrong_accepted_pair_count"], 2)
        self.assertEqual(score["unsupported_difference_count"], 1)

    def test_wrong_transcriptions_that_happen_to_differ_are_not_supported(self) -> None:
        row = truth_row(left="1", right="2")
        observed = ToolObservation(
            row.case_id, row.parameter_id, "wrong-A", "wrong-B", ObservationStatus.VALID
        )
        score = score_tool((row,), (observed,))
        self.assertRate(score, "ordinary_difference_recall", 1, 1)
        self.assertRate(score, "supported_difference_recall", 0, 1)
        self.assertRate(score, "raw_pair_exact_rate", 0, 1)
        self.assertEqual(score["unsupported_difference_count"], 1)
        self.assertEqual(score["wrong_accepted_pair_count"], 1)

    def test_rejected_correct_candidate_text_has_no_accepted_or_primary_credit(
        self,
    ) -> None:
        row = truth_row()
        for status in (ObservationStatus.ABSTAIN, ObservationStatus.ERROR):
            with self.subTest(status=status):
                score = score_tool((row,), (observation(row, status),))
                self.assertRate(score, "raw_pair_exact_rate", 1, 1)
                self.assertRate(score, "accepted_pair_exact_rate", 0, 1)
                self.assertRate(score, "supported_difference_recall", 0, 1)
                self.assertRate(score, "ordinary_difference_recall", 0, 1)
                self.assertRate(score, "unresolved_difference_rate", 1, 1)

    def test_all_abstentions_keep_present_differences_in_the_denominator(self) -> None:
        truth = difference_cohort(4)
        rows = observations_with_successes(truth, 0)
        score = score_tool(truth, rows)
        self.assertRate(score, "supported_difference_recall", 0, 4)
        self.assertRate(score, "ordinary_difference_recall", 0, 4)
        self.assertRate(score, "false_same_rate", 0, 4)
        self.assertRate(score, "unresolved_difference_rate", 4, 4)
        self.assertRate(score, "abstention_rate", 4, 4)
        self.assertRate(score, "error_rate", 0, 4)

    def test_error_and_abstention_rates_are_distinct(self) -> None:
        row = truth_row()
        score = score_tool((row,), (observation(row, ObservationStatus.ERROR),))
        self.assertRate(score, "error_rate", 1, 1)
        self.assertRate(score, "abstention_rate", 0, 1)
        self.assertRate(score, "unresolved_difference_rate", 1, 1)

    def test_both_missing_cannot_count_as_pair_exact(self) -> None:
        row = truth_row(left=None, right=None)
        score = score_tool((row,), (observation(row, ObservationStatus.ABSTAIN),))
        self.assertEqual(score["structural_pair_count"], 1)
        self.assertEqual(score["present_pair_count"], 0)
        self.assertEqual(score["true_difference_count"], 0)
        self.assertEqual(score["true_same_count"], 0)
        self.assertRate(score, "raw_pair_exact_rate", 0, 0)
        self.assertRate(score, "accepted_pair_exact_rate", 0, 0)
        self.assertRate(score, "supported_difference_recall", 0, 0)
        self.assertRate(score, "structural_rejection_rate", 1, 1)

    def test_structural_rejection_does_not_hide_hallucinated_valid_pairs(self) -> None:
        truth = (
            truth_row("a", None, "1"),
            truth_row("b", "1", None),
            truth_row("c", None, None),
        )
        rows = (
            observation(truth[0], ObservationStatus.ABSTAIN),
            observation(truth[1], ObservationStatus.ERROR),
            ToolObservation("synthetic-case", "c", "1", "2", ObservationStatus.VALID),
        )
        score = score_tool(truth, rows)
        self.assertRate(score, "structural_rejection_rate", 2, 3)
        self.assertRate(score, "raw_pair_exact_rate", 0, 0)
        self.assertRate(score, "accepted_pair_exact_rate", 0, 0)
        self.assertEqual(score["wrong_accepted_pair_count"], 1)
        self.assertEqual(score["unsupported_difference_count"], 1)

    def test_literal_spaces_unicode_and_numeric_format_are_not_normalized(self) -> None:
        for left, right in (
            ("1.0", "1.00"),
            ("0800", "800"),
            (" a", "a"),
            ("é", "e\u0301"),
            ("１", "1"),
        ):
            with self.subTest(left=left, right=right):
                row = truth_row(left=left, right=right)
                score = score_tool((row,), (observation(row),))
                self.assertRate(score, "supported_difference_recall", 1, 1)
                self.assertEqual(score["true_same_count"], 0)

    def test_only_same_pairs_have_no_difference_denominator(self) -> None:
        row = truth_row(left="1.20", right="1.20")
        score = score_tool((row,), (observation(row),))
        self.assertRate(score, "supported_difference_recall", 0, 0)
        self.assertRate(score, "false_positive_rate", 0, 1)
        self.assertRate(score, "accepted_pair_exact_rate", 1, 1)

    def test_empty_denominators_serialize_as_null_not_nan(self) -> None:
        row = truth_row(left=None, right=None)
        score = score_tool((row,), (observation(row, ObservationStatus.ERROR),))
        encoded = json.dumps(score, allow_nan=False, sort_keys=True)
        self.assertEqual(json.loads(encoded), score)
        self.assertIn('"value": null', encoded)


class DevelopmentComparisonTests(unittest.TestCase):
    def compare_counts(
        self, count: int, candidate_successes: int, baseline_successes: int
    ) -> dict:
        truth = difference_cohort(count)
        return compare_development(
            truth,
            {
                "candidate": observations_with_successes(truth, candidate_successes),
                "baseline": observations_with_successes(truth, baseline_successes),
            },
            "candidate",
        )

    def test_relative_five_percent_is_not_five_percentage_points(self) -> None:
        report = self.compare_counts(100, 84, 80)
        delta = report["comparisons"]["baseline"]
        self.assertEqual(delta["absolute_difference"], 0.04)
        self.assertEqual(delta["percentage_point_difference"], 4.0)
        self.assertEqual(delta["relative_gain"], 0.05)
        self.assertTrue(delta["relative_5pct_target_feasible"])
        self.assertEqual(report["status"], "DEVELOPMENT_ONLY")
        self.assertEqual(delta["status"], "DEVELOPMENT_ONLY")
        self.assertFalse(report["five_percent_confirmed"])
        self.assertFalse(delta["five_percent_confirmed"])
        self.assertIsNone(report["human_review_seconds"])

    def test_large_development_gain_is_still_not_confirmed(self) -> None:
        report = self.compare_counts(4, 4, 1)
        delta = report["comparisons"]["baseline"]
        self.assertEqual(delta["relative_gain"], 3.0)
        self.assertEqual(report["status"], "DEVELOPMENT_ONLY")
        self.assertEqual(delta["status"], "DEVELOPMENT_ONLY")
        self.assertFalse(report["five_percent_confirmed"])
        self.assertFalse(delta["five_percent_confirmed"])
        self.assertIsNone(report["human_review_seconds"])

    def test_zero_baseline_is_undefined_without_epsilon(self) -> None:
        for candidate_successes in (0, 4):
            with self.subTest(candidate_successes=candidate_successes):
                delta = self.compare_counts(4, candidate_successes, 0)["comparisons"][
                    "baseline"
                ]
                self.assertIsNone(delta["relative_gain"])
                self.assertIsNone(delta["relative_5pct_target_feasible"])
                self.assertEqual(
                    delta["relative_5pct_target_reason"],
                    "ZERO_BASELINE_RELATIVE_UNDEFINED",
                )
                self.assertFalse(delta["five_percent_confirmed"])

    def test_exact_twenty_over_twenty_one_boundary_is_attainable_but_not_confirmed(
        self,
    ) -> None:
        delta = self.compare_counts(21, 21, 20)["comparisons"]["baseline"]
        self.assertEqual(delta["relative_gain"], 0.05)
        self.assertTrue(delta["relative_5pct_target_feasible"])
        self.assertEqual(delta["relative_5pct_target_reason"], "WITHIN_SCORE_CEILING")
        self.assertFalse(delta["five_percent_confirmed"])

    def test_baseline_above_twenty_over_twenty_one_has_an_impossible_target(
        self,
    ) -> None:
        delta = self.compare_counts(100, 100, 96)["comparisons"]["baseline"]
        self.assertFalse(delta["relative_5pct_target_feasible"])
        self.assertEqual(delta["relative_5pct_target_reason"], "EXCEEDS_SCORE_CEILING")
        self.assertFalse(delta["baseline_at_score_ceiling"])

    def test_perfect_baseline_can_tie_but_not_gain_five_percent(self) -> None:
        delta = self.compare_counts(4, 4, 4)["comparisons"]["baseline"]
        self.assertTrue(delta["baseline_at_score_ceiling"])
        self.assertFalse(delta["relative_5pct_target_feasible"])
        self.assertEqual(delta["relative_gain"], 0.0)
        self.assertEqual(delta["absolute_difference"], 0.0)
        self.assertFalse(delta["five_percent_confirmed"])

    def test_regressions_are_negative_not_clipped(self) -> None:
        delta = self.compare_counts(4, 1, 2)["comparisons"]["baseline"]
        self.assertEqual(delta["relative_gain"], -0.5)
        self.assertEqual(delta["absolute_difference"], -0.25)
        self.assertEqual(delta["percentage_point_difference"], -25.0)

    def test_no_present_differences_produces_no_relative_claim(self) -> None:
        row = truth_row(left="same", right="same")
        report = compare_development(
            (row,), {"a": (observation(row),), "b": (observation(row),)}, "a"
        )
        delta = report["comparisons"]["b"]
        for key in (
            "absolute_difference",
            "percentage_point_difference",
            "relative_gain",
            "relative_5pct_target_feasible",
        ):
            self.assertIsNone(delta[key])
        self.assertEqual(delta["relative_5pct_target_reason"], "NO_PRESENT_DIFFERENCES")

    def test_every_baseline_uses_the_same_candidate_and_truth(self) -> None:
        truth = difference_cohort(4)
        tools = {
            "candidate": observations_with_successes(truth, 3),
            "strong": observations_with_successes(truth, 4),
            "weak": observations_with_successes(truth, 2),
        }
        report = compare_development(truth, tools, "candidate")
        self.assertEqual(set(report["tool_scores"]), set(tools))
        self.assertEqual(set(report["comparisons"]), {"strong", "weak"})
        self.assertEqual(report["comparisons"]["strong"]["relative_gain"], -0.25)
        self.assertEqual(report["comparisons"]["weak"]["relative_gain"], 0.5)
        self.assertEqual(json.loads(json.dumps(report, allow_nan=False)), report)

    def test_invalid_baseline_is_not_silently_dropped_or_scored_zero(self) -> None:
        truth = difference_cohort(2)
        rows = observations_with_successes(truth, 2)
        with self.assertRaises(ValueError):
            compare_development(
                truth, {"candidate": rows, "baseline": rows[:1]}, "candidate"
            )
        with self.assertRaises(TypeError):
            compare_development(
                truth, {"candidate": rows, "baseline": list(rows)}, "candidate"
            )

    def test_tools_need_a_plain_dict_candidate_and_at_least_one_baseline(self) -> None:
        truth = difference_cohort(1)
        rows = observations_with_successes(truth, 1)
        for bad in (None, True, [], DictSubclass({"a": rows, "b": rows})):
            with self.subTest(bad_type=type(bad)):
                with self.assertRaises(TypeError):
                    compare_development(truth, bad, "a")
        for bad in ({}, {"a": rows}):
            with self.assertRaises(ValueError):
                compare_development(truth, bad, "a")
        with self.assertRaises(ValueError):
            compare_development(truth, {"a": rows, "b": rows}, "missing")

    def test_tool_and_candidate_names_have_strict_types_and_safe_limits(self) -> None:
        truth = difference_cohort(1)
        rows = observations_with_successes(truth, 1)
        for bad in (True, 1, None, StringSubclass("tool"), "../tool", "", "x" * 129):
            error = TypeError if type(bad) is not str else ValueError
            with self.subTest(bad_type=type(bad)):
                with self.assertRaises(error):
                    compare_development(truth, {"good": rows, bad: rows}, "good")
                with self.assertRaises(error):
                    compare_development(truth, {"good": rows, "other": rows}, bad)


if __name__ == "__main__":
    unittest.main()
