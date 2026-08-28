from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from paramguard.ocr import OcrOutputError
from paramguard.synthetic import default_clean_case, render_case
from paramguard.tool_comparison import ObservationStatus
from paramguard.workflow import InvalidTransitionError, ReviewState, ReviewTask
from tools import compare_local_ocr as driver


class ComparisonDriverTests(unittest.TestCase):
    def response(self) -> dict:
        return {
            "schema_version": 1,
            "revision": 3,
            "crops": [
                {
                    "id": "left:a",
                    "text": " 01.20 mA ",
                    "confidence": 0.8,
                    "observation_count": 1,
                },
                {
                    "id": "right:a",
                    "text": None,
                    "confidence": None,
                    "observation_count": 0,
                },
            ],
        }

    def parse(self, response: dict) -> dict:
        return driver.parse_apple_response(
            json.dumps(response), 3, ("left:a", "right:a")
        )

    def run_mocked_native_text(self, text: str) -> tuple:
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            image_bytes = driver.verified_images(rendered)
            helper_bytes = b"synthetic-helper-never-executed"
            config = driver.AppleConfig(
                Path(directory) / "missing-helper",
                driver.digest_bytes(helper_bytes),
                3,
                "test-os",
                False,
            )
            task = driver.simulated_task(rendered, config.pipeline_spec())
            driver.start_task(task, "test-run")
            response = {
                "schema_version": 1,
                "revision": 3,
                "crops": [
                    {
                        "id": f"{side}:{pair.parameter_id}",
                        "text": getattr(pair, f"{side}_raw"),
                        "confidence": 0.9,
                        "observation_count": 1,
                    }
                    for side in ("left", "right")
                    for pair in rendered.spec.values
                ],
            }
            response["crops"][0]["text"] = text
            completed = CompletedProcess(
                ("missing-helper",), 0, json.dumps(response), ""
            )
            with patch.object(
                driver.Path, "read_bytes", return_value=helper_bytes
            ), patch.object(
                driver, "verified_images", return_value=image_bytes
            ), patch.object(
                driver.TesseractOcrEngine, "_run", return_value=completed
            ) as invoke:
                observed, detail = driver.run_apple(task, "test-run", rendered, config)
                invoke.assert_called_once()
            return task, observed, detail

    def test_fixed_design_is_reproducible_and_all_missing_are_predeclared(self) -> None:
        first = driver.generated_cases()
        self.assertEqual(first, driver.generated_cases())
        self.assertEqual(len(first), 32)
        keys = [
            (case.case_id, pair.parameter_id)
            for _, case in first
            for pair in case.values
        ]
        self.assertEqual(len(keys), 128)
        self.assertEqual(len(set(keys)), 128)
        present = differences = missing = 0
        for family, case in first:
            for pair in case.values:
                if pair.left_raw is None or pair.right_raw is None:
                    missing += 1
                    self.assertEqual(family, "MISSING_STRUCTURE")
                else:
                    present += 1
                    differences += pair.left_raw != pair.right_raw
        self.assertEqual((present, differences, missing), (116, 60, 12))

    def test_text_is_preserved_without_normalization(self) -> None:
        parsed = self.parse(self.response())
        self.assertEqual(parsed["left:a"]["text"], " 01.20 mA ")

    def test_native_whitespace_is_abstained_without_normalization(self) -> None:
        for text in (" ", "\t", "\r\n", "\u00a0"):
            with self.subTest(text=repr(text)):
                task, observed, detail = self.run_mocked_native_text(text)
                self.assertEqual(task.state, ReviewState.AI_REVIEW_COMPLETE)
                self.assertEqual(observed[0].status, ObservationStatus.ABSTAIN)
                self.assertEqual(observed[0].left_raw, text)
                self.assertEqual(detail["raw_rows"][0]["text"], text)
                self.assertTrue(task.revealed_ai_results()["temperature"].reason)
                self.assertTrue(
                    all(row.status is ObservationStatus.VALID for row in observed[1:])
                )

    def test_native_padded_text_is_not_trimmed_into_a_match(self) -> None:
        text = f" {default_clean_case().values[0].left_raw} "
        task, observed, _ = self.run_mocked_native_text(text)
        self.assertEqual(task.state, ReviewState.AI_REVIEW_COMPLETE)
        self.assertEqual(observed[0].status, ObservationStatus.VALID)
        self.assertEqual(observed[0].left_raw, text)
        self.assertNotEqual(observed[0].left_raw, observed[0].right_raw)
        self.assertFalse(
            task.revealed_ai_results()["temperature"].comparison_result.exact_match
        )

    def test_native_surrogate_text_fails_entire_batch_closed(self) -> None:
        for text in ("\ud800", "\udfff", "1\ud800 mA"):
            with self.subTest(text=repr(text)):
                task, observed, detail = self.run_mocked_native_text(text)
                self.assertEqual(task.state, ReviewState.AI_REVIEW_COMPLETE)
                self.assertEqual(len(observed), 4)
                self.assertTrue(
                    all(row.status is ObservationStatus.ERROR for row in observed)
                )
                self.assertTrue(
                    all(
                        row.left_raw is None and row.right_raw is None
                        for row in observed
                    )
                )
                self.assertEqual(detail["error_code"], OcrOutputError.code)
                self.assertEqual(detail["raw_rows"], [])
                self.assertIsInstance(
                    driver.canonical(
                        {
                            "observations": [driver.asdict(row) for row in observed],
                            "detail": detail,
                        }
                    ),
                    bytes,
                )

    def test_parser_rejects_escaped_surrogates(self) -> None:
        for text in ("\ud800", "\udfff", "1\ud800 mA"):
            response = self.response()
            response["crops"][0]["text"] = text
            with self.subTest(text=repr(text)), self.assertRaises(OcrOutputError):
                self.parse(response)

    def test_strict_json_invalid_unicode_raises_ocr_output_error(self) -> None:
        for text in ("\ud800", "\udfff"):
            source = json.dumps({"text": text}, ensure_ascii=False)
            with self.subTest(text=repr(text)), self.assertRaises(OcrOutputError):
                driver.strict_json(source)

    def test_parser_preserves_valid_non_bmp_and_surrounding_spaces(self) -> None:
        response = self.response()
        text = " 01.20 mA \U0001f642 "
        response["crops"][0]["text"] = text
        parsed = self.parse(response)
        self.assertEqual(parsed["left:a"]["text"], text)
        self.assertIsInstance(driver.canonical(parsed), bytes)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        for source in ('{"revision":3,"revision":3}', '{"a":{"x":1,"x":2}}'):
            with self.subTest(source=source), self.assertRaises(OcrOutputError):
                driver.strict_json(source)

    def test_wrong_schema_revision_and_boolean_numbers_are_rejected(self) -> None:
        for key, value in (
            ("schema_version", True),
            ("schema_version", 2),
            ("revision", True),
            ("revision", 2),
        ):
            payload = self.response()
            payload[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(OcrOutputError):
                self.parse(payload)

    def test_unknown_missing_duplicate_and_extra_rows_are_rejected(self) -> None:
        cases = []
        payload = self.response()
        payload["extra"] = 1
        cases.append(payload)
        payload = self.response()
        payload["crops"].pop()
        cases.append(payload)
        payload = self.response()
        payload["crops"][1]["id"] = "left:a"
        cases.append(payload)
        payload = self.response()
        payload["crops"][1]["id"] = "unknown:a"
        cases.append(payload)
        payload = self.response()
        payload["crops"][0]["verdict"] = "SAME"
        cases.append(payload)
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(OcrOutputError):
                self.parse(payload)

    def test_invalid_confidence_count_and_text_fail_whole_batch(self) -> None:
        for key, value in (
            ("confidence", True),
            ("confidence", float("nan")),
            ("confidence", float("inf")),
            ("confidence", -0.1),
            ("confidence", 1.1),
            ("confidence", None),
            ("observation_count", True),
            ("observation_count", -1),
            ("observation_count", 0),
            ("observation_count", 4097),
            ("text", True),
            ("text", ""),
            ("text", "x" * 4097),
        ):
            payload = self.response()
            payload["crops"][0][key] = value
            with self.subTest(key=key, value_type=type(value)), self.assertRaises(
                OcrOutputError
            ):
                self.parse(payload)

    def test_large_and_nested_invalid_json_are_rejected(self) -> None:
        for source in (
            "[1]",
            "null",
            "{broken",
            "[" * 1500 + "]" * 1500,
            " " * (driver.MAX_JSON_BYTES + 1),
        ):
            with self.subTest(length=len(source)), self.assertRaises(OcrOutputError):
                driver.strict_json(source)

    def test_apple_configuration_rejects_boolean_revision_and_wrong_flags(self) -> None:
        valid = driver.AppleConfig(
            Path("missing-helper"), "a" * 64, 3, "test-os", False
        )
        for change in (
            {"revision": True},
            {"revision": 0},
            {"language_correction": 1},
            {"helper_sha256": "bad"},
        ):
            with self.subTest(change=change), self.assertRaises(
                (TypeError, ValueError)
            ):
                replace(valid, **change)

    def test_apple_spec_binds_correction_helper_revision_and_operating_system(
        self,
    ) -> None:
        config = driver.AppleConfig(
            Path("missing-helper"), "a" * 64, 3, "test-os", False
        )
        for change in (
            {"revision": 2},
            {"language_correction": True},
            {"helper_sha256": "b" * 64},
            {"os_version": "other-os"},
        ):
            self.assertNotEqual(
                config.pipeline_spec(), replace(config, **change).pipeline_spec()
            )

    def test_prelock_calls_do_no_helper_or_image_reads(self) -> None:
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            config = driver.AppleConfig(
                Path(directory) / "missing-helper", "a" * 64, 3, "test-os", False
            )
            task = ReviewTask(
                task_id="test-task",
                evidence_manifest=rendered.manifest,
                approved_pipeline_spec=config.pipeline_spec(),
                reviewer_id="human",
            )
            with patch.object(driver.Path, "read_bytes") as read, patch.object(
                driver, "verified_images"
            ) as images:
                with self.assertRaises(InvalidTransitionError):
                    driver.run_apple(task, "not-started", rendered, config)
                read.assert_not_called()
                images.assert_not_called()

    def test_locked_but_not_started_still_cannot_invoke_apple(self) -> None:
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            config = driver.AppleConfig(
                Path(directory) / "missing-helper", "a" * 64, 3, "test-os", False
            )
            task = driver.simulated_task(rendered, config.pipeline_spec())
            with patch.object(driver.Path, "read_bytes") as read, patch.object(
                driver, "verified_images"
            ) as images:
                with self.assertRaises(InvalidTransitionError):
                    driver.run_apple(task, "not-started", rendered, config)
                read.assert_not_called()
                images.assert_not_called()

    def test_wrong_runtime_pipeline_fails_before_image_or_helper_read(self) -> None:
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            config = driver.AppleConfig(
                Path(directory) / "missing-helper", "a" * 64, 3, "test-os", False
            )
            task = driver.simulated_task(rendered, config.pipeline_spec())
            driver.start_task(task, "test-run")
            with patch.object(driver.Path, "read_bytes") as read, patch.object(
                driver, "verified_images"
            ) as images:
                with self.assertRaises(Exception) as caught:
                    driver.run_apple(
                        task,
                        "test-run",
                        rendered,
                        replace(config, language_correction=True),
                    )
                self.assertEqual(caught.exception.code, "EVIDENCE_VERSION_CONFLICT")
                read.assert_not_called()
                images.assert_not_called()

    def test_changed_native_executable_is_rejected_before_image_read(self) -> None:
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            config = driver.AppleConfig(
                Path(directory) / "missing-helper", "a" * 64, 3, "test-os", False
            )
            task = driver.simulated_task(rendered, config.pipeline_spec())
            driver.start_task(task, "test-run")
            with patch.object(
                driver.Path, "read_bytes", return_value=b"changed"
            ), patch.object(driver, "verified_images") as images:
                with self.assertRaisesRegex(ValueError, "helper changed"):
                    driver.run_apple(task, "test-run", rendered, config)
                images.assert_not_called()


if __name__ == "__main__":
    unittest.main()
