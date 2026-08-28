"""Unit and local integration tests for the Tesseract OCR adapter."""

import csv
import hashlib
import io
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from PIL import Image

from paramguard.ocr import (
    OcrExecutionError,
    OcrOutputError,
    TesseractConfig,
    TesseractOcrEngine,
    _parse_tesseract_tsv,
)
from paramguard.synthetic import default_clean_case, render_case
from paramguard.template import SYNTHETIC_PANEL_TEMPLATE


TSV_HEADER = (
    "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\t"
    "left\ttop\twidth\theight\tconf\ttext\n"
)


def word_row(*, text: str, confidence: float) -> str:
    return f"5\t1\t1\t1\t1\t1\t10\t8\t90\t30\t{confidence}\t{text}\n"


class FakeRunner:
    def __init__(self, tsv_output: str) -> None:
        self.tsv_output = tsv_output
        self.commands: list[list[str]] = []

    def __call__(
        self, command: list[str], **_: object
    ) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(command)
        if command[-1] == "--version":
            return subprocess.CompletedProcess(
                command, 0, b"tesseract 5.5.1\n leptonica-1.85.0\n", b""
            )
        return subprocess.CompletedProcess(
            command, 0, self.tsv_output.encode("utf-8"), b""
        )


class TesseractOcrTests(unittest.TestCase):
    def test_tsv_parser_keeps_word_text_confidence_and_box(self) -> None:
        tokens = _parse_tesseract_tsv(
            TSV_HEADER
            + word_row(text="1.20", confidence=96.5)
            + word_row(text="bar", confidence=91.0)
        )

        self.assertEqual(tuple(token.text for token in tokens), ("1.20", "bar"))
        self.assertEqual(tokens[0].confidence, 96.5)
        self.assertEqual(
            tokens[0].box.to_record(),
            {
                "left": 10,
                "top": 8,
                "right": 100,
                "bottom": 38,
            },
        )

    def test_malformed_tsv_fails_closed(self) -> None:
        with self.assertRaises(OcrOutputError):
            _parse_tesseract_tsv("text\tconf\nhello\t99\n")
        with self.assertRaises(OcrOutputError):
            _parse_tesseract_tsv(
                TSV_HEADER
                + word_row(text="x", confidence=96).replace("\t10\t", "\tbad\t", 1)
            )

    def test_tsv_preserves_literal_quotes_and_word_characters(self) -> None:
        for text in ('"AUTO"', '""', '"a""b"', '"AUTO', "  AUTO  ", "µμ①Ａ"):
            with self.subTest(text=text):
                tokens = _parse_tesseract_tsv(
                    TSV_HEADER + word_row(text=text, confidence=95.0)
                )
                self.assertEqual(tuple(token.text for token in tokens), (text,))

    def test_word_confidence_must_be_finite_and_in_range(self) -> None:
        for confidence in (float("nan"), float("inf"), -float("inf"), -1.0, 100.1):
            with self.subTest(confidence=confidence):
                with self.assertRaises(OcrOutputError):
                    _parse_tesseract_tsv(
                        TSV_HEADER
                        + word_row(text="untrusted", confidence=confidence)
                        + word_row(text="AUTO", confidence=95.0)
                    )

    def test_ambiguous_headers_and_incomplete_rows_are_rejected(self) -> None:
        valid = word_row(text="AUTO", confidence=95.0)
        malformed = (
            TSV_HEADER.rstrip("\n") + "\ttext\n" + valid.rstrip("\n") + "\tMANUAL\n",
            TSV_HEADER.replace("text\n", "unexpected\n") + valid,
            TSV_HEADER.rstrip("\n") + "\textra\n" + valid.rstrip("\n") + "\tx\n",
            TSV_HEADER + valid.rstrip("\n") + "\tignored-cell\n",
            TSV_HEADER + valid + "5\t1\t1\n",
            TSV_HEADER + valid.replace("5\t", "6\t", 1),
            TSV_HEADER + word_row(text="", confidence=95.0),
            TSV_HEADER + word_row(text="   ", confidence=95.0),
        )
        for index, output in enumerate(malformed):
            with self.subTest(index=index):
                with self.assertRaises(OcrOutputError):
                    _parse_tesseract_tsv(output)

    def test_csv_field_limit_errors_become_ocr_errors(self) -> None:
        oversized = "x" * (csv.field_size_limit() + 1)
        for output in (
            oversized,
            TSV_HEADER + word_row(text=oversized, confidence=95.0),
        ):
            with self.subTest(header_only=output is oversized):
                with self.assertRaises(OcrOutputError):
                    _parse_tesseract_tsv(output)

    def test_nonword_metadata_and_valid_confidence_boundaries(self) -> None:
        metadata = "1\t1\t0\t0\t0\t0\t0\t0\t440\t72\t-1\t\n"
        self.assertEqual(_parse_tesseract_tsv(TSV_HEADER + metadata), ())
        tokens = _parse_tesseract_tsv(
            TSV_HEADER
            + metadata
            + word_row(text="low", confidence=0.0)
            + word_row(text="high", confidence=100.0)
        )
        self.assertEqual(tuple(token.confidence for token in tokens), (0.0, 100.0))

    def test_fixed_crops_use_argument_list_and_return_read_only_results(self) -> None:
        runner = FakeRunner(TSV_HEADER + word_row(text="AUTO", confidence=95.0))
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            results = engine.extract_template(
                rendered.left_image_path,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )

        self.assertEqual(
            tuple(results), SYNTHETIC_PANEL_TEMPLATE.expected_parameter_ids
        )
        self.assertTrue(all(item.reliable for item in results.values()))
        self.assertTrue(all(item.extracted_text == "AUTO" for item in results.values()))
        self.assertEqual(results["mode"].engine_version, "5.5.1")
        crop_commands = [command for command in runner.commands if "tsv" in command]
        self.assertEqual(len(crop_commands), 4)
        self.assertTrue(all(isinstance(command, list) for command in crop_commands))
        self.assertTrue(all("--psm" in command for command in crop_commands))
        with self.assertRaises(TypeError):
            results["extra"] = results["mode"]  # type: ignore[index]

    def test_crop_digest_identifies_the_exact_binary_stdin(self) -> None:
        calls = []

        def capture(command, **kwargs):
            calls.append((command, kwargs))
            output = (
                "tesseract 5.5.1\n"
                if command[-1] == "--version"
                else TSV_HEADER + word_row(text="AUTO", confidence=95.0)
            )
            if kwargs.get("text"):
                return subprocess.CompletedProcess(command, 0, output, "")
            return subprocess.CompletedProcess(command, 0, output.encode("utf-8"), b"")

        engine = TesseractOcrEngine(binary="python3", runner=capture)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            source_bytes = rendered.left_image_path.read_bytes()
            results = engine.extract_template_bytes(
                source_bytes, template=SYNTHETIC_PANEL_TEMPLATE
            )
        crop_calls = [
            (command, kwargs) for command, kwargs in calls if command[-1] == "tsv"
        ]
        self.assertEqual(len(crop_calls), len(SYNTHETIC_PANEL_TEMPLATE.regions))
        with Image.open(io.BytesIO(source_bytes)) as source:
            for region, (command, kwargs) in zip(
                SYNTHETIC_PANEL_TEMPLATE.regions, crop_calls
            ):
                with self.subTest(parameter_id=region.parameter_id):
                    self.assertEqual(command[1:3], ["stdin", "stdout"])
                    self.assertIs(kwargs["text"], False)
                    self.assertNotIn("encoding", kwargs)
                    self.assertNotIn("errors", kwargs)
                    content = kwargs["input"]
                    self.assertIs(type(content), bytes)
                    self.assertTrue(content.startswith(b"\x89PNG\r\n\x1a\n"))
                    box = region.value_box
                    inset = engine.config.crop_inset_pixels
                    with io.BytesIO() as buffer:
                        source.crop(
                            (
                                box.left + inset,
                                box.top + inset,
                                box.right - inset,
                                box.bottom - inset,
                            )
                        ).save(buffer, format="PNG", optimize=False)
                        self.assertEqual(content, buffer.getvalue())
                    self.assertEqual(
                        results[region.parameter_id].crop_sha256,
                        hashlib.sha256(content).hexdigest(),
                    )
        self.assertIs(calls[0][1]["text"], False)
        self.assertIsNone(calls[0][1]["input"])

    def test_binary_runner_preserves_utf8_and_line_endings(self) -> None:
        output = 'µμ①Ａ "AUTO"\r\nsecond\rthird\n'
        calls = []

        def capture(command, **kwargs):
            calls.append(kwargs)
            return subprocess.CompletedProcess(command, 0, output.encode("utf-8"), b"")

        engine = TesseractOcrEngine(binary="python3", runner=capture)
        result = engine._run(("unused-test-command",))
        self.assertEqual(result.stdout, output)
        self.assertEqual(result.stderr, "")
        self.assertIs(calls[0]["text"], False)
        self.assertNotIn("encoding", calls[0])
        self.assertNotIn("errors", calls[0])

    def test_invalid_binary_output_is_an_ocr_error(self) -> None:
        for stdout, stderr in (
            (b"\xff", b""),
            (b"valid", b"\xff"),
            ("already decoded", b""),
            (b"valid", "already decoded"),
            (None, b""),
            (b"valid", None),
            (bytearray(b"valid"), b""),
        ):
            with self.subTest(stdout=stdout, stderr=stderr):

                def capture(command, **kwargs):
                    return subprocess.CompletedProcess(command, 0, stdout, stderr)

                engine = TesseractOcrEngine(binary="python3", runner=capture)
                with self.assertRaises(OcrOutputError):
                    engine._run(("unused-test-command",))

    def test_binary_stdin_keeps_execution_error_and_timeout_boundaries(self) -> None:
        payload = b"synthetic test input, not sent to a real process"
        for error in (
            OSError("synthetic unavailable"),
            subprocess.TimeoutExpired("synthetic", 0.25),
        ):
            calls = []

            def fail(command, **kwargs):
                calls.append(kwargs)
                raise error

            engine = TesseractOcrEngine(
                binary="python3",
                config=TesseractConfig(timeout_seconds=0.25),
                runner=fail,
            )
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(OcrExecutionError):
                    engine._run(("unused-test-command",), input_bytes=payload)
                self.assertIs(calls[0]["input"], payload)
                self.assertEqual(calls[0]["timeout"], 0.25)

        def nonzero(command, **kwargs):
            return subprocess.CompletedProcess(command, 2, b"", b"synthetic failure")

        engine = TesseractOcrEngine(binary="python3", runner=nonzero)
        with self.assertRaisesRegex(OcrExecutionError, "status 2"):
            engine._run(("unused-test-command",), input_bytes=payload)

    def test_no_tokens_and_low_confidence_abstain_with_reason(self) -> None:
        for output, confidence_phrase in (
            (TSV_HEADER, "no word tokens"),
            (TSV_HEADER + word_row(text="AUTO", confidence=20.0), "below"),
        ):
            with self.subTest(output=output):
                runner = FakeRunner(output)
                engine = TesseractOcrEngine(binary="python3", runner=runner)
                with TemporaryDirectory() as directory:
                    rendered = render_case(default_clean_case(), output_root=directory)
                    result = engine.extract_template(
                        rendered.left_image_path,
                        template=SYNTHETIC_PANEL_TEMPLATE,
                    )["mode"]
                self.assertFalse(result.reliable)
                self.assertIn(confidence_phrase, result.reason or "")

    def test_dimension_mismatch_is_not_silently_cropped(self) -> None:
        runner = FakeRunner(TSV_HEADER + word_row(text="AUTO", confidence=95.0))
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "small.png"
            from PIL import Image

            Image.new("RGB", (100, 100), "white").save(path)
            with self.assertRaises(OcrExecutionError):
                engine.extract_template(path, template=SYNTHETIC_PANEL_TEMPLATE)

    def test_configuration_digest_changes_with_threshold_or_crop(self) -> None:
        first = TesseractConfig()
        second = TesseractConfig(minimum_mean_confidence=80.0)
        third = TesseractConfig(crop_inset_pixels=9)
        self.assertNotEqual(first.content_sha256, second.content_sha256)
        self.assertNotEqual(first.content_sha256, third.content_sha256)

    def test_source_digest_and_decoded_crops_share_one_snapshot(self) -> None:
        runner = FakeRunner(TSV_HEADER + word_row(text="AUTO", confidence=95.0))
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            original_bytes = rendered.left_image_path.read_bytes()
            replacement_bytes = rendered.right_image_path.read_bytes()
            region = next(
                item
                for item in SYNTHETIC_PANEL_TEMPLATE.regions
                if item.parameter_id == "pressure"
            )
            box = region.value_box
            inset = TesseractConfig().crop_inset_pixels
            with Image.open(io.BytesIO(original_bytes)) as image:
                expected_crop = image.crop(
                    (
                        box.left + inset,
                        box.top + inset,
                        box.right - inset,
                        box.bottom - inset,
                    )
                )
                with io.BytesIO() as buffer:
                    expected_crop.save(buffer, format="PNG", optimize=False)
                    expected_hash = hashlib.sha256(buffer.getvalue()).hexdigest()

            def replace_after_source_read(command, **kwargs):
                if command[-1] == "--version":
                    # Only this test's newly rendered temporary fixture is changed.
                    rendered.left_image_path.write_bytes(replacement_bytes)
                return runner(command, **kwargs)

            engine = TesseractOcrEngine(
                binary="python3", runner=replace_after_source_read
            )
            results = engine.extract_template(
                rendered.left_image_path, template=SYNTHETIC_PANEL_TEMPLATE
            )
            self.assertEqual(rendered.left_image_path.read_bytes(), replacement_bytes)
            self.assertEqual(
                results["pressure"].source_image_sha256,
                hashlib.sha256(original_bytes).hexdigest(),
            )
            self.assertEqual(results["pressure"].crop_sha256, expected_hash)

    def test_bytes_api_matches_path_api_and_rejects_mutable_input(self) -> None:
        runner = FakeRunner(TSV_HEADER + word_row(text="AUTO", confidence=95.0))
        engine = TesseractOcrEngine(binary="python3", runner=runner)
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            content = rendered.left_image_path.read_bytes()
            expected = engine.extract_template(
                rendered.left_image_path, template=SYNTHETIC_PANEL_TEMPLATE
            )
            actual = engine.extract_template_bytes(
                content, template=SYNTHETIC_PANEL_TEMPLATE
            )
        self.assertEqual(actual, expected)

        class BytesSubclass(bytes):
            pass

        calls = len(runner.commands)
        for invalid in (
            bytearray(content),
            memoryview(content),
            BytesSubclass(content),
            None,
            "image.png",
        ):
            with self.subTest(kind=type(invalid).__name__), self.assertRaises(
                TypeError
            ):
                engine.extract_template_bytes(
                    invalid, template=SYNTHETIC_PANEL_TEMPLATE
                )
        with self.assertRaises(OcrExecutionError):
            engine.extract_template_bytes(b"", template=SYNTHETIC_PANEL_TEMPLATE)
        self.assertEqual(len(runner.commands), calls)

    @unittest.skipUnless(shutil.which("tesseract"), "local Tesseract is not installed")
    def test_real_tesseract_reads_the_clean_synthetic_pair(self) -> None:
        with TemporaryDirectory() as directory:
            rendered = render_case(default_clean_case(), output_root=directory)
            engine = TesseractOcrEngine()
            left = engine.extract_template(
                rendered.left_image_path,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )
            right = engine.extract_template(
                rendered.right_image_path,
                template=SYNTHETIC_PANEL_TEMPLATE,
            )

        self.assertEqual(left["pressure"].extracted_text, "1.20 bar")
        self.assertEqual(right["pressure"].extracted_text, "1.25 bar")
        self.assertEqual(left["speed"].extracted_text, "0800 rpm")
        self.assertEqual(right["speed"].extracted_text, "800 rpm")
        self.assertTrue(all(item.reliable for item in left.values()))
        self.assertTrue(all(item.reliable for item in right.values()))


if __name__ == "__main__":
    unittest.main()
