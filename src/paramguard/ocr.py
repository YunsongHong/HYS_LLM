"""Local Tesseract adapter for fixed, versioned field crops.

The adapter emits OCR observations and confidence metadata only.  It does not
decide whether two values match, does not mutate human records, and has no API
for approving or releasing a task.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import ExitStack
import csv
from dataclasses import dataclass
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import time
from types import MappingProxyType

from PIL import Image

from .template import BoundingBox, FixedTemplate


_LANGUAGE_PATTERN = re.compile(r"^[A-Za-z0-9_+/.-]{1,128}$")
_TSV_COLUMNS = (
    "level",
    "page_num",
    "block_num",
    "par_num",
    "line_num",
    "word_num",
    "left",
    "top",
    "width",
    "height",
    "conf",
    "text",
)


class OcrError(Exception):
    code = "OCR_ERROR"


class OcrUnavailableError(OcrError):
    code = "OCR_UNAVAILABLE"


class OcrExecutionError(OcrError):
    code = "OCR_EXECUTION_ERROR"


class OcrOutputError(OcrError):
    code = "OCR_OUTPUT_ERROR"


@dataclass(frozen=True, slots=True)
class TesseractConfig:
    language: str = "eng"
    page_segmentation_mode: int = 7
    engine_mode: int = 1
    dpi: int = 300
    crop_inset_pixels: int = 8
    minimum_mean_confidence: float = 70.0
    timeout_seconds: float = 15.0
    max_output_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if (
            not isinstance(self.language, str)
            or _LANGUAGE_PATTERN.fullmatch(self.language) is None
        ):
            raise ValueError("language contains unsupported characters")
        if type(self.page_segmentation_mode) is not int or not (
            0 <= self.page_segmentation_mode <= 13
        ):
            raise ValueError("page_segmentation_mode must be an integer from 0 to 13")
        if type(self.engine_mode) is not int or self.engine_mode not in (0, 1, 2, 3):
            raise ValueError("engine_mode must be 0, 1, 2, or 3")
        if type(self.dpi) is not int or self.dpi <= 0:
            raise ValueError("dpi must be a positive integer")
        if type(self.crop_inset_pixels) is not int or self.crop_inset_pixels < 0:
            raise ValueError("crop_inset_pixels must be a non-negative integer")
        if type(self.minimum_mean_confidence) not in (int, float) or not (
            0 <= self.minimum_mean_confidence <= 100
        ):
            raise ValueError("minimum_mean_confidence must be between 0 and 100")
        if type(self.timeout_seconds) not in (int, float) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        try:
            finite_timeout = math.isfinite(self.timeout_seconds)
        except OverflowError:
            finite_timeout = False
        if not finite_timeout:
            raise ValueError(
                "timeout_seconds must be finite and representable as a float"
            )
        if type(self.max_output_bytes) is not int or self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be a positive built-in integer")

    def to_record(self) -> dict[str, object]:
        return {
            "language": self.language,
            "page_segmentation_mode": self.page_segmentation_mode,
            "engine_mode": self.engine_mode,
            "dpi": self.dpi,
            "crop_inset_pixels": self.crop_inset_pixels,
            "minimum_mean_confidence": float(self.minimum_mean_confidence),
            "timeout_seconds": float(self.timeout_seconds),
            "max_output_bytes": self.max_output_bytes,
        }

    @property
    def content_sha256(self) -> str:
        encoded = json.dumps(
            self.to_record(), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class OcrToken:
    text: str
    confidence: float
    box: BoundingBox


@dataclass(frozen=True, slots=True)
class OcrFieldResult:
    parameter_id: str
    extracted_text: str | None
    mean_confidence: float | None
    reliable: bool
    reason: str | None
    tokens: tuple[OcrToken, ...]
    source_image_sha256: str
    crop_sha256: str
    engine_version: str
    config_sha256: str


DEFAULT_TESSERACT_CONFIG = TesseractConfig()


class TesseractOcrEngine:
    """Run the Tesseract CLI without shell interpolation."""

    def __init__(
        self,
        *,
        binary: str = "tesseract",
        config: TesseractConfig = DEFAULT_TESSERACT_CONFIG,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
    ) -> None:
        if not isinstance(binary, str) or binary.strip() == "":
            raise ValueError("binary must be non-empty text")
        if not isinstance(config, TesseractConfig):
            raise TypeError("config must be a TesseractConfig")
        if runner is not None and not callable(runner):
            raise TypeError("runner must be callable or None")
        self._binary = binary
        self._config = config
        self._runner = runner

    @property
    def config(self) -> TesseractConfig:
        return self._config

    def resolved_binary(self) -> str:
        resolved = shutil.which(self._binary)
        if resolved is None:
            raise OcrUnavailableError(f"Tesseract executable not found: {self._binary}")
        return resolved

    def engine_version(self) -> str:
        completed = self._run((self.resolved_binary(), "--version"))
        first_line = completed.stdout.splitlines()[0] if completed.stdout else ""
        match = re.fullmatch(r"tesseract\s+([^\s]+)", first_line.strip())
        if match is None:
            raise OcrOutputError("Could not parse Tesseract version output")
        return match.group(1)

    def extract_template(
        self,
        image_path: str | Path,
        *,
        template: FixedTemplate,
    ) -> Mapping[str, OcrFieldResult]:
        if not isinstance(template, FixedTemplate):
            raise TypeError("template must be a FixedTemplate")
        return self.extract_template_bytes(
            Path(image_path).read_bytes(), template=template
        )

    def extract_template_bytes(
        self,
        source_bytes: bytes,
        *,
        template: FixedTemplate,
    ) -> Mapping[str, OcrFieldResult]:
        """Hash and decode one immutable source snapshot, without reopening it."""

        if type(source_bytes) is not bytes:
            raise TypeError("source_bytes must be immutable built-in bytes")
        if not isinstance(template, FixedTemplate):
            raise TypeError("template must be a FixedTemplate")
        if not source_bytes:
            raise OcrExecutionError("source image is empty")
        source_hash = hashlib.sha256(source_bytes).hexdigest()
        engine_version = self.engine_version()

        results: dict[str, OcrFieldResult] = {}
        with Image.open(io.BytesIO(source_bytes)) as source:
            if source.size != (template.width, template.height):
                raise OcrExecutionError(
                    "source image dimensions do not match the approved template"
                )
            for region in template.regions:
                inset = self._config.crop_inset_pixels
                box = region.value_box
                if box.width <= inset * 2 or box.height <= inset * 2:
                    raise OcrExecutionError(
                        f"configured crop inset removes field {region.parameter_id}"
                    )
                crop = source.crop(
                    (
                        box.left + inset,
                        box.top + inset,
                        box.right - inset,
                        box.bottom - inset,
                    )
                )
                with io.BytesIO() as buffer:
                    crop.save(buffer, format="PNG", optimize=False)
                    crop_bytes = buffer.getvalue()
                results[region.parameter_id] = self._extract_crop(
                    crop_bytes,
                    parameter_id=region.parameter_id,
                    source_image_sha256=source_hash,
                    engine_version=engine_version,
                )
        return MappingProxyType(results)

    def _extract_crop(
        self,
        crop_bytes: bytes,
        *,
        parameter_id: str,
        source_image_sha256: str,
        engine_version: str,
    ) -> OcrFieldResult:
        config = self._config
        command = (
            self.resolved_binary(),
            "stdin",
            "stdout",
            "-l",
            config.language,
            "--psm",
            str(config.page_segmentation_mode),
            "--oem",
            str(config.engine_mode),
            "--dpi",
            str(config.dpi),
            "tsv",
        )
        # The recorded digest and the CLI input identify the same immutable PNG.
        crop_sha256 = hashlib.sha256(crop_bytes).hexdigest()
        completed = self._run(command, input_bytes=crop_bytes)
        tokens = _parse_tesseract_tsv(completed.stdout)
        extracted_text = " ".join(token.text for token in tokens) or None
        mean_confidence = (
            None
            if not tokens
            else sum(token.confidence for token in tokens) / len(tokens)
        )
        if not tokens:
            reliable = False
            reason = "Tesseract returned no word tokens for the approved crop"
        elif mean_confidence is not None and mean_confidence < float(
            config.minimum_mean_confidence
        ):
            reliable = False
            reason = (
                f"Mean OCR confidence {mean_confidence:.2f} is below the configured "
                f"threshold {float(config.minimum_mean_confidence):.2f}"
            )
        else:
            reliable = True
            reason = None

        return OcrFieldResult(
            parameter_id=parameter_id,
            extracted_text=extracted_text,
            mean_confidence=mean_confidence,
            reliable=reliable,
            reason=reason,
            tokens=tokens,
            source_image_sha256=source_image_sha256,
            crop_sha256=crop_sha256,
            engine_version=engine_version,
            config_sha256=config.content_sha256,
        )

    def _run(
        self, command: tuple[str, ...], *, input_bytes: bytes | None = None
    ) -> subprocess.CompletedProcess[str]:
        if input_bytes is not None and type(input_bytes) is not bytes:
            raise TypeError("OCR input must be immutable built-in bytes")
        try:
            if self._runner is None:
                completed = _capture_bounded_process(
                    command,
                    input_bytes=input_bytes,
                    timeout_seconds=float(self._config.timeout_seconds),
                    max_output_bytes=self._config.max_output_bytes,
                )
            else:
                # Injected runners are trusted test seams; their internal
                # allocations cannot be bounded by a check after they return.
                completed = self._runner(
                    list(command),
                    input=input_bytes,
                    capture_output=True,
                    text=False,
                    timeout=float(self._config.timeout_seconds),
                    check=False,
                )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise OcrExecutionError(f"Tesseract execution failed: {error}") from error
        if not isinstance(completed, subprocess.CompletedProcess):
            raise OcrExecutionError("OCR runner returned an unexpected result type")
        if type(completed.stdout) is not bytes or type(completed.stderr) is not bytes:
            raise OcrOutputError("OCR runner must return binary stdout and stderr")
        if (
            len(completed.stdout) + len(completed.stderr)
            > self._config.max_output_bytes
        ):
            raise OcrOutputError("Tesseract combined output exceeds the byte budget")
        try:
            stdout = completed.stdout.decode("utf-8")
            stderr = completed.stderr.decode("utf-8")
        except UnicodeDecodeError as error:
            raise OcrOutputError("Tesseract output is not valid UTF-8") from error
        if completed.returncode != 0:
            diagnostic = stderr.strip()
            raise OcrExecutionError(
                f"Tesseract exited with status {completed.returncode}: {diagnostic}"
            )
        return subprocess.CompletedProcess(
            completed.args, completed.returncode, stdout, stderr
        )


def _stop_and_reap(process: subprocess.Popen[bytes]) -> None:
    """Only dispose of the direct child this capture invocation owns."""

    try:
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
    finally:
        process.wait()


def _capture_bounded_process(
    command: tuple[str, ...],
    *,
    input_bytes: bytes | None,
    timeout_seconds: float,
    max_output_bytes: int,
) -> subprocess.CompletedProcess[bytes]:
    """Capture at most N bytes, reading at most N+1 to detect excess output.

    stdout and stderr share the budget. All three pipes are serviced without
    blocking on an unread peer. The deadline covers this invocation, not a
    complete image pair, and does not guarantee interruptible OS process setup
    or kernel-level cleanup. POSIX pipes are required by selectors.
    """

    if os.name != "posix":
        raise OcrUnavailableError("Bounded local OCR execution requires POSIX pipes")
    deadline = time.monotonic() + timeout_seconds
    with ExitStack() as resources:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.PIPE if input_bytes else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0,
        )
        resources.callback(_stop_and_reap, process)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                resources.enter_context(stream)
        selector = resources.enter_context(selectors.DefaultSelector())
        for stream, name in (
            (process.stdout, "stdout"),
            (process.stderr, "stderr"),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if process.stdin is not None:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        pending_input = memoryview(input_bytes or b"")
        input_offset = 0
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        captured = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            for key, _ in selector.select(remaining):
                if key.data == "stdin":
                    try:
                        written = os.write(
                            key.fd, pending_input[input_offset : input_offset + 65536]
                        )
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    if written <= 0:
                        raise OcrExecutionError("Tesseract input pipe made no progress")
                    input_offset += written
                    if input_offset == len(pending_input):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                else:
                    try:
                        chunk = os.read(
                            key.fd, min(65536, max_output_bytes - captured + 1)
                        )
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    captured += len(chunk)
                    if captured > max_output_bytes:
                        raise OcrOutputError(
                            "Tesseract combined output exceeds the byte budget"
                        )
                    buffers[key.data].extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout_seconds)
        process.wait(timeout=remaining)
        return subprocess.CompletedProcess(
            process.args,
            process.returncode,
            bytes(buffers["stdout"]),
            bytes(buffers["stderr"]),
        )


def _parse_tesseract_tsv(tsv_text: str) -> tuple[OcrToken, ...]:
    if not isinstance(tsv_text, str):
        raise TypeError("tsv_text must be str")
    # Tesseract writes literal word characters, not CSV-escaped quoted cells.
    reader = csv.DictReader(
        io.StringIO(tsv_text), delimiter="\t", quoting=csv.QUOTE_NONE
    )

    tokens: list[OcrToken] = []
    try:
        if tuple(reader.fieldnames or ()) != _TSV_COLUMNS:
            raise OcrOutputError("Tesseract TSV columns do not match the fixed schema")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise OcrOutputError("Tesseract TSV row has missing or surplus cells")
            if row["level"] not in ("1", "2", "3", "4", "5"):
                raise OcrOutputError("Tesseract TSV row has an unsupported level")
            if row["level"] != "5":
                continue
            text = row["text"]
            if text.strip() == "":
                raise OcrOutputError("Tesseract word row has no observable text")
            confidence = float(row["conf"])
            if not math.isfinite(confidence) or not 0 <= confidence <= 100:
                raise OcrOutputError(
                    "Tesseract word confidence must be finite in [0, 100]"
                )
            left = int(row["left"])
            top = int(row["top"])
            width = int(row["width"])
            height = int(row["height"])
            tokens.append(
                OcrToken(
                    text=text,
                    confidence=confidence,
                    box=BoundingBox(left, top, left + width, top + height),
                )
            )
    except (csv.Error, KeyError, TypeError, ValueError) as error:
        raise OcrOutputError(f"Malformed Tesseract TSV row: {error}") from error
    return tuple(tokens)
