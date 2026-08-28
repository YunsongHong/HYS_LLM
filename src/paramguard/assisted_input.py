"""Bounded local inputs for the opt-in, non-blind assisted workbench.

This module is not imported by the STRICT_SEQUENTIAL Web application. OCR
locations are candidates, not verified parameter identities. The supported
layout is one identifier followed by its value on each single-column row.
"""

from __future__ import annotations

import base64
import binascii
from collections import defaultdict
import csv
from dataclasses import dataclass
import hashlib
from io import BytesIO, StringIO
import json
import math
import re
import warnings

from PIL import Image, ImageOps, UnidentifiedImageError

from .ocr import OcrError, TesseractConfig, TesseractOcrEngine


MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_PNG_BYTES = 16 * 1024 * 1024
MAX_IMAGE_PIXELS = 16_000_000
MAX_IMAGE_EDGE = 16_000
MAX_TARGETS = 2000
MAX_TSV_BYTES = 4 * 1024 * 1024
MAX_WORDS_PER_PAGE = 40_000
MAX_CANDIDATES_PER_TARGET = 64
MODE = "ASSISTED_REVIEW_V1"
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
CODE_LIKE = re.compile(r"(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9_.:/-]+\Z")
TSV_COLUMNS = (
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
LOCATOR_CONFIG = {
    "version": "single-column-exact-id-v1",
    "language": "eng",
    "psm": 6,
    "minimum_word_confidence": 70,
    "value_reconstruction": "TSV words joined by one space; not verified image whitespace",
    "identifier_matching": "exact first word; no case folding or OCR character correction",
}


class AssistedError(Exception):
    """A bounded, non-sensitive message suitable for the local UI."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def text_value(value: object, name: str, limit: int, *, multiline: bool = False) -> str:
    if type(value) is not str or len(value) > limit:
        raise AssistedError("INVALID_TEXT", f"{name}必须是长度不超过 {limit} 的文字。")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise AssistedError("INVALID_TEXT", f"{name}包含无效字符。") from exc
    allowed = {"\n", "\r", "\t"} if multiline else set()
    if any((ord(c) < 32 or ord(c) == 127) and c not in allowed for c in value):
        raise AssistedError("INVALID_TEXT", f"{name}包含控制字符。")
    return value


def integer(value: object, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise AssistedError("INVALID_NUMBER", f"{name}必须是 {low} 到 {high} 的整数。")
    return value


def exact_keys(value: object, expected: set[str]) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise AssistedError("INVALID_SCHEMA", "请求字段与接口不一致，请刷新页面。")
    return value


def strict_json(raw: bytes) -> dict:
    def pairs(entries: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in entries:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(value: str) -> None:
        raise ValueError("nonfinite JSON number")

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite
        )
        canonical(value).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise AssistedError("INVALID_JSON", "JSON 无效或包含重复字段/非有限数字。") from exc
    if type(value) is not dict:
        raise AssistedError("INVALID_JSON", "请求必须是 JSON 对象。")
    return value


def parse_target_list(value: object) -> list[dict[str, str]]:
    """Accept newline IDs or CSV parameter_id,label, retaining user order."""
    source = text_value(value, "目标清单", 400_000, multiline=True)
    source = source.removeprefix("\ufeff")
    targets: list[dict[str, str]] = []
    seen: set[str] = set()
    try:
        reader = csv.reader(StringIO(source), strict=True)
        for row in reader:
            if not row or all(not cell.strip() for cell in row):
                continue
            if not targets and [cell.strip() for cell in row] in (
                ["parameter_id", "label"],
                ["id", "label"],
            ):
                continue
            if len(row) not in (1, 2):
                raise AssistedError("INVALID_TARGETS", "清单每行使用一个编号，或 CSV 的编号、名称两列。")
            key = row[0].strip()
            if IDENTIFIER.fullmatch(key) is None:
                raise AssistedError(
                    "INVALID_TARGETS", "编号须为连续的英文/数字标识，可含 . _ : / -，最多128字符。"
                )
            if key in seen:
                raise AssistedError("DUPLICATE_TARGET", f"目标清单中编号 {key} 重复，未自动合并。")
            label = text_value(row[1].strip() if len(row) == 2 else key, "名称", 160)
            if not label:
                label = key
            targets.append({"key": key, "label": label})
            seen.add(key)
            if len(targets) > MAX_TARGETS:
                raise AssistedError("TOO_MANY_TARGETS", f"本版每任务最多 {MAX_TARGETS} 个目标。")
    except csv.Error as exc:
        raise AssistedError("INVALID_TARGETS", "清单的 CSV 格式不完整。") from exc
    if not targets:
        raise AssistedError("EMPTY_TARGETS", "请先填写需要核验的参数编号。")
    return targets


@dataclass(frozen=True)
class NormalizedImage:
    name: str
    original: bytes
    png: bytes
    width: int
    height: int
    original_width: int
    original_height: int
    orientation: int
    format: str

    def descriptor(self) -> dict:
        return {
            "name": self.name,
            "source_sha256": digest(self.original),
            "png_sha256": digest(self.png),
            "width": self.width,
            "height": self.height,
            "source_width": self.original_width,
            "source_height": self.original_height,
            "source_format": self.format,
            "exif_orientation": self.orientation,
            "transform": "EXIF transpose; opaque RGB PNG; metadata not copied",
            "source_bytes": len(self.original),
            "png_bytes": len(self.png),
        }


def decode_upload(encoded: object, name: object) -> NormalizedImage:
    filename = text_value(name, "文件名", 180)
    if not filename or any(c in filename for c in "/\\") or filename in {".", ".."}:
        raise AssistedError("INVALID_FILENAME", "文件名不能包含路径。")
    if (
        type(encoded) is not str
        or not 0 < len(encoded) <= ((MAX_FILE_BYTES + 2) // 3) * 4
    ):
        raise AssistedError("FILE_TOO_LARGE", "单张原图须小于等于 8 MiB。")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AssistedError("INVALID_IMAGE", "图片传输编码无效。") from exc
    return normalize_image(data, filename)


def normalize_image(data: bytes, name: str = "image.png") -> NormalizedImage:
    if type(data) is not bytes or not 0 < len(data) <= MAX_FILE_BYTES:
        raise AssistedError("FILE_TOO_LARGE", "单张原图须小于等于 8 MiB。")
    if not (data.startswith(b"\x89PNG\r\n\x1a\n") or data.startswith(b"\xff\xd8\xff")):
        raise AssistedError("UNSUPPORTED_IMAGE", "当前仅接受真实 PNG 或 JPEG 图片。")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(data)) as probe:
                width, height = probe.size
                if (
                    probe.format not in {"PNG", "JPEG"}
                    or getattr(probe, "n_frames", 1) != 1
                ):
                    raise AssistedError("UNSUPPORTED_IMAGE", "不接受动画、多帧或其他格式。")
                if (
                    width * height > MAX_IMAGE_PIXELS
                    or max(width, height) > MAX_IMAGE_EDGE
                ):
                    raise AssistedError(
                        "IMAGE_TOO_LARGE", "单图上限1600万像素，单边最多16000像素，请分图上传。"
                    )
                fmt = probe.format
                probe.verify()
            with Image.open(BytesIO(data)) as source:
                orientation = source.getexif().get(274, 1)
                if type(orientation) is not int or not 1 <= orientation <= 8:
                    raise AssistedError("INVALID_IMAGE", "图片方向标记无效。")
                source.load()
                oriented = ImageOps.exif_transpose(source)
                rgba = oriented.convert("RGBA")
                if rgba.getchannel("A").getextrema() != (255, 255):
                    raise AssistedError("TRANSPARENT_IMAGE", "请将透明图片保存为不透明 PNG 后上传。")
                clean = Image.new("RGB", oriented.size)
                clean.paste(rgba.convert("RGB"))
                buffer = BytesIO()
                clean.save(buffer, format="PNG", optimize=False)
                png = buffer.getvalue()
                if len(png) > MAX_PNG_BYTES:
                    raise AssistedError("IMAGE_TOO_LARGE", "方向统一后的图片过大，请缩小或分图。")
                return NormalizedImage(
                    name,
                    data,
                    png,
                    clean.width,
                    clean.height,
                    width,
                    height,
                    orientation,
                    fmt,
                )
    except AssistedError:
        raise
    except (
        OSError,
        ValueError,
        SyntaxError,
        UnidentifiedImageError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as exc:
        raise AssistedError("INVALID_IMAGE", "图片损坏、格式不受支持或超出安全限制。") from exc


def checked_box(value: object, width: int, height: int) -> list[int]:
    if type(value) is not list or len(value) != 4:
        raise AssistedError("INVALID_REGION", "区域需要四个像素坐标。")
    x1, y1, x2, y2 = value
    for number in value:
        integer(number, "区域坐标", 0, max(width, height))
    if not (0 <= x1 < x2 <= width and 0 <= y1 < y2 <= height):
        raise AssistedError("INVALID_REGION", "区域超出图片或面积为零。")
    return [x1, y1, x2, y2]


def crop_png(png: bytes, box: list[int]) -> bytes:
    with Image.open(BytesIO(png)) as source:
        checked_box(box, source.width, source.height)
        with BytesIO() as output:
            source.crop(tuple(box)).save(output, format="PNG")
            return output.getvalue()


def parse_page_tsv(source: str, width: int, height: int) -> list[dict]:
    """Retain hierarchy and reject malformed words; never guess table columns."""
    text_value(source, "OCR 输出", MAX_TSV_BYTES, multiline=True)
    if len(source.encode("utf-8")) > MAX_TSV_BYTES:
        raise AssistedError("OCR_LIMIT", "识别输出超出上限。")
    grouped: dict[tuple[int, ...], list[dict]] = defaultdict(list)
    seen: set[tuple[int, ...]] = set()
    reader = csv.DictReader(StringIO(source), delimiter="\t", quoting=csv.QUOTE_NONE)
    try:
        if tuple(reader.fieldnames or ()) != TSV_COLUMNS:
            raise ValueError("wrong columns")
        for row_number, row in enumerate(reader):
            if (
                row_number > MAX_WORDS_PER_PAGE * 3
                or None in row
                or any(v is None for v in row.values())
            ):
                raise ValueError("invalid row")
            if row["level"] not in {"1", "2", "3", "4", "5"}:
                raise ValueError("invalid level")
            if row["level"] != "5":
                continue
            fields = [
                row[k]
                for k in (
                    "page_num",
                    "block_num",
                    "par_num",
                    "line_num",
                    "word_num",
                    "left",
                    "top",
                    "width",
                    "height",
                )
            ]
            if any(not n.isascii() or not n.isdecimal() or len(n) > 8 for n in fields):
                raise ValueError("invalid integer")
            page, block, par, line, word, left, top, w, h = map(int, fields)
            if page != 1 or min(block, par, line, word, w, h) < 1:
                raise ValueError("invalid hierarchy")
            key = (page, block, par, line, word)
            if key in seen or len(seen) >= MAX_WORDS_PER_PAGE:
                raise ValueError("duplicate or excessive word")
            seen.add(key)
            box = checked_box([left, top, left + w, top + h], width, height)
            confidence = float(row["conf"])
            if not math.isfinite(confidence) or not 0 <= confidence <= 100:
                raise ValueError("invalid confidence")
            word_text = text_value(row["text"], "OCR 词", 256)
            if not word_text.strip():
                raise ValueError("empty word")
            grouped[key[:4]].append(
                {"text": word_text, "box": box, "confidence": confidence}
            )
    except (ValueError, csv.Error, AssistedError) as exc:
        raise AssistedError("INVALID_OCR", "OCR 返回了无效结构，本页未接纳。") from exc
    lines = []
    for key, words in grouped.items():
        words.sort(key=lambda item: item["box"][0])
        box = [
            min(w["box"][0] for w in words),
            min(w["box"][1] for w in words),
            max(w["box"][2] for w in words),
            max(w["box"][3] for w in words),
        ]
        lines.append({"line": list(key), "words": words, "box": box})
    return sorted(lines, key=lambda line: (line["box"][1], line["box"][0]))


class LocalPageReader:
    """Existing bounded Tesseract process runner; no network or new weights."""

    def __init__(self) -> None:
        self.engine = TesseractOcrEngine(
            config=TesseractConfig(
                page_segmentation_mode=6,
                crop_inset_pixels=0,
                timeout_seconds=30,
                max_output_bytes=MAX_TSV_BYTES,
            )
        )

    def version(self) -> str:
        try:
            return self.engine.engine_version()
        except OcrError as exc:
            raise AssistedError("OCR_UNAVAILABLE", "本机 Tesseract 不可用，请先检查安装。") from exc

    def __call__(self, png: bytes, width: int, height: int) -> list[dict]:
        try:
            result = self.engine._run(
                (
                    self.engine.resolved_binary(),
                    "stdin",
                    "stdout",
                    "-l",
                    "eng",
                    "--psm",
                    "6",
                    "--oem",
                    "1",
                    "--dpi",
                    "300",
                    "tsv",
                ),
                input_bytes=png,
            )
            return parse_page_tsv(result.stdout, width, height)
        except OcrError as exc:
            raise AssistedError(
                "OCR_FAILED", "本地 OCR 未完成。请确认 Tesseract 和 eng 语言包已安装，或缩小单张图片后重试。"
            ) from exc


def candidates_from_lines(
    lines: list[dict], page: dict, targets: set[str]
) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = defaultdict(list)
    for line in lines:
        words = line["words"]
        key = words[0]["text"]
        if key not in targets:
            continue
        values = words[1:]
        raw = " ".join(w["text"] for w in values)
        problems = []
        if not values:
            problems.append("NO_VALUE")
        if any(w["text"] in targets or CODE_LIKE.fullmatch(w["text"]) for w in values):
            problems.append("AMBIGUOUS_LAYOUT")
        if min(w["confidence"] for w in words) < 70:
            problems.append("LOW_CONFIDENCE")
        if len(values) > 12 or len(raw) > 2048:
            problems.append("AMBIGUOUS_LAYOUT")
        value_box = (
            line["box"]
            if not values
            else [
                min(w["box"][0] for w in values),
                min(w["box"][1] for w in values),
                max(w["box"][2] for w in values),
                max(w["box"][3] for w in values),
            ]
        )
        result[key].append(
            {
                "page_id": page["page_id"],
                "name": page["name"],
                "source_sha256": page["source_sha256"],
                "png_sha256": page["png_sha256"],
                "box": line["box"],
                "value_box": value_box,
                "line": line["line"],
                "observed_id": key,
                "raw": raw,
                "confidence": min(w["confidence"] for w in words),
                "problems": problems,
                "method": "OCR_CANDIDATE",
                "words": words,
            }
        )
        if len(result[key]) > MAX_CANDIDATES_PER_TARGET:
            raise AssistedError("CANDIDATE_LIMIT", "同一编号候选过多，未截断为已完成，请分批处理。")
    return dict(result)
