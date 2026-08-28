import base64
from io import BytesIO
import unittest
from unittest.mock import patch

from PIL import Image

from paramguard.assisted_input import (
    AssistedError,
    LocalPageReader,
    MAX_TARGETS,
    candidates_from_lines,
    checked_box,
    decode_upload,
    normalize_image,
    parse_page_tsv,
    parse_target_list,
    strict_json,
)
from assisted_fixtures import png, tsv


class AssistedInputTests(unittest.TestCase):
    def test_exact_targets_keep_case_zeros_and_header_like_ids(self):
        result = parse_target_list("id\nparameter_id\nP001\np001\nP1")
        self.assertEqual(
            [r["key"] for r in result], ["id", "parameter_id", "P001", "p001", "P1"]
        )

    def test_explicit_csv_header_and_unicode_label(self):
        result = parse_target_list('\ufeffparameter_id,label\nP001,"压力,第一项"\nP002,温度')
        self.assertEqual(result[0], {"key": "P001", "label": "压力,第一项"})

    def test_duplicate_targets_never_silently_merge(self):
        for source in ("P1\nP1", "id\nid\nP1"):
            with self.subTest(source=source), self.assertRaises(
                AssistedError
            ) as caught:
                parse_target_list(source)
            self.assertEqual(caught.exception.code, "DUPLICATE_TARGET")

    def test_target_limits_and_invalid_inputs(self):
        self.assertEqual(
            len(parse_target_list("\n".join(f"P{i}" for i in range(MAX_TARGETS)))),
            MAX_TARGETS,
        )
        for value in (
            "",
            True,
            "P 1",
            "P1,a,b",
            'P1,"broken',
            "P1,\ud800",
            "P1\x00",
            "\n".join(f"P{i}" for i in range(MAX_TARGETS + 1)),
        ):
            with self.subTest(value=str(value)[:30]), self.assertRaises(AssistedError):
                parse_target_list(value)

    def test_strict_json_untrusted_shapes(self):
        for raw in (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":Infinity}',
            b'{"a":1e999}',
            b"[]",
            b'{"a":"\\ud800"}',
            b"\xff",
            b"[" * 2000,
        ):
            with self.subTest(raw=raw[:30]), self.assertRaises(AssistedError):
                strict_json(raw)
        self.assertEqual(strict_json(b'{"a":true}'), {"a": True})

    def test_upload_real_magic_and_filename(self):
        raw = png()
        self.assertEqual(
            decode_upload(base64.b64encode(raw).decode(), "synthetic.png").width, 700
        )
        for name in ("../a.png", "/a.png", "a\\b.png", "", ".", "a\x00"):
            with self.subTest(name=name), self.assertRaises(AssistedError):
                decode_upload(base64.b64encode(raw).decode(), name)
        for data in (b"", b"not a png", raw[:20], b"<svg/>"):
            with self.subTest(data=data[:20]), self.assertRaises(AssistedError):
                normalize_image(data)

    def test_base64_length_and_encoding(self):
        for value in (True, "!invalid!", "", "a" * 100):
            with self.subTest(value=value), self.assertRaises(AssistedError):
                decode_upload(value, "image.png")
        with patch("paramguard.assisted_input.MAX_FILE_BYTES", 8):
            with self.assertRaises(AssistedError):
                decode_upload(base64.b64encode(png()).decode(), "x.png")

    def test_pixel_limit_before_pixel_load(self):
        raw = png(size=(20, 20))
        with patch(
            "paramguard.assisted_input.MAX_IMAGE_PIXELS", 399
        ), self.assertRaises(AssistedError) as caught:
            normalize_image(raw)
        self.assertEqual(caught.exception.code, "IMAGE_TOO_LARGE")

    def test_transparency_and_animation_rejected(self):
        stream = BytesIO()
        Image.new("RGBA", (10, 10), (255, 0, 0, 0)).save(stream, format="PNG")
        with self.assertRaises(AssistedError):
            normalize_image(stream.getvalue())
        stream = BytesIO()
        Image.new("RGB", (10, 10), "white").save(
            stream,
            format="PNG",
            save_all=True,
            append_images=[Image.new("RGB", (10, 10), "black")],
            duration=100,
        )
        with self.assertRaises(AssistedError):
            normalize_image(stream.getvalue())

    def test_all_exif_orientations_and_metadata_removed(self):
        for orientation in range(1, 9):
            with self.subTest(orientation=orientation):
                original = Image.new("RGB", (80, 40), "white")
                original.paste("black", (0, 0, 20, 20))
                exif = Image.Exif()
                exif[274], exif[270] = orientation, "SYNTHETIC PRIVATE METADATA"
                stream = BytesIO()
                original.save(stream, format="JPEG", exif=exif)
                result = normalize_image(stream.getvalue())
                self.assertEqual(
                    (result.width, result.height),
                    (40, 80) if orientation >= 5 else (80, 40),
                )
                with Image.open(BytesIO(result.png)) as clean:
                    self.assertEqual(dict(clean.getexif()), {})
                    self.assertNotIn("exif", clean.info)
                self.assertNotEqual(
                    result.descriptor()["source_sha256"],
                    result.descriptor()["png_sha256"],
                )

    def test_box_exact_types_and_image_bounds(self):
        self.assertEqual(checked_box([0, 0, 10, 20], 10, 20), [0, 0, 10, 20])
        for box in (
            [False, 0, 10, 20],
            [0, 0, 10.0, 20],
            [-1, 0, 10, 20],
            [0, 0, 11, 20],
            [5, 0, 5, 10],
            [0, 1, 2],
            "0,0,2,2",
        ):
            with self.subTest(box=box), self.assertRaises(AssistedError):
                checked_box(box, 10, 20)

    def test_tsv_hierarchy_preserves_distinct_lines(self):
        source = tsv([("P1", "1.20 bar"), ("P2", "1.30 bar")])
        source = source.replace("5\t1\t1\t1\t2", "5\t1\t2\t1\t1")
        result = parse_page_tsv(source, 700, 400)
        self.assertEqual(len(result), 2)
        self.assertNotEqual(result[0]["line"], result[1]["line"])

    def test_tsv_rejects_untrusted_numeric_words_and_bounds(self):
        source = tsv([("P1", "1.20 bar")])
        for bad in (
            source.replace("\t95\t", "\tNaN\t"),
            source.replace("\t95\t", "\t101\t"),
            source.replace("\t100\t20\t", "\t9999\t20\t"),
            source.replace("\tP1", "\tP1\x00"),
            source + source.splitlines()[1] + "\n",
            source.replace("word_num", "unknown"),
        ):
            with self.subTest(bad=bad[:40]), self.assertRaises(AssistedError):
                parse_page_tsv(bad, 700, 400)

    def test_tsv_quotes_are_not_csv_quotes(self):
        result = parse_page_tsv(tsv([("P1", '"ON"')]), 700, 400)
        self.assertEqual(result[0]["words"][1]["text"], '"ON"')

    def test_exact_id_and_full_duplicate_candidates(self):
        page = {
            "page_id": "x",
            "name": "synthetic.png",
            "source_sha256": "a",
            "png_sha256": "b",
        }
        lines = parse_page_tsv(
            tsv([("P10", "1.0"), ("p1", "1.0"), ("P1", "01.00"), ("P1", "1.0")]),
            700,
            400,
        )
        found = candidates_from_lines(lines, page, {"P1"})
        self.assertEqual(list(found), ["P1"])
        self.assertEqual([c["raw"] for c in found["P1"]], ["01.00", "1.0"])

    def test_other_identifier_or_low_confidence_is_uncertain(self):
        page = {
            "page_id": "x",
            "name": "synthetic.png",
            "source_sha256": "a",
            "png_sha256": "b",
        }
        source = tsv([("P1", "P2 42")]).replace("\t95\t", "\t60\t")
        candidate = candidates_from_lines(
            parse_page_tsv(source, 700, 400), page, {"P1", "P2"}
        )["P1"][0]
        self.assertEqual(
            set(candidate["problems"]), {"AMBIGUOUS_LAYOUT", "LOW_CONFIDENCE"}
        )


if __name__ == "__main__":
    unittest.main()
