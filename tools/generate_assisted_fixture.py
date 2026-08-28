"""Rebuild labeled synthetic upload fixtures; no external images or truth in OCR."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def generate(
    output: Path, *, rows: int = 48, targets: int = 12, per_page: int = 100
) -> dict:
    if (
        not 1 <= targets <= min(rows, 2000)
        or not 1 <= rows <= 6000
        or not 1 <= per_page <= 300
    ):
        raise ValueError("invalid synthetic fixture size")
    if (rows + per_page - 1) // per_page > 64:
        raise ValueError("fixture exceeds the per-side page limit")
    if output.exists() or output.is_symlink():
        raise FileExistsError(
            "use a new output directory; existing artifacts are retained"
        )
    output.mkdir(parents=True)
    selected = [1 + i * rows // targets for i in range(targets)]
    missing = selected[2] if targets >= 3 else None
    duplicate = selected[3] if targets >= 4 else None
    changed = {number for i, number in enumerate(selected) if i % 4 == 1}
    expected = []
    positions = {
        side: {number: [] for number in selected} for side in ("left", "right")
    }
    paths = {"left": [], "right": []}
    files = []
    font, small = ImageFont.load_default(size=26), ImageFont.load_default(size=18)

    def value(number: int, side: str) -> str:
        amount = 10000 + number
        if side == "right" and number in changed:
            amount += 1
        return f"{amount // 100}.{amount % 100:02d} kPa"

    for side in ("left", "right"):
        for start in range(1, rows + 1, per_page):
            relative = f"{side}-{(start-1)//per_page+1:03d}.png"
            numbers = list(range(start, min(rows + 1, start + per_page)))
            if side == "right" and missing in numbers:
                numbers.remove(missing)
            if side == "left" and duplicate in numbers:
                numbers.insert(numbers.index(duplicate) + 1, duplicate)
            width, row_height, top = 900, 35, 92
            image = Image.new(
                "RGB",
                (width, top + len(numbers) * row_height + 24),
                "#fcfcf8" if side == "left" else "#f4f8fc",
            )
            draw = ImageDraw.Draw(image)
            draw.rectangle(
                (0, 0, width, 49), fill="#264c40" if side == "left" else "#29485f"
            )
            draw.text(
                (25, 15),
                f"SYNTHETIC TEST DATA / {side.upper()} / PAGE {(start-1)//per_page+1}",
                font=small,
                fill="white",
            )
            draw.text((32, 62), "PARAMETER ID", font=small, fill="#52645c")
            draw.text((330, 62), "VALUE", font=small, fill="#52645c")
            for i, number in enumerate(numbers):
                y = top + i * row_height
                draw.text((32, y), f"P{number:06d}", font=font, fill="#171f1b")
                draw.text((330, y), value(number, side), font=font, fill="#171f1b")
                if number in positions[side]:
                    positions[side][number].append(
                        {"name": relative, "row_box": [32, y, 890, y + row_height]}
                    )
            path = output / relative
            image.save(path, format="PNG")
            paths[side].append(relative)
            files.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "bytes": path.stat().st_size,
                    "width": width,
                    "height": image.height,
                }
            )
    for i, number in enumerate(selected):
        expected.append(
            {
                "ordinal": i,
                "key": f"P{number:06d}",
                "left_count": 2 if number == duplicate else 1,
                "right_count": 0 if number == missing else 1,
                "left_value": value(number, "left"),
                "right_value": value(number, "right") if number != missing else None,
                "locations": {
                    side: positions[side][number] for side in ("left", "right")
                },
                "expected": "NOT_LOCATED"
                if number == missing
                else "MULTIPLE_CANDIDATES"
                if number == duplicate
                else "DIFFERENT"
                if number in changed
                else "SAME",
            }
        )
    target_text = "parameter_id,label\n" + "".join(
        f"{row['key']},Synthetic parameter {row['ordinal']+1}\n" for row in expected
    )
    (output / "targets.csv").write_text(target_text, encoding="utf-8")
    manifest = {
        "synthetic": True,
        "generator": "assisted-single-column-v1",
        "source_rows_before_injected_cases_per_side": rows,
        "selected_targets": targets,
        "per_page": per_page,
        "images": paths,
        "files": files,
        "truth_for_evaluation_only": expected,
        "limitations": "Clean raster table, not a real photograph; truth is never passed to OCR.",
    }
    (output / "fixture.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows", type=int, default=48)
    parser.add_argument("--targets", type=int, default=12)
    parser.add_argument("--rows-per-page", type=int, default=100)
    args = parser.parse_args()
    result = generate(
        args.output, rows=args.rows, targets=args.targets, per_page=args.rows_per_page
    )
    print(
        json.dumps(
            {
                "synthetic": True,
                "images": len(result["files"]),
                "targets": result["selected_targets"],
                "output": str(args.output),
            }
        )
    )


if __name__ == "__main__":
    main()
