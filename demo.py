"""运行 V0.1 合成参数比较演示。"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from paramguard import compare_values


PROJECT_ROOT = Path(__file__).resolve().parent
DATA_PATH = PROJECT_ROOT / "data" / "sample_pairs.json"


def main() -> None:
    payload = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    rows: list[tuple[str, str, str, str]] = []
    counts: Counter[str] = Counter()

    for pair in payload["pairs"]:
        result = compare_values(pair["left"], pair["right"])
        counts[result.kind.value] += 1
        rows.append(
            (
                pair["parameter_id"],
                repr(pair["left"]),
                repr(pair["right"]),
                result.kind.value,
            )
        )

    widths = [
        max(len("PARAMETER"), *(len(row[0]) for row in rows)),
        max(len("LEFT (A)"), *(len(row[1]) for row in rows)),
        max(len("RIGHT (A')"), *(len(row[2]) for row in rows)),
        max(len("RESULT"), *(len(row[3]) for row in rows)),
    ]

    header = ("PARAMETER", "LEFT (A)", "RIGHT (A')", "RESULT")
    print(" | ".join(value.ljust(width) for value, width in zip(header, widths)))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(" | ".join(value.ljust(width) for value, width in zip(row, widths)))

    print("\nSummary")
    for kind, count in sorted(counts.items()):
        print(f"- {kind}: {count}")

    exact = counts.get("EXACT_MATCH", 0)
    print(f"\n{exact}/{len(rows)} pairs are character-identical.")
    print("Character-identical does not mean valid or approved for release.")


if __name__ == "__main__":
    main()
