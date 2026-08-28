#!/usr/bin/env python3
"""Run the frozen local OCR benchmark and write inspectable JSON evidence."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from paramguard.benchmark_runner import run_synthetic_benchmark
from paramguard.evaluation import DatasetSplit
from paramguard.ocr import OcrError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Render synthetic parameter panels, lock simulated first-human "
            "decisions, then evaluate the local Tesseract assistance path."
        )
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("artifacts/evaluation/synthetic-benchmark-v1"),
        help="Directory for generated synthetic images.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("artifacts/evaluation/synthetic-benchmark-v1.json"),
        help="JSON report path (replaced by this reproducible local run).",
    )
    parser.add_argument(
        "--include-development",
        action="store_true",
        help="Also run the development example; default reports held-out/challenge only.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    splits = (
        (
            DatasetSplit.DEVELOPMENT,
            DatasetSplit.HIDDEN_TEST,
            DatasetSplit.CHALLENGE,
        )
        if args.include_development
        else (DatasetSplit.HIDDEN_TEST, DatasetSplit.CHALLENGE)
    )
    try:
        execution = run_synthetic_benchmark(
            output_root=args.output_root,
            splits=splits,
        )
    except OcrError as error:
        print(f"Benchmark could not run local OCR: {error}", file=sys.stderr)
        return 2

    args.report.parent.mkdir(parents=True, exist_ok=True)
    temporary_report = args.report.with_suffix(args.report.suffix + ".tmp")
    temporary_report.write_text(execution.to_json() + "\n", encoding="utf-8")
    temporary_report.replace(args.report)

    print("ParamGuard synthetic benchmark completed.")
    print(f"Benchmark SHA-256: {execution.benchmark_sha256}")
    print(f"Pipeline spec SHA-256: {execution.pipeline_spec_hash}")
    for report in execution.reports:
        difference_recall = report.difference_recall.value
        false_negative_rate = report.false_negative_rate.value
        print(
            f"{report.split.value}: fields={report.field_count}, "
            f"difference_recall={difference_recall}, "
            f"false_negative_rate={false_negative_rate}, "
            f"abstention_rate={report.overall_abstention_rate.value}"
        )
    print(f"Evidence report: {args.report.resolve()}")
    print("This synthetic PoC report is test evidence, not GxP validation or release authority.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
