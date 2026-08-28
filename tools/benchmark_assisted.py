"""Real local OCR on reproducible uploads; no simulated human completion."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import time
import uuid

import PIL

from paramguard.assisted import AssistedWorkspace
from generate_assisted_fixture import generate


def run(output: Path, *, rows: int, targets: int, per_page: int) -> dict:
    if output.exists() or output.is_symlink():
        raise FileExistsError("benchmark output must be a new directory")
    output.mkdir(parents=True)
    started = time.monotonic()
    fixture = generate(output / "inputs", rows=rows, targets=targets, per_page=per_page)
    generated = time.monotonic()
    work = AssistedWorkspace(output / "workspace")
    try:
        initial = work.create(
            {
                "label": f"SYNTHETIC {rows} to {targets}; real OCR; zero human reviews",
                "targets": (output / "inputs/targets.csv").read_text("utf-8"),
                "acknowledge_assisted": True,
                "confirm_local_test_data": True,
                "confirm_single_column": True,
                "command_id": uuid.uuid4().hex,
            }
        )
        job = initial["job_id"]

        def binding(**extra):
            state = work.state(job)
            return {
                "expected_revision": state["revision"],
                "manifest_hash": state["manifest_hash"],
                "command_id": uuid.uuid4().hex,
                **extra,
            }

        for side in ("left", "right"):
            for name in fixture["images"][side]:
                data = (output / "inputs" / name).read_bytes()
                work.upload(
                    job,
                    binding(side=side, name=name, data=base64.b64encode(data).decode()),
                )
            print(
                f"Uploaded {side}: {len(fixture['images'][side])} synthetic images",
                flush=True,
            )
        uploaded = time.monotonic()
        work.start(job, binding())
        while not work.wait(5):
            state = work.state(job)
            print(
                f"OCR {state['progress']}/{len(state['pages'])} pages; state={state['state']}",
                flush=True,
            )
        indexed = time.monotonic()
        state = work.state(job)
        full = work.export(job)
        report = {
            "synthetic": True,
            "real_ocr": True,
            "human_reviews": 0,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "environment": {
                "python": platform.python_version(),
                "pillow": PIL.__version__,
                "platform": platform.platform(),
                "engine": state["engine_version"],
            },
            "input_rows_before_injections_per_side": rows,
            "target_count": targets,
            "images": len(fixture["files"]),
            "state": state["state"],
            "error": state["error"],
            "output_targets": len(full["items"]),
            "machine_counts": state["counts"],
            "can_finish": state["can_finish"],
            "approval": False,
            "seconds": {
                "generation": generated - started,
                "upload_and_freeze": uploaded - generated,
                "ocr": indexed - uploaded,
            },
        }
        if state["state"] == "READY":
            difference_total = sum(
                r["expected"] == "DIFFERENT"
                for r in fixture["truth_for_evaluation_only"]
            )
            supported, detected, false_same, paired, correct_pairs = 0, 0, 0, 0, 0
            failures = []
            for observed, truth in zip(
                full["items"], fixture["truth_for_evaluation_only"], strict=True
            ):
                machine = observed["machine"]
                both = all(
                    machine[s + "_selected"] is not None for s in ("left", "right")
                )
                paired += both
                exact = both
                for side in ("left", "right"):
                    index = machine[side + "_selected"]
                    c = machine[side][index] if index is not None else None
                    located = bool(c) and any(
                        c["name"] == loc["name"]
                        and loc["row_box"][1]
                        <= (c["box"][1] + c["box"][3]) / 2
                        < loc["row_box"][3]
                        for loc in truth["locations"][side]
                    )
                    exact = exact and located and c["raw"] == truth[side + "_value"]
                correct_pairs += bool(exact)
                if truth["expected"] == "DIFFERENT":
                    detected += observed["status"] == "DIFFERENT"
                    supported += observed["status"] == "DIFFERENT" and bool(exact)
                    false_same += observed["status"] == "SAME"
                if observed["status"] != truth["expected"] or not exact:
                    failures.append(
                        {
                            "key": truth["key"],
                            "expected": truth["expected"],
                            "observed": observed["status"],
                            "both_raw_values_and_row_locations_correct": bool(exact),
                        }
                    )
            report["metrics"] = {
                "unique_candidate_pairs": paired,
                "correct_row_and_value_pairs": correct_pairs,
                "true_differences": difference_total,
                "detected_differences": detected,
                "supported_differences": supported,
                "dangerous_same_on_true_differences": false_same,
                "supported_difference_recall": supported / difference_total
                if difference_total
                else None,
                "structural_targets": sum(
                    r["expected"] in {"NOT_LOCATED", "MULTIPLE_CANDIDATES"}
                    for r in fixture["truth_for_evaluation_only"]
                ),
            }
            report["mismatches_and_structural_cases"] = failures
        report["limitations"] = [
            "One clean synthetic layout and bundled font; not photographs or a held-out accuracy comparison",
            "Candidate exact IDs can still be OCR mistakes; image row location is checked against generator truth only in this evaluator",
            "No human timing, no production or 5-percent superiority claim",
            "TSV spaces are reconstructed; image whitespace is not certified",
        ]
        (output / "FULL_REPORT.json").write_text(
            json.dumps(full, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        work.close()
        reopened = AssistedWorkspace(output / "workspace")
        try:
            reopened.verify(job)
            report["restart_verified"] = reopened.state(job)["total"] == targets
        finally:
            reopened.close()
        report["seconds"]["total"] = time.monotonic() - started
        (output / "BENCHMARK.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(
            json.dumps(
                {
                    key: value
                    for key, value in report.items()
                    if key not in {"mismatches_and_structural_cases", "limitations"}
                },
                ensure_ascii=False,
                indent=2,
            ),
            flush=True,
        )
        return report
    finally:
        work.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows", type=int, default=6000)
    parser.add_argument("--targets", type=int, default=1000)
    parser.add_argument("--rows-per-page", type=int, default=200)
    args = parser.parse_args()
    run(args.output, rows=args.rows, targets=args.targets, per_page=args.rows_per_page)
