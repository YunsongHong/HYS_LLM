from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from paramguard.benchmark import (
    ChallengeCategory,
    SYNTHETIC_BENCHMARK_V1,
)
from paramguard.comparison import ComparisonKind
from paramguard.evidence import EvidenceRole
from paramguard.evaluation import DatasetSplit
from paramguard.synthetic import render_case


class SyntheticBenchmarkTests(unittest.TestCase):
    def test_frozen_benchmark_has_all_splits_and_unique_case_ids(self) -> None:
        benchmark = SYNTHETIC_BENCHMARK_V1

        self.assertEqual(
            len(benchmark.cases_for(DatasetSplit.DEVELOPMENT)),
            1,
        )
        self.assertEqual(
            len(benchmark.cases_for(DatasetSplit.HIDDEN_TEST)),
            7,
        )
        self.assertEqual(
            len(benchmark.cases_for(DatasetSplit.CHALLENGE)),
            2,
        )
        case_ids = [case.spec.case_id for case in benchmark.cases]
        self.assertEqual(len(case_ids), len(set(case_ids)))

    def test_benchmark_digest_is_canonical_and_stable(self) -> None:
        benchmark = SYNTHETIC_BENCHMARK_V1
        first = benchmark.content_sha256
        second = benchmark.content_sha256

        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)
        int(first, 16)
        decoded = json.loads(
            json.dumps(
                benchmark.to_record(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        self.assertEqual(decoded["benchmark_id"], benchmark.benchmark_id)
        self.assertEqual(decoded["version"], benchmark.version)

    def test_risk_categories_and_truth_cover_expected_failure_modes(self) -> None:
        benchmark = SYNTHETIC_BENCHMARK_V1
        observed_categories = {
            category
            for case in benchmark.cases
            for category in case.categories
        }

        self.assertEqual(observed_categories, set(ChallengeCategory))
        hidden = benchmark.cases_for(DatasetSplit.HIDDEN_TEST)
        hidden_by_id = {case.spec.case_id: case for case in hidden}
        self.assertTrue(
            all(
                pair.expected_comparison.kind is ComparisonKind.EXACT_MATCH
                for pair in hidden_by_id["hidden-all-same"].spec.values
            )
        )
        for case_id in (
            "hidden-negative-sign",
            "hidden-decimal-precision",
            "hidden-leading-zero",
            "hidden-unit-change",
            "hidden-mode-change",
            "hidden-missing-left",
        ):
            self.assertTrue(
                any(
                    pair.expected_comparison.kind
                    is not ComparisonKind.EXACT_MATCH
                    for pair in hidden_by_id[case_id].spec.values
                ),
                case_id,
            )

    def test_every_case_renders_to_bound_synthetic_evidence(self) -> None:
        benchmark = SYNTHETIC_BENCHMARK_V1
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory)
            rendered = tuple(
                render_case(case.spec, output_root=output_root)
                for case in benchmark.cases
            )

            self.assertEqual(len(rendered), len(benchmark.cases))
            for item in rendered:
                self.assertTrue(item.left_image_path.is_file())
                self.assertTrue(item.right_image_path.is_file())
                self.assertEqual(
                    item.manifest.expected_parameter_ids,
                    item.template.expected_parameter_ids,
                )
                paths_by_role = {
                    EvidenceRole.LEFT_PHOTO: item.left_image_path,
                    EvidenceRole.RIGHT_SCREENSHOT: item.right_image_path,
                }
                for artifact in item.manifest.artifacts:
                    item.manifest.assert_artifact_content(
                        artifact_id=artifact.artifact_id,
                        content=paths_by_role[artifact.role].read_bytes(),
                    )


if __name__ == "__main__":
    unittest.main()
