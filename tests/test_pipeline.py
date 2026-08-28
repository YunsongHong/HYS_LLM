"""Tests for immutable, content-bound pipeline configuration identity."""

from dataclasses import FrozenInstanceError, replace
import unittest

from paramguard.evidence import content_sha256
from paramguard.pipeline import PipelineSpec


def make_spec() -> PipelineSpec:
    return PipelineSpec(
        spec_id="approved-pipeline",
        engine_name="synthetic-ocr",
        engine_version="1.0",
        pipeline_version="1.0",
        comparator_version="1.0",
        configuration_sha256=content_sha256(b"approved-config-v1"),
    )


class PipelineSpecTests(unittest.TestCase):
    def test_same_record_has_stable_hash(self) -> None:
        first = make_spec()
        second = make_spec()

        self.assertEqual(first.spec_hash, second.spec_hash)
        self.assertEqual(len(first.spec_hash), 64)

    def test_each_version_and_configuration_digest_changes_hash(self) -> None:
        baseline = make_spec()
        variants = (
            replace(baseline, engine_name="other-engine"),
            replace(baseline, engine_version="2.0"),
            replace(baseline, pipeline_version="2.0"),
            replace(baseline, comparator_version="2.0"),
            replace(
                baseline,
                configuration_sha256=content_sha256(b"approved-config-v2"),
            ),
        )

        self.assertTrue(all(item.spec_hash != baseline.spec_hash for item in variants))
        self.assertEqual(len({item.spec_hash for item in variants}), len(variants))

    def test_spec_is_frozen(self) -> None:
        spec = make_spec()
        with self.assertRaises(FrozenInstanceError):
            spec.engine_version = "forged"  # type: ignore[misc]

    def test_rejects_unsafe_identifiers_and_non_sha_digest(self) -> None:
        with self.assertRaises(ValueError):
            replace(make_spec(), engine_name="name with spaces")
        with self.assertRaises(ValueError):
            replace(make_spec(), configuration_sha256="not-a-sha256")


if __name__ == "__main__":
    unittest.main()
