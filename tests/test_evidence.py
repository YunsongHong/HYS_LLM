"""Tests for immutable evidence manifests and substitution detection."""

from pathlib import Path
import tempfile
import unittest

from paramguard.evidence import (
    EvidenceArtifact,
    EvidenceManifest,
    EvidenceRole,
    content_sha256,
)


class EvidenceManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.left_content = b"synthetic-photo-bytes"
        self.right_content = b"synthetic-screenshot-bytes"
        self.left = EvidenceArtifact.from_bytes(
            artifact_id="left-a",
            role=EvidenceRole.LEFT_PHOTO,
            content=self.left_content,
            media_type="image/png",
        )
        self.right = EvidenceArtifact.from_bytes(
            artifact_id="right-a-prime",
            role=EvidenceRole.RIGHT_SCREENSHOT,
            content=self.right_content,
            media_type="image/png",
        )

    def _manifest(self, **changes: object) -> EvidenceManifest:
        values: dict[str, object] = {
            "manifest_id": "manifest-001",
            "schema_id": "synthetic-parameter-schema",
            "schema_version": "1.0",
            "schema_sha256": content_sha256(b"synthetic-schema-content-v1"),
            "template_id": "synthetic-pair-template",
            "template_version": "1.0",
            "template_sha256": content_sha256(b"synthetic-template-content-v1"),
            "expected_parameter_ids": ("temperature", "pressure"),
            "artifacts": (self.left, self.right),
        }
        values.update(changes)
        return EvidenceManifest(**values)  # type: ignore[arg-type]

    def test_same_manifest_has_stable_hash(self) -> None:
        first = self._manifest()
        second = self._manifest()

        self.assertEqual(first.manifest_hash, second.manifest_hash)
        self.assertEqual(len(first.manifest_hash), 64)

    def test_any_content_hash_or_schema_change_changes_manifest_hash(self) -> None:
        original = self._manifest()
        changed_left = EvidenceArtifact.from_bytes(
            artifact_id="left-a",
            role=EvidenceRole.LEFT_PHOTO,
            content=b"different-photo-bytes",
            media_type="image/png",
        )

        self.assertNotEqual(
            original.manifest_hash,
            self._manifest(artifacts=(changed_left, self.right)).manifest_hash,
        )
        self.assertNotEqual(
            original.manifest_hash,
            self._manifest(schema_version="2.0").manifest_hash,
        )
        self.assertNotEqual(
            original.manifest_hash,
            self._manifest(
                schema_sha256=content_sha256(b"changed-schema-same-version")
            ).manifest_hash,
        )
        self.assertNotEqual(
            original.manifest_hash,
            self._manifest(
                expected_parameter_ids=("temperature", "pressure", "mode")
            ).manifest_hash,
        )

    def test_exactly_one_photo_and_one_screenshot_are_required(self) -> None:
        with self.assertRaises(ValueError):
            self._manifest(artifacts=(self.left,))
        with self.assertRaises(ValueError):
            self._manifest(artifacts=(self.left, self.left))

    def test_duplicate_parameter_or_artifact_id_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._manifest(expected_parameter_ids=("pH", "pH"))
        duplicate_id_right = EvidenceArtifact.from_bytes(
            artifact_id="left-a",
            role=EvidenceRole.RIGHT_SCREENSHOT,
            content=self.right_content,
            media_type="image/png",
        )
        with self.assertRaises(ValueError):
            self._manifest(artifacts=(self.left, duplicate_id_right))

    def test_manifest_rejects_ids_that_workflow_cannot_use(self) -> None:
        with self.assertRaises(ValueError):
            self._manifest(expected_parameter_ids=("field with space",))
        with self.assertRaises(ValueError):
            self._manifest(schema_id="schema with space")

    def test_content_substitution_is_detected(self) -> None:
        manifest = self._manifest()
        manifest.assert_artifact_content(
            artifact_id="left-a", content=self.left_content
        )

        with self.assertRaisesRegex(ValueError, "no longer matches"):
            manifest.assert_artifact_content(
                artifact_id="left-a", content=b"substituted-content"
            )

    def test_file_hashing_matches_byte_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.png"
            path.write_bytes(self.left_content)
            from_file = EvidenceArtifact.from_file(
                artifact_id="left-a",
                role=EvidenceRole.LEFT_PHOTO,
                path=path,
                media_type="image/png",
            )

        self.assertEqual(from_file, self.left)

    def test_empty_evidence_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            EvidenceArtifact.from_bytes(
                artifact_id="empty",
                role=EvidenceRole.LEFT_PHOTO,
                content=b"",
                media_type="image/png",
            )

    def test_schema_and_template_content_hashes_are_required(self) -> None:
        with self.assertRaises(ValueError):
            self._manifest(schema_sha256="not-a-hash")
        with self.assertRaises(ValueError):
            self._manifest(template_sha256="A" * 64)


if __name__ == "__main__":
    unittest.main()
