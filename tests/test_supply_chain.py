from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from paramguard.supply_chain import (
    CheckReport,
    RuntimeSnapshot,
    check_supply_chain,
    declared_project_dependencies,
    validate_registry,
    validate_runtime,
)


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "supply-chain" / "registry.json"
PYPROJECT_PATH = ROOT / "pyproject.toml"


def registry_document() -> dict[str, object]:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def clean_registry_document() -> dict[str, object]:
    document = registry_document()
    document["components"] = [
        component
        for component in document["components"]
        if component["id"] != "tessdata-snum"
    ]
    return document


def codes(diagnostics: tuple[object, ...]) -> set[str]:
    return {item.code for item in diagnostics}


def expected_hashes(
    components: dict[str, dict[str, object]], *, include_tesseract: bool = True
) -> dict[str, str]:
    result: dict[str, str] = {}
    for component_id, component in components.items():
        method = component["integrity"]["method"]
        if method not in {"SHA256", "UPSTREAM_SHA256"}:
            continue
        if not include_tesseract and (
            component_id == "tesseract-cli"
            or component["artifact_kind"] == "LANGUAGE_DATA"
        ):
            continue
        result[component_id] = component["integrity"]["value"]
    return result


class RegistryValidationTests(unittest.TestCase):
    def test_current_registry_only_blocks_the_explicit_unknown_license(self) -> None:
        dependencies = declared_project_dependencies(PYPROJECT_PATH.read_bytes())
        diagnostics = validate_registry(
            registry_document(), direct_dependencies=dependencies
        )

        self.assertEqual(
            codes(diagnostics), {"COMPONENT_NEEDS_REVIEW", "UNKNOWN_LICENSE"}
        )
        self.assertEqual(
            {item.component_id for item in diagnostics}, {"tessdata-snum"}
        )

    def test_reviewed_subset_is_structurally_valid_and_covers_pyproject(self) -> None:
        dependencies = declared_project_dependencies(PYPROJECT_PATH.read_bytes())
        diagnostics = validate_registry(
            clean_registry_document(), direct_dependencies=dependencies
        )

        self.assertEqual(diagnostics, ())
        self.assertEqual(dependencies, ("pillow",))

    def test_duplicate_ids_fail_closed(self) -> None:
        document = clean_registry_document()
        document["components"].append(deepcopy(document["components"][0]))

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("DUPLICATE_COMPONENT_ID", codes(diagnostics))

    def test_duplicate_coordinate_with_different_id_fails_closed(self) -> None:
        document = clean_registry_document()
        duplicate = deepcopy(document["components"][0])
        duplicate["id"] = "different-id"
        document["components"].append(duplicate)

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("DUPLICATE_COMPONENT_COORDINATE", codes(diagnostics))

    def test_extra_or_missing_fields_violate_fixed_schema(self) -> None:
        extra = clean_registry_document()
        extra["unexpected"] = True
        missing = clean_registry_document()
        del missing["components"][0]["scope_note"]

        extra_diagnostics = validate_registry(extra, direct_dependencies=("pillow",))
        missing_diagnostics = validate_registry(
            missing, direct_dependencies=("pillow",)
        )

        self.assertIn("SCHEMA_KEYS_MISMATCH", codes(extra_diagnostics))
        self.assertIn("SCHEMA_KEYS_MISMATCH", codes(missing_diagnostics))

    def test_empty_field_and_non_boolean_are_rejected(self) -> None:
        document = clean_registry_document()
        document["components"][0]["scope_note"] = "  "
        document["components"][0]["runtime_required"] = 1

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("EMPTY_OR_INVALID_FIELD", codes(diagnostics))
        self.assertIn("INVALID_RUNTIME_REQUIRED", codes(diagnostics))

    def test_unknown_status_and_artifact_kind_are_rejected(self) -> None:
        document = clean_registry_document()
        document["components"][0]["verification_status"] = "PROBABLY_OK"
        document["components"][0]["artifact_kind"] = "MYSTERY"

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("UNKNOWN_VERIFICATION_STATUS", codes(diagnostics))
        self.assertIn("UNKNOWN_ARTIFACT_KIND", codes(diagnostics))

    def test_non_string_enum_values_are_rejected_without_crashing(self) -> None:
        document = clean_registry_document()
        component = document["components"][0]
        component["artifact_kind"] = ["PYTHON_RUNTIME"]
        component["project_relation"] = {"value": "RUNTIME_PREREQUISITE"}
        component["verification_status"] = ["VERIFIED"]
        component["integrity"]["method"] = ["SHA256"]

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("UNKNOWN_ARTIFACT_KIND", codes(diagnostics))
        self.assertIn("UNKNOWN_PROJECT_RELATION", codes(diagnostics))
        self.assertIn("UNKNOWN_VERIFICATION_STATUS", codes(diagnostics))
        self.assertIn("UNKNOWN_INTEGRITY_METHOD", codes(diagnostics))

    def test_relation_and_integrity_must_match_artifact_kind(self) -> None:
        document = clean_registry_document()
        component = document["components"][0]
        component["project_relation"] = "TRANSITIVE_RUNTIME"
        component["integrity"]["method"] = "VERSION_REPORT_ONLY"
        component["integrity"]["value"] = "version only"

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("RELATION_KIND_MISMATCH", codes(diagnostics))
        self.assertIn("INTEGRITY_KIND_MISMATCH", codes(diagnostics))

    def test_unknown_license_cannot_be_disguised_as_verified(self) -> None:
        document = clean_registry_document()
        component = document["components"][0]
        component["license_spdx"] = "UNKNOWN"
        component["verification_status"] = "VERIFIED"

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("UNKNOWN_LICENSE", codes(diagnostics))
        self.assertIn("UNKNOWN_LICENSE_NOT_BLOCKED", codes(diagnostics))

    def test_unreviewed_spdx_identifier_is_rejected(self) -> None:
        document = clean_registry_document()
        document["components"][0]["license_spdx"] = "Imaginary-9.9"

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("UNREVIEWED_LICENSE_EXPRESSION", codes(diagnostics))

    def test_bad_digest_and_unknown_integrity_method_are_rejected(self) -> None:
        document = clean_registry_document()
        integrity = document["components"][0]["integrity"]
        integrity["method"] = "TRUST_ME"
        integrity["value"] = "not-a-digest"

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("UNKNOWN_INTEGRITY_METHOD", codes(diagnostics))

        integrity["method"] = "SHA256"
        diagnostics = validate_registry(document, direct_dependencies=("pillow",))
        self.assertIn("INVALID_SHA256", codes(diagnostics))

    def test_absolute_local_path_is_rejected_without_echoing_it(self) -> None:
        document = clean_registry_document()
        secret = "/Users/example/private/license.txt"
        document["components"][0]["scope_note"] = secret

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))
        serialized = json.dumps([item.to_record() for item in diagnostics])

        self.assertIn("LOCAL_PATH_DISCLOSURE", codes(diagnostics))
        self.assertNotIn(secret, serialized)
        self.assertNotIn("example", serialized)

    def test_missing_direct_dependency_is_rejected(self) -> None:
        document = clean_registry_document()
        pillow = next(
            component
            for component in document["components"]
            if component["id"] == "pillow"
        )
        pillow["project_relation"] = "RUNTIME_PREREQUISITE"

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("UNREGISTERED_DIRECT_DEPENDENCY", codes(diagnostics))

    def test_missing_required_embedded_asset_is_rejected(self) -> None:
        document = clean_registry_document()
        document["components"] = [
            item
            for item in document["components"]
            if item["id"] != "pillow-embedded-aileron"
        ]

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("MISSING_REQUIRED_COMPONENT", codes(diagnostics))

    def test_unreviewed_or_credentialed_source_host_is_rejected(self) -> None:
        document = clean_registry_document()
        document["components"][0]["source_url"] = "https://example.invalid/source"
        document["components"][1]["source_url"] = (
            "https://user@example.invalid/source"
        )

        diagnostics = validate_registry(document, direct_dependencies=("pillow",))

        self.assertIn("INVALID_SOURCE_URL", codes(diagnostics))

    def test_stale_direct_dependency_entry_is_rejected(self) -> None:
        document = clean_registry_document()

        diagnostics = validate_registry(document, direct_dependencies=())

        self.assertIn("STALE_DIRECT_DEPENDENCY_ENTRY", codes(diagnostics))

    def test_dependency_parser_handles_extras_and_constraints(self) -> None:
        content = b"""
[project]
name = "demo"
version = "0.0.1"
dependencies = ["Some_Pkg[feature]>=1; python_version >= '3.11'"]
"""

        self.assertEqual(declared_project_dependencies(content), ("some-pkg",))

    def test_dependency_parser_rejects_malformed_requirement_tail(self) -> None:
        content = b"""
[project]
name = "demo"
version = "0.0.1"
dependencies = ["Pillow definitely-version-12"]
"""

        with self.assertRaises(ValueError):
            declared_project_dependencies(content)


class RuntimeValidationTests(unittest.TestCase):
    def matching_snapshot(self) -> tuple[dict[str, object], RuntimeSnapshot]:
        document = clean_registry_document()
        components = {item["id"]: item for item in document["components"]}
        native_versions = {
            component_id: component["observed_version"]
            for component_id, component in components.items()
            if component["artifact_kind"] == "NATIVE_LIBRARY"
        }
        snapshot = RuntimeSnapshot(
            python_version=components["python-runtime"]["observed_version"],
            pillow_version=components["pillow"]["observed_version"],
            tesseract_available=True,
            tesseract_version=components["tesseract-cli"]["observed_version"],
            tesseract_languages=("eng", "osd"),
            native_versions=native_versions,
            artifact_sha256=expected_hashes(components),
        )
        return document, snapshot

    def test_matching_snapshot_passes(self) -> None:
        document, snapshot = self.matching_snapshot()

        self.assertEqual(validate_runtime(document, snapshot), ())

    def test_version_hash_language_and_native_drift_fail(self) -> None:
        document, snapshot = self.matching_snapshot()
        snapshot = RuntimeSnapshot(
            python_version="0.0.0",
            pillow_version=snapshot.pillow_version,
            tesseract_available=True,
            tesseract_version=snapshot.tesseract_version,
            tesseract_languages=("eng", "unexpected"),
            native_versions={"leptonica": "0.0.0"},
            artifact_sha256={
                **expected_hashes(
                    {item["id"]: item for item in document["components"]}
                ),
                "python-runtime": "0" * 64,
            },
        )

        diagnostics = validate_runtime(document, snapshot)

        self.assertIn("VERSION_MISMATCH", codes(diagnostics))
        self.assertIn("ARTIFACT_HASH_MISMATCH", codes(diagnostics))
        self.assertIn("TESSDATA_SET_MISMATCH", codes(diagnostics))
        self.assertIn("NATIVE_LIBRARY_SET_MISMATCH", codes(diagnostics))

    def test_missing_tesseract_is_explicitly_incomplete_not_pass(self) -> None:
        document, snapshot = self.matching_snapshot()
        snapshot = RuntimeSnapshot(
            python_version=snapshot.python_version,
            pillow_version=snapshot.pillow_version,
            tesseract_available=False,
            tesseract_version=None,
            tesseract_languages=(),
            native_versions={},
            artifact_sha256=expected_hashes(
                {item["id"]: item for item in document["components"]},
                include_tesseract=False,
            ),
            skip_reason="Tesseract executable is unavailable; OCR checks were skipped",
        )

        diagnostics = validate_runtime(document, snapshot)
        report = CheckReport(diagnostics)

        self.assertIn("TESSERACT_RUNTIME_CHECK_SKIPPED", codes(diagnostics))
        self.assertEqual(report.status, "INCOMPLETE")
        self.assertFalse(report.passed)
        self.assertEqual(report.exit_code, 2)

    def test_missing_pillow_is_a_failure(self) -> None:
        document, snapshot = self.matching_snapshot()
        components = {item["id"]: item for item in document["components"]}
        snapshot = RuntimeSnapshot(
            python_version=snapshot.python_version,
            pillow_version=None,
            tesseract_available=snapshot.tesseract_available,
            tesseract_version=snapshot.tesseract_version,
            tesseract_languages=snapshot.tesseract_languages,
            native_versions=snapshot.native_versions,
            artifact_sha256=expected_hashes(components),
        )

        diagnostics = validate_runtime(document, snapshot)

        self.assertIn("PILLOW_UNAVAILABLE", codes(diagnostics))


class EndToEndCheckerTests(unittest.TestCase):
    def test_checked_in_registry_fails_only_for_recorded_review_blockers(self) -> None:
        report = check_supply_chain(
            REGISTRY_PATH, PYPROJECT_PATH, inspect_runtime=False
        )

        self.assertEqual(report.status, "FAIL")
        self.assertEqual(
            codes(report.diagnostics),
            {"COMPONENT_NEEDS_REVIEW", "UNKNOWN_LICENSE", "RUNTIME_CHECKS_SKIPPED"},
        )

    def test_read_error_report_does_not_disclose_input_path(self) -> None:
        secret_path = "/Users/example/private/missing.json"

        report = check_supply_chain(secret_path, PYPROJECT_PATH)
        serialized = json.dumps(report.to_record())

        self.assertEqual(report.status, "FAIL")
        self.assertIn("REGISTRY_READ_ERROR", codes(report.diagnostics))
        self.assertNotIn(secret_path, serialized)
        self.assertNotIn("example", serialized)

    def test_clean_registry_can_pass_with_injected_matching_runtime(self) -> None:
        document = clean_registry_document()
        components = {item["id"]: item for item in document["components"]}
        native_versions = {
            component_id: component["observed_version"]
            for component_id, component in components.items()
            if component["artifact_kind"] == "NATIVE_LIBRARY"
        }
        snapshot = RuntimeSnapshot(
            python_version=components["python-runtime"]["observed_version"],
            pillow_version=components["pillow"]["observed_version"],
            tesseract_available=True,
            tesseract_version=components["tesseract-cli"]["observed_version"],
            tesseract_languages=("eng", "osd"),
            native_versions=native_versions,
            artifact_sha256=expected_hashes(components),
        )
        with tempfile.TemporaryDirectory() as directory:
            registry_path = Path(directory) / "registry.json"
            registry_path.write_text(json.dumps(document), encoding="utf-8")

            report = check_supply_chain(
                registry_path,
                PYPROJECT_PATH,
                runtime_snapshot=snapshot,
            )

        self.assertTrue(report.passed)
        self.assertEqual(report.status, "PASS")
        self.assertEqual(report.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
