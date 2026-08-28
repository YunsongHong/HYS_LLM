"""Fail-closed checks for ParamGuard's small supply-chain inventory.

This module deliberately implements a narrow project registry, not a general
SBOM parser.  It uses only the Python standard library so checking the sole
declared Python dependency does not itself add another dependency.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import date
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tomllib
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse


SCHEMA_VERSION = 1

_TOP_LEVEL_KEYS = {
    "schema_version",
    "inventory_name",
    "scope",
    "verified_on",
    "components",
}
_COMPONENT_KEYS = {
    "id",
    "name",
    "artifact_kind",
    "project_relation",
    "observed_version",
    "license_spdx",
    "verification_status",
    "runtime_required",
    "source_url",
    "license_source_url",
    "observation_method",
    "scope_note",
    "integrity",
}
_INTEGRITY_KEYS = {"method", "value"}

_ARTIFACT_KINDS = {
    "PYTHON_RUNTIME",
    "PYTHON_PACKAGE",
    "CLI",
    "LANGUAGE_DATA",
    "EMBEDDED_ASSET",
    "NATIVE_LIBRARY",
}
_PROJECT_RELATIONS = {
    "DIRECT_DEPENDENCY",
    "RUNTIME_PREREQUISITE",
    "EMBEDDED_ASSET",
    "MODEL_DATA",
    "TRANSITIVE_RUNTIME",
}
_VERIFICATION_STATUSES = {"VERIFIED", "NEEDS_REVIEW"}
_INTEGRITY_METHODS = {"SHA256", "UPSTREAM_SHA256", "VERSION_REPORT_ONLY"}
_RELATION_BY_ARTIFACT_KIND = {
    "PYTHON_RUNTIME": "RUNTIME_PREREQUISITE",
    "PYTHON_PACKAGE": "DIRECT_DEPENDENCY",
    "CLI": "RUNTIME_PREREQUISITE",
    "LANGUAGE_DATA": "MODEL_DATA",
    "EMBEDDED_ASSET": "EMBEDDED_ASSET",
    "NATIVE_LIBRARY": "TRANSITIVE_RUNTIME",
}
_INTEGRITY_METHOD_BY_ARTIFACT_KIND = {
    "PYTHON_RUNTIME": "SHA256",
    "PYTHON_PACKAGE": "SHA256",
    "CLI": "SHA256",
    "LANGUAGE_DATA": "UPSTREAM_SHA256",
    "EMBEDDED_ASSET": "SHA256",
    "NATIVE_LIBRARY": "VERSION_REPORT_ONLY",
}
_REQUIRED_COMPONENT_IDS = {
    "python-runtime",
    "pillow",
    "pillow-embedded-aileron",
    "tesseract-cli",
    "tessdata-eng",
}
_REVIEWED_SOURCE_HOSTS = {
    "github.com",
    "giflib.sourceforge.net",
    "gitlab.com",
    "sourceforge.net",
}

# This is intentionally the small set used by this registry.  It is not an
# SPDX expression implementation.  Adding another license requires a reviewed
# checker change instead of silently accepting a typo or invented identifier.
_REVIEWED_SPDX_IDS = {
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "curl",
    "IJG",
    "libpng-2.0",
    "libtiff",
    "MIT",
    "MIT-CMU",
    "PSF-2.0",
    "Zlib",
}

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_DEPENDENCY_NAME_PATTERN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_EXTRAS_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\s*,\s*[A-Za-z0-9][A-Za-z0-9._-]*)*$"
)
_VERSION_CLAUSE_PATTERN = re.compile(
    r"^(?:===|==|~=|!=|<=|>=|<|>)\s*[^\s,;]+$"
)
_SPDX_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9.+-]+")
_LOCAL_PATH_PATTERN = re.compile(
    r"(?:^|[\s\"'=])(?:/(?!/)|[A-Za-z]:[\\/])"
)

_NATIVE_VERSION_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "leptonica": re.compile(r"\bleptonica-([^\s]+)"),
    "giflib": re.compile(r"\blibgif\s+([^\s:]+)"),
    "libjpeg-turbo": re.compile(r"\(libjpeg-turbo\s+([^\s)]+)\)"),
    "libpng": re.compile(r"\blibpng\s+([^\s:]+)"),
    "libtiff": re.compile(r"\blibtiff\s+([^\s:]+)"),
    "zlib": re.compile(r"\bzlib\s+([^\s:]+)"),
    "libwebp": re.compile(r"\blibwebp\s+([^\s:]+)"),
    "openjpeg": re.compile(r"\blibopenjp2\s+([^\s:]+)"),
    "libarchive": re.compile(r"\blibarchive\s+([^\s]+)"),
    "libcurl": re.compile(r"\blibcurl/([^\s]+)"),
}


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """One path-free, machine-readable checker finding."""

    severity: str
    code: str
    component_id: str
    message: str

    def to_record(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "code": self.code,
            "component_id": self.component_id,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class RuntimeSnapshot:
    """Sanitized observations; filesystem locations are never retained."""

    python_version: str
    pillow_version: str | None
    tesseract_available: bool
    tesseract_version: str | None
    tesseract_languages: tuple[str, ...]
    native_versions: Mapping[str, str]
    artifact_sha256: Mapping[str, str]
    skip_reason: str | None = None


@dataclass(frozen=True, slots=True)
class CheckReport:
    """Result of static and optional local-runtime checks."""

    diagnostics: tuple[Diagnostic, ...]

    @property
    def status(self) -> str:
        if any(item.severity == "ERROR" for item in self.diagnostics):
            return "FAIL"
        if any(item.severity == "SKIP" for item in self.diagnostics):
            return "INCOMPLETE"
        return "PASS"

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    @property
    def exit_code(self) -> int:
        if self.status == "FAIL":
            return 1
        if self.status == "INCOMPLETE":
            return 2
        return 0

    def to_record(self) -> dict[str, object]:
        counts = {
            severity: sum(
                item.severity == severity for item in self.diagnostics
            )
            for severity in ("ERROR", "WARNING", "SKIP")
        }
        return {
            "schema_version": 1,
            "status": self.status,
            "counts": counts,
            "diagnostics": [item.to_record() for item in self.diagnostics],
        }


def canonicalize_dependency_name(value: str) -> str:
    """Return the PEP 503-style canonical name needed by this checker."""

    return re.sub(r"[-_.]+", "-", value).lower()


def declared_project_dependencies(pyproject_bytes: bytes) -> tuple[str, ...]:
    """Read direct ``project.dependencies`` names without third-party parsers."""

    document = tomllib.loads(pyproject_bytes.decode("utf-8"))
    project = document.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject project table is missing")
    raw_dependencies = project.get("dependencies", [])
    if not isinstance(raw_dependencies, list):
        raise ValueError("project dependencies must be a list")

    names: list[str] = []
    for requirement in raw_dependencies:
        if not isinstance(requirement, str) or not requirement.strip():
            raise ValueError("project dependency entry must be non-empty text")
        names.append(canonicalize_dependency_name(_dependency_name(requirement)))
    if len(set(names)) != len(names):
        raise ValueError("project dependencies contain duplicate package names")
    return tuple(names)


def _dependency_name(requirement: str) -> str:
    """Parse the name while rejecting malformed tails conservatively."""

    match = _DEPENDENCY_NAME_PATTERN.match(requirement)
    if match is None:
        raise ValueError("project dependency name could not be parsed")
    remainder = requirement[match.end() :].strip()
    if remainder.startswith("["):
        closing = remainder.find("]")
        if closing <= 1 or _EXTRAS_PATTERN.fullmatch(remainder[1:closing]) is None:
            raise ValueError("project dependency extras could not be parsed")
        remainder = remainder[closing + 1 :].strip()

    if ";" in remainder:
        requirement_part, marker = remainder.split(";", 1)
        if not marker.strip():
            raise ValueError("project dependency marker must not be empty")
        remainder = requirement_part.strip()
    if not remainder:
        return match.group(1)
    if remainder.startswith("@"):
        direct_reference = remainder[1:].strip()
        if not direct_reference or any(character.isspace() for character in direct_reference):
            raise ValueError("project dependency direct reference is malformed")
        return match.group(1)
    if any(
        _VERSION_CLAUSE_PATTERN.fullmatch(clause.strip()) is None
        for clause in remainder.split(",")
    ):
        raise ValueError("project dependency version clause is malformed")
    return match.group(1)


def validate_registry(
    document: object,
    *,
    direct_dependencies: Sequence[str],
) -> tuple[Diagnostic, ...]:
    """Validate the fixed registry schema and its direct-dependency coverage."""

    diagnostics: list[Diagnostic] = []
    if not isinstance(document, dict):
        return (_error("INVALID_DOCUMENT", "registry must be a JSON object"),)

    keys = set(document)
    _check_fixed_keys(
        actual=keys,
        expected=_TOP_LEVEL_KEYS,
        diagnostics=diagnostics,
        component_id="registry",
        prefix="top-level",
    )
    if document.get("schema_version") != SCHEMA_VERSION:
        diagnostics.append(
            _error(
                "UNSUPPORTED_SCHEMA_VERSION",
                f"schema_version must equal {SCHEMA_VERSION}",
            )
        )
    for field in ("inventory_name", "scope"):
        _require_clean_text(document.get(field), field, diagnostics, "registry")
    _validate_date(document.get("verified_on"), diagnostics)

    components = document.get("components")
    if not isinstance(components, list) or not components:
        diagnostics.append(
            _error("INVALID_COMPONENTS", "components must be a non-empty list")
        )
        return tuple(diagnostics)

    seen_ids: set[str] = set()
    seen_coordinates: set[tuple[object, str, object]] = set()
    direct_component_names: set[str] = set()
    for index, component in enumerate(components):
        fallback_id = f"component-{index}"
        if not isinstance(component, dict):
            diagnostics.append(
                _error(
                    "INVALID_COMPONENT",
                    "component must be a JSON object",
                    fallback_id,
                )
            )
            continue
        raw_id = component.get("id")
        component_id = (
            raw_id
            if isinstance(raw_id, str)
            and _IDENTIFIER_PATTERN.fullmatch(raw_id) is not None
            else fallback_id
        )
        _check_fixed_keys(
            actual=set(component),
            expected=_COMPONENT_KEYS,
            diagnostics=diagnostics,
            component_id=component_id,
            prefix="component",
        )
        if not isinstance(raw_id, str) or _IDENTIFIER_PATTERN.fullmatch(raw_id) is None:
            diagnostics.append(
                _error(
                    "INVALID_COMPONENT_ID",
                    "component id must be a safe lowercase identifier",
                    component_id,
                )
            )
        elif raw_id in seen_ids:
            diagnostics.append(
                _error(
                    "DUPLICATE_COMPONENT_ID",
                    "component id must be unique",
                    component_id,
                )
            )
        else:
            seen_ids.add(raw_id)

        for field in (
            "name",
            "observed_version",
            "license_spdx",
            "verification_status",
            "source_url",
            "license_source_url",
            "observation_method",
            "scope_note",
        ):
            _require_clean_text(
                component.get(field), field, diagnostics, component_id
            )

        artifact_kind = component.get("artifact_kind")
        if not isinstance(artifact_kind, str) or artifact_kind not in _ARTIFACT_KINDS:
            diagnostics.append(
                _error(
                    "UNKNOWN_ARTIFACT_KIND",
                    "artifact_kind is not in the reviewed enum",
                    component_id,
                )
            )
        relation = component.get("project_relation")
        if not isinstance(relation, str) or relation not in _PROJECT_RELATIONS:
            diagnostics.append(
                _error(
                    "UNKNOWN_PROJECT_RELATION",
                    "project_relation is not in the reviewed enum",
                    component_id,
                )
            )
        if (
            isinstance(artifact_kind, str)
            and artifact_kind in _RELATION_BY_ARTIFACT_KIND
            and isinstance(relation, str)
            and relation in _PROJECT_RELATIONS
            and relation != _RELATION_BY_ARTIFACT_KIND[artifact_kind]
        ):
            diagnostics.append(
                _error(
                    "RELATION_KIND_MISMATCH",
                    "project_relation does not match the artifact kind",
                    component_id,
                )
            )
        if type(component.get("runtime_required")) is not bool:
            diagnostics.append(
                _error(
                    "INVALID_RUNTIME_REQUIRED",
                    "runtime_required must be a JSON boolean",
                    component_id,
                )
            )
        for field in ("source_url", "license_source_url"):
            if isinstance(component.get(field), str) and not _is_https_url(
                component[field]
            ):
                diagnostics.append(
                    _error(
                        "INVALID_SOURCE_URL",
                        f"{field} must be an HTTPS URL",
                        component_id,
                    )
                )

        status = component.get("verification_status")
        if not isinstance(status, str) or status not in _VERIFICATION_STATUSES:
            diagnostics.append(
                _error(
                    "UNKNOWN_VERIFICATION_STATUS",
                    "verification_status is not recognized",
                    component_id,
                )
            )
        elif status == "NEEDS_REVIEW":
            diagnostics.append(
                _error(
                    "COMPONENT_NEEDS_REVIEW",
                    "component is explicitly blocked pending license review",
                    component_id,
                )
            )

        license_expression = component.get("license_spdx")
        if isinstance(license_expression, str):
            _validate_license_expression(
                license_expression,
                status=status,
                component_id=component_id,
                diagnostics=diagnostics,
            )

        _validate_integrity(component.get("integrity"), component_id, diagnostics)
        integrity = component.get("integrity")
        if (
            isinstance(artifact_kind, str)
            and artifact_kind in _INTEGRITY_METHOD_BY_ARTIFACT_KIND
            and isinstance(integrity, dict)
            and isinstance(integrity.get("method"), str)
            and integrity.get("method") in _INTEGRITY_METHODS
            and integrity.get("method")
            != _INTEGRITY_METHOD_BY_ARTIFACT_KIND[artifact_kind]
        ):
            diagnostics.append(
                _error(
                    "INTEGRITY_KIND_MISMATCH",
                    "integrity method does not match the artifact kind",
                    component_id,
                )
            )

        name = component.get("name")
        version = component.get("observed_version")
        if (
            isinstance(name, str)
            and isinstance(artifact_kind, str)
            and isinstance(version, str)
        ):
            coordinate = (
                artifact_kind,
                canonicalize_dependency_name(name),
                version,
            )
            if coordinate in seen_coordinates:
                diagnostics.append(
                    _error(
                        "DUPLICATE_COMPONENT_COORDINATE",
                        "artifact kind, name, and version tuple must be unique",
                        component_id,
                    )
                )
            else:
                seen_coordinates.add(coordinate)

        if relation == "DIRECT_DEPENDENCY" and isinstance(
            component.get("name"), str
        ):
            direct_component_names.add(
                canonicalize_dependency_name(component["name"])
            )

    expected_dependencies = {
        canonicalize_dependency_name(item) for item in direct_dependencies
    }
    for missing_component_id in sorted(_REQUIRED_COMPONENT_IDS - seen_ids):
        diagnostics.append(
            _error(
                "MISSING_REQUIRED_COMPONENT",
                "required project runtime component is absent from the registry",
                missing_component_id,
            )
        )
    for missing in sorted(expected_dependencies - direct_component_names):
        diagnostics.append(
            _error(
                "UNREGISTERED_DIRECT_DEPENDENCY",
                f"direct dependency {missing!r} is absent from the registry",
            )
        )
    for stale in sorted(direct_component_names - expected_dependencies):
        diagnostics.append(
            _error(
                "STALE_DIRECT_DEPENDENCY_ENTRY",
                f"registry marks {stale!r} as direct but pyproject does not",
            )
        )
    return tuple(diagnostics)


def collect_runtime_snapshot() -> RuntimeSnapshot:
    """Observe versions and hashes without retaining or reporting local paths."""

    artifact_hashes: dict[str, str] = {}
    if (python_digest := _safe_sha256_file(Path(sys.executable))) is not None:
        artifact_hashes["python-runtime"] = python_digest
    try:
        pillow_distribution = importlib.metadata.distribution("Pillow")
        pillow_version: str | None = pillow_distribution.version
        record_entry = next(
            (
                entry
                for entry in (pillow_distribution.files or ())
                if str(entry).endswith(".dist-info/RECORD")
            ),
            None,
        )
        if record_entry is not None:
            record_path = Path(pillow_distribution.locate_file(record_entry))
            if (record_digest := _safe_sha256_file(record_path)) is not None:
                artifact_hashes["pillow"] = record_digest
        try:
            from PIL import ImageFont

            font = ImageFont.load_default(size=32)
            stream = getattr(font, "path", None)
            if hasattr(stream, "seek") and hasattr(stream, "read"):
                stream.seek(0)
                artifact_hashes["pillow-embedded-aileron"] = hashlib.sha256(
                    stream.read()
                ).hexdigest()
        except (AttributeError, ImportError, OSError, TypeError, ValueError):
            pass
    except importlib.metadata.PackageNotFoundError:
        pillow_version = None

    executable = shutil.which("tesseract")
    if executable is None:
        return RuntimeSnapshot(
            python_version=platform.python_version(),
            pillow_version=pillow_version,
            tesseract_available=False,
            tesseract_version=None,
            tesseract_languages=(),
            native_versions={},
            artifact_sha256=artifact_hashes,
            skip_reason="Tesseract executable is unavailable; OCR checks were skipped",
        )

    try:
        version_result = subprocess.run(
            (executable, "--version"),
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        languages_result = subprocess.run(
            (executable, "--list-langs"),
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return RuntimeSnapshot(
            python_version=platform.python_version(),
            pillow_version=pillow_version,
            tesseract_available=True,
            tesseract_version=None,
            tesseract_languages=(),
            native_versions={},
            artifact_sha256=artifact_hashes,
            skip_reason="Tesseract probes failed; OCR checks were skipped",
        )

    version_output = "\n".join(
        part for part in (version_result.stdout, version_result.stderr) if part
    )
    first_line = version_output.splitlines()[0].strip() if version_output else ""
    version_match = re.fullmatch(r"tesseract\s+([^\s]+)", first_line)
    tesseract_version = version_match.group(1) if version_match else None
    native_versions = {
        component_id: match.group(1)
        for component_id, pattern in _NATIVE_VERSION_PATTERNS.items()
        if (match := pattern.search(version_output)) is not None
    }
    languages, tessdata_directory = _parse_languages(languages_result.stdout)
    if (tesseract_digest := _safe_sha256_file(Path(executable))) is not None:
        artifact_hashes["tesseract-cli"] = tesseract_digest
    if tessdata_directory is not None:
        for language in languages:
            trained_data = tessdata_directory / f"{language}.traineddata"
            if trained_data.is_file():
                digest = _safe_sha256_file(trained_data)
                if digest is not None:
                    artifact_hashes[f"tessdata-{language}"] = digest

    return RuntimeSnapshot(
        python_version=platform.python_version(),
        pillow_version=pillow_version,
        tesseract_available=True,
        tesseract_version=tesseract_version,
        tesseract_languages=tuple(sorted(languages)),
        native_versions=native_versions,
        artifact_sha256=artifact_hashes,
        skip_reason=None if tesseract_version else "Tesseract version was not parseable",
    )


def validate_runtime(
    document: object,
    snapshot: RuntimeSnapshot,
) -> tuple[Diagnostic, ...]:
    """Compare sanitized local observations with an already parsed registry."""

    if not isinstance(document, dict) or not isinstance(document.get("components"), list):
        return ()
    components = {
        component.get("id"): component
        for component in document["components"]
        if isinstance(component, dict) and isinstance(component.get("id"), str)
    }
    diagnostics: list[Diagnostic] = []
    _compare_version(
        components,
        component_id="python-runtime",
        observed=snapshot.python_version,
        diagnostics=diagnostics,
    )
    if snapshot.pillow_version is None:
        diagnostics.append(
            _error(
                "PILLOW_UNAVAILABLE",
                "declared direct dependency Pillow is not importable",
                "pillow",
            )
        )
    else:
        _compare_version(
            components,
            component_id="pillow",
            observed=snapshot.pillow_version,
            diagnostics=diagnostics,
        )
    _compare_expected_hashes(
        components,
        snapshot.artifact_sha256,
        diagnostics,
        component_ids={
            "python-runtime",
            "pillow",
            "pillow-embedded-aileron",
        },
    )

    if not snapshot.tesseract_available or snapshot.tesseract_version is None:
        diagnostics.append(
            Diagnostic(
                severity="SKIP",
                code="TESSERACT_RUNTIME_CHECK_SKIPPED",
                component_id="tesseract-cli",
                message=snapshot.skip_reason
                or "Tesseract runtime checks were explicitly skipped",
            )
        )
        return tuple(diagnostics)

    _compare_version(
        components,
        component_id="tesseract-cli",
        observed=snapshot.tesseract_version,
        diagnostics=diagnostics,
    )
    _compare_expected_hashes(
        components,
        snapshot.artifact_sha256,
        diagnostics,
        component_ids={"tesseract-cli"}
        | {
            component_id
            for component_id, component in components.items()
            if component.get("artifact_kind") == "LANGUAGE_DATA"
        },
    )
    registered_languages = {
        component.get("name")
        for component in components.values()
        if component.get("artifact_kind") == "LANGUAGE_DATA"
        and isinstance(component.get("name"), str)
    }
    observed_languages = set(snapshot.tesseract_languages)
    if registered_languages != observed_languages:
        diagnostics.append(
            _error(
                "TESSDATA_SET_MISMATCH",
                "registered and locally reported Tesseract language sets differ",
                "tesseract-cli",
            )
        )

    registered_native = {
        component_id: component
        for component_id, component in components.items()
        if component.get("artifact_kind") == "NATIVE_LIBRARY"
    }
    if set(registered_native) != set(snapshot.native_versions):
        diagnostics.append(
            _error(
                "NATIVE_LIBRARY_SET_MISMATCH",
                "registered and Tesseract-reported native library sets differ",
                "tesseract-cli",
            )
        )
    for component_id, observed_version in snapshot.native_versions.items():
        _compare_version(
            components,
            component_id=component_id,
            observed=observed_version,
            diagnostics=diagnostics,
        )
    return tuple(diagnostics)


def check_supply_chain(
    registry_path: str | Path,
    pyproject_path: str | Path,
    *,
    inspect_runtime: bool = True,
    runtime_snapshot: RuntimeSnapshot | None = None,
) -> CheckReport:
    """Load, validate, and optionally compare the registry to this machine."""

    diagnostics: list[Diagnostic] = []
    try:
        document = json.loads(Path(registry_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return CheckReport(
            (_error("REGISTRY_READ_ERROR", "registry could not be read as JSON"),)
        )
    try:
        dependencies = declared_project_dependencies(Path(pyproject_path).read_bytes())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, ValueError):
        return CheckReport(
            (_error("PYPROJECT_READ_ERROR", "pyproject dependencies could not be read"),)
        )

    diagnostics.extend(
        validate_registry(document, direct_dependencies=dependencies)
    )
    if inspect_runtime:
        snapshot = runtime_snapshot or collect_runtime_snapshot()
        diagnostics.extend(validate_runtime(document, snapshot))
    else:
        diagnostics.append(
            Diagnostic(
                severity="SKIP",
                code="RUNTIME_CHECKS_SKIPPED",
                component_id="registry",
                message="runtime checks were explicitly skipped; result is incomplete",
            )
        )
    return CheckReport(tuple(diagnostics))


def _check_fixed_keys(
    *,
    actual: set[str],
    expected: set[str],
    diagnostics: list[Diagnostic],
    component_id: str,
    prefix: str,
) -> None:
    if actual != expected:
        diagnostics.append(
            _error(
                "SCHEMA_KEYS_MISMATCH",
                f"{prefix} fields do not match the fixed schema",
                component_id,
            )
        )


def _require_clean_text(
    value: object,
    field: str,
    diagnostics: list[Diagnostic],
    component_id: str,
) -> None:
    if not isinstance(value, str) or not value.strip():
        diagnostics.append(
            _error(
                "EMPTY_OR_INVALID_FIELD",
                f"{field} must be non-empty text",
                component_id,
            )
        )
        return
    if _LOCAL_PATH_PATTERN.search(value) is not None:
        diagnostics.append(
            _error(
                "LOCAL_PATH_DISCLOSURE",
                f"{field} must not contain an absolute local path",
                component_id,
            )
        )


def _validate_date(value: object, diagnostics: list[Diagnostic]) -> None:
    if not isinstance(value, str):
        diagnostics.append(_error("INVALID_VERIFIED_ON", "verified_on must be ISO date"))
        return
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        diagnostics.append(_error("INVALID_VERIFIED_ON", "verified_on must be ISO date"))
        return
    if parsed.isoformat() != value:
        diagnostics.append(
            _error("INVALID_VERIFIED_ON", "verified_on must use YYYY-MM-DD")
        )


def _validate_license_expression(
    expression: str,
    *,
    status: object,
    component_id: str,
    diagnostics: list[Diagnostic],
) -> None:
    if expression == "UNKNOWN":
        diagnostics.append(
            _error(
                "UNKNOWN_LICENSE",
                "license is UNKNOWN and must be resolved before approval",
                component_id,
            )
        )
        if status != "NEEDS_REVIEW":
            diagnostics.append(
                _error(
                    "UNKNOWN_LICENSE_NOT_BLOCKED",
                    "UNKNOWN license must use NEEDS_REVIEW status",
                    component_id,
                )
            )
        return
    tokens = _SPDX_TOKEN_PATTERN.findall(expression)
    identifiers = [token for token in tokens if token not in {"AND", "OR"}]
    if not identifiers or any(item not in _REVIEWED_SPDX_IDS for item in identifiers):
        diagnostics.append(
            _error(
                "UNREVIEWED_LICENSE_EXPRESSION",
                "license expression contains an unreviewed SPDX identifier",
                component_id,
            )
        )
        return
    normalized = " AND ".join(identifiers)
    if expression != normalized:
        diagnostics.append(
            _error(
                "INVALID_LICENSE_EXPRESSION",
                "license expression must be a reviewed SPDX id joined by AND",
                component_id,
            )
        )


def _validate_integrity(
    integrity: object,
    component_id: str,
    diagnostics: list[Diagnostic],
) -> None:
    if not isinstance(integrity, dict):
        diagnostics.append(
            _error(
                "INVALID_INTEGRITY",
                "integrity must be a JSON object",
                component_id,
            )
        )
        return
    _check_fixed_keys(
        actual=set(integrity),
        expected=_INTEGRITY_KEYS,
        diagnostics=diagnostics,
        component_id=component_id,
        prefix="integrity",
    )
    method = integrity.get("method")
    value = integrity.get("value")
    if not isinstance(method, str) or method not in _INTEGRITY_METHODS:
        diagnostics.append(
            _error(
                "UNKNOWN_INTEGRITY_METHOD",
                "integrity method is not in the reviewed enum",
                component_id,
            )
        )
    if not isinstance(value, str) or not value.strip():
        diagnostics.append(
            _error(
                "INVALID_INTEGRITY_VALUE",
                "integrity value must be non-empty text",
                component_id,
            )
        )
    elif (
        isinstance(method, str)
        and method in {"SHA256", "UPSTREAM_SHA256"}
        and _SHA256_PATTERN.fullmatch(value) is None
    ):
        diagnostics.append(
            _error(
                "INVALID_SHA256",
                "integrity value must be a lowercase SHA-256 digest",
                component_id,
            )
        )
    elif _LOCAL_PATH_PATTERN.search(value) is not None:
        diagnostics.append(
            _error(
                "LOCAL_PATH_DISCLOSURE",
                "integrity value must not contain an absolute local path",
                component_id,
            )
        )


def _is_https_url(value: str) -> bool:
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname in _REVIEWED_SOURCE_HOSTS
        and not parsed.username
        and port is None
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_sha256_file(path: Path) -> str | None:
    try:
        return _sha256_file(path)
    except OSError:
        return None


def _parse_languages(output: str) -> tuple[set[str], Path | None]:
    directory_match = re.search(r'List of available languages in "([^"]+)"', output)
    directory = Path(directory_match.group(1)) if directory_match else None
    languages = {
        line.strip()
        for line in output.splitlines()
        if _IDENTIFIER_PATTERN.fullmatch(line.strip()) is not None
    }
    return languages, directory


def _compare_expected_hashes(
    components: Mapping[str, Mapping[str, Any]],
    observed_hashes: Mapping[str, str],
    diagnostics: list[Diagnostic],
    *,
    component_ids: set[str],
) -> None:
    for component_id in sorted(component_ids):
        component = components.get(component_id)
        if component is None:
            diagnostics.append(
                _error(
                    "MISSING_RUNTIME_COMPONENT",
                    "expected hash-bound runtime component is absent from the registry",
                    component_id,
                )
            )
            continue
        integrity = component.get("integrity")
        if (
            isinstance(integrity, dict)
            and integrity.get("method") in {"SHA256", "UPSTREAM_SHA256"}
        ):
            observed = observed_hashes.get(component_id)
            if observed is None:
                diagnostics.append(
                    _error(
                        "ARTIFACT_HASH_UNAVAILABLE",
                        "required local artifact hash could not be observed",
                        component_id,
                    )
                )
            elif integrity.get("value") != observed:
                diagnostics.append(
                    _error(
                        "ARTIFACT_HASH_MISMATCH",
                        "local artifact SHA-256 differs from the recorded observation",
                        component_id,
                    )
                )


def _compare_version(
    components: Mapping[str, Mapping[str, Any]],
    *,
    component_id: str,
    observed: str,
    diagnostics: list[Diagnostic],
) -> None:
    component = components.get(component_id)
    if component is None:
        diagnostics.append(
            _error(
                "MISSING_RUNTIME_COMPONENT",
                "locally observed runtime component is absent from the registry",
                component_id,
            )
        )
        return
    if component.get("observed_version") != observed:
        diagnostics.append(
            _error(
                "VERSION_MISMATCH",
                "local version differs from the recorded observed_version",
                component_id,
            )
        )


def _error(
    code: str,
    message: str,
    component_id: str = "registry",
) -> Diagnostic:
    safe_id = (
        component_id
        if _IDENTIFIER_PATTERN.fullmatch(component_id) is not None
        else "invalid-component"
    )
    return Diagnostic(
        severity="ERROR", code=code, component_id=safe_id, message=message
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate ParamGuard's minimal supply-chain registry"
    )
    parser.add_argument(
        "--registry", default="supply-chain/registry.json", help="registry JSON"
    )
    parser.add_argument(
        "--pyproject", default="pyproject.toml", help="project metadata"
    )
    parser.add_argument(
        "--skip-runtime",
        action="store_true",
        help="perform schema/dependency checks only (returns INCOMPLETE)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    report = check_supply_chain(
        args.registry,
        args.pyproject,
        inspect_runtime=not args.skip_runtime,
    )
    print(json.dumps(report.to_record(), ensure_ascii=False, indent=2, sort_keys=True))
    return report.exit_code


if __name__ == "__main__":  # pragma: no cover - exercised through main tests
    raise SystemExit(main())
