"""Immutable, approved processing-pipeline identity."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe 1-128 character identifier")
    return value


@dataclass(frozen=True, slots=True)
class PipelineSpec:
    """A task-level allowlisted OCR/model/rule configuration."""

    spec_id: str
    engine_name: str
    engine_version: str
    pipeline_version: str
    comparator_version: str
    configuration_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "spec_id",
            "engine_name",
            "engine_version",
            "pipeline_version",
            "comparator_version",
        ):
            _identifier(name, getattr(self, name))
        if not isinstance(
            self.configuration_sha256, str
        ) or _SHA256_PATTERN.fullmatch(self.configuration_sha256) is None:
            raise ValueError(
                "configuration_sha256 must be 64 lowercase hexadecimal characters"
            )

    def to_record(self) -> dict[str, str]:
        return {
            "spec_id": self.spec_id,
            "engine_name": self.engine_name,
            "engine_version": self.engine_version,
            "pipeline_version": self.pipeline_version,
            "comparator_version": self.comparator_version,
            "configuration_sha256": self.configuration_sha256,
        }

    @property
    def spec_hash(self) -> str:
        canonical = json.dumps(
            self.to_record(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()
