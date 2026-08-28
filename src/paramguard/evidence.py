"""Immutable evidence manifests for a parameter-review task."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import re


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class EvidenceRole(str, Enum):
    """The two evidence sides in the interview-inspired comparison."""

    LEFT_PHOTO = "LEFT_PHOTO"
    RIGHT_SCREENSHOT = "RIGHT_SCREENSHOT"


def _require_text(name: str, value: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if value.strip() == "":
        raise ValueError(f"{name} must not be empty or whitespace")
    return value


def _require_identifier(name: str, value: str) -> str:
    checked = _require_text(name, value)
    if _IDENTIFIER_PATTERN.fullmatch(checked) is None:
        raise ValueError(f"{name} must be a safe 1-128 character identifier")
    return checked


def content_sha256(content: bytes) -> str:
    """Return a stable content identity without storing the content itself."""

    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if not content:
        raise ValueError("content must not be empty")
    return hashlib.sha256(content).hexdigest()


@dataclass(frozen=True)
class EvidenceArtifact:
    """Content identity and basic metadata for one immutable input file."""

    artifact_id: str
    role: EvidenceRole
    sha256: str
    byte_length: int
    media_type: str

    def __post_init__(self) -> None:
        _require_identifier("artifact_id", self.artifact_id)
        if not isinstance(self.role, EvidenceRole):
            raise TypeError("role must be an EvidenceRole")
        if not isinstance(self.sha256, str) or _SHA256_PATTERN.fullmatch(
            self.sha256
        ) is None:
            raise ValueError(
                "sha256 must contain 64 lowercase hexadecimal characters"
            )
        if type(self.byte_length) is not int or self.byte_length <= 0:
            raise ValueError("byte_length must be a positive integer")
        _require_text("media_type", self.media_type)

    @classmethod
    def from_bytes(
        cls,
        *,
        artifact_id: str,
        role: EvidenceRole,
        content: bytes,
        media_type: str,
    ) -> EvidenceArtifact:
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        if len(content) == 0:
            raise ValueError("evidence content must not be empty")
        return cls(
            artifact_id=artifact_id,
            role=role,
            sha256=content_sha256(content),
            byte_length=len(content),
            media_type=media_type,
        )

    @classmethod
    def from_file(
        cls,
        *,
        artifact_id: str,
        role: EvidenceRole,
        path: str | Path,
        media_type: str,
    ) -> EvidenceArtifact:
        file_path = Path(path)
        digest = hashlib.sha256()
        byte_length = 0
        with file_path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                byte_length += len(chunk)
        return cls(
            artifact_id=artifact_id,
            role=role,
            sha256=digest.hexdigest(),
            byte_length=byte_length,
            media_type=media_type,
        )

    def to_record(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "role": self.role.value,
            "sha256": self.sha256,
            "byte_length": self.byte_length,
            "media_type": self.media_type,
        }

    def read_verified_bytes(self, path: str | Path) -> bytes:
        """Read one snapshot within the frozen length plus one detection byte.

        This bounds growth relative to the approved artifact, not its absolute
        size or the time spent opening/reading a local file. Chunking avoids
        allocating a buffer from an arbitrarily large declared integer.
        """

        remaining = self.byte_length + 1
        content = bytearray()
        # Do not prefetch beyond the requested budget or stat then reopen.
        with Path(path).open("rb", buffering=0) as handle:
            while remaining:
                requested = min(remaining, 64 * 1024)
                chunk = handle.read(requested)
                if type(chunk) is not bytes or len(chunk) > requested:
                    raise ValueError("Evidence stream returned an invalid bounded read")
                if not chunk:
                    break
                content.extend(chunk)
                remaining -= len(chunk)
        snapshot = bytes(content)
        if (
            len(snapshot) != self.byte_length
            or hashlib.sha256(snapshot).hexdigest() != self.sha256
        ):
            raise ValueError(
                f"Evidence content no longer matches frozen artifact {self.artifact_id}"
            )
        return snapshot


@dataclass(frozen=True)
class EvidenceManifest:
    """Frozen evidence, field list, and interpretation versions for one task."""

    manifest_id: str
    schema_id: str
    schema_version: str
    schema_sha256: str
    template_id: str
    template_version: str
    template_sha256: str
    expected_parameter_ids: tuple[str, ...]
    artifacts: tuple[EvidenceArtifact, ...]

    def __post_init__(self) -> None:
        for name in (
            "manifest_id",
            "schema_id",
            "schema_version",
            "template_id",
            "template_version",
        ):
            _require_identifier(name, getattr(self, name))
        for name in ("schema_sha256", "template_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
                raise ValueError(
                    f"{name} must contain 64 lowercase hexadecimal characters"
                )

        if not isinstance(self.expected_parameter_ids, tuple):
            raise TypeError("expected_parameter_ids must be a tuple")
        if not self.expected_parameter_ids:
            raise ValueError("expected_parameter_ids must not be empty")
        for parameter_id in self.expected_parameter_ids:
            _require_identifier("parameter_id", parameter_id)
        if len(set(self.expected_parameter_ids)) != len(
            self.expected_parameter_ids
        ):
            raise ValueError("expected_parameter_ids must not contain duplicates")

        if not isinstance(self.artifacts, tuple):
            raise TypeError("artifacts must be a tuple")
        if any(not isinstance(item, EvidenceArtifact) for item in self.artifacts):
            raise TypeError("artifacts must contain only EvidenceArtifact values")
        artifact_ids = [item.artifact_id for item in self.artifacts]
        if len(set(artifact_ids)) != len(artifact_ids):
            raise ValueError("artifact IDs must not contain duplicates")
        roles = [item.role for item in self.artifacts]
        required_roles = {EvidenceRole.LEFT_PHOTO, EvidenceRole.RIGHT_SCREENSHOT}
        if set(roles) != required_roles or len(roles) != len(required_roles):
            raise ValueError(
                "artifacts must contain exactly one LEFT_PHOTO and one RIGHT_SCREENSHOT"
            )

    def to_record(self) -> dict[str, object]:
        return {
            "manifest_version": 1,
            "manifest_id": self.manifest_id,
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "schema_sha256": self.schema_sha256,
            "template_id": self.template_id,
            "template_version": self.template_version,
            "template_sha256": self.template_sha256,
            "expected_parameter_ids": list(self.expected_parameter_ids),
            "artifacts": [item.to_record() for item in self.artifacts],
        }

    @property
    def manifest_hash(self) -> str:
        encoded = json.dumps(
            self.to_record(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def assert_artifact_content(self, *, artifact_id: str, content: bytes) -> None:
        """Fail if supplied bytes no longer match the frozen artifact."""

        _require_identifier("artifact_id", artifact_id)
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        artifact = next(
            (item for item in self.artifacts if item.artifact_id == artifact_id), None
        )
        if artifact is None:
            raise KeyError(f"Unknown artifact ID: {artifact_id}")
        actual_hash = hashlib.sha256(content).hexdigest()
        if len(content) != artifact.byte_length or actual_hash != artifact.sha256:
            raise ValueError(
                f"Evidence content no longer matches frozen artifact {artifact_id}"
            )
