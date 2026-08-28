"""Small, framework-neutral actor model for domain authorization tests."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re


class PrincipalKind(str, Enum):
    HUMAN = "HUMAN"
    AI_SERVICE = "AI_SERVICE"
    SYSTEM_SERVICE = "SYSTEM_SERVICE"


class Role(str, Enum):
    PRIMARY_REVIEWER = "PRIMARY_REVIEWER"
    SECOND_REVIEWER = "SECOND_REVIEWER"
    QA_REVIEWER = "QA_REVIEWER"
    FINAL_APPROVER = "FINAL_APPROVER"
    ADMIN = "ADMIN"
    AI_WORKER = "AI_WORKER"
    AUDITOR = "AUDITOR"


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass(frozen=True, slots=True)
class Actor:
    actor_id: str
    kind: PrincipalKind
    roles: frozenset[Role]

    def __post_init__(self) -> None:
        if not isinstance(self.actor_id, str) or _IDENTIFIER_PATTERN.fullmatch(
            self.actor_id
        ) is None:
            raise ValueError("actor_id must be a safe 1-128 character identifier")
        if not isinstance(self.kind, PrincipalKind):
            raise TypeError("kind must be a PrincipalKind")
        if not isinstance(self.roles, frozenset):
            raise TypeError("roles must be a frozenset")
        if any(not isinstance(role, Role) for role in self.roles):
            raise TypeError("roles must contain only Role values")

    def has_role(self, role: Role) -> bool:
        return role in self.roles
