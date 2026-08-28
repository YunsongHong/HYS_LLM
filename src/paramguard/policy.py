"""Small, deny-by-default authorization policy core.

The module is deliberately framework-neutral and side-effect free.  It accepts
only the domain enums and :class:`~paramguard.identity.Actor` used elsewhere in
ParamGuard; it never turns untrusted role or state strings into permissions.

This policy is one authorization layer.  Domain aggregates must continue to
enforce their own state transitions, evidence binding, optimistic concurrency,
and audit semantics.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import Enum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any

from .adjudication import AdjudicationState
from .blind_review import BlindReviewState
from .identity import Actor, PrincipalKind, Role
from .workflow import ReviewState


POLICY_VERSION = "paramguard-policy-v2"


class PolicyAction(str, Enum):
    """Closed allowlist of actions covered by this first policy core."""

    R1_VIEW_EVIDENCE = "R1_VIEW_EVIDENCE"
    R1_RECORD_DECISION = "R1_RECORD_DECISION"
    R1_LOCK_REVIEW = "R1_LOCK_REVIEW"
    AI_QUEUE_REVIEW = "AI_QUEUE_REVIEW"
    AI_START_REVIEW = "AI_START_REVIEW"
    AI_RECORD_ASSESSMENT = "AI_RECORD_ASSESSMENT"
    AI_COMPLETE_REVIEW = "AI_COMPLETE_REVIEW"
    R2_VIEW_EVIDENCE = "R2_VIEW_EVIDENCE"
    R2_RECORD_DECISION = "R2_RECORD_DECISION"
    R2_LOCK_REVIEW = "R2_LOCK_REVIEW"
    QA_RECORD_DISPOSITION = "QA_RECORD_DISPOSITION"
    QA_COMPLETE_DISPOSITION = "QA_COMPLETE_DISPOSITION"
    FINAL_APPROVE = "FINAL_APPROVE"
    FINAL_REJECT = "FINAL_REJECT"


class PolicyPhase(str, Enum):
    PRIMARY_REVIEW = "PRIMARY_REVIEW"
    AI_REVIEW = "AI_REVIEW"
    SECOND_REVIEW = "SECOND_REVIEW"
    QA_DISPOSITION = "QA_DISPOSITION"
    FINAL_DECISION = "FINAL_DECISION"


class PolicyEffect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class PolicyReasonCode(str, Enum):
    """Stable internal reasons for protected audit and server diagnostics.

    These codes must not be returned verbatim by a public endpoint because the
    distinction between, for example, a missing assignment and a state mismatch
    can itself become an authorization oracle.
    """

    ALLOWED = "ALLOWED"
    INVALID_REQUEST_TYPE = "INVALID_REQUEST_TYPE"
    INVALID_TRUSTED_CONTEXT_TYPE = "INVALID_TRUSTED_CONTEXT_TYPE"
    UNKNOWN_ACTION = "UNKNOWN_ACTION"
    UNKNOWN_PHASE = "UNKNOWN_PHASE"
    INVALID_STATE_TYPE = "INVALID_STATE_TYPE"
    PHASE_STATE_TYPE_MISMATCH = "PHASE_STATE_TYPE_MISMATCH"
    INVALID_ACTOR = "INVALID_ACTOR"
    TASK_BINDING_REQUIRED = "TASK_BINDING_REQUIRED"
    INVALID_TASK_BINDING = "INVALID_TASK_BINDING"
    TASK_BINDING_MISMATCH = "TASK_BINDING_MISMATCH"
    MANIFEST_BINDING_REQUIRED = "MANIFEST_BINDING_REQUIRED"
    INVALID_MANIFEST_BINDING = "INVALID_MANIFEST_BINDING"
    MANIFEST_BINDING_MISMATCH = "MANIFEST_BINDING_MISMATCH"
    INVALID_ASSIGNEE_BINDING = "INVALID_ASSIGNEE_BINDING"
    REVIEWER_SEPARATION_CONTEXT_REQUIRED = (
        "REVIEWER_SEPARATION_CONTEXT_REQUIRED"
    )
    REVIEWER_SEPARATION_REQUIRED = "REVIEWER_SEPARATION_REQUIRED"
    ACTION_PHASE_MISMATCH = "ACTION_PHASE_MISMATCH"
    ACTION_STATE_MISMATCH = "ACTION_STATE_MISMATCH"
    PRINCIPAL_KIND_NOT_ALLOWED = "PRINCIPAL_KIND_NOT_ALLOWED"
    FORBIDDEN_ROLE_COMBINATION = "FORBIDDEN_ROLE_COMBINATION"
    REQUIRED_ROLE_MISSING = "REQUIRED_ROLE_MISSING"
    ASSIGNEE_NOT_BOUND = "ASSIGNEE_NOT_BOUND"
    ACTOR_NOT_ASSIGNED = "ACTOR_NOT_ASSIGNED"
    POLICY_EVALUATION_ERROR = "POLICY_EVALUATION_ERROR"


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """Client-shaped part of one authorization question.

    This object deliberately has no actor, phase/state, bound-resource, or
    assignment fields.  Those values must be obtained from authenticated
    server context instead of accepting a request containing both a claim and
    its supposed proof.  Runtime validation lives in :func:`evaluate_policy`;
    type annotations are never treated as runtime proof.
    """

    action: PolicyAction
    task_id: str | None = field(repr=False)
    evidence_manifest_hash: str | None = field(repr=False)

    def to_record(self) -> dict[str, str | bool]:
        """Return a fresh, deliberately redacted diagnostic record.

        Raw task and manifest identifiers belong in the domain audit sink with
        its own access controls.  They are intentionally absent here so a
        convenient policy diagnostic cannot become an accidental identifier
        leak.
        """

        if type(self.action) is not PolicyAction:
            raise TypeError("action must be a PolicyAction")
        return {
            "action": self.action.value,
            "task_binding_supplied": self.task_id is not None,
            "manifest_binding_supplied": self.evidence_manifest_hash is not None,
        }


@dataclass(frozen=True, slots=True)
class TrustedPolicyContext:
    """Server-derived authorization attributes; never populate from request JSON.

    The type name documents the trust boundary but is not a signature or a
    sandbox.  The policy enforcement adapter remains responsible for deriving
    the actor from authentication and every other field from the same trusted,
    transactionally consistent task snapshot.
    """

    actor: Actor = field(repr=False)
    phase: PolicyPhase = field(repr=False)
    state: ReviewState | BlindReviewState | AdjudicationState = field(repr=False)
    bound_task_id: str | None = field(repr=False)
    bound_evidence_manifest_hash: str | None = field(repr=False)
    assigned_primary_reviewer_id: str | None = field(default=None, repr=False)
    assigned_ai_service_id: str | None = field(default=None, repr=False)
    assigned_second_reviewer_id: str | None = field(default=None, repr=False)
    assigned_qa_reviewer_id: str | None = field(default=None, repr=False)
    assigned_final_approver_id: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    effect: PolicyEffect
    reason_code: PolicyReasonCode = field(repr=False)
    policy_version: str
    policy_digest: str

    @property
    def allowed(self) -> bool:
        return self.effect is PolicyEffect.ALLOW

    def to_record(self) -> dict[str, str | bool]:
        """Return a fresh public-safe record without a detailed denial oracle."""

        return {
            "effect": self.effect.value,
            "allowed": self.allowed,
            "reason_code": "ALLOWED" if self.allowed else "NOT_AUTHORIZED",
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
        }

    def to_internal_record(self) -> dict[str, str | bool]:
        """Return a protected-audit record containing the internal reason."""

        record = self.to_record()
        record["reason_code"] = self.reason_code.value
        return record


@dataclass(frozen=True, slots=True)
class _Rule:
    phase: PolicyPhase
    states: tuple[ReviewState | BlindReviewState | AdjudicationState, ...]
    principal_kind: PrincipalKind
    required_role: Role
    assignment_attribute: str | None
    allowed_roles: frozenset[Role]


_HUMAN_OPERATION_ROLES = frozenset(
    {
        Role.PRIMARY_REVIEWER,
        Role.SECOND_REVIEWER,
        Role.QA_REVIEWER,
        Role.FINAL_APPROVER,
        Role.AUDITOR,
    }
)
_AI_OPERATION_ROLES = frozenset({Role.AI_WORKER})


def _human_rule(
    phase: PolicyPhase,
    states: tuple[ReviewState | BlindReviewState | AdjudicationState, ...],
    role: Role,
    assignment_attribute: str,
) -> _Rule:
    return _Rule(
        phase=phase,
        states=states,
        principal_kind=PrincipalKind.HUMAN,
        required_role=role,
        assignment_attribute=assignment_attribute,
        allowed_roles=_HUMAN_OPERATION_ROLES,
    )


def _ai_rule(
    states: tuple[ReviewState, ...],
) -> _Rule:
    return _Rule(
        phase=PolicyPhase.AI_REVIEW,
        states=states,
        principal_kind=PrincipalKind.AI_SERVICE,
        required_role=Role.AI_WORKER,
        assignment_attribute="assigned_ai_service_id",
        allowed_roles=_AI_OPERATION_ROLES,
    )


_PRIMARY_OPEN = (ReviewState.HUMAN_REVIEW_OPEN,)
_SECOND_OPEN = (BlindReviewState.OPEN,)
_QA_OPEN = (AdjudicationState.QA_DISPOSITION_OPEN,)
_FINAL_READY = (AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,)
_FINAL_REJECTABLE = (
    AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
    AdjudicationState.APPROVAL_BLOCKED,
    AdjudicationState.REWORK_REQUIRED,
)

_RULES = MappingProxyType(
    {
        PolicyAction.R1_VIEW_EVIDENCE: _human_rule(
            PolicyPhase.PRIMARY_REVIEW,
            _PRIMARY_OPEN,
            Role.PRIMARY_REVIEWER,
            "assigned_primary_reviewer_id",
        ),
        PolicyAction.R1_RECORD_DECISION: _human_rule(
            PolicyPhase.PRIMARY_REVIEW,
            _PRIMARY_OPEN,
            Role.PRIMARY_REVIEWER,
            "assigned_primary_reviewer_id",
        ),
        PolicyAction.R1_LOCK_REVIEW: _human_rule(
            PolicyPhase.PRIMARY_REVIEW,
            _PRIMARY_OPEN,
            Role.PRIMARY_REVIEWER,
            "assigned_primary_reviewer_id",
        ),
        PolicyAction.AI_QUEUE_REVIEW: _ai_rule(
            (ReviewState.HUMAN_REVIEW_LOCKED,)
        ),
        PolicyAction.AI_START_REVIEW: _ai_rule(
            (ReviewState.AI_REVIEW_QUEUED,)
        ),
        PolicyAction.AI_RECORD_ASSESSMENT: _ai_rule(
            (ReviewState.AI_REVIEW_RUNNING,)
        ),
        PolicyAction.AI_COMPLETE_REVIEW: _ai_rule(
            (ReviewState.AI_REVIEW_RUNNING,)
        ),
        PolicyAction.R2_VIEW_EVIDENCE: _human_rule(
            PolicyPhase.SECOND_REVIEW,
            _SECOND_OPEN,
            Role.SECOND_REVIEWER,
            "assigned_second_reviewer_id",
        ),
        PolicyAction.R2_RECORD_DECISION: _human_rule(
            PolicyPhase.SECOND_REVIEW,
            _SECOND_OPEN,
            Role.SECOND_REVIEWER,
            "assigned_second_reviewer_id",
        ),
        PolicyAction.R2_LOCK_REVIEW: _human_rule(
            PolicyPhase.SECOND_REVIEW,
            _SECOND_OPEN,
            Role.SECOND_REVIEWER,
            "assigned_second_reviewer_id",
        ),
        PolicyAction.QA_RECORD_DISPOSITION: _human_rule(
            PolicyPhase.QA_DISPOSITION,
            _QA_OPEN,
            Role.QA_REVIEWER,
            "assigned_qa_reviewer_id",
        ),
        PolicyAction.QA_COMPLETE_DISPOSITION: _human_rule(
            PolicyPhase.QA_DISPOSITION,
            _QA_OPEN,
            Role.QA_REVIEWER,
            "assigned_qa_reviewer_id",
        ),
        PolicyAction.FINAL_APPROVE: _human_rule(
            PolicyPhase.FINAL_DECISION,
            _FINAL_READY,
            Role.FINAL_APPROVER,
            "assigned_final_approver_id",
        ),
        PolicyAction.FINAL_REJECT: _human_rule(
            PolicyPhase.FINAL_DECISION,
            _FINAL_REJECTABLE,
            Role.FINAL_APPROVER,
            "assigned_final_approver_id",
        ),
    }
)

_PHASE_STATE_TYPES = MappingProxyType(
    {
        PolicyPhase.PRIMARY_REVIEW: ReviewState,
        PolicyPhase.AI_REVIEW: ReviewState,
        PolicyPhase.SECOND_REVIEW: BlindReviewState,
        PolicyPhase.QA_DISPOSITION: AdjudicationState,
        PolicyPhase.FINAL_DECISION: AdjudicationState,
    }
)

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ASSIGNMENT_ATTRIBUTES = (
    "assigned_primary_reviewer_id",
    "assigned_ai_service_id",
    "assigned_second_reviewer_id",
    "assigned_qa_reviewer_id",
    "assigned_final_approver_id",
)

_SECOND_REVIEW_ACTIONS = frozenset(
    {
        PolicyAction.R2_VIEW_EVIDENCE,
        PolicyAction.R2_RECORD_DECISION,
        PolicyAction.R2_LOCK_REVIEW,
    }
)

if frozenset(_RULES) != frozenset(PolicyAction):
    missing = sorted(action.value for action in set(PolicyAction) - set(_RULES))
    extra = sorted(action.value for action in set(_RULES) - set(PolicyAction))
    raise RuntimeError(
        f"policy rule coverage mismatch; missing={missing!r}, extra={extra!r}"
    )

_CONTEXT_ASSIGNMENT_ATTRIBUTES = frozenset(
    item.name
    for item in fields(TrustedPolicyContext)
    if item.name.startswith("assigned_")
)
if _CONTEXT_ASSIGNMENT_ATTRIBUTES != frozenset(_ASSIGNMENT_ATTRIBUTES):
    raise RuntimeError("trusted policy context assignment field coverage mismatch")
if any(
    rule.assignment_attribute not in _CONTEXT_ASSIGNMENT_ATTRIBUTES
    for rule in _RULES.values()
):
    raise RuntimeError("policy rule references an unknown assignment attribute")


def _canonical_policy_definition() -> dict[str, Any]:
    rules = []
    for action in sorted(_RULES, key=lambda value: value.value):
        rule = _RULES[action]
        rules.append(
            {
                "action": action.value,
                "phase": rule.phase.value,
                "states": sorted(state.value for state in rule.states),
                "principal_kind": rule.principal_kind.value,
                "required_role": rule.required_role.value,
                "assignment_attribute": rule.assignment_attribute,
                "allowed_roles": sorted(role.value for role in rule.allowed_roles),
            }
        )
    return {
        "policy_version": POLICY_VERSION,
        "default_effect": PolicyEffect.DENY.value,
        "enum_universe": {
            "actions": sorted(value.value for value in PolicyAction),
            "phases": sorted(value.value for value in PolicyPhase),
            "effects": sorted(value.value for value in PolicyEffect),
            "reasons": sorted(value.value for value in PolicyReasonCode),
            "principal_kinds": sorted(value.value for value in PrincipalKind),
            "roles": sorted(value.value for value in Role),
            "review_states": sorted(value.value for value in ReviewState),
            "blind_review_states": sorted(value.value for value in BlindReviewState),
            "adjudication_states": sorted(value.value for value in AdjudicationState),
        },
        "trust_boundary": {
            "request_fields": [item.name for item in fields(PolicyRequest)],
            "trusted_context_fields": [
                item.name for item in fields(TrustedPolicyContext)
            ],
            "client_must_not_supply_actor_state_or_assignments": True,
            "trusted_context_is_not_cryptographically_authenticated": True,
            "assignment_attributes": sorted(_ASSIGNMENT_ATTRIBUTES),
        },
        "validation": {
            "request_exact_type": True,
            "trusted_context_exact_type": True,
            "actor_exact_type": True,
            "enum_exact_types": True,
            "identifier_pattern": _IDENTIFIER_PATTERN.pattern,
            "manifest_pattern": _SHA256_PATTERN.pattern,
            "phase_state_types": {
                phase.value: state_type.__name__
                for phase, state_type in sorted(
                    _PHASE_STATE_TYPES.items(), key=lambda item: item[0].value
                )
            },
            "task_exact_match": True,
            "manifest_sha256_exact_match": True,
            "assignment_check_scope": "ACTION_REQUIRED_ASSIGNMENT_ONLY",
            "assignee_actor_id_exact_match": True,
            "human_roles_must_be_explicit_allowed_subset": True,
            "ai_roles_must_be_exact_allowed_subset": True,
            "second_review_separation_actions": sorted(
                action.value for action in _SECOND_REVIEW_ACTIONS
            ),
            "ordinary_exception_effect": PolicyEffect.DENY.value,
            "public_denial_reason": "NOT_AUTHORIZED",
        },
        "rules": rules,
    }


def _digest_policy_definition(definition: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            definition,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


POLICY_DIGEST = _digest_policy_definition(_canonical_policy_definition())


def _decision(effect: PolicyEffect, reason: PolicyReasonCode) -> PolicyDecision:
    return PolicyDecision(
        effect=effect,
        reason_code=reason,
        policy_version=POLICY_VERSION,
        policy_digest=POLICY_DIGEST,
    )


def _deny(reason: PolicyReasonCode) -> PolicyDecision:
    return _decision(PolicyEffect.DENY, reason)


def _is_identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER_PATTERN.fullmatch(value) is not None


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_PATTERN.fullmatch(value) is not None


def _valid_actor(actor: object) -> bool:
    if type(actor) is not Actor:
        return False
    if not _is_identifier(actor.actor_id):
        return False
    if type(actor.kind) is not PrincipalKind:
        return False
    if type(actor.roles) is not frozenset:
        return False
    return all(type(role) is Role for role in actor.roles)


def evaluate_policy(
    request: object,
    trusted_context: object = None,
) -> PolicyDecision:
    """Evaluate one request, converting every ordinary failure into DENY.

    Catching ``Exception`` here is intentional: an authorization subsystem
    failure must not become permission.  Process-control exceptions such as
    ``KeyboardInterrupt`` are not swallowed.
    """

    try:
        if type(request) is not PolicyRequest:
            return _deny(PolicyReasonCode.INVALID_REQUEST_TYPE)
        if type(trusted_context) is not TrustedPolicyContext:
            return _deny(PolicyReasonCode.INVALID_TRUSTED_CONTEXT_TYPE)
        return _evaluate_checked(request, trusted_context)
    except Exception:
        return _deny(PolicyReasonCode.POLICY_EVALUATION_ERROR)


def _evaluate_checked(
    request: PolicyRequest,
    trusted_context: TrustedPolicyContext,
) -> PolicyDecision:
    if type(request.action) is not PolicyAction:
        return _deny(PolicyReasonCode.UNKNOWN_ACTION)
    if type(trusted_context.phase) is not PolicyPhase:
        return _deny(PolicyReasonCode.UNKNOWN_PHASE)
    if type(trusted_context.state) not in (
        ReviewState,
        BlindReviewState,
        AdjudicationState,
    ):
        return _deny(PolicyReasonCode.INVALID_STATE_TYPE)
    if not _valid_actor(trusted_context.actor):
        return _deny(PolicyReasonCode.INVALID_ACTOR)

    expected_state_type = _PHASE_STATE_TYPES[trusted_context.phase]
    if type(trusted_context.state) is not expected_state_type:
        return _deny(PolicyReasonCode.PHASE_STATE_TYPE_MISMATCH)

    if request.task_id is None or trusted_context.bound_task_id is None:
        return _deny(PolicyReasonCode.TASK_BINDING_REQUIRED)
    if not _is_identifier(request.task_id) or not _is_identifier(
        trusted_context.bound_task_id
    ):
        return _deny(PolicyReasonCode.INVALID_TASK_BINDING)
    if request.task_id != trusted_context.bound_task_id:
        return _deny(PolicyReasonCode.TASK_BINDING_MISMATCH)

    if (
        request.evidence_manifest_hash is None
        or trusted_context.bound_evidence_manifest_hash is None
    ):
        return _deny(PolicyReasonCode.MANIFEST_BINDING_REQUIRED)
    if not _is_sha256(request.evidence_manifest_hash) or not _is_sha256(
        trusted_context.bound_evidence_manifest_hash
    ):
        return _deny(PolicyReasonCode.INVALID_MANIFEST_BINDING)
    if (
        request.evidence_manifest_hash
        != trusted_context.bound_evidence_manifest_hash
    ):
        return _deny(PolicyReasonCode.MANIFEST_BINDING_MISMATCH)

    rule = _RULES[request.action]
    if trusted_context.phase is not rule.phase:
        return _deny(PolicyReasonCode.ACTION_PHASE_MISMATCH)
    if trusted_context.state not in rule.states:
        return _deny(PolicyReasonCode.ACTION_STATE_MISMATCH)

    if trusted_context.actor.kind is not rule.principal_kind:
        return _deny(PolicyReasonCode.PRINCIPAL_KIND_NOT_ALLOWED)
    if not trusted_context.actor.roles.issubset(rule.allowed_roles):
        return _deny(PolicyReasonCode.FORBIDDEN_ROLE_COMBINATION)
    if rule.required_role not in trusted_context.actor.roles:
        return _deny(PolicyReasonCode.REQUIRED_ROLE_MISSING)

    if rule.assignment_attribute is not None:
        assignee_id = getattr(trusted_context, rule.assignment_attribute)
        if assignee_id is None:
            return _deny(PolicyReasonCode.ASSIGNEE_NOT_BOUND)
        if not _is_identifier(assignee_id):
            return _deny(PolicyReasonCode.INVALID_ASSIGNEE_BINDING)

        if request.action in _SECOND_REVIEW_ACTIONS:
            primary_id = trusted_context.assigned_primary_reviewer_id
            if primary_id is None:
                return _deny(
                    PolicyReasonCode.REVIEWER_SEPARATION_CONTEXT_REQUIRED
                )
            if not _is_identifier(primary_id):
                return _deny(PolicyReasonCode.INVALID_ASSIGNEE_BINDING)
            if primary_id == assignee_id:
                return _deny(PolicyReasonCode.REVIEWER_SEPARATION_REQUIRED)

        if trusted_context.actor.actor_id != assignee_id:
            return _deny(PolicyReasonCode.ACTOR_NOT_ASSIGNED)

    return _decision(PolicyEffect.ALLOW, PolicyReasonCode.ALLOWED)


__all__ = [
    "POLICY_DIGEST",
    "POLICY_VERSION",
    "PolicyAction",
    "PolicyDecision",
    "PolicyEffect",
    "PolicyPhase",
    "PolicyReasonCode",
    "PolicyRequest",
    "TrustedPolicyContext",
    "evaluate_policy",
]
