"""Table-driven, fail-closed tests for the local authorization policy core."""

from dataclasses import FrozenInstanceError, fields, replace
from copy import deepcopy
import json
import re
import unittest
from unittest.mock import patch

import paramguard.policy as policy_module
from paramguard.adjudication import AdjudicationState
from paramguard.blind_review import BlindReviewState
from paramguard.identity import Actor, PrincipalKind, Role
from paramguard.policy import (
    POLICY_DIGEST,
    POLICY_VERSION,
    PolicyAction,
    PolicyEffect,
    PolicyPhase,
    PolicyReasonCode,
    PolicyRequest,
    TrustedPolicyContext,
    evaluate_policy,
)
from paramguard.workflow import ReviewState


MANIFEST_HASH = "a" * 64
OTHER_MANIFEST_HASH = "b" * 64


def actor(
    actor_id: str,
    kind: PrincipalKind,
    *roles: Role,
) -> Actor:
    return Actor(actor_id=actor_id, kind=kind, roles=frozenset(roles))


PRIMARY = actor("reviewer-r1", PrincipalKind.HUMAN, Role.PRIMARY_REVIEWER)
SECOND = actor("reviewer-r2", PrincipalKind.HUMAN, Role.SECOND_REVIEWER)
QA = actor("reviewer-qa", PrincipalKind.HUMAN, Role.QA_REVIEWER)
FINAL = actor("reviewer-final", PrincipalKind.HUMAN, Role.FINAL_APPROVER)
AI = actor("ai-worker-1", PrincipalKind.AI_SERVICE, Role.AI_WORKER)


def request_for(
    action: PolicyAction = PolicyAction.R1_RECORD_DECISION,
) -> PolicyRequest:
    return PolicyRequest(
        action=action,
        task_id="task-001",
        evidence_manifest_hash=MANIFEST_HASH,
    )


def context_for(
    *,
    actor_value: Actor = PRIMARY,
    phase: PolicyPhase = PolicyPhase.PRIMARY_REVIEW,
    state=ReviewState.HUMAN_REVIEW_OPEN,
) -> TrustedPolicyContext:
    return TrustedPolicyContext(
        actor=actor_value,
        phase=phase,
        state=state,
        bound_task_id="task-001",
        bound_evidence_manifest_hash=MANIFEST_HASH,
        assigned_primary_reviewer_id=PRIMARY.actor_id,
        assigned_ai_service_id=AI.actor_id,
        assigned_second_reviewer_id=SECOND.actor_id,
        assigned_qa_reviewer_id=QA.actor_id,
        assigned_final_approver_id=FINAL.actor_id,
    )


def decision_for(
    action: PolicyAction = PolicyAction.R1_RECORD_DECISION,
    *,
    actor_value: Actor = PRIMARY,
    phase: PolicyPhase = PolicyPhase.PRIMARY_REVIEW,
    state=ReviewState.HUMAN_REVIEW_OPEN,
):
    return evaluate_policy(
        request_for(action),
        context_for(actor_value=actor_value, phase=phase, state=state),
    )


ALLOW_CASES = (
    (
        PolicyAction.R1_VIEW_EVIDENCE,
        PolicyPhase.PRIMARY_REVIEW,
        ReviewState.HUMAN_REVIEW_OPEN,
        PRIMARY,
    ),
    (
        PolicyAction.R1_RECORD_DECISION,
        PolicyPhase.PRIMARY_REVIEW,
        ReviewState.HUMAN_REVIEW_OPEN,
        PRIMARY,
    ),
    (
        PolicyAction.R1_LOCK_REVIEW,
        PolicyPhase.PRIMARY_REVIEW,
        ReviewState.HUMAN_REVIEW_OPEN,
        PRIMARY,
    ),
    (
        PolicyAction.AI_QUEUE_REVIEW,
        PolicyPhase.AI_REVIEW,
        ReviewState.HUMAN_REVIEW_LOCKED,
        AI,
    ),
    (
        PolicyAction.AI_START_REVIEW,
        PolicyPhase.AI_REVIEW,
        ReviewState.AI_REVIEW_QUEUED,
        AI,
    ),
    (
        PolicyAction.AI_RECORD_ASSESSMENT,
        PolicyPhase.AI_REVIEW,
        ReviewState.AI_REVIEW_RUNNING,
        AI,
    ),
    (
        PolicyAction.AI_COMPLETE_REVIEW,
        PolicyPhase.AI_REVIEW,
        ReviewState.AI_REVIEW_RUNNING,
        AI,
    ),
    (
        PolicyAction.R2_VIEW_EVIDENCE,
        PolicyPhase.SECOND_REVIEW,
        BlindReviewState.OPEN,
        SECOND,
    ),
    (
        PolicyAction.R2_RECORD_DECISION,
        PolicyPhase.SECOND_REVIEW,
        BlindReviewState.OPEN,
        SECOND,
    ),
    (
        PolicyAction.R2_LOCK_REVIEW,
        PolicyPhase.SECOND_REVIEW,
        BlindReviewState.OPEN,
        SECOND,
    ),
    (
        PolicyAction.QA_RECORD_DISPOSITION,
        PolicyPhase.QA_DISPOSITION,
        AdjudicationState.QA_DISPOSITION_OPEN,
        QA,
    ),
    (
        PolicyAction.QA_COMPLETE_DISPOSITION,
        PolicyPhase.QA_DISPOSITION,
        AdjudicationState.QA_DISPOSITION_OPEN,
        QA,
    ),
    (
        PolicyAction.FINAL_APPROVE,
        PolicyPhase.FINAL_DECISION,
        AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
        FINAL,
    ),
    (
        PolicyAction.FINAL_REJECT,
        PolicyPhase.FINAL_DECISION,
        AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
        FINAL,
    ),
    (
        PolicyAction.FINAL_REJECT,
        PolicyPhase.FINAL_DECISION,
        AdjudicationState.APPROVAL_BLOCKED,
        FINAL,
    ),
    (
        PolicyAction.FINAL_REJECT,
        PolicyPhase.FINAL_DECISION,
        AdjudicationState.REWORK_REQUIRED,
        FINAL,
    ),
)

ALLOWED_STATES = {
    PolicyAction.R1_VIEW_EVIDENCE: frozenset({ReviewState.HUMAN_REVIEW_OPEN}),
    PolicyAction.R1_RECORD_DECISION: frozenset({ReviewState.HUMAN_REVIEW_OPEN}),
    PolicyAction.R1_LOCK_REVIEW: frozenset({ReviewState.HUMAN_REVIEW_OPEN}),
    PolicyAction.AI_QUEUE_REVIEW: frozenset({ReviewState.HUMAN_REVIEW_LOCKED}),
    PolicyAction.AI_START_REVIEW: frozenset({ReviewState.AI_REVIEW_QUEUED}),
    PolicyAction.AI_RECORD_ASSESSMENT: frozenset({ReviewState.AI_REVIEW_RUNNING}),
    PolicyAction.AI_COMPLETE_REVIEW: frozenset({ReviewState.AI_REVIEW_RUNNING}),
    PolicyAction.R2_VIEW_EVIDENCE: frozenset({BlindReviewState.OPEN}),
    PolicyAction.R2_RECORD_DECISION: frozenset({BlindReviewState.OPEN}),
    PolicyAction.R2_LOCK_REVIEW: frozenset({BlindReviewState.OPEN}),
    PolicyAction.QA_RECORD_DISPOSITION: frozenset(
        {AdjudicationState.QA_DISPOSITION_OPEN}
    ),
    PolicyAction.QA_COMPLETE_DISPOSITION: frozenset(
        {AdjudicationState.QA_DISPOSITION_OPEN}
    ),
    PolicyAction.FINAL_APPROVE: frozenset(
        {AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION}
    ),
    PolicyAction.FINAL_REJECT: frozenset(
        {
            AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
            AdjudicationState.APPROVAL_BLOCKED,
            AdjudicationState.REWORK_REQUIRED,
        }
    ),
}

PHASE_SAMPLE_STATE = {
    PolicyPhase.PRIMARY_REVIEW: ReviewState.HUMAN_REVIEW_OPEN,
    PolicyPhase.AI_REVIEW: ReviewState.AI_REVIEW_RUNNING,
    PolicyPhase.SECOND_REVIEW: BlindReviewState.OPEN,
    PolicyPhase.QA_DISPOSITION: AdjudicationState.QA_DISPOSITION_OPEN,
    PolicyPhase.FINAL_DECISION: AdjudicationState.READY_FOR_FINAL_HUMAN_DECISION,
}

STATE_ENUM_FOR_PHASE = {
    PolicyPhase.PRIMARY_REVIEW: ReviewState,
    PolicyPhase.AI_REVIEW: ReviewState,
    PolicyPhase.SECOND_REVIEW: BlindReviewState,
    PolicyPhase.QA_DISPOSITION: AdjudicationState,
    PolicyPhase.FINAL_DECISION: AdjudicationState,
}


class PolicyMatrixTests(unittest.TestCase):
    def test_allowlist_has_an_explicit_allow_case_for_every_action(self) -> None:
        covered = {item[0] for item in ALLOW_CASES}
        self.assertEqual(covered, set(PolicyAction))
        for action, phase, state, actor_value in ALLOW_CASES:
            with self.subTest(action=action.value, state=state.value):
                decision = evaluate_policy(
                    request_for(action),
                    context_for(
                        actor_value=actor_value, phase=phase, state=state
                    ),
                )
                self.assertIs(decision.effect, PolicyEffect.ALLOW)
                self.assertIs(decision.reason_code, PolicyReasonCode.ALLOWED)
                self.assertTrue(decision.allowed)

    def test_every_action_is_denied_in_every_other_phase(self) -> None:
        canonical = {}
        for action, phase, state, actor_value in ALLOW_CASES:
            canonical.setdefault(action, (phase, state, actor_value))
        for action, (allowed_phase, _state, actor_value) in canonical.items():
            for phase, state in PHASE_SAMPLE_STATE.items():
                if phase is allowed_phase:
                    continue
                with self.subTest(action=action.value, phase=phase.value):
                    decision = evaluate_policy(
                        request_for(action),
                        context_for(
                            actor_value=actor_value, phase=phase, state=state
                        ),
                    )
                    self.assertIs(decision.effect, PolicyEffect.DENY)
                    self.assertIs(
                        decision.reason_code,
                        PolicyReasonCode.ACTION_PHASE_MISMATCH,
                    )

    def test_every_action_is_denied_in_other_states_of_its_phase(self) -> None:
        canonical = {}
        for action, phase, state, actor_value in ALLOW_CASES:
            canonical.setdefault(action, (phase, state, actor_value))
        for action, (phase, _state, actor_value) in canonical.items():
            for state in STATE_ENUM_FOR_PHASE[phase]:
                if state in ALLOWED_STATES[action]:
                    continue
                with self.subTest(action=action.value, state=state.value):
                    decision = evaluate_policy(
                        request_for(action),
                        context_for(
                            actor_value=actor_value, phase=phase, state=state
                        ),
                    )
                    self.assertIs(decision.effect, PolicyEffect.DENY)
                    self.assertIs(
                        decision.reason_code,
                        PolicyReasonCode.ACTION_STATE_MISMATCH,
                    )

    def test_unrelated_roles_cannot_authorize_any_action(self) -> None:
        canonical = {}
        for action, phase, state, actor_value in ALLOW_CASES:
            canonical.setdefault(action, (phase, state, actor_value))
        for action, (phase, state, allowed_actor) in canonical.items():
            for unrelated_role in Role:
                if unrelated_role in allowed_actor.roles:
                    continue
                kind = allowed_actor.kind
                wrong_actor = actor(
                    allowed_actor.actor_id,
                    kind,
                    unrelated_role,
                )
                with self.subTest(action=action.value, role=unrelated_role.value):
                    decision = evaluate_policy(
                        request_for(action),
                        context_for(
                            actor_value=wrong_actor, phase=phase, state=state
                        ),
                    )
                    self.assertIs(decision.effect, PolicyEffect.DENY)


class PolicyFailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = request_for()
        self.context = context_for()

    def assertDenied(
        self,
        request,
        context,
        reason: PolicyReasonCode,
    ) -> None:  # noqa: N802 - unittest naming convention
        decision = evaluate_policy(request, context)
        self.assertIs(decision.effect, PolicyEffect.DENY)
        self.assertFalse(decision.allowed)
        self.assertIs(decision.reason_code, reason)

    def test_request_and_trusted_context_must_be_exact_boundary_types(self) -> None:
        self.assertDenied(
            None,
            self.context,
            PolicyReasonCode.INVALID_REQUEST_TYPE,
        )
        self.assertDenied(
            self.request,
            None,
            PolicyReasonCode.INVALID_TRUSTED_CONTEXT_TYPE,
        )
        self.assertDenied(
            self.request,
            {"assigned_primary_reviewer_id": PRIMARY.actor_id},
            PolicyReasonCode.INVALID_TRUSTED_CONTEXT_TYPE,
        )

        class PolicyRequestSubclass(PolicyRequest):
            pass

        subclass_request = PolicyRequestSubclass(
            action=self.request.action,
            task_id=self.request.task_id,
            evidence_manifest_hash=self.request.evidence_manifest_hash,
        )
        self.assertDenied(
            subclass_request,
            self.context,
            PolicyReasonCode.INVALID_REQUEST_TYPE,
        )

        class TrustedContextSubclass(TrustedPolicyContext):
            pass

        subclass_context = TrustedContextSubclass(
            **{
                item.name: getattr(self.context, item.name)
                for item in fields(TrustedPolicyContext)
            }
        )
        self.assertDenied(
            self.request,
            subclass_context,
            PolicyReasonCode.INVALID_TRUSTED_CONTEXT_TYPE,
        )

    def test_action_phase_and_state_enum_or_primitive_confusion_denies(self) -> None:
        for request, context, reason in (
            (
                replace(self.request, action="R1_RECORD_DECISION"),
                self.context,
                PolicyReasonCode.UNKNOWN_ACTION,
            ),
            (
                replace(self.request, action=PolicyPhase.PRIMARY_REVIEW),
                self.context,
                PolicyReasonCode.UNKNOWN_ACTION,
            ),
            (
                replace(self.request, action=True),
                self.context,
                PolicyReasonCode.UNKNOWN_ACTION,
            ),
            (
                self.request,
                replace(self.context, phase="PRIMARY_REVIEW"),
                PolicyReasonCode.UNKNOWN_PHASE,
            ),
            (
                self.request,
                replace(self.context, phase=PolicyAction.R1_RECORD_DECISION),
                PolicyReasonCode.UNKNOWN_PHASE,
            ),
            (
                self.request,
                replace(self.context, state="HUMAN_REVIEW_OPEN"),
                PolicyReasonCode.INVALID_STATE_TYPE,
            ),
            (
                self.request,
                replace(self.context, state=True),
                PolicyReasonCode.INVALID_STATE_TYPE,
            ),
            (
                self.request,
                replace(self.context, state=BlindReviewState.OPEN),
                PolicyReasonCode.PHASE_STATE_TYPE_MISMATCH,
            ),
        ):
            with self.subTest(reason=reason.value):
                self.assertDenied(request, context, reason)

    def test_bad_actor_and_string_roles_are_never_inferred(self) -> None:
        self.assertDenied(
            self.request,
            replace(self.context, actor="reviewer-r1"),
            PolicyReasonCode.INVALID_ACTOR,
        )
        with self.assertRaises(ValueError):
            actor("", PrincipalKind.HUMAN, Role.PRIMARY_REVIEWER)
        with self.assertRaises(TypeError):
            Actor(
                actor_id="reviewer-r1",
                kind=PrincipalKind.HUMAN,
                roles=frozenset({"PRIMARY_REVIEWER"}),
            )
        with self.assertRaises(TypeError):
            Actor(
                actor_id="reviewer-r1",
                kind="HUMAN",
                roles=frozenset({Role.PRIMARY_REVIEWER}),
            )

    def test_task_binding_rejects_missing_invalid_cross_task_and_bool_values(self) -> None:
        class AlwaysEqualString(str):
            def __eq__(self, other):
                return True

        cases = (
            (
                replace(self.request, task_id=None),
                self.context,
                PolicyReasonCode.TASK_BINDING_REQUIRED,
            ),
            (
                self.request,
                replace(self.context, bound_task_id=None),
                PolicyReasonCode.TASK_BINDING_REQUIRED,
            ),
            (
                replace(self.request, task_id=""),
                self.context,
                PolicyReasonCode.INVALID_TASK_BINDING,
            ),
            (
                replace(self.request, task_id=True),
                self.context,
                PolicyReasonCode.INVALID_TASK_BINDING,
            ),
            (
                replace(self.request, task_id=AlwaysEqualString("task-002")),
                self.context,
                PolicyReasonCode.INVALID_TASK_BINDING,
            ),
            (
                replace(self.request, task_id="task-002"),
                self.context,
                PolicyReasonCode.TASK_BINDING_MISMATCH,
            ),
        )
        for request, context, reason in cases:
            with self.subTest(reason=reason.value):
                self.assertDenied(request, context, reason)

    def test_manifest_binding_is_mandatory_lowercase_sha256_and_exact(self) -> None:
        class AlwaysEqualString(str):
            def __eq__(self, other):
                return True

        cases = (
            (
                replace(self.request, evidence_manifest_hash=None),
                self.context,
                PolicyReasonCode.MANIFEST_BINDING_REQUIRED,
            ),
            (
                self.request,
                replace(self.context, bound_evidence_manifest_hash=None),
                PolicyReasonCode.MANIFEST_BINDING_REQUIRED,
            ),
            (
                replace(self.request, evidence_manifest_hash="not-a-hash"),
                self.context,
                PolicyReasonCode.INVALID_MANIFEST_BINDING,
            ),
            (
                replace(self.request, evidence_manifest_hash=MANIFEST_HASH.upper()),
                self.context,
                PolicyReasonCode.INVALID_MANIFEST_BINDING,
            ),
            (
                replace(self.request, evidence_manifest_hash=True),
                self.context,
                PolicyReasonCode.INVALID_MANIFEST_BINDING,
            ),
            (
                replace(
                    self.request,
                    evidence_manifest_hash=AlwaysEqualString(OTHER_MANIFEST_HASH),
                ),
                self.context,
                PolicyReasonCode.INVALID_MANIFEST_BINDING,
            ),
            (
                replace(self.request, evidence_manifest_hash=OTHER_MANIFEST_HASH),
                self.context,
                PolicyReasonCode.MANIFEST_BINDING_MISMATCH,
            ),
        )
        for request, context, reason in cases:
            with self.subTest(reason=reason.value):
                self.assertDenied(request, context, reason)

    def test_internal_policy_exception_fails_closed_without_error_text(self) -> None:
        with patch(
            "paramguard.policy._evaluate_checked",
            side_effect=RuntimeError("secret internal failure"),
        ):
            decision = evaluate_policy(self.request, self.context)
        self.assertIs(decision.effect, PolicyEffect.DENY)
        self.assertIs(
            decision.reason_code,
            PolicyReasonCode.POLICY_EVALUATION_ERROR,
        )
        self.assertNotIn("secret", json.dumps(decision.to_record()))


class PolicyAssignmentAndIdentityTests(unittest.TestCase):
    def assertDenied(
        self,
        request,
        context,
        reason: PolicyReasonCode,
    ) -> None:  # noqa: N802 - unittest naming convention
        decision = evaluate_policy(request, context)
        self.assertFalse(decision.allowed)
        self.assertIs(decision.reason_code, reason)

    def test_client_request_cannot_carry_any_assignment_or_trusted_field(self) -> None:
        self.assertEqual(
            {item.name for item in fields(PolicyRequest)},
            {"action", "task_id", "evidence_manifest_hash"},
        )
        with self.assertRaises(TypeError):
            PolicyRequest(
                action=PolicyAction.AI_START_REVIEW,
                task_id="task-001",
                evidence_manifest_hash=MANIFEST_HASH,
                assigned_ai_service_id="attacker-ai",
            )
        with self.assertRaises(TypeError):
            PolicyRequest(
                action=PolicyAction.R1_RECORD_DECISION,
                task_id="task-001",
                evidence_manifest_hash=MANIFEST_HASH,
                actor=PRIMARY,
                phase=PolicyPhase.PRIMARY_REVIEW,
                state=ReviewState.HUMAN_REVIEW_OPEN,
                bound_task_id="task-001",
                bound_evidence_manifest_hash=MANIFEST_HASH,
                assigned_primary_reviewer_id=PRIMARY.actor_id,
            )

    def test_ai_worker_cannot_cross_task_or_assignment(self) -> None:
        ai_request = request_for(PolicyAction.AI_START_REVIEW)
        task_one = context_for(
            actor_value=AI,
            phase=PolicyPhase.AI_REVIEW,
            state=ReviewState.AI_REVIEW_QUEUED,
        )
        self.assertTrue(evaluate_policy(ai_request, task_one).allowed)

        self.assertDenied(
            replace(ai_request, task_id="task-002"),
            task_one,
            PolicyReasonCode.TASK_BINDING_MISMATCH,
        )
        task_two = replace(
            task_one,
            bound_task_id="task-002",
            assigned_ai_service_id="ai-worker-2",
        )
        self.assertDenied(
            replace(ai_request, task_id="task-002"),
            task_two,
            PolicyReasonCode.ACTOR_NOT_ASSIGNED,
        )
        self.assertDenied(
            ai_request,
            replace(task_one, assigned_ai_service_id=None),
            PolicyReasonCode.ASSIGNEE_NOT_BOUND,
        )
        for invalid in ("", True, [], "x" * 129):
            with self.subTest(invalid=repr(invalid)):
                self.assertDenied(
                    ai_request,
                    replace(task_one, assigned_ai_service_id=invalid),
                    PolicyReasonCode.INVALID_ASSIGNEE_BINDING,
                )

    def test_every_ai_action_rechecks_the_exact_service_assignment(self) -> None:
        other_ai = actor(
            "ai-worker-2",
            PrincipalKind.AI_SERVICE,
            Role.AI_WORKER,
        )
        for action, state in (
            (PolicyAction.AI_QUEUE_REVIEW, ReviewState.HUMAN_REVIEW_LOCKED),
            (PolicyAction.AI_START_REVIEW, ReviewState.AI_REVIEW_QUEUED),
            (PolicyAction.AI_RECORD_ASSESSMENT, ReviewState.AI_REVIEW_RUNNING),
            (PolicyAction.AI_COMPLETE_REVIEW, ReviewState.AI_REVIEW_RUNNING),
        ):
            with self.subTest(action=action.value):
                trusted = context_for(
                    actor_value=other_ai,
                    phase=PolicyPhase.AI_REVIEW,
                    state=state,
                )
                self.assertDenied(
                    request_for(action),
                    trusted,
                    PolicyReasonCode.ACTOR_NOT_ASSIGNED,
                )

    def test_unrelated_assignment_fields_cannot_poison_an_action(self) -> None:
        poisoned_r1 = replace(
            context_for(),
            assigned_ai_service_id=[],
            assigned_second_reviewer_id=PRIMARY.actor_id,
            assigned_qa_reviewer_id=True,
            assigned_final_approver_id=object(),
        )
        self.assertTrue(evaluate_policy(request_for(), poisoned_r1).allowed)

        poisoned_ai = replace(
            context_for(
                actor_value=AI,
                phase=PolicyPhase.AI_REVIEW,
                state=ReviewState.AI_REVIEW_QUEUED,
            ),
            assigned_primary_reviewer_id=object(),
            assigned_second_reviewer_id=object(),
            assigned_qa_reviewer_id=object(),
            assigned_final_approver_id=object(),
        )
        self.assertTrue(
            evaluate_policy(
                request_for(PolicyAction.AI_START_REVIEW), poisoned_ai
            ).allowed
        )

    def test_r1_r2_separation_is_enforced_only_when_r2_is_exercised(self) -> None:
        r2_request = request_for(PolicyAction.R2_RECORD_DECISION)
        r2_context = context_for(
            actor_value=SECOND,
            phase=PolicyPhase.SECOND_REVIEW,
            state=BlindReviewState.OPEN,
        )
        self.assertTrue(evaluate_policy(r2_request, r2_context).allowed)
        self.assertDenied(
            r2_request,
            replace(r2_context, assigned_primary_reviewer_id=None),
            PolicyReasonCode.REVIEWER_SEPARATION_CONTEXT_REQUIRED,
        )
        self.assertDenied(
            r2_request,
            replace(r2_context, assigned_primary_reviewer_id=True),
            PolicyReasonCode.INVALID_ASSIGNEE_BINDING,
        )
        same_person = replace(
            r2_context,
            assigned_primary_reviewer_id=SECOND.actor_id,
        )
        self.assertDenied(
            r2_request,
            same_person,
            PolicyReasonCode.REVIEWER_SEPARATION_REQUIRED,
        )

        r1_context = replace(
            context_for(),
            assigned_second_reviewer_id=PRIMARY.actor_id,
        )
        self.assertTrue(evaluate_policy(request_for(), r1_context).allowed)

        for action, phase, state, actor_value in ALLOW_CASES:
            if action in {
                PolicyAction.R2_VIEW_EVIDENCE,
                PolicyAction.R2_RECORD_DECISION,
                PolicyAction.R2_LOCK_REVIEW,
            }:
                continue
            with self.subTest(unrelated_action=action.value):
                unrelated_context = replace(
                    context_for(
                        actor_value=actor_value,
                        phase=phase,
                        state=state,
                    ),
                    assigned_second_reviewer_id=PRIMARY.actor_id,
                )
                self.assertTrue(
                    evaluate_policy(
                        request_for(action), unrelated_context
                    ).allowed
                )

    def test_human_multi_role_is_explicit_but_admin_and_ai_worker_are_forbidden(self) -> None:
        multi_role_primary = actor(
            PRIMARY.actor_id,
            PrincipalKind.HUMAN,
            Role.PRIMARY_REVIEWER,
            Role.QA_REVIEWER,
            Role.AUDITOR,
        )
        self.assertTrue(
            evaluate_policy(
                request_for(), context_for(actor_value=multi_role_primary)
            ).allowed
        )

        for forbidden_role in (Role.ADMIN, Role.AI_WORKER):
            ambiguous = actor(
                PRIMARY.actor_id,
                PrincipalKind.HUMAN,
                Role.PRIMARY_REVIEWER,
                forbidden_role,
            )
            with self.subTest(role=forbidden_role.value):
                self.assertDenied(
                    request_for(),
                    context_for(actor_value=ambiguous),
                    PolicyReasonCode.FORBIDDEN_ROLE_COMBINATION,
                )

    def test_ai_actions_require_exact_ai_service_role_shape(self) -> None:
        ai_request = request_for(PolicyAction.AI_START_REVIEW)
        ai_context = context_for(
            actor_value=AI,
            phase=PolicyPhase.AI_REVIEW,
            state=ReviewState.AI_REVIEW_QUEUED,
        )
        human_ai_role = actor(AI.actor_id, PrincipalKind.HUMAN, Role.AI_WORKER)
        self.assertDenied(
            ai_request,
            replace(ai_context, actor=human_ai_role),
            PolicyReasonCode.PRINCIPAL_KIND_NOT_ALLOWED,
        )
        for extra_role in (Role.ADMIN, Role.PRIMARY_REVIEWER, Role.AUDITOR):
            ambiguous_ai = actor(
                AI.actor_id,
                PrincipalKind.AI_SERVICE,
                Role.AI_WORKER,
                extra_role,
            )
            with self.subTest(role=extra_role.value):
                self.assertDenied(
                    ai_request,
                    replace(ai_context, actor=ambiguous_ai),
                    PolicyReasonCode.FORBIDDEN_ROLE_COMBINATION,
                )

    def test_system_service_has_no_implicit_action(self) -> None:
        system_ai = actor(
            AI.actor_id,
            PrincipalKind.SYSTEM_SERVICE,
            Role.AI_WORKER,
        )
        self.assertDenied(
            request_for(PolicyAction.AI_QUEUE_REVIEW),
            context_for(
                actor_value=system_ai,
                phase=PolicyPhase.AI_REVIEW,
                state=ReviewState.HUMAN_REVIEW_LOCKED,
            ),
            PolicyReasonCode.PRINCIPAL_KIND_NOT_ALLOWED,
        )
        system_human = actor(
            PRIMARY.actor_id,
            PrincipalKind.SYSTEM_SERVICE,
            Role.PRIMARY_REVIEWER,
        )
        self.assertDenied(
            request_for(),
            context_for(actor_value=system_human),
            PolicyReasonCode.PRINCIPAL_KIND_NOT_ALLOWED,
        )

    def test_missing_required_role_or_wrong_assignee_denies(self) -> None:
        no_role = actor(PRIMARY.actor_id, PrincipalKind.HUMAN)
        self.assertDenied(
            request_for(),
            context_for(actor_value=no_role),
            PolicyReasonCode.REQUIRED_ROLE_MISSING,
        )
        self.assertDenied(
            request_for(),
            replace(context_for(), assigned_primary_reviewer_id=None),
            PolicyReasonCode.ASSIGNEE_NOT_BOUND,
        )
        self.assertDenied(
            request_for(),
            replace(
                context_for(), assigned_primary_reviewer_id="reviewer-other"
            ),
            PolicyReasonCode.ACTOR_NOT_ASSIGNED,
        )


class PolicyValueObjectTests(unittest.TestCase):
    def test_policy_version_digest_and_canonical_definition_cover_rules(self) -> None:
        self.assertEqual(POLICY_VERSION, "paramguard-policy-v2")
        self.assertRegex(POLICY_DIGEST, re.compile(r"^[0-9a-f]{64}$"))
        self.assertEqual(
            POLICY_DIGEST,
            "3744cecb1ecf5be09e775f56ff07cd1fa1c6b53297a97a69506a40e22251f488",
        )

        definition = policy_module._canonical_policy_definition()
        self.assertEqual(
            {rule["action"] for rule in definition["rules"]},
            {action.value for action in PolicyAction},
        )
        self.assertEqual(
            definition["enum_universe"]["actions"],
            sorted(action.value for action in PolicyAction),
        )
        self.assertEqual(
            definition["validation"]["assignment_check_scope"],
            "ACTION_REQUIRED_ASSIGNMENT_ONLY",
        )
        self.assertEqual(
            set(definition["trust_boundary"]["request_fields"]),
            {"action", "task_id", "evidence_manifest_hash"},
        )
        self.assertIn(
            "assigned_ai_service_id",
            definition["trust_boundary"]["trusted_context_fields"],
        )

        mutated_definition = deepcopy(definition)
        mutated_definition["rules"][0]["states"] = ["FORGED_STATE"]
        self.assertNotEqual(
            policy_module._digest_policy_definition(mutated_definition),
            POLICY_DIGEST,
        )

    def test_every_decision_carries_the_same_policy_identity(self) -> None:
        allow = evaluate_policy(request_for(), context_for())
        deny = evaluate_policy(
            replace(request_for(), action="unknown"), context_for()
        )
        self.assertEqual(allow.policy_version, POLICY_VERSION)
        self.assertEqual(deny.policy_version, POLICY_VERSION)
        self.assertEqual(allow.policy_digest, POLICY_DIGEST)
        self.assertEqual(deny.policy_digest, POLICY_DIGEST)

    def test_records_are_redacted_fresh_frozen_and_serializable(self) -> None:
        request = request_for()
        context = context_for()
        before = request.to_record()
        decision_one = evaluate_policy(request, context)
        decision_two = evaluate_policy(request, context)

        self.assertEqual(before, request.to_record())
        self.assertEqual(decision_one, decision_two)
        json.dumps(before, sort_keys=True)
        json.dumps(decision_one.to_record(), sort_keys=True)

        leaked_values = (
            "task-001",
            MANIFEST_HASH,
            PRIMARY.actor_id,
            AI.actor_id,
            SECOND.actor_id,
            QA.actor_id,
            FINAL.actor_id,
        )
        serialized = json.dumps(request.to_record(), sort_keys=True)
        rendered = repr(request) + repr(context)
        for value in leaked_values:
            with self.subTest(value=value):
                self.assertNotIn(value, serialized)
                self.assertNotIn(value, rendered)

        mutated_copy = request.to_record()
        mutated_copy["action"] = "tampered"
        self.assertEqual(request.to_record(), before)
        with self.assertRaises(FrozenInstanceError):
            request.task_id = "tampered"
        with self.assertRaises(FrozenInstanceError):
            context.bound_task_id = "tampered"
        with self.assertRaises(FrozenInstanceError):
            decision_one.effect = PolicyEffect.DENY

    def test_decision_record_has_only_fixed_non_secret_fields(self) -> None:
        decision = evaluate_policy(request_for(), context_for())
        record = decision.to_record()
        self.assertEqual(
            set(record),
            {
                "effect",
                "allowed",
                "reason_code",
                "policy_version",
                "policy_digest",
            },
        )
        self.assertNotIn("task-001", json.dumps(record))
        self.assertNotIn(PRIMARY.actor_id, json.dumps(record))

        denied = evaluate_policy(
            replace(request_for(), action="unknown"), context_for()
        )
        self.assertEqual(denied.to_record()["reason_code"], "NOT_AUTHORIZED")
        self.assertNotIn(
            denied.reason_code.value,
            json.dumps(denied.to_record(), sort_keys=True),
        )
        self.assertEqual(
            denied.to_internal_record()["reason_code"],
            PolicyReasonCode.UNKNOWN_ACTION.value,
        )
        mutated_internal = denied.to_internal_record()
        mutated_internal["reason_code"] = "tampered"
        self.assertEqual(
            denied.to_internal_record()["reason_code"],
            PolicyReasonCode.UNKNOWN_ACTION.value,
        )
        self.assertNotIn(PolicyReasonCode.UNKNOWN_ACTION.value, repr(denied))


if __name__ == "__main__":
    unittest.main()
