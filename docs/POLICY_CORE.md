# ParamGuard deny-by-default 授权核心

## 1. 它解决什么问题

`src/paramguard/policy.py` 是一个小型、无框架、无网络、无副作用的授权决策核心。它只回答一个问题：

> 这个经过认证的 actor，在服务端当前阶段和状态下，对这个已绑定任务/证据，是否可以执行这个固定 action？

默认答案永远是 `DENY`。只有显式 allowlist 中的组合，并且同时通过主体、分配人、任务、Evidence Manifest 和必要的 R1/R2 分离检查，才返回 `ALLOW`。

这是工程 PoC 的一层防线，不是监管认证，也不代表任何公司的真实系统。

## 2. 独立对抗复审找到并修复了什么

v1 把 actor、状态、`bound_*` 和全部 `assigned_*` 放在同一个 `PolicyRequest` 里。如果边界层直接用客户端 JSON 构造整个对象，攻击者就能同时伪造“值”和“它应该等于的值”。类型注解不能证明这些属性来自可信存储。

v2 把边界拆成两个对象：

- `PolicyRequest`：只能包含客户端表达的 action、task ID 和 manifest hash；
- `TrustedPolicyContext`：包含经认证的 actor、服务端存储的 phase/state、已绑定资源和分配人。

这个拆分让错误接线更难发生，但 `TrustedPolicyContext` 的类名不是密码学证明。如果调用方仍然把客户端提供的 actor、state、`bound_*` 或 `assigned_*` 填进它，纯函数策略无法知道来源已被伪造，授权保证会失效。生产适配器必须从认证中间件和同一个事务一致的服务端任务快照构造它。

复审还修复了五类问题：

1. v1 对所有无关 assignment 先做检查，一个无关、错误的字段可以否决当前 action；v2 只检查当前规则所需的 assignment。
2. v1 的 R1/R2 同人检查会否决 AI、QA 或 final 等无关 action；v2 仅在实际执行 R2 action 时要求 R1 分配上下文存在并验证不同人。
3. v1 用 `isinstance(value, str)` 检查绑定字段，恶意 `str` 子类可重写相等比较；v2 对 request、context、actor、enum 和字符串都采用精确运行时类型检查。
4. v1 的 human 角色是“只禁止当前两个角色”，新增 enum 可能默认穿透；v2 改为显式 allowed-role 子集，未来未列出的角色会 fail closed。
5. v1 的请求记录和决策记录容易被当作普通日志，泄露内部 ID 或用细分拒绝原因形成 oracle；v2 的默认 `to_record()` 已脱敏，细分原因只由 `to_internal_record()` 提供给受保护的服务端审计。

## 3. 正确调用形状

```python
request = PolicyRequest(
    action=PolicyAction.AI_START_REVIEW,
    task_id=presented_task_id,
    evidence_manifest_hash=presented_manifest_hash,
)

# 下面的字段必须来自认证中间件和服务端可信存储，
# 不能从 request JSON 复制。
context = TrustedPolicyContext(
    actor=authenticated_actor,
    phase=stored_phase,
    state=stored_state,
    bound_task_id=stored_task_id,
    bound_evidence_manifest_hash=stored_manifest_hash,
    assigned_ai_service_id=stored_ai_service_id,
)

decision = evaluate_policy(request, context)
if not decision.allowed:
    public_body = decision.to_record()          # 只显示 NOT_AUTHORIZED
    protected_audit = decision.to_internal_record()  # 含固定内部原因
```

边界适配器还需要在同一个业务事务/CAS 中重新验证状态并执行操作。“先调策略，过一会再修改数据”会留下 TOCTOU 窗口，这不是这个纯函数能单独解决的。

## 4. 显式 allowlist

| 阶段 | 允许的 action | 必须的当前状态 | 必须的 principal / role | 必须匹配的服务端分配 |
|---|---|---|---|---|
| R1 | `R1_VIEW_EVIDENCE` | `HUMAN_REVIEW_OPEN` | human / `PRIMARY_REVIEWER` | R1 |
| R1 | `R1_RECORD_DECISION` | `HUMAN_REVIEW_OPEN` | human / `PRIMARY_REVIEWER` | R1 |
| R1 | `R1_LOCK_REVIEW` | `HUMAN_REVIEW_OPEN` | human / `PRIMARY_REVIEWER` | R1 |
| AI | `AI_QUEUE_REVIEW` | `HUMAN_REVIEW_LOCKED` | AI service / `AI_WORKER` | 指定 AI service |
| AI | `AI_START_REVIEW` | `AI_REVIEW_QUEUED` | AI service / `AI_WORKER` | 指定 AI service |
| AI | `AI_RECORD_ASSESSMENT` | `AI_REVIEW_RUNNING` | AI service / `AI_WORKER` | 指定 AI service |
| AI | `AI_COMPLETE_REVIEW` | `AI_REVIEW_RUNNING` | AI service / `AI_WORKER` | 指定 AI service |
| R2 | `R2_VIEW_EVIDENCE` | `OPEN` | human / `SECOND_REVIEWER` | R2，且与 R1 不同人 |
| R2 | `R2_RECORD_DECISION` | `OPEN` | human / `SECOND_REVIEWER` | R2，且与 R1 不同人 |
| R2 | `R2_LOCK_REVIEW` | `OPEN` | human / `SECOND_REVIEWER` | R2，且与 R1 不同人 |
| QA | `QA_RECORD_DISPOSITION` | `QA_DISPOSITION_OPEN` | human / `QA_REVIEWER` | QA |
| QA | `QA_COMPLETE_DISPOSITION` | `QA_DISPOSITION_OPEN` | human / `QA_REVIEWER` | QA |
| 最终人工 | `FINAL_APPROVE` | `READY_FOR_FINAL_HUMAN_DECISION` | human / `FINAL_APPROVER` | final |
| 最终人工 | `FINAL_REJECT` | `READY_FOR_FINAL_HUMAN_DECISION` / `APPROVAL_BLOCKED` / `REWORK_REQUIRED` | human / `FINAL_APPROVER` | final |

这个表不允许 AI 在 `HUMAN_REVIEW_OPEN` 期间排队、启动或记录结果，也没有任何“AI 批准” action。`SYSTEM_SERVICE` 在 v2 没有任何隐式权限；如果未来需要系统编排器排队，应先新增独立 action、系统服务 assignment、威胁模型和测试，不能借用当前规则。

## 5. 角色与职责分离

- human 可以同时持有多个显式人工职责角色，但当前 action 所需角色和当前任务分配仍必须同时匹配。
- human 只要混入 `ADMIN` 或 `AI_WORKER` 就不能用该 actor 形状执行当前人工 action。这是 PoC 的保守“主动角色”设计，不是对真实组织权限的推断。
- AI action 只接受 `AI_SERVICE` + 单一允许角色 `AI_WORKER`，并且 actor ID 必须精确等于该任务的 `assigned_ai_service_id`。
- R1/R2 分离在 R2 action 上强制。不对 AI/QA/final 检查无关 R2 字段，是为了支持“只对 AI 标记异常做针对性复核”与“完整盲 R2”两种流程配置。是否要求完整 R2 应由冻结流程配置和领域状态机决定。

## 6. 策略 digest

v2 的固定标识为：

```text
policy_version = paramguard-policy-v2
policy_digest  = 3744cecb1ecf5be09e775f56ff07cd1fa1c6b53297a97a69506a40e22251f488
```

digest 的规范 JSON 现在覆盖：

- action、phase、effect、reason、principal、role 和三组领域 state 的完整 enum 集合；
- `PolicyRequest` 与 `TrustedPolicyContext` 字段边界；
- 精确类型、ID/hash 格式、phase-state 类型映射、task/manifest 绑定、assignment 作用域、R1/R2 分离作用域、公开拒绝脱敏和异常默认拒绝；
- 每个 action 的 phase、states、principal kind、required role、allowed roles 和 assignment attribute。

模块导入时还检查：每个 `PolicyAction` 恰好有一条规则，每个规则引用的 assignment 确实存在。新增 action 但忘记规则会使服务启动失败，不会默认获权。

digest 只是“规范策略内容的可重现标识”，不是源码/二进制完整性证明、数字签名、部署证明或防篡改审计。

## 7. 边界和剩余风险

当前成果是可审查的 **policy core**，不是完成的生产授权系统：

- 尚未接入所有 Web/API 入口，不能声称当前 UI 的每个路由都受它保护；
- 不负责认证、session、mTLS/服务身份、生产 IAM、OPA、数据库 row-level policy 或电子签名；
- `TrustedPolicyContext` 没有自带来源证明；服务端适配器错误信任客户端时，本核心不能挽救；
- 不替代 `ReviewTask`、`BlindReviewSession` 和 `AdjudicationCase` 内部的状态迁移、CAS、证据绑定和追加式审计校验；
- 不包含生产组织、班次、委派、紧急访问、租户、属性库供应或撤权同步；
- 内部 `reason_code` 仍可由服务端代码读取；公开端点必须使用统一拒绝响应，不得把 `to_internal_record()` 返回客户端；
- v2 只覆盖表中 action。新 endpoint 必须先新增 action、威胁分析和测试，不得用自由字符串绕过 allowlist。

## 8. 验证

专项测试：

```bash
PYTHONPATH=src python3 -m unittest tests.test_policy -v
```

`tests/test_policy.py` 使用表驱动和对抗样例覆盖：每个 action 的 allow 组合、所有其他 phase/state、action/phase/state enum 混用、bool 和恶意 `str` 子类、跨任务/跨 AI assignment、客户端同时伪造上下文的 API 形状、无关 assignment 污染、R1/R2 分离作用域、人类多角色、admin/AI worker 混合、system service、异常 fail closed、digest 规则覆盖、冻结 value object 和默认记录脱敏。

## 9. 设计参考（不是合规背书）

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)：默认拒绝、每次请求重新授权、安全失败和授权测试。
- [OWASP Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)：安全相关属性应在服务端重新导出，不应信任请求中的隐藏或回传字段。
- [NIST SP 800-162, Guide to Attribute Based Access Control](https://csrc.nist.gov/pubs/sp/800/162/upd2/final)：用 subject、object、operation 和 environment 属性表达决策的概念参考。

这些资料只影响工程设计，不代表本 PoC 已实现 OWASP/NIST 完整体系，也不构成 GxP、21 CFR Part 11 或 EU Annex 11 验证。
