# 定向异常人工复核（Targeted Recheck）

## 这一层解决什么

`src/paramguard/targeted_review.py` 实现了与面试题设更接近的领域层：

1. R1 先独立完成全部字段，并在服务端锁定；
2. AI/OCR 之后才运行，且所有结果都已完成；
3. 领域层从真实 `ReviewTask` 重建人/AI/确定性比较事实，从受信的锁定上下文解析器取得关键性、图像质量和结构问题；
4. 领域层自己重算 route 和 process profile，只把需要定向复核的字段放入人工队列；
5. 结构问题、AI 系统错误和尚未由真实 SOP 定义处理方式的关键字段，保守地交给 QA；
6. 定向复核锁定后仍不能自动批准、关闭异常或放行。

这不是 `blind_review.py` 里的“全字段独立盲二审”。定向复核者知道哪些字段是锁后筛出的异常，因此不应被包装成 blind review。

## 不可跨过的源任务门

`TargetedReviewSession` 只接受类型严格为 `ReviewTask` 且状态为 `AI_REVIEW_COMPLETE` 的源任务，并且只接受内容与版本完全一致的 `INTERVIEW_TARGETED_RECHECK` profile。创建时会在 `ReviewTask` 的进程内锁下原子读取，并重新检查：

- workflow 必须是 `STRICT_SEQUENTIAL`；
- task、Evidence Manifest 和全量 Schema 必须一致；
- R1 决定必须全量、已锁定，且绑定同一 reviewer 和 manifest；
- AI run 必须在 R1 lock 之后排队和开始；
- AI assessment 必须全量、绑定同一 run、处理规格和 manifest；
- AI verdict 必须与保留的原始字符串和 `compare_values()` 重算结果一致。

读取到的 manifest、pipeline spec、R1 决定、AI run 和 AI assessments 都做深拷贝，不继续引用源任务里的对象。解析锁定 routing context 后还会再读一次源任务；如果两次快照不同，则 fail closed。因此，在 R1 未锁定、AI 未完成、快照被篡改或解析器 I/O 期间发生 TOCTOU 时，定向队列都不会被创建。

这个保证针对所有通过 `ReviewTask` API 并遵守其锁的同进程修改。如果攻击者已经可以在同一 Python 进程中任意修改私有字段、绕过锁或使用 `object.__setattr__`，这属于主机/进程已失陷，内存领域对象无法提供密码学防护。

## routing context 不再由请求自报

旧版创建 API 同时接受 `trusted_routing_signals` 和一个请求方给出的 SHA-256。这不足以证明 `is_critical`、`image_quality` 和 `field_issues` 来自可信源：调用方可以把值和哈希一起伪造，从而清除 QA referral。

现在创建 API 不再接受自由的 signals 或 context hash，而是调用 `TrustedRoutingContextResolver.resolve_locked_context()`。解析器返回 `LockedRoutingContext`，其内容包括：

- context ID 和版本；
- task ID 和 Evidence Manifest hash；
- 带时区的 `locked_at`；
- 与冻结 Schema 完全覆盖且顺序一致的不可变 tuple；
- 每个字段严格类型的 `is_critical`、`image_quality` 和 `field_issues`；
- 由全部内容重算的 `content_sha256`。

`LockedParameterRoutingContext` 故意没有 `human_verdict`、`ai_verdict` 或 `comparison_kind` 字段；这三类事实只能从源 `ReviewTask` 重建。模块会拒绝缺失、重复、未知字段、`bool` 型混淆、字符串冒充 enum、list 冒充 tuple，并会拷贝解析结果。

这是一个明确的信任边界，不是身份认证。组装 Web/API 时，resolver 必须由应用 composition root 注入，并从只读/写一次的受信存储按 task+manifest+version 解析；绝不能让 HTTP 请求选择 resolver、提供 context 对象或同时提供其“期望哈希”。本 PoC 尚未实现这个持久化适配器。

## 队列不由调用方指定

创建 API 没有 `targeted_parameter_ids`、`routes`、`reasons`、`trusted_routing_signals` 或 `routing_context_sha256` 入参。模块会：

- 用冻结的 R1/AI 快照生成 `human_verdict`、`ai_verdict` 和 `comparison_kind`；
- 用 `route_parameter()` 重算基础 route；
- 用 `decide_post_lock_next_step()` 和冻结 profile 重算后续步骤；
- 按 manifest 顺序生成定向队列、QA referral 和无异常字段集合。

| 重算结果 | 领域层处理 |
| --- | --- |
| `TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK` | 进入定向人工队列 |
| `QA_STRUCTURAL_OR_SYSTEM_REVIEW` | 不进入定向队列，保留 QA referral |
| `QA_CRITICAL_POLICY_CONFIRMATION` | 不猜测真实 SOP，保留 QA policy referral |
| `WAIT_FINAL_HUMAN_PROCESS_CONFIRMATION` | 不表示批准，仍等最终人工流程决定 |

`AI SAME` 不能覆盖 `R1 DIFFERENT`。这种组合会产生 `HUMAN_AI_DISAGREEMENT` 和 `HUMAN_DETECTED_DIFFERENCE`，因而进入定向复核；后续人工结论是新记录，不会改写 R1。

## 哈希覆盖什么

`source_snapshot_sha256` 的 v2 记录覆盖：

- task、assignment 以及被分配 actor 的 ID/kind/全部角色；
- 完整 Evidence Manifest 内容和 hash；
- 完整 approved pipeline spec 内容和 spec hash；
- R1 reviewer、lock 时间和每个字段的 verdict/reason/time/manifest 绑定；
- AI run 的 ID、引擎/版本/规格、queue/start 时间；
- 每个 AI assessment 的原始左右字符串、可靠性、确定性比较全量内容、原因和所有 run/spec 绑定；
- 完整 locked routing context，包括 criticality、quality 和 field issues；
- 重建的 `ReviewSignals`、route 结果、policy 内容和每字段 policy decision。

这防止“哈希存了，但关键原始事实没在哈希里”的假绑定。

## 身份、绑定与并发

定向任务必须分配给 `HUMAN`，且其角色只能是 `PRIMARY_REVIEWER` 和/或 `SECOND_REVIEWER`。任何混入 `ADMIN`、`AI_WORKER`、`QA_REVIEWER`、`FINAL_APPROVER` 或 `AUDITOR` 的多角色 actor，以及 `AI_SERVICE`/`SYSTEM_SERVICE` 都被拒绝。执行命令时的 actor 必须与分配时的 ID、kind 和角色集合全部一致，不只比较 actor ID。

面试描述没有证明定向复核者必须与 R1 不同，所以这个 profile **没有擅自添加身份分离规则**。R1 本人在拥有合法 reviewer 角色时可以被分配定向复核。如果真实 SOP 要求独立人员，应在经审批的 profile/IAM 层显式配置；如果要全量盲二审，应使用另一流程。

每次 `record_decision()` 和 `lock()` 都必须由客户端回传并经服务端核对 task ID、assignment ID、manifest hash、source snapshot hash、CAS revision 和 command ID。`RLock` 使同进程修改原子化；CAS 使同一 revision 的并发客户端只有一个能成功；同一 command ID 的完全相同重试返回原结果，而 payload 改变会报冲突。

## 定向 `SAME` 也必须解释

定向队列中的每个字段都已有一个锁后异常原因。因此本项目选择更可审计的规则：`SAME`、`DIFFERENT` 和 `UNABLE_TO_JUDGE` 三种定向结论都必须有简短的非空原因。这是 ParamGuard Vision 的保守设计选择，不是声称某条外部法规的通用要求。

定向 reviewer 判为 `SAME` 只是一条新的人工观察：

- `TargetedReviewDecision.closes_exception` 恒为 `False`；
- 不改写 R1 或 AI 快照；
- 不表示 QA/final 已同意关闭异常；
- `LockedTargetedReviewSubmission.final_human_confirmation_required` 恒为 `True`。

定向结论为 `DIFFERENT` 或 `UNABLE_TO_JUDGE` 时，`requires_qa` 为 `True`。已存在的 QA referral 也会使该值为 `True`。

## 锁定输出不是放行决定

`LockedTargetedReviewSubmission` 保留 routing context ID/版本/hash、source snapshot hash、profile、冻结的全量 expected parameter IDs、全部 targeted items、按队列顺序的全部人工决定、全部 QA referrals、无异常列表和 v2 内容哈希。三个分区必须互斥且精确覆盖 expected IDs，各自保持 Schema 顺序；decisions 必须按冻结顺序完全覆盖 targeted items。

`validate_locked_targeted_submission()` 会重算内容哈希，验证所有类型、身份/证据绑定、分区互斥性、完整决定集和时间顺序，并要求调用方提供受信的 expected source/submission hashes。下游必须从追加式审计或事务存储取得这两个 expected hash，不能从同一个请求接收“输出+期望哈希”。SHA-256 不是签名、身份认证或电子签名。

即使零异常，也只能得到一个空的已锁定复核快照，不会得到“自动通过”。该 aggregate 没有 `approve()` 方法，所有输出的 `automatic_release_allowed` 都恒为 `False`。

## 已做的对抗验证

`tests/test_targeted_review.py` 现有 35 个专项测试，覆盖：

- R1/AI 完成前创建、被篡改的 AI 结果、非目标 profile 和 resolver I/O 期间 TOCTOU；
- resolver 的 task/manifest 绑定、返回类型、缺失/重复/未知字段；
- 清除 critical/LOW/field issue 的可变对象攻击、`bool`/字符串/list 类型混淆；
- source hash 对 R1、AI raw/comparison、run ID、pipeline spec、criticality、quality 和 field issue 的变化感知；
- AI service、system service、admin、AI worker、QA/final/auditor 毒性多角色、错误 assignee 和同 ID 角色替换；
- 过期 task/assignment/manifest/snapshot/revision，重试幂等、command 冲突和两线程竞争；
- 所有定向 verdict 的 reason 要求、只读 Mapping/不可变 tuple 输出、锁后不可改；
- 漏掉 targeted decision、QA referral 或 no-exception partition，伪造 decision/上下文/提交 hash；
- AI SAME/R1 DIFFERENT、QA-only、零异常、定向 SAME 不关闭异常、DIFFERENT/UNABLE 升级；
- 1001 个合成字段的完整分类，没有截断异常集合。

专项命令：

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_targeted_review.py' -v
```

## 诚实的边界和尚未完成项

这一层现在是**内存领域 PoC**，尚未：

- 接入 Web UI/API；
- 接入可信的 routing-context 持久化解析器；
- 接入持久化事务、唯一索引、事务 outbox 或崩溃恢复；
- 接入追加式语义审计，因此下游尚无受信 expected source/submission hash 存储；
- 接入 QA 处理和最终人工 adjudication；
- 接入真实 IAM/RBAC，当前 `Actor` 仍是调用方交付的域对象；
- 实现数字签名、电子签名或防管理员篡改存储；
- 定义真实企业的 critical-parameter 处理规则。未知规则目前 fail closed 到 QA policy confirmation。

本模块属于仅使用合成数据验证的独立个人学习项目，不代表企业内部流程或 SOP。“AI 必须在人之后”是本项目的设计约束，不是普遍法规；项目没有获得 GxP、21 CFR Part 11、EU Annex 11 或任何监管验证。
