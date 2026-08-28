# 复核流程配置：定向异常复核与全量盲二审

## 先说结论

面试场景中不能改变的部分是：R1（第一审核员）必须先独立核验并锁定全部字段，AI 才能运行或显示。安全提速不来自跳过 R1，而来自两处：让 R1 的操作更顺畅、可恢复；R1 锁定后，只把确实出现差异、不确定或图像质量问题的字段组织成清晰的人工异常队列。

本项目把两种不同强度的后续控制明确分开。`INTERVIEW_TARGETED_RECHECK` 是默认定向复核档案的技术标识；`CONSERVATIVE_BLIND_R2` 是更保守的全量盲二审选项。它们都是本项目的设计，不代表任何企业的真实 SOP；全量盲二审也不是通用法规要求的必选项。

## 共同且不可配置的底线

两个 profile 都不改变以下规则：

1. R1 必须独立完成整个冻结 manifest，并由服务端一次性锁定；锁定前不得排队、运行或显示 AI，也不能通过排序、颜色、计数、错误或响应结构泄漏 AI 线索。
2. OCR/VLM 只提供观察；`SAME` 只能由确定性代码对保留的原始字符串逐字符比较。
3. AI 的 `SAME`、`NO_EXCEPTION_DETECTED` 或任何 profile 输出都不能自动批准、放行或关闭异常。
4. 缺失、重复、未知字段和 AI 系统错误进入 QA。
5. 这里的 profile 是锁后路由策略，不是对 R1 完整性的替代。

实现位于 `src/paramguard/review_policy.py`。纯函数 `decide_post_lock_next_step(signals, profile)` 复用经过验证的 `ReviewSignals` 和现有 route facts，输出固定 `ReviewNextStep`、原因列表、profile 版本和内容哈希。函数不读取或修改工作流，因此调用方仍必须用状态机证明 R1 已锁定。

## 两种 profile 到底有什么不同

| 情况 | `INTERVIEW_TARGETED_RECHECK` | `CONSERVATIVE_BLIND_R2` |
|---|---|---|
| 非关键字段，无差异、无不确定、质量可接受 | 等待最终人工流程确认 | 等待最终人工流程确认 |
| 差异、人机分歧、任一方无法判断、低质量、确定性比较非完全一致 | 仅对有关字段做锁后人工异常复核；此时可以显示 AI 上下文 | 触发另一名审核员对整个冻结 manifest 做盲二审；R2 锁定前看不到 R1/AI/路由 |
| 缺失、重复、未知字段或 AI 系统错误 | QA 结构/系统异常处理 | QA 结构/系统异常处理 |
| 仅有 `critical` 标记 | 暂停到 QA 确认应采用哪条经批准的关键字段规则 | 触发全 manifest 盲二审 |
| 自动放行 | 永远不允许 | 永远不允许 |

`INTERVIEW_TARGETED_RECHECK` 的“可看到 AI”只发生在 R1 完整锁定以后。它是有意设计的定向异常复核，不应被称作“独立盲二审”。两者解决不同问题：定向队列减少重复劳动；全量盲二审降低 AI 选择偏差和复核者被首审结果锚定的风险，但成本更高。

## 为什么关键字段不在这里猜

面试描述没有给出真实组织对关键字段的分类、二人核验范围或 QA 权限。项目不能据此猜“关键字段什么也不用加做”，也不能把“每个关键字段都让另一人重做整份清单”冒充成真实要求。

因此关键字段动作是 `ReviewPolicyProfile` 的必填、可哈希配置：

- 面试目标 profile 当前使用 `QA_CRITICAL_POLICY_CONFIRMATION`，表示在规则未知时暂停并让正式角色确认，既不静默放行，也不默认重做整份 manifest；
- 保守 profile 明确使用 `FULL_MANIFEST_BLIND_SECOND_REVIEW`；
- 如果真实、经批准的 SOP 要求只定向复核关键字段，必须创建新版本 profile，把动作显式改为 `TARGETED_POST_LOCK_HUMAN_EXCEPTION_RECHECK`，完成风险评估、批准和验证后才能启用。

profile 的 `policy_version` 和 `content_sha256` 必须与 task/audit 绑定。任何动作或版本变化都会改变哈希，旧 task 不能悄悄套用新规则。

## 1000 字段时间模型

下面是容量规划公式，不是实测性能，也不是对任何公司的工时断言。令：

- `N`：总字段数，例如 1000；
- `t_R1`：R1 每字段的平均观察和记录时间；
- `M`：锁后产生的异常字段数；
- `t_target`：每个异常的定向复核时间；
- `t_R2`：盲 R2 每字段平均时间；
- `Q`、`t_QA`：QA case 数及每 case 时间；
- `t_lock`、`t_AI`、`t_final`：锁定、AI 批处理和最终人工流程确认时间。

定向异常复核的总时间近似为：

```text
T_targeted = N * t_R1 + t_lock + t_AI + M * t_target + Q * t_QA + t_final
```

如果任一普通异常都触发全 manifest 盲二审，则近似为：

```text
T_blind = N * t_R1 + t_lock + t_AI + I_trigger * (N * t_R2) + Q * t_QA + t_final
```

其中 `I_trigger` 为 0 或 1。举一个只用于理解公式的假设例子：`N=1000`、`t_R1=5 秒`、`M=20`、`t_target=15 秒`、`t_R2=5 秒`。两种 profile 都必须先花约 83.3 分钟完成 R1；定向复核项约增加 5 分钟，而全量盲 R2 在被触发时约增加 83.3 分钟。锁定、AI、QA 和最终确认时间还要另加。真实数值必须用合成可用性测试和目标组织批准的数据重新测量，不能拿这个假设例子作简历性能结论。

这个模型也揭示了重要边界：当 `M` 接近 `N`、图像质量普遍差，或关键字段规则要求独立复核时，定向 profile 的节省会明显缩小；系统应该如实显示负担，不能为了好看的速度数字降低升级率。

## 不取消 R1 的安全提速点

- **键盘快捷键和固定焦点顺序**：减少鼠标移动，但不预填决定、不按 AI 结果排序，也不改变人必须观察每个字段的要求。
- **服务端增量保存与 CAS revision**：每次 R1 记录都可恢复，避免网络或浏览器故障让 1000 条全部重做；最终仍需完整性检查和原子锁定。
- **进度与缺失项定位**：只显示 R1 自己完成了多少、还缺哪些，不显示 AI 是否运行、AI 计数或风险颜色。
- **锁后异常聚焦**：AI 完成后生成明确的差异/不确定/低质量队列，复核者定位到原图 ROI、R1 记录和 AI 观察；机器仍不能关闭异常。
- **批量本地 OCR 与确定性比较**：减少人手抄写和查找成本，但失败、低置信和非完全一致均拒答并升级。
- **可观测的耗时分解**：分别记录 R1 操作、等待、AI、定向复核和 QA 时间，避免用一个总平均数掩盖错误或等待。

## 采用哪一个 profile

个人 PoC 可把 `INTERVIEW_TARGETED_RECHECK` 作为面试场景的默认概念，用合成数据验证“R1 完整锁定后才出现异常队列”。只有在组织 SOP、风险评估或 intended use 明确要求独立性和全量覆盖时，才选择 `CONSERVATIVE_BLIND_R2`。真实落地前应由 Process Owner、System Owner、QA/Validation 和 IT/OT Security 确认 profile、关键字段规则、身份隔离、电子签名和残余风险。

本文件不描述任何企业的真实流程，也不把 human-first 顺序或全量盲 R2 表述成普遍法规条文。它将默认定向复核与更保守的可选控制分开，便于实现、测试和讨论取舍。

## 当前集成边界

`review_policy.py` 已将两种 profile 冻结成带版本和内容哈希的纯函数投影。`targeted_review.py` 也已实现面试 profile 的领域层：它只从完成的 `ReviewTask` 和可信锁定 routing context 重算队列，并对逐项人工决定做 task/assignment/manifest/snapshot/revision/command 绑定。

不过，面试 profile 的可信 routing-context 持久化 adapter、Web、追加审计、QA 与 final 仍未全部接线。另一边，全字段盲 R2 已有 `blind_review.py`→`adjudication.py`→`audit_adapter.py` 的领域/审计集成测试，但同样没有 Web 或真实 IAM/数据库。这些区分防止用 policy 文档或单元测试冒充“两个流程都已上线”。
