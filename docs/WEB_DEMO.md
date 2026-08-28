# ParamGuard Vision 本地 Web v1

## 这个页面现在真正做到了什么

本地 Web PoC 已把面试场景中的主要顺序接成一条可操作流程：

```text
R1 独立逐字段人工判定
    -> 服务端检查完整性并原子锁定
    -> 锁后才可运行本地 OCR/确定性比较
    -> 服务端应用 INTERVIEW_TARGETED_RECHECK profile
    -> 定向异常人工复核 / QA referral / 等待最终人工确认
```

它没有实现、也不会假装实现“AI 自动通过”。所有公开 DTO、定向条目、人工决定和锁定快照的 `automatic_release_allowed` 都是 `false`。定向 reviewer 选择 `SAME` 也只是一条新的人工观察，`closes_exception` 仍为 `false`。

## 为什么 R1 锁前不会看到 AI 线索

R1 页面使用独立的静态模板 `src/paramguard/static/paramguard.html`。锁定前：

- `GET /api/state` 只返回 R1 字段、R1 自己的决定、manifest hash、R1 revision 和完成度；
- HTML/JSON 不含 task ID、OCR 结果、AI run、confidence、route、profile、routing context、source snapshot 或 targeted queue；
- 服务器不读图像字节来做 OCR/质量评估；只在用户请求证据图像时校验 manifest 中的字节哈希并返回图像；
- 猜测锁后端点只会得到简短、固定的 `STAGE_NOT_AVAILABLE`，不会得到运行状态、结果数量或引擎错误。

R1 每次写入只返回当前字段的 delta receipt，不回传全部字段列表。这使 1001 字段时的单次写响应保持 O(1) 大小。

## 定向队列是如何被创建的

`ParamGuardWebSession.run_assistive_check()` 只接受 `HUMAN_REVIEW_LOCKED` 的任务。本地 runner 完整返回后，Web composition root 还会先确认：

1. 真实 `ReviewTask` 已到 `AI_REVIEW_COMPLETE`；
2. 全量 AI assessment 与任务内冻结结果一致；
3. 传入 outcome 的字段顺序、确定性 route 与服务端重算一致；
4. 图像字节仍与 Evidence Manifest 一致，且用审批配置重算的质量 DTO 与 runner 返回值完全一致；
5. OCR DTO 必须两侧同时完整覆盖 schema，并绑定左/右源哈希、OCR config、engine version 和任务内冻结 raw values。质量门拒答或 OCR 系统错误时允许两侧都为空；“一侧缺失”或“结果用了 raw value 但 OCR DTO 不完整”会失败关闭。

只有这三步成功后，composition root 才用冻结 template 的 `critical` 标记、服务端验证过的图像质量以及精确覆盖 Schema 的事实创建 `LockedRoutingContext`，再交给仅能解析这一个对象的服务端 resolver。然后才创建真实 `TargetedReviewSession`。

这是一个内存信任边界。真实系统应从只写一次/只读数据库解析 context，而不是由 Web 进程现场创建。当前 PoC 没有把这一点冒充成持久化或密码学保证。

## 锁后 API

### 读取 inbox

```http
GET /api/exception-inbox
```

只在完整 AI run 和 `TargetedReviewSession` 都已创建后可用。响应分别列出：

- `items`：由 profile 重算后选中的定向复核项；
- `qa_referrals`：结构/系统问题和未定义真实 SOP 的关键字段规则；
- `no_exception_count`：辅助阶段没有路由异常的字段数，它不是“通过数”；
- 下一次 mutation 所需的 task/assignment/manifest/source-snapshot/revision 绑定。

### 记录一个定向结论

```http
POST /api/targeted-decision
Content-Type: application/json

{
  "task_id": "...",
  "assignment_id": "...",
  "evidence_manifest_hash": "...",
  "source_snapshot_sha256": "...",
  "parameter_id": "speed",
  "verdict": "SAME",
  "reason": "Synthetic evidence checked again character by character",
  "command_id": "targeted-decision-<unique-id>",
  "expected_revision": 0
}
```

`SAME` / `DIFFERENT` / `UNABLE_TO_JUDGE` 全部必须有非空 reason。幂等 `command_id` 的完全相同重试返回原结果；复用同一 command ID 但改动 payload 会冲突。响应是固定大小的单项 receipt，不重发全队列。

内存版 `TargetedReviewSession` 会保留 decision history 和幂等 command。为防止本地进程对同一字段无限改写而使内存无界增长，Web demo 对每个字段最多接受 16 个成功的定向决定 command，并设置与队列大小成比例的有限总预算。达到上限后新 command 得到 `429 TARGETED_MUTATION_LIMIT_REACHED`；已成功 command 的完全相同重试仍保持幂等。这是 PoC 资源边界，不是生产级配额策略。

### 锁定定向快照

```http
POST /api/targeted-lock
Content-Type: application/json

{
  "task_id": "...",
  "assignment_id": "...",
  "evidence_manifest_hash": "...",
  "source_snapshot_sha256": "...",
  "command_id": "targeted-lock-<unique-id>",
  "expected_revision": 1
}
```

队列没有全部决定时锁定会失败。如果定向队列为空，用户仍需显式锁定这个空快照；页面显示“等待最终人工确认”，不显示自动通过。

HTTP 客户端不能提交或选择 `profile_id`、`trusted_routing_signals`、`routing_context`、`routing_context_sha256` 或 resolver。这些额外键会被固定 JSON schema 拒绝。profile 和 routing context 的完整内容已纳入 `source_snapshot_sha256`。

## HTTP 适配层的安全边界

- 只允许显式 IPv4 loopback 监听，并严格验证 `Host`；
- 浏览器 mutation 验证 `Origin` 和 `Sec-Fetch-Site`，不发放 CORS 许可；
- JSON 必须有唯一 `Content-Type` 和 `Content-Length`，限制 32 KiB，禁止 chunked/ambiguous framing、重复 key 和 `NaN`/`Infinity`；
- 每个 endpoint 只接受精确键集合，严格拒绝 bool-as-int、容器冒充字符串和过长 reason；
- 默认最多 16 个并发 HTTP worker；慢请求占满后新连接获得不含 AI 状态的固定 `503 SERVER_BUSY`，而不是继续无界创建线程；
- `HEAD` / `TRACE` / `PUT` / 未知 method 不再使用 `BaseHTTPRequestHandler` 默认诊断页；统一回应不含 `Server` / `Date`，并保留 `no-store` 与安全 header；
- HTML 动态文本使用 HTML escaping，嵌入 JSON 额外转义 `<`/`>`/`&`，并使用每次响应的 CSP nonce；
- 所有页面、JSON 和图像响应都 `no-store`，且不回显堆栈、OCR 引擎错误或部分结果。

这些控制不是认证、授权、电子签名或管理员防篡改存储。特别是，HTTP 请求不含经验证的登录会话；Web 进程把预配置的 demo `Actor` 传给 domain 只是演示归属，不证明当前网络调用者就是该人。`request_actor_authenticated` 因此明确为 `false`。

## 如何本地运行

项目使用 Python。在仓库根目录执行：

```bash
PYTHONPATH=src python3 -m paramguard.webapp --port 8765
```

然后在浏览器打开 `http://127.0.0.1:8765/`。运行真实本地 OCR 前，环境需要有可用的 Tesseract 及相应语言数据。页面只生成和使用项目自带的合成案例；不应放入任何企业内部证据、SOP 或凭据。

专项测试：

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_webapp.py' -v
```

2026-08-25 本里程碑的最新本地专项运行结果为 **51/51 通过**，包括 R1 锁前泄漏、越序调用、runner 部分失败、伪造质量 DTO/路由/绑定、客户端自报 context/profile、幂等冲突、两线程 CAS、无界 revision 资源测试、慢连接并发上限、未知 HTTP method、XSS/JSON 重复 key、Host/Origin 和 1001 字段 O(1) mutation receipt。这是合成测试结果，不是真实工厂性能或合规结论。

## 仍然没有完成的边界

- 全字段盲 R2 尚未接入 Web；
- QA disposition 和最终人工决定尚未接入 Web；
- 追加式语义审计尚未记录 Web targeted mutation；
- 真实 IAM/RBAC、电子签名、持久化事务、唯一索引、outbox、崩溃恢复和部署验证都未实现；
- 默认 demo 由 R1 同一演示 actor 执行定向复核。这符合“面试描述没有证明必须换人”的谨慎边界，但绝不能称为独立二审或盲 R2；
- R1 首次页面和锁后结果/定向 inbox 仍会一次生成全量卡片/DTO。1001 字段的每次 mutation 已是 O(1) receipt，但首屏大 DOM、虚拟列表、分页/窗口化和断点恢复仍是真实的性能缺口。

本项目是独立个人演示，不代表企业内部系统或 SOP，也不是“AI 必须在人工之后运行”的通用法规证明。项目没有获得 GxP、21 CFR Part 11、EU Annex 11 或任何监管验证。
