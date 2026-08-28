# ParamGuard Vision 工程验证计划

| 字段 | 值 |
|---|---|
| 文档状态 | Draft；个人 PoC 的测试/证据计划，非组织级 CSV/CSA 或 GxP 验证方案 |
| 版本 | 0.1 |
| 日期 | 2026-08-25 |
| 需求基线 | [HUMAN_FIRST_URS.md](./HUMAN_FIRST_URS.md) v0.1 |
| 范围基线 | [PROJECT_SCOPE.md](./PROJECT_SCOPE.md) v0.1 |

## 1. 验证目的和声明边界

本计划用来回答一个有限的工程问题：

> 在当前代码、当前本地环境和冻结合成数据上，ParamGuard Vision 是否按项目定义的 human-first 不变式执行，并对已识别的差异、不确定、结构异常和审计攻击做 fail-closed 处理？

它不能回答：

- 真实公司 SOP 是否与此流程一致；
- 任何真实工厂、设备、相机、显示器、语言或参数分布下的性能；
- 系统是否符合 Part 11、EU GMP Annex 11 或任何组织的验证要求；
- 是否可以用于放行、偏差结案、电子签名或 OT 参数写入。

## 2. 受测基线

每次可引用的测试执行必须记录：

- Git commit SHA；若尚未提交，记录工作树文件 SHA-256 和明确的“未提交快照”状态；
- Python、Pillow、Tesseract 和操作系统版本；
- `EvidenceManifest`、`PipelineSpec`、Schema、模板、OCR config、质量 config、比较/路由版本哈希；
- benchmark ID、version、content SHA-256、split、样本数和各类别数；
- 命令、开始/结束 UTC 时间、通过/失败/跳过数、完整失败输出和生成报告路径；
- 已知偏差、残余风险、结论批准人（在个人 PoC 中仅为开发者审阅）。

当前 `artifacts/evaluation/synthetic-benchmark-v1.json` 是可重算的本地证据，不是受控验证报告。

## 3. 测试层次

| 层次 | 目的 | 主要证据 |
|---|---|---|
| 纯函数/值对象单元测试 | 验证原始字符比较、ID/hash/type、基础路由、锁后 profile、deny-by-default 授权和指标公式 | `test_comparison.py`, `test_evidence.py`, `test_pipeline.py`, `test_routing.py`, `test_review_policy.py`, `test_policy.py`, `test_evaluation.py` |
| 状态机与并发测试 | 证明越序、重复、stale、伪造、并发命令不得越过锁 | `test_workflow.py`, `test_targeted_review.py`, `test_blind_review.py`, `test_adjudication.py` |
| 图像/OCR 集成测试 | 验证固定 ROI、图像质量门、本地 Tesseract、证据/管道绑定，以及未接主管道的配准几何 contract | `test_template.py`, `test_synthetic.py`, `test_ocr.py`, `test_vision_pipeline.py`, `test_registration.py` |
| 可选 VLM 对抗测试 | 验证锁后/合成数据门、请求-响应绑定、schema/budget、本地重算、网络与输出 fail-closed | `test_vlm.py`；仅注入离线 transport，不是真实 API/模型效能测试 |
| 审计完整性/语义测试 | 验证追加、修改/删除/截断检出、全链语义重放、最终 CAS | `test_audit.py` 及跨模块 audit/adjudication integration tests |
| Web/API 契约与泄漏测试 | 证明 R1 锁前响应/HTML/头不包含 AI 线索，并拒绝 stale revision、跨 origin、请求混淆和伪造 runner/定向绑定 | `test_webapp.py`；当前已接 R1→AI→定向 inbox/作答/锁定，全字段盲 R2、QA、final 和审计 UI/API 未接 |
| 端到端情景 | 从合成图像、R1、OCR、路由到人工复核/QA/最终决定和审计 | 全字段盲 R2/直达 QA 的域层+审计 adapter 已有集成测试；面试 profile 已到 Web 定向锁定，但定向 submission→QA/final/审计尚未集成 |
| 冻结数据集评估 | 在不混合 development/held-out/challenge 的情况下测量差异、拒答、提取和升级 | `test_benchmark.py`, `test_benchmark_runner.py`, `benchmark_demo.py` |
| 静态/供应链检查 | 编译、文档边界、CI、依赖/字库/语言数据/native 库版本和许可证登记 | `compileall`, `test_documentation.py`, `test_supply_chain.py`, `.github/workflows/ci.yml`；实际 supply-chain checker 因 `snum.traineddata` 上游无可确认 LICENSE 而预期 fail closed；SBOM/漏洞/秘密扫描待建 |

## 4. 冻结数据集设计

`SYNTHETIC_BENCHMARK_V1` 分为：

- `DEVELOPMENT`：可用于调试字体、ROI、OCR config 和质量阈值；
- `HIDDEN_TEST`：对开源 PoC 而言它是“冻结、不用于后续调参的 held-out split”，不是真正对开发者保密的外部盲测；
- `CHALLENGE`：低对比度和模糊等应优先触发拒答/升级的高风险样本。

当前风险类别覆盖：负号、小数表示精度、前导零、单位、文本模式、缺失字段、低对比度和模糊。下一版应在不改写 v1 的前提下新增：透视/旋转、屏幕反光、局部遮挡、小数点/千位分隔、Unicode 微符号、多语言、多字体、重复/未知字段和图像内 prompt injection。

## 5. 预先定义的风险指标

主指标不使用 overall accuracy，而是：

| 指标 | 定义 | 解读边界 |
|---|---|---|
| 差异召回率 | 真实差异中被 AI 明确标记 `DIFFERENT` 的比例 | 拒答不计为检出，因此不可用高拒答伪造高召回 |
| 假阴性率 | 真实差异中被 AI 标记 `SAME` 的比例 | 最高优先级风险指标 |
| 未解决差异率 | 真实差异中 `UNABLE_TO_JUDGE`/`SYSTEM_ERROR` 的比例 | 安全但会增加人工工作量，不能隐藏 |
| 差异升级召回率 | 真实差异中进入任一人工例外路径的比例 | 表示流程安全网，不表示 AI 自己识别成功 |
| 假阳性率 | 真实一致字段中被 AI 标记 `DIFFERENT` 的比例 | 衡量额外人工负担，不得优先于假阴性 |
| 左/右/成对提取精确率 | OCR 原始输出与合成真值逐字符一致的比例 | 空格差异也算不精确，与项目的表示完整性目标一致 |
| 总拒答率 | 所有字段中 AI 拒答/系统错误的比例 | 必须与假阴性和人工负担一起报告 |
| 人工时间 | 真实受试者从展示到提交的服务端时间 | 当前使用合成 ground truth 模拟 R1，因此必须为 `null`，不得伪造提效比 |
| AI 处理时间 | 本地 quality+OCR+compare+route 的墙钟时间 | 环境依赖大，需记录硬件/版本，不可外推 |

## 6. PoC 接受准则

下列是当前合成 PoC 的工程出口闸门，不是真实 GMP 验收准则：

| ID | 准则 |
|---|---|
| `AC-HF-01` | 任一未完成或未锁定 R1 任务均无法 queue/start/read/write AI；图像管道早调用在读任何图像字节前失败。 |
| `AC-HF-02` | R1 锁前的服务端响应、HTML 和头部自动扫描不出现 AI/run/OCR/confidence/route/risk/result 数据或结果相关结构差异。 |
| `AC-EVD-01` | 任一证据字节、角色、Schema/模板内容或 PipelineSpec 改变都使旧绑定失效。 |
| `AC-DET-01` | 预定义的负号、小数位、前导零、Unicode、单位、空值和非字符输入边界全部通过确定性单元测试。 |
| `AC-ROUTE-01` | 锁后路径必须绑定已批准 profile 和可信锁定上下文；客户端不能自报定向异常、清除 critical/quality/structure 信号或改送更宽松 profile。 |
| `AC-TR-01` | 面试 profile 仅对服务端重算的普通异常生成完整定向队列；所有新人工结论必须带原因，`SAME` 也不关闭异常或跳过最终人工。 |
| `AC-R2-01` | 当且仅当已批准 profile 选择全字段盲 R2 时，要求与 R1 不同身份对完整 Schema 先盲审锁定；错 Manifest/revision/reviewer/伪造 submission 无状态副作用。 |
| `AC-QA-01` | 异常台账与可信路由+对账事实严格集合等价；所有异常都有不可覆盖的人工 disposition 前不能完成 QA。 |
| `AC-AUTH-01` | 所有路由的 `automatic_release_allowed` 均为 false；AI/system/service/admin 均无法写最终决定；blocking/rework 无法 approve。 |
| `AC-AUD-01` | 删除、篡改、重排、截断、时间倒退、重复 ID 和哈希自一致的不可能流程全部在重放时被拒绝。 |
| `AC-AUD-02` | 最终决定在单一审计锁/交易中校验当前 head、前置覆盖、CAS、append 和持久化；任一失败不产生 final state。 |
| `AC-EVAL-01` | 冻结 held-out 中假阴性率为 0，且差异升级召回率为 100%；未明确识别的差异必须以拒答/系统错误升级，不得 `SAME`+无例外。 |
| `AC-EVAL-02` | challenge 样本的已知低质量输入不得产生 `SAME` 放心结论；拒答和升级必须完整报告。 |
| `AC-REP-01` | README/UI/导出/简历说法都明确为“独立个人 PoC、仅用合成数据、非企业委托、非放行、非 GxP/Part 11 验证”。 |

若真实数据上市，不能沿用 `AC-EVAL-01/02` 的合成阈值。必须由实际 Process Owner/QA 根据 intended use、参数关键性、基准错误率和可接受的人工负担预先批准。

## 7. 当前执行快照

2026-08-25 对当前本地未提交快照重新执行了全量测试、编译检查和真实本地合成 benchmark。为遵守本次“只修中央文档”的审查边界，benchmark 重跑写入的是临时目录，而不是覆盖仓库中的 canonical artifact；最终里程碑还应在源码稳定后重建 `artifacts/evaluation/synthetic-benchmark-v1.json`。

- 命令 `PYTHONPATH=src python3 -m unittest discover -s tests -q`：435 项通过，0 失败，用时 17.431 s（`2026-08-25T13:29:51Z` 至 `2026-08-25T13:30:09Z`）；
- 命令 `PYTHONPATH=src python3 -m compileall -q src tests`：退出码 0；
- benchmark 生成时间：`2026-08-25T13:27:55.202291+00:00`；全程本地且不需网络；
- 环境：CPython 3.13.2，macOS/Darwin 25.5.0 arm64，Pillow 12.2.0，Tesseract 5.5.1；
- `src/paramguard` source-tree SHA-256：`b7a21e2e335809fb84981fda1b0ddc780f64d4f8e2c3923d490285f77d9279b8`；
- benchmark：`paramguard-synthetic-benchmark` v1.0，content SHA-256 `18c83b7d91d6b7fc925302f12c25c9185485aa1cc82149dec1525bb217188776`；
- PipelineSpec SHA-256：`9678b483ad387cb38ebe5afc90b1588e73bf62efbc28078f8441145f9bfb37b7`；
- held-out：28 字段/6 个真差异；差异召回 4/6（66.7%），假阴性 0/6（0%），未解决差异 2/6（33.3%），差异升级 6/6（100%），总拒答 2/28（7.1%）；
- challenge：8 字段/2 个真差异；全 8 字段拒答，2/2 真差异均升级，假阴性 0/2。

这个快照的正确解读是：在很小的合成分布上，当前管道没有把真差异标成 `SAME`，但它只明确识别了 4/6，另有 2/6 需人工处理。challenge 全拒答很安全，但对效率没有贡献。样本很小，未计算置信区间，不得声称“零漏检”或“真实性能 100%”。

## 8. 偏差、回归和出口

任一测试失败必须：

1. 保留原始输出和环境，不通过重跑隐藏间歇失败；
2. 登记受影响的 URS、威胁 ID、数据集/配置和声明；
3. 区分代码缺陷、测试缺陷、环境故障、数据集不足和预期拒答；
4. 修复后先重跑最小相关测试，再跑全套+编译+基准；
5. 对 human-first、身份、审计或假阴性有影响时，必须安排独立只读复审。

当前 PoC 只有在全部 `Must` 有可追溯证据、所有出口闸门通过、已知偏差有明确残余风险、README/演示可从空环境复现且用户能亲自解释时，才可标记为“学习项目 V1.0”。这一标记仍不是法规或企业生产批准。
