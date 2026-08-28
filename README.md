# ParamGuard Vision

图像参数比对的本地实验项目。上传两组图片，指定要检查的参数编号，把两侧候选区域放在一起，记录机器观察和人工结论。字符比较由 Python 完成，不由语言模型裁决。

项目有两个独立入口：默认的严格首审演示先人工、后 OCR；新增的辅助工作区先显示 OCR 候选，再逐项人工复核。后者不是独立首审，也不具备批准或放行功能。

这是一个使用纯合成数据的独立个人项目，不代表任何企业的系统、流程或委托成果。项目未经过 GxP、21 CFR Part 11 或 EU Annex 11 验证，不能用于生产或质量放行。

![辅助工作区：真实运行的网页、合成图片和本地 OCR 候选](./docs/demo/assets/assisted-paired-review.jpg)

[查看完整网页演示](./docs/demo/WALKTHROUGH.md) · [上传与使用说明](./docs/ASSISTED_WORKBENCH.md) · [6000 → 1000 实测](./docs/ASSISTED_BENCHMARK.md)

## 比对示例

命令行演示包含以下情况：

| A | A′ | 结果 |
| --- | --- | --- |
| `37.0 °C` | `37.0 °C` | 字符一致 |
| `7.20` | `7.25` | 数值表示不同 |
| `10 mg` | `10 μg` | 单位不同 |
| `025.0 L/min` | `25.0 L/min` | 格式不同 |

原始字符串会被保留；大小写、小数位、前导零和单位不会在比对前被统一。字符一致不代表参数合法或可以放行。

## 快速开始

需要 Python 3.11 或更高版本。以下命令在仓库根目录执行，适用于 macOS / Linux：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .

python demo.py
python workflow_demo.py
```

第一个演示打印字符比对结果；第二个演示人工首审、完整性检查、锁定和 AI 访问门禁。这两条命令不调用外部模型，也不需要安装 OCR 引擎。

首次接触 Python，可从[第 0 课](./docs/LEARNING_00.md)开始。

### 本地图片上传工作区

Web 和真实 OCR 基准还需要单独安装 [Tesseract](https://tesseract-ocr.github.io/tessdoc/Installation.html) 及 `eng` 语言数据。`pip install -e .` 不会安装这些外部程序。

真实 OCR 执行器目前支持 macOS / Linux，Windows 暂不支持。默认固定区域执行器的输出上限为 1 MiB；新工作区逐页 TSV 上限为 4 MiB。超限均拒绝结果，不截断后继续比较。

先确认它们可用：

```bash
tesseract --version
tesseract --list-langs
```

然后启动：

```bash
python -m paramguard.assisted_web --port 8766 --workspace artifacts/my-workspace
```

打开 <http://127.0.0.1:8766/>。选择两侧 PNG/JPEG，粘贴目标编号或导入 CSV，确认辅助模式后开始。图片与记录保存在本机 SQLite，不发送给云端模型；关闭后用同一命令可以继续查看。

首版支持单列、逐行的连续英文/数字编号，后面跟值与单位。编号断行、多列或模糊图片不保证自动定位；未找到和重复项会保留，可查看原图、选择候选或手动框选。每任务最多 2000 个目标、每侧 64 张图。详见[工作区说明](./docs/ASSISTED_WORKBENCH.md)。

没有测试图片时，先生成一组明确标记的合成样例：

```bash
python tools/generate_assisted_fixture.py --output artifacts/my-fixture --rows 48 --targets 12
```

分别上传其中的 `left-001.png`、`right-001.png`，导入 `targets.csv`。输出目录必须是新目录，工具不会覆盖已有样例。

### 严格人工首审演示（默认流程）

```bash
python -m paramguard.webapp --host 127.0.0.1 --port 8765
```

打开 <http://127.0.0.1:8765/>。这个独立入口仍使用固定合成模板，要求全部首审记录锁定后才运行 OCR；不能读取辅助工作区的候选或记录。操作流程见 [Web 文档](./docs/WEB_DEMO.md)。两个入口不要使用同一端口。

## 当前实现

| 模块 | 已实现 | 尚未覆盖 |
| --- | --- | --- |
| 字符比较与首审门禁 | 原始字符串比较、全字段作答检查、修订校验、锁定后才允许 AI | 参数业务合法性、真实公司 SOP |
| 严格首审 Web 演示 | 首审 → 锁定 → 本地 OCR → 定向异常复核 | 持久化、真实登录、QA 和最终人工决定 |
| 辅助图片工作区 | 上传、编号清单、逐页 OCR、配对图块、手动区域、25项分页、人工记录、重启恢复与 JSON 导出 | 任意版面、中文 OCR、多人身份、QA/批准流程 |
| SQLite P1 | 任务、冻结证据、首审修订、原子锁定、命令收据和事务 outbox | Web 接入、锁后流程、outbox 消费者 |
| 锁后领域流程 | 定向复核、可选盲二审、QA、最终人工决定及 JSONL 审计原型 | 完整 Web 接线、受控存储、电子签名 |
| 可选 VLM 适配层 | 锁后访问、结构化输出校验、离线对抗测试 | 真实 API 调用与模型效果验证；默认禁网 |

严格模式的默认档案为 `INTERVIEW_TARGETED_RECHECK`：锁后聚焦异常字段。可选的 `CONSERVATIVE_BLIND_R2` 要求另一身份对全部字段盲审，两者不是同一种审核。`ASSISTED_REVIEW_V1` 是另一个非盲工作区，不生成 R1/R2 记录。任何入口都不能自动放行。

## 验证

运行单元、对抗和集成测试：

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests tools
node tools/check_assisted_ui.mjs
```

[CI 配置](./.github/workflows/ci.yml)包含 Python 3.11 和 3.13，检查两个 Web 模板的打包和异步 UI 回归；缺少 Tesseract 时，相关集成测试会明确跳过。Node 只用于开发验证，不是运行工作区的依赖。

2026-08-28 的本机全量测试为两套 Python 各 741 项，3.13 有 1 项 SQLite 环境条件跳过。另有真实 Tesseract 的 60 图、1000 目标开发基准：250 个预设差异中 226 个形成原文支持的差异提示，仍有未定位、不确定和错字。它不是实拍照片或真人效率试验，完整分母与复现命令见[实测记录](./docs/ASSISTED_BENCHMARK.md)。

安装 Tesseract 后，可运行合成基准和本机供应链检查：

```bash
python benchmark_demo.py
python -m paramguard.supply_chain
```

基准输出到 `artifacts/evaluation/`，记录差异召回、假阴性、未解决差异和拒答率。生成文件默认不提交。测试结果只适用于所用合成数据，不能外推真实工厂性能。

供应链清单是开发环境基线。当前登记的 `tessdata-snum` 许可证为 `UNKNOWN`，检查会阻断；其他机器也可能出现版本或哈希不匹配。普通测试通过不等于供应链获准使用。

## 当前限制

- SQLite 收据回读与重试会核对命令、返回值和 outbox 的关系，但不替代全库完整性核验或受控存储。详见 [SQLite 文档](./docs/SQLITE_PERSISTENCE.md)。
- 严格首审 Web 会话仍在内存中，未接入独立的 SQLite P1 模块；辅助工作区使用自己的 SQLite 库，不表示严格审核流程已经持久化。
- 严格首审页面仍一次生成全部字段卡片；辅助工作区采用 25 项分页，已有 6000 行来源、1000 目标的测试。
- 严格模式 OCR 依赖固定模板；辅助模式仅支持受限单列布局。两者都没有通用图像配准或复杂表格理解能力。
- 辅助工作区用 OCR 词重建字符串，词间空格不能冒充图片中已核验的原始空格。高置信 OCR 也可能读错编号或数字。
- 哈希和追加日志不等于不可篡改存储。项目没有企业认证、电子签名或生产部署验证。

## 文档

- [学习路线](./docs/LEARNING_ROADMAP.md)
- [图片工作区](./docs/ASSISTED_WORKBENCH.md) · [网页演示](./docs/demo/WALKTHROUGH.md) · [实测记录](./docs/ASSISTED_BENCHMARK.md)
- [已有工具的比较协议](./docs/COMPARISON_PROTOCOL.md)
- [项目范围与声明](./docs/PROJECT_SCOPE.md) · [限制说明](./docs/CLAIMS_AND_LIMITATIONS.md)
- [架构](./docs/ARCHITECTURE.md) · [SQLite 持久化](./docs/SQLITE_PERSISTENCE.md)
- [流程档案](./docs/PROCESS_PROFILES.md) · [定向异常复核](./docs/TARGETED_RECHECK.md)
- [验证计划](./docs/VALIDATION_PLAN.md) · [需求追溯](./docs/TRACEABILITY_MATRIX.md)
- [CI](./docs/CI.md) · [供应链](./docs/SUPPLY_CHAIN.md)

## 贡献与许可

提交问题或修改前，请阅读 [CONTRIBUTING.md](./CONTRIBUTING.md) 和 [SECURITY.md](./SECURITY.md)。复现材料只能使用合成数据，不要上传公司图片、患者信息、凭据或本机完整日志。

本项目尚未选择对外许可证，不能仅凭仓库可见性推定使用授权。每次更新按[公开检查清单](./docs/PUBLISHING.md)复核文件与声明；许可证由作者另行决定。
