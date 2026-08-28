# ParamGuard Vision

图像参数比对的本地实验项目。审核员先逐项核对照片 A 和截图 A′，锁定首审记录后，系统才运行 OCR，并将差异交给人工复核。字符是否相同由 Python 规则判断，不由语言模型裁决。

这是一个使用纯合成数据的独立个人项目，不代表任何企业的系统、流程或委托成果。项目未经过 GxP、21 CFR Part 11 或 EU Annex 11 验证，不能用于生产或质量放行。

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

### 本地 Web 演示

Web 和真实 OCR 基准还需要单独安装 [Tesseract](https://tesseract-ocr.github.io/tessdoc/Installation.html) 及 `eng` 语言数据。`pip install -e .` 不会安装这些外部程序。

真实 OCR 的默认执行器目前支持 macOS / Linux，Windows 暂不支持。每次进程的标准输出与错误输出合计默认不超过 1 MiB；超限时拒绝结果，不截断后继续比较。限制与剩余风险见[架构说明](./docs/ARCHITECTURE.md)。

先确认它们可用：

```bash
tesseract --version
tesseract --list-langs
```

然后启动：

```bash
python -m paramguard.webapp --host 127.0.0.1 --port 8765
```

打开 <http://127.0.0.1:8765/>。演示只监听本机，使用项目生成的合成图像。操作流程见 [Web 文档](./docs/WEB_DEMO.md)。

## 当前实现

| 模块 | 已实现 | 尚未覆盖 |
| --- | --- | --- |
| 字符比较与首审门禁 | 原始字符串比较、全字段作答检查、修订校验、锁定后才允许 AI | 参数业务合法性、真实公司 SOP |
| Web 演示 | 首审 → 锁定 → 本地 OCR → 定向异常复核 | 持久化、真实登录、QA 和最终人工决定 |
| SQLite P1 | 任务、冻结证据、首审修订、原子锁定、命令收据和事务 outbox | Web 接入、锁后流程、outbox 消费者 |
| 锁后领域流程 | 定向复核、可选盲二审、QA、最终人工决定及 JSONL 审计原型 | 完整 Web 接线、受控存储、电子签名 |
| 可选 VLM 适配层 | 锁后访问、结构化输出校验、离线对抗测试 | 真实 API 调用与模型效果验证；默认禁网 |

默认档案为 `INTERVIEW_TARGETED_RECHECK`：锁后聚焦异常字段。可选的 `CONSERVATIVE_BLIND_R2` 要求另一身份对全部字段盲审，两者不是同一种审核。AI 不能修改人工记录；`SAME` 不能关闭异常，任何路径都不能自动放行。

## 验证

运行单元、对抗和集成测试：

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
```

[CI 配置](./.github/workflows/ci.yml)包含 Python 3.11 和 3.13；缺少 Tesseract 时，相关集成测试会明确跳过。配置文件存在不代表已经在 GitHub 上运行成功。

安装 Tesseract 后，可运行合成基准和本机供应链检查：

```bash
python benchmark_demo.py
python -m paramguard.supply_chain
```

基准输出到 `artifacts/evaluation/`，记录差异召回、假阴性、未解决差异和拒答率。生成文件默认不提交。测试结果只适用于所用合成数据，不能外推真实工厂性能。

供应链清单是开发环境基线。当前登记的 `tessdata-snum` 许可证为 `UNKNOWN`，检查会阻断；其他机器也可能出现版本或哈希不匹配。普通测试通过不等于供应链获准使用。

## 当前限制

- SQLite 收据回读与重试会核对命令、返回值和 outbox 的关系，但不替代全库完整性核验或受控存储。详见 [SQLite 文档](./docs/SQLITE_PERSISTENCE.md)。
- Web 会话保存在内存中，尚未接入独立的 SQLite 模块；关闭进程后不能据此恢复完整审核流程。
- 1,001 字段已有后端测试，但 Web 首屏仍一次生成全部卡片，没有虚拟列表。
- OCR 使用固定模板和区域；图像配准合同尚未接入真实配准引擎。
- 哈希和追加日志不等于不可篡改存储。项目没有企业认证、电子签名或生产部署验证。

## 文档

- [学习路线](./docs/LEARNING_ROADMAP.md)
- [项目范围与声明](./docs/PROJECT_SCOPE.md) · [限制说明](./docs/CLAIMS_AND_LIMITATIONS.md)
- [架构](./docs/ARCHITECTURE.md) · [SQLite 持久化](./docs/SQLITE_PERSISTENCE.md)
- [流程档案](./docs/PROCESS_PROFILES.md) · [定向异常复核](./docs/TARGETED_RECHECK.md)
- [验证计划](./docs/VALIDATION_PLAN.md) · [需求追溯](./docs/TRACEABILITY_MATRIX.md)
- [CI](./docs/CI.md) · [供应链](./docs/SUPPLY_CHAIN.md)

## 贡献与许可

提交问题或修改前，请阅读 [CONTRIBUTING.md](./CONTRIBUTING.md) 和 [SECURITY.md](./SECURITY.md)。复现材料只能使用合成数据，不要上传公司图片、患者信息、凭据或本机完整日志。

本项目尚未选择对外许可证，不能仅凭仓库可见性推定使用授权。发布前还需完成[公开检查清单](./docs/PUBLISHING.md)，由作者确认许可证和可见性。
