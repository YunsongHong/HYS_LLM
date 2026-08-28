# ParamGuard Vision 官方来源登记表

| 字段 | 值 |
|---|---|
| 登记表版本 | 0.1 |
| 统一访问/核验日 | 2026-08-25 |
| 收录规则 | 优先法规原文、监管机构、标准组织或发布机构的一手页面 |
| 用途 | 学习型 PoC 的设计依据和边界提醒，非法律意见或合规证明 |

## 1. 状态词汇

- **法规**：法律或编纂规则的条文。具体是否适用，仍取决于辖区、活动、产品和记录。
- **现行官方指南**：发布机构当前列出的指南或解释。指南不必然创设法律上可强制执行的新义务。
- **最终行业/政府指南**：已定稿的风险、数据完整性或安全参考；不因“最终”二字自动成为所有企业的法规。
- **征求意见草案**：非定稿文件，不得写成现行法定要求；仅可用于前瞻性设计和风险提醒。
- **官方项目技术文档**：软件维护方发布的使用或 API 资料；只支持实现选择，不是法规或性能证明。
- **项目决定**：ParamGuard Vision 为满足题设场景而采用的更严设计，不冒充法规原文。

## 2. 一手来源

| ID | 发布方与文件 | 截至核验日的状态 | 范围与本项目用法 | 不可越界的解读 |
|---|---|---|---|---|
| `SRC-US-11.10` | [eCFR, 21 CFR § 11.10 — Controls for closed systems](https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11/subpart-B/section-11.10) | **法规**；链接为持续更新、“authoritative but unofficial”的 eCFR 版本 | 在 Part 11 适用时，涉及闭合系统的验证、完整副本、保护/检索、授权访问、带时间戳审计轨迹和步骤顺序控制 | 不能只因项目用在“药企场景”就断言 Part 11 适用；也没有规定本 PoC 的特定 human-first 显示顺序 |
| `SRC-US-211.68` | [eCFR, 21 CFR § 211.68 — Automatic, mechanical, and electronic equipment](https://www.ecfr.gov/current/title-21/chapter-I/subchapter-C/part-211/subpart-D/section-211.68) | **法规**；eCFR 状态同上 | 针对药品制造中自动/电子设备，涉及书面检查计划、授权变更、输入/输出准确性和备份等 | 不能在不知道实际记录和用途时，直接将条文贴到个人 PoC 上 |
| `SRC-US-P11-SCOPE` | [FDA, Part 11, Electronic Records; Electronic Signatures — Scope and Application](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/part-11-electronic-records-electronic-signatures-scope-and-application) | **最终指南**，2003；页面明示“Contains Nonbinding Recommendations” | 解释 Part 11 对电子 predicate-rule 记录/签名的较窄适用方式，并强调先识别并记录 predicate rules 和实际依赖的记录 | 不可把“执法裁量”误写为 Part 11 已废止；也不可跳过基础 predicate rules |
| `SRC-US-DI` | [FDA, Data Integrity and Compliance With Drug CGMP: Questions and Answers](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/data-integrity-and-compliance-drug-cgmp-questions-and-answers) | **最终 Level 1 指南**，2018；非绑定性建议 | 针对药品 CGMP 数据的可靠性、准确性和基于流程/技术理解的风险控制 | 它不是通用 OCR/LLM 产品认证规范 |
| `SRC-EU-A11-INDEX` | [European Commission, EudraLex Volume 4 official index](https://health.ec.europa.eu/medicinal-products/eudralex/eudralex-volume-4_en) | **现行官方目录**；核验日仍将 Annex 11 列为“revision January 2011” | 用于核对当前 EU GMP Annex 11 版本身份 | 不可用征求意见的 2025 修订草案替代当前目录中的版本 |
| `SRC-EU-A11` | [European Commission, EudraLex Volume 4 Annex 11 — Computerised Systems](https://health.ec.europa.eu/document/download/8d305550-dd22-4dad-8463-2ddb4a1345f1_en) | **现行官方 GMP 指南**，revision 1，2011 年生效 | 适用于 GMP 活动中的计算机化系统；支持风险管理、验证、可追溯 URS、关键手工数据准确性检查、审计轨迹、安全和变更控制的设计参考 | 第 6 节允许额外准确性检查由第二位操作员或经验证的电子方式完成；因此它不支持“普遍必须人工先、AI 后”的声明 |
| `SRC-ICH-Q9R1` | [ICH, Q9(R1) Quality Risk Management, Step 4 Guideline](https://database.ich.org/sites/default/files/ICH_Q9%28R1%29_Guideline_Step4_2025_0115_0.pdf) | **ICH Step 4 最终指南** | 提供质量风险识别、评估、控制、沟通和复审框架；项目用它组织风险分析的方法 | ICH 文件在各辖区的实施方式必须另行确认；不是本 PoC 的认证书 |
| `SRC-PICS-DI` | [PIC/S PI 041-1, Good Practices for Data Management and Integrity in Regulated GMP/GDP Environments](https://picscheme.org/layout/document.php?id=714) | **PIC/S 最终指南**，2021-07-01 | 主要为检查机构提供数据完整性解释，也可供行业参考；支持风险对等的数据治理、追加式审计思路和可追溯 URS | PIC/S 指南本身不是某个辖区的成文法；应与适用的 GMP/GDP 要求一起解读 |
| `SRC-EU-A22-DRAFT` | [European Commission, draft Annex 22 — Artificial Intelligence](https://health.ec.europa.eu/document/download/5f38a92d-bb8e-4264-8898-ea076e926db6_en?filename=mp_vol4_chap4_annex22_consultation_guideline_en.pdf) 及 [official consultation page](https://health.ec.europa.eu/consultations/stakeholders-consultation-eudralex-volume-4-good-manufacturing-practice-guidelines-chapter-4-annex_en) | **征求意见草案，非现行 Annex**；征询期 2025-07-07 至 2025-10-07，页面状态 Closed | 仅作前瞻性参考：intended use、指标与接受准则、独立测试数据、置信度、运行监督与 human-in-the-loop 职责 | 不得写成“Annex 22 已生效”。草案的模型范围很窄；对 LLM/生成式 AI 的文字也必须明确标注为草案观点 |
| `SRC-NIST-OT` | [NIST SP 800-82 Rev. 3, Guide to Operational Technology Security](https://csrc.nist.gov/pubs/sp/800/82/r3/final) | **NIST 最终特别出版物**，2023-09；Rev. 4 在核验日尚非最终版 | 说明 OT 系统需同时考虑性能、可靠性、安全性和网络安全；支持本地优先、最小权限、分区和不向 OT 自动写参数的保守范围 | 它是通用 OT 安全指南，不是制药 GMP 或 Part 11 规范 |
| `SRC-US-CSA-DEVICE` | [FDA, Computer Software Assurance for Production and Quality Management System Software](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/computer-software-assurance-production-and-quality-management-system-software) | **最终指南**，2026-02 | 范围是医疗器械生产或质量管理系统中的计算机软件保证，可作风险导向测试的旁证 | 不是普通药品 GMP 计算机化系统的直接通用依据；本项目不得以它声称已符合药品 GxP |
| `SRC-TESS-CLI` | [Tesseract 官方 CLI 手册](https://github.com/tesseract-ocr/tesseract/blob/main/doc/tesseract.1.asc) 与 [官方 TSV 示例](https://github.com/tesseract-ocr/tessdoc/blob/main/Command-Line-Usage.md#tsv-output) | **官方项目技术文档**；滚动更新，核验日读取 `main` | 支持本地 CLI 调用、`--psm 7` 单行分割、`--version` 版本捕获以及 TSV 输出的文本、框和 confidence 字段 | TSV confidence 不能不经项目评估就解读为校准概率；官方功能存在不证明本项目 OCR 准确或可放行 |
| `SRC-TESS-QUALITY` | [Tesseract 官方 ImproveQuality](https://tesseract-ocr.github.io/tessdoc/ImproveQuality.html) | **官方项目技术文档**；滚动更新 | 说明 DPI、对比度/噪声、旋转、边界和 page-segmentation 会影响 OCR；用于解释为何要实施版本化图像质量拒答门 | 文档没有为本 PoC 的 contrast/edge 阈值背书；这些阈值是待隐藏测试集评估的项目配置 |
| `SRC-PILLOW` | [Pillow 官方 ImageDraw](https://pillow.readthedocs.io/en/stable/reference/ImageDraw.html)、[ImageFilter](https://pillow.readthedocs.io/en/stable/reference/ImageFilter.html) 与 [ImageStat](https://pillow.readthedocs.io/en/stable/reference/ImageStat.html) | **官方项目技术文档**；核验日 stable 文档为 12.3.0 | 用于绘制纯合成面板、生成模糊/低对比挑战样本并计算透明的图像统计量 | Pillow 是图像库，不为合成数据的业务代表性、质量阈值或模型性能作保证 |
| `SRC-OAI-RESPONSES` | [OpenAI Responses API — Create a model response](https://developers.openai.com/api/reference/cli/resources/responses/methods/create) 与 [Images and vision guide](https://developers.openai.com/api/docs/guides/images-vision) | **官方产品技术文档**；会随 API 演进，核验日 2026-08-25 | 支持可选 VLM 挑战者的 `input_image`、data URL、`store`、`text.format` 和 Responses 请求/响应形状 | 文档不是该组件的网络权限、真实账号可用性、视觉正确性、供应商签名或药企数据出域批准 |
| `SRC-OAI-STRUCTURED` | [OpenAI Structured model outputs](https://developers.openai.com/api/docs/guides/structured-outputs) | **官方产品技术文档**；核验日 2026-08-25 | 用于核对 strict JSON Schema 形状以及 enum/schema 容量界限，并为单请求参数上限和 fail-closed 预检提供技术依据 | Structured Outputs 约束形状，不保证模型转录内容是视觉事实，也不是防 prompt injection 或自动放行证明 |
| `SRC-OAI-MODEL` | [OpenAI GPT-5.4 mini model](https://developers.openai.com/api/docs/models/gpt-5.4-mini) | **官方模型技术文档**；核验日 2026-08-25 | 核对图像输入、Responses、Structured Outputs 和固定 snapshot `gpt-5.4-mini-2026-03-17` 的可用性 | 固定模型 ID 只是可复现身份的一部分，不证明当前账号有权限、模型适合 intended use 或本项目已实测真实 API |
| `SRC-OAI-DATA` | [OpenAI Data controls in the API platform](https://developers.openai.com/api/docs/guides/your-data) | **官方产品数据控制文档**；核验日 2026-08-25 | 用于明确 `store:false` 、abuse-monitoring retention 和 Zero Data Retention 是不同控制，并约束当前组件仅接受已审虚构合成证据 | `store:false` 不等于零保留；ZDR 需要资格、审批和组织/项目配置，不能由一个请求字段自行宣称 |

## 3. 来源交叉结论

### 可以做的有界推论

1. `SRC-US-11.10`、`SRC-EU-A11`、`SRC-US-DI` 和 `SRC-PICS-DI` 从不同角度支持：若系统真正进入适用的受规制流程，必须系统性处理记录真实性/完整性、授权、审计轨迹、变更和验证，不能只看模型准确率。
2. `SRC-EU-A11`、`SRC-ICH-Q9R1` 和 `SRC-PICS-DI` 共同支持基于 intended use、数据关键性和风险的控制强度。
3. `SRC-EU-A22-DRAFT` 可用来提前设计测试指标、独立测试数据、置信度/拒答、监督和人员职责，但它在本登记日仍只是草案。

### 不能从来源推出的结论

- 没有上述现行法规/指南建立一条跨所有场景的通用要求：“必须由人工完成全部检查，锁定后才能计算或显示 AI”。这是 `PD-HF-01` 的项目决定，用来满足题设场景和降低先看 AI 对独立判断的影响。
- Annex 11 第 6 节反而明确给出第二操作员或经验证电子方式两种准确性复核路径，具体控制应由实际风险和 SOP 确定。
- 引用任何一份文件都不能证明个人 PoC 已获得生产验证、法规批准或组织质量部门放行。

## 4. 维护规则

- 任何文档引用本表时使用 Source ID，并在“事实”、“基于来源的推论”和“项目决定”之间明确标注。
- 每次准备公开演示、面试或生产化评估前，重新核对链接、版本、状态和适用范围，更新访问日。
- 若 Annex 22 后续定稿，新增“最终版”条目，保留本草案记录；不静默改写历史来源状态。
