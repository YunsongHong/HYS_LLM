# 项目声明与限制

| 字段 | 值 |
|---|---|
| 文档状态 | 公开表述基线 |
| 版本 | 0.1 |
| 日期 | 2026-08-25 |
| 适用对象 | README、简历、面试、演示、报告和代码注释 |

## 1. 必须保留的核心声明

> ParamGuard Vision 是一个研究图像参数核验的独立个人项目，演示和测试只使用纯合成数据。它不代表任何企业的内部系统、流程或委托成果，也不使用企业内部数据、SOP 或验证材料。项目尚未针对真实 intended use 完成组织级 GxP/Part 11 验证，不得用于批次放行、偏差结案或自动修改 OT 参数。

若简历篇幅不足，最少保留：**“独立个人 PoC，使用纯合成数据，非企业内部或已验证生产系统。”**

## 2. 可以说与不可以说

| 主题 | 证据足够时可以说 | 不得说 | 原因 |
|---|---|---|---|
| 项目来源 | “独立开发的图像参数核验学习项目” | “企业委托项目”、“企业内部系统”、“真实生产流程复刻” | 没有企业委托、内部流程证据或生产部署 |
| 数据 | “演示和测试使用纯合成数据” | “在真实企业数据上验证” | 未获得或使用真实公司数据 |
| 法规参考 | “设计参考了 FDA/eCFR、EU GMP、ICH、PIC/S 和 NIST 的官方来源，并区分法规、指南和草案” | “已通过 FDA”、“Part 11 certified”、“Annex 11 validated”、“GxP compliant” | 引用法规不等于适用性评估、组织验证或监管批准 |
| Annex 22 | “将 2025 年 EU Annex 22 征求意见草案仅作前瞻性设计参考” | “Annex 22 已生效”、“法规强制 LLM 必须按本项目流程工作” | 官方页面在 2026-08-25 显示的是已结束征求意见，不是定稿 Annex |
| Human-first | “项目以后端状态门强制首审员先独立完成并锁定，再显示 AI 辅助结果” | “所有 GxP 法规都要求人工必须先于 AI” | 这是本项目针对题设的风险控制；现行 Annex 11 不规定该特定先后顺序 |
| AI 权限 | “AI/OCR 只辅助提取、对齐和异常说明，不覆盖人工、关闭偏差或放行” | “AI 替代复核”、“无人审核”、“自动放行” | 与项目 intended use 和权限边界相反 |
| 精确判定 | “原始字符级完全一致由确定性规则引擎判定，LLM/VLM 不承担最终精确判定” | “用 LLM 保证参数 100% 相同” | 概率模型不适合承担该项目的字符级放行标准 |
| 完全一致 | “`EXACT_MATCH` 表示两个非空原始字符串逐字符相同” | “`EXACT_MATCH` 表示参数合法/在限度内/可放行” | 字符相同不能证明值本身有效；例如两侧都是 `ERROR` |
| 审计 | “PoC 实现可检测简单篡改的追加式哈希链审计原型”（仅在相应测试存在时） | “不可篡改存储”、“WORM archive”、“符合 Part 11 审计轨迹” | JSONL+哈希链不等于 WORM、数字签名、受信时间戳、备份/恢复或已验证基础设施 |
| 性能 | “在数据集 X、版本 Y、阈值 Z上，差异召回率为…、假阴性为…” | “100% 准确”、“零漏检”、“提效 80%”（无受控实验时） | 所有性能声明必须绑定数据、样本数、阈值、置信区间/不确定性和限制 |
| 开发者贡献 | “我在指导下学习、复现并能解释的部分包括…” | 将尚未理解/复现的后台参考实现全部写成自己独立完成 | 简历只应陈述真正理解、可亲自重建和可面试辩护的工作 |

## 3. 当前必须承认的限制

- 这是个人 PoC，没有组织级 Quality Management System、独立 QA 放行或监管机构审核。
- 合成数据无法覆盖真实工厂的相机、显示器、照明、模板、语言、字体、设备老化、操作行为和网络边界。
- 不知道任何公司的实际 SOP、验收标准、参数关键性、二审规则、记录保留期和系统集成限制。
- 未经实际 intended use 的质量风险评估，不能从合成测试外推到生产环境。
- 本地哈希、追加事件和单元测试不代替身份管理、电子签名、WORM/受控存储、备份恢复、灾难恢复、业务连续性和安全监控。
- 自动化测试覆盖的是明确编写的案例，不是对未知错误、监管适用性或人因有效性的完整证明。
- 已实现的可选 VLM challenger 只在锁后处理经 allowlist 的可重建虚构合成图，默认禁网，而且只能返回 observation/abstain；它尚无真实 API/模型性能证据，核心字符精确比较仍是普通确定性软件。

## 4. 建议的简历表述

### 中文

> ParamGuard Vision（独立个人 PoC）—使用纯合成数据研究大批量图像参数核验。后端要求首审全部完成并锁定后才允许 AI/OCR，原始字符差异由确定性规则计算；带版本的流程档案将分歧、不确定和结构问题交给定向人工复核、条件性全字段盲二审或 QA。项目包含追加式审计原型和风险导向测试，不是企业委托成果或已验证的生产系统。

### English

> **ParamGuard Vision** is an independent personal project for image-assisted parameter review, built exclusively with synthetic data. The backend requires a complete, locked first review before AI/OCR can run. Deterministic rules compare raw strings; versioned profiles route discrepancies and uncertainty to targeted human recheck, optional full-manifest blind second review, or QA. It includes an audit prototype and risk-focused tests, but is not a commissioned enterprise system or a validated GxP/21 CFR Part 11 production system.

只有当你已能亲自重建、运行测试并说明上述每项设计时，才应使用完整版表述；否则应删减为你真正掌握的部分。

## 5. 性能声明模板

任何数字都应使用完整模板：

> 在纯合成、预先冻结的隐藏测试集 **[dataset name/version]** 上（`n=[sample count]`，其中差异样本 `[count]`），使用 **[software/model/rules version]** 和预先定义的 **[thresholds]**，差异召回率为 **[value, interval]**，假阴性率为 **[value, interval]**，拒答率为 **[value]**。结果仅适用于该合成数据分布，未证明真实工厂性能或 GxP 合规性。

若缺任一字段，就不应发布简化的“准确率/提效率”声明。
