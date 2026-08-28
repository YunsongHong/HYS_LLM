# GitHub 发布检查

此清单用于第一次公开前的人工检查，不会创建仓库、提交或上传文件。整理文档不代表项目已经具备发布条件。

## 作者需要确认

- [ ] 仓库名称和归属账号；
- [ ] 初始可见性；建议先用 private 核对内容，再单独决定是否公开；
- [ ] 对外许可证，随后添加根目录 LICENSE 和相符的包元数据；
- [ ] 私密漏洞接收渠道，并实际测试可用性。

许可证未选择前，不添加许可证徽章，也不接受外部代码合入。不要复制参考项目的维护者名单、许可证归属或认证徽章。

## 文件范围

通常纳入源码、测试、合成示例定义、经过审阅的文档和 CI 配置。提交之前逐项检查实际文件清单。

`.gitignore` 排除生成的 `artifacts/`、虚拟环境、构建产物、常见密钥文件、本地数据库、后台维护记录及个人准备笔记；文件仍留在本机。忽略规则不是秘密扫描，也不会自动移除已经被 Git 跟踪的内容。

需要额外人工检查的内容：

- `docs/BACKGROUND_PROGRESS.md` 与研究登记：可能含任务协调、时间线或本地路径，不直接当作发布说明；
- `supply-chain/registry.json`：开发机清单是否适合公开，许可阻断是否如实保留；
- 学习笔记、截图和示例：只保留可重生成的合成内容；
- 历史提交：即使工作区已删除敏感值，旧提交中也可能仍然存在。

截图或小型基准确需展示时，单独审查后放入公共示例目录，注明生成方法与限制。不要强制加入整个 `artifacts/`。

## 内容与验证

- [ ] README 的安装命令已在拟发布版本验证，不使用个人绝对路径；
- [ ] Web、SQLite 和领域层的能力分别描述，未接入的功能不写成可用；
- [ ] 已知缺陷仍可见，未将本地测试写成 GitHub CI 已通过；
- [ ] Python 3.11 / 3.13 测试及编译检查有对应记录；
- [ ] OCR 改动有本地合成基准，Web 改动有浏览器记录；
- [ ] Markdown 链接、Issue 表单和 PR 模板已检查；
- [ ] 供应链失败单独报告，未伪造许可证或性能数据；
- [ ] 项目仅使用合成数据，独立于任何企业，不暗示企业委托、生产部署或监管验证。

公开动作由作者确认后单独执行；本清单不授权 commit、push 或创建远程仓库。

## 本次文档结构参考

2026-08-27 查阅，借鉴信息组织，不复制正文或引入依赖：

| 来源 | 参考点 | 边界 |
| --- | --- | --- |
| [pdfplumber](https://github.com/jsvine/pdfplumber)（[MIT](https://github.com/jsvine/pdfplumber/blob/stable/LICENSE.txt)） | 开头交代适用范围，先给最小示例，再链接详细功能 | 不借用其功能或维护者声明 |
| [Docling](https://github.com/docling-project/docling)（[MIT](https://github.com/docling-project/docling/blob/main/LICENSE)） | 快速开始、文档入口与贡献说明分开 | 不添加不存在的包发布、社区或徽章 |
| [Tesseract](https://github.com/tesseract-ocr/tesseract)（[Apache-2.0](https://github.com/tesseract-ocr/tesseract/blob/main/LICENSE)） | 安装、使用、支持和许可有明确入口 | OCR 引擎许可不覆盖语言数据或本项目 |

社区文件的位置与链接方式参考 [GitHub README 文档](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes)和 [Issue 表单语法](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/syntax-for-issue-forms)。这些参考不是依赖、背书或合规证明。
