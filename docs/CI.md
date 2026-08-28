# ParamGuard Vision 持续集成（CI）

## 1. CI 会做什么

`.github/workflows/ci.yml` 在 push、pull request 或人工触发时，用 Python 3.11 和 3.13 分别执行：

1. 取出触发这次运行的精确代码 revision；
2. 安装项目声明的 Python 依赖；
3. 从已安装的 package 读取 `static/paramguard.html`，防止本地源码里有页面、但 wheel 漏打包静态资产；
4. 用 `compileall` 检查全部源码和测试能否被 Python 解析；
5. 运行 `tests/` 下的全部单元、对抗和集成测试。

项目声明支持 Python 3.11 及以上，因此同时测试最低支持版本和当前开发版本，可以更早发现“只在我电脑上可用”的问题。

## 2. 为什么这样配置

- workflow 只有 `contents: read` 权限，不需要写仓库、创建 release 或读取部署密钥。
- 不使用 `pull_request_target`，避免在带有基础仓库高权限的上下文中执行不受信任的 fork 代码。
- checkout 设置 `persist-credentials: false`，测试步骤不需要保留 GitHub token 的 Git 凭据。
- GitHub Actions 使用完整 commit SHA，而不是只写可移动的 major tag；旁边的注释保留已核验 release 名称，便于人工升级。
- 每个 job 有时间上限；同一分支出现更新时取消旧运行，减少无意义资源消耗。
- 没有配置任何 OpenAI、公司系统或云服务密钥；VLM 测试只能走注入的 fake transport，CI 不应发送图片到外部网络。
- Web HTML 通过 `tool.setuptools.package-data` 显式入包，CI 从已安装 distribution 而非 `src/` 路径验证该资产。这只证明文件被打包，不证明 Web 安全或部署合格。

截至 2026-08-25，所用官方 release 为：

- [actions/checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1)，固定 commit `3d3c42e5aac5ba805825da76410c181273ba90b1`；
- [actions/setup-python v7.0.0](https://github.com/actions/setup-python/releases/tag/v7.0.0)，固定 commit `5fda3b95a4ea91299a34e894583c3862153e4b97`。

“固定 SHA”降低 tag 被移动的风险，但不会自动证明 action 或其供应链没有漏洞。升级仍需查看官方 release、安全公告和 commit，再更新固定值并重新运行全部测试。

## 3. CI 明确没有证明什么

GitHub 托管 runner 上的测试成功不代表：

- 本机真实 Tesseract、tessdata 和 native 库与登记版本完全一致；
- OCR 对真实工厂图片达到可接受性能；
- 外部 VLM API 已经运行或适合上传真实数据；
- 项目已经获得 GxP、21 CFR Part 11、EU Annex 11 或企业验证；
- 代码可以写入 MES/DCS/SCADA/PLC/LIMS 或自动放行。

真实本地 OCR 集成测试在 runner 没有安装 Tesseract 时会明确 `skip`，不会伪装成已执行。完整的本机供应链检查仍要运行：

```bash
PYTHONPATH=src python3 -m paramguard.supply_chain
```

当前开发机因为额外安装的 `snum.traineddata` 上游许可证未知而预期返回 `FAIL`。CI 的普通测试全绿不能覆盖或消除这个独立阻断项。

## 4. 仍需改进

- 当前 `pyproject.toml` 使用受控版本范围，还没有包含 wheel SHA-256 的跨平台 lock 文件；安装步骤因此不是完全可复现构建。
- 尚未加入独立 secret/PII 扫描、SAST、依赖漏洞扫描、完整 SBOM、构件签名或 provenance attestation。
- 尚未建立受控 runner 镜像来固定 Tesseract、`eng.traineddata` 和 native 库。
- 仓库目前没有选择对外发布许可证；在公开发布或接收贡献前应由用户明确选择，而不是由自动化工具替用户作法律决定。

这些是下一阶段的供应链/发布工程工作，不应通过给 workflow 增加一个“绿色徽章”来掩盖。
