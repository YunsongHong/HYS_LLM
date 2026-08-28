# ParamGuard Vision 最小供应链与许可证清单

## 1. 先说结论

本项目现在有一份可机器检查的最小供应链注册表：`supply-chain/registry.json`。它覆盖当前实际使用或本机 Tesseract 明确报告的运行资产，但它**不是完整 SBOM**，也不是法律意见。

当前清单会有意识地检查失败，原因不是程序错误，而是本机安装的 `snum.traineddata` 来源仓库没有可确认的许可证。它虽然不是 ParamGuard 当前 `eng` OCR 配置的必需资产，但只要它仍在受控运行环境中，检查器就不会把 `UNKNOWN` 伪装成通过。

## 2. 这份清单包含什么

| 类别 | 当前观测 | 关系 | 许可证结论 |
|---|---|---|---|
| Python 运行时 | CPython 3.13.2 | 项目运行前提 | `PSF-2.0`（主许可证） |
| Python 直接依赖 | Pillow 12.2.0 | `pyproject.toml` 唯一直接运行依赖 | `MIT-CMU` |
| Pillow 内嵌资产 | Aileron Regular 子集 1.102 | `ImageFont.load_default(size=...)` 使用 | `CC0-1.0` |
| OCR 引擎 | Tesseract CLI 5.5.1 | OCR 运行前提 | `Apache-2.0` |
| OCR 模型数据 | `eng`、`osd`、`snum` | 本机 `--list-langs` 可见 | `eng/osd`: `Apache-2.0`；`snum`: `UNKNOWN` |
| 主要 native 库 | Leptonica、giflib、libjpeg-turbo、libpng、libtiff、zlib、libwebp、OpenJPEG、libarchive、libcurl | Tesseract 自报的图像/归档/网络运行面 | 逐项记录在 registry |

“当前观测”不等于“永久锁定”。升级 Python、Pillow、Tesseract、Homebrew 配方或 macOS 后，应重新生成观测证据，而不是为了让检查变绿而盲目改版本号。

## 3. 许可证和来源是怎样核验的

核验日期是 2026-08-25。注册表保存了每个组件的官方源码/版本链接、官方许可证链接、本地版本的获取方法和完整性记录。这里只总结关键证据，不复制第三方代码或整段许可证文本。

- CPython：[3.13.2 源码](https://github.com/python/cpython/tree/v3.13.2) 和 [CPython LICENSE](https://github.com/python/cpython/blob/v3.13.2/LICENSE)。上游文件说明 Python 软件与文档使用 Python Software Foundation License Version 2，同时也列出历史代码和内含组件的其他条款。因此 registry 记录主 SPDX `PSF-2.0`，不声称它覆盖 CPython 源码树内每个文件。
- Pillow：[Pillow 12.2.0](https://github.com/python-pillow/Pillow/tree/12.2.0) 与 [Pillow LICENSE](https://github.com/python-pillow/Pillow/blob/12.2.0/LICENSE) 确认项目主许可证为 `MIT-CMU`。安装包携带的 license bundle 可能包含编解码器等附加通知，如果将 wheel 随产品分发，应保留并单独复核这份 bundle。
- Tesseract：[Tesseract 5.5.1](https://github.com/tesseract-ocr/tesseract/tree/5.5.1) 和 [LICENSE](https://github.com/tesseract-ocr/tesseract/blob/5.5.1/LICENSE) 确认 `Apache-2.0`。Tesseract 自身也明确提醒，它的依赖可以使用不同的许可证，所以不能把 Tesseract 的 Apache 许可证直接套在 Leptonica 或编解码器上。
- `eng` 和 `osd`：本机哈希与 [tessdata_fast 4.1.0](https://github.com/tesseract-ocr/tessdata_fast/tree/4.1.0) 包资源哈希一致，该仓库的 [LICENSE](https://github.com/tesseract-ocr/tessdata_fast/blob/4.1.0/LICENSE) 为 `Apache-2.0`。
- `snum`：包配方指向 [USCDataScience 仓库的固定 commit](https://github.com/USCDataScience/counterfeit-electronics-tesseract/blob/319a6eeacff181dad5c02f3e7a3aff804eaadeca/Training%20Tesseract/snum.traineddata)，但仓库根目录没有可核对的 LICENSE，GitHub 仓库元数据也未识别许可证。“可以下载”不等于“可以再分发”，所以必须标记 `UNKNOWN / NEEDS_REVIEW`。

Native 库使用各项目的版本化官方文件核对：

- [Leptonica 1.85.0 license](https://github.com/DanBloomberg/leptonica/blob/1.85.0/leptonica-license.txt)：`BSD-2-Clause`。
- [giflib 项目](https://giflib.sourceforge.net/) 与 [SourceForge 5.2.2 COPYING](https://sourceforge.net/p/giflib/code/ci/5.2.2/tree/COPYING?format=raw)：`MIT`。
- [libjpeg-turbo 3.0.4 LICENSE](https://github.com/libjpeg-turbo/libjpeg-turbo/blob/3.0.4/LICENSE.md)：上游 roll-up 文件同时说明 `IJG`、`Zlib` 与 `BSD-3-Clause` 的适用范围，不能只记成 MIT 或单一 BSD。
- [libpng 1.6.58 LICENSE](https://github.com/pnggroup/libpng/blob/v1.6.58/LICENSE)：`libpng-2.0`。
- [libtiff 4.7.0 LICENSE](https://gitlab.com/libtiff/libtiff/-/blob/v4.7.0/LICENSE.md)：`libtiff`。
- [zlib 1.2.12 zlib.h](https://github.com/madler/zlib/blob/v1.2.12/zlib.h)：`Zlib`。
- [libwebp 1.5.0 COPYING](https://github.com/webmproject/libwebp/blob/v1.5.0/COPYING)：`BSD-3-Clause`。GitHub 仓库是上游指定的官方镜像，canonical 源在 Chromium Gitiles。
- [OpenJPEG 2.5.3 LICENSE](https://github.com/uclouvain/openjpeg/blob/v2.5.3/LICENSE)：`BSD-2-Clause`。上游已在 README 中把该仓库标成 unmaintained，这是维护/安全风险，不是许可证变更。
- [libarchive 3.8.0 COPYING](https://github.com/libarchive/libarchive/blob/v3.8.0/COPYING)：主体默认记录为 `BSD-2-Clause`，但官方文件明确说个别源文件的声明才是最终控制条款。
- [curl 8.7.1 COPYING](https://github.com/curl/curl/blob/curl-8_7_1/COPYING)：SPDX `curl`。当前只记录 Tesseract 自报的包级版本；操作系统厂商补丁的精确源码来源不在这份最小清单中。

## 4. Aileron 为什么要单独记一条

ParamGuard 的合成图像代码调用 `ImageFont.load_default(size=...)`。Pillow 的实现不是调用 macOS 字体，而是解码 `ImageFont.py` 内的 Aileron Regular 子集。因此，只记“Pillow / MIT-CMU”会丢失一个真实的运行资产边界。

[Pillow PR #7354](https://github.com/python-pillow/Pillow/pull/7354) 记录了来源和修改方式：维护者把 Aileron 作为 CC0 字体引入，删减字符后转换为 TTF 并内嵌。本机解码后的 OpenType name table 显示版本 1.102、设计者 Sora Sagano 与 `No Rights Reserved`，且字节 SHA-256 已写入 registry。

边界要说清：

- Pillow 代码仍是 `MIT-CMU`，不是 CC0。
- 内嵌 Aileron 子集单独记为 `CC0-1.0`。
- ParamGuard 目前输出的是合成 PNG 中的栅格化字形，不是拷贝一份独立 TTF/OTF 文件。
- 如果以后改成直接打包字体文件，这是新的分发场景，必须重新审查，不能直接沿用当前结论。

## 5. 检查器保证什么

检查器在 `src/paramguard/supply_chain.py`，不安装任何新包。它使用 Python 标准库完成以下检查：

1. registry 顶层、组件和 integrity 对象必须精确匹配固定 schema；多字段或少字段都拒绝。
2. 重复 ID、空字段、非布尔值、非 HTTPS 来源、非法 SHA-256、未审核的枚举值和未审核 SPDX 标识符全部拒绝。
3. `UNKNOWN` license 必须与 `NEEDS_REVIEW` 一起出现，而且两者都会使最终状态为 `FAIL`。
4. `pyproject.toml` 的每个 `project.dependencies` 直接依赖都必须有 `DIRECT_DEPENDENCY` 记录；过期的直接依赖标记也会失败。
5. 本机可用时，会比对 CPython、Pillow、Tesseract 版本，已记录的可哈希资产，Tesseract 可见语言集，以及 Tesseract 自报的主要 native 库集和版本。
6. 如果 Tesseract 不存在或无法执行，它返回 `SKIP` 诊断和 `INCOMPLETE`，不会说“已通过”。
7. JSON 报告不回显输入路径、用户名或本机绝对路径。registry 中如果出现常见本地绝对路径，也会拒绝。

它不会：

- 解析任意复杂 SPDX 表达式；当前只允许这份项目已人工复核的小型 SPDX 白名单。
- 证明一个 native 二进制的所有源文件和构建选项。`VERSION_REPORT_ONLY` 的意思就是只有引擎自报版本，还没有单独二进制哈希/来源证明。
- 枚举 Pillow wheel 内的每个可选 codec，也不枚举 libarchive 与操作系统的完整递归依赖树。
- 代替安全漏洞扫描、律师审查、组织的开源审批或受控环境的发布流程。

## 6. 怎样运行

在项目根目录执行：

```bash
PYTHONPATH=src python3 -m paramguard.supply_chain
```

当前预期结果是 `FAIL`，且诊断精确指向 `tessdata-snum` 的 `UNKNOWN_LICENSE` 与 `COMPONENT_NEEDS_REVIEW`。如果还看到版本、哈希、语言集或 native 库集不一致，说明运行环境已经漂移，需要复核后更新 registry。

只检查 schema 和 `pyproject.toml` 覆盖关系：

```bash
PYTHONPATH=src python3 -m paramguard.supply_chain --skip-runtime
```

`--skip-runtime` 不会将未检查的本机状态冒充为通过；如果没有其他错误，结果是 `INCOMPLETE`。

返回码：

- `0`：`PASS`，schema、直接依赖、许可证状态与所需本地检查全部通过。
- `1`：`FAIL`，存在一个或多个阻断错误。
- `2`：`INCOMPLETE`，没有已知阻断错误，但一个或多个运行检查被跳过。

单元和对抗测试：

```bash
PYTHONPATH=src python3 -m unittest tests.test_supply_chain -v
python3 -m compileall -q src/paramguard/supply_chain.py tests/test_supply_chain.py
```

## 7. 怎样处理当前 `snum` 阻断项

推荐的工程处理是建立一个受控 OCR 运行环境，只安装 ParamGuard 真正调用的 `eng` 模型（如果之后确实启用方向/脚本检测，再显式加入 `osd`）。另一条可接受路径是从 `snum` 权利人或可验证上游获得清晰的许可证证据。

不应采取的做法是：

- 因为这个模型“没有被主动调用”就把它从本机清单中隐藏。
- 仅依据搜索引擎、第三方镜像或文件名推测一个 SPDX 标识符。
- 将另一个 tessdata 仓库的 Apache-2.0 许可证套用到这个来源不同的 `snum` 文件。

## 8. 升级时的人工复核步骤

1. 先通过运行时自报、Python package metadata 和实际文件哈希记录“本机有什么”。
2. 定位与观测版本对应的官方 tag/commit，不用未锁定的 `main` 页面代替版本证据。
3. 阅读官方 LICENSE/COPYING 和 package-level 说明；多许可证项目必须记录正确表达式和适用边界。
4. 对模型、字体等非代码资产单独复核，不默认继承宿主包的许可证。
5. 更新观测版本、哈希、来源获取方式和 `verified_on`，再运行检查器和全部测试。
6. 如果仍无法精确确认，如实写 `UNKNOWN / NEEDS_REVIEW`；由人决定移除、替换、隔离或获得正式批准。

## 9. 明确的范围限制

这份清单的价值是“让已知依赖、资产边界和未解决问题可见、可测、可阻断”。它没有生成 SPDX/CycloneDX SBOM，没有枚举操作系统 framework，没有追溯每个 Homebrew bottle 的建造证明，也没有对所有递归依赖进行文件级 license scanning。

在真实企业或受监管部署前，还需要组织的开源审批、完整 SBOM、软件成分分析、漏洞管理、可复现构建/签名证明、安装包通知保留和法务审查。
