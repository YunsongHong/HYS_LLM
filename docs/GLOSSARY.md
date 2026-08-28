# ParamGuard Vision 新手词典

> 这是一张“随时回来查”的地图，不是需要背诵的考试范围。前台课程仍会一次只解释一个概念。

## 最基础的开发词

| 词 | 最简单的意思 | 在本项目里的例子 |
|---|---|---|
| 代码（code） | 写给计算机看的、非常精确的步骤 | “只有左右两个非空字符串逐字符相同才算 exact” |
| 程序（program） | 一组可以运行的代码 | 本地 Web 审核页面、OCR benchmark |
| Python | 我们选择的编程语言 | `src/paramguard/comparison.py` 是 Python 文件 |
| VS Code | 用来查看、修改和运行代码的编辑器 | 你截图里已经打开的应用 |
| Terminal / 终端 | 用文字命令让电脑做事的窗口 | 输入 `pwd` 查看“我现在在哪个文件夹” |
| 路径（path） | 一个文件或文件夹在电脑上的地址 | 项目目录、图片文件地址 |
| 文件（file） | 保存代码、文字、图片或数据的单位 | `README.md`, `photo_a.png` |
| 文件夹（directory/folder） | 用来组织多个文件的容器 | `src`, `tests`, `docs` |
| 模块（module） | 可以被其他 Python 代码导入的一份 `.py` 文件 | `comparison.py`, `workflow.py` |
| `import` | 在当前代码中使用另一个模块提供的东西 | Web 层导入 workflow，而不是复制状态机 |
| 函数（function） | 有名字、接收输入并产生结果的一段步骤 | `compare_values(left, right)` |
| 类（class） | 描述一类对象应有哪些数据和行为的蓝图 | `ReviewTask` 是审核任务的蓝图 |
| 对象（object） | 按某个 class 创建出来的具体实例 | task ID 为某个值的一项审核任务 |
| 枚举（enum） | 只能从固定选项里选一个值 | `SAME / DIFFERENT / UNABLE_TO_JUDGE` |
| 异常（exception） | 程序发现不能安全继续时发出的明确失败信号 | 少一个字段就拒绝锁定 |

## 前端、后端和数据词

| 词 | 最简单的意思 | 在本项目里的例子 |
|---|---|---|
| 前端（frontend） | 人在屏幕上看到并操作的部分 | 并排图片、ROI、S/D/U 按钮 |
| 后端（backend） | 在界面背后真正检查规则和保存状态的部分 | 锁定前拒绝启动 AI |
| API | 前端或另一个程序调用后端时必须遵守的“点单格式” | 提交一个字段的 verdict、manifest hash 和 revision |
| HTTP | 浏览器与本地 Web 后端交换请求/响应的一套规则 | `POST /first-review/decision` |
| JSON | 用固定文本结构表达字段和值 | `{"verdict":"SAME"}` |
| Schema | JSON 或业务记录允许有哪些字段、每个字段是什么类型 | 拒绝未知字段、重复字段或数字冒充字符串 |
| DTO | 专门给某一个角色/页面返回的数据形状 | R1 锁前 DTO 不含任何 AI 字段 |
| 状态（state） | 一项任务此刻处于哪个阶段 | `HUMAN_REVIEW_OPEN` |
| 状态机（state machine） | 规定状态能按哪些顺序变化的规则 | 人工锁定后才能进入 AI queued/running/complete |
| 不可变（immutable） | 创建或锁定后不能偷偷原地覆盖 | Evidence Manifest、已锁定的人工快照 |
| revision / 版本号 | 每次修改后递增的编号，用来发现过期页面 | 两个并发请求拿同一 revision 时只能一个成功 |
| manifest / 清单 | 列出“本任务准确使用了哪些证据和版本”的冻结目录 | 左右图 SHA-256、Schema、模板、字段清单 |
| hash / 哈希 | 把内容变成固定长度指纹；内容变一点，指纹通常就不同 | 检出图片或模板被替换 |
| 审计轨迹（audit trail） | 按顺序记录谁、何时、做了什么、为什么 | 追加 JSONL 事件和前序哈希 |

## 图像、OCR、LLM 词

| 词 | 最简单的意思 | 在本项目里的权限边界 |
|---|---|---|
| 图像识别 / Computer Vision | 让程序从图片里检测结构或内容 | 检查尺寸/质量、裁出固定 ROI |
| ROI | 图片中只关注的一小块区域 | 温度值所在的矩形框 |
| OCR | 把图片里的字变成字符串 | 从 ROI 读取 `"37.0 C"` |
| confidence | 模型对一次识别的自报把握，不是真实概率保证 | 太低时只能拒答并升级 |
| LLM | 主要处理语言的大模型 | 可以把结构化异常整理成易读说明 |
| VLM | 同时接收图片和文字的视觉语言模型 | 锁后做辅助观察/challenger，不做最终判定 |
| prompt | 发给模型的任务说明和上下文 | 要求只返回字段观察，不允许输出“放行” |
| structured output | 要求模型输出满足固定 JSON Schema | 未知/缺失/重复字段会被后端拒绝 |
| hallucination / 幻觉 | 模型生成了看似合理但证据中不存在的内容 | 编造 parameter ID 必须 fail closed |
| prompt injection | 图片或文本里藏着“忽略规则”等恶意指令 | 证据只被当作不可信数据，输出仍受 schema 和本地检查约束 |
| deterministic / 确定性 | 同样输入一定得到同样结果 | 原始字符串比较由普通 Python 完成 |
| abstain / 拒答 | 系统承认“我不能安全判断” | 图片低质量、OCR 缺值时进入人工复核 |
| fail closed / 失败关闭 | 出错时停止并升级，而不是默认通过 | 审计写失败就不能产生最终决定 |

## 人工流程和验证词

| 词 | 最简单的意思 | 在本项目里的含义 |
|---|---|---|
| human-first | 人先在没有 AI 线索的情况下独立完成 | R1 全字段提交并锁定后 AI 才运行 |
| R1 | 第一位人工审核员 | 独立看 A 和 A' 的全部字段 |
| exception recheck | AI 运行后，只对检出的异常再次人工核对 | 面试题设中最直接的提速路径 |
| R2 | 第二位独立审核员 | 只有 SOP/风险明确需要时采用更严格的盲二审 |
| QA | 处理结构错误、系统错误或未解决异常的人工角色 | AI 不能替 QA 关闭异常 |
| unit test / 单元测试 | 单独验证一个小规则 | `-5.0` 与 `5.0` 必须不同 |
| integration test / 集成测试 | 验证几个模块真正连接在一起 | workflow → R2 → QA → audit final |
| E2E / 端到端测试 | 像用户一样走完整流程 | 浏览器首审、锁定、OCR、查看辅助结果 |
| adversarial test / 对抗测试 | 主动尝试绕过、伪造或输入坏数据 | 重复 JSON key、过期 revision、伪造 AI route |
| synthetic data / 合成数据 | 为测试虚构、由程序生成的数据 | `SYNTHETIC EQUIPMENT PANEL` 图片 |
| benchmark | 固定输入和指标，用来公平比较不同版本 | hidden/challenge split、差异召回、假阴性、拒答率 |
| PoC | 证明想法可做的原型，不是生产系统 | ParamGuard Vision 当前定位 |

## Git 与 GitHub

| 词 | 最简单的意思 |
|---|---|
| Git | 在本机记录代码每次变更历史的工具 |
| repository / repo | 一个由 Git 管理的项目文件夹 |
| commit | 给一组变更拍一张带说明的历史快照 |
| branch | 从某个历史点分出的一条开发线 |
| GitHub | 托管 Git 仓库、协作和运行 CI 的网站；它不等于 Git 本身 |
| CI | 每次代码变化后自动运行测试的流程 |

记不住完全正常。真正的学习方式是：先亲手运行一个最小命令，再读一小段代码、改一个输入、看到一个测试为什么通过或失败。
