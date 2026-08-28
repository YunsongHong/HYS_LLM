# ParamGuard Vision：从零开始的亲手学习路线

> 适用对象：第一次系统做 LLM/视觉项目的计算机研究生。后台参考实现可以继续完善，但**后台已经写好的代码不等于你已经学会**。前台一次只做一课；当前只从第 0 课开始。

## 1. 我们到底用什么代码写

核心代码使用 **Python 3.11+**，在 **VS Code** 中编辑，通过 **Terminal** 运行。以后本地页面会遇到少量 HTML/CSS/JavaScript，数据会用 JSON，文档会用 Markdown；现在不用一起学。

先把四个东西分开：

- VS Code：写和看文件的工作台；
- Python：执行 `.py` 文件的程序；
- Terminal：输入命令的地方；
- 项目文件夹：代码、测试、图片和文档所在的位置。

第 0 课的现成说明在 [LEARNING_00.md](./LEARNING_00.md)。本路线不会直接把你扔进 OCR 或 LLM API。

## 2. 每一课怎样才算真的完成

一课只有同时满足以下条件才算完成：

1. 最小代码由你亲手逐行输入，不直接复制后台完整实现；
2. 你亲手运行验证命令，并能区分预期输出与报错；
3. 至少主动改坏一次输入或规则，看到测试为何失败；
4. 不看文档，用自己的话回答本课“能解释的问题”；
5. 将日期、文件、命令、实际结果和自己的解释记入学习记录。

建议以后创建 `student_work/` 作为个人练习区。它现在不需要由后台代写；每一课开始时再由你亲手创建相应文件。后台模块位于 `src/paramguard/`，可在完成自己的最小版本后用于对照，不能先复制再冒充理解。

学习记录可以使用这个模板：

```text
日期：
课程：
我亲手写的文件：
我运行的命令：
预期结果：
实际结果：
我主动制造的失败：
我对失败原因的解释：
还不会的问题：
```

## 3. 第一阶段：先会让 Python 听懂你

### 第 0 课：VS Code、Terminal、路径和第一行 Python

- **学习目标**：知道“用 Python 写”是什么意思；让终端站在正确项目目录；区分 Python 代码和 shell 命令。
- **本人需亲手写的最小代码**：在 VS Code 创建 `student_work/lesson00_hello.py`，只写：

  ```python
  print("ParamGuard Vision: Python is running")
  ```

- **验证命令**：

  ```bash
  # 在 VS Code 中打开仓库根目录，再打开终端。
  pwd
  python3 --version
  python3 student_work/lesson00_hello.py
  ```

- **能解释的问题**：VS Code、Python、Terminal 和项目文件夹分别是什么？为什么截图中的 `demo.py not found` 是路径问题，而不是 Python 语法问题？
- **不得跳过的门槛**：你能不看提示进入正确目录，把输出文字改成自己的句子，再次运行并看到变化。没有做到时不进入第 1 课。

### 第 1 课：字符串为什么是这个项目的证据

- **学习目标**：理解字符串、变量和 `==`；知道屏幕上的 `001`、`1.0`、`1.00` 不能先变成数字。
- **本人需亲手写的最小代码**：创建 `student_work/lesson01_strings.py`：

  ```python
  left_raw = "1.0"
  right_raw = "1.00"

  print(left_raw)
  print(right_raw)
  print(left_raw == right_raw)
  ```

- **验证命令**：

  ```bash
  python3 student_work/lesson01_strings.py
  ```

- **能解释的问题**：为什么数学上相等的显示值在这个需求中仍可能不完全一致？为什么 `001` 必须写成带引号的字符串？
- **不得跳过的门槛**：先预测、再运行 `"-0.5" == "0.5"`、`"001" == "1"` 和 `"AUTO" == "auto"`，三次都能解释输出。

### 第 2 课：把规则装进函数

- **学习目标**：理解函数、参数、返回值、`if` 和异常；写出“只有两个非空字符串逐字符相同才算 exact”的最小版本。
- **本人需亲手写的最小代码**：创建 `student_work/lesson02_exact.py`：

  ```python
  def exact_nonempty(left: str | None, right: str | None) -> bool:
      if left is not None and not isinstance(left, str):
          raise TypeError("left must be str or None")
      if right is not None and not isinstance(right, str):
          raise TypeError("right must be str or None")
      if left is None or right is None:
          return False
      if left.strip() == "" or right.strip() == "":
          return False
      return left == right


  print(exact_nonempty("37.0 °C", "37.0 °C"))
  print(exact_nonempty("1.0", "1.00"))
  print(exact_nonempty(None, None))
  ```

- **验证命令**：

  ```bash
  python3 student_work/lesson02_exact.py
  ```

- **能解释的问题**：为什么先检查类型和缺失值？为什么两个 `None` 不能算完全一致？`return left == right` 为什么必须放在缺失检查之后？
- **不得跳过的门槛**：你能自己增加纯空格、数字 `1`、Unicode 微符号三种输入，并在运行前说明会返回什么或抛出什么错误。

### 第 3 课：让测试替你抓回归

- **学习目标**：理解测试的输入、预期输出和断言；知道“程序能运行”不等于规则正确。
- **本人需亲手写的最小代码**：创建 `student_work/test_lesson02_exact.py`，导入自己第 2 课的函数：

  ```python
  import unittest

  from lesson02_exact import exact_nonempty


  class ExactNonemptyTests(unittest.TestCase):
      def test_identical_nonempty_strings_match(self) -> None:
          self.assertTrue(exact_nonempty("AUTO", "AUTO"))

      def test_precision_difference_does_not_match(self) -> None:
          self.assertFalse(exact_nonempty("1.0", "1.00"))

      def test_two_missing_values_do_not_match(self) -> None:
          self.assertFalse(exact_nonempty(None, None))


  if __name__ == "__main__":
      unittest.main()
  ```

- **验证命令**：

  ```bash
  cd student_work
  python3 -m unittest test_lesson02_exact.py -v
  cd ..
  ```

- **能解释的问题**：一个测试的 arrange、act、assert 分别在哪里？如果把最后一个 `False` 故意改成 `True`，失败信息告诉了你什么？
- **不得跳过的门槛**：亲手制造一次红色失败，再修复为通过；另外添加负号差异测试。只看后台“全套测试通过”不算完成。

### 第 4 课：JSON、路径与合成参数

- **学习目标**：理解 JSON 是数据而不是 Python 代码；用 `Path` 打开文件；确认显示值作为字符串保留。
- **本人需亲手写的最小代码**：创建 `student_work/lesson04_json.py`：

  ```python
  import json
  from pathlib import Path

  data_path = Path("data/sample_pairs.json")
  payload = json.loads(data_path.read_text(encoding="utf-8"))
  first = payload["pairs"][0]

  print(first["parameter_id"])
  print(repr(first["left"]))
  print(type(first["left"]).__name__)
  ```

- **验证命令**：

  ```bash
  python3 student_work/lesson04_json.py
  ```

- **能解释的问题**：`Path` 为什么会受当前目录影响？`repr` 帮你看见了什么？为什么 JSON 中参数值不应写成不带引号的数字？
- **不得跳过的门槛**：能够故意从错误目录运行一次、看懂报错，再回到项目根目录成功运行；能够指出 [sample_pairs.json](../data/sample_pairs.json) 全部是合成示例而非公司数据。

## 4. 第二阶段：亲手重建项目的安全核心

### 第 5 课：使用并质疑严格比较器

- **学习目标**：把自己写的布尔函数与项目的结构化比较结果连接起来；理解“差异分类只用于解释”。
- **本人需亲手写的最小代码**：创建 `student_work/lesson05_project_compare.py`：

  ```python
  from paramguard import compare_values

  pairs = [
      ("1.0 bar", "1.00 bar"),
      ("10 mg", "10 μg"),
      ("AUTO", "AUTO"),
  ]

  for left, right in pairs:
      result = compare_values(left, right)
      print(repr(left), repr(right), result.exact_match, result.kind.value)
  ```

- **验证命令**：

  ```bash
  PYTHONPATH=src python3 student_work/lesson05_project_compare.py
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_comparison.py' -v
  ```

- **能解释的问题**：为什么 `FORMAT_DIFFERENCE` 仍然不能自动通过？为什么 `EXACT_MATCH` 不等于参数合法？`Decimal` 在这里只帮助解释什么？
- **不得跳过的门槛**：不用看源码，先为负号、前导零、单位、空值各写一个预期；再阅读 [comparison.py](../src/paramguard/comparison.py) 和 [LEARNING_01.md](./LEARNING_01.md) 对照自己的预测。

### 第 6 课：Enum 与“流程所在的格子”

- **学习目标**：理解枚举和状态；知道固定状态比任意字符串更安全。
- **本人需亲手写的最小代码**：创建 `student_work/lesson06_state.py`：

  ```python
  from enum import Enum


  class State(str, Enum):
      HUMAN_OPEN = "HUMAN_OPEN"
      HUMAN_LOCKED = "HUMAN_LOCKED"
      AI_RUNNING = "AI_RUNNING"


  state = State.HUMAN_OPEN
  print(state.value)
  state = State.HUMAN_LOCKED
  print(state.value)
  ```

- **验证命令**：

  ```bash
  python3 student_work/lesson06_state.py
  ```

- **能解释的问题**：状态机与页面按钮有什么区别？为什么不能接受用户随便传入一个新的状态字符串？
- **不得跳过的门槛**：画出自己版本的合法箭头，并明确指出 `HUMAN_OPEN → AI_RUNNING` 为什么不合法；再阅读 [LEARNING_02.md](./LEARNING_02.md)。

### 第 7 课：最小 human-first 状态机

- **学习目标**：让“人工锁定前 AI 不能运行”成为代码规则，而不是口头要求。
- **本人需亲手写的最小代码**：创建 `student_work/lesson07_task.py`，把第 6 课的 `State` 定义放在文件上方，再写：

  ```python
  class TinyTask:
      def __init__(self) -> None:
          self.state = State.HUMAN_OPEN

      def lock_human(self) -> None:
          if self.state is not State.HUMAN_OPEN:
              raise RuntimeError("human review cannot lock now")
          self.state = State.HUMAN_LOCKED

      def start_ai(self) -> None:
          if self.state is not State.HUMAN_LOCKED:
              raise RuntimeError("AI is blocked before human lock")
          self.state = State.AI_RUNNING
  ```

  再亲手写两个测试：锁前 `start_ai()` 必须失败；`lock_human()` 后才能成功。

- **验证命令**：

  ```bash
  cd student_work
  python3 -m unittest test_lesson07_task.py -v
  cd ..
  ```

- **能解释的问题**：为什么只在前端隐藏 AI 按钮不够？当锁前调用失败时，安全状态应保持在哪里？
- **不得跳过的门槛**：测试必须同时断言“抛出错误”和“状态没有副作用”；能口头说出至少三种锁前侧信道，例如颜色、排序、计数、响应字段或时长。

### 第 8 课：全字段完整性、原子锁定与 revision

- **学习目标**：理解集合完整性、原子性和过期客户端；模拟 1000+ 字段中“少一个都不能锁”。
- **本人需亲手写的最小代码**：先写一个纯函数，再给它写测试：

  ```python
  def missing_ids(expected: tuple[str, ...], answered: set[str]) -> set[str]:
      if len(expected) != len(set(expected)):
          raise ValueError("duplicate expected id")
      unknown = answered - set(expected)
      if unknown:
          raise ValueError("unknown answered id")
      return set(expected) - answered


  expected = tuple(f"P{i:04d}" for i in range(1001))
  answered = set(expected[:-1])
  assert missing_ids(expected, answered) == {"P1000"}
  ```

  然后在同一文件亲手写一个 CAS 小函数：只有 `expected_revision == current_revision` 才返回下一版本，否则抛错。

  ```python
  def next_revision(*, current_revision: int, expected_revision: int) -> int:
      if expected_revision != current_revision:
          raise RuntimeError("stale revision")
      return current_revision + 1
  ```

- **验证命令**：

  ```bash
  python3 student_work/lesson08_completeness.py
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_workflow.py' -v
  ```

- **能解释的问题**：为什么锁定必须全成或全败？两个浏览器页面同时拿着同一 revision 时，为什么只能一个写成功？
- **不得跳过的门槛**：亲手写出缺一项、重复 expected ID、未知 answered ID、stale revision 四个失败测试；能够指出项目参考实现位于 [workflow.py](../src/paramguard/workflow.py)，但不逐行照抄。

### 第 9 课：证据哈希和它做不到的事

- **学习目标**：理解 SHA-256 内容指纹、manifest 和版本绑定；同时知道哈希不证明来源真实。
- **本人需亲手写的最小代码**：创建 `student_work/lesson09_hash.py`：

  ```python
  from hashlib import sha256


  def digest(data: bytes) -> str:
      return sha256(data).hexdigest()


  original = b"synthetic-photo-A"
  changed = b"synthetic-photo-A-prime"
  print(digest(original))
  print(digest(changed))
  assert digest(original) != digest(changed)
  ```

- **验证命令**：

  ```bash
  python3 student_work/lesson09_hash.py
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_evidence.py' -v
  ```

- **能解释的问题**：内容改变为什么会使旧绑定失效？攻击者若一开始就提交错误图片并计算正确哈希，哈希为什么不能证明图片可信？
- **不得跳过的门槛**：能够画出 task → manifest → 两张图片/Schema/template 的绑定链，并说出“hash chain 不等于合法事件或不可篡改存储”。

## 5. 第三阶段：从图片到锁后人工异常队列

### 第 10 课：图片、像素与 ROI

- **学习目标**：理解图片是像素数据，ROI 是固定矩形区域；先使用项目生成的合成图片，不接触公司资料。
- **本人需亲手写的最小代码**：创建 `student_work/lesson10_image.py`：

  ```python
  from PIL import Image

  image = Image.open("artifacts/synthetic/clean-demo-001/photo_a.png")
  print(image.size)
  print(image.mode)
  ```

- **验证命令**：

  ```bash
  python3 student_work/lesson10_image.py
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_synthetic.py' -v
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_template.py' -v
  ```

- **能解释的问题**：固定 ROI 的坐标表示什么？如果图片旋转、透视或裁切，为什么不能假装原 ROI 仍可靠？
- **不得跳过的门槛**：能够在合成图片上读取尺寸，并指出当前固定模板不能代表真实相机、屏幕、反光和设备布局分布；参考 [PROJECT_SCOPE.md](./PROJECT_SCOPE.md)。

### 第 11 课：OCR 是观察者，确定性比较器才判断字符一致

- **学习目标**：理解 OCR 输入/输出以及 confidence 的限制；把两侧观察交给本地比较器。
- **本人需亲手写的最小代码**：先不用真正 OCR，模拟一次可能的 OCR 输出，创建 `student_work/lesson11_observation.py`：

  ```python
  from paramguard import compare_values

  left_ocr_observation = "025.0 L/min"
  right_ocr_observation = "25.0 L/min"

  result = compare_values(left_ocr_observation, right_ocr_observation)
  print(result.kind.value)
  print(result.exact_match)
  ```

- **验证命令**：

  ```bash
  PYTHONPATH=src python3 student_work/lesson11_observation.py
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_ocr.py' -v
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_vision_pipeline.py' -v
  ```

- **能解释的问题**：OCR confidence 为什么不是“正确概率保证”？OCR、比较器和最终人工各拥有什么权限？
- **不得跳过的门槛**：能解释低质量、空观察、字符差异各自为何要拒答或升级；不能说“OCR 判定参数相同”。

### 第 12 课：锁后路由与两种复核 profile

- **学习目标**：把风险信号映射到人工下一步；区分定向异常复核与全量盲 R2。
- **本人需亲手写的最小代码**：创建 `student_work/lesson12_route.py`，写一个只用于理解的纯函数：

  ```python
  def needs_human_exception_recheck(
      *, exact_match: bool, abstained: bool, low_quality: bool
  ) -> bool:
      return (not exact_match) or abstained or low_quality


  assert needs_human_exception_recheck(
      exact_match=False, abstained=False, low_quality=False
  )
  ```

- **验证命令**：

  ```bash
  python3 student_work/lesson12_route.py
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_review_policy.py' -v
  ```

- **能解释的问题**：为什么定向异常复核更省重复劳动？为什么全量盲 R2 的独立性更强但成本更高？为什么关键字段规则不能由项目替公司猜？
- **不得跳过的门槛**：读完 [PROCESS_PROFILES.md](./PROCESS_PROFILES.md)，能说明当前 profile 只是策略投影、Web 尚未完整接线；任何函数结果都不能命名为 `automatic_release`。

### 第 13 课：追加事件、CAS 与 fail closed

- **学习目标**：理解为什么不能覆盖旧记录；模拟 append-only 事件和 stale revision 拒绝。
- **本人需亲手写的最小代码**：创建 `student_work/lesson13_audit.py`：

  ```python
  def append_event(
      events: tuple[str, ...], *, current_revision: int, expected_revision: int, event: str
  ) -> tuple[tuple[str, ...], int]:
      if expected_revision != current_revision:
          raise RuntimeError("stale revision")
      return events + (event,), current_revision + 1


  history, revision = append_event(
      (), current_revision=0, expected_revision=0, event="R1_RECORDED"
  )
  print(history, revision)
  ```

- **验证命令**：

  ```bash
  python3 student_work/lesson13_audit.py
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_audit.py' -v
  ```

- **能解释的问题**：为什么更正应追加而不是覆盖？为什么哈希正确仍可能是语义上不可能的事件顺序？审计写失败时为什么不能继续完成最终状态？
- **不得跳过的门槛**：亲手增加一次 stale revision 测试并证明原 `history` 没变；能说出 JSONL+hash 缺少的生产控制，例如 WORM、可信时间或备份恢复。

### 第 14 课：Web 页面不是安全边界

- **学习目标**：理解前端、后端、API 和 DTO；设计 R1 锁前的最小 allowlist 响应。
- **本人需亲手写的最小代码**：创建 `student_work/lesson14_dto.py`：

  ```python
  def r1_prelock_view(task_id: str, answered: int, total: int) -> dict[str, object]:
      return {
          "task_id": task_id,
          "answered": answered,
          "total": total,
          "can_lock": answered == total,
      }


  view = r1_prelock_view("synthetic-task", 2, 3)
  forbidden = {"ai", "ocr", "confidence", "route", "risk", "result"}
  serialized = repr(view).lower()
  assert all(word not in serialized for word in forbidden)
  print(view)
  ```

- **验证命令**：

  ```bash
  python3 student_work/lesson14_dto.py
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_webapp.py' -v
  ```

- **能解释的问题**：为什么 CSS 隐藏已经下发的 AI 数据没有用？锁前除了 JSON 字段，还可能从哪些侧信道泄漏？
- **不得跳过的门槛**：能指出当前 Web 是 loopback 学习演示，没有真实认证/SSO/生产会话；阅读 [TRACEABILITY_MATRIX.md](./TRACEABILITY_MATRIX.md) 中 `URS-HF-002` 与 `URS-SEC-001` 的未关闭缺口。

### 第 15 课：风险指标与可重算 benchmark

- **学习目标**：区分差异召回、假阴性、未解决差异、拒答和升级召回；不被 overall accuracy 迷惑。
- **本人需亲手写的最小代码**：创建 `student_work/lesson15_metrics.py`，用一个明确标注为“玩具练习、不是项目性能”的列表计算计数：

  ```python
  truth_is_difference = [True, True, False]
  observations = ["DIFFERENT", "ABSTAIN", "SAME"]

  true_differences = sum(truth_is_difference)
  detected = sum(
      truth and observed == "DIFFERENT"
      for truth, observed in zip(truth_is_difference, observations)
  )
  false_negatives = sum(
      truth and observed == "SAME"
      for truth, observed in zip(truth_is_difference, observations)
  )

  print("toy only", true_differences, detected, false_negatives)
  ```

- **验证命令**：

  ```bash
  python3 student_work/lesson15_metrics.py
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_evaluation.py' -v
  PYTHONPATH=src python3 benchmark_demo.py
  ```

- **能解释的问题**：为什么 `ABSTAIN` 不是检出也不是假装相同？为什么高拒答可能很安全却没有效率价值？为什么每个数字必须附数据集、版本、样本数和限制？
- **不得跳过的门槛**：运行基准后，亲手打开生成的 `artifacts/evaluation/synthetic-benchmark-v1.json`，把它与 [VALIDATION_PLAN.md](./VALIDATION_PLAN.md) 区分为“当前运行证据”和“可能过期的文档快照”；生成文件不随仓库分发，不得说“零漏检”或外推真实工厂。

## 6. 第四阶段：最后才加入可选 LLM/VLM

### 第 16 课：结构化输出也必须按不可信输入处理

- **学习目标**：理解 VLM challenger、JSON schema、allowlist、拒答和 fake transport；知道 schema 只约束形状，不保证内容正确。
- **本人需亲手写的最小代码**：创建 `student_work/lesson16_vlm_schema.py`；先不联网、不使用密钥，只写一个最小输出 allowlist：

  ```python
  ALLOWED_KEYS = {
      "parameter_id",
      "left_observation",
      "right_observation",
      "abstain",
      "reason",
  }


  def validate_observation(row: dict[str, object]) -> None:
      extra = set(row) - ALLOWED_KEYS
      if extra:
          raise ValueError(f"unknown keys: {sorted(extra)}")


  validate_observation(
      {
          "parameter_id": "P0001",
          "left_observation": "1.0",
          "right_observation": "1.00",
          "abstain": False,
          "reason": "",
      }
  )
  ```

  再增加一个含 `"release": True` 的恶意 row，证明它被拒绝。

- **验证命令**：

  ```bash
  python3 student_work/lesson16_vlm_schema.py
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_vlm.py' -v
  ```

- **能解释的问题**：为什么 VLM 只能在 R1 和本地 OCR 完成后运行？为什么严格 JSON schema 仍不能证明图片里的字符读对了？为什么 `store: false` 不等于零保留？
- **不得跳过的门槛**：读完 [LLM_COMPONENT.md](./LLM_COMPONENT.md)，能画出“VLM observation → 严格解析 → 本地 `compare_values` → 人工异常路径”；不配置真实 API key，不上传任何真实公司截图，也不把离线测试说成真实模型性能。

## 7. 第五阶段：从空白处重建并接受追问

### 第 17 课：个人 capstone 与面试准入

- **学习目标**：把已学的小模块在一个全新的练习目录中重新连接，不依赖记住仓库代码；明确自己真正拥有的贡献。
- **本人需亲手写的最小代码**：从空白目录重建一个小型合成任务，至少包含：三个参数、R1 全字段锁定、锁前 AI 失败、模拟 OCR 原始字符串、确定性比较、锁后异常列表，以及 `final_decision = None` 直到人工函数被调用。可以先用下面的骨架开始，但每个函数必须由你根据前面课程补完，并为每条不变量写测试：

  ```python
  expected_ids = ("P0001", "P0002", "P0003")
  r1_decisions: dict[str, str] = {}
  r1_locked = False
  final_decision: str | None = None


  def lock_r1() -> None:
      ...


  def run_auxiliary_check() -> list[str]:
      ...


  def record_final_human_decision(decision: str) -> None:
      ...
  ```
- **验证命令**：先运行自己的 capstone 测试，再运行仓库回归：

  ```bash
  python3 -m unittest discover -s student_work/capstone/tests -v
  PYTHONPATH=src python3 -m unittest discover -s tests -v
  PYTHONPATH=src python3 -m compileall -q src tests
  ```

- **能解释的问题**：在五分钟内从问题、信任边界、状态门、OCR、确定性比较、人工路由、VLM challenger、评估到生产缺口完整讲清；面对追问能指出代码和测试，而不是只复述术语。
- **不得跳过的门槛**：让另一个人随机删除一个判断、改变一张合成图片、提交 stale revision、插入未知 VLM 字段或让 AI 尝试放行；你必须能预测失败位置、运行测试、定位并修复。介绍自己的工作时，按[项目声明与限制](./CLAIMS_AND_LIMITATIONS.md)区分已经亲手验证的能力与尚未实现的功能。

## 8. 学习顺序中的硬性边界

- **不要从 API key 开始**：没有 Python、测试、状态和边界知识时，先调用模型只会得到一个无法验证的演示。
- **不要跳过 OCR + 确定性基线**：VLM 是可选 challenger；关掉 VLM 后，核心流程仍应工作。
- **不要用真实公司资料练习**：所有图片、字段和任务只用明确标记的合成数据。
- **不要把测试通过说成合规**：工程测试不是 GxP、Part 11、Annex 11 或组织级验证。
- **不要把后台实现算作本人能力**：只有亲手输入、主动破坏、修复、解释并能从空白重建的内容，才可以进入个人简历叙事。
- **不要追求一次学完**：每次只完成当前一课的门槛。遇到错误时保留错误文本，因为“看懂一次失败”往往比复制十段成功代码更有价值。

## 9. 现在真正要做的只有第 0 课

现在先不要运行 OCR、benchmark、Web 或 VLM 测试。打开 VS Code 的 Terminal，只确认：

```bash
# 在 VS Code 中打开仓库根目录，再打开终端。
pwd
```

输出正确后，再由你亲手创建 `student_work/lesson00_hello.py`，写一行 `print(...)`。完成并能解释路径后，我们才进入第 1 课。后台项目继续推进，不会把你的学习节奏往前拖。
