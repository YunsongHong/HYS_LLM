# SQLite 持久化 P1

## 这一步做了什么

这是一个**本地学习 PoC** 的第一段持久化层，只保存：

1. 明确标记为 `SYNTHETIC` 的 Evidence Manifest 与 Pipeline Spec；
2. 冻结的 1,001+ 参数顺序、两份证据摘要和 R1 服务端指派；
3. R1 对每个字段的逐次修订；
4. 全字段完整后的一次原子 R1 锁；
5. 每条命令的持久化幂等 receipt，以及同一事务中的 audit outbox 行。

它**没有**实现 AI 排队/OCR、定向复核、盲 R2、QA、最终批准、电子签名或放行。因此，本模块不会改变现有 human-first 规则，更不可能从数据库直接自动放行。

代码入口是：

- `src/paramguard/canonical_json.py`
- `src/paramguard/db.py`
- `src/paramguard/sqlite_repository.py`
- `src/paramguard/migrations/0001_initial.sql`

## 为什么默认使用 DELETE，而不是 WAL

SQLite 的普通原子提交机制使用 rollback journal；WAL 是另一个显式可选模式。[SQLite WAL 官方说明](https://www.sqlite.org/wal.html) 在 2026 年补充了 “WAL-reset bug”：该竞争条件可能影响 3.7.0 至 3.51.2，在多连接同时写入/检查点的很窄时序下可能造成损坏；官方列出的修复版本包括 3.51.3+，以及 3.44.6、3.50.7 回移版本。

本机两个测试解释器链接的 SQLite 并不相同：

| Python | 本次实测 SQLite | 本项目选择 |
|---|---:|---|
| 3.13.2 | 3.49.1 | WAL 门禁拒绝；只能用 DELETE |
| 3.11.15 | 3.53.2 | 已含修复，但仍须调用方明确 `journal_mode="WAL"`；默认仍是 DELETE |

这不是说 “WAL 永远不安全”，也不是把 SQLite 的低概率缺陷夸大成必然损坏。这里的决定很窄：当前 PoC 不需要用额外并发吞吐换取新的运行条件，所以选择更容易解释和恢复演练的 rollback journal。WAL 是否可用只依据 SQLite 官方的修复说明进行版本门禁，不依据博客或二手文章。

连接逐项设置并回读：

- `journal_mode=DELETE`（默认）；
- `synchronous=EXTRA`；
- `foreign_keys=ON`；
- `busy_timeout=5000` 毫秒；
- `trusted_schema=OFF`；
- `recursive_triggers=ON`。

[SQLite PRAGMA 官方说明](https://www.sqlite.org/pragma.html#pragma_synchronous)指出，rollback journal 的 `EXTRA` 在 `FULL` 基础上还会同步删除 journal 后的目录项，从而提高紧邻断电场景的耐久性。它仍不等于对所有硬件、文件系统、虚拟化层和磁盘缓存组合做出了保证。

## 为什么明确写 `isolation_level=None`

Python 3.11 与 3.13 的 `sqlite3` 事务 API 有演进。这里在两条 Python 线上都显式使用 `isolation_level=None`，让底层保持 SQLite autocommit，然后由仓库明确执行：

```text
BEGIN IMMEDIATE
  检查持久化 command receipt；重建已提交请求绑定后返回精确重试
  检查服务端 task / assignment / manifest / revision
  写领域行
  UPDATE tasks ... WHERE revision = ? AND state = ?   # SQL CAS
  写 canonical receipt
  写 audit outbox
COMMIT
```

事务主体或最终 `COMMIT` 抛错时都要 `ROLLBACK`。[SQLite 事务官方说明](https://sqlite.org/lang_transaction.html)说明 `BEGIN IMMEDIATE` 会立即开始写事务；若已有写事务，可能返回 `SQLITE_BUSY`。同一说明也明确：`COMMIT` 因 `SQLITE_BUSY` 失败时事务仍保持活动，稍后可以重试。因此不能只包住事务主体、让失败的 `COMMIT` 落在异常清理之外。本项目设置有限的 busy timeout，并用两进程测试证明同一旧 revision 不会产生两个赢家。

`immediate_transaction()` 与自持的 `consistent_read_transaction()` 现在共同使用一个提交边界：先确认事务没有被调用方提前结束，再执行 `COMMIT`；若提交失败且连接仍在事务中，先显式 `ROLLBACK`，再传播提交错误。合成回归覆盖两类真实路径：读连接持有锁导致 `COMMIT` 返回 `database is locked`，以及 `DEFERRABLE INITIALLY DEFERRED` 外键在提交时才失败。[SQLite 外键说明](https://www.sqlite.org/foreignkeys.html#fk_deferred)明确后一种失败也会让事务继续保持活动。回归还验证 SQLite 已自动回滚时不会再发多余回滚、嵌套调用被拒绝时不回滚调用方事务，并证明迁移提交失败不会留下半成品 schema、迁移账本或 `user_version`。这里没有自动重试提交，也没有把数据库提交等同于业务批准。

我们不使用 `Connection.executescript()`。Python 官方说明它可能在执行脚本前隐式提交，因此迁移文件先用 `sqlite3.complete_statement()` 分割，再在一个显式 `BEGIN IMMEDIATE` 中逐句 `execute()`。

## 数据库不变量

迁移创建九张 `STRICT` 表：

| 表 | 用途 | 主要不变量 |
|---|---|---|
| `_paramguard_migrations` | 已应用迁移账本 | 文件名、SHA-256、`user_version` 必须一致 |
| `tasks` | 聚合根 | 仅 `STRICT_SEQUENTIAL`；证据/流水线身份不可改 |
| `task_parameters` | 冻结字段顺序 | `(task_id, parameter_id)` 与 `(task_id, ordinal)` 唯一 |
| `evidence_artifacts` | 两侧证据元数据 | 每个 role 唯一，只保存摘要/长度/类型，不保存真实图片 |
| `task_assignments` | 服务端 R1 指派 | 当前 P1 只允许 `R1_REVIEWER` |
| `r1_decisions` | R1 修订历史 | 新修订只追加，不覆盖旧修订 |
| `r1_locks` | 完整 R1 快照锁 | 每任务最多一次，绑定 reviewer/manifest/snapshot hash |
| `command_receipts` | 幂等命令结果 | command ID 全局唯一，请求摘要不同则冲突 |
| `audit_outbox` | 待后续审计适配器消费的事件 | 与领域改变、receipt 同事务；P1 不声称已发布 |

[SQLite STRICT 表官方说明](https://sqlite.org/stricttables.html)指出，STRICT 表限制允许的数据类型，并让 integrity check 检查列类型。本项目另外用 `CHECK`、FK、唯一约束和 write-once trigger 缩小状态空间。触发器和哈希不是业务合法性的替代品；所有写命令仍先验证 reviewer、manifest、state 和 revision。

`tasks` 只有 `state`、`revision` 和 `r1_locked_at` 能按命令迁移，冻结身份字段禁止更新。其余 P1 证据、决定修订、锁、receipt 与 outbox 都由触发器拒绝更新和删除。

## Canonical JSON 为什么单独做

不可信 JSON 先解析、验证，再重编码，最后才计算 SHA-256。边界拒绝：

- 重复 object key；
- `NaN`、`Infinity` 和所有浮点值；
- 未知或缺失的 schema key；
- `dict`/`list`/`str`/`int` 的子类和其他模糊 Python 类型；
- 超过 signed 64-bit 的整数、过深/过大的文档和无效 UTF-8。

允许的数据子集是 null、精确 Boolean、signed 64-bit integer、精确字符串、list 和 string-key dict。对象 key 排序、无多余空格、UTF-8 编码。这样，`{"a":1,"b":2}` 与不同空格/顺序的同一输入会得到同一持久化身份，而 `{"a":1,"a":2}` 在进入业务层前失败。

这不是完整 RFC 8785 实现；它是更窄的项目内协议，特意不接受浮点数。

## 完整性锁与幂等恢复

锁 R1 时，仓库在同一个 `BEGIN IMMEDIATE` 内：

1. 读取 task、服务端 assignment、manifest hash 和期望 revision；
2. 按 `ordinal` 读取每个参数最新修订；
3. 任何缺失字段都会返回 `R1IncompleteError`，不改变数据库；
4. 将完整快照 canonical 重编码并计算 `snapshot_sha256`；
5. 用 `UPDATE ... WHERE revision=? AND state='HUMAN_REVIEW_OPEN'` 完成 CAS；
6. 插入唯一 `r1_locks`、command receipt 和 outbox；
7. 一次提交。

服务重启后，带同一 `command_id` 和完全相同请求的重试返回数据库中的**原 receipt**，包括原时间戳，不重新执行。相同 command ID 若绑定不同 payload/task/type，则拒绝为冲突。

每次 repository 启动还会在一个显式只读事务快照中做 P1 语义重放：canonical receipt 必须与 outbox 逐字段一致；receipt revision 必须无缺口且其 canonical UTC 时间不得随任务修订倒退；规范化参数/证据必须与冻结 manifest 一致；每条 decision 必须与 assignment、manifest、command receipt 对齐；锁快照会从最新 decisions 重新计算。写入时也会在同一 `BEGIN IMMEDIATE` 内把新时间与该任务上一持久修订比较，倒退时整个命令回滚。固定读快照避免并发 writer 恰好在多张表的核验之间提交，造成“把合法并发误判为跨表损坏”。测试会先移除保护 trigger，再同时伪造 receipt 和 outbox 的 JSON/hash，证明“哈希自洽但业务关联错误或时间倒退”的数据仍会在重启时失败关闭。

## 在线收据的请求、结果与 outbox 绑定

2026-08-27 的合成对抗测试发现：绕过并恢复保护触发器后，仅篡改命令收据的请求摘要，就能让运行中的实例对不同理由返回旧成功收据；重启重放却会拒绝。这不是已证明能由公开 HTTP 直接利用的缺陷，复现只操作临时合成数据库。

修复后，精确重试在原 `BEGIN IMMEDIATE` 事务中核对已提交命令：注册从冻结 manifest、pipeline 和指派重建；字段决定按 command ID 读取历史行，不能拿最新修订替代；锁定复用完整快照校验。重建摘要必须与收据请求摘要一致。注册、字段决定、锁定三类篡改均有回归；后续修订或锁定后的原请求仍返回原收据，不重新取时钟、不新增 revision 或 outbox。

后续对抗测试又发现，仅同步改写收据和 outbox 的结果 JSON/hash，仍可把原 `DIFFERENT` 显示成 `SAME`，或把未完成字段数伪造为 0。两份结果互相一致不代表与领域记录一致。现在精确重试及 `get_command_receipt()` 均核对该命令唯一的 outbox、冻结请求与领域返回值；注册结果保留初始完整度，字段结果的 `missing_count` 按其历史修订重算，锁定结果必须是已锁定状态且缺失数为 0。普通回读使用显式只读事务，多表检查共享同一快照。

这是命令级检查，不是每次在线重放整库。启动和显式完整性检查现已将 schema 核验与全量语义重放绑定到同一快照，见下节。其他读取入口和独立历史锚仍是后续工作。能同时改写领域事实、历史和所有镜像的数据库写入者，不能仅靠同文件哈希防住。

完整度查询访问该任务的参数和历史，注册成本随 manifest 增长，锁定重试会重建全字段快照；不能把所有重试都说成 O(1)。历史修订回读、锁后重试和重启后的原收据行为，见 [test_sqlite_repository.py](../tests/test_sqlite_repository.py) 中的回归测试。性能需要在目标环境单独测量；本地维护记录不随仓库分发，也不是生产 SLA。

## 迁移记录之外的表结构核验

迁移账本正常、`user_version=2`、`integrity_check=ok`，仍不证明实际建表语句符合打包迁移。本轮在临时合成库复现了额外列/表、删除 CHECK、修改默认值或类型仍通过旧检查；没有操作真实数据库，也没有证明公开 HTTP 可直接利用这些变更。

`verify_database_integrity()` 现在除已有索引/trigger 检查外，还比较 main 中表的建表 SQL、`table_xinfo` 列属性和 `table_list` 标记。基线由同一个 SQLite 运行时在隔离内存库执行完整打包迁移生成。SQLite 保存有限规范化、随后随 DDL 变化的建表文本；`table_xinfo` 还包含生成/隐藏列。因此不自行把任意 SQL 改写成“等价”文本，也不把物理 rootpage 当结构身份。[Schema table](https://www.sqlite.org/schematab.html)、[table_xinfo](https://www.sqlite.org/pragma.html#pragma_table_xinfo)

额外普通表、列或约束漂移会拒绝，不删除对象或自动修复。SQLite 自身 `sqlite_stat1` / `sqlite_stat4` 统计表不参与应用表身份比较；`ANALYZE` 后 `VACUUM` 有通过的正例。新增四项回归同时覆盖生成列、弱化 CHECK、默认值、类型、非空和外键变化。

这是 main 应用表的补充核验，不是对全部 SQLite 对象的保证。view 和连接作用域的后续检查见下节。运行中若有人绕过连接入口直接改库，需要显式完整性检查或重新打开仓库才能触发这项核验；不能声称每次业务读写都重新验证全库。

## 连接作用域与 view 核验

只核对 main 结构可能漏掉正在影响查询的 TEMP 对象。SQLite 对未限定 schema 的名称先查 TEMP，再查 main，最后查附加库；TEMP trigger 也能作用于 main 表，因此只给 SELECT 加上 `main.` 不够。[名称解析](https://www.sqlite.org/lang_naming.html)、[TEMP trigger](https://sqlite.org/lang_createtrigger.html#temp_triggers_on_non_temp_tables)

合成复现先把 main 中的 R1 指派人改成错误值，确认语义重放会拒绝，再在同一连接建立同名 TEMP 表，填入与注册收据一致的指派。旧检查仍核对正确的 main 表结构，却让后续未限定的读取命中 TEMP，于是误报成功。另有未经批准的 main view、附加库和 TEMP trigger 通过旧检查的负例。这里需要先控制被检查的同一连接；当前仓库每条命令新建并关闭连接，没有用户 SQL 入口，不是已证明的远程 HTTP 绕过。

迁移在事务开始后、任何迁移写入前检查连接作用域；完整性核验也先做同一检查。`PRAGMA database_list` 只允许 main 与空 TEMP，拒绝任何额外 attachment，再检查 TEMP 是否有对象；允许已初始化但为空的 TEMP。拒绝时不删除对象、不 DETACH，也不结束调用方已有的事务。[database_list](https://www.sqlite.org/pragma.html#pragma_database_list)

main 中的 view 定义与同一 SQLite 运行时执行打包迁移后的基线逐项比较；当前迁移没有批准 view。账本读写显式使用 main，STRICT 表列表只取 main。七项新增回归覆盖连接局部 shadow、TEMP 表/view/trigger、附加库、自持与调用方事务、迁移前零写入、额外 view 的启动/显式拒绝，以及空 TEMP 正例。新连接的对照确认 TEMP 不跨连接保留，真实的错误指派仍会被语义检查发现。

打包迁移、SQLite 驱动和 Python 连接操作方仍受信任。这不是任意 SQL 沙箱，也不防御检查后的进程内恶意操作；检查并未扩展到每一条在线命令。连接作用域与迁移回归见 [test_db.py](../tests/test_db.py) 和 [test_sqlite_migrations.py](../tests/test_sqlite_migrations.py)。

## 结构核验与语义重放共享快照

两个检查分别通过，不代表同一份数据同时满足两个条件。合成复现先准备状态 A：表结构正确，但指派人与注册收据不一致。在结构检查结束后，另一连接以单个事务把它换成状态 B：修正指派人，同时添加未批准表。旧代码会取 A 的结构和 B 的业务记录并返回成功，尽管在这次验证期间，两份已提交状态都不合格。复现需要直接修改临时数据库，并不证明公开 HTTP 可以实施这种改写。

启动检查和 `verify_integrity()` 现在都在同一个 `BEGIN` / `COMMIT` 内完成迁移身份、物理完整性、main 表/索引/触发器与业务语义核验。`verify_database_integrity()` 单独调用时自持读取事务；调用方已有显式事务时只加入，不提交或回滚调用方事务。连接仍须使用 `isolation_level=None`。

连接创建负责设置安全 PRAGMA；完整性检查只读取并验证现有设置。这样既不会在已有事务内触发 `Safety level may not be changed inside a transaction`，也不会把被关掉的外键或递归触发器偷偷恢复后报告正常。设置漂移会失败，原设置保留供调查。[SQLite PRAGMA](https://www.sqlite.org/pragma.html)、[事务说明](https://www.sqlite.org/lang_transaction.html)

回归覆盖启动和显式检查的 A/B 原子交换，以及合法并发决定的正例。在 DELETE 模式，读取事务阻止另一连接提交，超时的写入回滚后仍检查 A；在支持且显式启用的 WAL 模式，另一连接可以提交 B，但读取方继续检查 A 并拒绝。合法写入不会被误判：读取方可以接受完整的旧有效快照，随后新的检查再验证新状态。[SQLite isolation](https://www.sqlite.org/isolation.html)

这保证的是一次验证内部的一致性，不是“返回成功后数据库永远不会变化”。不覆盖未受信任管理员改写整个有效历史、外部可信锚、所有在线入口持续重放或真实企业身份认证；也不改变人工先行、AI 不批准的业务规则。

## 1,001 字段与恢复测试

字段分页使用：

```sql
WHERE task_id = ? AND ordinal > ?
ORDER BY ordinal
LIMIT ?
```

也就是 ordinal keyset，不用越来越慢的 `OFFSET`。测试注册 1,001 个合成字段，以 137 条一页遍历并检查 query plan 使用索引。

故障注入覆盖注册、R1 decision CAS、R1 lock/outbox 中间失败，验证每次都是“全有或全无”。另一个独立进程在 DELETE 模式的未提交事务中直接退出，重启连接后验证恢复到最后一次提交并运行 `integrity_check`/`foreign_key_check`。[SQLite 原子提交说明](https://sqlite.org/atomiccommit.html)和[rollback journal 锁定/热日志说明](https://sqlite.org/lockingv3.html)是此恢复模型的官方依据。

## 运行验证

```bash
PYTHONPATH=src python3.13 -m unittest \
  tests.test_canonical_json tests.test_db tests.test_sqlite_repository \
  tests.test_sqlite_concurrency tests.test_sqlite_recovery \
  tests.test_sqlite_migrations tests.test_packaging -v

PYTHONPATH=src python3.11 -m unittest discover -s tests -v
PYTHONPATH=src python3.13 -m unittest discover -s tests -v
python3.13 -m compileall -q src tests
```

迁移 SQL 已通过 `pyproject.toml` 的 `migrations/*.sql` package-data 规则进入 wheel；测试还会从 `importlib.resources` 检查安装资源声明。

## 明确没有解决的生产问题

此 P1 是独立个人项目的持久化原型，不是企业内部系统，也没有获得 GxP、EU Annex 11、21 CFR Part 11 或任何监管验证。至少仍缺：

- 企业认证、授权、账号生命周期和职责分离目录；
- 可信时间源、电子签名、签名含义和会话再认证；
- outbox 的独立审计消费者、发布确认、链式验证和长期保留；
- 加密、密钥托管、备份恢复、灾备目标和定期恢复演练；
- 文件权限、主机加固、恶意管理员模型和数据库副本治理；
- 监控、容量、锁等待 SLO、磁盘满/只读/损坏运行手册；
- 网络文件系统、多主机共享、容器编排和部署平台验证；
- 后锁 AI、定向复核/条件性盲 R2、QA 与最终人工闭环的事务化接线。

真实公司是否允许 SQLite、应使用何种 journal/同步级别、保留多久以及怎样审批，必须由其批准的架构、质量体系、风险评估和 SOP 决定。
