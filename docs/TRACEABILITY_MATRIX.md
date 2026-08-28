# ParamGuard Vision 需求—设计—测试追溯矩阵

| 字段 | 值 |
|---|---|
| 文档状态 | 活文档；每次里程碑后复核 |
| 基线日期 | 2026-08-25 |
| 需求基线 | `HUMAN_FIRST_URS.md` v0.1，共 29 条 Must |
| 证据含义 | 个人合成数据 PoC 的工程证据，不是 GxP/Part 11 验证 |

## 1. 状态解释

- **已覆盖**：当前 PoC 有实现和至少一个直接测试；仍不代表生产验证。
- **部分覆盖**：核心域规则已有实现/测试，但 UI、持久化、身份基础设施、真实数据或验证证据仍缺一部分。
- **待实现**：目前只有设计或限制说明，不能把它讲成已完成功能。

矩阵中的测试名使用 `tests/<文件>::<测试方法>` 的简写。全量测试数会继续变化，因此这里绑定具体行为，不把某一次总数当作永久证据。

## 2. 追溯矩阵

| URS | 状态 | 主要设计/代码 | 代表性自动化证据 | 尚未关闭的缺口 |
|---|---|---|---|---|
| `URS-ID-001` | 已覆盖 | `evidence.py`, `workflow.py`, `audit.py` | `test_evidence::test_duplicate_parameter_or_artifact_id_is_rejected`; `test_workflow::test_unknown_human_parameter_is_rejected`; `test_audit::test_duplicate_generated_event_id_is_rejected` | 生产 ID 服务/数据库唯一约束未实现 |
| `URS-EVD-001` | 已覆盖 | `EvidenceArtifact`, `EvidenceManifest`, `FixedTemplate`, `PipelineSpec` | `test_evidence::test_content_substitution_is_detected`; `test_vision_pipeline::test_changed_image_bytes_fail_before_ocr_assessment`; `test_evidence::test_schema_and_template_content_hashes_are_required` | SHA-256 绑定不能证明采集来源或真实性 |
| `URS-HF-001` | 已覆盖 | `ReviewTask` 严格状态机、`run_gated_ocr_pair` 授权检查 | `test_workflow::test_ai_cannot_be_queued_started_or_written_before_human_lock`; `test_vision_pipeline::test_early_call_fails_before_reading_images_or_invoking_engine` | 生产队列/worker 的独立权限边界未实现 |
| `URS-HF-002` | 部分覆盖 | R1 专用 allowlist DTO、锁前静态页面、`no-store` 和阶段化资源 | `test_webapp::test_prelock_state_has_a_strict_human_only_allowlist`; `test_webapp::test_prelock_html_and_errors_do_not_leak_post_lock_clues`; `test_webapp::test_static_first_review_template_itself_has_no_post_lock_button` | 尚无真实身份会话、代理/CDN/cache、WebSocket 和统计时序环境的渗透验证 |
| `URS-HF-003` | 已覆盖 | 固定模板顺序、整图/ROI 并排首审页 | `test_webapp::test_page_has_side_by_side_full_evidence_rois_and_keyboard_controls`; `test_template::test_default_template_has_stable_order_and_digest` | 真实 1000+ 字段分页/虚拟滚动的视觉一致性仍需用户研究 |
| `URS-HF-004` | 已覆盖 | `HumanVerdict` 枚举、无默认决定、完整性门 | `test_workflow::test_large_review_missing_one_of_1001_fields_cannot_lock`; `test_webapp::test_incomplete_human_review_cannot_lock` | 无真实可用性研究证明人员不会误触快捷键 |
| `URS-HF-005` | 部分覆盖 | 人工 verdict/reason 规则；原始 OCR 值独立保存 | `test_workflow::test_exception_human_verdict_requires_reason`; `test_webapp::test_backend_rejects_type_confusion_and_oversized_reason` | 当前 R1 领域对象没有独立的左右“人工观察字符串”输入字段，只保存判断和原因 |
| `URS-HF-006` | 部分覆盖 | `ReviewTask` 允许锁前修订；`audit.py` 能表示不覆盖的修订/correction 事件 | `test_workflow::test_human_can_revise_before_lock_but_snapshot_is_read_only`; `test_audit::test_original_event_remains_when_correction_is_appended` | `ReviewTask` 本身只保留当前决定；Web/aggregate mutation 未自动与追加审计交易化，也尚无完整修订时间线 UI |
| `URS-HF-007` | 已覆盖 | 同一 `RLock` 内检查全字段并锁定 | `test_workflow::test_incomplete_review_cannot_lock_atomically`; `test_workflow::test_concurrent_human_write_is_serialised_with_lock`; `test_webapp::test_two_concurrent_writes_with_one_revision_cannot_both_commit` | 单进程锁仍需替换为数据库交易/CAS |
| `URS-HF-008` | 部分覆盖 | 锁后不可覆盖/重锁；审计支持指向旧事件的 correction | `test_workflow::test_lock_is_timezone_aware_and_prevents_changes_or_relock`; `test_audit::test_correction_to_unknown_or_other_task_is_rejected` | 领域/Web 的受控锁后更正工作流尚未端到端连接 |
| `URS-AI-001` | 部分覆盖 | `AiRun`, `AiAssessment`, `OcrPairOutcome`, `PipelineSpec`, `EvidenceContext` | `test_audit::test_ai_event_preserves_complete_evidence_run_and_pipeline_binding`; `test_workflow::test_complete_ai_results_and_run_metadata_are_read_only`; `test_audit::test_wrong_manifest_run_or_pipeline_cannot_join_task` | OCR token/confidence 只在内存 outcome 中，未进入当前 `AiAssessment`/追加审计；真实模型的 provider request ID、用量和保留策略也未记录 |
| `URS-AI-002` | 已覆盖 | 人工与 AI 使用分离的不可变类型/API | `test_audit::test_ai_service_cannot_write_human_decision`; `test_workflow::test_caller_cannot_freely_submit_ai_verdict` | 生产 IAM/服务账号未实现 |
| `URS-AI-003` | 部分覆盖 | 冻结、内容寻址的 `PipelineSpec`；无在线学习代码路径 | `test_pipeline::test_each_version_and_configuration_digest_changes_hash`; `test_workflow::test_unapproved_pipeline_spec_cannot_be_queued` | 正式模型注册、批准签名、部署回退和变更审批未实现 |
| `URS-DET-001` | 已覆盖 | `compare_values` 保留 raw string，仅逐字符相同为 exact | `test_comparison::test_missing_minus_sign_is_detected`; `test_comparison::test_leading_zero_is_a_format_difference_not_a_match`; `test_comparison::test_raw_values_are_never_overwritten` | 无真实语言/字符集覆盖声明 |
| `URS-DET-002` | 已覆盖 | Decimal/Unicode 分类仅生成解释；OCR 和可选 VLM 都必须由本地 `compare_values()` 重算 exact | `test_comparison::test_decimal_precision_is_a_format_difference_not_a_match`; `test_comparison::test_aggressive_unicode_normalisation_is_not_called_low_risk_formatting`; `test_vlm::test_success_uses_local_deterministic_comparator_and_no_verdict` | VLM 没有真实 API/模型性能证据，且不在放行路径 |
| `URS-DET-003` | 已覆盖 | 缺失/未知/重复/无法解析 fail closed | `test_comparison::test_two_missing_values_are_not_a_match`; `test_workflow::test_duplicate_unknown_and_incomplete_ai_results_are_rejected`; `test_routing::test_each_structural_issue_takes_qa_route` | 当前固定模板不负责发现画面中额外的未知动态字段 |
| `URS-ROUTE-001` | 部分覆盖 | `routing.py` 重算基础事实；`review_policy.py` 以带版本/profile hash 选择定向复核、条件性全字段 R2、QA 或最终人工确认；`targeted_review.py` 从可信锁定上下文重算队列；Web 已接定向 inbox/作答/锁定 | `test_review_policy::test_every_nonstructural_exception_signal_gets_targeted_recheck`; `test_review_policy::test_any_ordinary_exception_or_critical_flag_triggers_full_manifest_blind_r2`; `test_targeted_review::test_queue_is_computed_from_source_and_policy_not_supplied_routes`; `test_webapp::test_targeted_recheck_is_real_but_never_closes_or_releases` | 定向 submission 尚未接追加审计/QA/final；可信 routing-context resolver 尚无持久化 adapter；关键性规则仍是合成假设 |
| `URS-ROUTE-002` | 已覆盖 | 结构 issue 优先直达 QA | `test_routing::test_qa_route_wins_when_multiple_concerns_exist`; `test_adjudication::test_critical_quality_and_structural_signals_cannot_be_omitted` | 动态字段检测/对齐尚未完成 |
| `URS-R2-001` | 已覆盖（条件性 R2 域层） | 当已批准 profile 选择全字段盲 R2 时，`Actor`/`Role`、受指派 R2 和 R1/R2 identity separation 强制生效 | `test_review_policy::test_any_ordinary_exception_or_critical_flag_triggers_full_manifest_blind_r2`; `test_blind_review::test_primary_and_second_reviewer_must_differ`; `test_audit::test_first_reviewer_cannot_act_as_independent_second_reviewer` | 本地 actor 对象不是企业 IdP 身份证明；面试 profile 的定向复核明确不冒充独立 R2 |
| `URS-R2-002` | 部分覆盖（条件性 R2 域层） | 独立 `blind_review.py`、全 Schema packet、锁前零 R1/AI 导入；只由 profile 显式选择 | `test_blind_review::test_packet_is_full_schema_allowlist_without_prior_result_hints`; `test_blind_review::test_module_does_not_import_workflow_or_routing`; `test_audit_adapter_integration::test_independent_route_uses_full_field_formal_r2_before_final` | 本地 Web 尚未提供真正 R2 作答/锁定界面；adjudication 尚未改为统一接收两种 profile |
| `URS-AUTH-001` | 已覆盖 | routing 永远 `automatic_release_allowed=False`；QA/final human-only | `test_routing::test_clean_noncritical_agreement_has_no_exception_but_no_release`; `test_adjudication::test_only_non_admin_human_final_approver_can_approve_or_reject`; `test_adjudication::test_blocking_and_rework_outcomes_cannot_reach_approval_ready` | PoC 的“最终批准”仅流程示范，不是产品/批次放行接口 |
| `URS-AUTH-002` | 已覆盖 | Web/报告固定限制文案，exception inbox 明示未闭环 | `test_webapp::test_no_exception_detection_never_becomes_release_status`; `test_webapp::test_http_post_lock_check_returns_auxiliary_results_and_open_inbox` | 后续任何新导出格式都要纳入同一契约测试 |
| `URS-AUD-001` | 部分覆盖 | 强类型 JSONL 追加、UTC、event ID、prev hash、correction | `test_audit::test_append_persists_and_restart_continues_hash_chain`; `test_audit::test_deleted_or_reordered_event_is_detected`; `test_audit::test_naive_or_backwards_clock_is_rejected` | audit store/语义已实现，但 R1、AI、Web 定向复核等多数 aggregate mutation 尚未强制经过它；JSONL 也不是 WORM、数字签名或受信时间戳 |
| `URS-AUD-002` | 部分覆盖 | 全链/语义重放 fail closed；final 原子 CAS + fsync | `test_audit::test_truncated_or_invalid_json_line_fails_closed`; `test_adjudication::test_atomic_audit_commit_failure_blocks_final_decision`; `test_audit_adapter_integration::test_stale_head_fails_cas_without_domain_final_then_retry_succeeds` | final 有原子 adapter，但中间 aggregate mutation 尚未与审计 append/outbox 原子集成；磁盘耗尽、备份/恢复和灾难恢复也未验证 |
| `URS-SEC-001` | 部分覆盖 | 域层固定角色 allowlist；`policy.py` deny-by-default 绑定 action/phase/state/task/manifest/精确分配，包括每 task 的 AI service | `test_policy::test_allowlist_has_an_explicit_allow_case_for_every_action`; `test_policy::test_ai_worker_cannot_cross_task_or_assignment`; `test_policy::test_human_multi_role_is_explicit_but_admin_and_ai_worker_are_forbidden`; `test_adjudication::test_only_non_admin_human_final_approver_can_approve_or_reject` | policy core 尚未接入全部 Web/API；本地 Web 没有认证、session、SSO、MFA 或电子签名 |
| `URS-OT-001` | 部分覆盖 | 当前模块仅读合成图片并生成本地报告；无 OT 写适配器 | `test_webapp::test_server_refuses_non_loopback_bind_addresses`; `test_vision_pipeline::test_early_call_fails_before_reading_images_or_invoking_engine` | 尚未加入持续静态 egress/禁止 OT 协议依赖的仓库策略测试 |
| `URS-DATA-001` | 部分覆盖 | `synthetic.py`, frozen synthetic benchmark，文档明确来源 | `test_synthetic::test_clean_case_renders_two_frozen_images_and_ground_truth`; `test_benchmark::test_every_case_renders_to_bound_synthetic_evidence` | 尚无成熟 secret/PII/真实数据扫描和外部数据引入审批流水线 |
| `URS-PERF-001` | 部分覆盖 | `evaluation.py`, `benchmark.py`, `benchmark_runner.py` | `test_evaluation::test_reports_detected_missed_and_unresolved_differences_separately`; `test_evaluation::test_split_filter_prevents_development_rows_from_changing_hidden_report`; `test_benchmark_runner::test_challenge_quality_gate_abstains_without_ocr_crop_commands` | 数据集很小且纯合成；人工用时为空；字段对齐指标和真实独立隐藏集仍缺失 |
| `URS-CHG-001` | 部分覆盖 | Manifest/Pipeline/benchmark/source-tree 内容哈希；回归测试 | `test_pipeline::test_each_version_and_configuration_digest_changes_hash`; `test_benchmark::test_benchmark_digest_is_canonical_and_stable`; `test_workflow::test_forged_run_and_all_result_versions_still_fail_approved_spec` | 无正式变更单、批准人、迁移方案和多版本生产重放环境 |

## 3. 当前最重要的未关闭项

按风险与面试展示价值排序：

1. 将已接 Web 的定向异常复核继续连接到可信 routing-context 持久层、追加审计、QA 和最终人工闸，同时保留可选全字段盲 R2 路径；
2. 为 1000+ 字段增加初始 DOM 虚拟化/分页、断点恢复和真人可用性测试；已有 mutation receipt 是 O(1) 小响应，仍须保持字段顺序不受 AI 影响；
3. 实现且独立验证真实 OpenCV/等价 registration adapter，保留原始 correspondence/inlier/residual 并在主管道重算；当前只有未接入的几何 quality contract；
4. 将 deny-by-default policy core 接到每个 API，再增加认证、持久事务/唯一约束/outbox 与受控电子签名的生产架构原型；
5. 增加成熟的 secret/PII/真实资料扫描、锁文件/SBOM 和漏洞扫描；已有 CI 与 fail-closed 供应链清单仍不代表这些已完成；
6. 扩大预先冻结的合成挑战集，并在有权限、正式数据/安全审批的前提下设计独立真实验证；可选 VLM 尚无真实 API 性能证据。

这份矩阵的价值在于暴露缺口。若某一行仍写“部分覆盖”，面试时就应准确说“我实现了哪一层、还缺哪一层”，不能把设计文档当作已经验证的事实。
