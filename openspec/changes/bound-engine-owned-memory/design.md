## Context
见 audits/embedding/report.md 的 MEM-01/MEM-02。Result items/bytes/locations 是操作结果限制；当前 bounded ledger 另外覆盖 input/catalog、decoded entry、scan scratch 和 Report 的生命周期，但 method-inventory 中间 vectors 与 vendor parse/CFG/SSA 仍不能代替完整工作集账户。

## Goals / Non-Goals
使内存合同可验证。不会仅把估计值重新命名为 RSS，也不会以大范围格式/lint 或 JNI 功能混入修复。

## Decisions
1. 首项工作列出每个分配点、归属、存活区间和是否能在分配前度量；优先覆盖 input/catalog/decoded/scratch/hits/results，保留 vendor 的限制清单。
2. 复用 Runtime 的单一账户，RAII permit 随 buffer/report 持有并在 Drop 释放；不创建第二套全局 Engine registry。跨线程共享同一账户，采用 checked arithmetic，失败路径回滚。
3. results 如果离开 Engine 后继续持有，其 permit 必须随报告移动；不得在返回前归还后让并发操作重复消费同一预算。输出转换产生的消费者副本不计入 core 的精确账户，明确边界。
4. 不可准确度量的 vendor allocations 使用经验证的输入规模上界与分阶段预算；没有证据就不能宣称受 max_engine_owned_bytes 完整限制。必要时明确拆成输入保留额度和工作集额度，用户不要求旧 API 兼容。
5. parse/CFG/SSA 单步协作检查仍需worker硬终止兜底；OS内存限制属于消费者部署策略，core 不设置进程全局 limits。

## Risks / Trade-offs
计量不能递归引入不可控大额元数据；避免每个对象一个 Arc/permit，按实际共享allocation聚合。测试以确定性计数器证明边界，不以一次RSS采样证明无泄漏。

## Migration Plan
bounded allocation table、契约决策和实现已由独立 ASC commits 完成；保留 review 所需的 source/docs commits，消费者更新 gitlink。后续 vendor/RSS/压力扩展沿下列扩展任务独立推进，不回填为本次基本验收证据。

## Open Questions
vendor 内部分配能精确覆盖到何层仍需单独测量；在有证据前，API 名称只承诺表中 engine ledger 的实测或保守估算范围，不承诺完整进程内存或 RSS。

## Allocation table and bounded acceptance

本轮把 `max_engine_owned_bytes` 命名为 ASC engine ledger 的活跃计量或保守准入上限。表中“实测”指已有确定性计数器/回归证据，“估算”指分配前由输入或结构大小推导的 permit，“未覆盖”指当前没有 core 级 permit，不能写成完整活跃内存或 RSS 保证。

| 资源阶段 | 持有者与生命周期 | 计量口径 | 本轮证据/边界 |
|---|---|---|---|
| input snapshot | `Artifact::input_memory`，从 open 成功到 Artifact drop | **实测/精确**：实际 owned bytes 长度，checked reservation | `engine_owned_bytes_account_tracks_and_releases`、open limit 回归；Arc 输入不复制但每次 open 保守计其长度 |
| archive catalog/root projection | `Artifact::catalog_memory`，从 open 到 Artifact drop | **估算**：目录记录、raw name/root 投影的结构系数 | open/archive identity tests；Rust allocator 元数据与 Arc 共享开销不单独展开 |
| decoded entry | `fold_roots`/`fold_scope`/manifest scope 的 decode permit，覆盖一次选中 entry 解码 | **实测/精确上界**：中央目录 declared uncompressed bytes，另有 shared decoded-byte quota 检查实际流 | `read_entry_reserves_the_budget_and_rolls_back_on_failure`、cross-entry decoded budget regressions；raw DEX 复用 input snapshot |
| scan scratch | fold 的每逻辑 DEX `estimated_scan_work` permit，至 rows 转移且 report permit 成功后释放 | **估算/保守**：DEX bytes、table counts、code-sized allowance；不等同 vendor RSS | `scanner_working_set_is_reserved_before_rows_and_releases_on_failure`；`ac1010c` 关闭 fold 批内 rows 先于 scratch permit 释放的窗口 |
| report payload/diagnostics | `Report` 的 permit，至 Report 及其最后一个 clone drop | **估算**：结构化 result bytes 与 diagnostic bytes；不声称逐 allocator 精确 | `report_permit_follows_report_lifetime_and_releases_for_reuse`；`4e3d710` 使 clone 共享真实 payload allocation，`into_value` 移除 |
| method inventory vectors | `method_inventory` 的 fields/methods vectors，至 report 构造 | **估算/有限窗口**：逐行 `method_declaration_size`/`field_declaration_size`，最终 report 取得额度；各 DEX scan permit 不跨 logical DEX 保留 | inventory identity/basic tests 已通过；该中间累积窗口仍是扩展验收，不宣称完整活跃覆盖 |
| typed facts and scoped rows | `fold_scope` 返回 rows，至最终 report reservation | **估算**：按 fact/reference/string/class 结构计算结果大小，scan permit 同时保留 | scoped visitor/string/instruction tests；vendor 内部对象不在该表的精确覆盖内 |
| vendor parse/CFG/SSA and backend scratch | droidsaw parser/decompiler 的内部对象，在一次解析/渲染期间 | **未覆盖**：仅受 backend input/control/budget 与阶段性 scan estimate 间接约束 | 不把 `guard.backend_budget` 或一次 RSS 采样称为 engine ledger；由 E18.1 扩展 |
| consumer serialization/output copies | core 返回后由 reverse-engine/host 生成的 JSON/source/file buffers | **未覆盖（边界外）**：属于消费者 own allocation | `Report::value()` 明确借用；core 不提供脱离 permit 的 owned extraction |

本轮基本验收覆盖表中 input、decoded、scan scratch、report 的可验证边界和失败回收；未覆盖行仍保留为独立扩展任务，不阻塞已交付公开 API。
