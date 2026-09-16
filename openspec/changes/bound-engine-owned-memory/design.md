## Context
见 audits/embedding/report.md 的 MEM-01/MEM-02。Result items/bytes/locations 是操作结果限制；当前 bounded ledger 另外覆盖 input/catalog、decoded entry、scan scratch 和 Report 的生命周期，并通过下述补充实现覆盖 method-inventory、vendor parser 与 CFG/SSA 的逻辑结构准入；它们仍不是完整进程工作集账户。

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
bounded allocation table、契约决策和实现已由独立 ASC commits 完成；保留 review 所需的 source/docs commits，消费者更新 gitlink。parser/CFG/SSA 的补充准入与本地压力测试已完成；目标部署 RSS 与 IDA 组合验收仍独立保留。

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
| method inventory vectors | `method_inventory` 的 fields/methods vectors，至 report 构造 | **估算/有限窗口**：逐行 `method_declaration_size`/`field_declaration_size`，最终 report 取得额度；各 DEX scan permit 跨 logical DEX 保留至 report 准入 | 跨 DEX 累积超限、失败回收与后续复用测试通过 |
| typed facts and scoped rows | `fold_scope` 返回 rows，至最终 report reservation | **估算**：按 fact/reference/string/class 结构计算结果大小，scan permit 同时保留 | scoped visitor/string/instruction tests；vendor 内部对象不在该表的精确覆盖内 |
| backend scratch | normalization copy 与其私有 permit 同时存活 | **精确长度**：复制前预留 validated view 的完整字节长度 | 一字节不足即在复制前拒绝；原 Artifact 不变 |
| vendor parser | `ParsedDex` 的 lease，解析前 census 至 ParsedDex drop | **逻辑结构上界**：actual referenced pools/class_data/code/debug/annotations 与容器容量；共享磁盘 offset 允许保守重复计数 | parser_memory 与 memory_admission 回归；nesting >128 显式 ResourceLimit；无全局 allocator hook |
| vendor CFG/SSA | checked report 持有最大方法工作集与 census lease | **逻辑结构上界**：blocks/edges/registers、decoded register uses、phi/current-def/读路径、DEX census | pipeline 超限在渲染前失败，report/parse 独立释放；类方法按顺序执行 |
| Source/partial source | `Report` 或共享 Error source/permit | **容量计量**：源码、class、annotations、fields/methods/debug metadata | clone 共用真实 source；metadata 不能只按 text.len 计量；转换临时对象仍依赖阶段 allowance |
| vendor optimizer/structurer/emitter、allocator bookkeeping | 内部临时对象或 OS allocator | **边界外**：没有逐容器 allocator hook；表达式扩展、BTree padding 与 allocator headers 不在精确计量承诺内 | worker 的 OS 内存上限属于部署策略，不能以 ledger/RSS 一次成功代替 |
| consumer serialization/output copies | core 返回后由 reverse-engine/host 生成的 JSON/source/file buffers | **未覆盖（边界外）**：属于消费者 own allocation | `Report::value()` 明确借用；core 不提供脱离 permit 的 owned extraction |

本轮代码与本地验证覆盖表中 input、decoded、scan scratch、inventory、parser、CFG/SSA 和 report 的声明边界与失败回收。边界外分配不属于该结构准入合同。

## E18.1 补充决策

parser census 按实际引用的结构遍历，避免用整个 DEX 长度乘最长字符串误拒绝普通 APK。损坏子节沿 vendor tolerant 路径计入已发生的容量申请；若 census 顶层未完成，则明确拒绝，不能以部分数字放行后续解析；整数溢出和过深 annotation 返回 typed resource error。CFG/SSA 使用图、寄存器和实际指令维度，SSA 当前消费 decoder 的至多五项 RegList，按实际消费结构计量；完整 invoke/range 参数事实由独立指令事实接口保留。寄存器域同时检查实际 dst/src 与宽写后继，不能信任畸形 header。扫描额度与 vendor 额度共用 Runtime 账户。

这些结构准入不是完整 allocator 证明。未覆盖的 optimizer/structurer/emitter 临时容器仍明确保留在边界表；本 change 不引入进程全局分配器，也不把进程 RSS 冒充精确计量。

审查补充：CFG leaders、exception handler vectors、common SSA phi/seal 工作列表和 predecessor 副本均单独计量。read-variable 与替换链逐个处理，计量的是同时存活的 chain/visited，不把累计调用次数乘成活跃内存。Vec 几何容量和小 vector 初始槽位另有 allowance，shared switch payload 按每次引用产生的边计数。
