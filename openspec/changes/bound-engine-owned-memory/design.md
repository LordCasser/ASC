## Context
见 audits/embedding/report.md 的 MEM-01/MEM-02。当前 Result items/bytes/locations 是操作结果限制；输入 snapshot reservation 是 Engine 活跃输入限制，两者不能代替完整工作集账户。

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
完成分配清单和契约决策后再写实现；独立 review/commit/feature matrix，最后由消费者更新gitlink。未完成前继续保留审计债务说明。

## Open Questions
vendor 内部分配能精确覆盖到何层由 1.1 的 allocation audit 决定；无法覆盖则缩小命名合同，不能保留虚假保证。
