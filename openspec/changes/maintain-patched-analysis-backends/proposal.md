## Why

现有后端已经支撑 Rust CLI；完全禁止补丁，会让非 final 静态初值、显式诊断和宿主隔离取决于上游何时发布。用户现已允许必要的自维护 vendor。问题因此变成：如何把修复范围、升级成本和发布链管住，同时让 CLI 分析能力完整。

## What Changes

- 保留 droidsaw-dex 2.0.0 与 axmldecoder 0.5.0 的现有来源作为起点，逐补丁登记、复现、测试；不把当前补丁注释当作正确性证明。
- 为 droidsaw 增加显式选项、结构化完整性/诊断、预算与取消检查入口，修复静态值及验收矩阵中确认的语义缺口。
- 修复 AXML 命名空间作用域、文档完整消费、typed values、长字符串和错误路径；保留原始未知值。
- 使用独立 package 名发布必要派生版本，保留 vendor 目录中的第三方边界和来源；core 只经私有 adapter 使用。
- 以全量解析为语义基准；scoped parse 只有通过等价验收才保留为内部优化。正确性优先于旧性能数字。

本 change 不创建新反编译器，不自动向上游发送补丁，不实施 registry 发布。可分派任务见 [执行计划](../../execution-plan.md)。

## Capabilities

### New Capabilities
- `maintained-backends`: 必要补丁的来源、边界、显式后端契约、完整性与升级测试。

### Modified Capabilities

无。CLI 语义归 complete-cli-analysis-contracts，打包与分发归 extract-publishable-core；这里只实现支撑能力，避免三个 change 重复定义同一行为。

## Impact

主要修改 vendor/droidsaw-dex、vendor/axmldecoder 及对应回归测试。派生 package 改名和依赖接线由分发工作包统一执行，不能由多个 agent 同时编辑根 Cargo.toml / Cargo.lock。
