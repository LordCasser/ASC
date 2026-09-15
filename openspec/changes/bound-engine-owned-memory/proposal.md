## Why
嵌入审计的 MEM-01/02 显示 max_engine_owned_bytes 目前只保留输入 bytes；catalog、解析索引、解压、vendor 工作集与结果不共享完整活跃账户。独立输入/结果上限不能证明总内存受控。此债务单独实施，不混入 submodule 接入。

## What Changes
- 先定义并落实 engine-owned allocations 的真实计量范围，消除历史接口文档与实现矛盾。
- permit 跟随实际资源生命周期，失败/取消归还；按实际分配前准入。
- vendor 无法精确计量的工作内存明确列出，并提供可验证上界或保持进程隔离限制，不伪称 RSS 硬限额。

## Capabilities
### New Capabilities
- `engine-memory-accounting`: 引擎活跃资源计量及其边界。
### Modified Capabilities

## Impact
engine、zip、dex 扫描与必要 vendor allocation 边界；不包括宿主 artifact TTL、MCP quotas 或 OS RSS 策略。
