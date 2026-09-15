# asc-core 嵌入审计

审计原点：`c42e7e6`（lordcasser/main），日期 2026-09-15。消费者是 reverse-engine 的 one-shot APK worker。按公开入口、输入/输出资源、受控 vendor、依赖 feature、旧 backend 补丁逐层核对；没有执行 registry publish 或远端 push。

## 已确认的问题

| 编号 | 原始问题 | 修复与证据 |
|---|---|---|
| EMB-01 | default/decompile/manifest 独立组合编译失败；workspace all-features 掩盖缺少 cfg | Limits.manifest、metadata mapper 与对应测试目标使用 feature gate；独立脚本运行四组合 |
| EMB-02 | open_bytes 忽略 control；path 只在全部读完后检查长度 | 入口/哈希/中央目录检查 control；统一 reader 在追加前检查实际增长；取消及增长 reader 回归 |
| EMB-03 | decompile 命中即停止，没有注释宣称的 completion pass；跨 entry 重复类未报告 | 全 scope 验证并确定首个身份；保留命中 entry，一次解压计量，重复诊断聚合 |
| EMB-04 | backend 取消只在调用前复制，运行期间不共享；所有错误映射 MalformedInput | DX-P06 共享 AtomicBool，按 typed BackendError 保留取消/期限/预算/索引原因 |
| EMB-05 | None 使用全局 Rayon pool；decompile 未进入 Engine 私有 pool | 默认一个私有 worker，反编译及 vendor 的并行解析进入同一 pool。这是旧 reverse-engine 已具备而需回迁的通用行为 |
| EMB-06 | 每个 DEX 独立获得完整结果预算；classes 未检查合计数量 | 按条目顺序合并并检查整个操作的 item/estimated-byte/location 上限；并行结果按 worker 数量分批持有 |
| EMB-07 | 公开 free functions 可绕过 Engine 的准入与账户检查 | 顶层实现改为私有，只保留 Engine 公开操作 |
| EMB-08 | 普通类名 Login / Login.View 被当作半截 descriptor 删除首字母 L | 只有完整 L...; 剥离边界；22 个 query 契约通过，并覆盖类 L；不保留含糊的半截 descriptor 猜测 |

## 可复现验证

`crates/asc-core/tests/embedded_regressions.rs` 只调用公开 API。将同一文件复制到 c42e7e6 的临时 detached worktree，运行：

```sh
cargo test -p asc-core --all-features --test embedded_regressions --locked
```

原始结果为 **2 passed / 6 failed**，修复后为 **8 passed / 0 failed**。原始失败具体发生在 APK 预取消、跨 DEX classes 数量、references 数量与位置数量、后置坏 DEX 错误地成功，以及反编译重复类诊断缺失。单个断言失败后的其他分支不能算已执行；例如原始 raw DEX/deadline 取消由源码确认，同一修复后的测试才执行到这些断言。临时 worktree 已删除，完整轻量日志保留在 `/tmp/asc-audit-logs/embedded-original-c42e7e6.log`。

修复后的 core lib **44/44**，vendor `asc_contracts` **8/8**。四种独立 feature matrix 已通过（`scripts/check-core-features.sh`，Rust 1.93.1，日志 `/tmp/asc-audit-logs/feature-matrix-after-gates-final.log`）；query 修复后 22 个 query 契约及单条目紧 decoded 预算 G02 单测通过。仓外 path consumer 的 default check、default scan 和 all-features G02 decompile 均通过（日志 `/tmp/asc-audit-logs/consumer-path-final.log`）；没有 workspace patch 或 CLI feature 合并。最终 reverse-engine 工具集由下游 change 验收。

原始基线：all-features core、rasc、workspace、两个 vendor 套件通过；默认及单 feature 失败。`cargo fmt --check` 已有约 1963 个 diff 段；clippy 命令退出 0 但有 15 条 warning，不能引用历史“0 警告”作为当前事实。parity comparator 自测 17/17。

## 独立架构债务

这些问题不混入 submodule 机械接入，也不消失在“审计通过”的概述里：

1. **MEM-01 活跃内存完整账户**：当前 `max_engine_owned_bytes` 实际保留输入 bytes；历史 interfaces.md 中输入/catalog/解压/scratch/结构/结果全账户的声明没有全部落实。输入、解压、scan 结果各有独立上限，但不等同于总活跃内存或 RSS。后续必须单独设计 permits 与真实分配前计量，或明确收窄该 API 合同；本轮不声称修复。
2. **MEM-02 中间结构**：scan 的 hits 索引、批内返回值、class filter 前临时结构和 vendor parse/CFG/SSA 不是整个进程内存硬限制。操作结果上限已修复，但不能据此宣称中间结构也都已计量。
3. **QUAL-01 质量基线**：格式及既有 clippy 警告单独清理；不能对当前 patch 顺带重排整个 vendor。源码审计发现 `.github` 不存在，历史“已建立原生 CI”声明需作为后续 gate 重建，不能当现场证据。
4. **PLAT-01 原生平台**：本机为 macOS arm64；没有用 Linux/Windows 原生运行冒充通过。BIN/IDA 的最终 native bridge 验收仍由消费者负责。
5. **PERF-01 scoped 优化**：旧 backend 的 prefix/scoped 速度不能直接回迁；full parse 与 scoped 在 R8/metadata/输入校验上的差异已有记录，必须先证实等价再启用。

上述债务独立于此次确定性执行修复。它们约束部署与后续演进，不应以“所有可能问题都已穷尽”对外描述。

## 工具链说明

本机 `rustup run 1.93.1 rustc/cargo --version` 确认为 1.93.1；同命令调用 cargo clippy 时实际选择 clippy 0.1.98。严格 `-D warnings` 被既有 vendor `chunks_exact_to_as_chunks` 警告阻断，未将其记为通过。新增的 collapsible_if 警告已修正；未顺带重排 vendor 或修改既有 lint 基线。

## 下游接入复查：EMB-09

`validate_standard_dex` 未先校验 `data_off <= len` 就做减法；公开 API 用 G02 的 data_off=len+1 复现 debug panic（`/tmp/asc-audit-logs/data-range-before.log`）。改用 checked_sub 后，len+1/u32::MAX 的 raw DEX 和 APK 路径均返回 MalformedInput，Engine 可继续处理有效输入。9 个 embedded regressions 全通过（`/tmp/asc-audit-logs/data-range-after.log`）。这项单点修复独立于内存账户/provider 功能计划，见归档 change `reject-out-of-range-dex-data`。
