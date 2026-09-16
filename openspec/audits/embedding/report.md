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

1. **MEM-01 活跃内存完整账户**：`max_engine_owned_bytes` 现在覆盖输入、catalog、解压、scan scratch 与 report 的部分估算；`Report` 在 `4e3d710` 中通过共享真实 payload allocation 修正了 clone/drop 所有权，移除了会把 payload 带出 permit 生命周期的 public `into_value`。`Artifact::fold_*` 在 `ac1010c` 中把每个逻辑 DEX 的 scan estimate permit 持有到 rows 转移并取得最终 report permit 后，才释放 scratch，因而覆盖了 fold 批内结果的临时存活窗口；`method_inventory` 的跨 logical DEX 中间 vectors、report size 及 vendor parse/CFG/SSA 仍分别只有结构估算或未覆盖。输入、解压、scan 结果各有独立上限，但不等同于完整活跃内存或 RSS；本轮按 design allocation table 收窄并记录边界，不声称完整 RSS 修复。
2. **MEM-02 中间结构**：scan 的 hits 索引、批内返回值、class filter 前临时结构和 vendor parse/CFG/SSA 不是整个进程内存硬限制。操作结果上限已修复，但不能据此宣称中间结构也都已计量。
3. **QUAL-01 质量基线**：格式及既有 clippy 警告单独清理；不能对当前 patch 顺带重排整个 vendor。源码审计发现 `.github` 不存在，历史“已建立原生 CI”声明需作为后续 gate 重建，不能当现场证据。
4. **PLAT-01 原生平台**：本机为 macOS arm64；没有用 Linux/Windows 原生运行冒充通过。BIN/IDA 的最终 native bridge 验收仍由消费者负责。
5. **PERF-01 scoped 优化**：旧 backend 的 prefix/scoped 速度不能直接回迁；full parse 与 scoped 在 R8/metadata/输入校验上的差异已有记录，必须先证实等价再启用。

上述债务独立于此次确定性执行修复。它们约束部署与后续演进，不应以“所有可能问题都已穷尽”对外描述。

## 工具链说明

本机 `rustup run 1.93.1 rustc/cargo --version` 确认为 1.93.1；同命令调用 cargo clippy 时实际选择 clippy 0.1.98。严格 `-D warnings` 被既有 vendor `chunks_exact_to_as_chunks` 警告阻断，未将其记为通过。新增的 collapsible_if 警告已修正；未顺带重排 vendor 或修改既有 lint 基线。

## 下游接入复查：EMB-09

`validate_standard_dex` 未先校验 `data_off <= len` 就做减法；公开 API 用 G02 的 data_off=len+1 复现 debug panic（`/tmp/asc-audit-logs/data-range-before.log`）。改用 checked_sub 后，len+1/u32::MAX 的 raw DEX 和 APK 路径均返回 MalformedInput，Engine 可继续处理有效输入。9 个 embedded regressions 全通过（`/tmp/asc-audit-logs/data-range-after.log`）。这项单点修复独立于内存账户/provider 功能计划，见归档 change `reject-out-of-range-dex-data`。

## 2026-09-16 provider/navigation 增量核对

本节记录本轮在 ASC 源仓的实现 checkpoint，不把下游 APK/IDA 联调结果倒灌成 core 证据。

* A16 provider 已由 `b41b82f` 提供 archive identity、bounded catalog、受控 copy 和 shared decoded quota。A16 2.1 的 feature matrix 与仓外 path consumer 证据仍以 `/tmp/asc-audit-logs/feature-matrix-after-gates-final.log` 和 `/tmp/asc-audit-logs/consumer-path-final.log` 为准；消费者 B 的 staged-output 联合验收已由 reverse-engine 通过，2.2 核心交付完成并保留 change 供 review，宿主原子发布与父子身份仍由消费者负责。
* A17 的 `4b5064f`/`d9f4b49` 提供 MethodInventory、FieldDeclaration、MethodTarget 和显式 scope；`bd84da4` 增加 `visit_method_declarations`、按 MethodId 的 `instructions_for_methods_in_scope`，`08f51c2` 增加有序 `invoke_registers`，`935207f` 增加不物化声明的 `dexes_in_scope`。`cargo test -p asc-core --all-features --locked` 本轮为 209 passed；其中包含 nested/all-detected scope 与 batch visitor 回归，C/D consumer 已通过公开 API 交接。完整 native/abstract/metadata fixture 矩阵、IDA 环境和性能基线仍未运行，已拆为 A17 扩展项；本 change 保留供 review，不宣称已归档。
* A18 的 `6141965`、`8b91724`、`abf5816`、scoped visitor、`4e3d710`、`ac1010c`、`d9f43ea` 让 input/catalog、解压、scan scratch、report 结果及部分 typed facts 在分配前取得精确或保守的 ledger charge，并由 RAII 归还；其中 report clone 共享同一真实 payload allocation，结果不能通过 public owned extraction 脱离 permit，fold 批内 rows 也保持其 scan estimate permit 到最终 report permit 取得。A18 design 已加入具体 allocation table：实测计数、结构估算和未覆盖的 method-inventory/vendor/consumer 阶段分别列明。该 ledger 的 `max_engine_owned_bytes` 只是引擎可计量资源的上限；method inventory 中间 vectors、report estimate、vendor parse/CFG/SSA 与部分 allocator metadata 没有完整精确计量，任何 `estimated_scan_work` 或 report estimate 也都不是 OS RSS 硬限制。bounded acceptance 已完成，扩展/环境验收保持未勾选。

复现命令（ASC 源仓，Rust 1.93.1，复用默认 `target`，未创建第二 target）：

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 \
  cargo test -p asc-core --all-features --locked
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 \
  cargo test -p asc-droidsaw-dex --test asc_contracts --locked
```

两条命令分别通过 209 个 asc-core 测试和 8 个 vendor contract tests。它们证明当前公开 API 与 fixture 合同，不证明完整平台矩阵、RSS 硬限制或真实 IDA 运行。

## 2026-09-16 补充开发与本地验证

`419e58c` 补齐 E17/E18 的本地代码：selected-method batch 按 DEX 复用 parse；方法 annotations/debug 投影；inventory 跨 DEX permit、normalization copy、Source/partial error 所有权，以及 vendor parser/CFG/SSA 结构准入。随后的 review 修复了未完成 census 的错误放行和 SSA 临时结构漏计。以上更新取代前文关于这些项目“未实现”的时点记录；allocator、optimizer/structurer/emitter 临时对象仍不属于精确结构计量合同。

四 feature 与仓外 path consumer 全通过；all-features 224 项，含 method golden 5、selected batch 6、threads=1/2 各 4 调用线程 × 20 轮取消恢复。vendor lib 943 passed / 1 ignored，memory_admission 5、asc_semantics 14 / 1 ignored、asc_contracts 8 通过。上游部分测试在缺少外部 fixture 时会提前返回，不能把测试框架计数当成外部 corpus 全量执行证据。

可复现入口：`scripts/check-core-features.sh`，以及 `cargo test -p asc-droidsaw-dex --lib --test asc_contracts --test asc_semantics --test memory_admission --locked`。真实 APK 性能和分页由消费者记录，IDA/native 与目标平台仍需对应环境。
