# 依赖决策：保留必要补丁，显式分发

2026-09-14 根据用户新约束修订：**特性完整度优先，允许自维护 patched vendor。** 本轮以现有 droidsaw-dex / axmldecoder 为主线修复，替换 crate 不再是交付前置条件。旧审计里的打包失败与候选缺口仍然成立；变化的是解决办法。

## 本轮选定路线

| 对象 | 决策 | 验收责任 |
|---|---|---|
| droidsaw-dex 2.0.0 vendor | 保留上游 crate 边界，增加 checked API、静态值与必要语义修复；full parse 默认，scoped 优化须证明等价 | A04/A05，DX-P01–05 |
| axmldecoder 0.5.0 vendor | 保留已有正确性补丁，补完整 namespace、typed/raw 文档及边界契约 | A06，AX-P01–04 |
| asc-core 私有 adapter | 只调用受控路径，转换身份/错误/metadata，不泄漏后端 DTO，不解析生成源码来补数据 | A07/A12 |
| 两个派生 package | 独立名称/版本发布；工作名 asc-droidsaw-dex / asc-axmldecoder；来源仍指向原上游 | A13 |
| ZIP / DEX scanner | 保留已有自有实现并补校验、Unicode、事实与预算；不为换库重写全部 | A02/A03/A11 |
| regex | 首选 fancy-regex，固定已验证版本和支持语法；超预算/不支持明确错误，不承诺 Python 全语法兼容 | A01/A03 |

droidsaw 2.0.0 的 full parse 不能修 G02：发布版与 vendor 的 classes.rs 同源，非 final 值丢失仍在 renderer。公开 class API 读环境开关，不能通过 ASC 在全局 unset env 隔离。新派生 API 是计划中的真实改动，不假设上游已有方法级公开入口。来源：[2.0.0 源码](https://docs.rs/crate/droidsaw-dex/2.0.0/source/)。

只维护这两个第三方派生包。无新增跨后端接口 crate，无 runtime backend selector，无第三份 parser 实现常驻。补丁详情由 [维护设计](../maintain-patched-analysis-backends/design.md) 负责。

## Cargo 接线与包内容

以下为目标配置示意，版本是本项目派生版本，**不是已经发布或已经拥有的 registry 名称**。A13 在准备发布时核对实际名字，不得借用上游身份。内部 dependency alias 保持现有 Rust 导入名，避免为了改名重写第三方源码。

```toml
# crates/asc-core/Cargo.toml
[dependencies]
droidsaw-dex = { package = "asc-droidsaw-dex", version = "=0.1.0", path = "../../vendor/droidsaw-dex", optional = true }
axmldecoder = { package = "asc-axmldecoder", version = "=0.1.0", path = "../../vendor/axmldecoder", optional = true }

[features]
default = []
decompile = ["dep:droidsaw-dex"]
manifest = ["dep:axmldecoder"]

# crates/asc-cli/Cargo.toml
# asc-core = { version = "0.1.0", path = "../asc-core", features = ["decompile", "manifest"] }
```

派生包起始独立 0.1.0，UPSTREAM.md 记录对应上游 2.0.0 / 0.5.0。core 对派生版本精确依赖，让库消费者不会越过未验证 patch 集；每次升级修订 pin、运行契约并发布 core 更新。其余通用依赖用正常兼容区间和 lockfile，不全面精确锁死所有传递依赖。

最终 virtual workspace 显式列四个 members，default-members 为两个产品包；vendor manifest 的 package.name 改名，库名/依赖 alias 保持一致。必须验证 examples 中原 import 可构建。根 `[patch.crates-io]` 删除；core/CLI 不包含一份未声明的嵌套源码副本。开发期 path + version 在打包后变为 registry version，不能指向未经修改的同名上游版本。[Cargo 多来源与重命名依赖](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)

第三方发布内容包含 source、build.rs 需要的文件、license/notices、upstream.json、PATCHES.md 及可运行回归测试。特别核对 droidsaw 的 `exclude=/tests`、`autotests=false`、build.rs 的缺文件早退：给 patch 测试显式 test target 并包含文件；构建依赖的 oracle/matrix 不能因打包漏文件就静默失效。移除 dev-only 生成步骤须保持同一测试责任，不能靠删测试让 archive 变绿。

`cargo package` 会规范化 manifest 并移除 patch，因此必须检查实际 archive 后再验证，不靠工作区构建证明独立消费。[Cargo package](https://doc.rust-lang.org/cargo/commands/cargo-package.html)

## 未发布阶段怎么验证

A13 提供 `scripts/verify-distribution.py`，输入 workspace 与输出临时目录，执行并记录以下步骤。该脚本只打包和本地验证，不含 publish。

1. 对两个派生包打包并验证；保存 `.crate` 的 SHA-256、文件列表、normalized Cargo.toml。其依赖应可由已有 registry 包解析。
2. 对尚依赖未发布派生版本的 core/CLI 生成归档。如引导时需要 `--no-verify`，只记为 archive-created，绝不能记为 package-verified。
3. 建立临时 **staging directory source 或测试 registry**：把上述真实归档和锁定的 registry 传递依赖解包，生成有效的 source/checksum 元数据。Cargo source replacement 指向这个完整依赖集合；source 里必须有实际派生 package，禁止 root patch、path dependency 或将原 manifest 改回本地路径。
4. 在仓库外建立只含 version 依赖的消费者；从 normalized archive 构建 core 的 feature matrix、CLI、examples 及功能 smoke。消费者 cwd、CARGO_HOME、target 独立；记录 staging 配置，区分初次准备允许下载依赖与验证阶段 offline。验证时仓库源码不可达。
5. 比对从 archive 实际解析的 package 名、版本、来源与预期，跑 G02、041、AXML unknown type、宿主 env 隔离；对 archive 内派生 patch tests 做显式 test target 运行。不能只检查编译。

这证明产物内容和补丁链可独立消费，**不证明正式 registry 已有这些版本或拥有发布权限**。实现可以完成到 `staged-verified`；实际 registry 解析列为发布前条件。之后获得实际发布授权，按“两个派生包 → core → CLI”发布，每一步等待 registry 可解析再做下一级 package/dry-run/真实消费者检查。不要为了通过规划任务偷偷执行 cargo publish。

## 候选替换保留为后续决策

以下事实来自前次同日源码/registry 核对，尚未对候选做完整能力验证。本轮不要求 agent 重复做宽泛选型。

| 候选 | 已核对事实 | 后续启用条件 |
|---|---|---|
| 上游 droidsaw-dex 2.0.0 | 已发布，公开 full parse/class API，无现有 parse_for_class；仍有 G02 和 env 问题 | 后续正式版本覆盖必要补丁且通过 DEP 全矩阵后逐项去补丁 |
| Androguard dex-decompiler | 仓库存在，但核对时 crates.io API 404；manifest 有 Git dex-parser/dex-bytecode、相邻 path apkparser | 发布链可解析并通过同一完整性/语义矩阵才替换 |
| resand 0.3.0 | 已发布，支持 ARSC/AXML raw chunks，扩展长度有实现；ResValueType::read 拒绝 unknown type | 未知原值/namespace/文档矩阵全部通过且维护面更小时考虑 |
| abxml 0.8.2 | 支持 Value::Unknown；旧依赖、passively-maintained，UTF-8 长度分支有 `== 0x80` 待核实 | 全长度范围、raw/namespace/资源矩阵通过才考虑 |
| Androguard axml-parser | 核对时 registry API 404，README 安装说法不能证明已发布 | 可独立打包消费且全矩阵通过 |
| android-abx | ABX 与 APK AXML 不同格式 | 排除 |

来源：[dex-decompiler Cargo](https://github.com/androguard/dex-decompiler/blob/main/Cargo.toml)、[resand 源码](https://docs.rs/crate/resand/0.3.0/source/src/res_value.rs)、[abxml 源码](https://docs.rs/crate/abxml/0.8.2/source/src/chunks/string_table.rs)、[axml-parser](https://github.com/androguard/axml-parser)、[android-abx](https://docs.rs/android-abx/latest/android_abx/)、[fancy-regex](https://github.com/fancy-regex/fancy-regex)。

## 依赖准入门槛

| Gate | 证据 | Owner |
|---|---|---|
| DEP-1 来源与发布链 | upstream/archive hashes、派生版本、license、MSRV、传递依赖；staged/registry 状态分别记录 | A04/A06/A13 |
| DEP-2 功能 | G02、041、注解/异常/静态值、AXML 全矩阵；必过 fixture 不能仅改成 Incomplete | A05/A06/A09/A14 |
| DEP-3 宿主 | checked 路径无 env/stdio/global 副作用，实际传递调用路径与子进程观察 | A04/A12/A14 |
| DEP-4 资源 | budget/control 覆盖、失败回收、深度/长度限制、实际 RSS 与最差不可中断阶段 | A04/A06/A11/A14 |
| DEP-5 独立消费 | normalized archive、feature matrix、仓库外消费者；无 root patch/本地路径隐含依赖 | A13/A14 |
| DEP-6 回归维护 | 上游差异账本、补丁重放/升级演练、等工作量确定性/性能报告 | A13/A14 |

源码核对和前次 tests 不代表上述实现完成。本次不修改 vendor/Cargo 业务文件，所有新 patch 和分发脚本均为待实施任务。
