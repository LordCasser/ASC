# ASC 规格与架构计划

当前 Rust 与 Python CLI **不完全一致**。已复现正则查询缺失、静态字段初始化值丢失、无校验和 DEX 的反编译接受范围不同；调试流、排序和重复条目处理也有差异。具体证据见 [CLI 审计](audits/cli-parity/report.md)。

本目录只维护 CLI 及支撑它的核心分析能力。本次没有改动业务代码。

## 基线与状态

| 对象 | 固定版本 | 用途 |
|---|---|---|
| Python main | `ccc6bae7704f5c5ef1a7271e27314837079621fb` | 从源码提取初始规格 |
| Rust rust | `e809c7b4b454ebc8eb4467f56d44a82e6139472b` | 审计对象、新分支起点 |
| 工作分支 | `lordcasser/main` | 保存规格与计划 |

`specs/` 当前是 Python 的行为基线，不能据此宣称 Rust 已符合这些规格。`changes/` 是目标行为和架构；只在对应实现与验收完成后归档、合并 delta。历史差异保留在审计目录。后续重新对照必须固定新的两侧 SHA，不能让候选分支成为自己的基线。

## 阅读顺序

1. [特性审计及证据](audits/cli-parity/report.md)：哪些一致、哪些缺失、哪些应该主动改变。
2. [Python CLI](specs/command-line/spec.md)、[APK 与逻辑 DEX](specs/apk-input/spec.md)、[查询与引用](specs/reference-search/spec.md)、[类反编译](specs/class-decompilation/spec.md)：现有行为。
3. [补齐分析契约](changes/complete-cli-analysis-contracts/proposal.md)：先决定并验证正确行为。
4. [独立 core 与薄 CLI](changes/extract-publishable-core/design.md)：两 crate 的依赖、API、生命周期与发布设计。
5. [第三方依赖决策](changes/extract-publishable-core/dependencies.md)：以特性完整度为先，保留必要补丁及后续退出条件。
6. [受控 vendor 维护](changes/maintain-patched-analysis-backends/proposal.md)：后端修复、补丁账本、独立派生包。
7. [Agent 实施入口](execution-plan.md)：15 个工作包、依赖顺序、文件所有权和交接规则。

## 后续执行

2026-09-14 更新：用户允许在保证特性完整度的前提下维护部分 patched vendor。采用现有 droidsaw-dex / axmldecoder 为起点，先修复与验证，使用独立派生 package 发布；候选替换是后续优化，不再阻断本轮实施。两个产品 crate 加最多两个现有第三方派生包，不扩展为通用后端框架。

按 [执行计划](execution-plan.md) 完成行为与后端修复，再迁移 library。三个 change 通过工作包依赖连接；同一个任务只有一个所有者。所有实施任务仍未勾选，本次只更新规格，不开始功能实施或发布。

```sh
openspec validate --all --strict --no-interactive
openspec status --change complete-cli-analysis-contracts
openspec status --change extract-publishable-core
openspec status --change maintain-patched-analysis-backends
```

采用 OpenSpec `spec-driven` 的 proposal / specs / design / tasks 结构，本次用 CLI `1.11.0` 验证。[OpenSpec 官方说明](https://github.com/Fission-AI/OpenSpec/blob/main/docs/concepts.md)
