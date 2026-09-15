## Why

Rust 已覆盖 Python CLI 的主要入口，但缺少正则查询、丢失非 final 静态初始化值，并缩小了可分析 DEX 的范围。输出、重复定义和错误处理也缺少统一契约。先确定正确行为，再迁移结构，才能区分修复与重构引入的回归。

证据见 [审计](../../audits/cli-parity/report.md)。本 change 只是一份待实施计划。

## What Changes

- 补齐显式正则查询；统一 Unicode、空值、声明类约束与非法模式的处理。
- 修复 getclass 的静态值丢失，建立 metadata / 控制流验收，允许结构安全但校验字段不一致的只读分析并报告诊断。
- 统一重复条目、重复类选择、引用身份、稳定排序和输出流。
- 保留 Rust 的 classes / manifest 扩展，建立真实规格和质量门槛。
- 不保留 Python 的偶然错误与旧文本格式兼容，不新增 DEX 导出或无关查询种类。

## Capabilities

### New Capabilities
- `rust-cli-extensions`: classes 索引及 manifest 解码的现有 Rust 能力。
- `analysis-validation`: 基于已知事实、双向比较、明确差异清单的验收。

### Modified Capabilities
- `command-line`: 统一参数、输出、诊断、退出与查询构造契约。
- `apk-input`: 明确验证边界、校验和容错、重复定义与逻辑 DEX 身份。
- `reference-search`: 显式 literal / regex，结构化引用，Unicode 与稳定聚合。
- `class-decompilation`: 按可观察语义验收，消除内部单类重建机制约束。

## Impact

将影响 `src/{cli,main,query,apk,zip,manifest}.rs`、`src/dex/` 和反编译适配路径；实际文件迁移由后续 change 完成。G02 的后端实现由 maintain-patched-analysis-backends 承担，本 change 负责集成和用户可见验收，避免重复修复。采用必要的受控 vendor，不等待上游发布；分派与依赖见 [执行计划](../../execution-plan.md)。
