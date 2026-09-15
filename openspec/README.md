# ASC 规格与实现

当前产品是 `asc-core` 通用分析库与 `rasc` 薄 CLI；维护分支为 `lordcasser/main`。`specs/` 是已合并合同，`changes/` 是待实施或待验收目标，`changes/archive/` 保存历史变更。历史 A00–A14 证据不能当作当前提交的测试结果。

## 当前工作

- [嵌入审计](audits/embedding/report.md)：固定 c42e7e6，记录复现、修复和独立债务。
- 2026-09-16 provider/navigation checkpoint：A16 2.1 已有 feature matrix 与仓外 path consumer 证据；A17 定向声明/DEX/instruction visitor 已实现；A18 仍是未完成的内存账户债务。
- [嵌入合同修复](changes/archive/2026-09-15-harden-embedded-core-contracts/proposal.md)：独立 feature、输入控制、全 DEX 校验、私有 pool 和跨 DEX 结果预算。
- [历史 CLI 审计](audits/cli-parity/report.md) 与 [验收矩阵](implementation/acceptance.md)：保留原始基线和未验证平台，不能把目录归档理解为所有声明都已验证。

reverse-engine 以 submodule 的 path crate 消费此库。通用解析原语和 vendor 修复在本仓按 OpenSpec 开发；MCP、IDA、样本任务和 artifact 发布在消费者中实现。库不依赖 CLI 或外部进程。

```sh
scripts/check-core-features.sh
cargo test -p asc-droidsaw-dex --test asc_contracts --locked
openspec validate --all --strict --no-interactive
```

分发脚本 `scripts/verify-distribution.py` 验证 registry staging，不执行正式发布；path/submodule 集成不要求先发布 registry。确认新的审计证据后才能更新对应 task 的勾选状态。

## 下一阶段 provider changes

- [受控 APK 条目](changes/expose-controlled-apk-entries/proposal.md)：供消费者 artifact 提取使用。
- [DEX 方法导航](changes/add-dex-method-navigation/proposal.md)：供源码精确导航与 JNI 声明清单使用。
- [活跃内存账户](changes/bound-engine-owned-memory/proposal.md)：独立修复 MEM-01/02，不混入接入变更。

A16 的消费者 staged-output 联合验收、A17 的完整 metadata/feature 矩阵，以及 A18 的完整 vendor 内存账户仍未完成；没有把实现 checkpoint 当作归档或正式发布。
