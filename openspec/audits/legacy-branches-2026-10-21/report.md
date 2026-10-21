# 旧分支收敛审计（2026-10-21）

基线：当前产品 `lordcasser/main@0d461d0`；旧 Python `main@ccc6bae7704f5c5ef1a7271e27314837079621fb`；早期原型 `rust-rewrite@7526ff2d56ed3b1f8d0c055b9a50790c45555418`。后者直接继承前者，两者与当前产品原先没有共同祖先。审计使用本地 Git 固定树和已有合同/证据，不声称本轮重跑了历史验收。

## 保留内容与合入方式

- 恢复 `main:LICENSE` 的 Apache-2.0 原文。当前 workspace 与两个产品 crate 均声明 Apache-2.0，但根目录缺少许可证全文。
- 将 `rust-rewrite`（同时包含 `main`）以 `ours` 策略合入历史，保留当前产品树；只另加许可证和本审计。该合并表示历史经过审查并收敛，不表示把原型功能合入产品。
- 固定 Python SHA 仍用于 CLI parity 复现与 corpus 来源。接入祖先历史后，删除旧本地/远端分支仍可通过 `git show ccc6bae:tests/dex_fixture.py` 或 `git archive ccc6bae` 读取基线，不依赖孤立对象的保留期。

## 内容审查

| 旧内容 | 结论与现有证据 |
| --- | --- |
| Python string/type/method/field 查询、method 0、共享 code_item、map 回退、opcode 边界 | 已由结构化身份和契约替代；[验收矩阵](../../implementation/acceptance.md) REF-01–04；[历史 CLI 审计](../cli-parity/report.md)；[A09](../../implementation/evidence/A09.md)。不搬回 Python scanner 的 dense-bucket 误归因行为。 |
| static_values、字段次序、零 checksum、DEX 041 | DECL-01、IN-03/04；[A05](../../implementation/evidence/A05.md)、[A14](../../implementation/evidence/A14.md)。当前 `contract_input.rs` 有 `in04_zero_checksum_fixture_warns_and_preserves_bytes`，vendor `asc_contracts` 保留 G02 初值回归。 |
| 历史真实负载和参考输出 | corpus registry 已记录原始 ZIP 与裸 DEX 哈希；`reference-workload-classes.dex` 的 SHA-256 为 `5cd2401e9ec9a41fc5f78d06acb10d9f334a973bb82df9af381d3e5024aee337`。本轮再次比较旧 ZIP 内 classes.dex 与当前 fixture 字节。无需再复制 ZIP。 |
| Rust 原型 CLI/GUI/handler | `src/main.rs` 的 findrefs 只有打印，getclass 只枚举 DEX；`asc_handler.rs` 的重建/反编译/查询接线仍 TODO；GUI Find 按钮无操作。没有可迁移的完整用户能力。 |
| Rust 原型 APK/DEX/locator/LEB128 与 builder/remapper | mmap + ZIP + DEX + 指令扫描已有受控输入、预算和失败合同；原型 APK 短文件 EOCD 扫描有直接越界切片风险，handler 还吞掉 inflate/parse 错误。重建器是 Python 内部重建路径的移植，当前产品使用受控 native backend；[历史审计的明确范围](../cli-parity/report.md) 已决定不新增 DEX writer 产品面。原型基础 roundtrip/type 单测不构成迁回平行解析器的理由。 |
| Python GUI、依赖和分发脚本 | 与当前通用库 + 薄 CLI 的产品范围和 native backend 不符；不增加 GUI/runtime 依赖，不恢复 Python 入口。 |

未发现需要迁入的独有业务修复。以上是本次源码/合同对照结论，不是所有输入行为等价的证明；既有 A16–A18 平台/内存待验收项保持原状态。

## 独立债务

当前树没有 `.github`。旧 Python CI 的无跳过回归、配对性能比较及 release 祖先检查可作为未来 Rust CI 的策略参考；直接复制将引用已移除的 Python runtime、脚本和分支。CI 重建另行处理，本次不新增 workflow，不将历史本机证据当持续集成或跨平台通过证明。

## 本轮验证

- 旧 `main` 是 `rust-rewrite` 祖先；本地与 origin 两个旧分支尖端一致。
- 恢复的 LICENSE 与旧 main blob 完全一致；历史 ZIP 的 classes.dex 与当前 corpus fixture 完全一致。
- 合并相对第一父提交只改变 LICENSE、本审计和审计入口；产品代码、依赖、测试与 fixture 均不变，因此不重新编译或重跑业务测试。
- 提交前执行 `git diff --cached --check`；提交后确认两个旧尖端都是 HEAD 祖先，再推送主分支并删除旧分支。
