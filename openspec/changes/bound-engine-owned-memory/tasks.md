## 1. 合同与实现
- [ ] 1.1 [A18] 前置 60f6d8d；逐一列出 engine/zip/dex/vendor 分配点与生命周期；写设计分配表及精确/估计边界，先解决 API 命名合同后实施。
- [ ] 1.2 [A18] 前置 1.1；对可精确度量的资源复用 Runtime 账户和 RAII permits；写资源边界代码；验收持有结果、clone/drop、并行额度竞争和算术溢出。
- [ ] 1.3 [A18] 前置 1.2；约束中间 hits/解压/批次以及可支持的 vendor 阶段；验收小结果大工作集、限额临界和失败后复用。
## 2. 交接
- [ ] 2.1 [A18] 前置 1.3；独立 feature matrix、取消/坏 DEX 回归和资源计数器验收，更新接口文档/审计债务；不以 RSS 一次采样标记通过。
- [ ] 2.2 [A18] 前置 2.1；固定独立提交供消费者更新gitlink，OpenSpec 校验归档；可与 A16/A17 独立审计，但共享 engine.rs 的实现编辑必须串行。

> 状态（2026-09-16）：`MemoryAccount`、RAII permits、输入/解压/scan/report 的部分估算边界及失败回收已有实现和单元测试。`Report` 已在 `4e3d710` 改为共享真实 payload allocation：clone 不再深拷贝后共用单个 permit，且移除了会把 payload 带出 permit 生命周期的 public `into_value`；`report_permit_follows_report_lifetime_and_releases_for_reuse` 覆盖 clone/drop/reuse。`Artifact::fold_*` 现在把每个逻辑 DEX 的 scan estimate permit 持有到 rows 转移并取得最终 report permit 之后，再释放 scratch permit；这覆盖了批内结果的临时存活窗口，但 report size 仍是结构估算。vendor parse/CFG/SSA 与中间结构也未形成完整精确账户，因此 A18 各项保持未勾选。`max_engine_owned_bytes` 是引擎 ledger 的测量或保守估算上限，不是 OS RSS 硬限制。
