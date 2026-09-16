## 1. 合同与实现
- [x] 1.1 [A18] 前置 60f6d8d；逐一列出 engine/zip/dex/vendor 分配点与生命周期；见本 design 的 allocation table，并区分实测、估算和未覆盖边界。
- [x] 1.2 [A18] 前置 1.1；对可精确度量的资源复用 Runtime 账户和 RAII permits；`Report` clone/drop、并行额度竞争、失败回收和算术溢出均有代码与基本测试。
- [x] 1.3 [A18] 前置 1.2；完成可计量的 hits/解压/批次边界，并明确 vendor 阶段的当前支持范围；fold rows 保留 scan permit 至 report 准入，跨 DEX result/decoded limits 与失败后复用已有回归，vendor 结构准入由 E18.1 补齐。
## 2. 交接
- [x] 2.1 [A18] 前置 1.3；独立 feature matrix、取消/坏 DEX 回归和资源计数器验收，更新接口文档/审计债务；不以 RSS 一次采样标记通过。
- [x] 2.2 [A18] 前置 2.1；固定 `4e3d710`/`ac1010c`/`d9f43ea` 代码提交与 `af224a2` 文档提交供消费者更新 gitlink，OpenSpec strict 校验通过；归档属于后续 review 管理动作。

## 3. 补充实施与验收（2026-09-16）
- [x] E18.1：跨 logical DEX inventory 保留 scan permit；backend normalization 在复制前按实际长度预留；vendor parser/CFG/SSA 通过注入 ledger 做结构计数和分配前阶段准入。Source metadata/text 与 partial error 生命周期计量、溢出/拒绝/取消/复用回归通过。覆盖边界见 design 和 vendor DX-P08，不承诺 emitter/allocator/RSS 全覆盖。
- [ ] E18.2：目标部署完整活跃内存/RSS 峰值验收；不把本机 RSS 采样当作进程内存硬限制证明。
- [x] E18.3-local：独立四 feature、仓外 consumer、并发重复/取消复用及 vendor ledger 测试通过；本机吞吐/RSS 实测已在 E17.3 完成；这不是目标部署 RSS 上限证明。
- [ ] E18.3-environment：目标部署平台与 IDA 组合矩阵，交由对应环境执行。
