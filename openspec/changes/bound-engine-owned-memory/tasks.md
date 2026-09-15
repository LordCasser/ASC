## 1. 合同与实现
- [x] 1.1 [A18] 前置 60f6d8d；逐一列出 engine/zip/dex/vendor 分配点与生命周期；见本 design 的 allocation table，并区分实测、估算和未覆盖边界。
- [x] 1.2 [A18] 前置 1.1；对可精确度量的资源复用 Runtime 账户和 RAII permits；`Report` clone/drop、并行额度竞争、失败回收和算术溢出均有代码与基本测试。
- [x] 1.3 [A18] 前置 1.2；完成可计量的 hits/解压/批次边界，并明确 vendor 阶段的当前支持范围；fold rows 保留 scan permit 至 report 准入，跨 DEX result/decoded limits 与失败后复用已有回归，vendor 未覆盖部分列入 E18.1。
## 2. 交接
- [x] 2.1 [A18] 前置 1.3；独立 feature matrix、取消/坏 DEX 回归和资源计数器验收，更新接口文档/审计债务；不以 RSS 一次采样标记通过。
- [x] 2.2 [A18] 前置 2.1；固定 `4e3d710`/`ac1010c`/`d9f43ea` 代码提交与 `af224a2` 文档提交供消费者更新 gitlink，OpenSpec strict 校验通过；归档属于后续 review 管理动作。

> 状态（2026-09-16）：本次 bounded acceptance 已完成：`MemoryAccount`/RAII、input/catalog、decoded quota、fold scan scratch、Report ownership、失败回收和 feature/basic regression 均有实现与证据。`Report` 在 `4e3d710` 改为共享真实 payload allocation，clone 不再深拷贝后共用单个 permit；`ac1010c` 让 fold rows 持有 scan estimate permit 至最终 report permit 取得；`d9f43ea` 禁止 charged report 被内部提取后脱离 permit。method inventory 的跨 logical DEX 中间累积、vendor parse/CFG/SSA 与 allocator metadata 仍不属于精确覆盖，列入下列扩展项。`max_engine_owned_bytes` 是引擎 ledger 的测量或保守估算上限，不是 OS RSS 硬限制。

## 3. 扩展/环境验收（不阻塞本次 bounded acceptance）
- [ ] E18.1：为 `method_inventory` 的跨 logical DEX 中间 vectors、vendor parse/CFG/SSA、backend scratch 建立分配前 permit 或受验证的阶段上界；当前表中已明确这些未覆盖窗口。
- [ ] E18.2：在目标部署环境验证完整活跃内存/RSS 与峰值行为；core 不把 OS RSS 采样或消费者序列化副本纳入 ledger 合同。
- [ ] E18.3：补齐完整 feature/平台/压力矩阵及并行吞吐基线；本轮只要求确定性基本回归与公开 API review。
