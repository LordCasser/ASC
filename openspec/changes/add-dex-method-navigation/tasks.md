## 1. 实体与范围
- [x] 1.1 [A17] 前置 60f6d8d；审计 model/dex 和 vendor method tables；写 inventory API 与 tests；MethodInventory/FieldDeclaration 保留声明身份、flags、code presence、字段静态值和完整 prototype，供 native/abstract/构造器/重载/无引用声明按真实 ID 消费。
- [x] 1.2 [A17] 前置 expose-controlled-apk-entries 1.1–1.3；写 engine 范围和 identity validation；MethodScope 覆盖 root、entry/logical、AllDetected（含 041），并拒绝跨 artifact 或范围外 ID。
## 2. 方法渲染
- [x] 2.1 [A17] 前置 1.1；复用 vendor renderer 的 class context 实现 checked MethodId 入口与 PATCHES；选中方法来源带所属 ClassId、metadata 和完整性诊断，不以整类文本切割伪造方法结果。
- [x] 2.2 [A17] 前置 1.2、2.1；接入 Engine pool/control/operation quota；单方法与批量 visitor 复用 scope parse，取消、预算失败和 incomplete source 保持 typed error。
## 3. 交接
- [x] 3.1 [A17] 前置 2.2；完成 ASC 四 feature 与仓外 C/D consumer 回归，固定 provider commits 与公开 API 供消费者使用，并通过 OpenSpec strict 校验；归档属于后续 review 管理动作。1.1 可与 A16 archive provider 并行。

> 状态（2026-09-16）：上述核心接口、scope/identity validation、checked method renderer、typed instruction facts、批量 visitor 和 C/D consumer handoff 已完成；ASC all-feature 本轮证据为 209 tests 全通过，feature matrix 与仓外 consumer 日志仍以 `openspec/audits/embedding/report.md` 所列路径为准。完整 native/abstract/构造器/metadata fixture 矩阵、IDA 运行和性能基线不属于本次基本验收，拆到下列扩展项。

## 4. 扩展/环境验收（不阻塞本次 provider 交付）
- [ ] E17.1：补齐 native/abstract/构造器/重载/无引用声明及 annotations/debug/参数名的独立 golden fixture 矩阵；当前实现已按真实 DEX 表和 flags 提供数据，本轮未声称矩阵全部运行。
- [ ] E17.2：在目标平台完成完整 feature/consumer/IDA native bridge 运行；本仓只记录公开 core 与 C/D API 交接，不把 IDA 环境结果倒灌为 ASC 证据。
- [ ] E17.3：基于真实 APK 测量批量 visitor 与 selected-method 的性能、峰值内存和分页策略；不改变当前确定性 API 合同。
