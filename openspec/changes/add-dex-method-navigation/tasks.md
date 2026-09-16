## 1. 实体与范围
- [x] 1.1 [A17] 前置 60f6d8d；审计 model/dex 和 vendor method tables；写 inventory API 与 tests；MethodInventory/FieldDeclaration 保留声明身份、flags、code presence、字段静态值和完整 prototype，供 native/abstract/构造器/重载/无引用声明按真实 ID 消费。
- [x] 1.2 [A17] 前置 expose-controlled-apk-entries 1.1–1.3；写 engine 范围和 identity validation；MethodScope 覆盖 root、entry/logical、AllDetected（含 041），并拒绝跨 artifact 或范围外 ID。
## 2. 方法渲染
- [x] 2.1 [A17] 前置 1.1；复用 vendor renderer 的 class context 实现 checked MethodId 入口与 PATCHES；选中方法来源带所属 ClassId、metadata 和完整性诊断，不以整类文本切割伪造方法结果。
- [x] 2.2 [A17] 前置 1.2、2.1；接入 Engine pool/control/operation quota；单方法与批量 visitor 复用 scope parse，取消、预算失败和 incomplete source 保持 typed error。
## 3. 交接
- [x] 3.1 [A17] 前置 2.2；完成 ASC 四 feature 与仓外 C/D consumer 回归，固定 provider commits 与公开 API 供消费者使用，并通过 OpenSpec strict 校验；归档属于后续 review 管理动作。1.1 可与 A16 archive provider 并行。

## 4. 补充实施与验收（2026-09-16）
- [x] E17.1：独立 method-navigation golden 5 项覆盖 native/abstract、构造器、重载、无引用声明、annotations/debug/参数名；修复 core debug 与 method/parameter annotation 投影。selected batch 6 项验证准确选择、稳定顺序、重复/外部/范围外拒绝、空集合与逐方法源码一致。
- [x] E17.2-local：四 feature matrix、仓外 path consumer、threads=1/2 各 4 调用线程 × 20 轮取消/恢复/源码一致性通过；visitor 使用 Engine private pool。
- [ ] E17.2-environment：真实 IDA native bridge 及目标部署平台验收，由匹配环境执行，不记作本机通过。
- [x] E17.3：真实 Telegram SRPHelper 同一组 6 个方法，在 threads=1/2 各独立进程比较 selected 与 selected batch；源码指纹一致。selected 为 12.341/12.117 s，batch 为 5.477/5.465 s；峰值 RSS 见 design。PhoneView 完整 104 成员/30 引用游标及单方法读取通过，消费者 runner 与实施记录已保存。
