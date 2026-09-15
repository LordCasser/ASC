## 1. 实体与范围
- [ ] 1.1 [A17] 前置 60f6d8d；审计 model/dex 和 vendor method tables；写 inventory API 与 tests；验收 native/abstract/构造器/重载/无引用声明。
- [ ] 1.2 [A17] 前置 expose-controlled-apk-entries 1.1–1.3；写 engine 范围和 identity validation；验收多逻辑 DEX、assets、跨 artifact ID、范围内外坏 entry。
## 2. 方法渲染
- [ ] 2.1 [A17] 前置 1.1；检查 vendor renderer 的 class context；实现最小 checked method 入口与 PATCHES；验收 annotations/debug/参数名/错误分类，完整类与方法结果对照。
- [ ] 2.2 [A17] 前置 1.2、2.1；接入 Engine pool/control/operation quota；验收 limit±1、失败后复用、取消和不完整源码不成功。
## 3. 交接
- [ ] 3.1 [A17] 前置 2.2；四 feature 与仓外 consumer 回归；产出固定 provider commit 与契约样本供消费者 C/D 使用，OpenSpec 校验归档。1.1 可与 A16 archive provider 并行。

> 状态（2026-09-16）：MethodInventory、FieldDeclaration、MethodTarget、显式 MethodScope、`decompile_method`、`visit_method_sources`、`visit_method_declarations`、`instructions_for_methods_in_scope` 与 `dexes_in_scope` 已落地；`method_inventory_accepts_nested_dex_scope_and_all_detected`、`batch_method_visitor_reuses_one_scope_parse` 等 core tests 通过。完整 native/abstract/构造器/metadata 矩阵、四 feature 仓外 consumer 与消费者交接仍未完成，因此 1.1–3.1 保持未勾选。
