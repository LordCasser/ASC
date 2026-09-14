## 1. 后端接口与来源 — A04

- [ ] 1.1 [A04] 按维护设计建立 droidsaw 来源清单与 patch ledger，核对发布源码差异，保留证据和 license。
- [ ] 1.2 [A04] 实现 checked parse/decompile、显式选项、方法/metadata 状态、budget/control；ASC 路径无 env/stdio/panic-on-error 副作用。
- [ ] 1.3 [A04] 将 full parse 作为默认事实路径，验证 DX-P01/02；未满足事实/诊断/预算等价时关闭 scoped 优化。
- [ ] 1.4 [A04] 运行 BACK-01/02/03，记录传递依赖可达路径及非抢占阶段，交接内部 API 给 A05/A07。

## 2. 反编译语义 — A05

- [ ] 2.1 [A05] 修复 G02 与 clinit 初值次序、final 降低、各类型值/elision/截断；原 access flags 留在 metadata。
- [ ] 2.2 [A05] 修复 DECL-02/03/04 矩阵中的 metadata、构造器、异常/宽值/分支等正常支持用例，V01 有定点事实证明。
- [ ] 2.3 [A05] 把不支持/失败/不确定路径全部接到 checked 状态；必过 fixture 不得以 Incomplete 通过。
- [ ] 2.4 [A05] 跑静态事实、可编译 fixture 行为和 corpus 定点验证；补丁分项登记，保留原上游对照失败和修复后结果。

## 3. AXML — A06

- [ ] 3.1 [A06] 按维护设计的来源格式登记 axmldecoder 和现有 1–8 补丁的对应关系。
- [ ] 3.2 [A06] 实现原始 typed values、namespace scope、匹配 end、完整消费、style metadata、长字符串与有界错误路径。
- [ ] 3.3 [A06] 通过 MAN-01/02/03/04；core 领域转换不依赖 vendor Rc/DTO 或对格式化字符串反向解析。

## 4. 维护可持续性 — A13 / A14

- [ ] 4.1 [A13] 将两个派生包以独立名称/版本分发，包含可运行 patch tests、来源和 notices；完整分发任务归 extract-publishable-core。
- [ ] 4.2 [A13] 提供从干净上游重放/核对差异的维护命令，演练删一项已覆盖 patch、保留其他 patch 的升级回归。
- [ ] 4.3 [A14] 独立核对 patch inventory 与实际 diff、全部必过用例和 DEP gate；证据完整后才归档。
