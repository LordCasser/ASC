## 1. 机械迁移与公开合同 — A10

- [x] 1.1 [A10] 等 A09 行为绿线后建立两产品 crate workspace，保留两个既有 vendor 边界；迁移 src/tests/bench，删除旧双实现。
- [x] 1.2 [A10] 固定 interfaces.md 的 Engine/Artifact、owned path/Arc/raw DEX、公共模型/错误与 feature 边界，CLI 仅依赖公开 core。
- [x] 1.3 [A10] 冻结内部 OperationContext/permits 接口供 A11/A12；不存在 todo!/占位成功，机械迁移前后行为快照一致。
- [x] 1.4 [A10] 创建仅依赖公开 API 的 examples/消费者，验证 Send+Sync、离开 Artifact 的结果、ID/账户检查及各 feature 编译。

## 2. 运行和资源 — A11

- [x] 2.1 [A11] 一个 Engine 私有 pool、Clone 共账户、可取消顶层串行准入/内部并行；不嵌套建池、不持额度互等。
- [x] 2.2 [A11] 实施所有初始 Limits、checked 增长、输入保留/解压/结构/结果/041 scratch 的 RAII 计量和 limit±1 测试；不足明确失败。
- [x] 2.3 [A11] 实施读取/解压/scan/admission/deadline 检查、错误/取消回收、同 Engine 后续复用和无后台残留；测量不可抢占阶段。
- [x] 2.4 [A11] 验证大量 041 members 不保留 N×container bytes；首版无跨操作缓存；预算估算与第三方/RSS 限制文档一致。

## 3. 后端与宿主隔离 — A12

- [x] 3.1 [A12] decompile/manifest 私有适配使用受控派生 API，转换身份/metadata/typed raw values/错误/control；第三方类型和 Rc 不泄漏。
- [x] 3.2 [A12] 可达核心与传递依赖无 env/stdio/logger/signal/cwd/process 副作用，宿主环境不改变明确选项控制的结果。
- [x] 3.3 [A12] default/manifest/decompile/all-features 相同查询事实和诊断，CLI 启用全部能力；联合 A11 验证后端预算/取消/重用。
- [x] 3.4 [A12] 仅 library 消费者跑 G02/G03/041/AXML 正常与反例，无外部 Python/JVM/CLI 进程依赖。

## 4. 必要补丁的独立分发 — A13

- [x] 4.1 [A13] 核对派生 package 名/版本/来源，将 root patch 改为 package+path+version 显式依赖；只保留两产品包和两个现有派生包。
- [x] 4.2 [A13] 核对 normalized archives、build.rs 所需文件、licenses/notices、upstream/patch ledger、显式 vendor test targets；不漏测试或隐含跳过构建 gate。
- [x] 4.3 [A13] 实现 scripts/verify-distribution.py，以真实归档构造 staging source、仓库外 version-only 消费者、完整 feature 与功能 smoke；不以 --no-verify 冒充通过。
- [x] 4.4 [A13] 建立 MSRV 1.93/stable、Linux x86_64/macOS arm64/Windows x86_64 原生 CI，产品 fmt/clippy/unit/integration/doc tests 和 vendor patch tests。
- [x] 4.5 [A13] 建立 ZIP/DEX/041/AXML/后端 fuzz 与实际 release crash harness，依赖可达性检查，记录构建期工具。
- [x] 4.6 [A13] 演练从上游重放补丁、删单项已覆盖 patch 的升级验证；生成 staged-verified 包/hash 与派生包→core→CLI 发布 checklist，不执行实际 publish。

## 5. 最终验收 — A14

- [x] 5.1 [A14] 独立复验 acceptance.md 全矩阵及 DEP-1–6，所有平台/feature/资源/副作用/归档路径有实际证据；skip 不计通过。
- [x] 5.2 [A14] 等工作量至少 10 次计时的 median/p95/RSS 报告、固定 fuzz smoke 和所有缺陷回归；正常支持 fixture 不能返回不完整蒙混过关。
- [x] 5.3 [A14] 核对每个 task/requirement 的证据和 patch diff，更新维护/API/资源文档；满足 staged-verified 后方可归档，正式 registry 未发布状态单独明确。
