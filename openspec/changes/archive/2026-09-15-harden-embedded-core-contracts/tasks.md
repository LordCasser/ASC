## 1. 复现和执行修复

- [x] 1.1 [A15] 固定 c42e7e6 审计基线，复现独立 feature 与公开 API 缺口；写入范围为审计报告/测试，验收为可重复命令与失败证据。
- [x] 1.2 [A15] 修复 feature、Engine 唯一入口和私有 pool；前置 1.1，范围 core engine/lib 与对应 tests，验收四种独立 feature 和 pool/账户检查。
- [x] 1.3 [A15] 修复有界快照、bytes control 与共享后端取消/错误映射；前置 1.1，范围 core engine/vendor control 与 PATCHES，验收增长 reader、取消/期限/复用。
- [x] 1.4 [A15] 修复全 DEX 反编译选择及一次解压计量；前置 1.1，范围 core engine 与公开 API 回归，验收后置损坏、重复定义、恰好预算。
- [x] 1.5 [A15] 修复跨 DEX 结果上限；前置 1.1，范围 engine/scan 与 tests，验收 limit±1 和单/多线程一致。
- [x] 1.6 [A15] 修复普通类名以 L 开头被截断的问题；范围 query 与 contract_query，完整 descriptor 才剥离 L/分号，验证 Login/Login.View/L。

## 2. 验证与交接

- [x] 2.1 [A15] 完成独立 package feature matrix、现有契约和派生补丁测试；前置 1.2–1.5，保留实际失败与环境限制。
- [x] 2.2 [A15] 更新当前状态、审计债务、维护补丁记录和下游 API 边界；校验 OpenSpec 后归档，交付可固定的本地提交，不宣称远端发布。
