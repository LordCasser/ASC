## 1. 核心关系查询
- [x] 1.1 [A20] 前置 Rust d78123f 与上游语义审计；写 model/query/dex/engine/lib 和专属夹具；验收 direct-only、精确匹配、Unicode、外部目标、重复身份及默认 feature；交接公开 API 与测试结果。
- [x] 1.2 [A20] 前置 1.1；写同范围资源/取消接线与测试；验收坏声明、041/跨 DEX、显式 scope、所有权、预算失败恢复与 Report clone 内存寿命；交接具体失败边界和命令。

## 2. CLI 与交付
- [x] 2.1 [A20] 前置 1.1 公共接口；写 rasc、JSON schema、README；验收参数提前拒绝、text/JSON/空集/-o 与稳定顺序，禁止 CLI 扫描 DEX。
- [x] 2.2 [A20] 前置 1.1–2.1；运行目标测试、workspace/feature matrix 和 OpenSpec strict，写 evidence/A20；独立 review 后标记已验证任务，不修改未完成环境矩阵。
