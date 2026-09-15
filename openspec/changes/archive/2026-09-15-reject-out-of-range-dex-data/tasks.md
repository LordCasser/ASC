## 1. 修复
- [x] 1.1 [A19] 前置 c703e2d；公开 API 构造越界 data_off，保存失败证据；范围 tests/embedded_regressions.rs。
- [x] 1.2 [A19] 前置 1.1；checked_sub 替换减法；范围 dex/container.rs；验收两个越界值、APK/raw、后续有效操作。
- [x] 1.3 [A19] 前置 1.2；strict 验证/归档并本地提交，更新下游 gitlink，保留未推送状态。
