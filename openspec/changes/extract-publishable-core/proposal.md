## Why

当前 package 只有 binary target，APK 层混合调度、解压、计时和行渲染；公共函数看似独立，却通过 stdout/stderr、Rayon 和第三方环境变量影响宿主。根目录 vendor patch 还使打包验证实际失败。需要一个可以直接依赖的分析库，而不是把现有 main 的模块全部 pub 后发布。

## What Changes

- 建立两 crate workspace：`asc-core`（分析 library）和 `rasc`（薄 CLI）。crate 名为工作名，发布前检查 registry 名称可用性。
- 领域身份/查询/结果由 core 拥有；输入解析、后端、调度、输出边界明确。
- CLI 只做参数、输入选择、命令调用、序列化、文件/管道、信号和退出码映射。
- 接受必要的受控 vendor，以独立派生 package 的 registry 版本分发；移除 root patch 的隐含依赖，核心 API 不暴露后端。具体补丁由 maintain-patched-analysis-backends 管理。
- 建立独立消费者、feature matrix、MSRV、跨平台与 registry 打包验证。

这是设计提案，业务迁移及发布均未实施。功能语义承接 `complete-cli-analysis-contracts`，不能用结构重组代替功能修复。

## Capabilities

### New Capabilities
- `core-library`: 原生、可嵌入的分析 API、数据归属、资源、错误和生命周期。
- `crate-distribution`: 独立发布、依赖隔离、补丁随 registry 分发和打包/消费者门槛。

### Modified Capabilities

无新增行为修改；CLI、分析语义由前一 change 管理。本 change 改变承载这些能力的边界与交付方式。

## Impact

迁移 `src/`、Cargo manifests、测试和 benchmark 路径；显式依赖第三方派生 package；引入 core examples 与 CLI integration tests。只有两个自有产品 crate，两个现有 vendor 可作为独立发布的第三方维护包，不为每个模块新建 package、不建立后端插件平台。第三方能力见 [依赖决策](dependencies.md)，分派见 [执行计划](../../execution-plan.md)。
