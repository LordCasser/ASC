## Purpose

确保 core 和 CLI 的发布产物可在仓库外独立解析、构建及使用，使工作区路径或发布时被删除的 patch 不再成为隐含依赖；必要 vendor 以明确的第三方派生 package 分发。

## ADDED Requirements

### Requirement: Two independent packages
workspace SHALL 包含一个可发布 core library 和一个 CLI 产品 package，CLI 单向依赖 core；可包含两个现有 vendor 的独立派生 package。各包具有独立元数据、文档与测试，核心无 binary/CLI 依赖。

#### Scenario: Build core alone
- **WHEN** 仅选择 core package 构建和测试
- **THEN** 不编译或调用 CLI；公开分析行为仍完整可用。

### Requirement: Registry-resolvable maintained dependencies
发布产物 SHALL 使用 registry 可解析的版本依赖；必要 vendor 以独立名称/版本的派生 package 发布，保留来源/许可证/测试。core 不能依赖消费者的 root patch、Git-only 或本地路径；不能通过禁用功能宣称完整 CLI 已达标。

#### Scenario: Package in external directory
- **WHEN** 去掉工作区配置，在外部解包 .crate 并构建消费者
- **THEN** 编译和功能 smoke 通过，包含 G02、041 与 unknown AXML，不能出现缺失 parse_for_class 或补丁退化。

#### Scenario: Required fork version is not yet published
- **WHEN** 派生包和 core 尚未存在于正式 registry
- **THEN** 实施阶段使用真实归档的隔离 staging 消费测试并记录范围；正式 registry 解析仍为待发布条件，不用 --no-verify 或 root patch 伪装通过。

### Requirement: Feature and toolchain verification
core SHALL 默认只含输入/classes/references，提供独立 manifest/decompile features；feature 增加能力而不改变已有查询结果。MSRV 与宣称支持的平台都必须实际验证。

#### Scenario: Minimal and full consumers
- **WHEN** 相同 references 在 default 与 all-features 下运行
- **THEN** 结果和诊断相同；default 不拉入反编译器，CLI 构建显式启用全部承诺能力。

### Requirement: Release readiness evidence
发布 SHALL 以 DEP-1 至 DEP-6、package verification、外部消费者、文档、许可证、功能/资源验证为门槛，按依赖顺序发布；未知后端能力必须阻断完整交付声明。

#### Scenario: Registry dry-run before core publication
- **WHEN** CLI 依赖的 core 版本尚未在 registry 存在
- **THEN** 不能将 workspace path 构建成功当作 registry 可安装证明；用 staging 验证并先发布 core。
