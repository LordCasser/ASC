# maintained-backends

## Purpose

定义 ASC 所维护的反编译和 AXML 派生依赖的来源、补丁、显式控制与完整性约束。升级或替换必须保存已承诺的分析事实，使用可复现测试验证，不以静默丢失信息换取简化或性能。

## Requirements


### Requirement: Traceable maintained source
每个派生 backend SHALL 固定可验证的上游 archive 与版本，为所有差异登记 patch ID、修改范围、fixture、责任角色和移除条件，保留原 license/notices；不把目录移动当作修复或解耦完成。

#### Scenario: Reconstruct a release
- **WHEN** 维护者从记录的 upstream archive 和补丁历史重建派生版本
- **THEN** 能复现所发布源代码，来源 hash 与 patch 账本一致，每个行为补丁有回归测试。

### Requirement: Explicit checked decompiler entry
派生反编译器 SHALL 提供 ASC 可达的显式选项/预算/取消及结构化结果入口，报告每个方法和 metadata 的完整性，不读隐式环境配置、不写进程输出、不把内部失败转成成功源码。

#### Scenario: Environment and incomplete method
- **WHEN** 设置所有已发现的 DROIDSAW 环境开关，执行正常及不支持方法 fixture
- **THEN** 正常结果由传入选项唯一决定，stdio 无副作用；不支持方法返回结构化状态，core 映射为不完整错误。

### Requirement: Semantic preservation before optimization
后端 SHALL 通过必过静态值、metadata、控制流和 DEX 版本矩阵；scoped/parallel 优化必须保持事实、诊断、输入校验与资源控制，不可通过删除信息换取性能。

#### Scenario: Encoded initializer overwritten later
- **WHEN** 非 final 静态字段有 encoded value 且 clinit 在覆盖前读取它
- **THEN** 源码行为保留初始读取和后续覆盖；返回不完整或删掉初值均不满足该支持场景。

#### Scenario: Scoped parse loses cross-class fact
- **WHEN** scoped parse 不能保留 full parse 的必需跨类事实或诊断
- **THEN** 使用 full parse，或先修复优化再启用；不把未比较的注释/metadata 默认全部删除。

### Requirement: Lossless bounded manifest backend
AXML 后端 SHALL 保留有序节点、namespace 作用域、文本、原始 typed value 与必要元数据，验证完整文档、边界和预算；不得以未知 value 或节点提前返回造成信息丢失。

#### Scenario: Namespace shadow and trailing root
- **WHEN** 文档嵌套重绑定 prefix 后退出作用域，或在第一根后附第二根
- **THEN** 前者恢复外层绑定且保留文本；后者返回结构错误，无 panic 或部分成功。

### Requirement: Controlled upgrade and replacement
维护者 SHALL 以相同验收矩阵验证派生升级和候选替换，仅删除已被发布版覆盖的补丁；性能补丁可删除，已承诺分析能力不可删除。

#### Scenario: Upstream fixes one patch
- **WHEN** 上游新版本修复扩展字符串但未支持未知 raw type
- **THEN** 仅删除已验证的对应补丁，其余补丁继续维护；不得把整包换回上游导致能力回归。
