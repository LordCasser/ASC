# core-library

## Purpose

见 change 归档说明。

## Requirements


### Requirement: Library-owned analysis contract
asc-core SHALL 独立提供输入加载、类索引、引用查询及可选反编译/manifest 能力，公开接口只包含自身领域类型和必要的标准库类型。CLI 仅包装此 API，业务规则不能复制到 CLI。

#### Scenario: Consumer without CLI
- **WHEN** 独立 crate 只依赖 asc-core
- **THEN** 可以完成 classes/references；启用对应 feature 后可反编译和解码 manifest，无需 rasc、clap 或子进程。

#### Scenario: Manifest does not depend on DEX parsing
- **WHEN** APK 有合法 manifest 但没有 DEX，或其中不相关 DEX 内容损坏
- **THEN** open 只建立 archive catalog，manifest 按自己的 entry 校验可成功；dexes/classes/references/getclass 才执行 DEX 解析和对应错误合同。

### Requirement: Immutable input ownership and identity
Artifact SHALL 拥有不可变输入和基于内容 SHA-256 的稳定身份；path 默认有界快照，bytes 接口接收不可变 owned 数据。041 共享容器地址空间；返回结果在 Artifact 销毁后仍有效。ID 可在相同内容重开后复用，不得用于不同内容或不存在的索引；Artifact 操作只使用其所属 Engine 账户。

#### Scenario: Drop artifact after query
- **WHEN** 查询结果已返回后销毁 Artifact
- **THEN** 结果仍可安全读取/序列化；没有 mmap 或借用悬垂。

#### Scenario: Many logical members
- **WHEN** 一个 041 容器包含数千成员
- **THEN** 内部 view 不为每成员常驻一份完整容器，单次后端 scratch 受额度控制。

#### Scenario: Clone engine and reuse identity
- **WHEN** Engine 被 Clone，或相同/不同 bytes 被重新打开并接收旧 ID
- **THEN** Clone 共用账户和 pool，相同内容/有效索引可复用 ID，不同内容/非法索引拒绝；其他独立账户的 Artifact 不可混用。

### Requirement: Controlled execution and resource lifetime
Engine SHALL 复用私有调度资源，按 implementation/interfaces.md 实施有限可配置预算、检查点和确定结果顺序；首版顶层串行可取消准入、内部共池并行，默认不缓存派生索引/源码。失败或取消归还操作资源且不保留后台任务；输入额度随 Artifact 释放。第三方不可抢占阶段和非 RSS 硬限制必须明确。

#### Scenario: Limit or cancellation followed by reuse
- **WHEN** 一次查询触发 ResourceLimit 或 Cancelled，随后在同 Engine 执行小查询
- **THEN** 后者可完成，无额度泄漏、死锁或残留半初始化状态。

#### Scenario: Another call waits for admission
- **WHEN** 一个操作正在执行，同 Engine 的第二个调用等待准入时被取消
- **THEN** 第二个调用可取消，不占用 pool worker 等待、不持部分执行额度造成死锁；第一个调用按自身 control 完成。

### Requirement: Embedding without process side effects
core SHALL 不写 stdout/stderr、不安装全局 logger、不改环境/信号/cwd、不退出进程、不执行外部工具。错误/诊断返回宿主，后端同样必须满足此可达路径约束。

#### Scenario: Host changes backend environment flags
- **WHEN** 宿主环境存在 DROIDSAW 调试、panic 或格式开关
- **THEN** 库行为由显式选项决定，不受这些环境开关暗中改变；没有符合条件的后端时该发布 gate 不通过。

### Requirement: Complete typed results and errors
core SHALL 区分空集、未找到、非法输入、资源耗尽、取消、后端错误及不完整反编译，返回来源和定位上下文；默认成功结果完整，不借未转义文本表达身份。

#### Scenario: Backend emits partial source
- **WHEN** 只有部分方法被正确反编译
- **THEN** 返回明确不完整错误和诊断，部分源码仅为显式可选信息，不当完整成功。
