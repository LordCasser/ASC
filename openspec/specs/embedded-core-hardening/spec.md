# embedded-core-hardening Specification

## Purpose

定义 ASC 作为独立 crate 嵌入时的最低可靠性合同：公开 Engine 入口统一持有私有线程池及输入准入，协作式取消和错误分类贯穿解析，整个操作共享结果上限，反编译按完整扫描范围校验并提供确定性身份。

## Requirements

### Requirement: Unambiguous class name normalization
类查询 SHALL 只将完整 `L...;` 识别为 descriptor；普通 Java/斜线类名仅转换分隔符，不删除原始首字母 L。半截 descriptor 不再通过猜测补齐。

#### Scenario: Class name beginning with L
- **WHEN** 消费者查询 Login、Login.View、L 或完整 LLogin;
- **THEN** 分别规范化为 LLogin;、LLogin/View;、LL; 和 LLogin;，不查询 ogin 或错误地拒绝合法类 L。

### Requirement: Independent feature and admission boundary
asc-core SHALL 在 default、manifest、decompile 与两者同时启用时独立编译，分析操作仅通过 Engine 的账户和准入检查执行，所有内部 Rayon 工作使用该 Engine 的私有 pool；未配置时使用一个 worker。

#### Scenario: Consumer without feature unification
- **WHEN** 仓外消费者仅引用 asc-core 并逐项切换 feature
- **THEN** 每种组合编译成功，无 rasc/clap 依赖，非 manifest 构建不需要 XML 后端。

#### Scenario: Pool and foreign artifact
- **WHEN** 指定两个 worker 反编译，或用另一个 Engine 的 Artifact 查询
- **THEN** vendor 并行阶段使用这两个 worker；跨账户查询返回 InvalidQuery，不能绕过公开 free function 执行。

### Requirement: Bounded cancellable input and backend execution
core SHALL 在 path 快照增长前检查实际上限，并在 bytes 输入入口观察 control；取消或期限通过受控后端共享和传递，错误类型保留原因，失败后资源可复用。

#### Scenario: Growing reader
- **WHEN** 读取的数据超过 metadata 预告及 max_input_bytes
- **THEN** 超限块不追加到快照，返回 ResourceLimit；同 Engine 可继续打开小输入。

#### Scenario: Cancelled bytes and shared backend control
- **WHEN** bytes 输入之前取消，或后端 parse/emit 期间宿主设置取消标记
- **THEN** 在下一检查点返回 Cancelled；deadline 保留 Deadline 原因，不报 MalformedInput，无轮询后台线程。

### Requirement: Complete class selection across DEX scope
类反编译 SHALL 验证所有选中 DEX，保留确定的首个匹配身份并统计重复定义；同条目只解压计费一次，诊断不因内部重复验证而重复。

#### Scenario: Broken DEX after selected class
- **WHEN** 第一条目定义目标类，后续选中 DEX 损坏
- **THEN** 返回该损坏错误而非成功源码；把条目放在前后都不能绕过校验。

#### Scenario: Exact decoded budget and duplicate definition
- **WHEN** 解压总量恰好等于预算，目标类在两个条目重复定义
- **THEN** 可完成反编译，身份按条目顺序确定，诊断说明重复，内部二次解析不增加解压计费。

### Requirement: Operation result ceilings
core SHALL 对 classes/references 的整个操作实施顶层数量、引用位置与估计字节上限，不能按每个逻辑 DEX 重新分配完整结果预算。

#### Scenario: Multi DEX exceeds combined result budget
- **WHEN** 两个 DEX 各自低于上限但合并结果超限
- **THEN** 返回 ResourceLimit，无成功部分结果；提高至总量边界后成功且线程数不改变事实或错误选择。
