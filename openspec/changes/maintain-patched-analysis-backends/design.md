## Context

`vendor/droidsaw-dex/src/parser/mod.rs` 有 scoped parse 和并行字符串池补丁；`classes.rs` 仍与 2.0.0 同源，G02 在字段输出路径。`decompile_class` 返回 String，入口及内部读取 DROIDSAW 环境开关；仅在 ASC 外层加 Result 无法知道内部是否失败。

`vendor/axmldecoder` 已修扩展长度、异常栈、typed values、未知类型与精度。进一步核对 `src/xml.rs::XmlDocument::new`，发现忽略 end namespace、根节点结束即返回，必须覆盖 namespace shadowing、结束节点一致性和尾随节点，不能沿用“剩余 unwrap 不可达”的注释作为证明。

## Goals / Non-Goals

**Goals:** 完成已承诺的分析矩阵；让补丁可独立验证、可随发布分发、可升级或删除；将后端副作用和类型挡在 core 内部。

**Non-Goals:** 重写完整反编译器；通用后端插件；保持派生 crate 与上游所有接口兼容；为图省事复制第三个候选库；用替换源码字符串恢复语义。

## Decisions

### 1. 包边界与预算

保留两个现有 vendor crate 的源码目录，最终 package 工作名为 `asc-droidsaw-dex`、`asc-axmldecoder`。它们是独立发布的第三方派生包，拥有自己的版本、README、来源、license、补丁账本和测试；不是 asc-core 的公开 API。产品层仍只有 asc-core / rasc。

不把 droidsaw 整个 src 直接塞进 core 私有模块：其 `crate::` 路径、build.rs、内部 oracle 和依赖有既有 crate 边界，大规模改路径会扩大每次升级 diff。也不要求消费者设置 `[patch.crates-io]`。发布接线见 [dependencies.md](../extract-publishable-core/dependencies.md)。

维护范围以当前两个包为上限；传递依赖若有阻断缺陷，先尝试小型边界修复或已发布版本。确需第三个 fork 时形成独立决策记录，说明证据、替代和新增维护面，由集成负责人重新分派，不允许 agent 顺手扩展 fork 链。

### 2. 补丁账本

每个 vendor 包维护 `UPSTREAM.md`、`PATCHES.md` 和可校验的来源记录 `upstream.json`。来源包含 package/version、registry archive URL、archive SHA-256、上游 repository/revision（无法验证则 null）、引入的源码树 hash、派生版本。上游原始发布包保留在可重取的测试缓存，不重复提交一份源码。

每个 patch 有稳定编号、问题输入、修改文件/符号、目标行为、测试 ID、是否必要、维护责任角色、上游状态和移除条件。至少登记下表；历史补丁编号在账本建立后仍可追踪。

| Patch | 责任与处理 |
|---|---|
| DX-P01 | scoped parse：先默认 full parse；call-site/handle、注解、debug、R8 跨类分析、错误完整性必须等价，未过则禁用或删除优化 |
| DX-P02 | 并行 string pool：只用宿主 Engine 安装的 pool，保留最小索引错误；有预算/取消，禁止另建全局 pool |
| DX-P03 | 显式后端选项、结构化结果、取消/budget：ASC 可达路径不读 env、不写 stdio；不可由源码注释猜成功 |
| DX-P04 | G02 静态值及初始化顺序；关联具体 field_idx，不因 final/输出重排错位 |
| DX-P05 | 经 fixture 证实的 metadata / 控制流问题，至少含 V01 声明顺序；每个新问题单列子编号 |
| AX-P01 | 长字符串 UTF-8/UTF-16 的两级长度、字符数量和边界 |
| AX-P02 | 栈/索引/chunk/结束节点/namespace 完整性和完整消费 |
| AX-P03 | 全部 typed value、未知 raw type/data、准确 dimensions/fractions |
| AX-P04 | 文档模型保留 namespace scope、节点顺序、text/tail/CDATA 与资源 ID；不只剩一段格式化字符串 |

AX-P01/02/03 要映射现有 PATCHES.md 的 1–8 条，不能以账本重写为由删掉旧修复。安全和正确性 patch 优先；只有测量证明有价值且不削弱语义的性能 patch 才保留。不设任意 LOC 上限；单个 patch 越过解析/输出多个子系统时重新审阅其必要性。

### 3. droidsaw 的显式调用路径

派生包新增一条真正可调用的 checked 路径，最终签名由 A04 在内部冻结，形状如下：

```text
parse_for_analysis(view, parse_options, budget, control) -> Result<ParsedDex, BackendError>
decompile_checked(parsed, selected_class_def_idx, emit_options, budget, control)
    -> Result<BackendReport, BackendError>
BackendReport { source, completeness, diagnostics, method_outcomes, metadata }
```

这是待实现 API，不是上游已有能力。`selected_class_def_idx` 保证重复 descriptor 不被再次 find_class 重选。内部可以使用已有 DexFile/ClassDefItem，core adapter 做身份核对和转换。

显式选项覆盖 trace、行号注释、错误处理、解析范围及当前可达的输出开关。新增路径不得调用 `Trace::from_env` 或 panic-on-error helper；深入检查调用链中的所有 env/stdout/stderr 入口，包括传递依赖。旧上游工具入口可保留给其 examples，但 ASC 不可到达。测试用独立子进程设置不同环境，避免测试自身并行 set_env 造成竞态。

方法级结果明确区分 Emitted、DeclarationOnly（abstract/native）、Unsupported、Failed、Indeterminate；最后三种不能组成完整成功。诊断包含 method_idx 和错误原因；替换 stub、fallback `?`、未知字段/类型等路径需逐项上报。不能靠扫描 `// DROIDSAW_INDETERMINATE` 等源码字符串推断状态。

预算/control 经解析循环、每个方法以及可长时间迭代的 CFG/SSA/优化阶段传递。核心的 Control 可用闭包/小型内部 context 映射到后端自己的类型，不让两个 vendor 依赖 asc-core，不增加公共 trait 平台。不能抢占的底层阶段如实测量；取消返回前等待已派发工作结束。

### 4. 语义修复边界

encoded_array 按 class_data 静态字段顺序映射 field_idx，缺省尾项按类型零值；短数组是合法 elision，数组自身截断是 malformed。保留所有已编码初值，包含非 final 以及被 clinit 再写的字段。

不能为满足 javac 的 final 限制而删掉真实初值或改变 clinit 读到的值；目标行为优先于原 access flag 的源码语法，确需降低 final/合成初始化结构时保留原 flags 于 metadata 并诊断。布尔/字符/负整数/长整型/浮点位值/字符串/null/引用型分别建事实 fixture；不能用浮点文本四舍五入改变初值。

metadata 至少覆盖类、字段、方法、参数注解及数组/嵌套/enum/class 值，visibility、泛型 signature、throws、外部/内部类关联、父类/接口、prototype、debug 参数/局部变量/行号。Java 源码不能完整表达的 DEX 信息放结构化 metadata，不能悄悄删除。不同 DEX 版本的 opcode、try/catch、switch/payload、宽值、构造器调用链按 [验收矩阵](../../implementation/acceptance.md) 分层验证。

完整性诊断只处理不在承诺支持集合内或确实无法转换的输入；对矩阵中的必过正常 fixture 返回 Incomplete 仍是失败，不能通过“现在会报错”关闭 G02/V01/V02。

### 5. AXML 的显式数据路径

vendor 负责 bytes → 有界、有序、完整的文档/事件模型，core 的 manifest 模块负责领域转换与 XML 输出。保留 raw type/data、raw string index/UTF-16 单元和 resource ID。不要在 vendor 格式化完丢掉原值，再在 core 解析文本。

实现 namespace push/pop、同 URI/不同 prefix、prefix shadowing、默认 namespace、带 namespace 的 attributes、匹配的 start/end 及单根文档。读完整个声明长度后才能成功；合法根后的格式节点按格式处理，第二根/尾随结构垃圾不得因提前 return 漏检。纯 XML 解析不加载外部实体/DTD，不做网络/文件访问。

文档深度、节点/属性/字符串/输出长度受限；优先迭代遍历避免输入控制的深递归栈耗尽。允许 style spans 存在并做边界校验，按 [接口契约](../../implementation/interfaces.md) 保留到 metadata；本轮不渲染富文本、不增加 ARSC/editor/writer 能力。

### 6. 升级和退出

从干净的 upstream archive 重放补丁系列/逐提交 cherry-pick，在旧/新上游与派生版本上跑同一事实 fixture。保留完整差异与新增/删除 patch 理由。原上游版本缺陷的预期失败只出现在对照报告，派生候选不能跳过对应测试。

只有上游正式发布覆盖某 patch 的语义及回归测试，才删除该 patch；只有整个 backend 通过 DEP-1–6，才换成上游或替代 crate。无须等待这一条件才能发布合格派生版本。测试及 notices 必须进入实际派生 archive，不能被上游 `exclude=/tests`、`autotests=false` 误排除。

## Migration plan

A00 固定 oracle → A04 droidsaw checked API → A05 语义修复；A06 的 AXML 可并行。A07 集成用户行为；A12 将后端隔离到 core；A13 统一改名打包。见 [工作包](../../execution-plan.md)。

## Risks / Trade-offs

新增派生包意味着真实的维护责任，不能称作零维护方案。当前两个后端都有未验证边界，因此补丁数量不能预先保证很少；若修复演变成通用 decompiler 重写，停止扩大本工作包，登记具体不满足的必过用例并拆出专门计划，不能降低本轮完成标准。
