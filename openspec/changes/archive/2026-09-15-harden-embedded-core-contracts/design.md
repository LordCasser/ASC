## Context

审计基线 c42e7e6，目标消费者 reverse-engine-backend-apk。当前 Engine/Artifact 的分离可以保留，问题发生在边界没有贯穿所有实现路径。历史 A14 文档所列通过项需用当前提交重新验证。

## Goals / Non-Goals

目标是让独立 crate 能可靠承接现有四种分析操作。此次不实现 APK 提取、JNI 绑定、资源解析或签名验证；这些仍由各自 change 管理。

## Decisions

1. feature 以独立 package/仓外 consumer 构建验证；manifest 类型仅在对应 feature 存在时进入 Limits。禁止通过 CLI 的 feature 合并补救。
2. 顶层 free functions 改为私有实现，消费者仅经 Engine 准入、账户检查进入。Engine 默认一个私有 Rayon pool，显式线程数必须大于零，包含 vendor 的并行解析路径。
3. 两种 path 输入共用有界 reader；metadata 预检后，每次追加都检查实际长度与 control。bytes 输入在保留额度和返回前检查取消，失败必须归还额度。哈希与目录检查点的粒度据实记录。
4. decompile 解析选择与全 scope 校验使用同一次条目遍历；只保留命中的条目缓冲，后续条目及时释放。每次解压计量一次，不让同一个条目的内部重复读取耗尽 decoded-bytes。重复定义按所有匹配 view 计数。错误不能输出成功源码。
5. vendor Control 与宿主共享 Arc<AtomicBool>，不建立轮询线程；后端 Cancelled/DeadlineExceeded/InputBudget/InvalidClassDefIndex 映射到领域错误，不统一报 MalformedInput。
6. result-items、locations、result-bytes 是一次操作上限。多逻辑 DEX 和多 ZIP entry 合并不得重新获得完整预算。字节值明确为估计而非 RSS；完整内存估计账户另列审计债务，不能声称已落实历史全部预算。

7. 类名正规化只识别完整 `L...;` 边界；普通 Java/slash 名称保留首字母 L，不猜测半截 descriptor。

## Risks / Trade-offs

校验目标类之后的 DEX 会使过去误报成功的输入返回错误，这是修正。默认线程数变为一个，CLI 显式配置保持自身默认。第三方单个 parse/CFG/SSA 阶段仍为协作式取消，worker 进程的硬终止由宿主负责。

## Migration Plan

先复现、后修复与复验，独立保存 ASC 提交，再由 reverse-engine submodule 固定 gitlink。源仓与 submodule 不维护两套实现。未推送提交必须显式标注，不把本地可构建当远端可复现。

## Open Questions

无阻断当前闭环的 API 决策；活跃内存全面计量与长时 fuzz 在审计记录中拆分。
