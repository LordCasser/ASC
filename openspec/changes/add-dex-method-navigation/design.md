## Context
60f6d8d 的 Source.class、Reference.caller 与 TargetMatch 已保留真实身份。MethodIdentity 只描述引用 caller，没有完整 native method catalog；默认根扫描无法选择 assets 内 DEX。现有 ClassSelector 支持 Id，但消费者需要公开构造/验证的完整链路。

## Goals / Non-Goals
补足通用 DEX 实体导航。无需重复提供已有引用位置或构造“JNI 方法”解析器；JNI bridge 通过 native access flag 和原型消费普通 method facts。

## Decisions
1. 优先扩展已有 MethodIdentity/报告模型，方法记录含 MethodId、declaring ClassId、完整参数/返回描述符、access_flags、code presence、code offset。native/abstract 无 code 是合法状态，不是解析失败。
2. ClassId/MethodId 使用 Artifact SHA-256 + entry/logical ordinal + class_def/method table index。构造后的 ID 只表示请求，执行必须验证它存在且属于当前 Artifact；禁止以显示类名作为去重键。未定义而只在 method_ids 引用的目标不能混入声明方法清单。
3. 明确 query scope 为 root-default 或具体 entry/logical 列表；复用 expose-controlled-apk-entries 的 entry 身份。有 scope 的 Artifact view 持有原 Artifact，不能生成内容相同但归属漂移的新 ArtifactId。默认根策略不变，显式 assets entry 以同一 DEX validation pipeline 处理。
4. 完整性针对选定范围成立；范围外坏 DEX 不导致显式单范围失败，范围内坏 entry 必须失败。结果携带 scope，空命中不表示全 APK 无命中。成员方法查询的 class 约束始终是 target 的声明类，与 caller filter 分离。
5. 方法反编译只按 MethodId。优先复用 vendor 已解析 class 的目标方法 renderer；如果无法在 core 外保留 annotations/debug/参数名/静态值和错误原因，就给 vendor 增加通用受控入口及最小补丁。不得反编译整类后用字符串切割作为方法结果。
6. native/abstract 方法返回声明和无代码原因；存在实现但 decompiler 不完整必须返回 IncompleteDecompilation，partial source 不冒充完整成功。预算/取消/私有 pool 与现有 Engine 一致。
7. 同一 scope 操作共享 decode/scan/result 预算；不会因每个方法重新 parse 和释放后重新获得额度。缓存是否必要由测量决定，不先增加全局项目数据库。
8. `visit_selected_method_sources` 接受已有 `MethodTarget` 集合，在同一 DEX parse 内只渲染选中方法。原 visitor 的 consumer 回调发生在渲染之后，在回调中过滤不能减少反编译工作；消费者也无法持有 core 私有的 parsed context。因此该入口放在 core，不扩展 `MethodScope` 的 DEX 范围含义，不增加全局缓存。目标归属、存在性、重复和范围先验证，源码仍借用当前报告。

## Risks / Trade-offs
vendor method renderer 可能依赖 class context，应保留窄上下文而非复制 SSA/CFG。精确导航先保证语义一致，旧 prefix/scoped 优化需完成 metadata 与完整解析对照才能启用。

## Migration Plan
先固定 provider 提交，消费者 C 再扩展输入/输出 schema 和 artifact 源码，D 再把 native declarations 与 SO candidates 配对。所有跨语言解析在宿主/后端组合层完成。

## Open Questions
核心方法入口、class context 和 metadata 映射已落地；后续仍需用独立 golden fixture 补齐 annotations/debug/参数名及 native/abstract/构造器矩阵，并在目标平台完成 IDA/性能验收。这些扩展不改变已交付的 MethodId、scope 或 typed instruction API。

## E17.3 消费者本地验收

2026-09-16，macOS arm64，Rust 1.93.1，非优化 debug=0，代码 `72541c6`。reverse-engine 的 `scripts/apk_method_perf.sh` 对 Telegram 12.10.1 的 SRPHelper 同一组 6 个方法测量，每组独立进程；方法发现不计入操作耗时，进程 RSS 包含发现阶段。

| threads | 路径 | 操作耗时 | 峰值 RSS |
|---|---|---|---|
| 1 | selected | 12.341 s | 608.19 MiB |
| 1 | selected-batch | 5.477 s | 591.22 MiB |
| 2 | selected | 12.117 s | 579.28 MiB |
| 2 | selected-batch | 5.465 s | 589.53 MiB |

四组源码聚合 SHA-256 为 `efe105cdbf3c3b19de738453b89e08f4ef831e22d8d60ae7f25be0f1dc353adf`。本样本批处理约快 2.2 倍，RSS 无一致下降，不做普遍性或硬限制承诺。消费者真实 MCP 测试遍历 PhoneView 全部 104 成员/30 引用调用者，并按 MethodRef 得到 7,479 bytes 的 lambda 方法响应；三项真实 APK 回归 3/3 通过。
