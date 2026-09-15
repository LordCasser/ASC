## Why

reverse-engine 将直接链接 lordcasser/main 的 asc-core。对 c42e7e6 的嵌入审计发现，workspace feature 合并掩盖独立 core 编译问题，反编译提前停止校验输入，path 快照只在读完后检查增长，取消与线程池没有贯穿受控后端。现有归档验收不能代替这些路径的回归验证。

## What Changes

- 修复独立 feature 编译；只有 Engine 暴露顶层分析入口。
- path 读取在增长前核验上限，open_bytes 响应 control。
- Engine 默认使用一个私有 worker，反编译复用该 pool；共享取消标记并保留错误原因。
- 类反编译校验全部选中 DEX，跨 entry 统计重复定义，每条目只解压一次。
- 校验整个操作的结果数量、位置及估计字节上限，防止多 DEX 乘大预算。
- 增加公开 API 回归、独立 feature gate，纠正审计和实施状态文档。

## Capabilities

### New Capabilities
- `embedded-core-hardening`: 下游嵌入所需的编译、执行、输入与结果边界。

### Modified Capabilities

## Impact

asc-core engine/scan、派生 decompiler 的取消 token、公开 API 测试与质量脚本。无 MCP、HTTP、样本任务或 IDA 依赖；不增加通用插件框架。完整活跃内存估计账户、跨平台原生验证和 JNI 新能力单独记录，不以本 change 宣称已完成。
