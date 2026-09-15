## Why
reverse-engine 需要从 APK 提取 DEX、SO 与资源并发布为宿主管理的 artifact。当前 ASC ZIP catalog/read_entry 是私有实现；消费者再写一个完整 ZIP parser 会使条目身份、CRC 和预算语义分叉。目录与受控读取属于通用 core，发布与租约属于消费者。

## What Changes
- 公开不可变 archive entry 身份、原始名称字节和有界目录查询。
- 经 Engine 读取指定 entry 到调用方提供的 writer，复用现有 ZIP 校验、取消与累计 decoded 预算。
- 明确未完成写入的提交责任；不向 core 引入磁盘路径发布、样本 MD5、MCP 或后台任务。

## Capabilities
### New Capabilities
- `controlled-apk-entries`: 通用 archive 身份与受控内容读取。
### Modified Capabilities

## Impact
涉及 asc-core engine/model/zip 与契约测试；薄 CLI 可后续消费。reverse-engine 的 add-managed-artifacts-and-apk-extraction 依赖此 provider，后续 JNI native inventory 使用同一 entry 身份。
