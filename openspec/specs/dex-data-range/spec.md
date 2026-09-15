# dex-data-range Specification

## Purpose

定义标准 DEX 数据区边界校验，要求对外部输入的 data_off 和 data_size 使用受检算术，确保 raw DEX 与 APK 两条入口对越界声明返回可分类的领域错误，而不是触发 panic、回绕或破坏后续操作的资源状态。

## Requirements

### Requirement: 越界数据区返回领域错误
Engine MUST 在计算标准 DEX data section 大小前验证 data_off 不超出输入，畸形偏移 SHALL 返回 MalformedInput，不触发 panic 或整数回绕。
#### Scenario: data_off 超过文件末尾
- **WHEN** raw DEX 或 APK 中标准 DEX 的 data_off 为文件长度加一或 u32::MAX
- **THEN** 公开 API 返回 MalformedInput，Engine 可继续分析后续有效输入
