## ADDED Requirements
### Requirement: 越界数据区返回领域错误
Engine MUST 在计算标准 DEX data section 大小前验证 data_off 不超出输入，畸形偏移 SHALL 返回 MalformedInput，不触发 panic 或整数回绕。
#### Scenario: data_off 超过文件末尾
- **WHEN** raw DEX 或 APK 中标准 DEX 的 data_off 为文件长度加一或 u32::MAX
- **THEN** 公开 API 返回 MalformedInput，Engine 可继续分析后续有效输入
