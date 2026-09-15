## Why
标准 DEX 的 data_off 大于文件长度时，validate_standard_dex 直接做长度减法，debug 构建会 panic。畸形输入必须返回领域错误。
## What Changes
- checked_sub 验证 data section 范围，拒绝所有越界值。
- 公开 Engine API 回归覆盖 len+1 和 u32::MAX，不更改其他解析语义。
## Capabilities
### New Capabilities
- `dex-data-range`: 标准 DEX 数据区范围校验。
### Modified Capabilities
## Impact
asc-core/src/dex/container.rs 及公开 API 测试；消费者更新 submodule 固定提交。
