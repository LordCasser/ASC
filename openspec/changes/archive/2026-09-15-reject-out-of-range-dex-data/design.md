## Context
60f6d8d 的修复没有触及此减法。输入可经过有效 tables/map 后到达 data_size 校验，必须先验证 data_off 的范围。
## Goals / Non-Goals
只消除单个畸形输入 panic，不重构整个 DEX validator。
## Decisions
使用 data.len().checked_sub(data_off) 与声明 data_size 比较，保留最小 header 边界及现有 MalformedInput 分类。
## Risks / Trade-offs
不会改变合法输入；错误保持既有 data_off/data_size 上下文。release 下也不能依赖整数回绕。
## Migration Plan
先在公开 API 复现 panic，修复后复验 raw DEX 和 APK 两入口、引擎复用；提交后由消费者固定 gitlink。
