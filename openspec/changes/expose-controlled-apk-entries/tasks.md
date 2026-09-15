## 1. Provider
- [x] 1.1 [A16] 前置 60f6d8d；核对 zip read_entry 与 Artifact 账户；写 model/engine API 及身份契约测试；验收重复名、raw bytes、跨 artifact 拒绝。
- [x] 1.2 [A16] 前置 1.1；将内部 inflate 扩为受控 sink 并复用现有 buffered 路径；写 zip/engine；验收 stored/deflate、CRC、LFH/CD、取消、writer 失败和 limit±1。
- [x] 1.3 [A16] 前置 1.2；完成 batch/shared quota，限制 catalog 输出；验收跨 entry 累计额度、失败后复用，无成功 partial artifact。
## 2. 交接
- [x] 2.1 [A16] 前置 1.3；运行 default/manifest/decompile/all-feature 与仓外 consumer，记录实际命令；发布本地提交，由 reverse-engine 固定 gitlink。证据：`scripts/check-core-features.sh`、`/tmp/asc-audit-logs/feature-matrix-after-gates-final.log`、`/tmp/asc-audit-logs/consumer-path-final.log`。
- [x] 2.2 [A16] 前置 2.1；与消费者 B 的 staged-output 测试联合验证；宿主负责原子发布和父子身份，不混入此 provider；OpenSpec 校验后保留 change 供 review，归档由后续管理动作完成。

> 状态（2026-09-16）：1.1–1.3 与 2.1 的 core/仓外命令已执行并保留日志；消费者 B 的 staged-output 联合测试已通过，宿主发布/父子身份职责仍在 reverse-engine。核心交付已完成并保留本 change 供 review，归档是后续管理动作。
