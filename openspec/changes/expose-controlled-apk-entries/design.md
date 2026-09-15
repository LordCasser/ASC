## Context
60f6d8d 已提供 Artifact SHA-256 与 DEX entry/logical 身份，但任意 ZIP 条目读取仍为私有。宿主以 MD5 命名原始样本，两种 digest 的用途必须区分。

## Goals / Non-Goals
提供可供任何 Rust 消费者复用的目录和提取原语。core 不选择输出目录、不写宿主索引、不决定覆盖或 artifact TTL。

## Decisions
1. `ArchiveEntryId = (ArtifactId, central_directory_ordinal)`，不是文件名。条目投影携带 raw_name bytes、压缩方法、声明大小/CRC、加密及目录属性。过滤名称只能影响输出，不能绕过 catalog 结构校验。
2. `Engine::archive_entries` 返回稳定顺序的条目事实；查询有 max_items/max_result_bytes。展示路径与原始 bytes 分开，不把不可解码名字替换后当 identity。
3. `Engine::copy_entry(artifact, entry_id, writer, control)` 为建议形状；实现前对现有 `zip::read_entry` 选择分块 sink 重构，使读取前检查实际 decoded 额度，不先分配整条目再写。writer 错误是明确失败；调用方必须丢弃未提交临时文件，只有 copy 完成且 CRC 验证通过才可发布。
4. EntryId 必须属于该 Artifact，并校验 LFH/CD 一致性、重叠/范围、CRC、压缩方法、尺寸与控制信号。重复名称全部可寻址；自动 root DEX/Manifest 的默认选择继续由现有策略决定。
5. 增量输出不降低完整性门槛。提供调用批次共享 decoded quota 的受控读取会话，优先复用已有 operation guard/账户；若不需要同时提取，不新增持久 session。批量入口需明确总预算，不能逐 entry 重置。
6. host 将 entry facts 绑定父 APK MD5、ASC ArtifactId 与 entry ordinal 后写临时文件并原子发布；路径穿越防御采用宿主生成文件名，不能把 ZIP raw name 当输出路径。

## Risks / Trade-offs
流式 CRC 在末尾才能确认，writer 的已写字节不可撤回。因此“成功返回才发布”必须成为消费者验收项。现有 input snapshot 保持不变；输出 sink 不能反向阻塞 host async executor，仍在 worker 内执行。

## Migration Plan
先实现并验收 core provider，再固定新的 submodule gitlink，再实现宿主 artifact 发布。不得通过复制 zip.rs 暂时绕过依赖。

## Open Questions
不支持的压缩/ZIP64/加密保持明确 UnsupportedFormat；只有独立 change 提供完整格式支持后才能扩展矩阵。
