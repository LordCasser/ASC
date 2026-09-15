## ADDED Requirements

### Requirement: Archive 条目具有无损身份
Engine SHALL 按 ArtifactId 与中央目录 ordinal 标识所有 ZIP 条目；名称作为原始 bytes 和可选展示文本返回，不作为唯一键。目录结果 SHALL 遵循操作级 items/bytes 上限。

#### Scenario: 重复或非 UTF-8 名称
- **WHEN** 两条记录同名或名称含不可解码字节
- **THEN** 两者仍具有不同稳定身份，原始 bytes 完整，消费者可明确选择任一条目

### Requirement: 指定条目读取受控且完整校验
Engine SHALL 对指定 entry 复用 catalog、局部头、范围、压缩、大小和 CRC 校验，按实际分块输出累计预算并响应取消。失败 MUST 不报告已完成的成功输出。

#### Scenario: CRC 失败发生在写入末尾
- **WHEN** writer 已接收部分或全部字节但最终 CRC 不符
- **THEN** 返回明确 malformed 错误，调用方不得发布临时输出

#### Scenario: 多条目累计限额
- **WHEN** 每个条目各自未超限但同一提取操作累计 decoded 超限
- **THEN** 在越界字节交给 writer 前失败，不因切换条目重置预算

#### Scenario: 外来身份或取消
- **WHEN** EntryId 指向其他 artifact，或输入/写出过程中取消
- **THEN** 分别返回 InvalidQuery 或保留取消原因的 Cancelled，失败不泄漏后续操作所需额度
