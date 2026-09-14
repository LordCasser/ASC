# apk-input

## Purpose

记录 Python CLI 从 APK 中选择 DEX、解压、遍历 DEX 041 逻辑成员和定位目标类的行为。规格覆盖本项目实际读取路径，不把完整 ZIP/Android 格式支持误写为已实现能力。

## Requirements

### Requirement: Root DEX discovery
读取器 SHALL 优先选择根目录中以 `classes` 开头、以 `.dex` 结尾的条目；只有不存在这类条目时才回退到任意根 `.dex`。嵌套目录内的 DEX 不参与 CLI 分析。

#### Scenario: Named entries suppress fallback
- **WHEN** APK 同时含 `classes.dex`、`other.dex` 与 `assets/classes.dex`
- **THEN** 仅选择 `classes.dex`。

#### Scenario: Duplicate entry names
- **WHEN** 根 `classes*.dex` 出现同名重复条目
- **THEN** Python 保留中央目录中的第一项；回退路径的任意根 `.dex` 不去重，所以同名 `a.dex` 可重复扫描。

### Requirement: Archive entry decoding
读取器 SHALL 使用中央目录中的大小、压缩方式及本地头偏移读取条目，支持 Stored(0) 与 Deflate(8)，拒绝其他压缩方法；声明的非零解压大小应与实际大小一致。

#### Scenario: Stored and deflated multidex
- **WHEN** 相同 DEX 分别装入 Stored 与 Deflate 的多 DEX APK
- **THEN** 两种压缩均可执行 getclass/findrefs，引用结果保留 DEX 名称。

#### Scenario: Invalid container metadata
- **WHEN** 找不到 EOCD、本地头签名错误或非零声明大小不匹配
- **THEN** 读取失败；当前实现没有完整 ZIP64、加密、多卷、CRC 验证契约。

### Requirement: Logical DEX containers
读取器 SHALL 对 `dex\n041\0` 依次按逻辑头的 `file_size` 寻找成员；保留物理容器的完整地址空间，将后续成员的头覆盖到副本起点，供后续按绝对偏移解析。

#### Scenario: Multiple logical members
- **WHEN** 一项 `classes.dex` 中找到多个逻辑 DEX
- **THEN** 按 `classes.dex!classes1.dex`、`classes.dex!classes2.dex` 命名，并依次分析成员。

#### Scenario: Plain or single member
- **WHEN** 普通 DEX 或只有一个逻辑成员
- **THEN** 保留原 ZIP entry 名。历史探测对畸形尾部采取停止/回退策略，不能据此认定已验证整个 DEX 041 容器。

### Requirement: Defined class lookup
getclass SHALL 在选中的 DEX 中验证目标类型确实出现在 `class_defs`；只出现在 `type_ids` 中的外部类型不算命中。entries 先按压缩大小排序，多个工作线程并发查找，命中后停止派发并尝试取消其余任务。

#### Scenario: Referenced external class
- **WHEN** 目标描述符在类型表中但没有 class definition
- **THEN** 继续查找其他 DEX，最终仍未定义则返回未找到。

#### Scenario: Repeated class definition across entries
- **WHEN** 多个 DEX 都定义目标类
- **THEN** Python 返回并发命中路径选中的一份；该结果受完成顺序影响，不能作为稳定的重复类优先级契约。

## Evidence

固定 main：[`apk_handler.py`](https://github.com/MG1937/ASC/blob/ccc6bae7704f5c5ef1a7271e27314837079621fb/src/asc_client/apk_handler.py) 的 `_parse_cd_dex_entries`、`_inflate_dex`、`_dex_defines_class`、`get_class_dex`；[`dex_container.py`](https://github.com/MG1937/ASC/blob/ccc6bae7704f5c5ef1a7271e27314837079621fb/src/asc_client/dex_container.py) 的 `iter_logical_dex_buffers`。
