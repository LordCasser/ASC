# apk-input

## Purpose

记录 Python CLI 从 APK 中选择 DEX、解压、遍历 DEX 041 逻辑成员和定位目标类的行为。规格覆盖本项目实际读取路径，不把完整 ZIP/Android 格式支持误写为已实现能力。

## Requirements


### Requirement: Root DEX discovery
读取器 SHALL 优先 root classes*.dex、否则 root *.dex，忽略嵌套 DEX；两条路径均按原中央目录 ordinal 保留第一个同名 entry，并报告重名诊断。

#### Scenario: Duplicate entry names
- **WHEN** 存在两个同名 a.dex 且没有 classes*.dex
- **THEN** 扫描一次并记录重复名，不能产生重复引用行。

#### Scenario: Named entries suppress fallback
- **WHEN** 存在 classes.dex、other.dex 与 assets/classes.dex
- **THEN** 只选择 root classes.dex。

### Requirement: Archive entry decoding
读取器 SHALL 支持单卷、非加密 Stored/Deflate，使用中央目录大小并支持 data descriptor；显式拒绝 ZIP64/多卷/加密/未知压缩，检查范围、实际解压大小、CRC 和资源预算。坏结构返回错误，不返回空结果。

#### Scenario: CRC mismatch
- **WHEN** 完整解压成功但 CRC 不一致
- **THEN** 分析失败并标注 entry，不宣称完整 payload。

#### Scenario: Prefix optimization
- **WHEN** class lookup 用 prefix 判断某 DEX 不命中
- **THEN** 它的结果不得比完整路径减少所承诺的校验；需完成剩余流校验，或明确未完成并不能提交完整成功。

#### Scenario: Stored and deflated multidex
- **WHEN** 相同多 DEX 负载分别为 Stored/Deflate
- **THEN** 两个路径得到同一引用事实和来源身份。

#### Scenario: Invalid container metadata
- **WHEN** EOCD、本地头、range 或 size 无效
- **THEN** 返回带位置/entry 信息的结构错误，不返回空成功。

### Requirement: Logical DEX containers
读取器 SHALL 为 035/037/038/039/040/041 建立经 fixture 验证的支持矩阵；041 校验成员链、大小及 header offset。内部 DexId 包含物理 entry ordinal 和逻辑 member ordinal，读视图保留整个容器地址空间；未知版本和 CompactDex/ODEX 返回 Unsupported。

#### Scenario: Multiple logical members
- **WHEN** 041 包含两个有效成员
- **THEN** 两者都参与查询，具不同稳定 DexId 和人类可读逻辑名称；不能将第二成员偏移误当切片内相对偏移。

#### Scenario: Broken logical header
- **WHEN** 成员大小为零、越界、header_offset 或 container_size 矛盾
- **THEN** 结构验证失败，不静默截取有效前缀。

#### Scenario: Plain or single member
- **WHEN** 普通 DEX 或单成员 041
- **THEN** 保持原 entry 显示名，仍具有稳定逻辑 ordinal；未通过容器校验不可回退为已支持普通 DEX。

### Requirement: Defined class lookup
定位器 SHALL 只命中 class_defs；保留不同 DEX 中所有定义，默认按 entry/member/class_def ordinal 选择，允许精确 DexId 选择。早停不改变优先级和错误顺序。

#### Scenario: Repeated class definition across entries
- **WHEN** 更低优先级 DEX 先完成且定义同名类
- **THEN** 仍等待/检查更高优先级候选，1 与 8 workers 返回相同 ClassId。

#### Scenario: Referenced external class
- **WHEN** 类型表有 descriptor 但 class_defs 无定义
- **THEN** 不判命中，继续查找其他 entry。

### Requirement: Integrity diagnostics
分析器 SHALL 区分 DEX checksum/signature 不一致和结构无效；前者保留 warning 后继续只读分析，后者返回结构错误。后端 scratch 中的校验字段修正不得修改输入或消除原始诊断。

#### Scenario: Zero checksum DEX
- **WHEN** G03 fixture 结构合法但完整性字段为零
- **THEN** 可反编译类并附完整性警告，原字节保持不变。
