# reference-search

## Purpose

记录 Python main 四种引用查询的目标选择、指令定位、聚合和边界，特别是文档里的 fuzzy 与源码里的字节正则之间的差别。引用是 code_item 内的指令引用，不是字符串在任意二进制位置出现。

## Requirements

### Requirement: Target selection
查询器 SHALL 支持 string、type、method、field 四类目标。string 使用 `re.compile(pattern.encode('utf-8'))` 在字符串数据区搜索；type 将匹配的 string id 映射为 type id。method/field 将匹配名称映射为对应成员 id，并可增加精确或模糊声明类约束。

#### Scenario: Pattern wildcard
- **WHEN** 字符串 `token` 被代码引用，查询 `tok.n` 或 `tok(en|x)`
- **THEN** Python 正则可选中 `token`；这不是字面子串语义。

#### Scenario: Exact and fuzzy class paths differ
- **WHEN** 对成员名 `SECOND` 查询 `SEC.ND`
- **THEN** 无类约束及模糊类约束路径用正则；精确类约束路径使用 `.name.find(pattern)`，把点当字面字符。

#### Scenario: Invalid and empty patterns
- **WHEN** string 模式为 `[` 或空字符串
- **THEN** 前者因正则语法错误失败；后者可能因字符串偏移映射失败而报错，审计 fixture 中为 `Error: 0`。type 空字符串直接无目标。不得把这些偶然差异视为合理的统一查询 API。

### Requirement: Reference instruction families
扫描器 SHALL 将 const-string / jumbo 识别为 string 引用，将 `1c,1f,20,22–25` 识别为 type 引用、`52–6d` 为 field 引用、`6e–72,74–78,fa,fb` 的第一索引为 method 引用。

#### Scenario: Shared code and method zero
- **WHEN** method id 0 与另一方法共享 code_item
- **THEN** 两个方法都可返回，不因 0 的假值语义丢失结果。

#### Scenario: Extended DEX references
- **WHEN** 遇到 invoke-custom、const-method-handle、const-method-type 或 polymorphic 的第二 proto 索引
- **THEN** 当前四种查询没有独立 call-site / handle / proto 模式；不得将这些索引误当成普通 method id。

### Requirement: Instruction boundary verification
扫描器 SHALL 在字节候选匹配后由 `InsnLocator.INSN_VERIFY.fullmatch` 校验从方法起点到候选偏移的指令序列；通过 class data / class definitions 构建方法位置映射，并支持 map 缺失时的回退。

#### Scenario: Opcode bytes inside an operand
- **WHEN** `const` 的立即数内含 `const-string` 的 opcode 和目标索引字节
- **THEN** 不应返回该伪引用；本次合成样本中 Python 和 Rust 都正确返回零行。

#### Scenario: Missing map entry
- **WHEN** class_data map entry 缺失或 map 为空
- **THEN** 从 class definitions 回退建立定位，仍能找到共享 code_item 的两个方法。

### Requirement: Reference aggregation
CLI 路径 SHALL 按调用方 method id 聚合，matched target id 去重并按索引排序，生成 `DEX | CLASS->METHOD | matched=(TARGET; TARGET)`。调用方按 method id 排序；跨 DEX 批次按进程完成顺序交付。

#### Scenario: Multiple matching instructions
- **WHEN** 同一方法多次引用同一匹配目标
- **THEN** 聚合行只显示该目标一次；同一方法匹配多个目标时用 `; ` 连接。

#### Scenario: Overloads and special characters
- **WHEN** 同一类有同名重载，或字符串中包含换行/` | `/`; `
- **THEN** 历史文本没有完整方法原型，字符串也不转义；不能将显示行作为无歧义的引用标识。

## Evidence

固定 main：[`findrefs_manager.py`](https://github.com/MG1937/ASC/blob/ccc6bae7704f5c5ef1a7271e27314837079621fb/src/asc_core/findrefs/findrefs_manager.py)、相邻 `locator/{string,type,method,field,insn}_locator.py`、`scan/code_item_scan.py`、[`asc_handler.py`](https://github.com/MG1937/ASC/blob/ccc6bae7704f5c5ef1a7271e27314837079621fb/src/asc_client/asc_handler.py) 的 `findrefs`。Python 直接 core 调用可关闭聚合，但 CLI 没有此开关，不增加对应命令行需求。
