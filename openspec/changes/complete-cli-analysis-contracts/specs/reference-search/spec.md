## MODIFIED Requirements

### Requirement: Target selection
查询器 SHALL 支持 Literal/Regex 两种显式模式，并独立组合目标名称与声明类约束；按逐条解码字符串匹配，精确、无类、模糊类路径语义一致。禁止跨字符串数据、ULEB 前缀或 NUL 边界匹配。模式构造和执行受资源限制。

#### Scenario: Pattern wildcard
- **WHEN** token 被引用，模式 tok.n 分别构造成 Regex 和 Literal
- **THEN** 前者命中、后者不命中；非法/空模式返回 InvalidQuery。

#### Scenario: Unicode member
- **WHEN** string、type、field 或 method 名含相同非 BMP 字符
- **THEN** 所有路径使用相同 MUTF-8/UTF-16 规则，不因某条路径把 UTF-8 字节直接对比 MUTF-8 而漏报；不能完成 regex 判定的 surrogate 保留原单元并返回 UnsupportedEncoding，不能跳过后当完整成功。

#### Scenario: Exact and fuzzy class paths differ
- **WHEN** 成员名模式 SEC.ND 为显式 Regex，分别使用精确类、模糊类或无类约束
- **THEN** 消除历史路径差异，名称始终按同一种 Regex 语义匹配；类约束按自身模式执行。

#### Scenario: Invalid and empty patterns
- **WHEN** 模式非法、为空或只有空白
- **THEN** 返回 InvalidQuery；非空模式中的有效空格不得被删去。

### Requirement: Reference instruction families
扫描器 SHALL 支持 string、type、field、method 的原有 opcode 家族和 jumbo/polymorphic 第一引用索引；invoke-custom/handle/proto 不误归类。未知/损坏指令返回明确错误。

#### Scenario: Polymorphic operands
- **WHEN** fa/fb 指令带 method 与 proto 两个索引
- **THEN** method 查询只使用 method 索引；扫描步长包含整个指令。

#### Scenario: Shared code and method zero
- **WHEN** method id 0 与其他方法共享 code_item
- **THEN** 各方法的身份与引用均保留。

#### Scenario: Extended DEX references
- **WHEN** 遇到 call-site、handle、proto operand
- **THEN** 不当作 method id 返回；仍正确跳过指令宽度，不增加未声明查询种类。

### Requirement: Instruction boundary verification
扫描器 SHALL 基于 class data、code_item 范围与完整指令宽度验证引用位置；共享代码与 method 0 不丢失。字节预筛只减少工作，不能改变完整扫描结果。

#### Scenario: Opcode bytes inside an operand
- **WHEN** 普通立即数或 switch/array payload 内出现类似引用的字节
- **THEN** 不返回伪引用；开启/关闭预筛得到同一结构化结果。

#### Scenario: Missing map entry
- **WHEN** class_data map 项缺失但 class_defs/class_data 结构可读
- **THEN** 引用扫描仍从已验证的 class_defs/class_data 路径得到同一事实，不依赖 map 的偶然布局。

### Requirement: Reference aggregation
结果 SHALL 使用 DexId、调用方完整 method identity、目标 kind/index 和指令位置建模。聚合按调用方身份去重 target id，按确定的 ordinal/index 排序；显示文本仅为投影。

#### Scenario: Overloads and special characters
- **WHEN** 同类两个同名但不同 prototype 的方法都引用目标
- **THEN** 两条方法身份都保留，text 和 JSON 可区分，不能用 class->name 覆盖。

#### Scenario: Delimiters in targets
- **WHEN** 目标字符串含换行、分隔符或 NUL
- **THEN** JSON 无损表达原值/原始单元，text 明确转义；往返后身份和匹配集合不变。

#### Scenario: Multiple matching instructions
- **WHEN** 同一方法多次引用一个 target 并引用多个不同 target
- **THEN** 聚合按 target id 去重，保留位置事实，稳定排序，不合并重载。
