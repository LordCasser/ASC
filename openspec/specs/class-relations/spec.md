# class-relations Specification

## Purpose
定义默认 feature 下基于 DEX class_def 的直接继承与接口声明反查，保留完整身份、显式范围、资源预算和薄 CLI 输出合同。

## Requirements

### Requirement: Direct declaration relationships
asc-core SHALL 在默认 feature 下按 class_def 的 superclass_idx 或 interfaces type_list 返回直接关系，目标可以只有 type_id 而没有本地定义；MUST NOT 推断传递关系或继承得到的接口。

#### Scenario: Direct and external targets
- **WHEN** A extends B、B extends C，A 声明接口 I，而 I 没有 class_def
- **THEN** 查询 B 仅返回 A，查询 C 仅返回 B，查询 I 的接口关系仅返回 A，不返回从 A 派生的类；接口自身声明的上级接口同样可查。

#### Scenario: No declared relation
- **WHEN** superclass 为 NO_INDEX 或 interfaces_off 为零
- **THEN** 对应关系没有结果，不解引用哨兵或零偏移。

### Requirement: Exact target matching
关系查询 SHALL 仅按完整 descriptor 精确匹配，CLI 接受 Java 点名并使用既有规范化与输入长度限制；不提供关系子串或 regex 入口。

#### Scenario: Exact descriptor and Java name
- **WHEN** 两个接口描述符含相同短名，分别使用完整 descriptor 和等价 Java 点名查询其中一个
- **THEN** 两种输入只返回指定类型的直接边，保留真实目标 type_id；短名不会作为子串匹配。

#### Scenario: Unicode and invalid query
- **WHEN** 目标含非 BMP 字符，或输入为空、全空白、非法 descriptor 或超出 pattern-bytes
- **THEN** 合法 UTF-16 精确命中，非法输入在打开文件前返回 InvalidQuery，长度超限返回 ResourceLimit。

### Requirement: Stable source and target identity
结果 SHALL 保留源 ClassId、完整 DexId、目标 Type TargetId 和 DexText，按源 identity 后目标 index 排序；相同描述符的不同定义不得合并。

#### Scenario: Duplicate definitions across entries and logical members
- **WHEN** 多个 DEX entry、041 logical member 或同 DEX 内有同名 class_def
- **THEN** 每个匹配定义独立返回，线程数和完成顺序不改变事实或排序；同一 class_def 重复声明同一接口不重复一条边。

### Requirement: Controlled complete results
关系查询 SHALL 使用 Engine 账户、准入、取消、范围、总结果预算与共享内存账本；成功为完整结果，失败不返回部分成功 Report。

#### Scenario: Malformed declarations despite empty matches
- **WHEN** 目标不存在但某已读取 superclass/type_list 索引、数量、对齐或范围损坏
- **THEN** 返回明确错误，不能把坏输入当作空结果。

#### Scenario: Cancel or budget failure then reuse
- **WHEN** 操作取消、结果上限或 engine-owned-memory 上限失败，随后对同 Engine 做小查询
- **THEN** 后续查询成功，返回 Report 及 clone 存活期间仍占用新增结果额度，释放后归还。

#### Scenario: Explicit scope and ownership
- **WHEN** 使用显式 DEX 范围或其他 Engine 的 Artifact
- **THEN** 仅分析选定有效范围并保持原 identity；范围外损坏不污染范围内结果，外部账户被拒绝。

### Requirement: Thin CLI projection
rasc SHALL 提供 extends 与 impl/implements 查询，仅调用公共 core API，并用独立 class_relations envelope 输出真实类关系，不构造方法 caller 或位置。

#### Scenario: Text JSON and empty result
- **WHEN** 同一查询输出 text、JSON、-o，或没有命中
- **THEN** text 与 JSON 保留相同关系身份，文件与 stdout 字节相同；空 text 为空 bytes，空 JSON 为 data=[]，完整成功 exit 0。
