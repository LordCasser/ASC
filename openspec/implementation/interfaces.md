# 实施接口契约

本文件补充三个 change 的 design/spec，解决分工时必须一致的类型、字节协议和运行规则。以下接口是目标，不是现有 Rust 已实现的 API。公开符号由 A01 固定领域部分、A10 固定 Engine 部分；后续调整先更新本文件和消费方测试，再由唯一所有者修改代码。非行为性的私有文件拆分由 owner 决定。

## 1. 公共模型

| 类型 | 首版合同 |
|---|---|
| ArtifactId | 输入完整 bytes 的 SHA-256，32 bytes；展示小写 64 hex；相同 bytes 同 ID |
| DexId | ArtifactId + u32 entry_ordinal + u32 logical_ordinal；ordinal 从 0 开始，entry 来自未排序中央目录，raw DEX 的 entry 为 0 |
| DexEntry | id: DexId、raw_entry_name: Vec<u8>、display_name/logical_name、version、header_offset；raw DEX 名为 <memory.dex> |
| Class | id: ClassId、dex: DexEntry、descriptor、java_name、package、simple_name；可读值使用 DexText，不丢原始单元 |
| MethodIdentity | id: MethodId、dex: DexEntry、owner、name、完整 prototype；原型的参数/返回 descriptor 无损保留 |
| ClassId | DexId + u32 class_def_idx；不以 descriptor 唯一化 |
| MethodId | DexId + u32 method_idx；完整 owner/name/prototype 随方法结果返回 |
| TargetId | DexId + kind(string/type/field/method) + u32 table_index；ordinal/index 不能从展示文本反解 |
| DexText | 保留 UTF-16 units；as_str 只在合法 Unicode 时给文本；未配对 surrogate 不经 replacement 合并 |
| ClassDescriptor | 私有构造，core 接收标准 Lpkg/Name;，拒绝 primitive/array；CLI 负责 Java 点名输入转换 |
| Pattern | 私有编译状态；literal/regex 构造接收原字符串和 PatternLimits，拒绝空/全空白，保留有效空格 |
| MemberQuery | name: Option<Pattern>，declaring_class: Option<ExactDescriptor/FuzzyPattern>，至少一项；只约束目标成员 |
| ReferenceQuery | String(Pattern)、Type(Pattern)、Field(MemberQuery)、Method(MemberQuery) |
| ClassFilter | 可选 Java 名大小写不敏感子串；空 filter 表示不过滤，规则不复用 Pattern 的空查询拒绝；有效 Unicode scalar 做非 locale lowercase，非配对 UTF-16 单元原样保留 |
| ClassSelector | Descriptor(ClassDescriptor, Option<DexId>) 或 Id(ClassId)；后者不再次按 descriptor 搜索 |
| Reference | caller: MethodIdentity，targets: Vec<TargetMatch>；TargetMatch 含 ID、完整名称/类型信息、升序去重 code_unit_offsets |
| Report<T> | value: T、diagnostics: Vec<Diagnostic>、stats: OperationStats；stats 不参与事实等价/默认 payload |
| Source | class: Class、UTF-8 Java 风格 text、SourceMetadata；完整成功才能存在于 Ok Report |
| SourceMetadata | 原 class/field/method flags、super/interfaces、prototype、annotations（目标/visibility/值）、generic signatures、throws、inner/enclosing、参数/debug locals/lines；缺失可选数据用 None |
| Manifest | 自有有序文档模型、原始 typed data 与 styles 元数据，显式 to_xml(&XmlRenderOptions, &OperationControl) -> Result<String>；不暴露 vendor Rc/DTO |
| Diagnostic | 稳定 code、severity、stage、可选 DexId/class/method/offset、message；message 非机器身份 |
| Error | kind、context、diagnostics；IncompleteDecompilation 另可携带 boxed partial Source；其余错误无伪成功 payload |

身份字段私有、提供读取方法；ClassId/DexId 只由有效 catalog/结果取得。CLI `--dex` 解析 ordinal 后从 Engine::dexes 返回的 catalog 精确取对应 ID，不直接构造任意 ID；不存在交 InvalidQuery，选择顺序仍由 core 决定。相同 bytes 重新打开可用原 ID，不同内容或不存在的索引返回 InvalidQuery。非 canonical 但可读的重名字段/方法不以 sanitize 后名称合并。

Literal 对 UTF-16 units 子串比较；Regex 对可表示为 Unicode 的逐条候选值执行。无配对 surrogate 的候选只有在已经能用其他独立约束排除时可跳过；仍需参与 regex 判定时返回 UnsupportedEncoding。ASCII/Unicode 的预筛只是加速，开启关闭必须等价。

所有引用事实保留 code unit 偏移；输出按 entry/logical/method_idx，再按 kind 顺序 string/type/field/method 与 target index 排序。相同方法共享 code_item 仍是不同 MethodId。类按 entry/logical/class_def_idx 排序。诊断按 stage 的固定顺序 input、dex、query、decompile、manifest，然后相同身份/offset/code 排序；不按完成时间排序。

Manifest 文档有序保留 Element/Text/CData/Comment/ProcessingInstruction，声明及合法 prolog/epilog 的位置；attribute 保留 URI/prefix/local name 和 raw value。AXML 注释/行号/style spans 留 metadata，不假设所有信息都能投影为 XML 文本。缺失 android namespace 声明但可由 resource ID 确认的场景可补显式绑定并 warning；无法确定 URI 的 prefix 不猜测，返回结构错误。

XmlRenderOptions 包含有限 max_output_bytes/max_depth（默认取下表 result-bytes/depth），域内序列化独立于 Engine，使用有界 writer 并检查 control。非法 XML 字符/名称不能悄悄 replacement，to_xml 返回 UnsupportedEncoding 或 MalformedInput；合法原始文档可在 library 的 Manifest 模型中保留。XML 文本解析仅支持 UTF-8/XML 1.0 与内建/数字字符引用，其他声明编码/版本明确 Unsupported；DTD/自定义实体拒绝。支持边界与正常 fixture 分开验收。

## 2. Engine / Artifact 接口

```rust
// 目标签名；Result 使用 asc_core 自有 Error。
Engine::new(options: EngineOptions) -> Result<Engine>;
Engine::open_path(&self, path: impl AsRef<Path>, kind: InputKind,
                  control: &OperationControl) -> Result<Artifact>;
Engine::open_bytes(&self, bytes: Arc<[u8]>, kind: InputKind,
                   control: &OperationControl) -> Result<Artifact>;
Engine::classes(&self, artifact: &Artifact, filter: &ClassFilter,
                 control: &OperationControl) -> Result<Report<Vec<Class>>>;
Engine::references(&self, artifact: &Artifact, query: &ReferenceQuery,
                    control: &OperationControl) -> Result<Report<Vec<Reference>>>;
Engine::decompile(&self, artifact: &Artifact, selector: &ClassSelector,
                   control: &OperationControl) -> Result<Report<Source>>;
Engine::manifest(&self, artifact: &Artifact,
                  control: &OperationControl) -> Result<Report<Manifest>>;
Engine::dexes(&self, artifact: &Artifact,
              control: &OperationControl) -> Result<Report<Vec<DexEntry>>>;
```

InputKind 为 Apk/Dex，不按文件扩展名猜；CLI 首版入口仍是 APK。Engine::dexes 返回 selected entry 的名字、ordinal、版本和 header offset；也是 getclass --dex 的定位入口。open APK 仅验证输入与中央目录 catalog，不为 manifest 预解析无关 DEX；逻辑成员在 dexes/classes/references/getclass 操作中有界构建。dexes 对无 DEX 返回空 catalog；查询/classes/getclass 在无 DEX 时返回 NotFound，manifest 不要求存在或有效的 DEX；raw DEX 调用 manifest 返回 UnsupportedFormat。之后操作的验证范围见下一节。

Engine 是可 Clone 的 Arc 句柄，Clone 共享一个私有 pool 和资源账户；Engine/Artifact 为 Send + Sync，结果拥有数据。Artifact 记录所属 Engine 账户，操作只接受同一账户创建的 Artifact；其他 Engine 拒绝 InvalidQuery，调用者可用同一 bytes 重新 open。Artifact 持有输入 permits 到 drop，因此 Engine 句柄先 drop 仍不会让输入预算失去归属。所有操作同步返回，调用期间克隆内部句柄；最后一个账户句柄和活动调用释放后销毁 pool。返回的 owned 结果不再占 Engine permits，受 per-operation result 上限约束；宿主持有的历史结果总量不属于 Engine 的硬上限。

open_path 读取有界 owned bytes；metadata 只预检，实际读超过上限必须中断，hash 和解析检查 control。快照保证读取完成后内容不变，不声称在另一个进程写文件时具有文件系统事务快照。open_bytes 不复制 Arc 数据，但每次 open 保守申请其完整长度额度；只保证一次 Artifact 内的 041 views 共享 bytes，不试图用全局指针表跨 Artifact 精确核算共享内存。

不提供长期结果/源码缓存，不提供流式 partial 回调。Artifact 仅持有输入、中央目录 catalog 和必要诊断；派生解压/索引在单次操作中复用，完成释放。041 中完整物理 bytes 只有一份，logical view = Arc + header_offset；后端 scratch 按当前操作计量，不常驻一份每成员副本。

## 3. 内部模块交接

这些是 crate-private 合同，可合并小模块；后端不依赖 asc-core。

| 提供者 → 消费者 | 交接内容 |
|---|---|
| input → dex/decompile | ValidatedDexView { immutable physical bytes, header_offset, DexId, version }；已验证的 ranges，不可重新猜 ordinal |
| dex → engine | Result<Vec<Reference>> / class definitions；无字符串行、排序由同一身份规则定义 |
| engine → modules | OperationContext，引用 Limits、Control、allocator permits 和诊断收集；模块不创建 pool，不写 env/stdio |
| decompile → vendor | checked parse/decompile、真实 class_def_idx、显式 options、budget/control；映射结果 metadata/errors |
| manifest → vendor/XML reader | 受限 bytes/深度/数量；有序 namespace/raw typed data；转换后不保留非 Send 的 vendor Rc |
| core → CLI | 完成的 Report；CLI 独立 render，不能重新解释 DEX 指令或做重复定义选择 |

A02 提供 low-level view，A07 集成现有 apk；A10 把形状迁入 core 后固定 OperationContext 的借用和 permits 接口。A11 改 engine/input 资源行为，A12 改 decompile/manifest adapter；二者不得改共享接口文件，如需调整向集成 owner 提交具体 diff。

## 4. 校验范围、完整结果与错误优先级

选中的 root DEX 条目按 Python root 优先规则和去重策略决定。open APK 验证 archive catalog；DEX headers/逻辑身份留给 DEX 操作，manifest entry 的数据解码留给 manifest 操作。不会因为无关图片 CRC 出错而扫描整个 APK，但所有选中的 DEX 必须按以下合同检查，不能对早停路径降低标准。

dexes/references/classes/getclass 在返回完整成功前，完成所有 selected DEX entry 的压缩流、长度和 CRC 校验，检查所读取的 DEX headers/tables/class_data/code_item/指令边界。没有请求的 annotation/debug 等段不宣称全部语义验证；getclass 后端 full parse 会读取的段必须全部按后端 checked 规则验证。`--dex` 只改变类选择，不改变 archive/selected-entry 完整性合同；manifest 操作只要求整个 catalog 结构和选中的最后一个 manifest entry 完整有效。

ZIP 名称选择/去重用原始 bytes；显示优先合法 UTF-8，否则逐字节转义，不用 lossy display 作为键。选中 root 名称规则匹配 ASCII classes*.dex / *.dex 原始 bytes。ZIP 同时验证本地头与中央目录的名字、方法、关键 flags 一致。data descriptor 开启时用中央目录 sizes，接受合法的有/无 descriptor signature 两种形式，核对 descriptor 和实际流；关闭时本地 CRC/sizes 必须一致。解码完整输入且不得接受超出 declared size 的尾流；未知 ZIP64/多卷/加密明确拒绝。无关 entry 无需解压，但中央目录记录/range 必须可读。

错误顺序固定：构造查询/选项 → 输入/catalog → entry ordinal/logical ordinal → 指令/后端定位顺序。并行多错误按最低身份/offset 选择主错误，附已确定诊断；不得用 first-completed 选择。操作观察到显式取消/deadline 后优先返回 Cancelled（cause=User/Deadline），尚未交付的结果作废；不同取消发生时刻不承诺选择同一个解析错误。资源竞争只承诺每个完成结果相同，不承诺并发操作中谁先获得资源额度。

DEX checksum/signature 不匹配为 warning；安全结构无效为 MalformedInput，不能用 scratch 修头掩盖。临时 normalize 只为后端接受输入，保留原 offset 映射/诊断，操作结束释放。

## 5. 资源与取消的初始参数

以下是首版工程默认值，**尚未测量验证**。A11 测边界，A14 用 corpus 校准；每项可调高但必须是有限正数，checked arithmetic。逻辑版本自身更严格的格式上限始终优先。超额返回 ResourceLimit，不能伪装为 NotFound/空集。

| Limits 字段 / CLI key | 初始默认 | 计量 |
|---|---|---|
| max_input_bytes / input-bytes | 512 MiB | 单个 APK/raw DEX，owned snapshot/Arc 保留 |
| max_entry_bytes / entry-bytes | 256 MiB | 单 entry 解压的实际字节，不只信元数据 |
| max_total_decoded_bytes / decoded-bytes | 1 GiB | 每操作累计 entry 解压量，流式校验丢弃的数据也计入 |
| max_engine_owned_bytes / engine-bytes | 2 GiB | 本 Engine 输入、catalog、解压/041 scratch、ASC 自有结构和结果组装的活跃估计；不含不可控第三方与已返回结果 |
| max_archive_entries / entries | 100,000 | 中央目录全部条目 |
| max_logical_dexes / dexes | 4,096 | 一个 Artifact 选中的逻辑 DEX 总数 |
| max_table_items / table-items | 4,000,000 | 每个 DEX table，格式本身的限制更优先 |
| max_string_units / string-units | 1,048,576 | 单个 DEX/AXML 字符串的 UTF-16 units |
| max_nesting_depth / depth | 256 | AXML、encoded value/annotation 等输入控制嵌套 |
| max_xml_nodes / xml-nodes | 1,000,000 | 元素+文本+CDATA 总数 |
| max_xml_attributes / xml-attributes | 1,000,000 | 文档累计，不是每节点 |
| max_method_code_units / code-units | 1,048,576 | 单 code_item |
| max_result_items / result-items | 250,000 | 返回 classes/Reference 的顶层项目数 |
| max_reference_locations / locations | 1,000,000 | 返回目标位置累计数 |
| max_result_bytes / result-bytes | 128 MiB | 单次 owned 结果/metadata 的估计字节；CLI 序列化产物另受同上限 |
| max_pattern_bytes / pattern-bytes | 16 KiB | 每个模式 UTF-8 bytes，构造时检查 |
| regex_compile_bytes / regex-bytes | 8 MiB | 委托 regex 编译/DFA 各自大小上限，不是整个 regex 进程内存硬限制 |
| regex_backtrack_limit / regex-steps | 1,000,000 | 每候选匹配的后端回溯上限；同时受操作 deadline |

regex 使用已验证版本的 builder backtrack_limit、delegate_size_limit、delegate_dfa_size_limit；后端不支持的编译控制不得伪装为有效限制。API 来源：[fancy-regex RegexBuilder](https://docs.rs/fancy-regex/latest/fancy_regex/struct.RegexBuilder.html)。

所有 reserve/grow 在分配前核算；可准确统计的 bytes 用实际值，结构估算明确单位和系数。无法按字节统计的第三方预算映射单列于 A11 报告；不得把上表称作整个进程 RSS 硬限制。后端解析/CFG/SSA 还受上述输入、数量、深度及自有 Budget 约束。

Library workers 默认 1，CLI 默认 8，零拒绝。Engine 建一个私有 pool；嵌套 vendor Rayon 工作在这个 pool 内执行。首版同 Engine **串行准入顶层分析操作**，每个操作内部并行；同时调用按可取消的 admission 等待。这样避免多个操作各持部分 permits 再互等的死锁，不用引入复杂调度器。无需 FIFO 保证；不得在 pool worker 上阻塞等待另一顶层操作。Artifact open 的输入保留额度不等待其他 Artifact drop，若不足立即 ResourceLimit，附当前占用信息。

OperationControl 通过 Clone 的 CancelToken 和可选 std::time::Instant deadline 构造；token 可由外部线程设置。admission 等待以有界 condvar 超时唤醒检查 control；读取/解压每不超过 64 KiB 检查一次，scanner 每方法并在长循环每不超过 4096 code units 检查，后端每阶段/方法检查，提交前必查。A11 验证检查点，记录不能抢占的第三方函数；不承诺硬超时，也不采用返回 Cancelled 后仍在后台运行的超时线程。

## 6. CLI 的确定协议

保留 getclass、findrefs 的四个查询、classes、manifest；不增加 GUI/raw DEX/export/writer 命令。以下共用选项放在命令级，findrefs 在 kind 前后都接受：`--threads/--thread`（8）、`--debug`、`-o/--output`、`--format text|json`（text）、`--timeout-ms N`、可重复 `--limit KEY=VALUE`。大小值只接受十进制正整数 bytes/count，帮助列单位，未知/重复 key 退出 2。manifest 的 workers 接受同配置但不承诺并行加速。

findrefs 的 `--regex` 适用于值/成员名和 fuzzy class，`--class` 精确 descriptor 不受影响。`--fuzzy-class` 无 `--class` 为错误；`--dex` 只属于 getclass，语法 `<entry_ordinal>:<logical_ordinal>`，从 classes/JSON 可获取，非数字/溢出为语法错误，合法格式但不存在为 InvalidQuery。type literal 和 fuzzy literal 的 Java 点名转换由 CLI 完成，string literal 不转换，regex 不转换。

```text
rasc findrefs app.apk string 'tok.n' --regex --format json
rasc findrefs app.apk field 'SEC.ND' --class example.Statics --regex
rasc classes app.apk --format json
rasc getclass app.apk example.Test --dex 0:1 -o Test.java
rasc manifest app.apk --limit entry-bytes=268435456
```

### text

references 每行：`<dex-key> | <dex-name> | <method_idx> | <caller> | <targets-json>`；dex-key 为 `entry:logical`，caller 为 `owner->name(proto)return`，目标数组使用下面 JSON 的 target 对象，含 index 和 code_unit_offsets。classes 每行 `dex-key | dex-name | class_def_idx | descriptor | java-name | package | simple-name`。普通列的反斜杠 U+005C、竖线、LF、CR、tab、NUL 和不可打印/非配对 UTF-16 分别写作 `\\`、`\|`、`\n`、`\r`、`\t`、`\u0000`、`\uXXXX`；先转义原始反斜杠。末列 targets-json 只用 JSON 转义，消费方按前四个未转义分隔符切分后将剩余整段作为 JSON，不再给 JSON 施加 `\|`。排序由 core 事实顺序决定，CLI 不按渲染文本重排。

getclass 的 payload 是 Java 风格源码，UTF-8/LF，恰好一个结尾 LF；SourceMetadata 在 JSON 中保留，text 模式来源/重复类诊断进 stderr。manifest 二进制输入输出 XML 声明、4 空格缩进、LF；混合文本节点不得插入改变文本的缩进。合法 UTF-8 纯 XML 可保留原始字节（此项例外保留原换行/BOM），JSON 同时给领域文档。text references/classes 空集为空 bytes。

### json

所有成功命令输出一个 JSON object、恰好一个结尾 LF；不是 NDJSON。首版 `schema_version=1`，keys 固定序列化顺序、UTF-8 字符输出，禁用浮点 NaN/Infinity JSON number（typed bits 另存）；不把 stats/timings 放入 payload，因此 --debug 不改变 bytes。library 无强制 serde 公共依赖，CLI 的 DTO 从领域模型生成。

CLI text/JSON/XML 序列化都使用按 result-bytes 限额的 writer，在增长前拒绝超限、每不超过 64 KiB 检查 control；不能先无界生成 String 再检查长度。manifest JSON 中的 xml 也必须完整生成，不能以 null 悄悄省略序列化失败；不满足声明的 XML 输出范围时整个命令失败，library 原始文档仍可被显式消费。

```json
{"schema_version":1,"operation":"findrefs","artifact_id":"<64-lowercase-hex>","data":[],"diagnostics":[]}
```

ID 对象保留完整 artifact_id、entry_ordinal、logical_ordinal 以及对应 class_def_idx/method_idx/index。Reference 对象为 `{caller:{id,dex,owner,name,prototype},targets:[{id,kind,value,code_unit_offsets}]}`；member value 含 owner/name/prototype 或 field type，string/type value 用 DexText。DexText 序列化为 `{text:<string-or-null>,utf16:[<u16>...]}`，正常 Unicode 和非配对单元均无损。classes data 是 Class 数组；getclass data 为 `{class,source,metadata}`；manifest data 为 `{xml,document}`，document 含有序 nodes、attributes、namespace scope、typed raw data、string styles。字段命名 snake_case，u32 索引用 JSON number，64 位 typed data 用固定宽 hex string，避免下游 JS 精度丢失。A01 固定这些 DTO golden，不自行增减结构。

无引用/类过滤后无命中：JSON data=[]、exit 0，不能输出空 bytes。成功 warning 同时在 diagnostics 与 stderr 可见，debug stats 只在 stderr；错误不写成功 envelope、不输出半成品，stderr 有稳定 error code 与定位。

### 文件与退出

同一次序列化产物用于 -o/stdout。先算完并校验，再写同目录临时文件、flush/sync、原子替换已有普通文件，然后 stdout；跨介质不能事务提交。输出路径是目录/symlink/当前输入的同一文件（含可识别的 hardlink）时拒绝，避免覆盖输入；普通既存输出默认替换。Unix/Windows 使用经验证的原子替换路径，失败时原文件保留、清理临时文件。取消发生在文件替换前则不提交；替换是输出提交点，之后完成 stdout 或报告写出错误，不以晚到取消假装文件未写。

exit 0 完整成功（含空集）；2 参数/InvalidQuery；1 输入/分析/文件/不完整；130 用户取消或 deadline（stderr 区分原因）。Unix BrokenPipe 可由 SIGPIPE 终止；Windows BrokenPipe 安静返回 0，其他写错 1。无参帮助到 stderr/2，--help/--version 到 stdout/0。不会因 stderr/debug 改变成功 payload，也不让 core 安装信号或退出进程。
