## Context

main 的规格是行为参照，不是正确性 oracle。Rust 的常规引用搜索已在 supplied DEX 的多个非空查询上得到相同结果；确定的差异集中在 pattern、静态 metadata、接受范围、身份与输出。Python 的字节正则可能跨字符串/NUL/ULEB 前缀，精确类路径又会切成 literal，不能直接平移。

## Goals / Non-Goals

**Goals:** 补齐 CLI 分析能力；把匹配、身份、错误、完整性和确定性变成可测试契约；保留现有 Rust 扩展。

**Non-Goals:** 原命令字节兼容；把所有反编译文本逐字对齐；重建通用 DEX writer；新指令查询种类、资源编辑或任意代码运行。

## Decisions

### 1. 查询显式建模

`Pattern` 只含 `Literal` / `Regex`。默认 literal 是大小写敏感的子串；CLI 通过 `--regex` 指定正则。库在构造时编译模式并验证长度；Regex 逐条已解码的 DEX string / descriptor / member name 匹配，绝不扫字符串池的拼接字节。

成员名模式与声明类约束独立。`--class` 默认精确描述符，只有 `--fuzzy-class` 才对子串/正则匹配。`--regex` 影响名称和模糊类，不改变精确类。精确类和 getclass 支持 Java 点名；literal type/模糊类支持将 Java package 点名转换为 slash 形式，必须在 CLI 标注这条规则；regex 原样作用于 descriptor，不能替换其中的点。库直接接收明确类型，不猜字符串意图。

拒绝空/全空白的查询模式；不偷偷 trim 非空 string 模式，因为空格可能属于要搜的字符串。仅用于检查空模式时判断 whitespace，存储原值。精确类名按 descriptor 语法验证，而不是机械补前后缀接受数组/primitive 的畸形拼接。

Python 支持 regex 功能，因此选型验证覆盖分组、alternation、锚点、字符类、量词、转义、lookaround、backreference；可优先验证纯 Rust `fancy-regex`，给出 backtrack/编译大小预算。它公开支持 lookaround/backreference，但不能由此宣称 Python `re` 的所有语法兼容；不支持的语法必须报 `InvalidQuery` 并说明，禁止静默当 literal。[候选官方说明](https://github.com/fancy-regex/fancy-regex)

Unicode 的正确性以 DEX 的 UTF-16/MUTF-8 内容为准。所有目标路径用同一解码与比较规则；未配对 surrogate 保留原始单元供诊断，展示转义，不能把不同原值经 U+FFFD replacement 合并。regex 仅对可表示的 Unicode 文本工作；存在无法完成判定的候选时返回 UnsupportedEncoding 和原始单元诊断，不能跳过候选后返回空成功。可返回的原始字符串值保留在结果模型中。

### 2. 引用身份独立于显示文本

内部保留 `(DexId, method_idx, target_kind, target_idx, code_unit_offset)`。共享 code_item 的每个方法都返回自己的身份；聚合只是这些事实的投影。`MethodId` 展示时包含 owner、name、完整 prototype；字段包含 owner、name、type。一个 target id 的多次引用聚合到一个目标，必要时保留位置集合，不用行字符串或 class->name 做键。

CLI 默认显示逐方法聚合行，排序键为 `(entry_ordinal, logical_member_ordinal, method_idx)`，目标按 kind/index 排序；所有字段需转义控制字符和分隔符。增加 `--format json`（完整对象，不靠解析 text），使下游能验证重载、Unicode 和诊断。text/JSON 同时写文件和 stdout 时使用同一次序列化产物。

### 3. 输入验证与分析完整性分开

只读分析对 checksum/signature 不一致产生 warning，不放弃结构安全的 DEX。结构、偏移、长度、索引、指令宽度依然严格校验。向强制校验的后端传参时，可以在私有 scratch 副本中重新计算校验字段；保存原始校验事实，不修改用户文件，不借此掩盖结构错误。

ZIP 只承诺单卷、非加密 Stored/Deflate。明确拒绝 ZIP64 及不支持的方法，不依赖偶然越界报错。中央目录/本地头范围、entry 数、输出大小和 CRC 要有明确定义：使用中央目录大小，data-descriptor flag 可以接受；完整解压后核对 CRC，不将失败伪装成无命中。prefix 只证明所需索引可读，不能冒充整个 entry 已验证；完成结果要求整项校验，性能优化不得偷偷削弱这个定义。

同名 root DEX 统一取第一中央目录 entry，记录重名诊断。不同 DEX 中同名类保留所有定义；getclass 默认按 `(entry_ordinal, logical_ordinal, class_def_idx)` 取第一份，输出身份及重复诊断，也允许用 `--dex` 显式选逻辑成员。`--dex` 在重名 ZIP 场景需使用稳定 ordinal 身份，不能只靠文件名。

041 成员通过整个物理缓冲区和逻辑 header offset 表达，先验证 member 链、header_offset、container_size、file_size。普通版本在目标支持矩阵中逐个列出 035/037/038/039/040/041；036、未知、CompactDex/ODEX 明确 Unsupported，不将只检查 `dex\n` 当版本支持。每个声明支持的版本须先有 fixture，未验收不能发布支持声明。

### 4. 反编译质量按数据验收

G02 必须保留静态非 final 初值及初始执行顺序；不能用“输出可阅读”放行。建立纯 fixture 的预期事实：字段值/类型、方法完整原型、构造器链、异常范围和处理器、注解目标和值、debug locals/行号、宽寄存器、switch/array payload、invoke 与返回值等。

接口输出包含完整性状态与诊断。未知指令、后端失真/失败、只得到部分方法时不能返回看似完整的成功源码。已知可重编译的 fixture 用 javac/D8 和行为断言辅助验证；Android 复杂类仅用结构/指令事实与人工定点复核，不能泛称所有反编译源可编译。

不恢复 Python 的单类 DEX writer。对现有 CLI 来说，它是实现手段；公开接口应是 decompile 结果，不暴露一个没有用户要求的重建产品面。

### 5. 输出与错误

保留 Rust stdout 只承载 payload、stderr 承载诊断。语法/查询错误退出 2；输入/分析/写出错误 1；完整结果（含空引用集）0；取消 130；检测到反编译不完整则失败 1。库本身不定义退出码。

第一版采用 complete-or-error 的结果交付：先完成计算与验证再写 payload，不在默认模式边扫描边输出可能半成品的结果。资源不足时返回 `ResourceLimit`，而不是无上限累计。输出文件用同目录临时文件、flush 后原子替换；文件与 stdout 跨介质无法整体原子提交，先完成文件再 stdout，stdout BrokenPipe 不回滚已保存文件。Unix SIGPIPE 行为留在 CLI。

## Risks / Trade-offs

- G02 来自后端；公开完整 parse 只能去性能 patch，不能修字段 renderer。受控 vendor 修复与后续候选替换必须过同一测试，详见 [依赖决策](../extract-publishable-core/dependencies.md)。不加 source-string 正则补丁。
- regex 开销、全量 CRC 与更严格的完整性定义可能降低现有吞吐。用同一输入/输出语义比较再定预算，不能拿省略工作当加速。
- 多 DEX 早停只允许跳过已确认优先级更低的任务，不能把首个完成者作为结果。并发排序也约束错误的选择顺序。
- 部分 metadata 和 Unicode 仍未验证，tasks 是阻断条件；当前不存在“除格式外全相同”的证据。

## Delivery order

查询与身份 → 输入/确定性 → 反编译质量 → 扩展契约 → 完整回归。每一步单独有 fixture、实现、验收记录；性能及打包重组不混入功能修复。

实施接口和 CLI 字节协议见 [interfaces.md](../../implementation/interfaces.md)，必过证据见 [acceptance.md](../../implementation/acceptance.md)，任务分派见 [execution-plan.md](../../execution-plan.md)。
