# 2026-10-15 上游增量审计

## 结论与边界

本次完整评审 `3279d9dd..b93cbd0` 的 40 个提交，其中 26 个非合并提交、14 个合并提交。**“评审到上游 b93cbd0”不等于“全部上游功能已经吸收”。** 本轮决定吸收的是跨 DEX 的直接继承/接口声明反查；Unicode 与 locator 越界修复已有等价机制，需以当前提交复验结果补强证据。混合查询批处理、源码语义 span 和单 DEX 快速路径分别保留为便利性、能力与性能候选，不混入直接关系查询实现。

固定比较对象：

- Rust 起点：[LordCasser/ASC `d78123f7c4748e1112314562d3397afbe3df8a06`](https://github.com/LordCasser/ASC/commit/d78123f7c4748e1112314562d3397afbe3df8a06)，默认分支 `lordcasser/main`。
- 上次已评审上游：[MG1937/ASC `3279d9dd6ffb9c844f8599bd2bf69a13bb602480`](https://github.com/MG1937/ASC/commit/3279d9dd6ffb9c844f8599bd2bf69a13bb602480)。依据是 [既有审计](../upstream-2026-09-15/report.md) 的“2026-09-17 增量核对”，不是 Rust Git 祖先关系，也不是最近一次审计文件的提交日期。
- 本次上游头：[MG1937/ASC `b93cbd0798131312b6dc083198e6decbca28a12e`](https://github.com/MG1937/ASC/commit/b93cbd0798131312b6dc083198e6decbca28a12e)，`main`，于 2026-10-15 UTC 通过 Git 远端引用和完整对象核实。
- 历史 Python 行为基线仍是 `ccc6bae7704f5c5ef1a7271e27314837079621fb`；本轮没有把历史契约/实验的固定 SHA 全局替换成最新上游。

最新 Rust 提交虽然是 10 月提交，审计内容只核对到上述 3279d9dd；不能据提交时间宣称已吸收随后所有上游变化。此次按父子 diff、最终源码和既有 Rust 合同核对，没有按提交标题推断缺失。

## 26 个非合并提交的完整分类

| 提交 | 处理 | 实际变化与 Rust 判断 |
|---|---|---|
| [4e3da83](https://github.com/MG1937/ASC/commit/4e3da8306b5bf65cec1c3d6f0f68139b1e81a170) | 保留缺口；不纳入本轮 | 新增反编译源码 token 引用和声明元数据，method/field precise-name 路径服务于导航；不是只有 GUI 文件变化。源码语义 span 与独立 exact-name 原语的判断见下文。 |
| [ac5cae1](https://github.com/MG1937/ASC/commit/ac5cae15742fdd0dce4ad3e6b59df58c7ef21628) | 已有等价机制 | 修复 tinydex 把 UTF-16 单元数当 UTF-8 字节数、非 ASCII 解码与 UTF-16 排序查找；Rust 按声明单元数解码，并在 class_def/成员表逐行匹配。 |
| [b58e146](https://github.com/MG1937/ASC/commit/b58e14699b1afca89061278342e448b069fc12dd) | 验证工具；不移植降级比较 | benchmark 的 findrefs 答案只比较 DEX/方法前缀，忽略 matched payload 文本以容纳解码修复；Rust 仍应比较完整结构化事实，不能据此放松 Unicode 正确性门禁。 |
| [85810a9](https://github.com/MG1937/ASC/commit/85810a960f6b218ddb91e75b91e9450f21a74224) | 无产品移植项 | README 赞助信息。 |
| [870f692](https://github.com/MG1937/ASC/commit/870f692c2f0c6894b7f0b8b1b2e9be9c3f93f4b3) | 无产品移植项 | README 赞助信息。 |
| [26c6f8f](https://github.com/MG1937/ASC/commit/26c6f8fc693e854559db4d2d5a5bed66c64f632c) | 无产品移植项 | README 赞助信息。 |
| [efa3457](https://github.com/MG1937/ASC/commit/efa34570262832c01ff35c653b3fe55a670a599d) | 已有等价机制；实现路径不同 | 重建 DEX 的字符串改用 MUTF-8 编码及 UTF-16 单元长度；Rust 原生反编译不经过这段 Python 最小 DEX 重建器，已有原生 MUTF-8/UTF-16 解析与 vendor 编码器。 |
| [4df4923](https://github.com/MG1937/ASC/commit/4df492342580c69c8d32e9b10a63e9cadeecb0a4) | 无产品移植项 | Python 包版本 0.1.1.post3。 |
| [2e4b8a2](https://github.com/MG1937/ASC/commit/2e4b8a2c24266be7ade31fd1aa60b8241e478b24) | 后端独立；不搬运 | 提取 dadguard、调整 AXML 依赖、移除大量导入 stub，并调整 DAD analysis 接入。Rust 使用独立受控 vendor 后端，不能把 Python 分发/依赖迁移当 Rust 缺失算法。 |
| [17f2d2f](https://github.com/MG1937/ASC/commit/17f2d2f9f9d2a7d8cac2bce70eb03ee1dcea22a8) | 上游验证适配 | 测试导入与执行方式适配 dadguard；不构成新的 Rust 分析合同。 |
| [7bec59a](https://github.com/MG1937/ASC/commit/7bec59a1067d48ae21ba8dc69fa4ae1ed474f048) | 上游验证适配 | 修正 benchmark 基线依赖；未来重跑 Python/Rust 比较应记录环境差异，不直接复用历史性能结论。 |
| [4a61f3b](https://github.com/MG1937/ASC/commit/4a61f3beb3d32957e0f8f4964dfdc13d40940b4e) | Python 运行时元数据 | 修改 pyproject 的 Python 版本声明以采用 3.14 free-threading；该提交没有 scanner/thread-pool 实现变更。 |
| [b4af9e0](https://github.com/MG1937/ASC/commit/b4af9e002be6a40f9c691f339443343e8d2b28cf) | 已有等价机制 | listclass 用 MUTF-8 解码 class descriptor；Rust classes 使用 lossless DexText/UTF-16 解析。 |
| [90e3d09](https://github.com/MG1937/ASC/commit/90e3d0900572b2943400bf4a66951e1cc50711b5) | 已有等价机制 | precise-name、无 class 约束时，method/field proxy 的 enumerate 改为 range(len(table))，避免越表；Rust 明确以 header.methods_size/fields_size 作边界。 |
| [b5c4355](https://github.com/MG1937/ASC/commit/b5c435523a847df81b055a30b5341870054bfbde) | 已有等价机制 | getclass 非 BMP 查询编码为 MUTF-8，保持 DEX UTF-16 排序；Rust 将规范 descriptor 转 UTF-16，逐 class_def 比较，不依赖 UTF-8 排序二分。 |
| [ed830c0](https://github.com/MG1937/ASC/commit/ed830c0cd49cdf3a29dbafcdb80ff61aaeef05bc) | 已有等价机制 | string locator 非 BMP 模式改为 MUTF-8，精确成员 class 查找改用 UTF-16 序；Rust 按解码单元匹配，不走原始 UTF-8 模式对 MUTF-8 缓冲区的路径。 |
| [e94ea6f](https://github.com/MG1937/ASC/commit/e94ea6fda880e65435014772b68c286cb0ff3b61) | 保留缺口；不纳入本轮 | 增加字段、字符串、类型等源码 token 元数据及 Ctrl 跳转/xref；Rust 方法/指令身份 API 不能替代源码字符 span，见下文。 |
| [0414d2b](https://github.com/MG1937/ASC/commit/0414d2b4595235baaf4894b5f3c72c01f638217e) | 本轮采用 | 新增 superclass_idx/interface_type_idxs 与 class_def 直接 extends/impl 扫描，精确目标 descriptor；是本轮确定的公共查询能力缺口。 |
| [19affad](https://github.com/MG1937/ASC/commit/19affadbe1f338dcb340442b23ec55da053d0705) | 随关系能力参考 | 调整 _find_type_idx_precisely 迁入 TypeLocator 后的测试调用；不是另一项查找算法。 |
| [d3c05a2](https://github.com/MG1937/ASC/commit/d3c05a201a997b9690ca394761d72ba38a727c03) | 结构适配；优化暂缓 | 拆分 APK loader/reader/worker 和 GUI 组件；另含单 DEX getclass 绕过线程池、使用无取消 one-shot inflate 的快速路径，不能只归类为改名。Rust 是否获益须另测，不能牺牲取消/预算合同。 |
| [c474b1b](https://github.com/MG1937/ASC/commit/c474b1b4c3d4f94952cdc33f2f4e177a42c19b14) | 真实便利缺口；暂缓 | group=True 为混合 query 字典按 kind 返回结果；不是按目标分组的新扫描算法。Rust 当前没有混合种类一次调用 API，但已有 typed caller/target/location 聚合。 |
| [ed8ef00](https://github.com/MG1937/ASC/commit/ed8ef00c5deb53cccbde182defd39eeffca90a65) | 本轮采用 | 把 extends/impl 接入 CLI、class descriptor 规范化和类关系输出；返回 class type_id，而非 containing method_id。 |
| [6573cac](https://github.com/MG1937/ASC/commit/6573caca70b51074dfdef4fff34b322cd62623eb) | 无产品移植项 | Python 包版本更新。 |
| [55c1275](https://github.com/MG1937/ASC/commit/55c1275d22d26542377810b20012f9d4efb2ce7e) | CLI 文档/版本元数据 | 更新 prog/help 和版本子命令处理；Rust clap 已提供 --version，关系查询帮助随本轮能力补齐，不复制 Python 参数解析。 |
| [1736771](https://github.com/MG1937/ASC/commit/1736771618981f7243d6827e7cfb3071492943ca) | 文档参考 | README 更新 CLI 用法和 extends/impl 示例；Rust 文档按自身接口更新。 |
| [9bab341](https://github.com/MG1937/ASC/commit/9bab341f6dd0749d58c847ecf8fef85e11ee5eed) | Python 启动开销 | 延后 importlib.metadata 版本读取并更新包版本；Rust clap 版本来自编译期元数据，没有该导入开销。 |

## 14 个合并提交

对全部合并提交执行 `git log --merges --remerge-diff`，结果没有额外的冲突解决差异；它们没有在已列非合并提交之外引入需要单独移植的内容。仍保留完整清单，避免重复计算或遗漏评审范围。

| 合并提交 | PR | 处理 |
|---|---|---|
| [5395f17](https://github.com/MG1937/ASC/commit/5395f176c9292d1073fb17d5774c4071a431e8b4) | #31 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [2c13441](https://github.com/MG1937/ASC/commit/2c134417eea9d10ba0bcfecec1f068ec0dfb83e7) | #34 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [918a57b](https://github.com/MG1937/ASC/commit/918a57b960e0daf1d4acec027f1c1c100e2bc8e2) | #35 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [8a805bd](https://github.com/MG1937/ASC/commit/8a805bd648e3d479fd690a3bdd74bd47d4d63ef4) | #36 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [f4e1112](https://github.com/MG1937/ASC/commit/f4e1112d1a4ce9219b83a5af0d13365094e4397f) | #40 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [e06edbd](https://github.com/MG1937/ASC/commit/e06edbdd70fa418ae9115021508d1d0b97ba0bdf) | #41 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [464f9fe](https://github.com/MG1937/ASC/commit/464f9fef0db41099c4cf3f55c78b33f2606780d2) | #43 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [079fc3e](https://github.com/MG1937/ASC/commit/079fc3ef6a228ae81266259e595b3ad11269423e) | #44 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [e2313ef](https://github.com/MG1937/ASC/commit/e2313efb809000708a39f8191d592e8865ad67ff) | #45 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [7c96a31](https://github.com/MG1937/ASC/commit/7c96a314afa59cfb26116075324e1fdf702ce29c) | #46 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [3092cd1](https://github.com/MG1937/ASC/commit/3092cd1e83b48394e5a53c337e44caaef2701420) | #47 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [d3d75ab](https://github.com/MG1937/ASC/commit/d3d75ab7a3c092345102d2ec66ab614ad4a6cc75) | #48 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [a458f41](https://github.com/MG1937/ASC/commit/a458f41a42a8ecfc29e9f4fa202b8374243a67af) | #49 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |
| [b93cbd0](https://github.com/MG1937/ASC/commit/b93cbd0798131312b6dc083198e6decbca28a12e) | #50 | 合并记录；所含功能按上表分类，不重复计为新增能力。 |

## 优先采用：直接类关系查询

### 上游精确语义

证据是固定上游的 [ClassDefItemScan](https://github.com/MG1937/ASC/blob/b93cbd0798131312b6dc083198e6decbca28a12e/droidasc/asc_core/findrefs/scan/class_def_item_scan.py)、[TypeLocator](https://github.com/MG1937/ASC/blob/b93cbd0798131312b6dc083198e6decbca28a12e/droidasc/asc_core/findrefs/locator/type_locator.py) 和 [CLI](https://github.com/MG1937/ASC/blob/b93cbd0798131312b6dc083198e6decbca28a12e/droidasc/cli.py)。

- `extends`：精确定位目标 type_id，再匹配 class_def 的 `superclass_idx`。只有直接父类匹配。
- `impl`：精确定位目标 type_id，再检查 class_def 的 `interfaces_off` 指向的 type_list。它查询直接声明的接口关系，也包括接口声明继承另一接口时使用的 interfaces 表，不做类/接口递归闭包。
- 目标必须精确匹配完整 Dalvik descriptor；CLI 可把 Java dotted name 规范化成 descriptor。没有 substring/regex 关系查询。
- 目标可以只出现在 type 表而未在本输入中定义，例如框架父类。缺失目标返回空集合。
- 返回值是匹配 class_def 的 `class_idx`，属于 type 表索引，并非 class_def ordinal 或 method_id。每个 DEX 内保持 class_def 顺序；上游 APK findrefs 按 worker 完成顺序输出，不能据此推断全局稳定顺序。
- 上游没有对重复 class_def 去重，但只返回 type_id，身份信息不足。Rust 应保留自己的 `ClassId`、`DexId`、entry/logical-member 来源及稳定顺序，不能退化成纯名字列表。

### Rust 起点的真实缺口

固定 Rust 的 [ReferenceQuery](https://github.com/LordCasser/ASC/blob/d78123f7c4748e1112314562d3397afbe3df8a06/crates/asc-core/src/model.rs) 只有 String/Type/Field/Method，`Engine::references` 查询 code_item 中的引用。`SourceMetadata::class` 已有 super_class/interfaces，但它是单类反编译输出，不能替代轻量、全输入的关系反查入口。CLI 的 FindKind 同样只有四类。

本轮应增加独立、类型明确的直接关系查询合同，复用已有输入、DEX 041 身份、资源预算、取消、错误和完整结果语义。类定义关系不能伪装为有调用方法和指令位置的 `Reference`。确切 API 与输出由本轮功能 change 规定；审计不把上游实现细节强制成 Rust 架构。

### 最低验收矩阵

1. A extends B、B extends C：查询 B 只返回 A，查询 C 只返回 B；不得自动返回传递子类。
2. A declares I、B extends A：impl I 只返回直接声明者 A；另测接口对接口的直接声明、多个接口与不匹配接口。
3. type 表中存在但输入未定义的框架目标；缺失目标；`NO_INDEX` superclass；`interfaces_off=0`。
4. Java dotted name/完整 descriptor 规范化；相似名字不得 substring 命中；非 BMP descriptor 精确匹配。
5. 同名类跨 DEX、重复定义、Stored/Deflate APK、raw DEX、DEX 041 多 logical member、稳定顺序和来源身份。
6. superclass/type index 越界，interfaces type_list 截断/越界/非法索引；即使无匹配也不得把坏输入当完整成功。
7. 查询/输入/结果预算、预取消/中途取消/恢复、deadline、engine ownership；受控 Report 生命周期和 feature matrix。
8. CLI 文本/JSON、参数放置、输出文件与错误退出；库调用不依赖 CLI 或反编译 feature。

## 已有等价机制：Unicode 与 locator 边界

### MUTF-8、UTF-16 与非 BMP

Rust 的 [ScanDex](https://github.com/LordCasser/ASC/blob/d78123f7c4748e1112314562d3397afbe3df8a06/crates/asc-core/src/dex/mod.rs) 采用以下路径：

- `string_payload` 读取声明的 UTF-16 单元数，`decode_string_into` 用 `mutf8::decode_units` 解码精确单元数并要求相应位置有 NUL terminator。它既不按 UTF-8 字节数截断，也不跨字符串继续搜索。
- `match_string_table`、`match_type_table`、`match_member_table` 对解码后的 UTF-16 单元调用同一 Pattern；精确声明类约束也是 UTF-16 单元比较。
- `locate_class` 扫 class_def，把查询 descriptor 转成 UTF-16 后比较，避免 UTF-8/Python code point 与 DEX UTF-16 排序不一致造成二分漏报。
- `DexText` 保留原始 UTF-16 单元。合法 surrogate pair 可表达为 Unicode，未配对 surrogate 不被替换后静默合并；无法完成 regex 判定时返回 UnsupportedEncoding。不能移植上游的 replacement-character 容错覆盖此合同。
- Rust 原生反编译不经过 Python DexBuilder 的重建路径；受控 vendor 的 `emit_dex::encode_mutf8_into` 及 supplementary/NUL 回归提供额外编码证据，但不能把一个 vendor 单测当作整个产品路径已经复验。

既有回归入口包括 `contract_references` 的 `ref02_mutf8_pool_facts_match_the_scan`、`ref02_bad_mutf8_declared_length_is_rejected`、`ref02_mutf8_edge_variants_fail_malformed`、`ref02_member_and_type_paths_enforce_the_surrogate_rule`；`contract_query` 的 `literals_compare_utf16_units_not_utf8_bytes` 和 `regex_over_unpaired_surrogate_is_unsupported_not_nomatch`。本轮宜补上与上游情形对应的 getclass/classes 非 BMP 精确定位和 UTF-16 排序逆序对（U+10000 与 U+E000）端到端证据，不能只凭存在 codec 单测宣称所有 API 覆盖。

### precise-member 越表

上游 [90e3d09](https://github.com/MG1937/ASC/commit/90e3d0900572b2943400bf4a66951e1cc50711b5) 修的是 Python proxy 的 sequence protocol：无 class 约束的 precise-name 分支执行 `enumerate(dex.methods/fields)`，proxy 不以 IndexError 结束，导致走出表范围。修复改为 `range(len(table))`。

Rust `ScanDex::match_member_table` 用 `header.methods_size/fields_size` 的显式范围遍历，`member_row` 再校验 index，并通过受界限的 type/string 读取解析内容；不存在同样的隐式迭代终止机制。建议以末行/零行成员表和伪造越界索引复验，而不是照搬 Python proxy 修复。

上游 precise-name 由 GUI/API 的 tuple/list 传入，并非新 CLI 旗标。Rust 对合法 Unicode 名称可用 anchored regex 表达精确名称，但独立的 lossless exact-name pattern 不是现有 API；regex 对未配对 surrogate 的错误策略也不等同于精确单元匹配。因此不把它记录成全范围参数级兼容；若消费者确需这一原语，应另立明确语义的 change。

## 暂不采用与保留的真实缺口

### 混合查询批处理

[FindRefManager._find_ref_grouped](https://github.com/MG1937/ASC/blob/b93cbd0798131312b6dc083198e6decbca28a12e/droidasc/asc_core/findrefs/findrefs_manager.py) 的 `group=True` 接受混合种类字典，返回每个输入 kind 对应的列表；例如 extends 和 string 可同次调用。它不是按目标类聚合多个 interface，也不是新的 target 去重算法。

Rust 现有 `Reference` 已保存调用者完整 prototype、TargetId、目标值和位置，单次查询内部的结构化分组比上游纯索引更明确；但确实没有一次调用多个查询种类的等价 API。后续若需要减少重复解析/扫描，应先定义 batch 的每项错误、共享 decoded/result/memory 预算、取消、部分结果与稳定顺序，再用端到端工作负载验证。当前直接类关系查询没有必须依赖此 API 的理由。

### 源码语义 span

4e3da83/e94ea6f 不只是 GUI 美化：`decompile_dex_bytes_with_metadata` 和 `_source_with_member_references` 从 DAD writer token 保留声明/使用、owner、名称、prototype/field type 以及源码字符区间，后续用于点击导航和引用检索。这对嵌入式阅读器或分析 Agent 也有 core 价值。

Rust 的方法/指令 provider 已提供稳定 MethodId、原型、字节码位置与调用目标，但这些不是生成 Java 文本中的字符区间。**源码 token→语义身份映射是尚未覆盖的能力，不能把它写成“已有方法导航，所以已实现”。** 当前任务优先吸收可独立验证的 class_def 关系查询；源码 span 需要 Rust 反编译 writer 自身携带语义 provenance，还要规定 UTF-8 byte/Unicode scalar/UTF-16 offset、文本变化后映射、重载/同名字段、annotation、字符串转义、部分反编译和预算等合同。直接搬运依赖 DAD IR/token 类型的 Python补丁不适用于现有后端。本轮保留该缺口，未宣称它不值得实现，也未将其混入关系 change。

### 单 DEX 快速路径与后端整理

- d3c05a2 新增单 DEX getclass 跳过 ThreadPoolExecutor，同时允许没有 stop_event 的 one-shot inflate。Rust 私有线程池、内存许可和操作取消的成本不同；是否需要跳过 pool 必须以 Rust API/CLI 的端到端计时验证，且不得因此绕过现有取消/预算检查。
- 2e4b8a2 的 dadguard/AXML 迁移解决 Python 后端和启动依赖问题；Rust 已使用独立受控 vendor。没有证据支持为名称对齐更换 Rust 后端。后续有具体反编译语义差异时，仍应建立同一输入的契约样本后评估。
- 本区间 `droidasc/asc_core/findrefs/scan/code_item_scan.py` 没有变化；不能把旧 `bytes.translate` 算法重复列为新增优化。本次没有重跑历史性能实验，也没有声称获得任何性能提升。

## 可复核命令与当前验证状态

以下命令针对单独的上游 checkout，`BASE`/`HEAD` 应使用本报告完整 SHA；Rust 测试命令在 Rust checkout 执行。

```sh
git merge-base --is-ancestor "$BASE" "$HEAD"
git rev-list --count "$BASE..$HEAD"                 # 40
git rev-list --count --no-merges "$BASE..$HEAD"     # 26
git log --merges --remerge-diff "$BASE..$HEAD"      # 14，无额外 resolution diff
git diff "$BASE..$HEAD" -- droidasc/asc_core/findrefs/scan/code_item_scan.py

cargo test -p asc-core --test contract_references ref02_ --locked
cargo test -p asc-core --test contract_query literals_compare_utf16_units_not_utf8_bytes --locked
cargo test -p asc-core --test contract_query regex_over_unpaired_surrogate_is_unsupported_not_nomatch --locked
```

初始源码审计确认了远端引用/完整对象、上游增量范围、merge resolution 检查和源码/既有合同对应关系。下面记录随后实际执行的本轮 Rust 复验；这些结果对应各次运行的工作树快照，历史报告的通过记录不作为本轮证据。

### 本轮运行结果

测试对象：Rust 基础提交 `d78123f7c4748e1112314562d3397afbe3df8a06` 加本轮尚未提交的直接类关系改动；不是原始基础提交的测试结果，也不是已发布版本。以下为 2026-10-15 UTC 的测试快照。

| 命令/范围 | 实际结果 | 证据 |
|---|---|---|
| `cargo test --workspace --all-features --locked` | 25 条标准 harness 汇总，1277 passed、0 failed、6 项既有 ignored | `final-logs/workspace.log`，退出码 0；另含自定义 harness 的 `asc_contracts` 8 项通过，不计入前述 1277 |
| `scripts/check-core-features.sh`：无默认 feature | 190 passed、0 failed、0 ignored | `final-logs/features.log` 中 `default` 段；实际参数为 `--no-default-features` |
| 同上：仅 `manifest` | 213 passed、0 failed、0 ignored | 同日志 `manifest` 段 |
| 同上：仅 `decompile` | 218 passed、0 failed、0 ignored | 同日志 `decompile` 段 |
| 同上：`--all-features` | 241 passed、0 failed、0 ignored | 同日志 `all-features` 段 |
| 同脚本：workspace 外 path consumer | default-check、default-run、all-features-run 全通过 | 同日志末尾；consumer 未继承 workspace patch 或 CLI feature 合并 |
| `cargo test -p asc-droidsaw-dex --test asc_contracts --locked` | 自定义 harness 8 项全部通过 | `final-logs/vendor.log`，退出码 0 |

本轮运行日志目录为 `/workspace/shared/asc-upstream-20261015/final-logs/`，是此次执行环境中的证据位置，不是仓库内持久化附件。可复现入口仍是上表命令和已纳入仓库的回归测试。

上表 workspace 运行包含新 `class_relations` 13 项、`class_relations_cli` 8 项及独立 allocation 回归 1 项；既有 `contract_references` 52 项、`contract_query` 22 项也已在当前改动上执行，包含前文列出的 REF-02、UTF-16 literal 与 surrogate regex 回归。新增 `unicode_exact_normalization_and_utf16_order` 和 `unicode_class_decompile_selects_non_bmp_and_high_bmp_exactly` 对非 BMP/高 BMP 精确选择提供本轮证据。feature matrix 中关系测试为无反编译 feature 时 12 项、启用 decompile 时 13 项。

独立 review 发现的三项 P1 已修复并复验：

1. raw DEX 041 的显式 logical scope 必须只扫描指定 member，不能因共享物理输入而退化成整个 container；保留跨 member 共用的物理解码预算。
2. `interfaces_off` 必须拒绝 header、map 和各 ID table 元数据区域，同时允许 DEX 041 合法共享 data；不得仅以“在整个输入内”作为有效 type_list 判据。
3. Vec 扩容时旧、新分配可能同时存活；结果聚合在增长前为该峰值预留预算，避免账面低于瞬时所有权。最新 workspace 和四组 feature 重跑均已包含独立 `class_relations_memory::aliased_interface_fanout_is_rejected_before_unaccounted_vector_growth` 回归且通过，计入上表；该测试观测分配请求的峰值，不等于进程 RSS 或全局 hard-heap 保证。

质量门禁的实际边界：

- `openspec validate --all --strict --no-interactive`：15 项通过、0 失败，见 `final-logs/openspec.log`。
- 全 workspace 的 strict clippy：退出码 101，`asc-droidsaw-dex` 报告 181 个错误；在独立、干净的 `d78123f` 基础 worktree 重跑也退出 101，并复现相同 vendor 的 181 个错误。见 `final-logs/clippy.log` 和 `final-logs/baseline-clippy.log`。这是已有 vendor lint 债务阻断，不能据此前提宣称本次新增代码已经通过完整 strict lint。
- 全仓格式检查：本轮退出码 1，干净 `d78123f` 基础 worktree 同样退出 1。见 `final-logs/fmt.log` 和 `final-logs/baseline-fmt.log`。基础失败说明历史存在格式债务，不等于证明所有新增/修改行已通过格式检查。
- 本次没有顺带修复历史全仓格式或 vendor lint 债务，也没有把测试/OpenSpec 通过写成“全部质量门禁通过”。后续修改实现或新增测试仍需对相应最终工作树复验。

本轮未进行 APK 性能比较、跨平台验证、IDA 集成或真实部署 RSS 矩阵，因此没有新的性能、全平台或进程硬内存上限声明。源码语义 span 仍是独立候选，没有新开对应 change，也没有宣称被本次关系能力覆盖。上游 `b93cbd0` 是已审计边界，仍然不是“全部已移植”的标记。
