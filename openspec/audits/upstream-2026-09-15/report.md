# 上游更新与 Rust xrefs 优化核对

本轮不需要进行 Rust 同步改进。自上次 Python 基线以来，上游没有大的核心功能或算法更新；新增 `getmanifest` 已被 Rust 的 `manifest` 覆盖。`bytes.translate` 早已包含在原基线中。按本轮确认的范围，仅保留核对结论和一次性实验数据，不新增同步或优化任务。

固定证据：Python 原基线 `ccc6bae7704f5c5ef1a7271e27314837079621fb`，2026-09-15 拉取的上游 `c4e268cb78e4a2169455e8d96aa7a2db75c81f36`，Rust 实验基线 `6141965dfeac4256bd96240799d7bf308fa21e27`。审计期间本地另有提交推进到 `60c8ec2`；新增 typed instruction provider 没有改变本次比较的 `scan_code`、目标过滤器和 opcode 表。范围只有 CLI/core。

## 2026-09-17 增量核对

上游从 `c4e268cb78e4a2169455e8d96aa7a2db75c81f36` 更新到 `3279d9dd6ffb9c844f8599bd2bf69a13bb602480`。结论仍然是不需要同步 Rust。这里真正新增的 CLI 能力只有 `listclass`，而当前 Rust 已经有 `classes` 和 `Engine::classes`；另外一项 core 修改是 Python 3.10 的正则语法兼容。没有新的 xrefs、反编译、Deflate 或 benchmark 优化。

| 提交 | 上游变化 | Rust 判断 |
|---|---|---|
| [484d853](https://github.com/MG1937/ASC/commit/484d853660ee1520de2b8796b89ff7676ffdd9ec) | `InsnLocator._build_insn_verify` 在 Python 3.10 不支持 atomic group 时，从 `(?>(?:...)*)` 回退到普通 `(?:...)*`；新增测试证明两种形式验证结果一致 | Python 解释器兼容修复。Rust 按 opcode 宽度表逐指令校验，不使用这段正则，没有对应修复 |
| [752477e](https://github.com/MG1937/ASC/commit/752477e8a374860853c9fcfd6e6604c0db9dcfa7) | 新增 `listclass`，遍历 APK 的 root DEX 与 DEX 041 logical members，保留定义顺序和重复 descriptor，支持 Stored/Deflate、`--prefix`、`-o` 与多 DEX 并行 | Rust 已覆盖同类能力，并额外保留 `ClassId`、`DexId`、entry 名、Java/package/simple name 和重复定义诊断；不需要新增命令别名或第二套扫描路径 |
| [382c4c5](https://github.com/MG1937/ASC/commit/382c4c5a1dcebaef714306718b4487721ac3e988) | Python 包版本改为 `0.1.1.post1` | 分发元数据，无 Rust 行为影响 |

`listclass` 与 Rust `classes` 的界面不完全相同：Python 输出一行一个 Dalvik descriptor，`--prefix` 做大小写敏感的 descriptor 前缀过滤；Rust 输出带来源身份的结构化行，`--filter` 对 Java 名做大小写不敏感子串过滤。底层能力没有缺口，Rust 的结果还能区分不同 DEX 中的同名定义。当前项目不要求 Python CLI 的参数级兼容，所以不为这两个表面差异增加 alias 或专用 prefix API。

本次对照确认 Rust 已覆盖上游新增测试关心的边界：DEX 041 logical members、稳定 entry/member/class-def 顺序、重复定义保留、Stored/Deflate 输入和错误校验。定向验证通过：

```text
cargo test -p asc-core classes_lists_all_definitions_and_flags_duplicates --locked
cargo test -p rasc classes_text_and_json_bytes_are_frozen --locked
cargo test -p asc-core --test contract_input in03_container_041_single_member_keeps_name_and_multi_member_shares_address_space --locked
cargo test -p asc-core --test contract_query class_filter_is_case_insensitive_and_blank_means_no_filter --locked
```

上游 `7c31f06` 只修复 GUI subprocess module path，按本项目 CLI-only 范围忽略。其余新增 SHA 是合并提交。`code_item_scan.py`、`bytes.translate`、单类 Deflate probe、依赖列表和 benchmark 文件均未变化。因此本次只更新审计基线，不创建 OpenSpec change，也不修改 Rust 产品代码。

## 上游实际更新

| 提交 | 变化 | Rust 是否需要吸收 |
|---|---|---|
| [07645e6](https://github.com/MG1937/ASC/commit/07645e6eb8a5b112f74a10084dffa8ae0f01338d) | 新增 `getmanifest` CLI，复用既有 XML decoder；支持 stdout、输出文件和耗时信息 | Rust 已有 `manifest` → `Engine::manifest`，无新增同步项 |
| [362f83c](https://github.com/MG1937/ASC/commit/362f83c3d3e1e78ee79095bc3cdad740a69a54a8) | `src` 搬到 `droidasc`，相对导入、安装包、console script、`python -m droidasc`；`main.py` 保留为委托入口 | 是 Python 分发整理。Rust 已有 library/CLI 分层；本次迁移没有新的 DEX scanner 算法 |
| [1bd7b17](https://github.com/MG1937/ASC/commit/1bd7b178cca33eb01a7d5a78b21708f09b8fadba) | 安装文档与包元数据；新增 Apache-2.0 LICENSE，替换此前 pyproject 的 MIT 标记 | 无运行时移植项；未来直接引用源码时记录对应提交及许可 |
| [81b8deb](https://github.com/MG1937/ASC/commit/81b8deb88b7cde72ad4d3c1f492d09d094bf98e5) | release 源码收集路径适配 | 无 Rust 功能项 |
| [b426286](https://github.com/MG1937/ASC/commit/b426286b9c0de4556f2393c66354ec4c5ae5138f)、[6b4a9c9](https://github.com/MG1937/ASC/commit/6b4a9c9e27403272738cb50b805491a4ea84c0a5) | benchmark wrapper 改写旧导入，清空 `PYTHONPATH` | 仅影响上游验证入口，无 Rust 算法同步项 |

核对了提交树、rename diff 和关键函数；原基线与最新 `code_item_scan.py` 去掉导入语句后相同。单类 Deflate probe、回退路径和反编译算法在这段更新内没有实质变化。现有 benchmark 通过 `main.py` 调用的入口仍然成立，历史文档中的 `src/...` 与旧 SHA 一起保留，不应全局替换路径。

`bytes.translate` 首次进入 [81a1acdc（09-12）](https://github.com/MG1937/ASC/commit/81a1acdc9849c2560f26b0bc270f2ec4c48fe14e)，父提交是 `6642c2551bac99ac39ec9d1f91e1a0f7ff0092c1`。它已包含在 `ccc6bae` 中；`19285b3` 是合并提交，不能再算一次算法升级。81a1acdc 同时改了 operand regex、解压和启动流程，随后部分实现还被回滚，不能把整个提交的耗时下降归因于 translate，也不适合整包照搬。

## translate 在优化哪一段

Python 先解析目标 ID，再对 code region 的原始字节找候选，最后由 `InsnLocator` 校验指令边界。这里的“全局 xrefs”是跨 DEX 搜索查询目标，没有要求构建全部引用的永久索引。

对 16 位索引指令，opcode 在 `p`，小端索引在 `p+2`、`p+3`。上游建立两张 256 项的 0/1 表：opcode 集合和目标 ID 高字节集合。`bytes.translate` 批量产生两个掩码，用偏移三字节的切片对齐，转成大整数做 AND，再由 `bytes.find` 枚举候选。候选仍然要读取完整 ID 做集合查询，并校验指令边界。[固定实现](https://github.com/MG1937/ASC/blob/c4e268cb78e4a2169455e8d96aa7a2db75c81f36/droidasc/asc_core/findrefs/scan/code_item_scan.py#L171-L244)

它把 regex VM 和 Python 层循环中的工作交给了 C 实现的批量操作。这里的掩码是**输入每字节对应一个 0/1 字节**，并不是紧凑的每字节一 bit；还包含复制、切片、大整数和转换结果等 O(N) 临时空间。源码没有给出 SIMD 保证。

上游按 opcode 家族选择路径：type、method、field 使用 translate；string 的普通和 jumbo 各自只有一个 opcode，保留 regex。阈值是 opcode 个数，不是实际数据密度。不能据此推出所有 xrefs 查询都会受益。

## 两个隔离实验

环境：Apple M4 Pro，macOS 26.6.2 arm64，Python 3.14.7，rustc 1.98.1。使用上游固定提交的 `tests/fixtures/reference-workload.zip`，其中 DEX 为 9,577,628 字节，SHA-256 `5cd2401e9ec9a41fc5f78d06acb10d9f334a973bb82df9af381d3e5024aee337`。code region 为 `[1290224, 4499920)`，3,209,696 字节；枚举到 46,009 个非空方法体记录。

原始结果和口径在 [measurements.json](measurements.json)。这些实验只回答局部实现选择，不能用于 Python/Rust 产品速度排名。

**Python：隔离 translate 本身。** 同一个当前 scanner，强制走已有的 operand-aware regex，与默认分流比较；另测优化前父提交。每项预热后交错轮换执行 15 次，取中位数。三种路径的原始候选 offset 和目标 ID 列表全部一致。

| 查询：类型/子串 | 目标数 | operand regex / ms | 当前分流 / ms | 耗时变化 |
|---|---:|---:|---:|---:|
| method / `view` | 20 | 9.445 | 9.462 | +0.2% |
| field / `action` | 160 | 18.524 | 14.952 | −19.3% |
| type / `View` | 654 | 19.102 | 16.969 | −11.2% |
| string / `create` | 572 | 2.969 | 3.000 | +1.1%，两者都是 regex |
| method / `onCreate` | 141 | 11.988 | 12.703 | +6.0% |
| field / `INSTANCE` | 199 | 18.017 | 13.991 | −22.3% |
| type / `Activity` | 135 | 11.180 | 12.848 | +14.9% |

相对真正的旧 scanner，总改动在这些查询的 raw scan 阶段下降约 34%–83%；这个数字包含 operand-aware regex 等同时变化。隔离 translate 后可以看到改善和退化并存。这里没有测 `InsnLocator` 最终边界验证、ZIP 解压、CLI 启动和结果生成，因此没有复现端到端“提升 30%”的结论。百分比统一使用耗时下降 `(old-new)/old`，不混用吞吐提升。

**Rust：保留逐指令宽度遍历，只替换 ID membership。** 从同一个 DEX 导出方法体，使用固定 Rust 基线的 opcode 表；对比 `BTreeSet`、高字节表加 `BTreeSet`、`Vec<u64>` 位图。所有路径的命中数与位置/ID checksum 相同。15 轮交错计时，每轮重复 10 次，表中为单次扫描中位数。

| 查询 | BTreeSet / ms | 高字节预筛+BTreeSet / ms | 位图 / ms | 位图耗时下降 | 位图字节数 |
|---|---:|---:|---:|---:|---:|
| method / `view` | 2.824 | 2.224 | 2.290 | 18.9% | 5,056 |
| field / `action` | 2.549 | 2.304 | 2.086 | 18.2% | 2,608 |
| type / `View` | 2.131 | 2.112 | 1.851 | 13.2% | 936 |
| string / `create` | 1.933 | 1.830 | 1.756 | 9.1% | 8,520 |
| method / `onCreate` | 3.365 | 2.536 | 2.283 | 32.2% | 5,176 |
| field / `INSTANCE` | 2.548 | 2.335 | 2.087 | 18.1% | 2,656 |
| type / `Activity` | 2.046 | 1.961 | 1.835 | 10.3% | 920 |

这是独立简化循环，不是 `asc-core` benchmark：未包含目标集合构建、结果 BTreeMap 聚合、元数据解析、取消检查、预算、线程池、ZIP CRC 或 CLI。七个查询都超过现有四目标预筛阈值，所以也没有测小目标路径。位图大小由最大目标 ID 决定；构建成本不在计时内。只比较命中数和 checksum，不能替代完整 `Reference` 差分验证。单一 DEX、单一 ARM 平台，也没有测 RSS 或硬件计数器。当前结果足以支持进一步验证，不能直接确定通用阈值。

## 本轮处理

维持当前 Rust 实现，不创建同步 change、不调整依赖或 vendor，也不新增性能优化工作包。Python 历史基线继续使用 `ccc6bae`，本次上游提交只作为增量核对记录。

实验说明了 Python 批量过滤的机制，以及 Rust 目标查询存在可测的局部成本；它们没有证明自上次基线以来出现了需要同步的新优化，也没有证明 Rust CLI 可以获得 30% 的整体收益。因此不据此推动实现改动。

代码对照还确认：现有 Rust 已使用 const opcode 表；小目标集合有 operand 字节预筛。`ScanDex::scan_code` 即使预筛未通过，仍检查指令宽度和 payload。这与 Python 先找原始候选再做指令边界验证的路径不同，不能仅按局部计时交换算法。

一次性实验程序和构建产物仅在临时目录运行，未加入 Cargo workspace；归档数据包括固定 SHA、环境、Python 原始采样和 Rust 中位数。没有执行真实 APK 的端到端性能验证，也没有更新既有 OpenSpec 功能或验收状态。
