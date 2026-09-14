# Python main 与 Rust 的 CLI 特性审计

结论：**不完全一致，也不能把当前 Rust 视为 Python CLI 的等价替换。** 本次仅覆盖命令行和其核心路径，时间为 2026-09-14。基线 SHA 见 [目录说明](../../README.md)。未更改业务实现。

## 已复现的差异

使用 main 自带 `tests/dex_fixture.py` 构造 APK，再把 main 的 `reference-workload.zip` 中 9,577,628 字节的 DEX 装入 APK。完整命令、两侧退出码、stdout/stderr 摘录、哈希见 [results.json](results.json)，复现工具见 [reproduce.py](reproduce.py)。行比较使用 multiset，避免 set 隐藏重复；本工具仍不是完整的结构化语义判定器。

| 编号 | 场景 / Python 结果 | Rust 结果 | 判断 / 计划 |
|---|---|---|---|
| G01 | `string tok.n`、`tok(en\|x)` 各 4 行；field `SEC.ND` 无类/模糊类约束各 1 行 | 均 0 行 | 缺正则查询能力；增加显式模式，不保留 Python 按分支切换匹配器的偶然语义 |
| G02 | 静态非 final 字段输出 `FIRST = 11`、`SECOND = 22` | 两个字段均无 initializer，getSecond 仍读取 SECOND | 确定的数据丢失；不能按格式差异豁免 |
| G03 | checksum/signature 全零的可读 DEX 仍可 getclass | `Adler-32 mismatch`，退出 1 | 接受范围缩小；目标提供诊断并继续结构安全的分析 |
| D01 | type `example.Test` 经正则匹配 `Lexample/Test;`，2 行 | 0 行 | 是点作为通配符的效果，不是 Python type 自动转换；目标用显式正则表达同一需求 |
| D02 | `string [` 退出 1；空 string 在本 fixture 为 `Error: 0` | 字面模式均空结果、退出 0 | 明确新语法和空模式错误，不复制偏移映射故障 |
| D03 | 两个同名 fallback `a.dex` 得到 4 行 | 去重后 2 行 | 主动统一根 DEX 重名策略；不恢复重复扫描 |
| D04 | debug 计时混入 stdout；示例 8 行 | stdout 仅 4 行结果，debug 在 stderr | 保留 Rust 的输出分离 |
| D05 | 无参数帮助到 stdout，退出 0；负线程数运行错误 1 | 无参数帮助到 stderr、退出 2；负线程数语法错误 2 | 无需兼容退出码细节，明确新契约 |
| V01 | ClockFaceView 源码 272 行 | 401 行 | 不能由行数推断正确性；已看到 Rust 构造器用 `v0` 后才声明，Python 也有 float 当整数等问题，两个后端都不是语义 oracle |

G02 的根因在 Rust [emit_fields](../../../vendor/droidsaw-dex/src/classes.rs)：只有 `is_final && is_static && !final_inlined` 才考虑 `static_values`。main 的 `make_static_field_dex` 含实际 encoded values；没有 `final` 不能成为忽略初始化值的理由。

G03 来自不同调用路径：Python 重建内部 DEX 并关闭该结果的 Adler32 错误；Rust [decompile_class](../../../src/apk.rs) 直接交给后端校验原始 DEX。输入结构是否合法和校验字段是否一致是两个判断，目标不能混在一起。

## 范围覆盖与证据

| 编号 | 能力 / 边界 | Python main / Rust 证据 | 当前判断 |
|---|---|---|---|
| C01 | getclass、四种 findrefs、threads/thread、debug、output | main.py；src/cli.rs | 主命令面已覆盖；参数/输出语义见 D04/D05 |
| C02 | 精确类描述符归一化、成员名/类至少一项 | main.py `_format_class_name` / `_build_member_find`；src/query.rs、src/cli.rs | 普通常用输入一致；Rust 有归一化单测 |
| C03 | root classes*.dex 优先、root *.dex 回退、不读嵌套 DEX | apk_handler.py `_parse_cd_dex_entries`；src/apk.rs `parse_dex_entries` | 名称选择相同，fallback 重名不同 D03 |
| C04 | Stored/Deflate、多 DEX、共享 code_item、method 0 | main tests；Rust apk/dex tests；stored/deflated-string probes | 两种压缩各 4 行一致 |
| C05 | type 存在但 class_def 不存在 | Python `_dex_defines_class`；Rust `defines_class` | 都要求定义；Python 二分 type 表，Rust 遍历 class_defs，非规范重复 type 的接受范围不同 |
| C06 | DEX 041 多成员、成员名、完整容器偏移 | 两侧 dex_container/container.rs | 两侧有实现；Rust 自测通过，未做跨语言 041 完整 corpus 等价验证 |
| C07 | 四类指令与 jumbo/polymorphic | Python `_IDX_GROUPS` + InsnLocator；Rust opcodes.rs | 指令族设计相同；call-site/handle/proto 无独立查询，两侧共有边界 |
| C08 | 指令边界、map 回退、空代码、共享代码 | Python InsnLocator.locate 169–202；Rust scan_code、class_data | 两侧有边界校验；立即数伪引用 probe 均零行；不能声称 Python 完全不校验 |
| C09 | 普通 member/type 实际 DEX 引用 | corpus-method/field/type | onCreate 84、INSTANCE 1055、Activity 133 行 multiset 一致；不能外推所有查询 |
| C10 | 无命中、缺类、0 workers | probes + CLI | 无命中可空成功、缺类与 0 workers 均错误；细节不同 |
| C11 | 已有 classes 与 manifest CLI | Rust src/main.rs / manifest.rs | Python main 没有这两个 CLI 子命令；按 Rust 新增能力建立目标规格，不纳入 Python 等价分母 |
| V02 | 注解、debug info、异常、静态初始化、构造器、泛型、复杂控制流 | Python constructor/builder/decompiler；droidsaw classes/parser | 实现路径不同，覆盖不充分；G02 已失败，剩余须逐 metadata fixture 验收 |
| V03 | Unicode / MUTF-8 / 末尾 string / pool 非连续布局 | Python StringLocator 与 tinydex `_get_string`；Rust matching_strings/matching_members/mutf8 | Rust string/type 查询编码 MUTF-8，member/exact class 仍用普通 UTF-8；Python tinydex 按 UTF-8 replacement 解码。不能宣称非 BMP/NUL 的全路径一致 |
| V04 | 重载与输出标识、含换行或分隔符的命中 | 两侧输出均只含 class->name | 都存在表示歧义；目标必须包含完整原型和身份，不以显示字符串做去重键 |
| V05 | 重复类、并行早停、确定性 | Python FIRST_COMPLETED；Rust AtomicBool + SmallestFirst | Rust 同样可能在更低优先级任务未开始前被另一命中停止；当前 list_classes 的 descriptor 去重和 getclass 选择并非共同规则 |
| V06 | 畸形 ZIP/DEX/AXML、CRC、压缩炸弹、映射文件变化 | src/zip.rs、bytes.rs、dex、manifest.rs | 已有局部校验和单测，但没有整体资源上限，也没有完整版本/加密标志/CRC 契约；不是“已安全支持任意输入” |
| P01 | 独立 library / registry 发布 | Cargo.toml、src/main.rs；打包实测 | 只有 binary target；打包失去 patch 后 E0599，parse_for_class 不存在 |
| P02 | 核心输出/配置/依赖隔离 | src/apk.rs render_reference/debug、droidsaw env 读取 | 核心返回预渲染行、直接 eprintln、第三方读取环境变量；不适合直接公开为 library API |

Python 源码均指向固定 [main 树](https://github.com/MG1937/ASC/tree/ccc6bae7704f5c5ef1a7271e27314837079621fb)。表中的 Rust 文件指本次起点 `e809c7b`；文档修改后业务源码未变化。

## 现有验证不能证明什么

1. `bench/corpus_parity.py` 的 sweep 只使 Rust-only 行失败，Python-only 行只计数；`split_rows` 按不含原型的字符串身份覆盖重载。manifest 内容不同的分支不增加 failures，XML 比较还忽略 text/tail。因此“parity ok”不能证明完整一致。
2. `bench/row_oracle.py` 关于 Python 匹配整个 class->member、完全缺少边界检查的注释与本次 main 的 locator 源码不符。必须基于固定 SHA 复核，不能沿用旧原因归类。
3. `bench/decompile_equivalence.py` 比较两份 Rust binary，且删除 droidsaw 注释。它验证 scoped parse 的局部影响，不是 Python/Rust 全特性证明。
4. `bench/jadx_parity.py` 主要看字符串集合与部分字符串顺序，不覆盖数值、静态字段、原型、异常边、初始化顺序；JADX 也只能提供独立对照，不能替代已知输入的预期事实。
5. `tests/self_contained.rs` 只扫描本 crate 的部分源码及直接依赖名，没有验证整个传递依赖图或所有第三方副作用。
6. README 中旧性能测量列的是 Androguard 4.1.4，本次 main 的 requirements.txt 固定 4.1.3；测试时期、依赖和基线均不能混用。本次按 main 的实际依赖重新验证。

这些是验证体系债务，列入第一份 change 的验收任务；本次不修改历史脚本。

结构定位使用 Atlas 对 src/apk.rs 的 scoped search/explore，随后直接核对上述调用路径与两侧源码。Atlas 的局部结构事实不是全仓库/编译器级证明，未用局部调用图的空结果推断功能不存在。

## 本次运行与复现

| 项目 | 结果 / 限制 |
|---|---|
| `cargo test --locked` | 65 单测 + 2 集成测试通过，Rust 1.98.1 / macOS arm64 |
| main `tests/run_tests.py --require-decompiler` | 24 项通过，Python 3.12.9 + Androguard 4.1.3；这是原仓库回归，不等于跨语言等价 |
| audit probes | 28 个有限场景；完整观测见 results.json；不计算“等价百分比” |
| `cargo package --locked --allow-dirty` | verification 失败，E0599: `DexFile::parse_for_class` 不存在；未执行 publish |
| 性能 | 本次未重新跑统计性能比较；不沿用 README 的 8× 作为未来架构承诺 |
| 未验证 | 多 APK corpus、完整反编译语义、跨平台、MSRV 1.93、全部 DEX 版本/异常组合、候选 crate 替换后的契约 |

Python 从 `git archive` 提取到临时目录，保持源码不变。release 回归依赖 `git ls-files`，第一次因 archive 无索引失败；为临时副本建立仅含 main 文件的 Git index 后，全部通过。这不是 Python 功能缺陷。

```sh
# 在保留 main 的 checkout 中，先安装其 requirements.txt；Python 3.12。
cargo build --locked
REF_PY=/path/to/python-venv/bin/python
REF_ROOT=/path/to/main-checkout
"$REF_PY" openspec/audits/cli-parity/reproduce.py \
  --python-root "$REF_ROOT" --rust-bin target/debug/rasc \
  --output /tmp/asc-cli-parity.json
```

真实 DEX SHA-256：`5cd2401e9ec9a41fc5f78d06acb10d9f334a973bb82df9af381d3e5024aee337`。测试 APK 在临时目录生成并删除，不提交样本副本。JSON 摘录上限 3000 字符；保留完整输出哈希和行数，但源码语义复核必须重新运行并保留全文。

## 差异去向

- G01/G02/G03、D01–D05、C11、V02–V06 → `complete-cli-analysis-contracts`；补齐能力并写清主动改变的语义。
- P01/P02、资源与身份边界 → `extract-publishable-core`；不以大重构掩盖已有功能缺失。
- Python 单类 DEX writer 的内部重建、输入 mutation/全局 monkey patch 不搬入新体系；CLI 没有 DEX 导出命令，不能因内部实现不同就新增一个 writer 产品面。
- 任意 call-site/handle/proto 专用查询、完整资源表解析、APK 修改/签名/运行、反编译器通用重写都不是本次新增能力。若未来需要，各自另开 change。

有限审计不可能证明不存在未知缺陷；本计划用逐项验收和发布阻断条件覆盖已知边界，避免把“未发现”当成“完全一致”。
