# 验收矩阵与完成标准

这里的 ID 是任务卡、fixture、测试报告和 OpenSpec requirement 的共同索引。所有行都是交付门槛；“正常 fixture 必须完整成功”和“坏/不支持输入必须明确失败”分别断言。增加错误诊断不能代替补齐正常能力。

## 证据格式

A00 创建 `tests/fixtures/contracts/manifest.json` 和 fixtures/generators/expected facts。每条记录包含 case_id、矩阵 ID、来源与许可证、生成器版本/seed、输入 SHA-256、预期事实来源、expected outcome、关联审计编号；生成结果固定到最小可分发 fixture。事实来自手工编码布局/公开格式和独立编译输入，不由候选输出自动刷新。

每个 agent 在 `openspec/implementation/evidence/Axx.md` 交接：实际 base/head SHA、变动文件、矩阵 IDs、命令/工具链/平台、结果计数、预期失败与候选通过、失败/skip 原因、待接线事项。只有完成后才建立该证据文件；此刻没有这些文件，不生成虚假 passed。A09/A14 生成统一 JSON 报告，case 只能是 passed/failed/skipped，skipped 不算 passed。

相同 fixture 在 Python 不支持或表现错误时，记录 expected-difference，附旧审计编号或新证据；候选仍按独立事实验证。用于差异豁免的清单有确切 case/输出字段，禁止全局忽略注释、空白、行序或所有 Python-only 引用。

## 行为门槛

| ID | 关联 spec / 审计 | 必过正常输入与反例 | 实施 → 验收 |
|---|---|---|---|
| CLI-01 | command-line / C01,C02,D05 | 七种调用路径（getclass、四种 findrefs、classes、manifest）；help/version/noargs；threads alias、1/2/8、零/负数、所有共用选项与非法组合；分析前拒绝非法查询 | A01/A08 → A09 |
| CLI-02 | command-line / D04 | 每命令 text/JSON、-o 与 stdout 相同、debug 不改变 bytes；空 text 和 JSON envelope 各自正确；完整 metadata/Unicode/身份可 round-trip | A08 → A09 |
| CLI-03 | command-line | 文件替换/已有文件/目录/symlink/输入同文件与 hardlink；磁盘/权限/rename/stdout 失败；取消提交点；Unix SIGPIPE 和 Windows BrokenPipe；错误无伪成功 payload | A08 → A09/A14 |
| REF-01 | reference-search / G01,D01,D02,C02 | 四种查询 × literal/regex；`.`、alternation、锚点、字符类、量词、转义、捕获、lookaround/backreference、精确/模糊/无类；非法语法、空/全空白；有效空格不 trim，过长/回溯预算明确失败 | A01/A03 → A09 |
| REF-02 | reference-search / V03 | string/type/member/class 同一 BMP/非 BMP/NUL；非配对 surrogate 不混同；MUTF-8 长度/末尾/非连续池/重复 string offsets；坏编码、跨字符串/NUL/ULEB 伪匹配 | A03 → A09 |
| REF-03 | reference-search / C07,C08 | 原有 string/type/field/method opcode 家族、jumbo、fa/fb；call-site/handle/proto 不误分类；立即数/payload 伪 opcode；unknown/truncated instruction 失败，map 回退仍有真实命中 | A03 → A09 |
| REF-04 | reference-search / C04,V04 | method 0、共享 code_item、同名重载、同 target 多位置/多 target、控制字符/分隔符；完整身份、数值索引、重复数双向比较，无展示字符串覆盖 | A03/A07 → A09 |
| IN-01 | apk-input / C03,D03 | root classes*.dex 优先/fallback/嵌套忽略、两类重名取第一并 warning；无 DEX 的查询失败但纯 manifest APK 可成功；合法 manifest 不受无关 DEX 内容错误影响 | A02/A07 → A09 |
| IN-02 | apk-input / C04,V06 | Stored/Deflate/空流/data descriptor 有无签名；CD/local header 一致；坏 EOCD/ranges/CRC/实际大小/尾流；ZIP64/加密/多卷/未知方法拒绝 | A02 → A09 |
| IN-03 | apk-input / C06 | 035/037/038/039/040 各有真实相应 header/opcode fixture；041 单/多成员、跨成员 section 地址；坏零长度/循环/偏移/溢出、未知版本/CompactDex/ODEX 拒绝。不能只改 magic 冒充全版本覆盖 | A02/A05 → A09 |
| IN-04 | apk-input / G03 | 正常/零 checksum/SHA-1 mismatch 的同一结构；warning 后成功，bytes/hash 不变，重复 decompile/references 一致；结构坏仍失败 | A02/A07 → A09 |
| IN-05 | apk-input / V05,C05 | 外部 type 无 class_def 不命中；跨 entry/逻辑 member/同 DEX 重复类；保留全部定义，指定 ordinal 精确选择；反向完成调度、1/2/8 workers 相同身份/错误 | A07 → A09 |
| DECL-01 | class-decompilation / G02 | FIRST=11、SECOND=22 与读取目标；各 primitive/reference encoded value、elision、clinit 覆盖前读、final/非 final、字段排序；截断/类型冲突失败，不能填零隐藏未知值 | A05 → A09 |
| DECL-02 | class-decompilation / V02 | class/field/method/parameter 注解目标、visibility、嵌套/数组/enum/class 值、generic signature、throws、inner/enclosing、access、super/interfaces、proto、debug params/locals/lines；无 debug 正常；不可表达信息在 metadata 保留 | A05 → A09 |
| DECL-03 | class-decompilation / V01,V02 | 构造器 this/super 顺序、重载、native/abstract、if/loop/switch/array payload、宽寄存器和 float/double 位值、try/catch/finally、长方法、polymorphic；V01 use-before-declare 定点修复；正常支持 fixture 需完整成功 | A05 → A09 |
| DECL-04 | class-decompilation | 区分合法无 body 与 stub/fallback/indeterminate；故意不支持方法返回带 MethodId 的不完整错误，正常矩阵不能豁免；部分源码只在 Error 的明确字段内 | A04/A05/A07 → A09 |
| MAN-01 | rust-cli-extensions / C11 | 最后同名 manifest entry；UTF-8 纯 XML/AXML、长 UTF-8/UTF-16 length、style span metadata；无 manifest、错误编码、纯 XML 假文本拒绝 | A06/A07 → A09 |
| MAN-02 | rust-cli-extensions | 全 typed value：reference/attribute、string、boolean、signed/hex、float raw bits、dimension/fraction、四种 color、未知/reserved/dynamic raw type/data；全部保留与正确 XML escaping | A06 → A09 |
| MAN-03 | rust-cli-extensions | prefix shadow、end namespace、默认/属性 namespace、节点顺序、text/tail/CDATA/comments/PI/prolog/epilog、mixed whitespace；缺声明有明确诊断策略，单根后尾部结构必须消费；XML 不能丢 text/tail 比较 | A06 → A09 |
| MAN-04 | rust-cli-extensions | chunks/strings/indices/stack/匹配 end/重复属性/第二根/EOF/深度/节点/属性/输出上限；DTD/外部实体拒绝且无 I/O；release profile 无输入触发 panic | A06 → A09/A14 |

## 架构、补丁与分发门槛

| ID | 关联 spec | 必须得到的证据 | 实施 → 验收 |
|---|---|---|---|
| BACK-01 | maintained-backends | 两份固定上游 archive hash；现有/新增 patch 映射，回归和许可证完整；源码 diff 无未登记行为改动 | A04/A06/A13 → A14 |
| BACK-02 | maintained-backends, core-library | 环境开关矩阵、实际可达传递依赖、空 stdout/stderr；不装全局 logger、signal/env/cwd、不进程退出/启动；checked 状态经真实后端传播 | A04/A12 → A14 |
| BACK-03 | maintained-backends | full/scoped/parallel 相同 selected class facts、metadata、诊断与错误完整性；方法/handle/call-site/R8 依赖检查；不等价时关闭优化 | A04/A05 → A14 |
| CORE-01 | core-library | 默认 features 只 input/classes/references，公开标准库/自有 DTO；compile/doc examples 只依赖 core；API 返回数据可离开 Artifact | A10 → A14 |
| CORE-02 | core-library | path/Arc/raw DEX 相同事实；原输入不写；跨账户 Artifact 拒绝/相同内容重开 ID 可用/不同内容 ID 拒绝；Engine Clone 复用，无悬垂 | A10/A11 → A14 |
| CORE-03 | core-library | 单 pool、顶层串行准入/内部并行、1/2/8 同结果；共享 Engine 并发、失败/取消后复用，retained input permits 回收 | A11 → A14 |
| CORE-04 | core-library | 每个 Limits 字段 limit-1/limit/limit+1（用小 override 无须分配数 GiB）、实际增长而非信 metadata、深度/结果/041 scratch；1k members 无 N×物理副本保留 | A11/A12 → A14 |
| CORE-05 | core-library | admission 等待/读取/解压/scan/backend/输出前取消，deadline cause、等待中可取消；返回后无后台工作；固定检查点及不可抢占阶段测量 | A11/A12 → A14 |
| CORE-06 | core-library, crate-distribution | CLI 只依赖公开 core、无 ZIP/DEX 业务重复、core 无 CLI/runtime tool 依赖；feature 组合事实/诊断一致；传递依赖实际检查 | A10/A12/A13 → A14 |
| DIST-01 | crate-distribution | 两派生包/core/CLI 的 normalized archives、checksums、构建所需文件及 patch test targets；无 root patch/隐含 path/Git-only；版本链明确 | A13 → A14 |
| DIST-02 | crate-distribution | default/no-default/manifest/decompile/all-features 仓库外消费者；同样场景从实际归档运行，G02/041/unknown AXML/env test；staging 与正式 registry 状态区分 | A13 → A14 |
| DIST-03 | crate-distribution | Rust 1.93 与 stable 的 fmt/clippy/tests/doc/features；Linux x86_64、macOS arm64、Windows x86_64 原生 smoke；所有 skip 列为未通过 | A13 → A14 |
| DIST-04 | maintained-backends | 补丁重放/上游升级演练、删除单补丁仍保留其他能力；独立派生版本/核心 pin 更新机制 | A13 → A14 |
| QUAL-01 | analysis-validation | 修正单向 parity、重载覆盖、错误 oracle 注释、manifest 不失败/text-tail 漏比；所有允许差异有精确 case 依据 | A00/A09 → A14 |
| QUAL-02 | analysis-validation | 固定实际真实 DEX 和至少 3 个有来源/hash/可合法测试的 APK（多 DEX 与复杂 manifest 均覆盖）；非空四类引用、定点源码事实；不同版本样本，不能只换压缩算 3 APK | A00/A09 → A14 |
| QUAL-03 | analysis-validation | 固定 SHA/工具链/模式/线程/输入/相同事实，warm-up 后至少 10 次计时，median/p95/peak RSS；full 与 scoped 单独，owned/CRC 成本计入；不沿用旧 8× 宣称 | A14 |
| QUAL-04 | analysis-validation | 有效 fixture 变异与结构 fuzz：ZIP/DEX headers/opcode/041/AXML/后端；debug 和实际 release profile，超时/abort 由测试进程观察，最小化 crash 成为回归 | A13/A14 |

## 对外声明的边界

“完成本计划”要求上述正常 fixture 成功、反例按合同失败、每个矩阵 ID 有通过证据，全部旧测试按新合同迁移后仍有效。已知 67 项 Rust 测试和 24 项 Python 基线测试只是起点，不固定未来总数；测试删改必须说明被哪个更强场景覆盖。

独立语义验证分三层：最小 fixture 的字段/索引/控制流 facts 为硬断言；可编译的纯 Java fixture 用 javac 与固定版本 D8 构建，再用反编译重编译后的行为/可控 Android 测试比较；Android 复杂 corpus 用 DEX 指令/metadata 事实加定点检查。不要求所有反编译文本可重新编译，也不把任何一个 decompiler 的输出当作唯一真值。JADX/Python/JVM 仅为开发测试工具，生产不调用它们。

QUAL-04 的首轮最低运行量为每个选定 fuzz target 10 分钟固定 seed smoke，加每轮 CI 固定小语料回归；这只是可复现起点，不声称穷尽恶意输入。A14 给出 targets、时长、exec 数、崩溃/timeout、peak RSS；有效支持输入崩溃或返回不完整阻断完成，畸形输入 crash 也阻断发布。

若平台、样本、工具或 registry 条件未具备，报告 blocked/未验证并保留相应任务未勾选，不偷偷缩小支持矩阵。只有正式发布这一外部动作可独立留待授权：staged-verified 可以完成代码实施与归档，但不得声称 registry 已发布/已经可 cargo add；发布 checklist 留在发行记录中。

## Requirement 到验收的逐项映射

每行对应 change spec 中的准确 requirement 名称；工作包 owner 由上面矩阵指定。A14 应检查本表与实际 requirement 集完全相等，新增要求时不能只增文案而忘记验收。

| Capability | Requirement | 验收 ID |
|---|---|---|
| command-line | Analysis commands | CLI-01 |
| command-line | Query normalization | CLI-01、REF-01 |
| command-line | Payload and diagnostic output | CLI-02、CLI-03 |
| command-line | Exit and failure behavior | CLI-01、CLI-03 |
| apk-input | Root DEX discovery | IN-01 |
| apk-input | Archive entry decoding | IN-02、CORE-04 |
| apk-input | Logical DEX containers | IN-03、CORE-04 |
| apk-input | Defined class lookup | IN-05 |
| apk-input | Integrity diagnostics | IN-04 |
| reference-search | Target selection | REF-01、REF-02 |
| reference-search | Reference instruction families | REF-03 |
| reference-search | Instruction boundary verification | REF-03、REF-04 |
| reference-search | Reference aggregation | REF-04 |
| class-decompilation | Target class decompilation | DECL-02、DECL-03、DECL-04 |
| class-decompilation | Static initial values | DECL-01 |
| class-decompilation | Reconstruction and integrity behavior | IN-04、CORE-04 |
| class-decompilation | Analysis runtime independence | CORE-06、BACK-02 |
| rust-cli-extensions | Class listing | IN-05、CLI-02 |
| rust-cli-extensions | Manifest decoding | MAN-01、MAN-02、MAN-03、MAN-04 |
| rust-cli-extensions | XML serialization | MAN-02、MAN-03、CLI-02 |
| analysis-validation | Bidirectional correctness evidence | QUAL-01 |
| analysis-validation | Semantic and boundary matrix | REF-01、REF-02、REF-03、REF-04、IN-01、IN-02、IN-03、IN-04、IN-05、DECL-01、DECL-02、DECL-03、DECL-04、MAN-01、MAN-02、MAN-03、MAN-04、CORE-04、CORE-05 |
| analysis-validation | Honest coverage reporting | QUAL-02、QUAL-03、QUAL-04、DIST-03 |
| core-library | Library-owned analysis contract | CORE-01、CORE-06 |
| core-library | Immutable input ownership and identity | CORE-02、CORE-04 |
| core-library | Controlled execution and resource lifetime | CORE-03、CORE-04、CORE-05 |
| core-library | Embedding without process side effects | BACK-02、CORE-06 |
| core-library | Complete typed results and errors | DECL-04、CLI-02、CORE-01 |
| crate-distribution | Two independent packages | CORE-01、CORE-06、DIST-01 |
| crate-distribution | Registry-resolvable maintained dependencies | DIST-01、DIST-02 |
| crate-distribution | Feature and toolchain verification | CORE-06、DIST-02、DIST-03 |
| crate-distribution | Release readiness evidence | DIST-01、DIST-02、DIST-03、DIST-04、QUAL-03、QUAL-04 |
| maintained-backends | Traceable maintained source | BACK-01、DIST-01 |
| maintained-backends | Explicit checked decompiler entry | BACK-02、DECL-04、CORE-05 |
| maintained-backends | Semantic preservation before optimization | BACK-03、DECL-01、DECL-02、DECL-03、DECL-04 |
| maintained-backends | Lossless bounded manifest backend | MAN-01、MAN-02、MAN-03、MAN-04 |
| maintained-backends | Controlled upgrade and replacement | BACK-01、DIST-04 |
