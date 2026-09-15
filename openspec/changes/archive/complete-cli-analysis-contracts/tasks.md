## 1. 独立证据 — A00

- [x] 1.1 [A00] 固定两侧 SHA 与 G01–G03/全部矩阵 case 的来源、输入 hash、独立预期和非空断言，创建可复现 fixture/harness。
- [x] 1.2 [A00] 修正 parity 单向比较、重载覆盖、旧 row oracle 假设和 manifest 不失败/text-tail 漏比；比较器自测必须检测故意删改事实。
- [x] 1.3 [A00] 固定真实 DEX 和至少 3 个不同实际 APK 的测试 manifest/来源，明确外部工具与可取得性。

## 2. 查询与事实模型 — A01 / A03

- [x] 2.1 [A01] 按 interfaces.md 固定 ID/DexText/Pattern/MemberQuery/Report/Error 与 metadata/manifest 模型，公开构造约束；交接可编译类型。
- [x] 2.2 [A01] 实现 literal/regex、空模式/descriptor/Java 点名/精确模糊独立约束；固定语法/编译/回溯限制和 CLI JSON schema/golden。
- [x] 2.3 [A03] 四种查询统一 MUTF-8/UTF-16/Unicode 匹配，覆盖 NUL/非 BMP/surrogate/末尾/非连续池；不跳过无法完成判定的候选。
- [x] 2.4 [A03] 完整方法原型/目标 index/指令位置建模，共享 code_item、method 0、重载不合并；所有原有 opcode 家族和边界/预筛等价通过。
- [x] 2.5 [A03] 去掉 scanner 对 droidsaw codec 的依赖；结果/code/string/pattern 限额和扫描取消检查真实执行。

## 3. 输入边界 — A02

- [x] 3.1 [A02] ZIP Stored/Deflate、CD/local/descriptor、CRC/长度/ranges、重复 ordinal 和不支持格式契约通过。
- [x] 3.2 [A02] 验证 DEX 035/037/038/039/040/041、table/ULEB/指令结构边界，提供共享物理地址的 ValidatedDexView。
- [x] 3.3 [A02] G03 checksum/signature warning 与私有 scratch、原始 bytes/offset 不变；结构坏输入仍失败。
- [x] 3.4 [A02] low-level 增长/数量/深度预算与 control 检查；为 prefix/full 完整校验接线提供接口与反例。

## 4. 后端能力集成 — A07

- [x] 4.1 [A07] 确认 vendor change 的 A04/A05/A06 已通过并合入：G02、metadata/control-flow 和 AXML 正常矩阵不能用 Incomplete 代替成功。
- [x] 4.2 [A07] 输入/扫描/checked decompile/manifest 收敛为结构化 Report；转换诊断/错误，不以生成源码字符串修补。
- [x] 4.3 [A07] 全部类定义、默认最小 ordinal/显式 dex/class_def_idx、重名 entry/无 DEX/最后 manifest 选择一致；反向完成/1/2/8 workers 确定。
- [x] 4.4 [A07] selected DEX 的完整流/CRC 不被 prefix 或早停削弱；错误顺序和完整交付一致，去掉 apk 预渲染/打印和临时桥接。

## 5. CLI 闭环 — A08

- [x] 5.1 [A08] 全命令参数与线程别名、regex/dex/format/limits/deadline、构造与退出码按 interfaces.md 实现。
- [x] 5.2 [A08] 同次序列化的 text/JSON/完整身份/raw metadata、空集协议、debug 与 payload 分离。
- [x] 5.3 [A08] 有界输出、临时文件 flush/sync/原子替换、输入同文件拒绝、stdio/文件失败/取消提交点、Unix/Windows 管道行为。
- [x] 5.4 [A08] 更新帮助与双语 README，保留全部 CLI 分析能力，不加入无关产品命令。

## 6. 行为冻结 — A09 / A14

- [x] 6.1 [A09] CLI/REF/IN/DECL/MAN 全矩阵、原测试迁移、固定 Python 基线、继承 28 probes 与实际 corpus 验证通过；允许差异精确到 case。
- [x] 6.2 [A09] 独立检查非自比较、双向事实/重复数和 XML text/tail；所有 failed/skip 的必过项关闭后冻结行为证据供 A10。
- [x] 6.3 [A14] 在最终 workspace/public API/归档 CLI 重跑相同矩阵与等工作量性能/RSS，确认重构后无未分类回归，再更新 specs/归档。
