# command-line

## Purpose

记录 Python main 在命令行中已经提供的分析入口、参数和输出行为，作为 Rust 能力审计的固定参照。这里描述历史事实；更合理的目标语义由 change 明确覆盖。

## Requirements


### Requirement: Analysis commands
CLI SHALL 提供 getclass、四种 findrefs，保留 --threads/--thread（默认 8）、--debug、-o/--output，并公开 --regex、--format text|json、--timeout-ms、--limit KEY=VALUE 与 getclass --dex 的明确帮助。共用选项、数值单位和 ordinal 语法遵循 implementation/interfaces.md；classes/manifest 按 rust-cli-extensions 定义。

#### Scenario: Explicit regular expression
- **WHEN** 执行 findrefs 的 string 查询 tok.n 并启用 --regex
- **THEN** 返回 token 的引用；关闭 --regex 时按字面子串处理。

#### Scenario: Decompile by dotted name
- **WHEN** 执行 getclass app.apk com.example.Main --threads 2 -o Main.java
- **THEN** 正确定位类并输出源码，报告来源；文件和 stdout 相同。

#### Scenario: Search by member constraint
- **WHEN** method 查询名称为 onCreate，--class 为 com.example.Main
- **THEN** 约束目标方法的声明类，返回调用方；不把 --class 应用于调用方。

### Requirement: Query normalization
CLI SHALL 把用户输入构造成已验证的领域查询。精确类支持 Java 点名和 descriptor；regex 针对 descriptor 原样匹配。literal type/模糊类的点名转换在帮助中明确；精确类不受 --regex 影响。空/全空白模式与无任何成员约束是语法错误。

#### Scenario: Exact class with regular expression member
- **WHEN** field 模式 SEC.ND 启用 regex，类为 example.Statics
- **THEN** 类精确归一化，名称仍按显式 regex 匹配 SECOND，不因精确类而退化为 literal。

#### Scenario: Member query has no constraint
- **WHEN** method/field 无成员名及有效类约束
- **THEN** 构造阶段返回 InvalidQuery，CLI 退出 2。

#### Scenario: Partial class descriptor
- **WHEN** 精确类输入为 com.example.Main 或 Lcom.example.Main;
- **THEN** 验证并归一化为 Lcom/example/Main;，不接受拼接出的畸形 descriptor。

### Requirement: Payload and diagnostic output
CLI SHALL 只向 stdout 写 payload，向 stderr 写诊断；默认完成整个操作后才提交输出。文件和 stdout 使用同一次有界序列化字节，文本为 UTF-8/LF（合法纯 XML 原文保留是明确例外），控制字符可逆转义，JSON 使用 schema_version=1 的结构化身份和诊断，不含不稳定 timings。

#### Scenario: Debug reference query
- **WHEN** 任意支持 debug 的命令同时指定 -o
- **THEN** debug 不改变 payload，文件与 stdout 字节一致；文件写失败则不发送 stdout payload。

#### Scenario: Output consumer closes
- **WHEN** 文件保存完成后 stdout 接收者关闭
- **THEN** CLI 按平台管道规则退出、不回滚已保存文件、不 panic；不承诺跨两个输出介质的原子性。

#### Scenario: Empty reference result
- **WHEN** 合法输入和查询没有引用
- **THEN** 返回完整空集，text 的 stdout/指定文件为空；JSON 输出 data=[] 的完整 envelope，退出 0。

#### Scenario: Output would replace the input
- **WHEN** -o 指向输入同一文件、可识别的 hardlink、symlink 或目录
- **THEN** CLI 明确拒绝，不覆盖输入；正常输出使用同目录临时文件和原子替换，提交点后不因晚到取消声称未写出。

### Requirement: Exit and failure behavior
CLI SHALL 对完整结果（含空集）返回 0，参数/查询错误返回 2，输入/分析/输出错误或反编译不完整返回 1，用户取消/deadline 返回 130 并区分原因。无参数帮助到 stderr 并返回 2；--help/--version 到 stdout 并返回 0。Unix 关闭管道可以按 SIGPIPE 结束，Windows BrokenPipe 安静返回 0；其他输出错误返回 1。

#### Scenario: Invalid worker count
- **WHEN** 线程数为零或负值
- **THEN** 在分析前拒绝并返回 2，无需打开输入。

#### Scenario: Missing class
- **WHEN** 合法引用查询无结果，或 getclass 找不到类
- **THEN** 前者空成功；后者 NotFound 并返回 1，两者不能混淆。
