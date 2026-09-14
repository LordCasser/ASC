# command-line

## Purpose

记录 Python main 在命令行中已经提供的分析入口、参数和输出行为，作为 Rust 能力审计的固定参照。这里描述历史事实；更合理的目标语义由 change 明确覆盖。

## Requirements

### Requirement: Analysis commands
Python CLI SHALL 提供 `getclass APK CLASS` 与 `findrefs APK {string,type,method,field}`。两个主命令接受 `--threads` / `--thread`，默认 8，以及 `--debug`；`-o` / `--output` 同时保存结果。

#### Scenario: Decompile by dotted name
- **WHEN** 执行 `getclass app.apk com.example.Main --threads 2 -o Main.java`
- **THEN** 定位该类、反编译为 Java 风格源码并输出到 stdout 与文件。

#### Scenario: Search by member constraint
- **WHEN** 执行 `findrefs app.apk method onCreate --class com.example.Main`
- **THEN** 搜索被引用的目标方法名和声明类，返回引用它的调用方；`--class` 不限定调用方类。

### Requirement: Query normalization
CLI SHALL 将精确类名中的点转换为斜杠，并补齐 `L` / `;`；已有 `L...;` 且含斜杠时原样保留。模糊类仅在含点且不含斜杠时转换点。string/type 的 value 不进行此归一化。成员名及类约束中空字符串视为未给出。

#### Scenario: Member query has no constraint
- **WHEN** method/field 查询未给出成员名或有效类约束
- **THEN** 报错 `query needs at least one of class or ... name`，运行失败。

#### Scenario: Partial class descriptor
- **WHEN** getclass 接收 `com.example.Main` 或 `Lcom.example.Main;`
- **THEN** 归一化为 `Lcom/example/Main;`。

### Requirement: Payload and diagnostic output
CLI SHALL 将引用结果逐 DEX 批次写入 stdout；若有 `-o`，同时写入 UTF-8 文件，换行为 LF。反编译文件在缺少末尾换行时追加换行。历史 `--debug` 的计时与 APK 日志也写入 stdout，异常消息写入 stderr。

#### Scenario: Debug reference query
- **WHEN** findrefs 启用 debug 且得到结果
- **THEN** stdout 同时有结果和计时，输出文件只有引用结果；这个历史行为不等于目标输出契约。

#### Scenario: Empty reference result
- **WHEN** 查询合法、APK 可读但没有引用
- **THEN** 正常结束且不输出结果行；指定输出文件时文件可为空。

### Requirement: Exit and failure behavior
CLI SHALL 在没有参数时打印帮助并成功退出；argparse 语法错误返回 2；处理过程抛出异常时输出 `Error:` 并返回 1，debug 下另有 traceback。

#### Scenario: Missing class
- **WHEN** getclass 找不到请求类
- **THEN** stderr 报告该类不在 APK 中，退出码 1。

#### Scenario: Invalid worker count
- **WHEN** 解析到 0 或负数线程数并进入线程/进程池路径
- **THEN** 池构造失败，运行错误返回 1；没有 DEX 的提前返回路径不保证触发同一检查。

## Evidence

固定 main：[`main.py`](https://github.com/MG1937/ASC/blob/ccc6bae7704f5c5ef1a7271e27314837079621fb/main.py) 的 `_build_main_parser`、`_format_class_name`、`_normalize_class_query`、`_handle_findrefs`、`_handle_getclass`、`main`。详细复现见审计。
