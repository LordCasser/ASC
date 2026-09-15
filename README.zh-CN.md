# rasc

[English](README.md)（主文档）

[维护规格与计划](openspec/README.md)：Python CLI 基线、Rust 特性审计，以及独立 library / 薄 CLI 架构。提案尚未实施。

## rasc 是什么

rasc 是 ASC 的 Rust 重构实现，一个**出于测试目的、但确实可用**的 APK/DEX 分析工具。
它用来探索原生实现的性能表现，以及 Agent 在重构代码、围绕明确目标优化性能时的能力。

大部分实现与迭代由 Agent 参照 ASC 完成，少部分情况由人介入。因此，它既是一个可用的工具，
也是一次 Agent Coding 实践，而不是完全无人参与的自动生成成果。

## rasc CLI-only

出于测试目的，rasc 以简为主，只提供 CLI，围绕 Agent 使用场景优化，不做 GUI。

## 性能与取舍

在一份 343 MiB APK 的 11 个测试场景中，rasc 相对 ASC 的几何平均加速比为 **8.0×**。
测量方法与详细结果见[英文版「性能与取舍」](README.md#performance-and-trade-offs)中的折叠区。

这个结果并非没有代价。随着优化推进，rasc 的部分设计已经与 ASC 不同，不再是逐行翻译。
它更偏向吞吐性能，愿意用更多内存换取速度；例如，多线程引用搜索的峰值内存高于 ASC。
这是一种取舍，不代表每个场景都更省资源。

理解这一速度优势时，首先应考虑从 Python 转向 Rust 原生实现的差别，而不是把它当作 Rust
优于其他语言、或 Agent 优于人工开发的证明。实际结果也受算法、并行方式和内存策略影响。
换用 Zig、C++ 等语言，性能也可能进一步提升。

## 构建

```sh
cargo build --release
./target/release/rasc --help
```

## 命令行

```sh
rasc getclass app.apk com.example.Main                 # 单个类 → Java 风格源码
rasc getclass --threads 16 -o Main.java app.apk 'Lcom/example/Main;'
rasc findrefs app.apk string Authorization             # 在所有根 DEX 中查找引用
rasc findrefs app.apk string 'tok.n' --regex           # 值按正则表达式匹配
rasc findrefs app.apk method onCreate --class com.example.Main
rasc findrefs app.apk field INSTANCE --class example --fuzzy-class
rasc classes app.apk                                   # 类索引
rasc manifest app.apk                                  # 二进制 AndroidManifest.xml → XML
rasc getclass app.apk example.Test --dex 0:1           # 钉选某个逻辑 DEX
```

所有命令共用：`--threads/--thread N`（默认 8，必须为正）、`--debug`（stderr
输出统计，不改变 payload）、`-o/--output FILE`（与 stdout 完全相同的字节，
经同目录临时文件原子替换写入）、`--format text|json`（默认 `text`；JSON 为
单个 envelope 对象，含 `schema_version`、`operation`、`artifact_id`、`data`
与 `diagnostics`）、`--timeout-ms N`（N 毫秒后取消）、可重复的
`--limit KEY=VALUE`（资源上限表覆盖，十进制正整数，见 `rasc --help`）。

退出码：`0` 完整成功（含空结果），`2` 参数或查询错误，`1` 输入/分析/输出错误
与不完整反编译，`130` 取消（用户或超时）。`--help`/`--version` 输出到 stdout
并返回 0；无参数时帮助输出到 stderr 并返回 2。

更多用法见 `rasc --help`，具体命令的参数可通过 `rasc <命令> --help` 查看。
