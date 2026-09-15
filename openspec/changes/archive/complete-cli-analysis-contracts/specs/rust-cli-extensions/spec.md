## Purpose

将 Rust 已有 classes 与 manifest 命令作为明确的 CLI 能力维护，约束身份、过滤、XML 内容与错误行为；它们不属于 Python main 命令行的等价比较项。

## ADDED Requirements

### Requirement: Class listing
classes SHALL 列出 root DEX 的所有 class definitions，包含 ClassId、DexId、descriptor、Java 名、package/simple name；同名不同来源不能静默消失。--filter 是 Java 名的大小写不敏感子串，按稳定身份排序。

#### Scenario: Same name in two DEXes
- **WHEN** 两个 DEX 定义相同 descriptor
- **THEN** 都可见且可用于 getclass --dex 精确选择；不以 descriptor 单独去重。

### Requirement: Manifest decoding
manifest SHALL 读取最后一个同名 AndroidManifest.xml entry（保持现有 Rust 选择），支持合法 UTF-8 纯 XML 与二进制 AXML；输出保留 namespace、attributes、节点顺序、text/tail/CDATA 和 typed values。未知 value type 保留 raw type/data 并明确表示，不能丢整个文档。

#### Scenario: Extended string and unknown type
- **WHEN** string pool 使用扩展长度，或 attribute 带未命名 type byte
- **THEN** 安全解码并保留完整内容或 raw type/value，不能 panic 或伪装为普通零值。

#### Scenario: Malformed XML
- **WHEN** 文本仅以小于号开头但不合法，或 AXML chunk/string/namespace/stack 越界
- **THEN** 返回结构错误；不是未经验证的 passthrough。合法 style spans 校验并保留于文档 metadata；不扩展为富文本渲染或资源编辑。

#### Scenario: Namespace scope and complete document
- **WHEN** 嵌套节点重绑定 prefix，或第一根节点后存在第二根/无效尾部
- **THEN** namespace 在退出时恢复；完整文档必须被消费，非法尾部返回错误，不能根结束即返回成功。

#### Scenario: Plain XML with external entity declaration
- **WHEN** 纯 XML 含 DTD 或外部实体声明
- **THEN** 明确拒绝，不读取外部文件或网络；合法 UTF-8 文档按完整根/namespace/文本契约处理。

### Requirement: XML serialization
XML 序列化 SHALL 可确定、正确转义，typed dimensions/fractions 使用精确二进制数值规则；XML formatting 不是和 Python 逐字相同的目标。二进制形式输出 XML 声明、4 空格缩进、LF；纯 XML 可保留合法原文。

#### Scenario: Mixed content
- **WHEN** XML 的 text、tail 或 CDATA 含有效空白与特殊字符
- **THEN** 美化不能改变节点文本语义，CDATA 中的结束序列须正确拆分。
