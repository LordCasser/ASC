# class-decompilation

## Purpose

记录 Python getclass 将目标类转换为可阅读 Java 风格源码的能力，以及它的 DEX 提取与重建路径。重建是当前实现机制，不要求新架构必须拥有一个独立 DEX writer，也不保证反编译源码一定能重新编译。

## Requirements

### Requirement: Target class decompilation
getclass SHALL 定位定义目标类的 DEX，在内存中抽取目标类需要的数据，重映射索引并重建单类 DEX，然后调用 Androguard 4.1.3 DAD 输出该类源码。

#### Scenario: Basic class
- **WHEN** 合成 DEX 包含 `Lexample/Test;` 和共享代码的 `first`、`second`
- **THEN** 输出类 Test 及两个方法；输入不存在的类时失败。

#### Scenario: Metadata needed for source
- **WHEN** 类含父类、接口、字段、方法原型、静态值、异常处理、注解或 debug info
- **THEN** 重建路径收集并重映射这些结构；方法注解通过 Python 的 DAD patch 加入源码。复杂组合的输出正确性仍须独立验证，不能仅由存在处理代码推定。

### Requirement: Static initial values
反编译路径 SHALL 保持字段声明顺序、encoded static value 的位置与代码中 field operand 的映射一致，包括没有 `final` 修饰的静态字段。

#### Scenario: Non-final static values
- **WHEN** `Lexample/Statics;` 包含 FIRST=11、SECOND=22，getSecond 读取 SECOND
- **THEN** 源码保留两个初始化值，方法仍读取 SECOND。该场景由 main 的 `make_static_field_dex` 和重建回归测试支撑。

### Requirement: Reconstruction and integrity behavior
Python 路径 SHALL 输出带 `035` magic 的内部重建 DEX，并将 signature/checksum 置零；其 Androguard header patch 忽略 Adler32 验证错误，让内部重建结果可以反编译。该行为不构成对外可安装 DEX 的保证。

#### Scenario: Zero input checksum
- **WHEN** 结构可读的合成 DEX 的 checksum/signature 都为零
- **THEN** getclass 仍能经重建路径输出类源码；这不等价于跳过结构/索引校验。

### Requirement: Analysis runtime independence
引用搜索 SHALL 无需导入 Androguard 或反编译器；getclass 按需加载反编译依赖及纯 Python MUTF-8 shim。

#### Scenario: Search without site packages
- **WHEN** 用不加载 site packages 的 Python 对合成 DEX 执行引用分析
- **THEN** 仍可返回引用；只有反编译需要额外依赖。

## Evidence and limits

固定 main：[`dex_manager.py`](https://github.com/MG1937/ASC/blob/ccc6bae7704f5c5ef1a7271e27314837079621fb/src/asc_core/core/dex/dex_manager.py)、相邻 `dex_constructor.py`、`dex_remapper.py`、`dex_builder.py`；[`decompiler.py`](https://github.com/MG1937/ASC/blob/ccc6bae7704f5c5ef1a7271e27314837079621fb/src/asc_core/utils/decompiler.py)；[`test_decompiler.py`](https://github.com/MG1937/ASC/blob/ccc6bae7704f5c5ef1a7271e27314837079621fb/tests/test_decompiler.py)。

源码同时留下需单独核对的限制：带 try 的指令长度按 u16 读取，builder 生成 debug_info 后部分新头回填逻辑被注释；不能把“有重建代码”写成所有 metadata 已正确保留。目标架构按可观测分析结果验收，不复制这些实现细节。
