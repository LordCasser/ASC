# class-decompilation

## Purpose

记录 Python getclass 将目标类转换为可阅读 Java 风格源码的能力，以及它的 DEX 提取与重建路径。重建是当前实现机制，不要求新架构必须拥有一个独立 DEX writer，也不保证反编译源码一定能重新编译。

## Requirements


### Requirement: Target class decompilation
分析器 SHALL 将指定 ClassId 反编译为 Java 风格源码并返回来源、完整性和诊断；不要求内部先生成单类 DEX，也不要求逐字等于 Python。完整成功必须保留验收矩阵中的类型、成员、初始化和控制流事实。

#### Scenario: Unsupported method
- **WHEN** 后端无法正确转换一个方法或只输出 stub
- **THEN** 结果标为不完整并含该方法诊断，CLI 返回 1；不能仅因返回了 String 就当作成功。

#### Scenario: Metadata needed for source
- **WHEN** fixture 包含构造器链、异常处理、method 注解和 debug info
- **THEN** 初始化顺序、异常目标、注解值及作用位置保留；缺少 debug info 不阻止分析。

#### Scenario: Basic class
- **WHEN** 对包含 first/second 两个方法的 Test fixture 执行反编译
- **THEN** 源码包含两个正确方法；缺失请求类返回 NotFound。

### Requirement: Static initial values
分析器 SHALL 保持所有静态字段 encoded initial values 与字段身份的映射，包含非 final 字段、默认值及 clinit 后续覆盖的执行次序。

#### Scenario: Non-final static values
- **WHEN** 对 main 的 make_static_field_dex 执行 getclass
- **THEN** FIRST 初值为 11、SECOND 初值为 22，getSecond 读取 SECOND；不得仅保留字段名。

### Requirement: Reconstruction and integrity behavior
分析器 SHALL 保持输入不可变；仅为后端适配创建有边界的 scratch view。DEX 校验字段不一致由 apk-input 的完整性诊断处理；不得靠改头部跳过结构验证，也不暴露通用 DEX 重建接口。

#### Scenario: Repeated decompile
- **WHEN** 对同一输入先后反编译并执行引用查询
- **THEN** 数据和结果保持一致，scratch 在操作结束释放，原校验事实仍可见。

#### Scenario: Zero input checksum
- **WHEN** G03 的结构安全 DEX 完整性字段为零
- **THEN** 在只读分析中报告 warning 并反编译；原始数据不被覆盖。

### Requirement: Analysis runtime independence
生产分析 SHALL 原生运行于 Rust 进程内；引用扫描不初始化反编译后端，不调用 Python/JVM/外部命令。第三方可选能力不进入不需要它的依赖闭包。

#### Scenario: Search without site packages
- **WHEN** 只启用查询能力的下游调用 references
- **THEN** 无反编译器构建/初始化/运行依赖，结果与完整构建一致。
