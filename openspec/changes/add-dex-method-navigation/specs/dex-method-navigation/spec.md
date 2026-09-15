## ADDED Requirements

### Requirement: 方法清单保留真实声明
Engine SHALL 返回声明方法的完整身份、原型、access flags 和代码存在性，覆盖 native、abstract、构造器和重载；不得从渲染源码推断声明。

#### Scenario: 未被引用的 native 方法
- **WHEN** 类中 native 方法没有任何 DEX caller
- **THEN** inventory 仍返回该方法、完整 JNI 可用 descriptor 与 native flag，不依赖 reference 查询命中

### Requirement: 明确 DEX 范围贯穿导航
Engine SHALL 接受已验证 entry/logical 范围并将该范围应用于类、方法、引用与反编译，保留父 ArtifactId 和全局 ordinal。

#### Scenario: assets DEX 和同名类
- **WHEN** 默认根 DEX 和显式 assets DEX 含同 descriptor
- **THEN** 精确 ID 定位请求的定义，返回相应范围与身份，不改成首个根定义

#### Scenario: 范围内外的坏条目
- **WHEN** 一个选定范围之外的 DEX 损坏
- **THEN** 明确范围查询不解析该条目，但不宣称全 APK 校验通过；如果坏条目属于范围内则整个查询失败

### Requirement: 按 MethodId 反编译
Engine SHALL 根据验证后的 MethodId 提供 Java-like 方法源码、必要类上下文 metadata 与完整性诊断；不完整执行必须保留 typed error。

#### Scenario: 重载与无代码方法
- **WHEN** 两个同名重载中一个有实现而另一个 native
- **THEN** 各自 ID 返回各自原型；native 返回声明与无代码状态，实现按目标方法渲染，不能串接其他重载的代码
