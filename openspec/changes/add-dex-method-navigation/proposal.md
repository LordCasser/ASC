## Why
ASC 已有 ClassId/MethodId、reference caller/target 与 code-unit offsets；缺口是完整 method inventory（含无引用的 native 方法）、方法 access flags、显式扫描范围及单方法 decompile。APK→JNI 联动不能从 Java-like 文本猜测 native 声明和签名。

## What Changes
- 公开 class/method inventory、完整 descriptor/prototype/access flags 和 native/abstract 状态。
- 让 catalog 中的明确 entry/logical DEX 范围与现有身份贯穿 classes/references/decompile；支持非根 DEX 的显式选择。
- 在 core 暴露稳定 MethodId 选择的受控方法反编译，保留 metadata 和完整性诊断。

## Capabilities
### New Capabilities
- `dex-method-navigation`: 按真实 DEX 身份进行方法导航。
### Modified Capabilities

## Impact
asc-core model/dex/engine、必要时 asc-droidsaw-dex 的通用受控入口及 PATCHES；reverse-engine 的 add-precise-apk-code-navigation 和 add-apk-native-bridge 是消费者。JNI 名称映射、SO 分析、IDA 地址与注册证据不进入 core。
