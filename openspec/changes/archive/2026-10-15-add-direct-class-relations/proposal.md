## Why

上游 `0414d2b` 与 `ed8ef00` 在 class_def 声明层支持直接 superclass 与 interfaces 反查。Rust 当前仅有四类指令引用，继承元数据依赖可选反编译后端；消费者无法在默认 feature 下按真实 ClassId 跨 DEX 查询关系。

## What Changes

- 在 asc-core 增加独立的直接类关系查询和逐边事实，复用 Class、ClassDescriptor、TargetId、Report 与现有受控扫描流程。
- 仅支持精确类名，与上游关系查询一致；不新增关系子串或 regex 入口。
- rasc 的 findrefs 增加 extends、impl（implements 别名），text/JSON 保留 ClassId、DexId 和目标 type_id，不伪造调用方法或指令位置。
- 增加手工构造的独立关系夹具、回归和资源证据，更新接口与 schema。

## Capabilities

### New Capabilities
- `class-relations`: 查询 class_def 中直接声明的父类或接口关系。

### Modified Capabilities

## Impact

写入 asc-core model/query/dex/engine/lib、rasc 参数与渲染、专属测试、README、JSON schema 与 A20 规格/证据。无需新依赖或 vendor 修改，不改变已有指令引用语义，不归档或勾选 A16–A18 的未完成环境验收。
