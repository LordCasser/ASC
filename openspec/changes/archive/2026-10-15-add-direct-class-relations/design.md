## Context

实际实施起点为 Rust `d78123f`；上游评审范围从 `3279d9dd6ffb9c844f8599bd2bf69a13bb602480` 至 `b93cbd0798131312b6dc083198e6decbca28a12e`。上游 extends/impl 精确定位 type_id 后读取 class_def+8 或 +12 的 type_list；返回定义类的 type_id。上游 group 只是按查询 kind 返回字典，不是继承闭包或目标分组。Rust 保留 class_def ordinal，避免重复定义被合并。

## Goals / Non-Goals

默认 feature 即可得到直接关系及完整来源；仅支持精确 descriptor，与上游关系查询范围一致。不会推断传递继承、继承得到的接口、接口是否实际存在或类型系统合法性。不会反编译、扫描无关 code_item、增加关系数据库或持久缓存，也不复制 Python 二分/编码算法。

## Decisions

1. `ClassRelationKind::{Extends, Implements}`、`ClassRelationQuery { kind, target: ClassDescriptor }`、`ClassRelation { class: Class, kind, target_id: TargetId, target: DexText }` 为自有领域类型。每条匹配声明边一行；target_id 的 kind 恒为 Type，index 是所在 DEX type_id，不能假装目标拥有 ClassId。
2. `query::class_relation_query(kind, input, PatternLimits)` 负责 Java 名规范化，核心构造器只接收已经验证的 ClassDescriptor；不暴露关系模糊查询。空/非法/过大查询在打开输入前失败。
3. `Engine::class_relations` 和 `class_relations_in_scope` 返回 `Report<Vec<ClassRelation>>`。根默认范围与 MethodScope 显式范围沿用现有选择、准入、账户、完整性和错误合同。按源 ClassId 后目标 type_id 稳定排序，重复描述符的不同 ClassId 全保留；重复接口 type_id 在同一声明中去重。
4. 从现有 checked ScanDex 读取所有 class_def 身份及 superclass/interfaces 索引；NO_INDEX superclass 与零 interfaces_off 表示无边。type_list 做对齐、数量、乘法/范围及每个 type/string 引用检查。查询无命中仍验证已读取声明关系，不将坏输入隐藏成空成功。不宣称验证未读取的代码、注解或调试信息。
5. 同一操作共享 result-items/result-bytes；每条边计一个 item。内层在增长前限制结果并逐行检查取消，外层 fold_scope/fold_roots 合计预算。关系结果的工作和返回存储均计入共享 memory ledger；最终 Report permit 接管前不得释放工作 permit，clone 保持计量。错误和取消没有部分成功 Report，后续操作可复用 Engine。
6. rasc 使用已有 findrefs 子命令框架，但 JSON operation 为 `class_relations`，data 为关系数组 `{class,kind,target_id,target}`；无 caller/offset 字段。text 为 `dex-key | dex-name | class_def_idx | descriptor | kind | type_idx | target`，沿用列转义。仅支持 exact；`impl` 与 `implements` 同义。输出预算、原子文件提交及退出规则不变。

7. 独立 review 发现已有 raw 041 的 MethodScope::Dexes 丢弃 logical ordinal。修复共享 scope resolver 和消费循环，保留每个真实 logical selector，selected/whole-container 语义一致；补关系、classes/dexes/instructions 与反编译 scope 的公开回归。

## Risks / Trade-offs

共享 type_list 可使声明边数量大于输入 bytes，不能仅依赖已有 scanner 的粗略工作估算。实施必须对新增行提前申请内存、在最终移交前保留对应 permit，且测试低预算拒绝和恢复。非配对 UTF-16 关系目标使用 DexText 保留；exact 按 units 判定，不进行 UTF-8 对 MUTF-8 的字节比较。源 Class 仍遵守现有合法 ClassDescriptor 合同。

## Migration Plan

先写本 change 与 A20 任务卡，再依次实施领域/扫描/Engine、CLI/schema、回归；独立 review 后按证据勾选。现有四种 ReferenceQuery 不变，feature-none 消费者不依赖 decompile/manifest。通过当前平台验证不代表其他平台/IDA/真实 APK 性能已验收。

## Open Questions

无阻断设计问题；scope 使用现有 MethodScope 名称，不为此复制新的范围类型。

## Verification refinements

独立 review 的三个可重现问题已在本包修复并补回归：

- raw 041 的显式 logical scope：选择 0 不再返回所有 member，选择 1 不再变成空集；
  共享 resolver、相关消费者与 scoped class decompile 一并保留 selector。两个 raw member
  的 decoded budget 只计一次物理输入。
- interfaces_off 指向 header 的 0x2c 或 ID table/map 不再因首字为零而被当作空 list。
  标准 DEX 使用声明 data 范围；041 使用整个容器但排除所有 member 的 metadata 区间，
  已验证跨 member 共享接口列表依旧可读。
- 同一接口 list 的多个不同 type_id alias 一个字符串，结果可远大于输入。fold 的源 Vec
  与目标 Vec 同时存活，各自可能有近两倍容量，故结构槽按四倍预留，深拷贝 payload
  与去重树另计。32769 边的独立 allocator 反例已验证低预算在行预留阶段拒绝；
  完整结果在足够预算下仍返回全部不同 type_id。decode scratch 改为
  `16 * min(physical_bytes, max_string_units)` 加每个实际 member 256 bytes 的排除区间界。

输出 schema 配套按 operation 判别 data，消除多个数组 oneOf 导致空数组不合法的问题；
旧 tuple items 数组改为 Draft 2020-12 的 prefixItems，数据形状不变。schema 自检、新旧
真实 payload 和空集均已验证。详细命令与平台限制见 A20 evidence。
