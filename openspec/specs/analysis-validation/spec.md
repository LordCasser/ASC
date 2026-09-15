# analysis-validation

## Purpose

见 change 归档说明。

## Requirements


### Requirement: Bidirectional correctness evidence
验收 SHALL 使用固定两侧 SHA、输入哈希和完整身份/目标/重复次数做双向差异，所有未分类差异失败。允许差异必须有审计编号、目标行为和独立预期 fixture。

#### Scenario: Python-only reference
- **WHEN** 基线多出一条已验证为真实的引用
- **THEN** gate 失败，不能仅记录条数后成功。

### Requirement: Semantic and boundary matrix
验收 SHALL 覆盖四种查询、正则/字面、Unicode、重载、重复 DEX/类、041、metadata、输入错误、资源耗尽、输出失败和并发。反编译使用已知结构/行为作 oracle；manifest 比较必须包含 text/tail。

#### Scenario: Missing static initialization
- **WHEN** 后端保留字符串和方法名但丢失 G02 的数值
- **THEN** 静态值 gate 失败，不因文本非空或字符串集合一致而通过。

### Requirement: Honest coverage reporting
验证报告 SHALL 记录实测与未验证项，空命中不能充当正向覆盖，skip 不得计为通过。性能在同一语义/参数/输出/线程/平台下对比并报告内存，不能沿用旧分支的速度承诺。

#### Scenario: Candidate backend has only source inspection
- **WHEN** 仅阅读了候选 crate README 和 API
- **THEN** 标记候选未完成实测，不将其视为等价依赖或已完成任务。
