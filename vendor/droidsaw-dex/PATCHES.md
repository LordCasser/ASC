# Patch ledger: droidsaw-dex 2.0.0 → asc derived

## DX-P06 — shared host cancellation (A15)

- **问题输入**：ASC 只在 parse/emit 前复制取消状态，宿主在后端执行期间取消不能到达已有检查点。
- **修改文件/符号**：`src/analysis.rs` 的 `Control` 使用 `Arc<AtomicBool>`，新增 `from_cancel_flag`。
- **目标行为**：宿主和后端观察同一标记；deadline 仍由 `Budget` 独立传递，不伪装成用户取消。无轮询线程。
- **测试**：core `engine::tests::backend_control_shares_live_cancellation_and_preserves_causes`；vendor 原有 checked API 取消/期限测试继续执行。
- **必要**：是，嵌入取消合同。维护者：ASC `lordcasser/main`。
- **上游状态**：未提交上游；本地维护补丁。
- **移除条件**：上游提供经过同等测试的共享宿主控制入口。

---

Vendored copy of [`droidsaw-dex`](https://github.com/droidsaw/droidsaw-dex) 2.0.0
(BSD-3-Clause, `LICENSE` kept as shipped). Source provenance and hashes live in
[`upstream.json`](upstream.json); the ready-to-file upstream request text lives in
[`UPSTREAM.md`](UPSTREAM.md). Every behavioural difference against the registry
archive is registered below as a `DX-Pxx` entry. Patched lines carry
`PATCHED (rasc)` / `PATCHED (asc)` markers in source.

At the A04 baseline (commit ff6b414) the diff against the upstream archive was
confined to `src/parser/mod.rs` (DX-P01 + DX-P02). DX-P03 is added by A04.
DX-P04/DX-P05 are registered problems whose code changes land in A05.

Field key (per `maintain-patched-analysis-backends` design §2):

- **问题输入** — the input/shape that exposes the problem.
- **修改文件/符号** — where the patch lives.
- **目标行为** — the behaviour the derived package promises.
- **测试** — pinning test IDs (`asc_contracts::*` are the A04 targets in
  `tests/asc_contracts.rs` of this crate).
- **必要** — whether the patch is required for the ASC acceptance matrix.
- **上游状态** — filed / not filed / no upstream channel yet.
- **移除条件** — when to drop the patch again.

---

## DX-P01 — scoped parse (`parse_for_decompilation` / `parse_for_class`)

- **问题输入**: `rasc getclass` asks for exactly one class per DEX; `DexFile::parse`
  decodes every class body plus emit-only tables (whole-input SHA-1, map-driven
  method handles / call-site ids / section-walk error side channel). Measured on a
  9.8 MiB `classes.dex` (24,436 class_def rows): 120.7 ms full vs 23.7 ms scoped.
- **修改文件/符号**: `src/parser/mod.rs` — `DexFile::parse_inner(data, emit_support,
  target)` (was `parse_inner(data)`), new `DexFile::parse_for_decompilation`,
  `DexFile::parse_for_class` with unmatched-descriptor fallback to the full parse;
  per-class `class_data`/`code_item`/static-value loops skip non-target classes.
- **目标行为**: identical decompiler-visible facts for the selected class; all
  other class bodies stay unparsed. From A04 on, the ASC-reachable entry is
  `analysis::parse_for_analysis` with `ParseOptions::scope` — **`Full` is the
  default**; `ScopedToDescriptor` is opt-in and its known inequivalences are
  reported as structured diagnostics (`R8OriginCommentsDropped`, scope fallback
  notice), see DX-P03.
- **测试**: `src/apk.rs` unit tests (scoped vs full source equality, unmatched
  descriptor falls back, end-to-end `decompile_class`);
  `asc_contracts::scoped_parse_equivalence` (full vs scoped selected-class
  source/metadata/outcome/diagnostic parity on the G02 fixture).
- **必要**: no (performance only). Semantics-first: if any equivalence gap is
  found that diagnostics cannot carry honestly, the scope must be disabled or
  deleted (design DX-P01 rule).
- **上游状态**: request drafted in `UPSTREAM.md` §1; not filed (no upstream
  release channel confirmed for this fork cycle).
- **移除条件**: upstream publishes a public parse scope that keeps R8-origin
  analysis reachable, or ASC measurement (A11/A14) shows the scope no longer pays.

### Known inequivalences (registered, not hidden)

1. `@droidsaw R8Origin(...)` comments come from a whole-DEX analysis over every
   class body; a scoped parse drops them. The Java source itself is unaffected
   (verified by stripping those comment lines; `bench/decompile_equivalence.py`
   reports them separately). `analysis::decompile_checked` emits a structured
   `R8OriginCommentsDropped` diagnostic whenever the scope was not `Full`, so ASC
   never has to scan the source to learn this.
2. Emit-only tables (whole-input SHA-1 canonicality flag, method handles,
   call-site ids, section-walk parse-error side channel) are skipped in **both**
   the full-decompile and scoped-decompile parse shapes, because their only
   consumer is DEX re-emission which ASC never performs. Consequence:
   `DexError`s from the section walker are not produced on the decompile path;
   this is identical for full and scoped, so it cannot break full/scoped
   equivalence (it is a decompile-parse vs `DexFile::parse` difference and is
   recorded here rather than silently dropped).

## DX-P02 — parallel string pool (`parse_string_pool` via rayon)

- **问题输入**: the string pool is a sequential loop over independent entries;
   9.4 ms of a ~24 ms class-scoped parse on a 9.8 MiB DEX.
- **修改文件/符号**: `src/parser/mod.rs` — `parse_string_entry` split out;
  `parse_string_pool` collects `(0..count).into_par_iter().map(...)` through
  rayon's ordered collect, preserving first-error (lowest index) semantics.
- **目标行为**: byte-identical pool and identical first-error selection; decode
  cost spread over cores. Errors and resource control are unchanged: the pool
  size is still `bound_count`-capped against the input length before the pool is
  decoded, and the ordered collect makes the error deterministic. Known
  non-result-affecting transitive environment read: rayon's global pool consults
  `RAYON_NUM_THREADS` when it initializes; thread count cannot change results
  here (ordered collect). ASC-side pool ownership (host-installed pool, budget
  and cancel during the pool decode) is A11/A12 wiring per design DX-P02; A04
  records it as a non-preemptible phase.
- **测试**: `asc_contracts::scoped_parse_equivalence` (error/order parity comes
  from the ordered-collect invariant asserted indirectly by pool equality in
  every test); upstream unit tests of `parse_string_pool` semantics.
- **必要**: no (performance only).
- **上游状态**: request drafted in `UPSTREAM.md` §3; not filed.
- **移除条件**: upstream ships the parallel decode, or measurement shows no win
  on the ASC corpus.

## DX-P03 — ASC controlled entry: checked API, structured outcomes, side-effect removal (A04)

- **问题输入**: every ASC-reachable path before A04 went through
  `decompile_class` → `Trace::from_env()` reading `DROIDSAW_DECOMPILE_TRACE`,
  with further env reads inside the method pipeline
  (`DROIDSAW_PANIC_ON_DECOMPILE_ERR`, `DROIDSAW_DEX_EMIT_LINE_COMMENTS`) and
  transitive env/stdio through `droidsaw-common`'s diag ring
  (`DROIDSAW_DUMP`, `DROIDSAW_DUMP_MAX_STAGES`, `DROIDSAW_CRASH_DIR` +
  `eprintln!`). `decompile_class` returns a bare `String`, so callers cannot
  tell a failed method (`// Failed to decompile:` comment), an unrecognized
  region, or a dropped static initializer from a clean emit except by scanning
  the source.
- **修改文件/符号**:
  - new `src/analysis.rs`: `parse_for_analysis` / `decompile_checked` /
    `ParseOptions` / `EmitOptions` / `Budget` / `Control` / `BackendError` /
    `BackendReport` / `MethodOutcome` / `Completeness` / `BackendDiagnostic` /
    `BackendMetadata`; controlled-mode gate (`enter_controlled`) plus
    `stage_dump_gated`.
  - `src/classes.rs`: `RunCtx` threads explicit trace/line-comment/panic/cancel
    knobs from the API boundary (legacy wrappers still read env once at their
    boundary — unchanged behaviour, ASC no longer calls them);
    `ClassOutcome`/`MethodRecord` sinks record per-method statuses, dropped
    static initializers, unresolved-name fallbacks, indeterminate detectors;
    cancellation/deadline checkpoints between method-pipeline stages.
  - `src/{cfg,ssa,structure,emit,decode}.rs`: the eight
    `droidsaw_common::diag::stage_dump(...)` call sites route through
    `analysis::stage_dump_gated`, a no-op while controlled mode is active.
  - `src/error.rs`: new `DexError::AnalysisControlAbort { deadline }` so stage
    checkpoints can abort without panicking.
  - `src/parser/mod.rs`: `parse_inner` becomes `pub(crate)` (entry point for
    `parse_for_analysis`); `parse_for_class` doc-marked
    deprecated-by-checked (kept until A07 rewires `src/apk.rs`).
  - `src/diag.rs`: `walk_unrecognized` becomes `pub(crate)` (reused by the
    outcome recorder; no behaviour change).
- **目标行为**: results are a pure function of `(view, options, budget,
  control)`; no env reads, no stdio writes, no panic-on-error, no process/cwd/
  signal mutation on the ASC-reachable path. Completeness and per-method status
  (`Emitted` / `DeclarationOnly{abstract|native|no-code}` / `Suppressed` /
  `Unsupported` / `Failed` / `Indeterminate` / `Cancelled`) are structured data
  produced by instrumenting the emit path itself — never recovered by scanning
  the emitted source. The upstream tool entries (`DexFile::parse`,
  `decompile_class*`, examples) remain for the crate's own examples and are
  documented as not-ASC-reachable.
- **测试**: `asc_contracts::env_switches_are_inert` (subprocess env matrix:
  all known `DROIDSAW*` switches set, normal + failing-method inputs, identical
  digests, empty stdout/stderr), `asc_contracts::g02_static_initializer_drop_is_reported`
  (G02 defect state structured), `asc_contracts::declaration_only_outcome`,
  `asc_contracts::failed_method_outcome`, `asc_contracts::cancel_and_deadline`,
  `asc_contracts::scoped_parse_equivalence`, `asc_contracts::legacy_bridge_matches_checked`.
- **必要**: yes — BACK-02/DECL-04 require it.
- **上游状态**: not applicable for filing as-is (ASC-specific entry); the
  stage-dump gating and RunCtx threading are generic enough to propose after
  A05 stabilizes the report shape.
- **移除条件**: upstream grows an explicit-options, no-env, structured-result
  entry covering the same guarantees; or the ASC core stops vendoring this
  crate.

## DX-P04 — G02: static initial values dropped for non-final fields (LANDED in A05)

- **问题输入**: `tests/fixtures/contracts/inputs/g02-static-initializers.dex`
  (sha256 `5686e4a4…f20fe`): `Lexample/Statics;` with encoded-array values
  `FIRST=11`, `SECOND=22` on `public static` (non-final) fields and
  `getSecond()` reading `SECOND`.
- **修改文件/符号**: `src/classes.rs::emit_fields` — the initializer is only
  read when `is_final && is_static && !final_inlined` (and not
  `<clinit>`-assigned), so a non-final static field's encoded value is silently
  dropped and the declaration renders bare (`public static int FIRST;`).
- **目标行为** (per design §4): encoded values map by `class_data` static-field
  order onto `field_idx`; short arrays are legal elision, truncation is
  malformed; all encoded initial values are preserved — including non-final
  fields and fields later overwritten by `<clinit>`; clinit-before-overwrite
  reads must see the encoded value. A05 implements; A04 ships the structured
  defect report so the fix is observable: `BackendReport.metadata.static_fields`
  carries `encoded_value_java` + `initializer_emitted` + `drop_reason`
  (`NonFinalStatic` today) and `Completeness::Incomplete` carries
  `StaticInitializerDropped` reasons.
- **测试**: `asc_contracts::g02_static_initializer_drop_is_reported` (A04:
  defect-as-data); A05 adds the positive DECL-01 assertions on the same fixture.
- **必要**: yes — DECL-01/G02.
- **上游状态**: not filed yet.
- **移除条件**: fix merged and the DECL-01 matrix passes; ledger entry stays as
  historical record.

## DX-P05 — metadata / control-flow semantic fixes (umbrella; partially landed in A05, see status)

- **问题输入**: the DECL-02/DECL-03 fixture matrix (annotations, generic
  signatures, throws, inner/enclosing, debug info, V01 use-before-declare
  declaration order, constructor chains, switch payloads, wide values,
  try/catch/finally, polymorphic invokes).
- **修改文件/符号**: to be enumerated by A05 per sub-issue (each new confirmed
  problem gets a `DX-P05.n` sub-entry: input, site, target, test).
- **目标行为**: the acceptance-matrix normal fixtures decompile completely;
  unsupported methods report structured status instead of silent stubs. A04
  provides the reporting rails (`Unsupported`/`Indeterminate` statuses,
  unrecognized-region records via `diag::walk_unrecognized`, name-resolution
  fallback diagnostics).
- **测试**: A05 (fixture-driven).
- **必要**: yes — DECL-02/03/04.
- **上游状态**: open.
- **移除条件**: per sub-entry, when the corresponding acceptance row passes.

---

## Historical notes carried over

The original vendor README text (rasc-era) documenting the two original patches,
their measurements and the three-layer safety argument (synthetic-APK unit
tests, `bench/decompile_equivalence.py` over stratified real-APK samples,
`bench/contracts.sh` dotted-vs-slashed spelling equivalence) is preserved in the
git history of this file and in `UPSTREAM.md`; nothing was deleted with the
ledger rewrite. `tests/self_contained.rs` in the root crate scans `src/` only
(it stops at the first `#[cfg(test)]` marker per file and never walks
`vendor/`), so the subprocess-based env matrix test in this crate's
`tests/asc_contracts.rs` does not violate the no-process-spawn rule for
production code.


---

## A05 落地状态（2026-09-15，集成 owner 记录）

**已落地并有回归测试**（tests/asc_semantics.rs，13 项全绿；asc_contracts 8 项）：

- DX-P04：`StaticValues` 诚实解码（elision 尾项=类型默认值、截断=malformed 上报、
  非法类型冲突上报），emit_fields 不再以 `is_final` 门控 encoded 初值，
  clinit 先读后写次序保留，final 标志在 clinit 再写场景降级并出诊断。
  测试：`dxp04_all_static_initial_values_emitted`、`dxp04_clinit_before_overwrite_read_sees_encoded_value`、
  `dxp04_truncated_static_values_reported_not_zero_filled`、`dxp04_type_conflict_reported_not_silently_rendered`、
  `dxp04_final_lowered_for_clinit_rewritten_value`。
- DX-P05a：RUNTIME 注解进源码、BUILD/SYSTEM 进 `BackendMetadata`；方法
  prototype/access；debug 参数与局部变量名；无 debug info 仍 Complete。
  测试：`dxp05a_annotations_metadata_lossless_and_runtime_in_source`、
  `dxp05a_member_reports_prototype_and_access`、
  `dxp05a_debug_param_and_local_names_in_source`、`dxp05a_no_debug_info_still_complete`。
- DX-P05b（部分）：构造器 this(...) 委托识别（own-class `<init>` 渲染
  `this(...)` 而非 `super(...)`）；DECL-03 语义矩阵 fixture
  （`decl03_control_flow_constructors_and_payloads`：分支极性、packed/sparse
  switch payload、宽类型字面量、try/catch 两处理器、native/abstract、长方法）。
- IN-03 后端侧：035/037/038/039/040/041 header 变体经 parse_for_analysis
  解析；cdex/odex/未知版本拒绝。测试：`in03_*` 三项。

**已知未修复缺陷**（如实登记，阻断 DECL-03 全绿；均为上游既有、经
干净 A04 基线对照确认非本轮回归）：

1. 循环结构恢复：`for` 形态（sum/i 局部变量 + if_ge 回边）退化为
   `if (…) {} else { do {} while (v0); }` 且 v0 未声明——SSA 对该形态
   的 phi 恢复失败后回退渲染。方法仍标记 Emitted（DECL-04 关注点）。
2. fill-array-data 初始化 sugar 渲染错误（`new int{ v6 }`），数组内容
   未从 payload 展开。
3. ~~上游 lib 单元测试因 `exclude=/tests` 缺 fixture 自 A04 起不可编译~~
   （已由 DX-P07 修复：fixture 改为运行时读取 + skip，干净检出可编译）。

测试基建修复（tests/support，非上游语义）：type_list 4 字节对齐
（androguard 仲裁确认违反规范）、if-lt/if-ge/if-lez 操作码勘误、
switch/fill payload 32 位偏移的第二个占位字、若干 clippy 项。

---

## DX-P07 — 测试 fixture 运行时读取（修复 lib 单测不可编译）

- **问题输入**: 任何 fresh checkout。上游 lib 单测以 `include_bytes!`
  引用 `tests/fixtures/classes.dex`、`classes_named.dex` 与 fuzz
  seeds/crash 语料，这些文件不随仓库分发（`.gitignore` 排除），导致
  `cargo test --workspace` 在干净检出上直接编译失败（A04 起登记的已知
  缺陷 3）。
- **修改文件/符号**: `src/lib.rs` 新增 `#[cfg(test)] mod test_fixtures`
  （`optional()`/`fallback_dex()`/`skipping()`）；约 90 处测试站点由
  `include_bytes!` 改为运行时读取 + 缺失即 skip；`scaffold_dex`/两处
  `fixture_dex`/`ort` 在上游 fixture 缺失时回退到已提交的 g02 契约
  DEX（这些测试只需一个可解析的 `DexFile`）；`static_field_lookup` 的
  SBOM fixture 同样改为运行时 skip。
- **目标行为**: 干净检出上 workspace 测试可编译可运行；fixture 恢复后
  同一测试自动恢复完整断言（skip 分支不再触发）。936 lib 测试 +
  asc_contracts/asc_semantics 全绿验证。
- **测试**: `cargo test --workspace` 于无 fixture 的检出上通过。
- **必要**: 是（可复现验收的前置条件）。
- **上游状态**: 不适用（构建/测试基建，非语义）。
- **移除条件**: 上游 fixture 以可再分发许可入库后可回退为
  `include_bytes!`；在此之前保留。

## DX-P08 — checked parser and CFG/SSA memory admission (2026-09-16)

- `Budget.memory` accepts the host's `MemoryLedger`; opaque RAII leases retain
  reservations in `ParsedDex` and checked reports. No allocator hook, global
  account, subprocess or environment dependency is added. Reports no longer
  deep-clone while sharing one reservation; equality ignores the lease.
- `parser_memory.rs` walks referenced DEX structures without building parser
  IR. It counts string aliases, class data, instructions/payloads/catches,
  annotation values and debug references, including map-driven retained data.
  Unknown/truncated subsections retain the parser's tolerant outcome; checked
  arithmetic and annotation nesting beyond 128 return a resource error.
- `memory.rs` admits CFG/SSA from instruction/block/edge/register dimensions,
  including range invokes, exception edges, phi operands and the trampoline
  census. Class methods execute sequentially, so the largest method workspace
  is retained, together with the census, through the checked report handoff.
- Scoped parse fallback drops the unsuccessful scoped IR before full parsing.
  Parse documentation now reflects `parse_view(..., true, ...)` and its
  checksum/call-site/section-table work.
- This is logical payload admission, not an allocator or RSS limit. BTree node
  padding, allocator metadata, structurer/optimizer temporaries and emitter
  expression expansion are not claimed as exact tracked allocations. The ASC
  wrapper separately accounts normalization buffers and retained Source data;
  a process-level memory limit still belongs to the host deployment.
- Tests: `parser_memory` unit cases (overflow, excessive depth, small fixture,
  unrelated long string), `tests/memory_admission.rs` (rejection, ownership,
  cancellation/reuse and report lifetime), plus existing ASC contracts.

DX-P08 review follow-up: an incomplete outer census fails closed; parser class indexes, pending debug/annotation references and switch-case violations are counted. CFG/SSA additionally covers observed register domains, shared switch uses, leader/handler containers, common phi/seal state, replacement traversal and Vec capacity. Each sequential traversal contributes its live peak, not cumulative allocations across calls.
