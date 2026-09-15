//! PATCHED (asc, DX-P03): ASC controlled analysis entry points.
//!
//! This module is the frozen interface between the ASC core decompile
//! adapter and this vendored backend (see
//! `openspec/changes/maintain-patched-analysis-backends/design.md` §3 and
//! `openspec/implementation/interfaces.md` §3, row "decompile → vendor").
//! Two functions form the whole contract:
//!
//! - [`parse_for_analysis`] — parse a validated DEX view into a
//!   [`ParsedDex`], with explicit scope, budget and cancel control.
//! - [`decompile_checked`] — decompile one class, selected by its real
//!   `class_def_idx` (never re-resolved by descriptor), into a
//!   [`BackendReport`] carrying the source, a completeness verdict,
//!   per-method outcomes, structured diagnostics and static-field
//!   metadata.
//!
//! # Side-effect contract (BACK-02)
//!
//! While either function is on the stack the crate runs in *controlled
//! mode*: no environment variable is read, nothing is written to
//! stdout/stderr, errors are returned (never panicked on), and no
//! process/cwd/signal state is touched. Concretely:
//!
//! - the entry points call [`crate::parser::DexFile::parse_inner`]
//!   directly, bypassing `DexFile::parse`'s `droidsaw-common` diag
//!   wrapper (`with_input_hash` + `stage_dump`);
//! - the per-stage `droidsaw_common::diag::stage_dump` call sites in
//!   `cfg.rs` / `ssa.rs` / `structure.rs` / `emit.rs` / `decode.rs`
//!   route through [`stage_dump_gated`], a no-op under controlled mode;
//! - trace output, line-number comments and panic-on-error behaviour
//!   are threads of explicit [`EmitOptions`], not env switches.
//!
//! The upstream tool entries (`DexFile::parse`, `decompile_class*`,
//! `EnumInlineMap::build`, the crate examples) keep their historical
//! env-driven behaviour for the crate's own tooling; they are **not
//! reachable from ASC** and are documented as such at each definition.
//!
//! # Determinism
//!
//! Results are a pure function of `(view, options, budget, control)`.
//! The parallel string pool (DX-P02) uses rayon's ordered collect, so
//! thread count — including rayon's own `RAYON_NUM_THREADS` env read at
//! global-pool init — cannot change results or error selection.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::error::DexError;
use crate::parser::DexFile;

// ─────────────────────────────────────────────────────────────────────
// Controlled-mode gate
// ─────────────────────────────────────────────────────────────────────

/// Depth counter for controlled mode. Reentrant because
/// `decompile_checked` may be called while a `parse_for_analysis` guard
/// is still alive in a caller frame; the mode ends when the last guard
/// drops.
static CONTROLLED_DEPTH: AtomicUsize = AtomicUsize::new(0);

/// RAII guard returned by [`enter_controlled`]. Dropping it decrements
/// the controlled-mode depth; the mode ends at depth 0.
#[must_use]
pub(crate) struct ControlGuard {
    /// Prevents `Clone` (a cloned guard would decrement twice).
    _private: (),
}

pub(crate) fn enter_controlled() -> ControlGuard {
    CONTROLLED_DEPTH.fetch_add(1, Ordering::Release);
    ControlGuard { _private: () }
}

impl Drop for ControlGuard {
    fn drop(&mut self) {
        CONTROLLED_DEPTH.fetch_sub(1, Ordering::Release);
    }
}

fn is_controlled() -> bool {
    CONTROLLED_DEPTH.load(Ordering::Acquire) > 0
}

/// Replacement for `droidsaw_common::diag::stage_dump` at the eight
/// in-crate call sites. Under controlled mode (ASC) it is a no-op, so
/// the `DROIDSAW_DUMP` / `DROIDSAW_DUMP_MAX_STAGES` env reads and the
/// ring-eviction `eprintln!` inside `droidsaw-common`'s diag module are
/// unreachable. Outside controlled mode it forwards unchanged, keeping
/// the upstream debug facility intact for the crate's own tools.
pub(crate) fn stage_dump_gated<S>(stage: &str, payload: &S)
where
    S: serde::Serialize + ?Sized,
{
    if is_controlled() {
        return;
    }
    droidsaw_common::diag::stage_dump(stage, payload);
}

// ─────────────────────────────────────────────────────────────────────
// Options / budget / control
// ─────────────────────────────────────────────────────────────────────

/// Parse scope for [`parse_for_analysis`]. The default is [`ParseScope::Full`]
/// — the scoped fast path is opt-in because it has a registered
/// inequivalence (cross-class R8-origin comments; see `PATCHES.md`
/// DX-P01) that ASC must opt into knowingly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseScope {
    /// Parse every class body (the "decompile" parse shape: all class
    /// bodies, annotations and debug info; emit-only tables remain
    /// skipped — see DX-P01 note 2).
    Full,
    /// Parse only the class bodies of `descriptor`; every other class
    /// keeps its `class_def` row but no body. If the descriptor matches
    /// no class def the parse falls back to [`ParseScope::Full`]
    /// semantics and [`ParsedDex::scoped_fell_back_to_full`] reports it.
    ScopedToDescriptor {
        /// Type descriptor to keep, e.g. `Lcom/example/Foo;`.
        descriptor: String,
    },
}

/// Explicit parse options. Deliberately tiny: everything the previous
/// env-driven path configured is either fixed here (no env) or belongs
/// to [`EmitOptions`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOptions {
    /// Which class bodies to parse. Defaults to [`ParseScope::Full`].
    pub scope: ParseScope,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            scope: ParseScope::Full,
        }
    }
}

/// Explicit emit-time knobs replacing the `DROIDSAW_DECOMPILE_TRACE`,
/// `DROIDSAW_DEX_EMIT_LINE_COMMENTS` and
/// `DROIDSAW_PANIC_ON_DECOMPILE_ERR` env switches. All default to off;
/// ASC passes explicit values and the environment is never consulted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmitOptions {
    /// Per-stage trace lines (upstream `DROIDSAW_DECOMPILE_TRACE`).
    /// ASC must pass `false`: the trace writes to stderr.
    pub trace: bool,
    /// Emit `// line N` comments from debug info (upstream
    /// `DROIDSAW_DEX_EMIT_LINE_COMMENTS`).
    pub line_comments: bool,
    /// Promote per-method pipeline errors to panics (upstream
    /// `DROIDSAW_PANIC_ON_DECOMPILE_ERR`). Debug facility only; ASC
    /// must pass `false` — panics violate the library contract.
    pub panic_on_err: bool,
}

/// Minimal frozen budget shape (A11 wires the full resource account).
/// Both fields are advisory caps checked at the documented checkpoints;
/// they never change results, only abort them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Budget {
    /// Wall-clock deadline. Checked at parse entry/exit, before the R8
    /// trampoline census, between method-pipeline stages and per method.
    /// A deadline that has already passed makes the call fail fast.
    pub deadline: Option<Instant>,
    /// Hard cap on the input view length in bytes, charged once at
    /// parse entry. `None` means unbounded (upstream parse-side
    /// `bound_count` caps still apply).
    pub max_input_bytes: Option<u64>,
}

/// Cooperative cancellation token. Clone shares the same flag; set it
/// from any thread. Cancellation is *cooperative*: the checkpoints
/// listed under [`Budget`] observe it, the phases listed in
/// `PATCHES.md` DX-P03 (non-preemptible functions) do not, and a
/// cancelled call returns [`BackendError::Cancelled`] without
/// delivering a report.
#[derive(Debug, Clone, Default)]
pub struct Control {
    cancelled: Arc<AtomicUsize>,
}

impl Control {
    /// Create a fresh, non-cancelled control.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(1, Ordering::Release);
    }

    /// Whether [`Control::cancel`] was called.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) != 0
    }
}

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

/// Error surface of the checked entry points. Core maps this onto its
/// own `Error` (suggested mapping in the evidence doc): `Dex` →
/// MalformedInput-ish, `Cancelled`/`DeadlineExceeded` → Cancelled with
/// cause User/Deadline, `InputBudget`/`InvalidClassDefIndex` →
/// ResourceLimit/InvalidQuery.
#[derive(Debug)]
pub enum BackendError {
    /// A backend-internal typed error (parse or method pipeline).
    Dex(DexError),
    /// The cancel token was observed set; no report is delivered.
    Cancelled,
    /// The deadline passed; no report is delivered.
    DeadlineExceeded,
    /// The input view exceeds `Budget::max_input_bytes`.
    InputBudget {
        /// Actual view length.
        bytes: usize,
        /// Configured cap.
        cap: u64,
    },
    /// `selected_class_def_idx` is out of range for this `ParsedDex`.
    InvalidClassDefIndex {
        /// The index that was passed.
        index: usize,
        /// Number of class defs actually present.
        class_defs: usize,
    },
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::Dex(e) => write!(f, "backend error: {e}"),
            BackendError::Cancelled => write!(f, "analysis cancelled by control"),
            BackendError::DeadlineExceeded => write!(f, "analysis deadline exceeded"),
            BackendError::InputBudget { bytes, cap } => {
                write!(f, "input of {bytes} bytes exceeds budget cap {cap}")
            }
            BackendError::InvalidClassDefIndex { index, class_defs } => write!(
                f,
                "class_def index {index} out of range (this DEX has {class_defs} class defs)"
            ),
        }
    }
}

impl std::error::Error for BackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BackendError::Dex(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DexError> for BackendError {
    fn from(e: DexError) -> Self {
        BackendError::Dex(e)
    }
}

/// Internal: map a stage-checkpoint abort to its surfaced cause.
fn abort_to_backend(deadline: bool) -> BackendError {
    if deadline {
        BackendError::DeadlineExceeded
    } else {
        BackendError::Cancelled
    }
}

// ─────────────────────────────────────────────────────────────────────
// Report model
// ─────────────────────────────────────────────────────────────────────

/// Machine-readable diagnostic code. Stable identity for ASC; the
/// human `message` is not a machine key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticCode {
    /// An encoded static-field initializer exists but the emitter
    /// dropped it (see the matching `InitializerDropReason`).
    StaticInitializerDropped,
    /// An encoded static-field initializer could not be rendered and a
    /// type-default zero literal was emitted instead (hidden unknown).
    StaticInitializerDefaulted,
    /// A method pipeline stage returned a typed error.
    MethodFailed,
    /// A method body contains unrecognized bytecode-signature regions.
    MethodUnsupported,
    /// A Kotlin-vs-Java rendering detector returned `Indeterminate`.
    DetectorIndeterminate,
    /// A pool lookup fell back to the `?` placeholder name.
    UnresolvedName,
    /// A return-type descriptor lookup failed and `void` was assumed.
    UnresolvedType,
    /// A scoped parse fell back to the full parse (descriptor matched
    /// no class def).
    ScopedFallbackToFull,
    /// A scoped parse cannot produce cross-class R8-origin comments.
    R8OriginCommentsDropped,
    /// PATCHED (asc, DX-P04): the class_def's `static_values`
    /// encoded_array is truncated/malformed — entries beyond the
    /// decodable prefix are unknown and were NOT zero-filled.
    StaticValuesTruncated,
    /// PATCHED (asc, DX-P04): a `final` field's access flag was lowered
    /// in the emitted source so the declaration initializer (encoded
    /// value) and the `<clinit>` reassignment can coexist. The raw
    /// flags stay in `StaticFieldReport::access_flags`. Rendering
    /// decision only — does not affect completeness.
    FinalFlagLowered,
    /// The DEX carries tolerant-parse failure records
    /// (`DexFile::parse_errors`).
    ParseErrorsPresent,
}

/// One structured diagnostic. `method_idx` / `field_idx` locate the
/// record when applicable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendDiagnostic {
    /// Machine identity.
    pub code: DiagnosticCode,
    /// Human-readable detail; not a machine key.
    pub message: String,
    /// Method the diagnostic is about, when applicable.
    pub method_idx: Option<u32>,
    /// Field the diagnostic is about, when applicable.
    pub field_idx: Option<u32>,
}

/// Why an encoded static initializer was not (fully) reflected in the
/// emitted declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitializerDropReason {
    /// G02 defect state: the field is static but not final, and
    /// `emit_fields` only reads `static_values` for final fields. A05
    /// (DX-P04) fixes the emitter; until then this is reported as an
    /// incompleteness.
    NonFinalStatic,
    /// `<clinit>` assigns the field, so the declaration initializer is
    /// intentionally suppressed (javac rejects the double-assign on
    /// `final`). Intentional, informational.
    AssignedInClinit,
    /// R8 inlined the class's `<clinit>` into another method; `final`
    /// and the initializer are stripped so the assignment compiles.
    /// Intentional, informational.
    R8InlinedAssignment,
    /// The encoded value exists but `encoded_value_to_java` cannot
    /// render it; the emitter may substitute a type-default literal,
    /// hiding the unknown value (DECL-01 forbids that silently).
    /// PATCHED (asc, DX-P04): since DX-P04 the emitter no longer
    /// zero-fills a present-but-unrenderable value — it reports this
    /// reason (an incompleteness) and leaves the declaration bare.
    UnrenderableValue,
    /// PATCHED (asc, DX-P04): the encoded_array declared an entry for
    /// this field position but the bytes were truncated/malformed, so
    /// the value is unknown. Never zero-filled (DECL-01).
    TruncatedStaticValues,
    /// PATCHED (asc, DX-P04): the encoded value's tag conflicts with
    /// the field's declared type (e.g. String value on an `int`
    /// field). Reported instead of rendered; DECL-01 type-conflict row.
    TypeConflict,
}

/// Per-static-field record for [`BackendMetadata`]. This is the G02
/// defect-as-data surface A05 builds its fix assertions on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticFieldReport {
    /// `field_ids` index (identity within the DEX).
    pub field_idx: u32,
    /// Best-effort field name (`"?"` if the string pool lookup failed).
    pub name: String,
    /// Field type descriptor.
    pub type_descriptor: String,
    /// Raw access flags from `class_data`.
    pub access_flags: u32,
    /// Java-literal rendering of the encoded-array entry when one
    /// exists **and** it renders; `None` when the slot is elided or the
    /// value is unrenderable (distinguish via [`Self::drop_reason`]).
    pub encoded_value_java: Option<String>,
    /// PATCHED (asc, A12): the raw encoded value, resolved to a
    /// primitive-only typed record (DECL-02 typed metadata).
    pub typed_value: Option<crate::analysis::TypedValue>,
    /// PATCHED (asc, DX-P04): lossless metadata-grade rendering of the
    /// encoded-array entry whenever one exists at this slot (including
    /// shapes Java source cannot express — Method / MethodType /
    /// MethodHandle / Annotation values render as typed reference
    /// text). `None` only when the slot is elided/truncated/unreadable,
    /// so a present-but-dropped value is never silently gone.
    pub encoded_value_metadata: Option<String>,
    /// Whether the emitted declaration carries an `= <literal>` part.
    pub initializer_emitted: bool,
    /// Why an existing encoded value was not reflected, when applicable.
    pub drop_reason: Option<InitializerDropReason>,
}

/// Why a method is declaration-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationKind {
    /// `ACC_ABSTRACT` set, no code item.
    Abstract,
    /// `ACC_NATIVE` set, no code item.
    Native,
    /// No code item and neither flag (degenerate DEX shape).
    NoCode,
}

/// Why a method intentionally does not appear in the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionReason {
    /// javac/D8-synthetic enum plumbing (`$values`, bridge ctor,
    /// `values()`, `valueOf`, enum-populating `<clinit>`).
    EnumSyntheticMethod,
    /// Kotlin top-level-function facade synthetic `<init>`/`<clinit>`.
    KotlinFacadeSynthetic,
}

/// Per-method outcome. Produced by instrumenting the emit loop itself
/// (`classes.rs::emit_methods`), never by scanning the source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodStatus {
    /// A method body was emitted (no unrecognized regions recorded).
    Emitted,
    /// No code item; only a declaration is possible.
    DeclarationOnly {
        /// Which flag shape caused it.
        kind: DeclarationKind,
    },
    /// Intentionally absent from the source (synthetic plumbing).
    Suppressed {
        /// Which suppression fired.
        reason: SuppressionReason,
    },
    /// The body contains unrecognized bytecode-signature regions; the
    /// emitted method embeds raw-region comments. Cannot be part of a
    /// complete success.
    Unsupported {
        /// Number of real (non-sentinel) unrecognized regions.
        regions: usize,
        /// Region kind summary (one entry per region).
        detail: String,
    },
    /// A pipeline stage returned a typed error; the source carries a
    /// `// Failed to decompile:` comment for this method.
    Failed {
        /// Error summary.
        detail: String,
    },
    /// The class-level Kotlin rendering verdict was `Indeterminate`;
        /// the emitted shape is a best guess.
    Indeterminate {
        /// Which detectors refused to answer.
        detail: String,
    },
    /// A control checkpoint aborted this method; the whole call returns
    /// `Err(BackendError::Cancelled)` / `Err(DeadlineExceeded)` and the
    /// partial source is discarded.
    Cancelled,
}

/// One method's outcome, identified by `method_idx` (the DEX method_ids
/// index). `name` / `is_direct` are conveniences for triage; identity
/// is `method_idx` only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodOutcome {
    /// DEX method_ids index (identity).
    pub method_idx: u32,
    /// Best-effort raw name (`"?"` if unresolvable — then a matching
    /// `UnresolvedName` diagnostic is present).
    pub name: String,
    /// Direct (true) vs virtual (false) list membership.
    pub is_direct: bool,
    /// Outcome status.
    pub status: MethodStatus,
}

/// Why the report is not complete. Any non-empty list means the caller
/// must not treat the source as a full success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncompleteReason {
    /// A method failed its pipeline.
    MethodFailed {
        /// Which method.
        method_idx: u32,
    },
    /// A method emitted with unrecognized regions.
    MethodUnsupported {
        /// Which method.
        method_idx: u32,
        /// How many real unrecognized regions.
        regions: usize,
    },
    /// A method's rendering verdict was indeterminate.
    MethodIndeterminate {
        /// Which method.
        method_idx: u32,
    },
    /// A control checkpoint aborted at least one method.
    MethodCancelled,
    /// An encoded static initializer was dropped (G02 defect family).
    StaticInitializerDropped {
        /// Which field.
        field_idx: u32,
    },
    /// A class-level rendering detector refused to answer.
    DetectorIndeterminate {
        /// How many detector diagnostics fired.
        detectors: usize,
    },
    /// The DEX records tolerant-parse failures that dropped subsection
    /// data (annotation trees / encoded arrays / class_data / code
    /// items / debug info / interface lists). Structural anomalies
    /// (pool ordering etc.) are diagnostics only and do not appear
    /// here.
    ParseErrors {
        /// How many subsection-dropping `DexFile::parse_errors`
        /// entries exist.
        count: usize,
    },
}

/// Completeness verdict for a [`BackendReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completeness {
    /// Every method emitted cleanly, no initializer drops, no
    /// indeterminate detectors, no parse-error records.
    Complete,
    /// Something above is violated; `reasons` enumerates each one.
    Incomplete {
        /// Machine-readable reasons (may be several).
        reasons: Vec<IncompleteReason>,
    },
}

/// Class-level metadata returned alongside the source. Minimal frozen
/// shape for A04; A05 extends it under the DX-P04/DX-P05 ledger
/// entries (annotations, throws, inner/enclosing, debug info etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendMetadata {
    /// Index into `DexFile::class_defs` that was decompiled.
    pub class_def_idx: usize,
    /// Class type descriptor (`Lcom/example/Foo;`).
    pub descriptor: String,
    /// Raw class access flags.
    pub access_flags: u32,
    /// Superclass descriptor, when resolvable.
    pub super_descriptor: Option<String>,
    /// Implemented/extended interface descriptors in declaration order.
    pub interfaces: Vec<String>,
    /// `SourceFile` attribute string, when present.
    pub source_file: Option<String>,
    /// Per-static-field records (see [`StaticFieldReport`]).
    pub static_fields: Vec<StaticFieldReport>,
    /// Instance field count from `class_data`.
    pub instance_field_count: usize,
    /// Direct + virtual method count from `class_data`.
    pub method_count: usize,
    /// PATCHED (asc, DX-P05a): every annotation carried by the class's
    /// annotation directory, on every target (class / field / method /
    /// parameter) and in every visibility (BUILD / RUNTIME / SYSTEM),
    /// with lossless element rendering. RUNTIME-visibility annotations
    /// are additionally rendered into the source; BUILD/SYSTEM shapes
    /// live only here.
    pub annotations: Vec<AnnotationReport>,
    /// PATCHED (asc, DX-P05a): raw `dalvik.annotation.Signature`
    /// string, joined in encoded order. Java generics are not
    /// reconstructed into source (a wrong generic header is worse than
    /// an honest metadata record); the signature is preserved verbatim.
    pub generic_signature: Option<String>,
    /// PATCHED (asc, DX-P05a): `dalvik.annotation.InnerClass` facts for
    /// this class (raw access flags + simple name when present).
    pub inner_class: Option<InnerClassReport>,
    /// PATCHED (asc, DX-P05a): `dalvik.annotation.EnclosingClass` /
    /// `dalvik.annotation.EnclosingMethod` facts for this class.
    pub enclosing: Option<EnclosingReport>,
    /// PATCHED (asc, DX-P05a): per-instance-field raw metadata (the
    /// source render already carries these; this is the lossless
    /// structured copy keyed by `field_idx`).
    pub instance_field_reports: Vec<FieldMetaReport>,
    /// PATCHED (asc, DX-P05a): per-method raw metadata including the
    /// prototype descriptor (identity is `method_idx`).
    pub method_reports: Vec<MethodMetaReport>,
}

/// PATCHED (asc, DX-P05a): annotation visibility (the annotation_item
/// visibility byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationVisibility {
    /// 0 — not visible at runtime (build-time only).
    Build,
    /// 1 — visible reflectively at runtime.
    Runtime,
    /// 2 — system (dalvik language-mapping) annotations.
    System,
}

/// PATCHED (asc, DX-P05a): what an annotation is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationTarget {
    /// The class itself.
    Class,
    /// A field, by `field_ids` index.
    Field {
        /// Which field.
        field_idx: u32,
    },
    /// A method, by `method_ids` index.
    Method {
        /// Which method.
        method_idx: u32,
    },
    /// One method parameter (annotation_set_ref_list entry).
    Parameter {
        /// Which method.
        method_idx: u32,
        /// Zero-based parameter position.
        index: u32,
    },
}

/// PATCHED (asc, A12/DECL-02): a fully-resolved, primitive-only encoded
/// value. Pool indexes (strings/types/fields/methods/protos) resolve at
/// report-build time, so no vendor pool type crosses the checked API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedValue {
    /// VALUE_NULL.
    Null,
    /// VALUE_BOOLEAN.
    Boolean(bool),
    /// VALUE_BYTE.
    Byte(i8),
    /// VALUE_SHORT.
    Short(i16),
    /// VALUE_CHAR (UTF-16 code unit).
    Char(u16),
    /// VALUE_INT.
    Int(i32),
    /// VALUE_LONG.
    Long(i64),
    /// VALUE_FLOAT as raw IEEE-754 bits - the only lossless form (DECL-01).
    FloatBits(u32),
    /// VALUE_DOUBLE as raw IEEE-754 bits - the only lossless form (DECL-01).
    DoubleBits(u64),
    /// VALUE_STRING with the string resolved from the pool.
    Text(String),
    /// VALUE_TYPE with the descriptor resolved from the pool.
    Type(String),
    /// VALUE_FIELD resolved to (declaring class, name, type descriptor).
    Field {
        /// Declaring class descriptor.
        class: String,
        /// Field name.
        name: String,
        /// Field type descriptor.
        ty: String,
    },
    /// VALUE_METHOD resolved to (declaring class, name, prototype).
    Method {
        /// Declaring class descriptor.
        class: String,
        /// Method name.
        name: String,
        /// Prototype descriptor `(params)ret`.
        proto: String,
    },
    /// VALUE_ENUM resolved to (enum class, constant name).
    Enum {
        /// Enum class descriptor.
        class: String,
        /// Constant name.
        name: String,
    },
    /// VALUE_ARRAY with each element typed recursively.
    Array(Vec<TypedValue>),
    /// VALUE_ANNOTATION with the type descriptor and named elements.
    Annotation {
        /// Annotation type descriptor.
        type_descriptor: String,
        /// Named element values.
        elements: Vec<(String, TypedValue)>,
    },
    /// VALUE_METHOD_TYPE with the prototype descriptor.
    MethodType(String),
    /// VALUE_METHOD_HANDLE as the method_handles index.
    MethodHandle(u32),
}

/// PATCHED (asc, DX-P05a): one structured annotation with lossless
/// element rendering (values render through the metadata-grade
/// encoded-value text, so Method / MethodType / MethodHandle /
/// nested-Annotation values are preserved too).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnotationReport {
    /// What the annotation is attached to.
    pub target: AnnotationTarget,
    /// Visibility byte interpretation.
    pub visibility: AnnotationVisibility,
    /// Annotation type descriptor (`Lcom/example/Foo;`).
    pub type_descriptor: String,
    /// Elements in encoded order: (name, metadata-grade value text).
    pub elements: Vec<(String, String)>,
    /// PATCHED (asc, A12): the same elements as typed values (DECL-02
    /// typed metadata); populated from the annotation encoded values.
    pub typed_elements: Vec<(String, TypedValue)>,
}

/// PATCHED (asc, DX-P05a): `dalvik.annotation.InnerClass` facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerClassReport {
    /// Raw `accessFlags` element.
    pub access_flags: u32,
    /// Simple name element, when present (anonymous classes omit it).
    pub name: Option<String>,
}

/// PATCHED (asc, DX-P05a): enclosing-class / enclosing-method facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclosingReport {
    /// Enclosing class descriptor (EnclosingClass.value or
    /// EnclosingMethod.class).
    pub class: Option<String>,
    /// Enclosing method name, when EnclosingMethod.method is a real
    /// method reference (absent for constructors/initializers).
    pub method: Option<String>,
}

/// PATCHED (asc, DX-P05a): raw instance-field metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMetaReport {
    /// `field_ids` index (identity).
    pub field_idx: u32,
    /// Field name.
    pub name: String,
    /// Field type descriptor.
    pub type_descriptor: String,
    /// Raw access flags from `class_data`.
    pub access_flags: u32,
}

/// PATCHED (asc, DX-P05a): raw method metadata with prototype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodMetaReport {
    /// `method_ids` index (identity).
    pub method_idx: u32,
    /// Method name.
    pub name: String,
    /// Raw access flags from `class_data`.
    pub access_flags: u32,
    /// Prototype rendered as `(param,param)ret` from type descriptors.
    pub prototype: String,
    /// Direct (true) vs virtual (false) list membership.
    pub is_direct: bool,
}

/// The result of [`decompile_checked`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendReport {
    /// Java-style source text. On `Completeness::Incomplete` this is
    /// still the best-effort emit (same text the legacy path produced).
    pub source: String,
    /// Completeness verdict; check before trusting `source`.
    pub completeness: Completeness,
    /// Structured diagnostics (machine code + human message).
    pub diagnostics: Vec<BackendDiagnostic>,
    /// Per-method outcomes, direct methods first, then virtual, in
    /// `class_data` order.
    pub method_outcomes: Vec<MethodOutcome>,
    /// Class-level metadata.
    pub metadata: BackendMetadata,
}

// ─────────────────────────────────────────────────────────────────────
// Internal collectors (filled by the classes.rs instrumentation)
// ─────────────────────────────────────────────────────────────────────

/// Per-method transient record filled inside `decompile_method`.
#[derive(Debug, Default)]
pub(crate) struct MethodRecord {
    /// Real (non-sentinel) unrecognized regions found in the method's
    /// statement tree.
    pub(crate) unrecognized: Vec<(u32, &'static str)>,
    /// Diagnostics collected during the method pipeline.
    pub(crate) diagnostics: Vec<BackendDiagnostic>,
}

/// Per-class accumulator threaded through `decompile_class_impl`.
#[derive(Debug, Default)]
pub(crate) struct ClassOutcome {
    /// Outcomes in emit order.
    pub(crate) method_outcomes: Vec<MethodOutcome>,
    /// Class-level diagnostics.
    pub(crate) diagnostics: Vec<BackendDiagnostic>,
    /// Static-field reports filled by `emit_fields`.
    pub(crate) static_fields: Vec<StaticFieldReport>,
}

// ─────────────────────────────────────────────────────────────────────
// ParsedDex
// ─────────────────────────────────────────────────────────────────────

/// A parsed, still-borrowing DEX view. `decompile_checked` accepts only
/// this type, guaranteeing the decompile reuses the caller's validated
/// bytes instead of re-reading input.
pub struct ParsedDex<'a> {
    pub(crate) dex: DexFile,
    pub(crate) data: &'a [u8],
    pub(crate) scope: ParseScope,
    pub(crate) fell_back_to_full: bool,
}

impl<'a> ParsedDex<'a> {
    /// The parsed DexFile (pools, class defs, tolerant-parse records).
    #[must_use]
    pub fn dex(&self) -> &DexFile {
        &self.dex
    }

    /// The scope that was requested.
    #[must_use]
    pub fn scope(&self) -> &ParseScope {
        &self.scope
    }

    /// Whether a scoped request matched no class def and the full parse
    /// ran instead (results are then full-parse-equivalent).
    #[must_use]
    pub fn scoped_fell_back_to_full(&self) -> bool {
        self.fell_back_to_full
    }

    /// Number of tolerant-parse failure records
    /// (`DexFile::parse_errors`).
    #[must_use]
    pub fn parse_error_count(&self) -> usize {
        self.dex.parse_errors.len()
    }
}

impl fmt::Debug for ParsedDex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedDex")
            .field("scope", &self.scope)
            .field("fell_back_to_full", &self.fell_back_to_full)
            .field("parse_errors", &self.dex.parse_errors.len())
            .field("class_defs", &self.dex.class_defs.len())
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Checked entries
// ─────────────────────────────────────────────────────────────────────

/// Parse a validated DEX view for analysis under explicit options,
/// budget and control.
///
/// Both scope shapes use the "decompile" parse (`parse_inner(data,
/// false, …)`): all requested class bodies, annotations, debug info;
/// emit-only tables (whole-input SHA-1 canonicality, map-driven method
/// handles / call-site ids / section-walk error channel) are skipped in
/// both because their only consumer is DEX re-emission — recorded as
/// DX-P01 note 2, identical for full and scoped so it cannot break
/// equivalence.
///
/// While this function runs the crate is in controlled mode (no env
/// reads, no stdio).
pub fn parse_for_analysis<'a>(
    view: &'a [u8],
    options: &ParseOptions,
    budget: &Budget,
    control: &Control,
) -> Result<ParsedDex<'a>, BackendError> {
    let _gate = enter_controlled();
    if let Some(cap) = budget.max_input_bytes {
        let len = u64::try_from(view.len()).unwrap_or(u64::MAX);
        if len > cap {
            return Err(BackendError::InputBudget {
                bytes: view.len(),
                cap,
            });
        }
    }
    abort_check(control, budget)?;
    let (dex, fell_back) = match &options.scope {
        ParseScope::Full => (DexFile::parse_view(view, true, None)?, false),
        ParseScope::ScopedToDescriptor { descriptor } => {
            let scoped = DexFile::parse_view(view, true, Some(descriptor.as_str()))?;
            let matched = scoped.class_defs.iter().any(|cd| {
                scoped
                    .type_descriptors
                    .get(usize::try_from(cd.class_idx.0).unwrap_or(usize::MAX))
                    .map(String::as_str)
                    == Some(descriptor.as_str())
            });
            if matched {
                (scoped, false)
            } else {
                abort_check(control, budget)?;
                (DexFile::parse_view(view, true, None)?, true)
            }
        }
    };
    abort_check(control, budget)?;
    Ok(ParsedDex {
        dex,
        data: view,
        scope: options.scope.clone(),
        fell_back_to_full: fell_back,
    })
}

/// Decompile one class by its real `class_def_idx` under explicit
/// options, budget and control, returning a structured report.
///
/// `selected_class_def_idx` indexes `parsed.dex().class_defs` directly;
/// duplicate descriptors are never re-resolved (the caller's catalog
/// identity wins). Only [`BackendError::InvalidClassDefIndex`] and
/// control/budget errors can fail before emit; method-level failures
/// land in `method_outcomes` + `Completeness::Incomplete`.
///
/// Non-preemptible phases this call passes through (full list in
/// `PATCHES.md` DX-P03): `parse_inner` section loops (incl. the
/// parallel string-pool collect), `build_trampoline_census`,
/// `parse_code_item`, `Cfg::build`, `SsaBody::build`, `infer_types`,
/// `optimize`, `structure`/`wrap_try_catch`, `r8_inversion::apply`,
/// `sugar::desugar`, `emit_method`. Checkpoints sit before/after parse,
/// before the census, between method-pipeline stages and per method.
pub fn decompile_checked(
    parsed: &ParsedDex,
    selected_class_def_idx: usize,
    emit: &EmitOptions,
    budget: &Budget,
    control: &Control,
) -> Result<BackendReport, BackendError> {
    let _gate = enter_controlled();
    abort_check(control, budget)?;
    let class_def = parsed
        .dex
        .class_defs
        .get(selected_class_def_idx)
        .ok_or(BackendError::InvalidClassDefIndex {
            index: selected_class_def_idx,
            class_defs: parsed.dex.class_defs.len(),
        })?;

    let ctx = crate::classes::RunCtx::checked(emit, budget, control);
    let mut outcome = ClassOutcome::default();
    let source = crate::classes::decompile_class_impl(
        &parsed.dex,
        parsed.data,
        class_def,
        None,
        &ctx,
        None,
        Some(&mut outcome),
    );

    if let Some(err) = abort_observed(control, budget) {
        return Err(abort_to_backend(err));
    }

    let detector_count = outcome
        .diagnostics
        .iter()
        .filter(|d| d.code == DiagnosticCode::DetectorIndeterminate)
        .count();
    let mut diagnostics = std::mem::take(&mut outcome.diagnostics);
    match (&parsed.scope, parsed.fell_back_to_full) {
        (ParseScope::Full, _) => {}
        (ParseScope::ScopedToDescriptor { .. }, true) => diagnostics.push(BackendDiagnostic {
            code: DiagnosticCode::ScopedFallbackToFull,
            message: "scoped descriptor matched no class def; the full parse ran instead"
                .to_string(),
            method_idx: None,
            field_idx: None,
        }),
        (ParseScope::ScopedToDescriptor { .. }, false) => diagnostics.push(BackendDiagnostic {
            code: DiagnosticCode::R8OriginCommentsDropped,
            message: "scoped parse cannot produce cross-class R8-origin comments (DX-P01)"
                .to_string(),
            method_idx: None,
            field_idx: None,
        }),
    }
    let parse_error_count = parsed.dex.parse_errors.len();
    let dropping_parse_errors = parsed
        .dex
        .parse_errors
        .iter()
        .filter(|p| parse_error_drops_subsection(&p.kind))
        .count();
    if parse_error_count > 0 {
        diagnostics.push(BackendDiagnostic {
            code: DiagnosticCode::ParseErrorsPresent,
            message: format!(
                "DEX carries {parse_error_count} tolerant-parse failure record(s) \
                 ({dropping_parse_errors} subsection drops; structural anomalies such as \
                 pool ordering are diagnostics only)"
            ),
            method_idx: None,
            field_idx: None,
        });
    }

    let metadata = build_metadata(parsed, class_def, selected_class_def_idx, &outcome);
    let completeness = build_completeness(&outcome, detector_count, dropping_parse_errors);
    let ClassOutcome {
        method_outcomes, ..
    } = outcome;

    Ok(BackendReport {
        source,
        completeness,
        diagnostics,
        method_outcomes,
        metadata,
    })
}

// ─────────────────────────────────────────────────────────────────────
// Report assembly helpers
// ─────────────────────────────────────────────────────────────────────

fn abort_check(control: &Control, budget: &Budget) -> Result<(), BackendError> {
    if control.is_cancelled() {
        return Err(BackendError::Cancelled);
    }
    if let Some(deadline) = budget.deadline {
        if Instant::now() >= deadline {
            return Err(BackendError::DeadlineExceeded);
        }
    }
    Ok(())
}

fn abort_observed(control: &Control, budget: &Budget) -> Option<bool> {
    if control.is_cancelled() {
        return Some(false);
    }
    if let Some(deadline) = budget.deadline {
        if Instant::now() >= deadline {
            return Some(true);
        }
    }
    None
}

fn build_metadata(
    parsed: &ParsedDex,
    class_def: &crate::ids::ClassDefItem,
    class_def_idx: usize,
    outcome: &ClassOutcome,
) -> BackendMetadata {
    let dex = &parsed.dex;
    let descriptor = dex
        .get_type_descriptor(class_def.class_idx)
        .unwrap_or("?")
        .to_string();
    let super_descriptor = class_def
        .superclass_idx
        .and_then(|idx| dex.get_type_descriptor(idx).ok())
        .map(str::to_string);
    let interfaces = if class_def.interfaces_off != 0 {
        dex.type_lists
            .get(&class_def.interfaces_off)
            .map(|list| {
                list.iter()
                    .filter_map(|tidx| dex.get_type_descriptor(*tidx).ok().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let source_file = class_def
        .source_file_idx
        .and_then(|idx| dex.get_string(idx).ok())
        .map(str::to_string);

    let (instance_field_count, method_count) = if class_def.class_data_off == 0 {
        (0, 0)
    } else {
        match crate::decode::parse_class_data(parsed.data, class_def.class_data_off) {
            Ok(cd) => (
                cd.instance_fields.len(),
                cd.direct_methods
                    .len()
                    .saturating_add(cd.virtual_methods.len()),
            ),
            Err(_) => (0, 0),
        }
    };

    // PATCHED (asc, DX-P05a): lossless metadata — annotations on every
    // target and visibility, generic signature, inner/enclosing facts,
    // per-member raw reports.
    let annotations = collect_annotation_reports(dex, class_def);
    let generic_signature = annotations
        .iter()
        .find(|a| {
            a.visibility == AnnotationVisibility::System
                && a.type_descriptor == "Ldalvik/annotation/Signature;"
        })
        .and_then(|a| {
            // The Signature `value` element renders as `{ "L..", "\n", .. }`
            // via the metadata-grade text; extract the quoted strings and
            // join them verbatim for an honest raw signature.
            let joined = a
                .elements
                .iter()
                .find(|(name, _)| name == "value")
                .map(|(_, text)| text.clone())?;
            let parts: Vec<String> = quoted_parts(&joined);
            if parts.is_empty() {
                None
            } else {
                Some(parts.concat())
            }
        });
    let inner_class = annotations.iter().find_map(|a| {
        if a.type_descriptor != "Ldalvik/annotation/InnerClass;" {
            return None;
        }
        let access_flags = a
            .elements
            .iter()
            .find(|(name, _)| name == "accessFlags")
            .and_then(|(_, text)| text.parse::<u32>().ok())
            .unwrap_or(0);
        let name = a
            .elements
            .iter()
            .find(|(name, _)| name == "name")
            .and_then(|(_, text)| unquote(text));
        Some(InnerClassReport { access_flags, name })
    });
    // EnclosingClass / EnclosingMethod facts are read from the raw
    // annotation items (not the rendered reports) so the class stays a
    // real `L…;` descriptor.
    let enclosing = {
        let find_item = |desc: &str| {
            let dir = dex.annotations.get(&class_def.annotations_off)?;
            if dir.class_annotations_off == 0 {
                return None;
            }
            let entries = dex.annotation_sets.get(&dir.class_annotations_off)?;
            for item_off in entries {
                let Some(item) = dex.annotation_items.get(item_off) else {
                    continue;
                };
                if dex.get_type_descriptor(item.annotation.type_idx).ok() == Some(desc) {
                    return Some(item.clone());
                }
            }
            None
        };
        if let Some(item) = find_item("Ldalvik/annotation/EnclosingClass;") {
            item.annotation.elements.iter().find_map(|(name_idx, v)| {
                let name = dex.get_string(*name_idx).ok()?;
                if name != "value" {
                    return None;
                }
                match v {
                    crate::annotation::EncodedValue::Type(t) => Some(EnclosingReport {
                        class: dex.get_type_descriptor(*t).ok().map(str::to_string),
                        method: None,
                    }),
                    _ => None,
                }
            })
        } else if let Some(item) = find_item("Ldalvik/annotation/EnclosingMethod;") {
            let mut class = None;
            let mut method = None;
            for (name_idx, v) in &item.annotation.elements {
                let Ok(name) = dex.get_string(*name_idx) else {
                    continue;
                };
                // (compared as strings: DexString == &str)
                if name == "class" {
                    if let crate::annotation::EncodedValue::Type(t) = v {
                        class = dex.get_type_descriptor(*t).ok().map(str::to_string);
                    }
                } else if name == "method" {
                    if let crate::annotation::EncodedValue::Method(m) = v {
                        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; m.0 bounded < dex.methods.len() by parser validation; lossless on 32+-bit platforms.")]
                        if let Some(mitem) = dex.methods.get(m.0 as usize) {
                            method = dex.get_string(mitem.name_idx).ok().map(str::to_string);
                        }
                    }
                }
            }
            Some(EnclosingReport { class, method })
        } else {
            None
        }
    };

    // Per-member raw reports from class_data (declared order).
    let mut instance_field_reports = Vec::new();
    let mut method_reports = Vec::new();
    if class_def.class_data_off != 0 {
        if let Ok(cd) = crate::decode::parse_class_data(parsed.data, class_def.class_data_off) {
            for ef in &cd.instance_fields {
                #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; field_idx.0 bounded < dex.fields.len() by parser validation of field_ids pool; lossless on 32+-bit platforms.")]
                if let Some(field) = dex.fields.get(ef.field_idx.0 as usize) {
                    instance_field_reports.push(FieldMetaReport {
                        field_idx: ef.field_idx.0,
                        name: dex.get_string(field.name_idx).unwrap_or("?").to_string(),
                        type_descriptor: dex
                            .get_type_descriptor(field.type_idx)
                            .unwrap_or("?")
                            .to_string(),
                        access_flags: ef.access_flags,
                    });
                }
            }
            for (is_direct, list) in [
                (true, &cd.direct_methods),
                (false, &cd.virtual_methods),
            ] {
                for em in list {
                    #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; method_idx.0 bounded < dex.methods.len() and proto_idx.0 < dex.protos.len() by parser validation; lossless on 32+-bit platforms.")]
                    if let Some(m) = dex.methods.get(em.method_idx.0 as usize) {
                        let name = dex.get_string(m.name_idx).unwrap_or("?").to_string();
                        let prototype = dex
                            .protos
                            .get(m.proto_idx.0 as usize)
                            .map(|p| {
                                let ret = dex
                                    .get_type_descriptor(p.return_type_idx)
                                    .unwrap_or("?");
                                let params: Vec<String> = if p.parameters_off == 0 {
                                    Vec::new()
                                } else {
                                    dex.type_lists
                                        .get(&p.parameters_off)
                                        .map(|list| {
                                            list.iter()
                                                .filter_map(|t| {
                                                    dex.get_type_descriptor(*t).ok()
                                                })
                                                .map(str::to_string)
                                                .collect()
                                        })
                                        .unwrap_or_default()
                                };
                                format!("({}){}", params.concat(), ret)
                            })
                            .unwrap_or_else(|| "?".to_string());
                        method_reports.push(MethodMetaReport {
                            method_idx: em.method_idx.0,
                            name,
                            access_flags: em.access_flags,
                            prototype,
                            is_direct,
                        });
                    }
                }
            }
        }
    }

    BackendMetadata {
        class_def_idx,
        descriptor,
        access_flags: class_def.access_flags,
        super_descriptor,
        interfaces,
        source_file,
        static_fields: outcome.static_fields.clone(),
        instance_field_count,
        method_count,
        annotations,
        generic_signature,
        inner_class,
        enclosing,
        instance_field_reports,
        method_reports,
    }
}

/// PATCHED (asc, DX-P05a): collect every annotation in the class's
/// annotation directory, all targets and visibilities, with lossless
/// element rendering.
fn collect_annotation_reports(
    dex: &crate::parser::DexFile,
    class_def: &crate::ids::ClassDefItem,
) -> Vec<AnnotationReport> {
    let mut out = Vec::new();
    let Some(dir) = dex.annotations.get(&class_def.annotations_off) else {
        return out;
    };
    let push_set = |set_off: u32, target: AnnotationTarget, out: &mut Vec<AnnotationReport>| {
        let Some(entries) = dex.annotation_sets.get(&set_off) else {
            return;
        };
        for item_off in entries {
            let Some(item) = dex.annotation_items.get(item_off) else {
                continue;
            };
            let visibility = match item.visibility {
                0 => AnnotationVisibility::Build,
                1 => AnnotationVisibility::Runtime,
                _ => AnnotationVisibility::System,
            };
            let type_descriptor = dex
                .get_type_descriptor(item.annotation.type_idx)
                .unwrap_or("?")
                .to_string();
            let mut elements = Vec::new();
            let mut typed_elements = Vec::new();
            for (name_idx, value) in &item.annotation.elements {
                elements.push((
                    dex.get_string(*name_idx).unwrap_or("?").to_string(),
                    crate::classes::encoded_value_metadata_text(dex, value),
                ));
                typed_elements.push((
                    dex.get_string(*name_idx).unwrap_or("?").to_string(),
                    crate::classes::encoded_value_to_typed(dex, value),
                ));
            }
            out.push(AnnotationReport {
                target,
                visibility,
                type_descriptor,
                elements,
                typed_elements,
            });
        }
    };
    if dir.class_annotations_off != 0 {
        push_set(
            dir.class_annotations_off,
            AnnotationTarget::Class,
            &mut out,
        );
    }
    for f in &dir.fields {
        if f.annotations_off != 0 {
            push_set(
                f.annotations_off,
                AnnotationTarget::Field {
                    field_idx: f.field_idx.0,
                },
                &mut out,
            );
        }
    }
    for m in &dir.methods {
        if m.annotations_off != 0 {
            push_set(
                m.annotations_off,
                AnnotationTarget::Method {
                    method_idx: m.method_idx.0,
                },
                &mut out,
            );
        }
    }
    for p in &dir.parameters {
        if p.annotations_off == 0 {
            continue;
        }
        let Some(refs) = dex.annotation_set_ref_lists.get(&p.annotations_off) else {
            continue;
        };
        for (index, set_off) in refs.iter().enumerate() {
            if *set_off != 0 {
                push_set(
                    *set_off,
                    AnnotationTarget::Parameter {
                        method_idx: p.method_idx.0,
                        #[allow(clippy::cast_possible_truncation, clippy::as_conversions, reason = "PROOF: index is an annotation_set_ref_list position (< 256 in practice, bounded by the decoded list length); u32 widening is exact for any DEX-representable list.")]
                        index: index as u32,
                    },
                    &mut out,
                );
            }
        }
    }
    out
}

/// Extract the quoted string parts of a metadata-grade array text
/// (`{ "Lfoo;", "…" }`) — used to reassemble the raw dalvik Signature.
/// Odd-indexed fragments of a quote-split are the quoted contents;
/// no string slicing needed (the renderer's own text is well-formed).
fn quoted_parts(text: &str) -> Vec<String> {
    text.split('"')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, chunk)| chunk.to_string())
        .collect()
}

/// Unquote a metadata-grade string value text (`"foo"` → `foo`).
fn unquote(text: &str) -> Option<String> {
    text.trim()
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .map(str::to_string)
}

/// Whether a tolerant-parse failure kind means a subsection's data was
/// dropped (annotation trees, encoded arrays, class_data, code items,
/// debug info, interface lists) — i.e. the decompiled class may be
/// missing facts — versus a structural anomaly record (pool ordering,
/// duplicate class_def rows, topology, reserved bits, unreadable
/// map_list) that leaves the selected class's facts intact. Only the
/// former counts toward `Completeness::Incomplete`; both surface as
/// the `ParseErrorsPresent` diagnostic.
fn parse_error_drops_subsection(kind: &crate::parser::ParseFailureKind) -> bool {
    use crate::parser::ParseFailureKind as K;
    matches!(
        kind,
        K::AnnotationDirectory
            | K::AnnotationSet
            | K::AnnotationSetRefList
            | K::AnnotationItem
            | K::EncodedArray
            | K::ClassData
            | K::CodeItem
            | K::DebugInfo
            | K::Interfaces
    )
}

fn build_completeness(
    outcome: &ClassOutcome,
    detector_count: usize,
    parse_error_count: usize,
) -> Completeness {
    let mut reasons: Vec<IncompleteReason> = Vec::new();
    for mo in &outcome.method_outcomes {
        match &mo.status {
            MethodStatus::Failed { .. } => reasons.push(IncompleteReason::MethodFailed {
                method_idx: mo.method_idx,
            }),
            MethodStatus::Unsupported { regions, .. } => {
                reasons.push(IncompleteReason::MethodUnsupported {
                    method_idx: mo.method_idx,
                    regions: *regions,
                });
            }
            MethodStatus::Indeterminate { .. } => {
                reasons.push(IncompleteReason::MethodIndeterminate {
                    method_idx: mo.method_idx,
                });
            }
            MethodStatus::Cancelled => reasons.push(IncompleteReason::MethodCancelled),
            MethodStatus::Emitted | MethodStatus::DeclarationOnly { .. } | MethodStatus::Suppressed { .. } => {}
        }
    }
    for field in &outcome.static_fields {
        // PATCHED (asc, DX-P04): every reason that means "an encoded
        // value the DEX carries is not reflected in the source" counts
        // as an incompleteness. `AssignedInClinit`/`R8InlinedAssignment`
        // stay intentional-only shapes that cannot carry a rendered
        // declaration initializer under javac rules — but since DX-P04
        // an encoded value present on such a field IS emitted (with the
        // final flag lowered), so neither fires for a present value.
        let dropped = matches!(
            field.drop_reason,
            Some(
                InitializerDropReason::NonFinalStatic
                    | InitializerDropReason::UnrenderableValue
                    | InitializerDropReason::TruncatedStaticValues
                    | InitializerDropReason::TypeConflict
            )
        );
        if dropped {
            reasons.push(IncompleteReason::StaticInitializerDropped {
                field_idx: field.field_idx,
            });
        }
    }
    if detector_count > 0 {
        reasons.push(IncompleteReason::DetectorIndeterminate {
            detectors: detector_count,
        });
    }
    if parse_error_count > 0 {
        reasons.push(IncompleteReason::ParseErrors {
            count: parse_error_count,
        });
    }
    if reasons.is_empty() {
        Completeness::Complete
    } else {
        Completeness::Incomplete { reasons }
    }
}
