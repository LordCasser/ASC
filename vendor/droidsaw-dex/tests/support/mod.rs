//! Self-contained minimal DEX builder for the A05 semantics test target
//! (`asc_semantics`). Deliberately dependency-free (no root-crate
//! `tests/support`, no fixture files on disk): every test constructs
//! its DEX bytes in-process, then drives the checked API
//! (`parse_for_analysis` / `decompile_checked`).
//!
//! Coverage map (what the builder can emit):
//! - header versions 035/037/038/039/040/041 (+ arbitrary magic bytes
//!   for the cdex/odex rejection tests)
//! - sorted string/type/proto/field/method pools (pool-order clean, so
//!   reports carry no ordering diagnostics)
//! - class_data (static/instance fields, direct/virtual methods),
//!   static_values encoded arrays (incl. deliberate truncation)
//! - hand-assembled bytecode with label-based branch fixups, packed /
//!   sparse switch payloads, fill-array-data payload, try/catch
//!   handler lists
//! - debug_info state machine (param names, locals, line table)
//! - annotation directories (class / field / method / parameter,
//!   BUILD/RUNTIME/SYSTEM visibility, nested values)
//! - method_handles + call_site_ids sections (invoke-custom fixtures)
//! - Adler-32 checksum and SHA-1 signature, both computed, so the
//!   images are checksum-clean like real d8 output.
//!
//! Layout order avoids every patch-back cycle: code items are written
//! *before* class_data (so `code_off` is known when the uleb is
//! emitted), debug items before code items, call-site encoded arrays
//! before the call_site_ids table.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────
// Access flags (DEX spec table 7.1)
// ─────────────────────────────────────────────────────────────────────

pub const ACC_PUBLIC: u32 = 0x1;
pub const ACC_PRIVATE: u32 = 0x2;
pub const ACC_STATIC: u32 = 0x8;
pub const ACC_FINAL: u32 = 0x10;
pub const ACC_NATIVE: u32 = 0x100;
pub const ACC_INTERFACE: u32 = 0x200;
pub const ACC_ABSTRACT: u32 = 0x400;
pub const ACC_SYNTHETIC: u32 = 0x1000;
pub const ACC_ENUM: u32 = 0x4000;
pub const ACC_CONSTRUCTOR: u32 = 0x1_0000;

/// Annotation visibility (annotation_item visibility byte).
pub const VIS_BUILD: u8 = 0;
pub const VIS_RUNTIME: u8 = 1;
pub const VIS_SYSTEM: u8 = 2;

// ─────────────────────────────────────────────────────────────────────
// Encoded value model (shared by static_values and annotations)
// ─────────────────────────────────────────────────────────────────────

/// A source-level encoded value spec. Descriptors and names resolve
/// through the builder's pools at `build()` time.
#[derive(Clone, Debug)]
pub enum Val {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    /// Bit-exact float (full 4-byte encoding).
    FloatBits(u32),
    /// Bit-exact double (full 8-byte encoding).
    DoubleBits(u64),
    Str(String),
    Type(String),
    Field { class: String, name: String, ty: String },
    Method { class: String, name: String, ret: String, params: Vec<String> },
    MethodType { ret: String, params: Vec<String> },
    MethodHandle { kind: u16, method: String },
    Enum { class: String, name: String, ty: String },
    Array(Vec<Val>),
    /// Nested annotation value (`VALUE_ANNOTATION`).
    Ann(AnnSpec),
    Null,
    Bool(bool),
}

/// One annotation: visibility + type + name/value elements.
#[derive(Clone, Debug)]
pub struct AnnSpec {
    pub visibility: u8,
    pub type_desc: String,
    pub elements: Vec<(String, Val)>,
}

impl AnnSpec {
    pub fn new(visibility: u8, type_desc: &str) -> Self {
        Self {
            visibility,
            type_desc: type_desc.to_string(),
            elements: Vec::new(),
        }
    }

    pub fn elem(mut self, name: &str, value: Val) -> Self {
        self.elements.push((name.to_string(), value));
        self
    }
}

/// dalvik.annotation.InnerClass shape (system annotation).
pub fn inner_class_spec(access_flags: i32, name: Option<&str>) -> AnnSpec {
    let mut spec = AnnSpec::new(VIS_SYSTEM, "Ldalvik/annotation/InnerClass;");
    spec.elements
        .push(("accessFlags".to_string(), Val::Int(access_flags)));
    if let Some(n) = name {
        spec.elements
            .push(("name".to_string(), Val::Str(n.to_string())));
    }
    spec
}

/// dalvik.annotation.EnclosingClass shape.
pub fn enclosing_class_spec(class_desc: &str) -> AnnSpec {
    AnnSpec::new(VIS_SYSTEM, "Ldalvik/annotation/EnclosingClass;")
        .elem("value", Val::Type(class_desc.to_string()))
}

/// dalvik.annotation.EnclosingMethod shape (method variant).
pub fn enclosing_method_spec(class_desc: &str, method: &str) -> AnnSpec {
    AnnSpec::new(VIS_SYSTEM, "Ldalvik/annotation/EnclosingMethod;")
        .elem("class", Val::Type(class_desc.to_string()))
        .elem(
            "method",
            Val::Method {
                class: class_desc.to_string(),
                name: method.to_string(),
                ret: "V".to_string(),
                params: Vec::new(),
            },
        )
}

/// dalvik.annotation.Signature shape.
pub fn signature_spec(items: &[&str]) -> AnnSpec {
    let mut spec = AnnSpec::new(VIS_SYSTEM, "Ldalvik/annotation/Signature;");
    spec.elements.push((
        "value".to_string(),
        Val::Array(items.iter().map(|s| Val::Str(s.to_string())).collect()),
    ));
    spec
}

/// dalvik.annotation.Throws shape.
pub fn throws_spec(types: &[&str]) -> AnnSpec {
    let mut spec = AnnSpec::new(VIS_SYSTEM, "Ldalvik/annotation/Throws;");
    spec.elements.push((
        "value".to_string(),
        Val::Array(types.iter().map(|t| Val::Type(t.to_string())).collect()),
    ));
    spec
}

// ─────────────────────────────────────────────────────────────────────
// Bytecode assembler
// ─────────────────────────────────────────────────────────────────────

/// Pool kinds for index fixups (the operand word is patched after the
/// pools are sorted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolKind {
    String,
    Type,
    Field,
    Method,
    Proto,
    CallSite,
    MethodHandle,
}

#[derive(Clone, Debug)]
struct PoolFixup {
    word: usize,
    kind: PoolKind,
    key: String,
}

#[derive(Clone, Copy, Debug)]
enum BranchWidth {
    /// 10t: signed 8-bit offset in the operand byte.
    W8,
    /// 21t/22t/31t: signed 16-bit operand word.
    W16,
}

#[derive(Clone, Debug)]
struct BranchFixup {
    pc: usize,
    word: usize,
    width: BranchWidth,
    label: String,
}

#[derive(Clone)]
enum PendingPayload {
    PackedSwitch {
        first_key: i32,
        targets: Vec<String>,
        operand_word: usize,
    },
    SparseSwitch {
        keys: Vec<i32>,
        targets: Vec<String>,
        operand_word: usize,
    },
    FillArray {
        element_width: u16,
        data: Vec<u8>,
        operand_word: usize,
    },
}

/// Label-based Dalvik bytecode assembler. Branch and pool operands are
/// symbolic; `finalize` resolves branch/payload operands, the builder
/// patches pool operands.
#[derive(Default, Clone)]
pub struct Asm {
    pub words: Vec<u16>,
    labels: HashMap<String, usize>,
    pool_fixups: Vec<PoolFixup>,
    branches: Vec<BranchFixup>,
    payloads: Vec<PendingPayload>,
    finalized: bool,
}

impl Asm {
    pub fn new() -> Self {
        Self::default()
    }

    fn emit(&mut self, word: u16) {
        self.words.push(word);
    }

    fn emit_i32(&mut self, v: i32) {
        self.emit(v as u16);
        self.emit((v >> 16) as u16);
    }

    fn emit_i64(&mut self, v: i64) {
        self.emit_i32(v as i32);
        self.emit_i32((v >> 32) as i32);
    }

    fn pool_word(&mut self, kind: PoolKind, key: &str) {
        let word = self.words.len();
        self.emit(0);
        self.pool_fixups.push(PoolFixup {
            word,
            kind,
            key: key.to_string(),
        });
    }

    fn branch_operand(&mut self, label: &str, width: BranchWidth) {
        let word = self.words.len();
        self.emit(0);
        self.branches.push(BranchFixup {
            pc: word - 1,
            word,
            width,
            label: label.to_string(),
        });
    }

    /// Bind a label to the current code-unit address.
    pub fn label(&mut self, name: &str) -> &mut Self {
        let pc = self.words.len();
        self.labels.insert(name.to_string(), pc);
        self
    }

    pub fn nop(&mut self) -> &mut Self {
        self.emit(0x0000);
        self
    }

    pub fn move_reg(&mut self, dst: u16, src: u16) -> &mut Self {
        self.emit(0x01 | (dst << 8) | (src << 12));
        self
    }

    pub fn move_wide(&mut self, dst: u16, src: u16) -> &mut Self {
        self.emit(0x04 | (dst << 8) | (src << 12));
        self
    }

    pub fn move_object(&mut self, dst: u16, src: u16) -> &mut Self {
        self.emit(0x07 | (dst << 8) | (src << 12));
        self
    }

    pub fn move_result(&mut self, dst: u16) -> &mut Self {
        self.emit(0x0a | (dst << 8));
        self
    }

    pub fn move_result_wide(&mut self, dst: u16) -> &mut Self {
        self.emit(0x0b | (dst << 8));
        self
    }

    pub fn move_result_object(&mut self, dst: u16) -> &mut Self {
        self.emit(0x0c | (dst << 8));
        self
    }

    pub fn move_exception(&mut self, dst: u16) -> &mut Self {
        self.emit(0x0d | (dst << 8));
        self
    }

    pub fn return_void(&mut self) -> &mut Self {
        self.emit(0x0e);
        self
    }

    pub fn return_reg(&mut self, reg: u16) -> &mut Self {
        self.emit(0x0f | (reg << 8));
        self
    }

    pub fn return_wide(&mut self, reg: u16) -> &mut Self {
        self.emit(0x10 | (reg << 8));
        self
    }

    pub fn return_object(&mut self, reg: u16) -> &mut Self {
        self.emit(0x11 | (reg << 8));
        self
    }

    pub fn const4(&mut self, dst: u16, lit: i8) -> &mut Self {
        self.emit(0x12 | (dst << 8) | ((((lit as u8) as u16) & 0xf) << 12));
        self
    }

    pub fn const16(&mut self, dst: u16, lit: i16) -> &mut Self {
        self.emit(0x13 | (dst << 8));
        self.emit(lit as u16);
        self
    }

    pub fn const32(&mut self, dst: u16, lit: i32) -> &mut Self {
        self.emit(0x14 | (dst << 8));
        self.emit_i32(lit);
        self
    }

    pub fn const_high16(&mut self, dst: u16, lit16: u16) -> &mut Self {
        self.emit(0x15 | (dst << 8));
        self.emit(lit16);
        self
    }

    pub fn const_wide32(&mut self, dst: u16, lit: i32) -> &mut Self {
        self.emit(0x16 | (dst << 8));
        self.emit_i32(lit);
        self
    }

    pub fn const_wide64(&mut self, dst: u16, lit: i64) -> &mut Self {
        self.emit(0x18 | (dst << 8));
        self.emit_i64(lit);
        self
    }

    pub fn const_wide_high16(&mut self, dst: u16, lit16: u16) -> &mut Self {
        self.emit(0x19 | (dst << 8));
        self.emit(lit16);
        self
    }

    pub fn const_string(&mut self, dst: u16, s: &str) -> &mut Self {
        self.emit(0x1a | (dst << 8));
        self.pool_word(PoolKind::String, s);
        self
    }

    pub fn instance_of(&mut self, dst: u16, obj: u16, ty: &str) -> &mut Self {
        self.emit(0x20 | (dst << 8) | (obj << 12));
        self.pool_word(PoolKind::Type, ty);
        self
    }

    fn sfield_op(&mut self, op: u16, reg: u16, class: &str, name: &str, ty: &str) {
        self.emit(op | (reg << 8));
        self.pool_word(PoolKind::Field, &field_key(class, name, ty));
    }

    pub fn sget(&mut self, dst: u16, class: &str, name: &str, ty: &str) -> &mut Self {
        self.sfield_op(0x60, dst, class, name, ty);
        self
    }

    pub fn sget_wide(&mut self, dst: u16, class: &str, name: &str, ty: &str) -> &mut Self {
        self.sfield_op(0x61, dst, class, name, ty);
        self
    }

    pub fn sget_object(&mut self, dst: u16, class: &str, name: &str, ty: &str) -> &mut Self {
        self.sfield_op(0x62, dst, class, name, ty);
        self
    }

    pub fn sget_boolean(&mut self, dst: u16, class: &str, name: &str, ty: &str) -> &mut Self {
        self.sfield_op(0x63, dst, class, name, ty);
        self
    }

    pub fn sput(&mut self, src: u16, class: &str, name: &str, ty: &str) -> &mut Self {
        self.sfield_op(0x69, src, class, name, ty);
        self
    }

    pub fn sput_wide(&mut self, src: u16, class: &str, name: &str, ty: &str) -> &mut Self {
        self.sfield_op(0x6a, src, class, name, ty);
        self
    }

    pub fn sput_object(&mut self, src: u16, class: &str, name: &str, ty: &str) -> &mut Self {
        self.sfield_op(0x6b, src, class, name, ty);
        self
    }

    pub fn sput_boolean(&mut self, src: u16, class: &str, name: &str, ty: &str) -> &mut Self {
        self.sfield_op(0x6c, src, class, name, ty);
        self
    }

    fn ifield_op(&mut self, op: u16, a: u16, b: u16, class: &str, name: &str, ty: &str) {
        self.emit(op | (a << 8) | (b << 12));
        self.pool_word(PoolKind::Field, &field_key(class, name, ty));
    }

    pub fn iget(&mut self, dst: u16, obj: u16, class: &str, name: &str, ty: &str) -> &mut Self {
        self.ifield_op(0x52, dst, obj, class, name, ty);
        self
    }

    pub fn iget_object(
        &mut self,
        dst: u16,
        obj: u16,
        class: &str,
        name: &str,
        ty: &str,
    ) -> &mut Self {
        self.ifield_op(0x54, dst, obj, class, name, ty);
        self
    }

    pub fn iput(&mut self, src: u16, obj: u16, class: &str, name: &str, ty: &str) -> &mut Self {
        self.ifield_op(0x59, src, obj, class, name, ty);
        self
    }

    pub fn iput_object(
        &mut self,
        src: u16,
        obj: u16,
        class: &str,
        name: &str,
        ty: &str,
    ) -> &mut Self {
        self.ifield_op(0x5b, src, obj, class, name, ty);
        self
    }

    /// Generic 35c invoke. `regs` length must be ≤ 5.
    fn invoke35c(&mut self, op: u16, regs: &[u16], kind: PoolKind, key: &str) {
        assert!(regs.len() <= 5, "35c holds at most 5 registers");
        let count = regs.len() as u16;
        let op_word = self.words.len();
        self.emit(0);
        self.pool_word(kind, key);
        let g = if count == 5 { regs[4] } else { 0 };
        self.words[op_word] = op | (g << 8) | (count << 12);
        let r = |i: usize| if i < regs.len() { regs[i] } else { 0 };
        self.emit(r(0) | (r(1) << 4) | (r(2) << 8) | (r(3) << 12));
    }

    pub fn invoke_static(&mut self, method: &str, regs: &[u16]) -> &mut Self {
        self.invoke35c(0x71, regs, PoolKind::Method, method);
        self
    }

    pub fn invoke_virtual(&mut self, method: &str, regs: &[u16]) -> &mut Self {
        self.invoke35c(0x6e, regs, PoolKind::Method, method);
        self
    }

    pub fn invoke_direct(&mut self, method: &str, regs: &[u16]) -> &mut Self {
        self.invoke35c(0x70, regs, PoolKind::Method, method);
        self
    }

    pub fn invoke_interface(&mut self, method: &str, regs: &[u16]) -> &mut Self {
        self.invoke35c(0x72, regs, PoolKind::Method, method);
        self
    }

    pub fn invoke_custom(&mut self, call_site_key: &str, regs: &[u16]) -> &mut Self {
        self.invoke35c(0xfc, regs, PoolKind::CallSite, call_site_key);
        self
    }

    /// invoke-polymorphic (45cc): method + proto operands.
    pub fn invoke_polymorphic(
        &mut self,
        method: &str,
        proto: &(String, Vec<String>),
        regs: &[u16],
    ) -> &mut Self {
        assert!(regs.len() <= 5, "45cc holds at most 5 registers");
        let count = regs.len() as u16;
        let op_word = self.words.len();
        self.emit(0);
        self.pool_word(PoolKind::Method, method);
        let g = if count == 5 { regs[4] } else { 0 };
        self.words[op_word] = 0xfa | (g << 8) | (count << 12);
        let r = |i: usize| if i < regs.len() { regs[i] } else { 0 };
        self.emit(r(0) | (r(1) << 4) | (r(2) << 8) | (r(3) << 12));
        self.pool_word(PoolKind::Proto, &proto_key(&proto.0, &proto.1));
        self
    }

    /// invoke-polymorphic/range (4rcc).
    pub fn invoke_polymorphic_range(
        &mut self,
        method: &str,
        proto: &(String, Vec<String>),
        start: u16,
        count: u16,
    ) -> &mut Self {
        self.emit(0xfb | (count << 8));
        self.pool_word(PoolKind::Method, method);
        self.emit(start);
        self.pool_word(PoolKind::Proto, &proto_key(&proto.0, &proto.1));
        self
    }

    pub fn invoke_static_range(&mut self, method: &str, start: u16, count: u16) -> &mut Self {
        self.emit(0x78 | (count << 8));
        self.pool_word(PoolKind::Method, method);
        self.emit(start);
        self
    }

    pub fn invoke_virtual_range(&mut self, method: &str, start: u16, count: u16) -> &mut Self {
        self.emit(0x74 | (count << 8));
        self.pool_word(PoolKind::Method, method);
        self.emit(start);
        self
    }

    /// add-int (23x): `op vAA, vBB, vCC`.
    pub fn add_int(&mut self, dst: u16, a: u16, b: u16) -> &mut Self {
        self.emit(0x90 | (dst << 8));
        self.emit(a | (b << 8));
        self
    }

    /// mul-int (23x).
    pub fn mul_int(&mut self, dst: u16, a: u16, b: u16) -> &mut Self {
        self.emit(0x92 | (dst << 8));
        self.emit(a | (b << 8));
        self
    }

    /// add-int/2addr (12x): `op vA, vB`.
    pub fn add_int_2addr(&mut self, dst: u16, src: u16) -> &mut Self {
        self.emit(0xb0 | (dst << 8) | (src << 12));
        self
    }

    pub fn add_int_lit16(&mut self, dst: u16, src: u16, lit: i16) -> &mut Self {
        self.emit(0xd0 | (dst << 8) | (src << 12));
        self.emit(lit as u16);
        self
    }

    pub fn new_array(&mut self, dst: u16, len: u16, elem_ty: &str) -> &mut Self {
        self.emit(0x24 | (dst << 8) | (len << 12));
        self.pool_word(PoolKind::Type, elem_ty);
        self
    }

    pub fn aget(&mut self, dst: u16, arr: u16, idx: u16) -> &mut Self {
        self.emit(0x44 | (dst << 8));
        self.emit(arr | (idx << 8));
        self
    }

    pub fn aget_wide(&mut self, dst: u16, arr: u16, idx: u16) -> &mut Self {
        self.emit(0x45 | (dst << 8));
        self.emit(arr | (idx << 8));
        self
    }

    pub fn aput(&mut self, src: u16, arr: u16, idx: u16) -> &mut Self {
        self.emit(0x4b | (src << 8));
        self.emit(arr | (idx << 8));
        self
    }

    pub fn aput_wide(&mut self, src: u16, arr: u16, idx: u16) -> &mut Self {
        self.emit(0x4c | (src << 8));
        self.emit(arr | (idx << 8));
        self
    }

    pub fn array_length(&mut self, dst: u16, arr: u16) -> &mut Self {
        self.emit(0x1e | (dst << 8) | (arr << 12));
        self
    }

    pub fn fill_array_data(&mut self, reg: u16, element_width: u16, data: &[u8]) -> &mut Self {
        // PATCHED (asc, A05): the payload operand is a 32-bit code-unit
        // offset — two placeholder words, both patched in finalize().
        let operand_word = self.words.len() + 1;
        self.emit(0x26 | (reg << 8));
        self.emit(0);
        self.emit(0);
        self.payloads.push(PendingPayload::FillArray {
            element_width,
            data: data.to_vec(),
            operand_word,
        });
        self
    }

    pub fn goto(&mut self, label: &str) -> &mut Self {
        self.emit(0x28);
        self.branch_operand(label, BranchWidth::W8);
        self
    }

    pub fn goto16(&mut self, label: &str) -> &mut Self {
        self.emit(0x29);
        self.branch_operand(label, BranchWidth::W16);
        self
    }

    pub fn if_eqz(&mut self, reg: u16, label: &str) -> &mut Self {
        self.emit(0x38 | (reg << 8));
        self.branch_operand(label, BranchWidth::W16);
        self
    }

    pub fn if_nez(&mut self, reg: u16, label: &str) -> &mut Self {
        self.emit(0x39 | (reg << 8));
        self.branch_operand(label, BranchWidth::W16);
        self
    }

    pub fn if_eq(&mut self, a: u16, b: u16, label: &str) -> &mut Self {
        self.emit(0x32 | (a << 8) | (b << 12));
        self.branch_operand(label, BranchWidth::W16);
        self
    }

    pub fn if_lt(&mut self, a: u16, b: u16, label: &str) -> &mut Self {
        // PATCHED (asc, A05): if-lt is opcode 0x34 (0x35 is if-ge).
        self.emit(0x34 | (a << 8) | (b << 12));
        self.branch_operand(label, BranchWidth::W16);
        self
    }

    /// neg-int (12x unary).
    pub fn neg_int(&mut self, dst: u16, src: u16) -> &mut Self {
        self.emit(0x7b | (dst << 8) | (src << 12));
        self
    }

    pub fn if_lez(&mut self, reg: u16, label: &str) -> &mut Self {
        // PATCHED (asc, A05): if-lez is opcode 0x3d (0x3b is if-gez).
        self.emit(0x3d | (reg << 8));
        self.branch_operand(label, BranchWidth::W16);
        self
    }

    pub fn if_ge(&mut self, a: u16, b: u16, label: &str) -> &mut Self {
        // PATCHED (asc, A05): if-ge is opcode 0x35 (0x36 is if-gt).
        self.emit(0x35 | (a << 8) | (b << 12));
        self.branch_operand(label, BranchWidth::W16);
        self
    }

    /// add-long (23x, wide pair).
    pub fn add_long(&mut self, dst: u16, a: u16, b: u16) -> &mut Self {
        self.emit(0x9b | (dst << 8));
        self.emit(a | (b << 8));
        self
    }

    /// add-double (23x, wide pair).
    pub fn add_double(&mut self, dst: u16, a: u16, b: u16) -> &mut Self {
        self.emit(0xab | (dst << 8));
        self.emit(a | (b << 8));
        self
    }

    pub fn cmp_long(&mut self, dst: u16, a: u16, b: u16) -> &mut Self {
        self.emit(0xa2 | (dst << 8));
        self.emit(a | (b << 8));
        self
    }

    pub fn packed_switch(&mut self, reg: u16, first_key: i32, targets: &[&str]) -> &mut Self {
        // PATCHED (asc, A05): 32-bit payload operand - two placeholder words.
        let operand_word = self.words.len() + 1;
        self.emit(0x2b | (reg << 8));
        self.emit(0);
        self.emit(0);
        self.payloads.push(PendingPayload::PackedSwitch {
            first_key,
            targets: targets.iter().map(|s| s.to_string()).collect(),
            operand_word,
        });
        self
    }

    pub fn sparse_switch(&mut self, reg: u16, keys: &[i32], targets: &[&str]) -> &mut Self {
        // PATCHED (asc, A05): 32-bit payload operand - two placeholder words.
        let operand_word = self.words.len() + 1;
        self.emit(0x2c | (reg << 8));
        self.emit(0);
        self.emit(0);
        self.payloads.push(PendingPayload::SparseSwitch {
            keys: keys.to_vec(),
            targets: targets.iter().map(|s| s.to_string()).collect(),
            operand_word,
        });
        self
    }

    pub fn new_instance(&mut self, dst: u16, ty: &str) -> &mut Self {
        self.emit(0x22 | (dst << 8));
        self.pool_word(PoolKind::Type, ty);
        self
    }

    pub fn check_cast(&mut self, reg: u16, ty: &str) -> &mut Self {
        self.emit(0x1f | (reg << 8));
        self.pool_word(PoolKind::Type, ty);
        self
    }

    pub fn throw(&mut self, reg: u16) -> &mut Self {
        self.emit(0x27 | (reg << 8));
        self
    }

    /// Resolve labels + append payloads. Called by the builder; must be
    /// called exactly once (before pool patching).
    pub fn finalize(&mut self) {
        assert!(!self.finalized, "Asm::finalize called twice");
        self.finalized = true;
        let mut pending = std::mem::take(&mut self.payloads);
        for payload in pending.drain(..) {
            // Payloads must sit at an even code-unit address.
            if self.words.len() % 2 == 1 {
                self.emit(0x0000);
            }
            let payload_pc = self.words.len();
            match payload {
                PendingPayload::PackedSwitch {
                    first_key,
                    targets,
                    operand_word,
                } => {
                    self.emit(0x0100);
                    self.emit(targets.len() as u16);
                    self.emit_i32(first_key);
                    // PATCHED (asc, A05): packed-switch payload targets are
                    // relative to the ADDRESS OF THE SWITCH OPCODE (the
                    // insn carrying the payload reference), not the payload
                    // itself (DEX spec §packed-switch-payload).
                    let base = (operand_word - 1) as i64;
                    for t in &targets {
                        let off = self.labels[t] as i64 - base;
                        self.emit(off as u16);
                        self.emit((off >> 16) as u16);
                    }
                    let delta = payload_pc as i64 - base;
                    self.words[operand_word] = (delta as u16 as i64) as u16;
                    self.words[operand_word + 1] = ((delta >> 16) & 0xffff) as u16;
                }
                PendingPayload::SparseSwitch {
                    keys,
                    targets,
                    operand_word,
                } => {
                    self.emit(0x0200);
                    self.emit(targets.len() as u16);
                    for k in &keys {
                        self.emit_i32(*k);
                    }
                    // PATCHED (asc, A05): sparse-switch payload targets are
                    // relative to the switch opcode's address (see above).
                    let base = (operand_word - 1) as i64;
                    for t in &targets {
                        let off = self.labels[t] as i64 - base;
                        self.emit(off as u16);
                        self.emit((off >> 16) as u16);
                    }
                    let delta = payload_pc as i64 - base;
                    self.words[operand_word] = (delta as u16 as i64) as u16;
                    self.words[operand_word + 1] = ((delta >> 16) & 0xffff) as u16;
                }
                PendingPayload::FillArray {
                    element_width,
                    data,
                    operand_word,
                } => {
                    self.emit(0x0300);
                    self.emit(element_width);
                    let units = (data.len().div_ceil(element_width as usize)) as u16;
                    self.emit(units);
                    for b in &data {
                        self.emit(*b as u16);
                    }
                    if self.words.len() % 2 == 1 {
                        self.emit(0x0000);
                    }
                    // PATCHED (asc, A05): fill-array-data's payload operand
                    // is relative to the fill-array-data opcode's address
                    // (DEX spec §fill-array-data-payload), not absolute.
                    let base = (operand_word - 1) as i64;
                    let delta = payload_pc as i64 - base;
                    self.words[operand_word] = (delta as u16 as i64) as u16;
                    self.words[operand_word + 1] = ((delta >> 16) & 0xffff) as u16;
                }
            }
        }
        let branches = std::mem::take(&mut self.branches);
        for b in branches {
            // PATCHED (asc, A05): switch/fill-array-data insns register an
            // empty-label placeholder branch whose operand word is patched
            // by the payload resolution above (payload_pc), not by a
            // label offset. Skip those here instead of panicking on the
            // never-defined "" label.
            if b.label.is_empty() {
                continue;
            }
            let off = self.labels[&b.label] as i64 - b.pc as i64;
            match b.width {
                BranchWidth::W8 => self.words[b.word] = (off as i8) as u16,
                BranchWidth::W16 => self.words[b.word] = off as u16,
            }
        }
    }

    pub fn label_pc(&self, name: &str) -> u32 {
        self.labels[name] as u32
    }

    pub fn code_units(&self) -> usize {
        self.words.len()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Pool key helpers (identity before/after sorting)
// ─────────────────────────────────────────────────────────────────────

pub fn field_key(class: &str, name: &str, ty: &str) -> String {
    format!("{class}->{name}:{ty}")
}

pub fn method_key_from(desc: &str, name: &str, ret: &str, params: &[String]) -> String {
    format!("{desc}->{name}({}:{})", params.join(""), ret)
}

pub fn method_key(desc: &str, name: &str, ret: &str, params: &[&str]) -> String {
    format!(
        "{desc}->{name}({}:{})",
        params.join(""),
        ret
    )
}

fn proto_key(ret: &str, params: &[String]) -> String {
    format!("({}:{})", params.join(""), ret)
}

// ─────────────────────────────────────────────────────────────────────
// Code / debug / try specs
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct TrySpec {
    pub start: String,
    pub end: String,
    /// (exception type descriptor, handler label); None = catch-all.
    pub handlers: Vec<(Option<String>, String)>,
}

#[derive(Clone, Debug, Default)]
pub struct DebugSpec {
    pub line_start: u32,
    /// Parameter names in order (None → NO_INDEX).
    pub param_names: Vec<Option<String>>,
    pub events: Vec<DebugEvent>,
}

#[derive(Clone, Debug)]
pub enum DebugEvent {
    AdvancePc(u32),
    AdvanceLine(i32),
    StartLocal {
        reg: u16,
        name: String,
        ty: String,
    },
    StartLocalExtended {
        reg: u16,
        name: String,
        ty: String,
        sig: String,
    },
    EndLocal(u16),
    RestartLocal(u16),
    PrologueEnd,
    EpilogueBegin,
    SetFile(String),
}

#[derive(Clone, Default)]
pub struct CodeSpec {
    pub registers: u16,
    pub ins: u16,
    pub outs: u16,
    pub asm: Option<Asm>,
    pub tries: Vec<TrySpec>,
    pub debug: Option<DebugSpec>,
}

impl CodeSpec {
    pub fn new(registers: u16, ins: u16, outs: u16) -> Self {
        Self {
            registers,
            ins,
            outs,
            ..Default::default()
        }
    }

    pub fn with_asm(mut self, f: impl FnOnce(&mut Asm)) -> Self {
        let mut asm = Asm::new();
        f(&mut asm);
        self.asm = Some(asm);
        self
    }

    pub fn with_debug(mut self, debug: DebugSpec) -> Self {
        self.debug = Some(debug);
        self
    }

    pub fn with_try(mut self, start: &str, end: &str, handlers: Vec<(Option<String>, String)>) -> Self {
        self.tries.push(TrySpec {
            start: start.to_string(),
            end: end.to_string(),
            handlers,
        });
        self
    }
}

// ─────────────────────────────────────────────────────────────────────
// Class spec
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct FieldEntry {
    /// field pool key (from `DexBuilder::field`).
    pub key: String,
    pub access: u32,
}

#[derive(Clone)]
pub struct MethodEntry {
    /// method pool key (from `DexBuilder::method`).
    pub key: String,
    pub access: u32,
    pub code: Option<CodeSpec>,
}

#[derive(Default, Clone, Debug)]
pub struct AnnotationDirSpec {
    pub class: Vec<AnnSpec>,
    /// (field key, annotations)
    pub fields: Vec<(String, Vec<AnnSpec>)>,
    /// (method key, annotations)
    pub methods: Vec<(String, Vec<AnnSpec>)>,
    /// (method key, per-parameter annotation sets)
    pub params: Vec<(String, Vec<Vec<AnnSpec>>)>,
}

#[derive(Clone)]
pub struct ClassSpec {
    pub descriptor: String,
    pub access: u32,
    pub super_descriptor: Option<String>,
    pub interfaces: Vec<String>,
    pub source_file: Option<String>,
    pub static_fields: Vec<FieldEntry>,
    pub instance_fields: Vec<FieldEntry>,
    pub direct_methods: Vec<MethodEntry>,
    pub virtual_methods: Vec<MethodEntry>,
    pub static_values: Vec<Val>,
    /// Overstate the declared encoded_array size by this many entries
    /// (malformed-truncation fixtures).
    pub static_values_declared_extra: usize,
    /// Raw bytes appended after the encoded values (inside the declared
    /// count) so the tail is genuinely undecodable — a deterministic
    /// malformed-truncation shape rather than accidental padding.
    pub static_values_trailer: Vec<u8>,
    pub annotations: Option<AnnotationDirSpec>,
}

impl ClassSpec {
    pub fn new(descriptor: &str, access: u32) -> Self {
        Self {
            descriptor: descriptor.to_string(),
            access,
            super_descriptor: Some("Ljava/lang/Object;".to_string()),
            interfaces: Vec::new(),
            source_file: None,
            static_fields: Vec::new(),
            instance_fields: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
            static_values: Vec::new(),
            static_values_declared_extra: 0,
            static_values_trailer: Vec::new(),
            annotations: None,
        }
    }
}

/// LambdaMetafactory-shaped call-site spec (invoke-custom fixtures).
#[derive(Clone, Debug)]
pub struct CallSiteSpec {
    /// Bootstrap method handle (method_handle index).
    pub bootstrap_handle: usize,
    /// SAM interface method name.
    pub method_name: String,
    pub method_type: (String, Vec<String>),
}

// ─────────────────────────────────────────────────────────────────────
// Builder
// ─────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct DexBuilder {
    version: [u8; 3],
    /// Raw 8-byte magic override (cdex/odex rejection fixtures). When
    /// set, the header magic is written verbatim and version matching
    /// is expected to fail at parse time.
    magic_override: Option<[u8; 8]>,
    strings: Vec<String>,
    string_set: HashMap<String, usize>,
    types: Vec<String>,
    type_set: HashMap<String, usize>,
    protos: Vec<(String, Vec<String>)>,
    proto_set: HashMap<String, usize>,
    fields: Vec<(String, String, String)>, // key → (class, name, ty)
    field_set: HashMap<String, usize>,
    methods: Vec<(String, String, Vec<String>, String)>, // key → (class, name, params, ret)
    method_set: HashMap<String, usize>,
    method_handles: Vec<(u16, String)>, // (kind, method key)
    method_handle_set: HashMap<String, usize>,
    call_sites: Vec<CallSiteSpec>,
    call_site_set: HashMap<String, usize>,
    pub classes: Vec<ClassSpec>,
}

impl DexBuilder {
    pub fn new() -> Self {
        Self {
            version: *b"035",
            ..Default::default()
        }
    }

    pub fn set_version(&mut self, v: &[u8; 3]) -> &mut Self {
        self.version = *v;
        self
    }

    /// For raw-magic rejection fixtures: write arbitrary leading bytes.
    pub fn set_raw_magic(&mut self, magic: &[u8; 8]) -> &mut Self {
        self.version = [magic[4], magic[5], magic[6]];
        self.magic_override = Some(*magic);
        self
    }

    pub fn intern_string(&mut self, s: &str) -> usize {
        if let Some(&idx) = self.string_set.get(s) {
            return idx;
        }
        let idx = self.strings.len();
        self.strings.push(s.to_string());
        self.string_set.insert(s.to_string(), idx);
        idx
    }

    pub fn intern_type(&mut self, desc: &str) -> usize {
        self.intern_string(desc);
        if let Some(&idx) = self.type_set.get(desc) {
            return idx;
        }
        let idx = self.types.len();
        self.types.push(desc.to_string());
        self.type_set.insert(desc.to_string(), idx);
        idx
    }

    pub fn intern_proto(&mut self, ret: &str, params: &[String]) -> usize {
        self.intern_type(ret);
        for p in params {
            self.intern_type(p);
        }
        let key = proto_key(ret, params);
        if let Some(&idx) = self.proto_set.get(&key) {
            return idx;
        }
        let idx = self.protos.len();
        self.protos.push((ret.to_string(), params.to_vec()));
        self.proto_set.insert(key, idx);
        idx
    }

    pub fn field(&mut self, class: &str, name: &str, ty: &str) -> String {
        self.intern_type(class);
        self.intern_type(ty);
        self.intern_string(name);
        let key = field_key(class, name, ty);
        if self.field_set.contains_key(&key) {
            return key;
        }
        self.field_set.insert(key.clone(), self.fields.len());
        self.fields
            .push((class.to_string(), name.to_string(), ty.to_string()));
        key
    }

    pub fn method(&mut self, class: &str, name: &str, ret: &str, params: &[&str]) -> String {
        let params: Vec<String> = params.iter().map(|s| s.to_string()).collect();
        self.intern_proto(ret, &params);
        self.intern_type(class);
        self.intern_string(name);
        let key = method_key_from(class, name, ret, &params);
        if self.method_set.contains_key(&key) {
            return key;
        }
        self.method_set.insert(key.clone(), self.methods.len());
        self.methods
            .push((class.to_string(), name.to_string(), params, ret.to_string()));
        key
    }

    pub fn method_handle(&mut self, kind: u16, method_key: &str) -> usize {
        let key = format!("{kind}:{method_key}");
        if let Some(&idx) = self.method_handle_set.get(&key) {
            return idx;
        }
        let idx = self.method_handles.len();
        self.method_handles.push((kind, method_key.to_string()));
        self.method_handle_set.insert(key, idx);
        idx
    }

    pub fn call_site(&mut self, spec: CallSiteSpec) -> String {
        let key = format!("cs{}:{}", spec.bootstrap_handle, spec.method_name);
        if self.call_site_set.contains_key(&key) {
            return key;
        }
        self.call_site_set.insert(key.clone(), self.call_sites.len());
        self.call_sites.push(spec);
        key
    }

    pub fn add_class(&mut self, spec: ClassSpec) {
        self.intern_type(&spec.descriptor);
        if let Some(sup) = spec.super_descriptor.clone() {
            self.intern_type(&sup);
        }
        for i in spec.interfaces.clone() {
            self.intern_type(&i);
        }
        if let Some(sf) = spec.source_file.clone() {
            self.intern_string(&sf);
        }
        self.classes.push(spec);
    }

    /// Intern every string/type/field/method/proto referenced from
    /// specs (static_values, annotations, debug info, call sites) so
    /// the pool-sort pass sees the complete pool. Field/method handles
    /// created here are stored under their pool keys, so `write_val`
    /// resolves them.
    fn intern_spec_refs(&mut self) {
        let call_sites = self.call_sites.clone();
        for cs in &call_sites {
            self.intern_string(&cs.method_name);
            let (ret, params) = cs.method_type.clone();
            self.intern_proto(&ret, &params);
        }
        let classes = self.classes.clone();
        for class in &classes {
            self.intern_type(&class.descriptor);
            for v in &class.static_values {
                self.intern_val(v);
            }
            let anns: Vec<(String, AnnSpec)> = {
                let mut out = Vec::new();
                if let Some(dir) = &class.annotations {
                    for a in &dir.class {
                        out.push((String::new(), a.clone()));
                    }
                    for (_, sets) in &dir.fields {
                        for a in sets {
                            out.push((String::new(), a.clone()));
                        }
                    }
                    for (_, sets) in &dir.methods {
                        for a in sets {
                            out.push((String::new(), a.clone()));
                        }
                    }
                    for (_, param_sets) in &dir.params {
                        for sets in param_sets {
                            for a in sets {
                                out.push((String::new(), a.clone()));
                            }
                        }
                    }
                }
                out
            };
            for (_, ann) in anns {
                self.intern_ann(&ann);
            }
            for m in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                let Some(code) = &m.code else { continue };
                if let Some(debug) = &code.debug {
                    for n in debug.param_names.iter().flatten() {
                        self.intern_string(n);
                    }
                    for e in &debug.events {
                        match e {
                            DebugEvent::StartLocal { name, ty, .. } => {
                                self.intern_string(name);
                                self.intern_type(ty);
                            }
                            DebugEvent::StartLocalExtended { name, ty, sig, .. } => {
                                self.intern_string(name);
                                self.intern_type(ty);
                                self.intern_string(sig);
                            }
                            DebugEvent::SetFile(f) => {
                                self.intern_string(f);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    fn intern_val(&mut self, v: &Val) {
        match v {
            Val::Str(s) => {
                self.intern_string(s);
            }
            Val::Type(t) => {
                self.intern_type(t);
            }
            Val::Field { class, name, ty } | Val::Enum { class, name, ty } => {
                self.field(class, name, ty);
            }
            Val::Method { class, name, ret, params } => {
                self.method(class, name, ret, &params.iter().map(String::as_str).collect::<Vec<_>>());
            }
            Val::MethodType { ret, params } => {
                let params = params.clone();
                self.intern_proto(ret, &params);
            }
            Val::MethodHandle { kind, method } => {
                // The underlying method must already be registered by
                // the test; intern its parts defensively.
                let _ = kind;
                self.intern_string(method);
            }
            Val::Array(items) => {
                for item in items {
                    self.intern_val(item);
                }
            }
            Val::Ann(spec) => self.intern_ann(spec),
            _ => {}
        }
    }

    fn intern_ann(&mut self, spec: &AnnSpec) {
        self.intern_type(&spec.type_desc);
        for (name, value) in &spec.elements {
            self.intern_string(name);
            self.intern_val(value);
        }
    }

    /// Assemble the full DEX image.
    pub fn build(&mut self) -> Vec<u8> {
        self.intern_spec_refs();
        // proto shorty descriptors are pool strings too
        let protos = self.protos.clone();
        for (ret, params) in &protos {
            self.intern_string(&shorty_descriptor(ret, params));
        }
        // ---- sort pools to spec order -------------------------------

        // strings: UTF-16 code-unit order
        let mut string_order: Vec<usize> = (0..self.strings.len()).collect();
        string_order.sort_by(|&a, &b| {
            self.strings[a]
                .encode_utf16()
                .cmp(self.strings[b].encode_utf16())
        });
        let string_new_idx: Vec<usize> = {
            let mut map = vec![0usize; self.strings.len()];
            for (new, old) in string_order.iter().enumerate() {
                map[*old] = new;
            }
            map
        };

        // types: by descriptor string index
        let mut types_sorted: Vec<String> = self.types.clone();
        types_sorted.sort_by(|a, b| {
            string_new_idx[self.string_set[a]].cmp(&string_new_idx[self.string_set[b]])
        });
        let type_new_idx: Vec<usize> = {
            let mut map = vec![0usize; self.types.len()];
            for (new, desc) in types_sorted.iter().enumerate() {
                map[self.type_set[desc]] = new;
            }
            map
        };

        // protos: by (return type idx, params lexicographic)
        let mut protos_sorted: Vec<(String, Vec<String>)> = self.protos.clone();
        protos_sorted.sort_by(|a, b| {
            let ra = type_new_idx[self.type_set[&a.0]];
            let rb = type_new_idx[self.type_set[&b.0]];
            ra.cmp(&rb).then_with(|| {
                let pa: Vec<usize> = a.1.iter().map(|p| type_new_idx[self.type_set[p]]).collect();
                let pb: Vec<usize> = b.1.iter().map(|p| type_new_idx[self.type_set[p]]).collect();
                pa.cmp(&pb)
            })
        });
        let proto_new_idx: Vec<usize> = {
            let mut map = vec![0usize; self.protos.len()];
            for (new, (ret, params)) in protos_sorted.iter().enumerate() {
                map[self.proto_set[&proto_key(ret, params)]] = new;
            }
            map
        };

        // fields: (class, name, type)
        let mut fields_sorted: Vec<(String, String, String)> = self.fields.clone();
        fields_sorted.sort_by(|a, b| {
            let ca = type_new_idx[self.type_set[&a.0]];
            let cb = type_new_idx[self.type_set[&b.0]];
            ca.cmp(&cb)
                .then_with(|| {
                    string_new_idx[self.string_set[&a.1]]
                        .cmp(&string_new_idx[self.string_set[&b.1]])
                })
                .then_with(|| {
                    type_new_idx[self.type_set[&a.2]].cmp(&type_new_idx[self.type_set[&b.2]])
                })
        });
        let field_new_idx: Vec<usize> = {
            let mut map = vec![0usize; self.fields.len()];
            for (new, (class, name, ty)) in fields_sorted.iter().enumerate() {
                map[self.field_set[&field_key(class, name, ty)]] = new;
            }
            map
        };

        // methods: (class, name, proto)
        let mut methods_sorted: Vec<(String, String, Vec<String>, String)> = self.methods.clone();
        methods_sorted.sort_by(|a, b| {
            let ca = type_new_idx[self.type_set[&a.0]];
            let cb = type_new_idx[self.type_set[&b.0]];
            ca.cmp(&cb)
                .then_with(|| {
                    string_new_idx[self.string_set[&a.1]]
                        .cmp(&string_new_idx[self.string_set[&b.1]])
                })
                .then_with(|| {
                    proto_new_idx[self.proto_set[&proto_key(&a.3, &a.2)]]
                        .cmp(&proto_new_idx[self.proto_set[&proto_key(&b.3, &b.2)]])
                })
        });
        let method_new_idx: Vec<usize> = {
            let mut map = vec![0usize; self.methods.len()];
            for (new, (class, name, params, ret)) in methods_sorted.iter().enumerate() {
                map[self.method_set[&method_key_from(class, name, ret, params)]] = new;
            }
            map
        };

        // ---- deterministic size pre-computation ----------------------
        let string_data_offsets: Vec<u32> = {
            let mut offs = Vec::with_capacity(self.strings.len());
            let mut cur = 0u32;
            for &old in string_order.iter() {
                let s = &self.strings[old];
                offs.push(cur);
                cur += uleb_len(s.chars().count() as u32) as u32 + s.len() as u32 + 1;
            }
            offs
        };
        let n_strings = self.strings.len();
        let n_types = self.types.len();
        let n_protos = self.protos.len();
        let n_fields = self.fields.len();
        let n_methods = self.methods.len();
        let n_classes = self.classes.len();

        // proto parameter type lists (contiguous, 4-aligned start)
        let proto_param_offset: BTreeMap<String, u32> = {
            let mut map = BTreeMap::new();
            let mut cur = 0u32; // relative to the section start
            for (ret, params) in &protos_sorted {
                if params.is_empty() {
                    continue;
                }
                let key = proto_key(ret, params);
                if map.contains_key(&key) {
                    continue;
                }
                // PATCHED (asc, A05): type_list is a 4-byte-aligned structure
                // (DEX spec §type_list); every list offset must be aligned,
                // not just the section start.
                let rel = cur.div_ceil(4) * 4;
                map.insert(key, rel);
                cur = rel + 4 + 2 * params.len() as u32;
            }
            map
        };
        let proto_type_lists_size: u32 = proto_param_offset
            .iter()
            .map(|(k, off)| {
                let params_len = self.protos[self.proto_set[k]].1.len();
                off + 4 + 2 * params_len as u32
            })
            .max()
            .unwrap_or(0);

        // class interface type lists (each 4-aligned)
        let mut interface_offsets: BTreeMap<String, u32> = BTreeMap::new();
        {
            let mut cur = 0u32;
            for class in &self.classes {
                if class.interfaces.is_empty() {
                    continue;
                }
                let aligned = cur.div_ceil(4) * 4;
                interface_offsets.insert(class.descriptor.clone(), aligned);
                cur = aligned + 4 + 2 * class.interfaces.len() as u32;
            }
        }
        let iface_lists_size: u32 = interface_offsets
            .values()
            .next_back()
            .map(|last| {
                let desc = self
                    .classes
                    .iter()
                    .find(|c| interface_offsets[&c.descriptor] == *last)
                    .map(|c| c.interfaces.len())
                    .unwrap_or(0);
                last + 4 + 2 * desc as u32
            })
            .unwrap_or(0);

        // ---- write ---------------------------------------------------
        let mut out: Vec<u8> = vec![0; 0x70]; // header

        let off_string_ids = out.len();
        out.resize(out.len() + n_strings * 4, 0);
        let off_type_ids = out.len();
        out.resize(out.len() + n_types * 4, 0);
        let off_proto_ids = out.len();
        out.resize(out.len() + n_protos * 12, 0);
        let off_field_ids = out.len();
        out.resize(out.len() + n_fields * 8, 0);
        let off_method_ids = out.len();
        out.resize(out.len() + n_methods * 8, 0);
        let off_class_defs = out.len();
        out.resize(out.len() + n_classes * 32, 0);

        // type lists: proto params first, then interface lists (4-align)
        pad_to_align4(&mut out);
        let off_type_lists = out.len();
        for (_ret, params) in &protos_sorted {
            if params.is_empty() {
                continue;
            }
            // PATCHED (asc, A05): keep every type_list 4-byte aligned.
            pad_to_align4(&mut out);
            out.extend_from_slice(&(params.len() as u32).to_le_bytes());
            for p in params {
                out.extend_from_slice(&((type_new_idx[self.type_set[p]]) as u16).to_le_bytes());
            }
        }
        debug_assert_eq!(out.len() - off_type_lists, proto_type_lists_size as usize);
        for class in &self.classes {
            if class.interfaces.is_empty() {
                continue;
            }
            pad_to_align4(&mut out);
            let want = off_type_lists as u32 + interface_offsets[&class.descriptor];
            while (out.len() as u32) < want {
                out.push(0);
            }
            out.extend_from_slice(&(class.interfaces.len() as u32).to_le_bytes());
            for i in &class.interfaces {
                out.extend_from_slice(&((type_new_idx[self.type_set[i]]) as u16).to_le_bytes());
            }
        }

        // string data
        let off_string_data = out.len();
        for &old in string_order.iter() {
            let s = &self.strings[old];
            write_uleb(&mut out, s.chars().count() as u32);
            out.extend_from_slice(s.as_bytes());
            out.push(0);
        }

        // ---- pools ---------------------------------------------------
        for (new, rel) in string_data_offsets.iter().enumerate() {
            let row = off_string_ids + new * 4;
            let abs = off_string_data as u32 + rel;
            out[row..row + 4].copy_from_slice(&abs.to_le_bytes());
        }
        for (new, desc) in types_sorted.iter().enumerate() {
            let row = off_type_ids + new * 4;
            let idx = string_new_idx[self.string_set[desc]] as u32;
            out[row..row + 4].copy_from_slice(&idx.to_le_bytes());
        }
        for (new, (ret, params)) in protos_sorted.iter().enumerate() {
            let row = off_proto_ids + new * 12;
            let shorty = shorty_descriptor(ret, params);
            let shorty_idx = string_new_idx[self.string_set[&shorty]] as u32;
            out[row..row + 4].copy_from_slice(&shorty_idx.to_le_bytes());
            let ret_idx = type_new_idx[self.type_set[ret]] as u32;
            out[row + 4..row + 8].copy_from_slice(&ret_idx.to_le_bytes());
            if !params.is_empty() {
                let off = off_type_lists as u32 + proto_param_offset[&proto_key(ret, params)];
                out[row + 8..row + 12].copy_from_slice(&off.to_le_bytes());
            }
        }
        for (new, (class, name, ty)) in fields_sorted.iter().enumerate() {
            let row = off_field_ids + new * 8;
            out[row..row + 2]
                .copy_from_slice(&((type_new_idx[self.type_set[class]]) as u16).to_le_bytes());
            out[row + 2..row + 4]
                .copy_from_slice(&((type_new_idx[self.type_set[ty]]) as u16).to_le_bytes());
            out[row + 4..row + 8].copy_from_slice(
                &((string_new_idx[self.string_set[name]]) as u32).to_le_bytes(),
            );
        }
        for (new, (class, name, params, ret)) in methods_sorted.iter().enumerate() {
            let row = off_method_ids + new * 8;
            out[row..row + 2]
                .copy_from_slice(&((type_new_idx[self.type_set[class]]) as u16).to_le_bytes());
            out[row + 2..row + 4].copy_from_slice(
                &((proto_new_idx[self.proto_set[&proto_key(ret, params)]]) as u16).to_le_bytes(),
            );
            out[row + 4..row + 8].copy_from_slice(
                &((string_new_idx[self.string_set[name]]) as u32).to_le_bytes(),
            );
        }

        // ---- debug items (before code items) --------------------------
        let mut debug_offsets: HashMap<String, u32> = HashMap::new();
        for class in &self.classes {
            for m in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                let Some(code) = &m.code else { continue };
                let Some(debug) = &code.debug else { continue };
                let off = out.len() as u32;
                write_debug_item(&mut out, debug, &self.string_set, &string_new_idx, &self.type_set, &type_new_idx);
                debug_offsets.insert(m.key.clone(), off);
            }
        }

        // ---- code items (before class_data) ---------------------------
        let mut code_offsets: HashMap<String, u32> = HashMap::new();
        for class in &self.classes {
            for m in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                let Some(code) = &m.code else { continue };
                pad_to_align4(&mut out);
                let code_off = out.len() as u32;
                code_offsets.insert(m.key.clone(), code_off);

                let mut asm = code.asm.clone().unwrap_or_default();
                asm.finalize();
                let mut words = asm.words.clone();
                if !code.tries.is_empty() && words.len() % 2 == 1 {
                    words.push(0x0000); // pad insns to 4-byte boundary
                }

                // encoded_catch_handler_list (bytes built first so the
                // try items can reference handler offsets)
                let mut handler_bytes: Vec<u8> = Vec::new();
                let mut handler_offsets: Vec<u16> = Vec::new();
                // PATCHED (asc, A05): try_item.handler_off is relative to
                // the START of the encoded_catch_handler_list — i.e. it
                // includes the list's own uleb128 size prefix (DEX spec
                // §encoded_catch_handler_list; the vendored decoder
                // measures from the same base). Previously the prefix was
                // omitted, so a first-handler offset of 0 (the common
                // single-list shape d8 produces) failed decode with
                // "handler_off 0 not found".
                let handler_list_prefix_len = uleb_len(code.tries.len() as u32);
                for t in &code.tries {
                    handler_offsets.push((handler_bytes.len() + handler_list_prefix_len) as u16);
                    handler_offsets.push(handler_bytes.len() as u16);
                    let has_catch_all = t.handlers.iter().any(|(ty, _)| ty.is_none());
                    let typed: Vec<&(Option<String>, String)> =
                        t.handlers.iter().filter(|(ty, _)| ty.is_some()).collect();
                    write_sleb(
                        &mut handler_bytes,
                        if has_catch_all {
                            -(typed.len() as i32)
                        } else {
                            typed.len() as i32
                        },
                    );
                    for (ty, label) in &typed {
                        let desc = ty.clone().expect("typed handler");
                        write_uleb(
                            &mut handler_bytes,
                            type_new_idx[self.type_set[&desc]] as u32,
                        );
                        write_uleb(&mut handler_bytes, asm.label_pc(label));
                    }
                    if has_catch_all {
                        let catch_all = t
                            .handlers
                            .iter()
                            .find(|(ty, _)| ty.is_none())
                            .map(|(_, l)| l)
                            .expect("catch-all label");
                        write_uleb(&mut handler_bytes, asm.label_pc(catch_all));
                    }
                }
                let mut handlers_with_size = Vec::new();
                write_uleb(&mut handlers_with_size, code.tries.len() as u32);
                handlers_with_size.extend_from_slice(&handler_bytes);

                let debug_off = debug_offsets.get(&m.key).copied().unwrap_or(0);
                let tries_size = code.tries.len() as u16;
                out.extend_from_slice(&code.registers.to_le_bytes());
                out.extend_from_slice(&code.ins.to_le_bytes());
                out.extend_from_slice(&code.outs.to_le_bytes());
                out.extend_from_slice(&tries_size.to_le_bytes());
                out.extend_from_slice(&debug_off.to_le_bytes());
                out.extend_from_slice(&(words.len() as u32).to_le_bytes());
                for w in &words {
                    out.extend_from_slice(&w.to_le_bytes());
                }
                // pool fixups patch the raw insns bytes
                for fixup in &asm.pool_fixups {
                    let idx: u32 = match fixup.kind {
                        PoolKind::String => {
                            string_new_idx[self.string_set[&fixup.key]] as u32
                        }
                        PoolKind::Type => type_new_idx[self.type_set[&fixup.key]] as u32,
                        PoolKind::Field => {
                            field_new_idx[self.field_set[&fixup.key]] as u32
                        }
                        PoolKind::Method => {
                            method_new_idx[self.method_set[&fixup.key]] as u32
                        }
                        PoolKind::Proto => {
                            proto_new_idx[self.proto_set[&fixup.key]] as u32
                        }
                        PoolKind::CallSite => self.call_site_set[&fixup.key] as u32,
                        PoolKind::MethodHandle => {
                            self.method_handle_set[&fixup.key] as u32
                        }
                    };
                    let byte = code_off as usize + 16 + fixup.word * 2;
                    out[byte..byte + 2].copy_from_slice(&(idx as u16).to_le_bytes());
                }
                if !code.tries.is_empty() {
                    // try items first (8-byte stride), then handlers
                    for (t, hoff) in code.tries.iter().zip(handler_offsets.iter()) {
                        let start = asm.label_pc(&t.start);
                        let end = asm.label_pc(&t.end);
                        out.extend_from_slice(&start.to_le_bytes());
                        out.extend_from_slice(&((end - start) as u16).to_le_bytes());
                        out.extend_from_slice(&hoff.to_le_bytes());
                    }
                    out.extend_from_slice(&handlers_with_size);
                }
            }
        }

        // ---- static_values encoded arrays ------------------------------
        // Pair each static field with its positional encoded value and
        // sort into ascending field_idx order (d8 class_data shape) so
        // the encoded_array maps onto the class_data field order.
        let sorted_statics: Vec<Vec<(FieldEntry, Option<Val>)>> =
            self.classes.iter().map(|class| {
                let mut pairs: Vec<(FieldEntry, Option<Val>)> = class
                    .static_fields
                    .iter()
                    .cloned()
                    .zip(
                        class
                            .static_values
                            .iter()
                            .map(|v| Some(v).cloned())
                            .chain(std::iter::repeat(None)),
                    )
                    .collect();
                pairs.truncate(class.static_fields.len().max(class.static_values.len()));
                // (static_values exceeding the field count is degenerate;
                // the encoded array is clamped by the field list above.)
                pairs.sort_by_key(|(f, _)| field_new_idx[self.field_set[&f.key]]);
                pairs
            }).collect();
        let mut static_value_offsets: HashMap<usize, u32> = HashMap::new();
        for (c_i, class) in self.classes.iter().enumerate() {
            if class.static_values.is_empty() && class.static_values_declared_extra == 0 {
                continue;
            }
            let off = out.len() as u32;
            static_value_offsets.insert(c_i, off);
            let _value_count = sorted_statics[c_i].iter().filter(|(_, v)| v.is_some()).count()
                + class.static_values_declared_extra;
            write_uleb(&mut out, (class.static_values.len() + class.static_values_declared_extra) as u32);
            for (_, v) in sorted_statics[c_i].iter() {
                if let Some(v) = v {
                    write_val(
                        &mut out,
                        v,
                        &self.string_set,
                        &string_new_idx,
                        &self.type_set,
                        &type_new_idx,
                        &self.field_set,
                        &field_new_idx,
                        &self.method_set,
                        &method_new_idx,
                        &self.proto_set,
                        &proto_new_idx,
                        &self.method_handle_set,
                    );
                }
            }
            if !class.static_values_trailer.is_empty() {
                out.extend_from_slice(&class.static_values_trailer);
            }
        }

        // ---- call-site encoded arrays, then the call_site_ids table ----
        let mut call_site_encoded_offsets: Vec<u32> = Vec::new();
        for spec in &self.call_sites {
            call_site_encoded_offsets.push(out.len() as u32);
            let handle_val = Val::MethodHandle {
                kind: 0,
                method: String::new(),
            };
            // Write the bootstrap method-handle value with the real index.
            write_val_index_raw(&mut out, 0x16, spec.bootstrap_handle as u32);
            let _ = handle_val;
            let name_idx = self.string_set[&spec.method_name] as u32;
            write_val_index_raw(&mut out, 0x17, string_new_idx[name_idx as usize] as u32);
            let proto_idx = self.proto_set[&proto_key(&spec.method_type.0, &spec.method_type.1)];
            write_val_index_raw(&mut out, 0x15, proto_idx as u32);
        }
        let call_site_section_off: u32 = if self.call_sites.is_empty() {
            0
        } else {
            pad_to_align4(&mut out);
            let base = out.len() as u32;
            for off in &call_site_encoded_offsets {
                out.extend_from_slice(&off.to_le_bytes());
            }
            base
        };

        // ---- method handles table --------------------------------------
        let method_handle_section_off: u32 = if self.method_handles.is_empty() {
            0
        } else {
            pad_to_align4(&mut out);
            let base = out.len() as u32;
            for (kind, mkey) in &self.method_handles {
                let m = self.method_set[mkey];
                out.extend_from_slice(&kind.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes()); // unused
                out.extend_from_slice(&(method_new_idx[m] as u16).to_le_bytes());
            }
            base
        };

        // ---- class data items ------------------------------------------
        let mut class_data_offsets: HashMap<usize, u32> = HashMap::new();
        for (c_i, class) in self.classes.iter().enumerate() {
            if class.static_fields.is_empty()
                && class.instance_fields.is_empty()
                && class.direct_methods.is_empty()
                && class.virtual_methods.is_empty()
            {
                continue;
            }
            class_data_offsets.insert(c_i, out.len() as u32);
            // DEX class_data entries ascend by pool index (d8 shape);
            // the sorted static field order was computed above (shared
            // with the static_values pass).
            let statics = &sorted_statics[c_i];
            let mut instance_fields = class.instance_fields.clone();
            instance_fields.sort_by_key(|f| field_new_idx[self.field_set[&f.key]]);
            let mut direct_methods = class.direct_methods.clone();
            direct_methods.sort_by_key(|m| method_new_idx[self.method_set[&m.key]]);
            let mut virtual_methods = class.virtual_methods.clone();
            virtual_methods.sort_by_key(|m| method_new_idx[self.method_set[&m.key]]);

            write_uleb(&mut out, statics.len() as u32);
            write_uleb(&mut out, instance_fields.len() as u32);
            write_uleb(&mut out, direct_methods.len() as u32);
            write_uleb(&mut out, virtual_methods.len() as u32);
            let mut prev = 0usize;
            for (f, _v) in statics {
                let fidx = field_new_idx[self.field_set[&f.key]];
                write_uleb(&mut out, (fidx - prev) as u32);
                write_uleb(&mut out, f.access);
                prev = fidx;
            }
            let mut prev = 0usize;
            for f in &instance_fields {
                let fidx = field_new_idx[self.field_set[&f.key]];
                write_uleb(&mut out, (fidx - prev) as u32);
                write_uleb(&mut out, f.access);
                prev = fidx;
            }
            let mut prev = 0usize;
            for m in direct_methods.iter() {
                let midx = method_new_idx[self.method_set[&m.key]];
                write_uleb(&mut out, (midx - prev) as u32);
                write_uleb(&mut out, m.access);
                match m.code.as_ref().and_then(|_| code_offsets.get(&m.key)) {
                    Some(off) => write_uleb(&mut out, *off),
                    None => write_uleb(&mut out, 0),
                }
                prev = midx;
            }
            // PATCHED (asc, A05): the virtual_methods list restarts its
            // method_idx_diff accumulator at 0 (DEX class_data_item encodes
            // each list independently; the parser's decoder does the same).
            // Carrying prev across the direct→virtual boundary produced
            // negative diffs (subtract overflow) whenever a virtual method
            // index was below the last direct one.
            let mut prev = 0usize;
            for m in virtual_methods.iter() {
                let midx = method_new_idx[self.method_set[&m.key]];
                write_uleb(&mut out, (midx - prev) as u32);
                write_uleb(&mut out, m.access);
                match m.code.as_ref().and_then(|_| code_offsets.get(&m.key)) {
                    Some(off) => write_uleb(&mut out, *off),
                    None => write_uleb(&mut out, 0),
                }
                prev = midx;
            }
        }

        // ---- annotations -----------------------------------------------
        let mut annotation_dir_offsets: HashMap<usize, u32> = HashMap::new();
        for (c_i, class) in self.classes.iter().enumerate() {
            let Some(dir) = &class.annotations else {
                continue;
            };
            let off = write_annotation_directory(
                &mut out,
                dir,
                &self.string_set,
                &string_new_idx,
                &self.type_set,
                &type_new_idx,
                &self.field_set,
                &field_new_idx,
                &self.method_set,
                &method_new_idx,
                &self.proto_set,
                &proto_new_idx,
                &self.method_handle_set,
            );
            annotation_dir_offsets.insert(c_i, off);
        }

        // ---- class_def rows --------------------------------------------
        for (c_i, class) in self.classes.iter().enumerate() {
            let row = off_class_defs + c_i * 32;
            let class_idx = type_new_idx[self.type_set[&class.descriptor]] as u32;
            let super_idx = class
                .super_descriptor
                .as_ref()
                .map(|s| type_new_idx[self.type_set[s]] as u32)
                .unwrap_or(0xffff_ffff);
            let interfaces_off = interface_offsets
                .get(&class.descriptor)
                .map(|rel| off_type_lists as u32 + rel)
                .unwrap_or(0);
            let source_idx = class
                .source_file
                .as_ref()
                .map(|s| string_new_idx[self.string_set[s]] as u32)
                .unwrap_or(0xffff_ffff);
            let annotations_off = annotation_dir_offsets.get(&c_i).copied().unwrap_or(0);
            let class_data_off = class_data_offsets.get(&c_i).copied().unwrap_or(0);
            let static_values_off = static_value_offsets.get(&c_i).copied().unwrap_or(0);
            out[row..row + 4].copy_from_slice(&class_idx.to_le_bytes());
            out[row + 4..row + 8].copy_from_slice(&class.access.to_le_bytes());
            out[row + 8..row + 12].copy_from_slice(&super_idx.to_le_bytes());
            out[row + 12..row + 16].copy_from_slice(&interfaces_off.to_le_bytes());
            out[row + 16..row + 20].copy_from_slice(&source_idx.to_le_bytes());
            out[row + 20..row + 24].copy_from_slice(&annotations_off.to_le_bytes());
            out[row + 24..row + 28].copy_from_slice(&class_data_off.to_le_bytes());
            out[row + 28..row + 32].copy_from_slice(&static_values_off.to_le_bytes());
        }

        // ---- map list ---------------------------------------------------
        pad_to_align4(&mut out);
        let map_off = out.len() as u32;
        {
            let mut items: Vec<(u16, u32, u32)> = Vec::new();
            items.push((0x0000, 1, 0));
            if n_strings > 0 {
                items.push((0x0001, n_strings as u32, off_string_ids as u32));
            }
            if n_types > 0 {
                items.push((0x0002, n_types as u32, off_type_ids as u32));
            }
            if n_protos > 0 {
                items.push((0x0003, n_protos as u32, off_proto_ids as u32));
            }
            if n_fields > 0 {
                items.push((0x0004, n_fields as u32, off_field_ids as u32));
            }
            if n_methods > 0 {
                items.push((0x0005, n_methods as u32, off_method_ids as u32));
            }
            if n_classes > 0 {
                items.push((0x0006, n_classes as u32, off_class_defs as u32));
            }
            if call_site_section_off != 0 {
                items.push((
                    0x0007,
                    self.call_sites.len() as u32,
                    call_site_section_off,
                ));
            }
            if method_handle_section_off != 0 {
                items.push((
                    0x0008,
                    self.method_handles.len() as u32,
                    method_handle_section_off,
                ));
            }
            items.push((0x1000, 1, map_off));
            if proto_type_lists_size + iface_lists_size > 0 {
                items.push((
                    0x1001,
                    proto_param_offset.len() as u32 + interface_offsets.len() as u32,
                    off_type_lists as u32,
                ));
            }
            if !class_data_offsets.is_empty() {
                let first = class_data_offsets.values().copied().min().unwrap();
                items.push((0x2000, class_data_offsets.len() as u32, first));
            }
            if !code_offsets.is_empty() {
                let first = code_offsets.values().copied().min().unwrap();
                items.push((0x2001, code_offsets.len() as u32, first));
            }
            if n_strings > 0 {
                items.push((0x2002, n_strings as u32, off_string_data as u32));
            }
            if !debug_offsets.is_empty() {
                let first = debug_offsets.values().copied().min().unwrap();
                items.push((0x2003, debug_offsets.len() as u32, first));
            }
            if !static_value_offsets.is_empty() {
                let first = static_value_offsets.values().copied().min().unwrap();
                items.push((0x2005, static_value_offsets.len() as u32, first));
            }
            if !annotation_dir_offsets.is_empty() {
                let first = annotation_dir_offsets.values().copied().min().unwrap();
                items.push((0x2006, annotation_dir_offsets.len() as u32, first));
            }
            items.sort_by_key(|(_, _, off)| *off);
            out.extend_from_slice(&(items.len() as u32).to_le_bytes());
            for (ty, size, off) in items {
                out.extend_from_slice(&ty.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes());
                out.extend_from_slice(&size.to_le_bytes());
                out.extend_from_slice(&off.to_le_bytes());
            }
        }

        // ---- header + checksums ------------------------------------------
        let file_size = out.len() as u32;
        let magic: [u8; 8] = self.magic_override.unwrap_or([
            b'd', b'e', b'x', b'\n', self.version[0], self.version[1], self.version[2], 0,
        ]);
        out[0..8].copy_from_slice(&magic);
        out[32..36].copy_from_slice(&file_size.to_le_bytes());
        out[36..40].copy_from_slice(&0x70u32.to_le_bytes());
        out[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        out[44..48].copy_from_slice(&0u32.to_le_bytes()); // link_size
        out[48..52].copy_from_slice(&0u32.to_le_bytes()); // link_off
        out[52..56].copy_from_slice(&map_off.to_le_bytes());
        out[56..60].copy_from_slice(&(n_strings as u32).to_le_bytes());
        out[60..64].copy_from_slice(&(off_string_ids as u32).to_le_bytes());
        out[64..68].copy_from_slice(&(n_types as u32).to_le_bytes());
        out[68..72].copy_from_slice(&(off_type_ids as u32).to_le_bytes());
        out[72..76].copy_from_slice(&(n_protos as u32).to_le_bytes());
        out[76..80].copy_from_slice(&(off_proto_ids as u32).to_le_bytes());
        out[80..84].copy_from_slice(&(n_fields as u32).to_le_bytes());
        out[84..88].copy_from_slice(&(off_field_ids as u32).to_le_bytes());
        out[88..92].copy_from_slice(&(n_methods as u32).to_le_bytes());
        out[92..96].copy_from_slice(&(off_method_ids as u32).to_le_bytes());
        out[96..100].copy_from_slice(&(n_classes as u32).to_le_bytes());
        out[100..104].copy_from_slice(&(off_class_defs as u32).to_le_bytes());
        out[104..108].copy_from_slice(&(file_size - off_string_data as u32).to_le_bytes());
        out[108..112].copy_from_slice(&(off_string_data as u32).to_le_bytes());

        let sha = sha1(&out[32..]);
        out[12..32].copy_from_slice(&sha);
        let adler = adler32(&out[12..]);
        out[8..12].copy_from_slice(&adler.to_le_bytes());
        out
    }
}

// magic override field is part of the struct above; no extra impl needed.

// ─────────────────────────────────────────────────────────────────────
// value / annotation / debug writers
// ─────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn write_val(
    out: &mut Vec<u8>,
    v: &Val,
    string_set: &HashMap<String, usize>,
    string_new_idx: &[usize],
    type_set: &HashMap<String, usize>,
    type_new_idx: &[usize],
    field_set: &HashMap<String, usize>,
    field_new_idx: &[usize],
    method_set: &HashMap<String, usize>,
    method_new_idx: &[usize],
    proto_set: &HashMap<String, usize>,
    proto_new_idx: &[usize],
    method_handle_set: &HashMap<String, usize>,
) {
    match v {
        Val::Byte(x) => write_val_int(out, 0x00, *x as i32 as u32, 1),
        Val::Short(x) => write_val_int(out, 0x02, *x as i32 as u32, width_for_i16(*x)),
        Val::Char(x) => write_val_int(out, 0x03, u32::from(*x), width_for_u16(*x)),
        Val::Int(x) => write_val_int(out, 0x04, *x as u32, width_for_i32(*x)),
        Val::Long(x) => {
            let width = width_for_i64(*x);
            out.push(0x06 | ((width as u8 - 1) << 5));
            let bytes = x.to_le_bytes();
            out.extend_from_slice(&bytes[..width]);
        }
        Val::FloatBits(bits) => {
            out.push(0x10 | (3 << 5));
            out.extend_from_slice(&bits.to_le_bytes());
        }
        Val::DoubleBits(bits) => {
            out.push(0x11 | (7 << 5));
            out.extend_from_slice(&bits.to_le_bytes());
        }
        Val::Str(s) => write_val_index_raw(
            out,
            0x17,
            string_new_idx[string_set[s]] as u32,
        ),
        Val::Type(t) => write_val_index_raw(out, 0x18, type_new_idx[type_set[t]] as u32),
        Val::Field { class, name, ty } => write_val_index_raw(
            out,
            0x19,
            field_new_idx[field_set[&field_key(class, name, ty)]] as u32,
        ),
        Val::Method { class, name, ret, params } => write_val_index_raw(
            out,
            0x1a,
            method_new_idx[method_set[&method_key_from(class, name, ret, params)]] as u32,
        ),
        Val::MethodType { ret, params } => write_val_index_raw(
            out,
            0x15,
            proto_new_idx[proto_set[&proto_key(ret, params)]] as u32,
        ),
        Val::MethodHandle { kind, method } => {
            let idx = method_handle_set[&format!("{kind}:{method}")];
            write_val_index_raw(out, 0x16, idx as u32);
        }
        Val::Enum { class, name, ty } => write_val_index_raw(
            out,
            0x1b,
            field_new_idx[field_set[&field_key(class, name, ty)]] as u32,
        ),
        Val::Array(items) => {
            out.push(0x1c);
            write_uleb(out, items.len() as u32);
            for item in items {
                write_val(
                    out,
                    item,
                    string_set,
                    string_new_idx,
                    type_set,
                    type_new_idx,
                    field_set,
                    field_new_idx,
                    method_set,
                    method_new_idx,
                    proto_set,
                    proto_new_idx,
                    method_handle_set,
                );
            }
        }
        Val::Ann(spec) => {
            write_annotation_body(
                out,
                spec,
                string_set,
                string_new_idx,
                type_set,
                type_new_idx,
                field_set,
                field_new_idx,
                method_set,
                method_new_idx,
                proto_set,
                proto_new_idx,
                method_handle_set,
            );
        }
        Val::Null => out.push(0x1e),
        Val::Bool(b) => out.push(0x1f | (u8::from(*b) << 5)),
    }
}

/// `VALUE_ANNOTATION` body — called after the visibility byte or as a
/// nested value; emits the 0x1d header itself.
#[allow(clippy::too_many_arguments)]
fn write_annotation_body(
    out: &mut Vec<u8>,
    spec: &AnnSpec,
    string_set: &HashMap<String, usize>,
    string_new_idx: &[usize],
    type_set: &HashMap<String, usize>,
    type_new_idx: &[usize],
    field_set: &HashMap<String, usize>,
    field_new_idx: &[usize],
    method_set: &HashMap<String, usize>,
    method_new_idx: &[usize],
    proto_set: &HashMap<String, usize>,
    proto_new_idx: &[usize],
    method_handle_set: &HashMap<String, usize>,
) {
    out.push(0x1d);
    write_encoded_annotation_body(
        out,
        spec,
        string_set,
        string_new_idx,
        type_set,
        type_new_idx,
        field_set,
        field_new_idx,
        method_set,
        method_new_idx,
        proto_set,
        proto_new_idx,
        method_handle_set,
    );
}

/// encoded_annotation body: `type_idx || size || (name_idx, value)*` —
/// no 0x1d prefix (shared by VALUE_ANNOTATION and annotation_item).
#[allow(clippy::too_many_arguments)]
fn write_encoded_annotation_body(
    out: &mut Vec<u8>,
    spec: &AnnSpec,
    string_set: &HashMap<String, usize>,
    string_new_idx: &[usize],
    type_set: &HashMap<String, usize>,
    type_new_idx: &[usize],
    field_set: &HashMap<String, usize>,
    field_new_idx: &[usize],
    method_set: &HashMap<String, usize>,
    method_new_idx: &[usize],
    proto_set: &HashMap<String, usize>,
    proto_new_idx: &[usize],
    method_handle_set: &HashMap<String, usize>,
) {
    write_uleb(out, type_new_idx[type_set[&spec.type_desc]] as u32);
    write_uleb(out, spec.elements.len() as u32);
    for (name, value) in &spec.elements {
        write_uleb(out, string_new_idx[string_set[name]] as u32);
        write_val(
            out,
            value,
            string_set,
            string_new_idx,
            type_set,
            type_new_idx,
            field_set,
            field_new_idx,
            method_set,
            method_new_idx,
            proto_set,
            proto_new_idx,
            method_handle_set,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn write_annotation_directory(
    out: &mut Vec<u8>,
    dir: &AnnotationDirSpec,
    string_set: &HashMap<String, usize>,
    string_new_idx: &[usize],
    type_set: &HashMap<String, usize>,
    type_new_idx: &[usize],
    field_set: &HashMap<String, usize>,
    field_new_idx: &[usize],
    method_set: &HashMap<String, usize>,
    method_new_idx: &[usize],
    proto_set: &HashMap<String, usize>,
    proto_new_idx: &[usize],
    method_handle_set: &HashMap<String, usize>,
) -> u32 {
    fn write_ann_item(
        out: &mut Vec<u8>,
        spec: &AnnSpec,
        sa: &HashMap<String, usize>,
        sn: &[usize],
        ta: &HashMap<String, usize>,
        tn: &[usize],
        fa: &HashMap<String, usize>,
        fni: &[usize],
        ma: &HashMap<String, usize>,
        mn: &[usize],
        pa: &HashMap<String, usize>,
        pn: &[usize],
        ha: &HashMap<String, usize>,
    ) -> u32 {
        // annotation_item = visibility byte || encoded_annotation body.
        // The body has NO 0x1d VALUE_ANNOTATION header byte — that
        // prefix only exists on free-standing encoded_value positions.
        let off = out.len() as u32;
        out.push(spec.visibility);
        write_encoded_annotation_body(out, spec, sa, sn, ta, tn, fa, fni, ma, mn, pa, pn, ha);
        off
    }
    fn write_ann_set(
        out: &mut Vec<u8>,
        origin: u32,
        specs: &[AnnSpec],
        sa: &HashMap<String, usize>,
        sn: &[usize],
        ta: &HashMap<String, usize>,
        tn: &[usize],
        fa: &HashMap<String, usize>,
        fni: &[usize],
        ma: &HashMap<String, usize>,
        mn: &[usize],
        pa: &HashMap<String, usize>,
        pn: &[usize],
        ha: &HashMap<String, usize>,
    ) -> u32 {
        // Spec layout: [u32 size][size × u32 item offsets][items...].
        // Items are built in a temp first so the offsets array comes
        // directly after the size word.
        pad_to_align4(out);
        let set_off = out.len() as u32;
        let mut items = Vec::new();
        let mut offs = Vec::new();
        for spec in specs {
            offs.push(write_ann_item(
                &mut items, spec, sa, sn, ta, tn, fa, fni, ma, mn, pa, pn, ha,
            ));
        }
        out.extend_from_slice(&(specs.len() as u32).to_le_bytes());
        let header = 4u32 + 4 * specs.len() as u32;
        for off in &offs {
            // item offsets are absolute image offsets: origin positions
            // this buffer's zero inside the final image
            out.extend_from_slice(&(origin + set_off + header + off).to_le_bytes());
        }
        out.extend_from_slice(&items);
        set_off
    }

    // Build the annotation sets / ref lists in a scratch buffer first,
    // then emit the directory header followed by the scratch bytes —
    // so `dir_off` points at the header (spec layout). The scratch is
    // pre-grown to the header+rows length so every offset the writers
    // compute inside it is already an absolute image offset.
    let rows_len = 8
        * (dir.fields.len() + dir.methods.len() + dir.params.len());
    #[allow(clippy::cast_possible_truncation, clippy::as_conversions, reason = "PROOF: image offsets are bounded by the DEX u32 file_size envelope; usize→u32 is exact for any builder-produced image.")]
    let base = (out.len().div_ceil(4) * 4 + 16 + rows_len) as u32;
    let mut scratch: Vec<u8> = vec![0u8; base as usize];
    let class_set_rel = if dir.class.is_empty() {
        0
    } else {
        write_ann_set(&mut scratch, 0, &dir.class, string_set, string_new_idx, type_set, type_new_idx, field_set, field_new_idx, method_set, method_new_idx, proto_set, proto_new_idx, method_handle_set)
    };
    let mut field_rows: Vec<(u32, u32)> = Vec::new();
    for (key, specs) in &dir.fields {
        let fidx = field_new_idx[field_set[key]] as u32;
        let rel = write_ann_set(&mut scratch, 0, specs, string_set, string_new_idx, type_set, type_new_idx, field_set, field_new_idx, method_set, method_new_idx, proto_set, proto_new_idx, method_handle_set);
        field_rows.push((fidx, rel));
    }
    let mut method_rows: Vec<(u32, u32)> = Vec::new();
    for (key, specs) in &dir.methods {
        let midx = method_new_idx[method_set[key]] as u32;
        let rel = write_ann_set(&mut scratch, 0, specs, string_set, string_new_idx, type_set, type_new_idx, field_set, field_new_idx, method_set, method_new_idx, proto_set, proto_new_idx, method_handle_set);
        method_rows.push((midx, rel));
    }
    let mut param_rows: Vec<(u32, Vec<u32>)> = Vec::new();
    for (key, param_sets) in &dir.params {
        let midx = method_new_idx[method_set[key]] as u32;
        // annotation_set_ref_list = [u32 size][size × u32 set offsets],
        // sets following the offsets array (same shape as
        // annotation_set_item). Build the sets in a temp first so the
        // offsets land directly after the size word.
        pad_to_align4(&mut scratch);
        let ref_rel = scratch.len() as u32;
        scratch.extend_from_slice(&(param_sets.len() as u32).to_le_bytes());
        let mut sets_bytes = Vec::new();
        let mut offs = Vec::new();
        // the sets land after the entry words; their absolute origin is
        // the current scratch end plus the entry table
        let sets_origin = scratch.len() as u32 + 4 * param_sets.len() as u32;
        for specs in param_sets {
            offs.push(write_ann_set(&mut sets_bytes, sets_origin, specs, string_set, string_new_idx, type_set, type_new_idx, field_set, field_new_idx, method_set, method_new_idx, proto_set, proto_new_idx, method_handle_set));
        }
        for off in &offs {
            scratch.extend_from_slice(&(sets_origin + off).to_le_bytes());
        }
        scratch.extend_from_slice(&sets_bytes);
        param_rows.push((midx, vec![ref_rel]));
    }

    pad_to_align4(out);
    let dir_off = out.len() as u32;
    debug_assert_eq!(base, dir_off + 16u32 + (rows_len as u32));
    let class_set_off = class_set_rel;
    out.extend_from_slice(&class_set_off.to_le_bytes());
    out.extend_from_slice(&(field_rows.len() as u32).to_le_bytes());
    out.extend_from_slice(&(method_rows.len() as u32).to_le_bytes());
    out.extend_from_slice(&(param_rows.len() as u32).to_le_bytes());
    for (fidx, off) in &field_rows {
        out.extend_from_slice(&fidx.to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
    }
    for (midx, off) in &method_rows {
        out.extend_from_slice(&midx.to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
    }
    for (midx, refs) in &param_rows {
        out.extend_from_slice(&midx.to_le_bytes());
        for off in refs {
            out.extend_from_slice(&off.to_le_bytes());
        }
    }
    // append the scratch body (skip the pre-grown offset base)
    out.extend_from_slice(&scratch[base as usize..]);
    dir_off
}

fn write_debug_item(
    out: &mut Vec<u8>,
    debug: &DebugSpec,
    string_set: &HashMap<String, usize>,
    string_new_idx: &[usize],
    type_set: &HashMap<String, usize>,
    type_new_idx: &[usize],
) {
    write_uleb(out, debug.line_start);
    write_uleb(out, debug.param_names.len() as u32);
    for name in &debug.param_names {
        match name {
            Some(n) => write_uleb(out, (string_new_idx[string_set[n]] + 1) as u32),
            None => write_uleb(out, 0), // NO_INDEX encoded as uleb128p1 0
        }
    }
    for event in &debug.events {
        match event {
            DebugEvent::AdvancePc(delta) => {
                out.push(0x01);
                write_uleb(out, *delta);
            }
            DebugEvent::AdvanceLine(delta) => {
                out.push(0x02);
                write_sleb(out, *delta);
            }
            DebugEvent::StartLocal { reg, name, ty } => {
                out.push(0x03);
                write_uleb(out, u32::from(*reg));
                write_uleb(out, (string_new_idx[string_set[name]] + 1) as u32);
                write_uleb(out, type_new_idx[type_set[ty]] as u32);
                write_uleb(out, 0); // signature: NO_INDEX
            }
            DebugEvent::StartLocalExtended { reg, name, ty, sig } => {
                out.push(0x04);
                write_uleb(out, u32::from(*reg));
                write_uleb(out, (string_new_idx[string_set[name]] + 1) as u32);
                write_uleb(out, type_new_idx[type_set[ty]] as u32);
                write_uleb(out, (string_new_idx[string_set[sig]] + 1) as u32);
            }
            DebugEvent::EndLocal(reg) => {
                out.push(0x05);
                write_uleb(out, u32::from(*reg));
            }
            DebugEvent::RestartLocal(reg) => {
                out.push(0x06);
                write_uleb(out, u32::from(*reg));
            }
            DebugEvent::PrologueEnd => out.push(0x07),
            DebugEvent::EpilogueBegin => out.push(0x08),
            DebugEvent::SetFile(name) => {
                out.push(0x09);
                write_uleb(out, (string_new_idx[string_set[name]] + 1) as u32);
            }
        }
    }
    out.push(0x00); // DBG_END_SEQUENCE
}

// ─────────────────────────────────────────────────────────────────────
// Byte-level helpers
// ─────────────────────────────────────────────────────────────────────

pub fn write_uleb(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

pub fn write_sleb(out: &mut Vec<u8>, mut v: i32) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        let done = (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

pub fn uleb_len(v: u32) -> usize {
    let mut len = 1;
    let mut v = v >> 7;
    while v != 0 {
        len += 1;
        v >>= 7;
    }
    len
}

fn pad_to_align4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn width_for_i16(v: i16) -> usize {
    if (-128..=127).contains(&v) {
        1
    } else {
        2
    }
}

fn width_for_u16(v: u16) -> usize {
    if v <= 0x7f {
        1
    } else {
        2
    }
}

fn width_for_i32(v: i32) -> usize {
    if (-128..=127).contains(&v) {
        1
    } else if (-32768..=32767).contains(&v) {
        2
    } else {
        4
    }
}

fn width_for_i64(v: i64) -> usize {
    let bytes = v.to_le_bytes();
    let negative = v < 0;
    for width in 1..=8usize {
        let rest = &bytes[width..];
        let rest_ok = rest.iter().all(|&b| if negative { b == 0xff } else { b == 0 });
        let top = bytes[width - 1];
        let top_ok = if negative {
            top & 0x80 != 0
        } else {
            top & 0x80 == 0
        };
        if rest_ok && top_ok {
            return width;
        }
    }
    8
}

/// Write a sized signed int value with `width` payload bytes
/// (two's-complement low bytes; the parser reads exactly this many).
fn write_val_int(out: &mut Vec<u8>, tag: u8, value: u32, width: usize) {
    out.push(tag | ((width as u8 - 1) << 5));
    let bytes = value.to_le_bytes();
    out.extend_from_slice(&bytes[..width]);
}

/// Index-typed encoded value: minimal-width little-endian index.
fn write_val_index_raw(out: &mut Vec<u8>, tag: u8, index: u32) {
    let width = uleb_len(index);
    out.push(tag | ((width as u8 - 1) << 5));
    let bytes = index.to_le_bytes();
    out.extend_from_slice(&bytes[..width]);
}

fn shorty_descriptor(ret: &str, params: &[String]) -> String {
    let shorty_char = |d: &str| -> char {
        match d {
            "Z" => 'Z',
            "B" => 'B',
            "S" => 'S',
            "C" => 'C',
            "I" => 'I',
            "J" => 'J',
            "F" => 'F',
            "D" => 'D',
            "V" => 'V',
            _ => 'L',
        }
    };
    let mut s = String::new();
    s.push(shorty_char(ret));
    for p in params {
        s.push(shorty_char(p));
    }
    s
}

pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

/// Minimal SHA-1 (fixture-grade; matches FIPS 180-1).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
