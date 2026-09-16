//! Logical memory admission for the checked analysis entry points.
//!
//! This module deliberately models bytes owned by the backend's logical
//! containers.  It does not intercept the process allocator and it does not
//! claim to be an RSS limit.  The checked entry points reserve a structural
//! upper bound before parsing or before entering the CFG/SSA pipeline; the
//! returned RAII lease remains live until the parsed value/report is dropped.

use std::mem::size_of;
use std::sync::Arc;

use crate::analysis::BackendError;
use crate::decode::{CodeItem, PayloadData};
use crate::parser::DexFile;

/// A logical reservation held by a checked backend value.
///
/// Implementations normally wrap a host-side RAII permit.  The trait is
/// intentionally opaque: the backend only needs ownership and drop semantics.
pub trait MemoryLease: std::fmt::Debug + Send + Sync {}

/// Host-provided logical memory ledger.
///
/// `bytes` is a checked logical allocation bound, and `label` identifies the
/// admission phase. Implementations must return an owned lease; dropping it
/// releases the reservation. No global allocator hook is involved.
pub trait MemoryLedger: std::fmt::Debug + Send + Sync {
    /// Reserve `bytes` until the returned lease is dropped.
    fn reserve(
        &self,
        bytes: u64,
        label: &'static str,
    ) -> Result<Box<dyn MemoryLease>, BackendError>;
}

/// Reserve through an optional host ledger and make the returned lease
/// clonable by report internals without cloning the underlying reservation.
pub(crate) fn reserve(
    ledger: Option<&Arc<dyn MemoryLedger>>,
    bytes: u64,
    label: &'static str,
) -> Result<Option<Arc<dyn MemoryLease>>, BackendError> {
    let Some(ledger) = ledger else {
        return Ok(None);
    };
    let lease = ledger.reserve(bytes, label)?;
    Ok(Some(Arc::from(lease)))
}

fn overflow(label: &'static str) -> BackendError {
    BackendError::MemoryBoundOverflow { label }
}

fn add(total: &mut u64, value: u64, label: &'static str) -> Result<(), BackendError> {
    *total = total.checked_add(value).ok_or_else(|| overflow(label))?;
    Ok(())
}

fn mul(a: u64, b: u64, label: &'static str) -> Result<u64, BackendError> {
    a.checked_mul(b).ok_or_else(|| overflow(label))
}

fn usize_u64(value: usize, label: &'static str) -> Result<u64, BackendError> {
    u64::try_from(value).map_err(|_| overflow(label))
}

fn add_usize_count(
    total: &mut u64,
    count: usize,
    element_size: usize,
    label: &'static str,
) -> Result<(), BackendError> {
    add(
        total,
        mul(
            usize_u64(count, label)?,
            usize_u64(element_size, label)?,
            label,
        )?,
        label,
    )
}

pub(crate) fn parser_bound(data: &[u8]) -> Result<u64, BackendError> {
    crate::parser_memory::parser_bound(data)
}

/// Return the CFG/SSA working-set bound for one decoded method.
///
/// The graph terms follow the actual structural counters: `B` is bounded by
/// entry + per-instruction fall-through/branch targets + switch cases +
/// handler entries; normal edges are `2B + S`; exception edges are bounded by
/// `B * C`, where `C` is the sum of handler clauses across try regions. SSA
/// phi operands are `R * E`, and unresolved predecessor walks are bounded by
/// `uses * B`. Every byte term names the represented container element.
pub(crate) fn method_pipeline_bound(code: &CodeItem) -> Result<u64, BackendError> {
    let i = usize_u64(code.instructions.len(), "cfg_ssa.instructions")?;
    let r = u64::from(code.registers_size);
    let t = usize_u64(code.tries.len(), "cfg_ssa.tries")?;
    let mut branch_targets = 0u64;
    let mut handler_entries = 0u64;
    let mut uses = 0u64;
    for insn in &code.instructions {
        if insn.target.is_some() {
            branch_targets = branch_targets
                .checked_add(1)
                .ok_or_else(|| overflow("cfg_ssa.branch_targets"))?;
        }
        // DEX RegList is format-capped at five registers. This is the
        // classifier's maximum read vector, not a guessed multiplier.
        let reads = if matches!(
            crate::decode::insn_format(insn.op),
            crate::decode::InsnFormat::F3rc | crate::decode::InsnFormat::F4rcc
        ) {
            u64::try_from(insn.literal).unwrap_or(u64::MAX)
        } else {
            5
        };
        uses = uses
            .checked_add(reads)
            .ok_or_else(|| overflow("cfg_ssa.reads"))?;
    }
    let mut switch_cases = 0u64;
    for payload in code.payloads.values() {
        match payload {
            PayloadData::PackedSwitch { targets, .. } => {
                switch_cases = switch_cases
                    .checked_add(usize_u64(targets.len(), "cfg_ssa.switch_cases")?)
                    .ok_or_else(|| overflow("cfg_ssa.switch_cases"))?;
            }
            PayloadData::SparseSwitch { targets, .. } => {
                switch_cases = switch_cases
                    .checked_add(usize_u64(targets.len(), "cfg_ssa.switch_cases")?)
                    .ok_or_else(|| overflow("cfg_ssa.switch_cases"))?;
            }
            PayloadData::FillArrayData { .. } => {}
        }
    }
    for handler in &code.catch_handlers {
        let catch_count = usize_u64(handler.catches.len(), "cfg_ssa.handler_entries")?;
        handler_entries = handler_entries
            .checked_add(catch_count)
            .and_then(|value| value.checked_add(u64::from(handler.catch_all_addr.is_some())))
            .ok_or_else(|| overflow("cfg_ssa.handler_entries"))?;
    }
    let b = 1u64
        .checked_add(i)
        .and_then(|value| value.checked_add(branch_targets))
        .and_then(|value| value.checked_add(switch_cases))
        .and_then(|value| value.checked_add(handler_entries))
        .ok_or_else(|| overflow("cfg_ssa.blocks"))?;
    let normal_edges = b
        .checked_mul(2)
        .and_then(|value| value.checked_add(switch_cases))
        .ok_or_else(|| overflow("cfg_ssa.normal_edges"))?;
    let mut clauses = 0u64;
    for try_item in &code.tries {
        let handler = code
            .catch_handlers
            .get(try_item.handler_idx)
            .ok_or_else(|| overflow("cfg_ssa.handler_index"))?;
        clauses = clauses
            .checked_add(usize_u64(handler.catches.len(), "cfg_ssa.handler_clauses")?)
            .and_then(|value| value.checked_add(u64::from(handler.catch_all_addr.is_some())))
            .ok_or_else(|| overflow("cfg_ssa.handler_clauses"))?;
    }
    let exception_edges = b
        .checked_mul(clauses)
        .ok_or_else(|| overflow("cfg_ssa.exception_edges"))?;
    let edges = normal_edges
        .checked_add(exception_edges)
        .ok_or_else(|| overflow("cfg_ssa.edges"))?;
    let phi_count = b.checked_mul(r).ok_or_else(|| overflow("cfg_ssa.phis"))?;
    let phi_operands = r
        .checked_mul(edges)
        .ok_or_else(|| overflow("cfg_ssa.phi_operands"))?;
    let read_walks = 2u64
        .checked_mul(b)
        .ok_or_else(|| overflow("cfg_ssa.read_walks"))?;

    let mut total = 0u64;
    for (count, element, label) in [
        (b, size_of::<crate::cfg::BasicBlock>(), "cfg.blocks"),
        (
            i,
            size_of::<crate::decode::Instruction>(),
            "cfg.block_instructions",
        ),
        (edges, size_of::<crate::cfg::Edge>(), "cfg.edges"),
        (edges, size_of::<crate::cfg::BlockIdx>(), "cfg.predecessors"),
        (
            t,
            size_of::<crate::cfg::ExceptionRegion>(),
            "cfg.exception_regions",
        ),
        (
            b,
            size_of::<(u32, crate::cfg::BlockIdx)>(),
            "cfg.address_index",
        ),
        (b, size_of::<Vec<crate::cfg::Edge>>(), "cfg.edge_worklists"),
        (
            edges,
            size_of::<crate::cfg::Edge>(),
            "cfg.edge_worklist_edges",
        ),
        (
            edges,
            size_of::<(crate::cfg::BlockIdx, crate::cfg::BlockIdx)>(),
            "cfg.predecessor_worklist",
        ),
        (b, size_of::<crate::ssa::SsaBlock>(), "ssa.blocks"),
        (i, size_of::<crate::ssa::SsaInsn>(), "ssa.instructions"),
        (uses, size_of::<crate::ssa::VarId>(), "ssa.uses"),
        (phi_count, size_of::<crate::ssa::PhiNode>(), "ssa.phis"),
        (
            phi_count,
            size_of::<((crate::cfg::BlockIdx, u16), crate::ssa::VarId)>(),
            "ssa.current_def",
        ),
        (
            phi_operands,
            size_of::<(crate::cfg::BlockIdx, crate::ssa::VarId)>(),
            "ssa.phi_operands",
        ),
        (r, size_of::<crate::ssa::VarId>(), "ssa.parameters"),
        (
            phi_count,
            size_of::<(crate::ssa::VarId, crate::ssa::VarId)>(),
            "ssa.replacements",
        ),
        (
            read_walks,
            size_of::<crate::cfg::BlockIdx>(),
            "ssa.read_walks",
        ),
    ] {
        add(
            &mut total,
            mul(count, usize_u64(element, label)?, label)?,
            label,
        )?;
    }
    Ok(total)
}

/// Class methods run sequentially. Reserve their largest CFG/SSA workspace,
/// plus class-data and the DEX-wide trampoline census which coexist with it.
pub(crate) fn reserve_class_pipeline(
    ledger: Option<&Arc<dyn MemoryLedger>>,
    dex: &DexFile,
    class_index: usize,
    selected_method: Option<u32>,
) -> Result<Option<Arc<dyn MemoryLease>>, BackendError> {
    if ledger.is_none() {
        return Ok(None);
    }
    let class = &dex.class_defs[class_index];
    let mut maximum = 0;
    let mut class_bytes = 0;
    if let Some(data) = dex.class_datas.get(&class.class_data_off) {
        add_usize_count(
            &mut class_bytes,
            data.static_fields.len() + data.instance_fields.len(),
            size_of::<crate::decode::EncodedField>() * 2,
            "class fields",
        )?;
        add_usize_count(
            &mut class_bytes,
            data.direct_methods.len() + data.virtual_methods.len(),
            size_of::<crate::decode::EncodedMethod>() * 2,
            "class methods",
        )?;
        for method in data.direct_methods.iter().chain(&data.virtual_methods) {
            if selected_method.is_some_and(|selected| selected != method.method_idx.0) {
                continue;
            }
            if let Some(code) = dex.code_items.get(&method.code_off) {
                maximum = maximum.max(method_pipeline_bound(code)?);
            }
        }
    }
    add(&mut maximum, class_bytes, "class-data reparse")?;
    // TrampolineCensus owns three method/code/class-data maps, one class
    // map, and caller lists for invoke-static sites (all identities, no text).
    let declarations = dex.class_datas.values().try_fold(0usize, |sum, data| {
        sum.checked_add(data.direct_methods.len())
            .and_then(|n| n.checked_add(data.virtual_methods.len()))
            .ok_or_else(|| overflow("trampoline declarations"))
    })?;
    add_usize_count(
        &mut maximum,
        declarations,
        size_of::<(crate::ids::MethodIdx, u32)>() * 3,
        "trampoline method maps",
    )?;
    add_usize_count(
        &mut maximum,
        dex.class_defs.len(),
        size_of::<(u32, usize)>(),
        "trampoline class map",
    )?;
    add_usize_count(
        &mut maximum,
        dex.methods.len(),
        size_of::<(crate::ids::MethodIdx, Vec<crate::ids::MethodIdx>)>()
            + size_of::<crate::ids::MethodIdx>() * 4,
        "trampoline caller lists",
    )?;
    for code in dex.code_items.values() {
        let calls = code
            .instructions
            .iter()
            .filter(|instruction| {
                matches!(
                    instruction.op,
                    crate::opcodes::Opcode::InvokeStatic
                        | crate::opcodes::Opcode::InvokeStaticRange
                )
            })
            .count();
        add_usize_count(
            &mut maximum,
            calls,
            size_of::<crate::ids::MethodIdx>() * 2,
            "trampoline call sites",
        )?;
    }
    reserve(ledger, maximum, "vendor CFG/SSA")
}
