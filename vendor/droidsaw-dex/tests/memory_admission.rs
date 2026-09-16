//! Checked-path logical memory admission contracts.
//!
//! These tests use a small RAII ledger rather than an allocator hook. They
//! verify the ownership boundary that the core bridge depends on: parser
//! admission is held by `ParsedDex`, pipeline/report admission survives until
//! the report is dropped, rejected reservations leave no live lease, and a
//! cancelled request does not poison later requests using the same ledger.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use droidsaw_dex::analysis::{
    decompile_checked, parse_for_analysis, BackendError, Budget, Control, EmitOptions, MemoryLease,
    MemoryLedger, ParseOptions, ParsedDex,
};
use droidsaw_dex::DexFile;

const G02: &[u8] = include_bytes!("fixtures/g02-static-initializers.dex");
const G02_DESCRIPTOR: &str = "Lexample/Statics;";

/// A thread-safe test ledger with exact active-byte accounting. The handle is
/// cloneable only so `Budget` can hold an `Arc<dyn MemoryLedger>` while tests
/// retain access to the counters.
#[derive(Debug)]
struct LedgerState {
    limit: u64,
    active: AtomicU64,
    accepted: AtomicUsize,
    rejected: AtomicUsize,
    released: AtomicUsize,
}

#[derive(Debug, Clone)]
struct LedgerHandle {
    state: Arc<LedgerState>,
}

#[derive(Debug)]
struct StateLease {
    state: Arc<LedgerState>,
    bytes: u64,
}

impl MemoryLease for StateLease {}

impl Drop for StateLease {
    fn drop(&mut self) {
        self.state.active.fetch_sub(self.bytes, Ordering::AcqRel);
        self.state.released.fetch_add(1, Ordering::AcqRel);
    }
}

impl MemoryLedger for LedgerHandle {
    fn reserve(
        &self,
        bytes: u64,
        label: &'static str,
    ) -> Result<Box<dyn MemoryLease>, BackendError> {
        let mut current = self.state.active.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                self.state.rejected.fetch_add(1, Ordering::AcqRel);
                return Err(BackendError::MemoryBudget { bytes, label });
            };
            if next > self.state.limit {
                self.state.rejected.fetch_add(1, Ordering::AcqRel);
                return Err(BackendError::MemoryBudget { bytes, label });
            }
            match self.state.active.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.state.accepted.fetch_add(1, Ordering::AcqRel);
                    return Ok(Box::new(StateLease {
                        state: Arc::clone(&self.state),
                        bytes,
                    }));
                }
                Err(observed) => current = observed,
            }
        }
    }
}

impl LedgerHandle {
    fn new(limit: u64) -> Self {
        Self {
            state: Arc::new(LedgerState {
                limit,
                active: AtomicU64::new(0),
                accepted: AtomicUsize::new(0),
                rejected: AtomicUsize::new(0),
                released: AtomicUsize::new(0),
            }),
        }
    }

    fn active(&self) -> u64 {
        self.state.active.load(Ordering::Acquire)
    }
}

fn budget_for(ledger: &LedgerHandle) -> Budget {
    let memory: Arc<dyn MemoryLedger> = Arc::new(ledger.clone());
    Budget {
        memory: Some(memory),
        ..Budget::default()
    }
}

fn selected_class(dex: &DexFile) -> usize {
    dex.class_defs
        .iter()
        .position(|class_def| {
            dex.get_type_descriptor(class_def.class_idx).ok() == Some(G02_DESCRIPTOR)
        })
        .expect("G02 fixture class")
}

fn parse_without_ledger(data: &[u8]) -> ParsedDex<'_> {
    parse_for_analysis(
        data,
        &ParseOptions::default(),
        &Budget::default(),
        &Control::new(),
    )
    .expect("G02 fixture parses")
}

#[test]
fn parse_rejection_has_no_live_lease() {
    let ledger = LedgerHandle::new(0);
    let result = parse_for_analysis(
        G02,
        &ParseOptions::default(),
        &budget_for(&ledger),
        &Control::new(),
    );
    assert!(matches!(result, Err(BackendError::MemoryBudget { .. })));
    assert_eq!(ledger.active(), 0);
    assert_eq!(ledger.state.released.load(Ordering::Acquire), 0);
    assert!(ledger.state.rejected.load(Ordering::Acquire) >= 1);
}

#[test]
fn parsed_dex_holds_and_releases_parser_lease() {
    let ledger = LedgerHandle::new(u64::MAX);
    let parsed = parse_for_analysis(
        G02,
        &ParseOptions::default(),
        &budget_for(&ledger),
        &Control::new(),
    )
    .expect("unlimited logical ledger accepts parser bound");
    assert!(ledger.active() > 0);
    assert!(ledger.state.accepted.load(Ordering::Acquire) >= 1);

    drop(parsed);
    assert_eq!(ledger.active(), 0);
    assert_eq!(ledger.state.released.load(Ordering::Acquire), 1);
}

#[test]
fn pipeline_rejection_has_no_live_lease() {
    let parsed = parse_without_ledger(G02);
    let ledger = LedgerHandle::new(0);
    let class_idx = selected_class(parsed.dex());
    let result = decompile_checked(
        &parsed,
        class_idx,
        &EmitOptions::default(),
        &budget_for(&ledger),
        &Control::new(),
    );
    assert!(matches!(result, Err(BackendError::MemoryBudget { .. })));
    assert_eq!(ledger.active(), 0);
    assert_eq!(ledger.state.released.load(Ordering::Acquire), 0);
}

#[test]
fn cancelled_request_can_reuse_the_same_ledger() {
    let ledger = LedgerHandle::new(u64::MAX);
    let cancelled = Control::new();
    cancelled.cancel();
    let first = parse_for_analysis(
        G02,
        &ParseOptions::default(),
        &budget_for(&ledger),
        &cancelled,
    );
    assert!(matches!(first, Err(BackendError::Cancelled)));
    assert_eq!(ledger.active(), 0);

    let parsed = parse_for_analysis(
        G02,
        &ParseOptions::default(),
        &budget_for(&ledger),
        &Control::new(),
    )
    .expect("fresh request reuses ledger after cancellation");
    assert!(ledger.active() > 0);
    drop(parsed);
    assert_eq!(ledger.active(), 0);
}

#[test]
fn report_lease_survives_parsed_dex_and_equality_ignores_lease() {
    let ledger_a = LedgerHandle::new(u64::MAX);
    let budget_a = budget_for(&ledger_a);
    let parsed_a = parse_for_analysis(G02, &ParseOptions::default(), &budget_a, &Control::new())
        .expect("first parse");
    let class_idx = selected_class(parsed_a.dex());
    let report_a = decompile_checked(
        &parsed_a,
        class_idx,
        &EmitOptions::default(),
        &budget_a,
        &Control::new(),
    )
    .expect("first report");
    let active_with_both = ledger_a.active();
    assert!(active_with_both > 0);

    let ledger_b = LedgerHandle::new(u64::MAX);
    let budget_b = budget_for(&ledger_b);
    let parsed_b = parse_for_analysis(G02, &ParseOptions::default(), &budget_b, &Control::new())
        .expect("second parse");
    let report_b = decompile_checked(
        &parsed_b,
        selected_class(parsed_b.dex()),
        &EmitOptions::default(),
        &budget_b,
        &Control::new(),
    )
    .expect("second report");
    assert_eq!(report_a, report_b);

    drop(parsed_a);
    assert!(
        ledger_a.active() > 0,
        "report must retain its logical lease after ParsedDex drops"
    );
    drop(report_a);
    assert_eq!(ledger_a.active(), 0);
    drop(report_b);
    drop(parsed_b);
    assert_eq!(ledger_b.active(), 0);
}
