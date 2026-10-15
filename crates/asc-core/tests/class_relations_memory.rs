//! Independent allocation regression for the A20 folded-result capacity peak.
//! This is a deterministic fixture check, not an RSS/hard-heap guarantee.
#[path = "../../../tests/fixtures/contracts/class_relations/mod.rs"]
mod fixture;
mod support;
use asc_core::engine::Limits;
use asc_core::error::ErrorKind;
use asc_core::{ClassRelationKind, Engine, EngineOptions, InputKind, OperationControl};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct MeasuredAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn add(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
}
// SAFETY: all allocation/deallocation operations delegate unchanged to System;
// the extra atomics only observe requested sizes and never access allocations.
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            add(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            add(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            System.dealloc(ptr, layout);
        }
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(ptr, layout, size) };
        if !next.is_null() {
            if size >= layout.size() {
                add(size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed);
            }
        }
        next
    }
}
#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

#[test]
fn aliased_interface_fanout_is_rejected_before_unaccounted_vector_growth() {
    const LIMIT: u64 = 42_000_000;
    let engine = Engine::new(EngineOptions {
        limits: Limits {
            max_engine_owned_bytes: LIMIT,
            ..Limits::default()
        },
        threads: Some(1),
    })
    .unwrap();
    let input: Arc<[u8]> = Arc::from(fixture::alias_type_fanout(32_769));
    let artifact = engine
        .open_bytes(input, InputKind::Dex, &OperationControl::new())
        .unwrap();
    let query = asc_core::query::class_relation_query(
        ClassRelationKind::Implements,
        "A",
        &Default::default(),
    )
    .unwrap();
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let error = engine
        .class_relations(&artifact, &query, &OperationControl::new())
        .unwrap_err();
    assert_eq!(*error.kind(), ErrorKind::ResourceLimit);
    let peak_growth = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    assert!(
        peak_growth < LIMIT as usize,
        "aliased interface result grew by {peak_growth} bytes before rejection (ledger limit {LIMIT})"
    );
    let absent = asc_core::query::class_relation_query(
        ClassRelationKind::Implements,
        "Missing",
        &Default::default(),
    )
    .unwrap();
    assert!(
        engine
            .class_relations(&artifact, &absent, &OperationControl::new())
            .unwrap()
            .value()
            .is_empty()
    );
}
