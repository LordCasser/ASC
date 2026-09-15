//! Deterministic regressions for the embedded `asc_core::Engine` boundary.
//!
//! These tests deliberately use only the public Engine/model/query surface.
//! The byte fixtures are committed contract inputs; the small stored-entry
//! archive builder below is the same ZIP shape as `tests/support/apk.rs`, with
//! enough entries to exercise whole-archive scope contracts.

use asc_core::bytes::OperationControl;
use asc_core::engine::{Engine, EngineOptions, InputKind, Limits};
use asc_core::error::{CancelCause, ErrorKind};
use asc_core::model::{ClassFilter, DiagnosticCode, PatternLimits};
use asc_core::query::{self, MatchMode};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

const G01_DEX: &[u8] =
    include_bytes!("../../../tests/fixtures/contracts/inputs/g01-regex-string.dex");
const G02_DEX: &[u8] =
    include_bytes!("../../../tests/fixtures/contracts/inputs/g02-static-initializers.dex");
const G02_APK: &[u8] =
    include_bytes!("../../../tests/fixtures/contracts/inputs/g02-static-initializers.apk");

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Build a deterministic stored-entry ZIP containing the selected root DEXes.
fn apk_with_dexes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    const VERSION: u16 = 20;
    const DOS_TIME: u16 = 0;
    const DOS_DATE: u16 = 0x21;

    let mut local = Vec::new();
    let mut central = Vec::new();
    for (name, payload) in entries {
        let name = name.as_bytes();
        let crc = crc32(payload);
        let offset = local.len() as u32;
        let size = payload.len() as u32;

        local.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut local, VERSION);
        push_u16(&mut local, 0);
        push_u16(&mut local, 0);
        push_u16(&mut local, DOS_TIME);
        push_u16(&mut local, DOS_DATE);
        push_u32(&mut local, crc);
        push_u32(&mut local, size);
        push_u32(&mut local, size);
        push_u16(&mut local, name.len() as u16);
        push_u16(&mut local, 0);
        local.extend_from_slice(name);
        local.extend_from_slice(payload);

        central.extend_from_slice(b"PK\x01\x02");
        push_u16(&mut central, VERSION);
        push_u16(&mut central, VERSION);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, DOS_TIME);
        push_u16(&mut central, DOS_DATE);
        push_u32(&mut central, crc);
        push_u32(&mut central, size);
        push_u32(&mut central, size);
        push_u16(&mut central, name.len() as u16);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, offset);
        central.extend_from_slice(name);
    }

    let central_offset = local.len() as u32;
    let central_size = central.len() as u32;
    let mut output = local;
    output.extend_from_slice(&central);
    output.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut output, 0);
    push_u16(&mut output, 0);
    push_u16(&mut output, entries.len() as u16);
    push_u16(&mut output, entries.len() as u16);
    push_u32(&mut output, central_size);
    push_u32(&mut output, central_offset);
    push_u16(&mut output, 0);
    output
}

fn engine_with_limits(limits: Limits) -> Engine {
    Engine::new(EngineOptions {
        limits,
        threads: Some(2),
    })
    .expect("one-worker engine")
}

fn open_apk(engine: &Engine, bytes: &[u8]) -> asc_core::engine::Artifact {
    engine
        .open_bytes(
            Arc::from(bytes.to_vec().into_boxed_slice()),
            InputKind::Apk,
            &OperationControl::new(),
        )
        .expect("open APK")
}

fn open_dex(engine: &Engine, bytes: &[u8]) -> asc_core::engine::Artifact {
    engine
        .open_bytes(
            Arc::from(bytes.to_vec().into_boxed_slice()),
            InputKind::Dex,
            &OperationControl::new(),
        )
        .expect("open raw DEX")
}

fn assert_kind(error: &asc_core::Error, expected: ErrorKind) {
    assert_eq!(*error.kind(), expected, "unexpected error: {error}");
}

fn assert_cancel(error: &asc_core::Error, cause: CancelCause) {
    assert_kind(error, ErrorKind::Cancelled { cause });
}

#[test]
fn default_engine_uses_the_public_open_and_scan_contract() {
    let engine = Engine::new(EngineOptions::default()).expect("default engine");
    let artifact = open_dex(&engine, G02_DEX);
    let report = engine
        .classes(&artifact, &ClassFilter::none(), &OperationControl::new())
        .expect("scan classes");
    assert_eq!(report.value().len(), 1);
    assert_eq!(report.value()[0].descriptor().as_str(), "Lexample/Statics;");
}

#[test]
fn cancelled_open_bytes_is_observed_before_apk_or_raw_dex_parse() {
    let cancel = Arc::new(AtomicBool::new(true));
    let control = OperationControl::new().with_cancel_flag(Arc::clone(&cancel));
    let engine = Engine::new(EngineOptions::default()).expect("engine");

    let apk_error = engine
        .open_bytes(Arc::from(G02_APK), InputKind::Apk, &control)
        .err()
        .expect("cancelled APK must not open");
    assert_cancel(&apk_error, CancelCause::User);

    let dex_error = engine
        .open_bytes(Arc::from(G02_DEX), InputKind::Dex, &control)
        .err()
        .expect("cancelled raw DEX must not open");
    assert_cancel(&dex_error, CancelCause::User);

    let expired = OperationControl::new().with_deadline(Instant::now() - Duration::from_secs(1));
    let deadline_error = engine
        .open_bytes(Arc::from(G02_APK), InputKind::Apk, &expired)
        .err()
        .expect("expired APK deadline must not open");
    assert_cancel(&deadline_error, CancelCause::Deadline);

    let deadline_dex_error = engine
        .open_bytes(Arc::from(G02_DEX), InputKind::Dex, &expired)
        .err()
        .expect("expired raw DEX deadline must not open");
    assert_cancel(&deadline_dex_error, CancelCause::Deadline);
}

#[test]
fn duplicate_g02_dexes_report_duplicate_class_definition() {
    let apk = apk_with_dexes(&[("classes.dex", G02_DEX), ("classes2.dex", G02_DEX)]);
    let engine = Engine::new(EngineOptions::default()).expect("engine");
    let artifact = open_apk(&engine, &apk);
    let report = engine
        .classes(&artifact, &ClassFilter::none(), &OperationControl::new())
        .expect("classes");

    assert_eq!(report.value().len(), 2);
    assert_eq!(
        report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code() == DiagnosticCode::DuplicateClassDefinition)
            .count(),
        1,
        "duplicate descriptor should have one aggregate diagnostic"
    );
}

#[cfg(feature = "decompile")]
mod decompile_regressions {
    use super::*;
    use asc_core::model::{ClassSelector, Source};

    fn selector() -> ClassSelector {
        ClassSelector::Descriptor(
            query::exact_descriptor("Lexample/Statics;").expect("G02 descriptor"),
            None,
        )
    }

    fn assert_bad_scope(apk: Vec<u8>) {
        let engine = Engine::new(EngineOptions::default()).expect("engine");
        let artifact = open_apk(&engine, &apk);
        let error = engine
            .decompile(&artifact, &selector(), &OperationControl::new())
            .expect_err("every selected DEX must be validated");
        assert_kind(&error, ErrorKind::MalformedInput);
    }

    #[test]
    fn broken_dex_after_selected_class_is_malformed_in_both_orders() {
        let mut broken = G02_DEX.to_vec();
        broken[..8].fill(0);
        assert_bad_scope(apk_with_dexes(&[
            ("classes.dex", G02_DEX),
            ("classes2.dex", &broken),
        ]));
        assert_bad_scope(apk_with_dexes(&[
            ("classes.dex", &broken),
            ("classes2.dex", G02_DEX),
        ]));
    }

    #[test]
    fn exact_decoded_budget_allows_complete_duplicate_scope_decompile() {
        let mut limits = Limits::default();
        limits.max_total_decoded_bytes = (G02_DEX.len() as u64) * 2;
        let engine = engine_with_limits(limits);
        let apk = apk_with_dexes(&[("classes.dex", G02_DEX), ("classes2.dex", G02_DEX)]);
        let artifact = open_apk(&engine, &apk);
        let report: asc_core::model::Report<Source> = engine
            .decompile(&artifact, &selector(), &OperationControl::new())
            .expect("each selected entry is charged exactly once");
        assert!(report.value().text().contains("SECOND = 22"));
        assert_eq!(report.value().class().id().dex().entry_ordinal(), 0);
        assert_eq!(
            report
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code() == DiagnosticCode::DuplicateClassDefinition)
                .count(),
            1,
            "duplicate descriptor should be diagnosed once during decompile"
        );
    }
}

#[test]
fn classes_budget_is_combined_across_dexes_and_engine_remains_reusable() {
    let apk = apk_with_dexes(&[("classes.dex", G01_DEX), ("classes2.dex", G01_DEX)]);
    let mut limits = Limits::default();
    limits.scan.max_result_items = 1;
    let engine = engine_with_limits(limits);
    let artifact = open_apk(&engine, &apk);
    let error = engine
        .classes(&artifact, &ClassFilter::none(), &OperationControl::new())
        .expect_err("two class rows must exceed the combined item ceiling");
    assert_kind(&error, ErrorKind::ResourceLimit);

    let query = query::string_query("absent", MatchMode::Literal, &PatternLimits::default())
        .expect("string query");
    let report = engine
        .references(&artifact, &query, &OperationControl::new())
        .expect("admission must be reusable after ResourceLimit");
    assert!(report.value().is_empty());
}

#[test]
fn references_item_budget_is_combined_across_dexes_and_reusable_after_failure() {
    let apk = apk_with_dexes(&[("classes.dex", G01_DEX), ("classes2.dex", G01_DEX)]);
    let mut limits = Limits::default();
    limits.scan.max_result_items = 1;
    limits.scan.max_reference_locations = 2;
    let engine = engine_with_limits(limits);
    let artifact = open_apk(&engine, &apk);
    let query = query::string_query("token", MatchMode::Literal, &PatternLimits::default())
        .expect("const-string query");
    let error = engine
        .references(&artifact, &query, &OperationControl::new())
        .expect_err("two reference rows must exceed the combined item ceiling");
    assert_kind(&error, ErrorKind::ResourceLimit);

    let report = engine
        .references(
            &artifact,
            &query::string_query("absent", MatchMode::Literal, &PatternLimits::default())
                .expect("no-hit query"),
            &OperationControl::new(),
        )
        .expect("admission must be reusable after ResourceLimit");
    assert!(report.value().is_empty());
}

#[test]
fn reference_locations_budget_is_combined_across_dexes() {
    let apk = apk_with_dexes(&[("classes.dex", G01_DEX), ("classes2.dex", G01_DEX)]);
    let mut limits = Limits::default();
    limits.scan.max_result_items = 8;
    limits.scan.max_reference_locations = 2;
    let engine = engine_with_limits(limits);
    let artifact = open_apk(&engine, &apk);
    let query = query::string_query("tok", MatchMode::Literal, &PatternLimits::default())
        .expect("const-string query");
    let error = engine
        .references(&artifact, &query, &OperationControl::new())
        .expect_err("four locations must exceed the combined location ceiling");
    assert_kind(&error, ErrorKind::ResourceLimit);
}

#[test]
fn out_of_range_standard_data_offsets_return_errors_without_panicking() {
    let engine = Engine::new(EngineOptions::default()).unwrap();
    let control = OperationControl::new();
    for offset in [G02_DEX.len() as u32 + 1, u32::MAX] {
        let mut broken = G02_DEX.to_vec();
        broken[0x6c..0x70].copy_from_slice(&offset.to_le_bytes());
        let raw = engine.open_bytes(Arc::from(broken.clone()), InputKind::Dex, &control).unwrap();
        let error = engine.classes(&raw, &ClassFilter::none(), &control).unwrap_err();
        assert_kind(&error, ErrorKind::MalformedInput);
        let apk = apk_with_dexes(&[("classes.dex", &broken)]);
        let artifact = open_apk(&engine, &apk);
        let error = engine.classes(&artifact, &ClassFilter::none(), &control).unwrap_err();
        assert_kind(&error, ErrorKind::MalformedInput);
    }
    let artifact = engine.open_bytes(Arc::from(G02_DEX), InputKind::Dex, &control).unwrap();
    assert!(!engine.classes(&artifact, &ClassFilter::none(), &control).unwrap().value().is_empty());
}
