//! A20 public, default-feature relation contracts over byte-authored fixtures.
#[path = "../../../tests/fixtures/contracts/class_relations/mod.rs"]
mod fixture;
mod support;

use asc_core::engine::Limits;
use asc_core::error::{CancelCause, ErrorKind};
use asc_core::model::{ClassFilter, MethodScope, PatternLimits, TargetKind};
use asc_core::query::class_relation_query;
use asc_core::{ClassRelationKind as Kind, Engine, EngineOptions, InputKind, OperationControl};
use fixture::{dex, read32, write32};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

fn engine() -> Engine {
    Engine::new(EngineOptions::default()).unwrap()
}
fn open(engine: &Engine, bytes: &[u8], kind: InputKind) -> asc_core::engine::Artifact {
    engine
        .open_bytes(Arc::from(bytes), kind, &OperationControl::new())
        .unwrap()
}
fn query(kind: Kind, target: &str) -> asc_core::ClassRelationQuery {
    class_relation_query(kind, target, &PatternLimits::default()).unwrap()
}
fn sources(engine: &Engine, bytes: &[u8], kind: Kind, target: &str) -> Vec<u32> {
    let artifact = open(engine, bytes, InputKind::Dex);
    engine
        .class_relations(&artifact, &query(kind, target), &OperationControl::new())
        .unwrap()
        .value()
        .iter()
        .map(|r| r.class().id().class_def_idx())
        .collect()
}

#[test]
fn direct_only_external_target_and_interface_inheritance() {
    let bytes = dex(
        &["LA;", "LB;", "LC;", "LI;", "LJ;"],
        &[
            (0, 1, vec![3]),
            (1, 2, vec![]),
            (2, u32::MAX, vec![]),
            (4, u32::MAX, vec![3]),
        ],
    );
    let e = engine();
    assert_eq!(sources(&e, &bytes, Kind::Extends, "B"), [0]);
    assert_eq!(sources(&e, &bytes, Kind::Extends, "C"), [1]);
    assert_eq!(sources(&e, &bytes, Kind::Implements, "I"), [0, 3]);
    assert!(sources(&e, &bytes, Kind::Extends, "I").is_empty());
    assert!(sources(&e, &bytes, Kind::Implements, "Absent").is_empty());
}

#[test]
fn duplicate_definitions_and_type_rows_are_not_descriptor_deduplicated() {
    let bytes = dex(
        &["LA;", "LI;", "LI;"],
        &[(0, u32::MAX, vec![2, 1, 2]), (0, u32::MAX, vec![1])],
    );
    let e = engine();
    let a = open(&e, &bytes, InputKind::Dex);
    let report = e
        .class_relations(
            &a,
            &query(Kind::Implements, "LI;"),
            &OperationControl::new(),
        )
        .unwrap();
    let identities = report
        .value()
        .iter()
        .map(|r| (r.class().id().class_def_idx(), r.target_id().table_index()))
        .collect::<Vec<_>>();
    assert_eq!(identities, [(0, 1), (0, 2), (1, 1)]);
    assert!(
        report
            .value()
            .iter()
            .all(|r| r.target_id().kind() == TargetKind::Type
                && r.target_id().dex() == r.class().id().dex())
    );
    drop(a);
    assert_eq!(report.value()[0].target().as_str().unwrap(), "LI;");
}

#[test]
fn unicode_exact_normalization_and_utf16_order() {
    // UTF-16 orders U+10000 before U+E000; scalar order is the reverse.
    let bytes = dex(
        &["Lpkg/\u{10000};", "Lpkg/\u{e000};", "Lpkg/Parent;"],
        &[(0, 2, vec![1]), (1, 2, vec![0])],
    );
    let e = engine();
    assert_eq!(sources(&e, &bytes, Kind::Implements, "pkg.\u{10000}"), [1]);
    assert_eq!(sources(&e, &bytes, Kind::Implements, "Lpkg/\u{e000};"), [0]);
    assert!(sources(&e, &bytes, Kind::Implements, "Parent").is_empty());
    let a = open(&e, &bytes, InputKind::Dex);
    let classes = e
        .classes(&a, &ClassFilter::none(), &OperationControl::new())
        .unwrap();
    assert_eq!(classes.value()[0].descriptor().as_str(), "Lpkg/\u{10000};");
    assert_eq!(classes.value()[1].descriptor().as_str(), "Lpkg/\u{e000};");
}

#[test]
fn malformed_declarations_fail_even_when_query_matches_nothing() {
    let good = dex(&["LA;", "LI;"], &[(0, 1, vec![1])]);
    let defs = read32(&good, 0x64) as usize;
    let list = read32(&good, defs + 12) as usize;
    let e = engine();
    for (at, value) in [
        (defs + 8, 100),
        (defs + 12, 1),
        (defs + 12, 0x2c),
        (defs + 12, read32(&good, 0x3c)),
        (defs + 12, read32(&good, 0x34)),
        (defs + 12, u32::MAX - 3),
        (list, 100),
        (list + 4, 100),
    ] {
        let mut bad = good.clone();
        write32(&mut bad, at, value);
        fixture::finish_integrity(&mut bad);
        let a = open(&e, &bad, InputKind::Dex);
        let err = e
            .class_relations(
                &a,
                &query(Kind::Extends, "Missing"),
                &OperationControl::new(),
            )
            .unwrap_err();
        assert_eq!(*err.kind(), ErrorKind::MalformedInput, "at {at}: {err}");
    }
    assert_eq!(sources(&e, &good, Kind::Extends, "I"), [0]);
}

#[test]
fn multi_dex_and_041_absolute_offsets_preserve_stable_identities() {
    let bytes = dex(&["LA;", "LB;"], &[(0, 1, vec![])]);
    let apk = fixture::apk(&[("classes.dex", &bytes), ("classes2.dex", &bytes)]);
    for threads in [1, 2] {
        let e = Engine::new(EngineOptions {
            threads: Some(threads),
            ..Default::default()
        })
        .unwrap();
        let a = open(&e, &apk, InputKind::Apk);
        let r = e
            .class_relations(&a, &query(Kind::Extends, "B"), &OperationControl::new())
            .unwrap();
        assert_eq!(
            r.value()
                .iter()
                .map(|r| r.class().id().dex().entry_ordinal())
                .collect::<Vec<_>>(),
            [0, 1]
        );
        let b = open(&e, &fixture::container_041(), InputKind::Dex);
        let r = e
            .class_relations(
                &b,
                &query(Kind::Implements, "example.I"),
                &OperationControl::new(),
            )
            .unwrap();
        assert_eq!(
            r.value()
                .iter()
                .map(|r| r.class().id().dex().logical_ordinal())
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(r.value()[0].target().as_str().unwrap(), "Lexample/I;");
    }
}

#[test]
fn explicit_scope_avoids_unselected_damage_and_rejects_foreign_artifact() {
    let bytes = dex(&["LA;", "LB;"], &[(0, 1, vec![])]);
    let apk = fixture::apk(&[("classes.dex", &bytes), ("classes2.dex", b"bad dex")]);
    let e = engine();
    let a = open(&e, &apk, InputKind::Apk);
    let entries = e
        .archive_entries(
            &a,
            &asc_core::ArchiveEntryQuery::default(),
            &OperationControl::new(),
        )
        .unwrap();
    let scope = MethodScope::Entries(vec![entries.value()[0].id()]);
    let q = query(Kind::Extends, "B");
    assert_eq!(
        e.class_relations_in_scope(&a, &scope, &q, &OperationControl::new())
            .unwrap()
            .value()
            .len(),
        1
    );
    assert!(e.class_relations(&a, &q, &OperationControl::new()).is_err());
    assert_eq!(
        *engine()
            .class_relations(&a, &q, &OperationControl::new())
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidQuery
    );
}

#[test]
fn result_limits_accumulate_across_dexes_and_recover() {
    let bytes = dex(&["LA;", "LB;"], &[(0, 1, vec![])]);
    let apk = fixture::apk(&[("classes.dex", &bytes), ("classes2.dex", &bytes)]);
    let mut limits = Limits::default();
    limits.scan.max_result_items = 1;
    let e = Engine::new(EngineOptions {
        limits,
        ..Default::default()
    })
    .unwrap();
    let a = open(&e, &apk, InputKind::Apk);
    assert_eq!(
        *e.class_relations(&a, &query(Kind::Extends, "B"), &OperationControl::new())
            .unwrap_err()
            .kind(),
        ErrorKind::ResourceLimit
    );
    assert!(
        e.class_relations(
            &a,
            &query(Kind::Extends, "Missing"),
            &OperationControl::new()
        )
        .unwrap()
        .value()
        .is_empty()
    );
    let one = open(&e, &bytes, InputKind::Dex);
    assert_eq!(
        e.class_relations(&one, &query(Kind::Extends, "B"), &OperationControl::new())
            .unwrap()
            .value()
            .len(),
        1
    );
    let mut limits = Limits::default();
    limits.scan.max_result_bytes = 1;
    let e = Engine::new(EngineOptions {
        limits,
        ..Default::default()
    })
    .unwrap();
    let a = open(&e, &bytes, InputKind::Dex);
    assert_eq!(
        *e.class_relations(&a, &query(Kind::Extends, "B"), &OperationControl::new())
            .unwrap_err()
            .kind(),
        ErrorKind::ResourceLimit
    );
}

#[test]
fn cancelled_and_expired_queries_leave_engine_reusable() {
    let e = engine();
    let a = open(&e, &dex(&["LA;", "LB;"], &[(0, 1, vec![])]), InputKind::Dex);
    let flag = Arc::new(AtomicBool::new(true));
    let q = query(Kind::Extends, "B");
    let error = e
        .class_relations(&a, &q, &OperationControl::new().with_cancel_flag(flag))
        .unwrap_err();
    assert_eq!(
        *error.kind(),
        ErrorKind::Cancelled {
            cause: CancelCause::User
        }
    );
    let error = e
        .class_relations(
            &a,
            &q,
            &OperationControl::new().with_deadline(Instant::now() - Duration::from_millis(1)),
        )
        .unwrap_err();
    assert_eq!(
        *error.kind(),
        ErrorKind::Cancelled {
            cause: CancelCause::Deadline
        }
    );
    assert_eq!(
        e.class_relations(&a, &q, &OperationControl::new())
            .unwrap()
            .value()
            .len(),
        1
    );
}

#[test]
fn exact_query_rejects_invalid_or_oversized_inputs() {
    for input in ["", "   ", "[LA;", "L;"] {
        assert_eq!(
            *class_relation_query(Kind::Extends, input, &PatternLimits::default())
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidQuery
        );
    }
    let limits = PatternLimits {
        max_pattern_bytes: 2,
        ..PatternLimits::default()
    };
    assert_eq!(
        *class_relation_query(Kind::Extends, "Long", &limits)
            .unwrap_err()
            .kind(),
        ErrorKind::ResourceLimit
    );
}

#[test]
fn raw_and_apk_041_explicit_logical_scopes_select_one_member() {
    let bytes = fixture::container_041();
    for kind in [InputKind::Dex, InputKind::Apk] {
        let input = if kind == InputKind::Apk {
            fixture::apk(&[("classes.dex", &bytes)])
        } else {
            bytes.clone()
        };
        let e = engine();
        let a = open(&e, &input, kind);
        let catalog = e.dexes(&a, &OperationControl::new()).unwrap();
        for selected in catalog.value() {
            let scope = MethodScope::Dexes(vec![selected.id(), selected.id()]);
            let relations = e
                .class_relations_in_scope(
                    &a,
                    &scope,
                    &query(Kind::Implements, "example.I"),
                    &OperationControl::new(),
                )
                .unwrap();
            assert_eq!(relations.value().len(), 1);
            assert_eq!(relations.value()[0].class().id().dex(), selected.id());
            let classes = e
                .classes_in_scope(&a, &scope, &ClassFilter::none(), &OperationControl::new())
                .unwrap();
            assert_eq!(classes.value().len(), 1);
            assert_eq!(classes.value()[0].id().dex(), selected.id());
            let scoped = e
                .dexes_in_scope(&a, &scope, &OperationControl::new())
                .unwrap();
            assert_eq!(scoped.value().len(), 1);
            assert_eq!(scoped.value()[0].id(), selected.id());
            #[cfg(feature = "decompile")]
            {
                let selector = asc_core::model::ClassSelector::Descriptor(
                    asc_core::query::exact_descriptor("example.Child").unwrap(),
                    None,
                );
                let source = e
                    .decompile_in_scope(&a, &scope, &selector, &OperationControl::new())
                    .unwrap();
                assert_eq!(source.value().class().id().dex(), selected.id());
                let inventory = e
                    .method_inventory(&a, &scope, &OperationControl::new())
                    .unwrap();
                assert_eq!(inventory.value().dex_entries().len(), 1);
                assert_eq!(inventory.value().dex_entries()[0].id(), selected.id());
            }
        }
    }
}

#[test]
fn container_interface_pointers_cannot_alias_any_member_metadata() {
    let good = fixture::container_041();
    let second = read32(&good, 0x20) as usize;
    let defs = read32(&good, 0x64) as usize;
    for pointer in [
        0x2c,
        read32(&good, 0x3c),
        read32(&good, 0x34),
        second as u32 + 0x2c,
        read32(&good, second + 0x3c),
    ] {
        let mut bad = good.clone();
        write32(&mut bad, defs + 12, pointer);
        let e = engine();
        let a = open(&e, &bad, InputKind::Dex);
        let error = e
            .class_relations(
                &a,
                &query(Kind::Implements, "Missing"),
                &OperationControl::new(),
            )
            .unwrap_err();
        assert_eq!(
            *error.kind(),
            ErrorKind::MalformedInput,
            "pointer {pointer}: {error}"
        );
    }
}

#[test]
fn explicit_raw_members_share_one_physical_decoded_budget() {
    let bytes = fixture::container_041();
    let limits = Limits {
        max_total_decoded_bytes: bytes.len() as u64,
        ..Limits::default()
    };
    let e = Engine::new(EngineOptions {
        limits,
        ..Default::default()
    })
    .unwrap();
    let a = open(&e, &bytes, InputKind::Dex);
    let ids = e
        .dexes(&a, &OperationControl::new())
        .unwrap()
        .value()
        .iter()
        .map(|d| d.id())
        .collect();
    let report = e
        .class_relations_in_scope(
            &a,
            &MethodScope::Dexes(ids),
            &query(Kind::Implements, "example.I"),
            &OperationControl::new(),
        )
        .unwrap();
    assert_eq!(report.value().len(), 2);
}

#[cfg(feature = "decompile")]
#[test]
fn unicode_class_decompile_selects_non_bmp_and_high_bmp_exactly() {
    use asc_core::model::ClassSelector;
    let bytes = dex(
        &["Lpkg/\u{10000};", "Lpkg/\u{e000};", "Ljava/lang/Object;"],
        &[(0, 2, vec![]), (1, 2, vec![])],
    );
    let e = engine();
    let a = open(&e, &bytes, InputKind::Dex);
    for (index, name) in ["pkg.\u{10000}", "pkg.\u{e000}"].into_iter().enumerate() {
        let descriptor = asc_core::query::exact_descriptor(name).unwrap();
        let result = e
            .decompile(
                &a,
                &ClassSelector::Descriptor(descriptor.clone(), None),
                &OperationControl::new(),
            )
            .unwrap();
        assert_eq!(result.value().class().id().class_def_idx(), index as u32);
        assert_eq!(result.value().class().descriptor(), &descriptor);
    }
}
