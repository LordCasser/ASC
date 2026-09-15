//! A12 embedding-host contract tests (BACK-02, CORE-05/06 slices):
//! a downstream host uses only the public `asc_core` API, and the backend
//! stays invisible and inert.
//!
//! What each test pins:
//! - `scan_never_initializes_the_backend`: references results on an artifact
//!   are byte-identical before and after a decompile call on the same
//!   engine/artifact (analysis runtime independence, command-line spec
//!   "Analysis runtime independence");
//! - `decompile_is_deterministic`: repeated checked decompilations of the
//!   same class render identical bytes (no hidden state, no scheduling
//!   dependence);
//! - env independence at the process level is covered by the vendored
//!   crate's own `asc_contracts` child-probe test (see
//!   vendor/droidsaw-dex/tests/asc_contracts.rs) and cited in A12 evidence.

use asc_core::engine::{Engine, EngineOptions, InputKind};
use asc_core::bytes::OperationControl;
use asc_core::model::ClassFilter;
#[cfg(feature = "decompile")]
use asc_core::model::{ClassDescriptor, ClassSelector};
#[cfg(feature = "decompile")]
use asc_core::query;

#[cfg(feature = "decompile")]
#[test]
fn scan_never_initializes_the_backend() {
    let dex = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/contracts/inputs/g02-static-initializers.dex"
    ))
    .expect("g02 fixture");
    let engine = Engine::new(EngineOptions::default()).expect("engine");
    let control = OperationControl::new();
    let artifact = engine
        .open_bytes(std::sync::Arc::from(dex.into_boxed_slice()), InputKind::Dex, &control)
        .expect("open raw DEX");

    let query = query::string_query("SECOND", query::MatchMode::Literal, &Default::default())
        .expect("query");
    let before = engine.references(&artifact, &query, &control).expect("references before");

    // Now run a decompile (backend parse + emit) on the same artifact.
    let selector = ClassSelector::Descriptor(
        ClassDescriptor::from_normalized("Lexample/Statics;".to_owned()).expect("descriptor"),
        None,
    );
    let source = engine
        .decompile(&artifact, &selector, &control)
        .expect("decompile after backend parse");
    assert!(source.value().text().contains("SECOND = 22"), "backend must fix G02");

    // The references result is unchanged by the backend having run.
    let after = engine.references(&artifact, &query, &control).expect("references after");
    assert_eq!(before.value(), after.value(), "scan results must not drift after backend use");
}

#[cfg(feature = "decompile")]
#[test]
fn decompile_is_deterministic() {
    let dex = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/contracts/inputs/g02-static-initializers.dex"
    ))
    .expect("g02 fixture");
    let engine = Engine::new(EngineOptions::default()).expect("engine");
    let control = OperationControl::new();
    let artifact = engine
        .open_bytes(std::sync::Arc::from(dex.into_boxed_slice()), InputKind::Dex, &control)
        .expect("open raw DEX");
    let selector = ClassSelector::Descriptor(
        ClassDescriptor::from_normalized("Lexample/Statics;".to_owned()).expect("descriptor"),
        None,
    );
    let first = engine.decompile(&artifact, &selector, &control).expect("first decompile");
    let second = engine.decompile(&artifact, &selector, &control).expect("second decompile");
    assert_eq!(first.value().text(), second.value().text(), "deterministic source");
}

#[test]
fn classes_and_references_agree_on_the_raw_dex_entry() {
    let dex = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/contracts/inputs/g02-static-initializers.dex"
    ))
    .expect("g02 fixture");
    let engine = Engine::new(EngineOptions::default()).expect("engine");
    let control = OperationControl::new();
    let artifact = engine
        .open_bytes(std::sync::Arc::from(dex.into_boxed_slice()), InputKind::Dex, &control)
        .expect("open raw DEX");
    let dexes = engine.dexes(&artifact, &control).expect("dexes");
    assert_eq!(dexes.value().len(), 1);
    assert_eq!(dexes.value()[0].id().entry_ordinal(), 0);
    assert_eq!(
        dexes.value()[0].display_name().as_str().as_deref(),
        Some("<memory.dex>"),
        "raw DEX display name"
    );
    let listed = engine.classes(&artifact, &ClassFilter::none(), &control).expect("classes");
    assert!(listed
        .value()
        .iter()
        .any(|class| class.descriptor().as_str() == "Lexample/Statics;"));
}
