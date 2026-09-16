#![cfg(feature = "decompile")]

mod support;

use asc_core::engine::{Artifact, Engine, EngineOptions, InputKind};
use asc_core::error::ErrorKind;
use asc_core::{MethodScope, MethodTarget, OperationControl};
use std::sync::Arc;
use support::dex::{make_dex, make_static_field_dex};

fn open_fixture(engine: &Engine, bytes: Vec<u8>) -> Artifact {
    engine
        .open_bytes(
            Arc::from(bytes.into_boxed_slice()),
            InputKind::Dex,
            &OperationControl::new(),
        )
        .unwrap()
}

fn fixture_methods(engine: &Engine, artifact: &Artifact) -> Vec<MethodTarget> {
    let mut targets: Vec<_> = engine
        .method_inventory(artifact, &MethodScope::Root, &OperationControl::new())
        .unwrap()
        .value()
        .methods()
        .iter()
        .map(|method| method.target())
        .collect();
    targets.sort_unstable();
    targets
}

fn selected_sources(
    engine: &Engine,
    artifact: &Artifact,
    scope: &MethodScope,
    targets: &[MethodTarget],
) -> Vec<(u32, String)> {
    let mut sources = Vec::new();
    engine
        .visit_selected_method_sources(
            artifact,
            scope,
            targets,
            &OperationControl::new(),
            |declaration, result| {
                let source = result.expect("fixture method should decompile");
                sources.push((
                    declaration.target().method().method_idx(),
                    source.text().to_owned(),
                ));
                Ok(())
            },
        )
        .unwrap();
    sources
}

#[test]
fn selected_batch_visits_exact_subset_in_stable_order() {
    let engine = Engine::new(EngineOptions::default()).unwrap();
    let artifact = open_fixture(&engine, make_dex());
    let targets = fixture_methods(&engine, &artifact);
    assert_eq!(targets.len(), 2);

    let scope = MethodScope::Dexes(vec![targets[0].class().dex()]);
    let sources = selected_sources(&engine, &artifact, &scope, &[targets[1], targets[0]]);
    assert_eq!(sources.len(), 2);
    assert!(sources[0].0 < sources[1].0);
    let subset = selected_sources(&engine, &artifact, &scope, &[targets[1]]);
    assert_eq!(subset, vec![sources[1].clone()]);
}

#[test]
fn selected_batch_sources_match_individual_decompilation() {
    let engine = Engine::new(EngineOptions::default()).unwrap();
    let artifact = open_fixture(&engine, make_dex());
    let targets = fixture_methods(&engine, &artifact);
    let scope = MethodScope::Dexes(vec![targets[0].class().dex()]);
    let batch = selected_sources(&engine, &artifact, &scope, &targets);

    let individual: Vec<_> = targets
        .iter()
        .map(|target| {
            (
                target.method().method_idx(),
                engine
                    .decompile_method(&artifact, target, &OperationControl::new())
                    .unwrap()
                    .value()
                    .text()
                    .to_owned(),
            )
        })
        .collect();
    assert_eq!(batch, individual);
}

#[test]
fn selected_batch_rejects_duplicates_before_callbacks() {
    let engine = Engine::new(EngineOptions::default()).unwrap();
    let artifact = open_fixture(&engine, make_dex());
    let target = fixture_methods(&engine, &artifact)[0];
    let mut callbacks = 0;
    let error = engine
        .visit_selected_method_sources(
            &artifact,
            &MethodScope::Root,
            &[target, target],
            &OperationControl::new(),
            |_, _| {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();

    assert_eq!(*error.kind(), ErrorKind::InvalidQuery);
    assert_eq!(callbacks, 0);
}

#[test]
fn selected_batch_rejects_foreign_targets_before_callbacks() {
    let engine = Engine::new(EngineOptions::default()).unwrap();
    let artifact = open_fixture(&engine, make_dex());
    let foreign = open_fixture(&engine, make_static_field_dex());
    let target = fixture_methods(&engine, &foreign)[0];
    let mut callbacks = 0;
    let error = engine
        .visit_selected_method_sources(
            &artifact,
            &MethodScope::Root,
            &[target],
            &OperationControl::new(),
            |_, _| {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();

    assert_eq!(*error.kind(), ErrorKind::InvalidQuery);
    assert_eq!(callbacks, 0);
}

#[test]
fn selected_batch_rejects_target_outside_scope_before_callbacks() {
    let engine = Engine::new(EngineOptions::default()).unwrap();
    let artifact = open_fixture(&engine, make_dex());
    let target = fixture_methods(&engine, &artifact)[0];
    let mut callbacks = 0;
    let error = engine
        .visit_selected_method_sources(
            &artifact,
            &MethodScope::Dexes(Vec::new()),
            &[target],
            &OperationControl::new(),
            |_, _| {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();

    assert_eq!(*error.kind(), ErrorKind::InvalidQuery);
    assert_eq!(callbacks, 0);
}

#[test]
fn selected_batch_empty_selection_is_a_successful_noop() {
    let engine = Engine::new(EngineOptions::default()).unwrap();
    let artifact = open_fixture(&engine, make_dex());
    let mut callbacks = 0;
    engine
        .visit_selected_method_sources(
            &artifact,
            &MethodScope::Dexes(Vec::new()),
            &[],
            &OperationControl::new(),
            |_, _| {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(callbacks, 0);
}
