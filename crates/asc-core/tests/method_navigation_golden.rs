//! E17.1 public API golden matrix for precise DEX method navigation.

#![cfg(feature = "decompile")]

mod support;

use asc_core::OperationControl;
use asc_core::dto;
use asc_core::engine::{Engine, EngineOptions, InputKind};
use asc_core::error::{CancelCause, ErrorKind};
use asc_core::model::{ClassSelector, MethodScope};
use asc_core::query::{self, ClassSpec, MatchMode, MemberSpec};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn engine_and_artifact() -> (Engine, asc_core::engine::Artifact) {
    let engine = Engine::new(EngineOptions {
        threads: Some(2),
        ..Default::default()
    })
    .expect("engine");
    let artifact = engine
        .open_bytes(
            Arc::from(support::method_navigation::fixture().into_boxed_slice()),
            InputKind::Dex,
            &OperationControl::new(),
        )
        .expect("method-navigation fixture is valid DEX");
    (engine, artifact)
}

fn metadata_json(source: &asc_core::model::Source) -> String {
    let mut writer = dto::Writer::new();
    dto::write_source_metadata(&mut writer, source.metadata());
    writer.finish()
}

fn method<'a>(
    inventory: &'a asc_core::model::MethodInventory,
    name: &str,
    prototype: &str,
) -> &'a asc_core::model::MethodDeclaration {
    inventory
        .methods()
        .iter()
        .find(|declaration| {
            declaration.identity().name().as_str().as_deref() == Some(name)
                && prototype_of(declaration) == prototype
        })
        .unwrap_or_else(|| panic!("missing {name}{prototype}"))
}

fn prototype_of(declaration: &asc_core::model::MethodDeclaration) -> String {
    let prototype = declaration.identity().prototype();
    let parameters = prototype
        .parameters()
        .iter()
        .map(|parameter| parameter.as_str().unwrap_or_default())
        .collect::<String>();
    format!(
        "({parameters}){}",
        prototype.return_type().as_str().unwrap_or_default()
    )
}

#[test]
fn inventory_golden_keeps_every_declared_method_identity_and_flags() {
    let (engine, artifact) = engine_and_artifact();
    let report = engine
        .method_inventory(&artifact, &MethodScope::Root, &OperationControl::new())
        .expect("inventory");
    let inventory = report.value();
    assert_eq!(inventory.methods().len(), 7);
    assert_eq!(inventory.resolved_dexes().len(), 1);
    assert_eq!(inventory.resolved_dexes()[0].artifact(), artifact.id());
    assert_eq!(inventory.resolved_dexes()[0].entry_ordinal(), 0);
    assert_eq!(inventory.resolved_dexes()[0].logical_ordinal(), 0);

    let expected = [
        (0, "<init>", "()V", 0x0001_0001, true, true),
        (1, "<init>", "(I)V", 0x0001_0001, true, true),
        (2, "abstractApi", "(I)V", 0x0401, false, false),
        (
            3,
            "nativeApi",
            "(Ljava/lang/String;)I",
            0x0101,
            false,
            false,
        ),
        (4, "overload", "(I)V", 0x0001, false, true),
        (5, "overload", "(Ljava/lang/String;)V", 0x0001, false, true),
        (6, "parameterMethod", "(I)I", 0x0001, false, true),
    ];
    for (declaration, (method_idx, name, prototype, flags, direct, has_code)) in
        inventory.methods().iter().zip(expected)
    {
        assert_eq!(declaration.id().method_idx(), method_idx);
        assert_eq!(
            declaration.identity().name().as_str().as_deref(),
            Some(name)
        );
        assert_eq!(prototype_of(declaration), prototype);
        assert_eq!(declaration.access_flags(), flags);
        assert_eq!(declaration.is_direct(), direct);
        assert_eq!(declaration.has_code(), has_code);
        assert_eq!(
            declaration.class().descriptor().as_str(),
            "Lfixture/Navigation;"
        );
        assert_eq!(declaration.class_id().class_def_idx(), 0);
        assert_eq!(declaration.class_id().dex().artifact(), artifact.id());
        assert_eq!(declaration.id().dex(), declaration.class_id().dex());
        assert_eq!(declaration.code_off().is_some(), has_code);
    }
    // The native declaration has no implementation and no reference caller,
    // yet remains present in the declaration table with its full JNI shape.
    let native = method(inventory, "nativeApi", "(Ljava/lang/String;)I");
    assert_eq!(native.id().method_idx(), 3);
    assert_eq!(native.access_flags() & 0x0100, 0x0100);
    assert!(!native.has_code());
    let native_query = query::member_query(
        false,
        MemberSpec {
            name: Some("nativeApi"),
            mode: MatchMode::Literal,
            class: Some(ClassSpec::Exact("Lfixture/Navigation;")),
        },
        &Default::default(),
    )
    .expect("native method reference query");
    let native_references = engine
        .references(&artifact, &native_query, &OperationControl::new())
        .expect("scan native method references");
    assert!(
        native_references.value().is_empty(),
        "native declaration is intentionally unreferenced, got {:?}",
        native_references.value()
    );
    let abstract_method = method(inventory, "abstractApi", "(I)V");
    assert_eq!(abstract_method.access_flags() & 0x0400, 0x0400);
    assert!(!abstract_method.has_code());
}

#[test]
fn selected_method_golden_distinguishes_constructors_and_overloads() {
    let (engine, artifact) = engine_and_artifact();
    let inventory = engine
        .method_inventory(&artifact, &MethodScope::Root, &OperationControl::new())
        .expect("inventory");
    let expected_sources = [
        ("<init>", "()V", "public Navigation() {\n}\n"),
        ("<init>", "(I)V", "public Navigation(int v1) {\n}\n"),
        ("overload", "(I)V", "public void overload(int v1) {\n}\n"),
        (
            "overload",
            "(Ljava/lang/String;)V",
            "public void overload(String v1) {\n}\n",
        ),
    ];
    for (name, prototype, expected_source) in expected_sources {
        let declaration = method(inventory.value(), name, prototype);
        let source = engine
            .decompile_method(&artifact, &declaration.target(), &OperationControl::new())
            .unwrap_or_else(|error| panic!("decompile {name}{prototype}: {error}"));
        assert_eq!(source.value().text(), expected_source);
        assert_eq!(source.value().class().id(), declaration.class_id());
        assert_eq!(source.stats().result_items, 1);
    }
}

#[test]
fn selected_method_and_class_context_have_identical_metadata_with_debug_and_annotations() {
    let (engine, artifact) = engine_and_artifact();
    let inventory = engine
        .method_inventory(&artifact, &MethodScope::Root, &OperationControl::new())
        .expect("inventory");
    let declaration = method(inventory.value(), "parameterMethod", "(I)I");
    let selected = engine
        .decompile_method(&artifact, &declaration.target(), &OperationControl::new())
        .expect("selected method");
    assert_eq!(
        selected.value().text(),
        "public int parameterMethod(int count) {\n    return count;\n}\n"
    );
    assert!(selected.value().text().contains("count"));
    assert!(!selected.value().text().contains("overload"));

    let class = engine
        .decompile(
            &artifact,
            &ClassSelector::Id(declaration.class_id()),
            &OperationControl::new(),
        )
        .expect("class context");
    assert_eq!(selected.value().class().id(), class.value().class().id());
    assert_eq!(
        metadata_json(selected.value()),
        metadata_json(class.value())
    );
    let metadata = metadata_json(selected.value());
    const EXPECTED_ANNOTATIONS: &str = r#"annotations":[{"target":{"target":"class"},"annotation":{"visibility":"runtime","type_descriptor":{"text":"Lfixture/Marker;","utf16":[76,102,105,120,116,117,114,101,47,77,97,114,107,101,114,59]},"items":[{"name":{"text":"value","utf16":[118,97,108,117,101]},"value":{"type":"string","value":{"text":"annotated","utf16":[97,110,110,111,116,97,116,101,100]}}}],"rendered":"value = \"annotated\""}},{"target":{"target":"method","index":6},"annotation":{"visibility":"build","type_descriptor":{"text":"Lfixture/Marker;","utf16":[76,102,105,120,116,117,114,101,47,77,97,114,107,101,114,59]},"items":[{"name":{"text":"value","utf16":[118,97,108,117,101]},"value":{"type":"string","value":{"text":"annotated","utf16":[97,110,110,111,116,97,116,101,100]}}}],"rendered":"value = \"annotated\""}},{"target":{"target":"parameter","method_index":6,"parameter_index":0},"annotation":{"visibility":"build","type_descriptor":{"text":"Lfixture/Param;","utf16":[76,102,105,120,116,117,114,101,47,80,97,114,97,109,59]},"items":[],"rendered":""}}]"#;
    const EXPECTED_DEBUG: &str = r#"debug":{"parameter_names":[{"text":"count","utf16":[99,111,117,110,116]}],"locals":[],"lines":[{"code_unit":0,"line":42}]}"#;
    assert!(metadata.contains(EXPECTED_ANNOTATIONS));
    assert!(metadata.contains(EXPECTED_DEBUG));
    assert!(metadata.contains(r#""name":{"text":"parameterMethod","utf16":[112,97,114,97,109,101,116,101,114,77,101,116,104,111,100]}"#));
}

#[test]
fn declaration_only_native_and_abstract_methods_have_exact_selected_results() {
    let (engine, artifact) = engine_and_artifact();
    let inventory = engine
        .method_inventory(&artifact, &MethodScope::Root, &OperationControl::new())
        .expect("inventory");
    for (name, prototype, expected_source) in [
        (
            "nativeApi",
            "(Ljava/lang/String;)I",
            "public native int nativeApi(java.lang.String p0);\n",
        ),
        (
            "abstractApi",
            "(I)V",
            "public abstract void abstractApi(int p0);\n",
        ),
    ] {
        let declaration = method(inventory.value(), name, prototype);
        let source = engine
            .decompile_method(&artifact, &declaration.target(), &OperationControl::new())
            .unwrap_or_else(|error| panic!("decompile {name}: {error}"));
        assert_eq!(source.value().text(), expected_source);
    }
}

#[test]
fn invalid_target_and_cancelled_operations_are_bounded_and_typed() {
    let (engine, artifact) = engine_and_artifact();
    let inventory = engine
        .method_inventory(&artifact, &MethodScope::Root, &OperationControl::new())
        .expect("inventory");
    let declaration = method(inventory.value(), "parameterMethod", "(I)I");

    let other = engine_and_artifact().1;
    let foreign = engine
        .decompile_method(&other, &declaration.target(), &OperationControl::new())
        .expect_err("foreign MethodTarget must be rejected");
    assert_eq!(foreign.kind(), &ErrorKind::InvalidQuery);

    let deadline = OperationControl::new().with_deadline(Instant::now() - Duration::from_millis(1));
    let expired = engine
        .decompile_method(&artifact, &declaration.target(), &deadline)
        .expect_err("expired selected-method operation");
    assert_eq!(
        expired.kind(),
        &ErrorKind::Cancelled {
            cause: CancelCause::Deadline
        }
    );

    let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let cancelled = OperationControl::new().with_cancel_flag(flag);
    let error = engine
        .method_inventory(&artifact, &MethodScope::Root, &cancelled)
        .expect_err("cancelled inventory");
    assert_eq!(
        error.kind(),
        &ErrorKind::Cancelled {
            cause: CancelCause::User
        }
    );
}
