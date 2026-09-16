#!/usr/bin/env bash
# Compile and test asc-core in every supported feature combination.
#
# Keep this matrix independent from rasc: a workspace build can unify the
# consumer's features and hide a missing cfg boundary in asc-core itself.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"

if command -v rustup >/dev/null 2>&1 && rustup run 1.93.1 cargo --version >/dev/null 2>&1; then
    CARGO=(rustup run 1.93.1 cargo)
else
    CARGO=(cargo)
fi

run_matrix() {
    local name="$1"
    shift
    printf '\n=== asc-core feature: %s ===\n' "$name"
    CARGO_TARGET_DIR="$TARGET" "${CARGO[@]}" test -p asc-core --locked "$@"
}

cd "$ROOT"
run_matrix default --no-default-features
run_matrix manifest --no-default-features --features manifest
run_matrix decompile --no-default-features --features decompile
run_matrix all-features --all-features

# Build a consumer outside the workspace.  Its manifest has no workspace
# patch or CLI dependency, so feature unification in the root cannot hide a
# missing public asc-core boundary.
CONSUMER="$(mktemp -d /tmp/asc-core-consumer.XXXXXX)"
trap 'rm -r "$CONSUMER"' EXIT
mkdir -p "$CONSUMER/src"
cat > "$CONSUMER/Cargo.toml" <<EOF
[package]
name = "asc-core-path-consumer"
version = "0.1.0"
edition = "2024"

[features]
decompile = ["asc-core/decompile"]
manifest = ["asc-core/manifest"]

[dependencies]
asc-core = { path = "$ROOT/crates/asc-core", default-features = false }
EOF
cat > "$CONSUMER/src/main.rs" <<'EOF'
use std::env;
use std::fs;
use std::sync::Arc;

use asc_core::engine::{Engine, EngineOptions, InputKind};
use asc_core::model::ClassFilter;
use asc_core::OperationControl;

#[cfg(feature = "decompile")]
use asc_core::model::{ClassDescriptor, ClassSelector};

fn main() {
    let path = env::var("ASC_G02_DEX").expect("ASC_G02_DEX is set by the smoke script");
    let dex = fs::read(path).expect("read G02 DEX fixture");
    let engine = Engine::new(EngineOptions::default()).expect("create engine");
    let control = OperationControl::new();
    let artifact = engine
        .open_bytes(Arc::from(dex.into_boxed_slice()), InputKind::Dex, &control)
        .expect("open G02 DEX");
    let classes = engine
        .classes(&artifact, &ClassFilter::none(), &control)
        .expect("list G02 classes");
    assert!(
        classes
            .value()
            .iter()
            .any(|class| class.descriptor().as_str() == "Lexample/Statics;"),
        "G02 class is missing"
    );

    #[cfg(feature = "decompile")]
    {
        let selector = ClassSelector::Descriptor(
            ClassDescriptor::from_normalized("Lexample/Statics;".to_owned())
                .expect("G02 descriptor"),
            None,
        );
        let source = engine
            .decompile(&artifact, &selector, &control)
            .expect("decompile G02 class");
        assert!(
            source.value().text().contains("SECOND = 22"),
            "G02 static initializer value is missing"
        );
        let scope = asc_core::MethodScope::Root;
        let inventory = engine.method_inventory(&artifact, &scope, &control).expect("method inventory");
        let targets = inventory.value().methods().iter().map(|method| method.target()).collect::<Vec<_>>();
        let mut batch = Vec::new();
        engine.visit_selected_method_sources(&artifact, &scope, &targets, &control, |declaration, result| {
            batch.push((declaration.target(), result.expect("batch source").text().to_owned()));
            Ok(())
        }).expect("selected batch visitor");
        assert_eq!(batch.len(), targets.len());
        for (target, text) in batch {
            let single = engine.decompile_method(&artifact, &target, &control).expect("selected method");
            assert_eq!(text, single.value().text());
        }

    }
}
EOF

G02="$ROOT/tests/fixtures/contracts/inputs/g02-static-initializers.dex"
run_consumer() {
    local name="$1"
    shift
    local log="$CONSUMER/$name.log"
    if ! CARGO_TARGET_DIR="$TARGET" ASC_G02_DEX="$G02" "${CARGO[@]}" \
        "$@" --manifest-path "$CONSUMER/Cargo.toml" >"$log" 2>&1; then
        cat "$log"
        return 1
    fi
    printf 'consumer %s: passed\n' "$name"
}

"${CARGO[@]}" generate-lockfile --offline --manifest-path "$CONSUMER/Cargo.toml" \
    >"$CONSUMER/lock.log" 2>&1
run_consumer default-check check --locked --offline --no-default-features
run_consumer default-run run --locked --offline --no-default-features
run_consumer all-features-run run --locked --offline --all-features

printf '\nasc-core feature matrix and path consumer: all checks passed\n'
