//! Repeated/concurrent public method operations share admission and release
//! cancelled requests without changing identities or escaping the private pool.
#![cfg(feature = "decompile")]
use asc_core::error::{CancelCause, ErrorKind};
use asc_core::{Engine, EngineOptions, InputKind, MethodScope, OperationControl};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[test]
fn shared_engine_repeats_method_batches_on_one_and_two_workers() {
    let bytes: Arc<[u8]> = Arc::from(
        include_bytes!("../../../tests/fixtures/contracts/inputs/g02-static-initializers.dex")
            .as_slice(),
    );
    for threads in [1, 2] {
        let engine = Engine::new(EngineOptions {
            threads: Some(threads),
            ..Default::default()
        })
        .unwrap();
        let artifact = Arc::new(
            engine
                .open_bytes(bytes.clone(), InputKind::Dex, &OperationControl::new())
                .unwrap(),
        );
        let inventory = engine
            .method_inventory(&artifact, &MethodScope::Root, &OperationControl::new())
            .unwrap();
        let target = inventory
            .value()
            .methods()
            .iter()
            .find(|row| row.has_code())
            .unwrap()
            .target();
        let expected = engine
            .decompile_method(&artifact, &target, &OperationControl::new())
            .unwrap()
            .value()
            .text()
            .to_owned();
        drop(inventory);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let engine = engine.clone();
                let artifact = artifact.clone();
                let expected = &expected;
                scope.spawn(move || {
                    for _ in 0..20 {
                        let flag = Arc::new(AtomicBool::new(true));
                        let control = OperationControl::new().with_cancel_flag(flag.clone());
                        let error = engine
                            .decompile_method(&artifact, &target, &control)
                            .unwrap_err();
                        assert_eq!(
                            error.kind(),
                            &ErrorKind::Cancelled {
                                cause: CancelCause::User
                            }
                        );
                        flag.store(false, Ordering::Release);
                        let mut count = 0;
                        engine
                            .visit_selected_method_sources(
                                &artifact,
                                &MethodScope::Root,
                                &[target],
                                &control,
                                |declaration, source| {
                                    assert_eq!(rayon::current_num_threads(), threads);
                                    assert_eq!(declaration.target(), target);
                                    assert_eq!(source.unwrap().text(), expected);
                                    count += 1;
                                    Ok(())
                                },
                            )
                            .unwrap();
                        assert_eq!(count, 1);
                    }
                });
            }
        });
        assert_eq!(
            engine
                .decompile_method(&artifact, &target, &OperationControl::new())
                .unwrap()
                .value()
                .text(),
            expected
        );
    }
}
