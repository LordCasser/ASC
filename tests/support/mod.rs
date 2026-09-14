//! In-crate test support for the A00-A14 contract fixture system.
//!
//! Shared by `tests/contract_harness.rs` and the later `contract_*`
//! integration tests. The crate keeps its dependency list minimal on purpose;
//! everything the fixtures need - hashing, JSON, DEX/APK construction and fact
//! comparison - is implemented here against the standard library only. New
//! dependencies require the integration owner (see openspec/execution-plan.md).

pub mod apk;
pub mod compare;
pub mod dex;
pub mod json;
pub mod sha;
