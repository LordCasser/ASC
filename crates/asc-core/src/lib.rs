//! asc-core: APK and DEX analysis as a library.
//!
//! The public surface is small and intentional (openspec/implementation/
//! interfaces.md §2): an [`engine::Engine`] opens immutable
//! [`engine::Artifact`]s and runs operations that return [`model::Report`]s
//! over the frozen domain types, or [`error::Error`]s with stable kinds.
//! Third-party backend types never cross this boundary; the `decompile` and
//! `manifest` features gate the optional analysis capabilities without
//! changing query semantics.
//!
//! `pub(crate)` visibility here is the crate boundary for A10: modules and
//! items below stay private until A10's API freeze review (A13/A14 revisit
//! before packaging).

pub mod engine;
pub mod error;
pub mod model;
pub mod query;

pub mod bytes;
pub mod dex;
#[cfg(feature = "manifest")]
pub mod manifest;
pub(crate) mod zip;

pub use bytes::OperationControl;
pub use engine::{ArchiveCopySession, Engine, EngineOptions, InputKind};
pub use error::Error;
pub use model::dto;
pub use model::{
    ArchiveEntry, ArchiveEntryId, ArchiveEntryQuery, ArtifactId, MethodDeclaration, MethodId,
    MethodInventory, MethodScope, MethodTarget, Report,
};
