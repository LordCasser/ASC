//! The analysis error model: stable kinds, carried diagnostics, and the one
//! pseudo-success payload the contract allows (partial source on an
//! incomplete decompilation).
//!
//! The kind strings are the contract: the CLI prints them as error codes and
//! the JSON schema names them, so they must not drift. Exit-code mapping is a
//! CLI concern (`InvalidQuery` -> 2, `Cancelled` -> 130, the rest -> 1); the
//! library itself never decides process behaviour.

use crate::model::{Diagnostic, MemoryPermit, Source};
use std::sync::Arc;
use std::fmt;

/// Why an operation failed. The stable `code()` strings are part of the
/// frozen CLI contract (schemas/cli-v1.schema.json).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// A query or option was syntactically or semantically invalid before any
    /// input was read.
    InvalidQuery,
    /// A requested class, DEX or target does not exist in the artifact.
    NotFound,
    /// The input is structurally broken at the claimed layer (ZIP, DEX, AXML).
    MalformedInput,
    /// The container or encoding is well-formed but outside the supported
    /// matrix (e.g. CompactDex, ZIP64, an undeclared XML encoding).
    UnsupportedFormat,
    /// Data cannot be represented in the required text encoding (e.g. a regex
    /// decision over an unpaired UTF-16 surrogate).
    UnsupportedEncoding,
    /// A resource limit from the engine limits table was exceeded.
    ResourceLimit,
    /// The operation was cancelled by the user or a deadline. The cause says
    /// which, because the CLI reports them differently.
    Cancelled { cause: CancelCause },
    /// A decompiler produced a result that is not a complete success; the
    /// partial source, when any, rides on the error.
    IncompleteDecompilation,
}

/// What triggered a cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelCause {
    User,
    Deadline,
}

impl ErrorKind {
    /// The stable machine-readable code, shared by CLI stderr and JSON.
    pub fn code(&self) -> &'static str {
        match self {
            ErrorKind::InvalidQuery => "InvalidQuery",
            ErrorKind::NotFound => "NotFound",
            ErrorKind::MalformedInput => "MalformedInput",
            ErrorKind::UnsupportedFormat => "UnsupportedFormat",
            ErrorKind::UnsupportedEncoding => "UnsupportedEncoding",
            ErrorKind::ResourceLimit => "ResourceLimit",
            ErrorKind::Cancelled { .. } => "Cancelled",
            ErrorKind::IncompleteDecompilation => "IncompleteDecompilation",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// An analysis failure: a stable kind, a human-facing context chain, the
/// diagnostics observed before the failure, and - only for incomplete
/// decompilations - the partial source.
#[derive(Clone, Debug)]
pub struct Error {
    kind: ErrorKind,
    context: Vec<String>,
    diagnostics: Vec<Diagnostic>,
    partial_source: Option<Arc<Source>>,
    // The shared partial source must retain its charge across cloned errors.
    memory: Option<MemoryPermit>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            context: Vec::new(),
            diagnostics: Vec::new(),
            partial_source: None,
            memory: None,
        }
    }

    pub(crate) fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context.push(context.into());
        self
    }

    pub(crate) fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    /// Attaches the partial source; only meaningful for
    /// [`ErrorKind::IncompleteDecompilation`].
    pub(crate) fn with_partial_source(mut self, source: Source) -> Self {
        self.partial_source = Some(Arc::new(source));
        self
    }

    pub(crate) fn with_memory(mut self, memory: MemoryPermit) -> Self {
        self.memory = Some(memory);
        self
    }

    #[allow(dead_code)] // A07/A08 wiring surface; used by contract tests
    #[allow(dead_code)] // A07/A08 wiring surface
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    #[allow(dead_code)]
    pub fn context(&self) -> &[String] {
        &self.context
    }

    #[allow(dead_code)]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// The partial decompiled source, when the failure is an incomplete
    /// decompilation that still produced usable text.
    #[allow(dead_code)]
    pub fn partial_source(&self) -> Option<&Source> {
        self.partial_source.as_deref()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind.code())?;
        for context in self.context.iter().rev() {
            write!(f, ": {context}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

/// Construction helpers used across the crate.
impl Error {
    pub(crate) fn invalid_query(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidQuery).with_context(message)
    }

    pub fn resource_limit(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ResourceLimit).with_context(message)
    }

    pub(crate) fn unsupported_encoding(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::UnsupportedEncoding).with_context(message)
    }

    pub(crate) fn malformed_input(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::MalformedInput).with_context(message)
    }
}
