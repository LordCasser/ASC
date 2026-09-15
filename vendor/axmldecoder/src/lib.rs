//!Decoder for the binary XML format used by Android.
//!
//!This is the rasc-maintained fork of `axmldecoder 0.5.0` (see PATCHES.md /
//!UPSTREAM.md). The fork replaces the deku-derived readers with a validating
//!cursor parser whose only job is to turn bytes into an **ordered, bounded,
//!complete** document model: nodes in stream order, attributes with their raw
//!typed values, namespace events with scopes, string-pool styles and the
//!resource map. It deliberately does **not** format typed values into strings;
//!the raw `type`/`data` pair is the single source of truth and projection into
//!readable text is the consumer's job.
//!
//!No path in this crate panics on input: every read is bounds-checked and
//!every structural inconsistency is a `ParseError`.

mod binaryxml;
mod cursor;
mod stringpool;
mod xml;

use thiserror::Error;

pub use crate::binaryxml::{Attribute, Cdata, Document, Element, NamespaceEvent, Node, RawValue};
pub use crate::stringpool::{StringPoolData, StyleSpan};

/// Resource limits honoured by [`parse_document`]. Every field must be a
/// positive finite number; the defaults mirror the ASC limits table
/// (interfaces.md §5: depth 256, xml-nodes/xml-attributes 1_000_000,
/// string-units 1_048_576).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum open-element nesting depth.
    pub max_depth: usize,
    /// Maximum number of nodes (elements + text/cdata) in the document.
    pub max_nodes: usize,
    /// Maximum attributes, counted cumulatively over the document.
    pub max_attributes: usize,
    /// Maximum UTF-16 units in one string-pool string.
    pub max_string_units: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_depth: 256,
            max_nodes: 1_000_000,
            max_attributes: 1_000_000,
            max_string_units: 1_048_576,
        }
    }
}

/// Everything that can go wrong while decoding a binary XML document.
///
/// `Malformed` maps to a structural error in the caller; `Limit` maps to a
/// resource-limit error; `Cancelled` maps to cooperative cancellation or an
/// expired deadline observed at one of the parser's checkpoints. All carry a
/// human message that is not a machine contract.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The byte stream is not a structurally valid binary XML document.
    #[error("malformed binary XML: {0}")]
    Malformed(String),
    /// A decode limit from [`DecodeLimits`] was exceeded.
    #[error("resource limit exceeded: {0}")]
    Limit(String),
    /// The [`Cancel`] probe fired at a checkpoint: the host cancelled the
    /// operation or its deadline passed.
    #[error("cancelled at a decode checkpoint")]
    Cancelled,
}

/// Cooperative cancellation/deadline probe (AX-P06).
///
/// The parser consults it at chunk, string and attribute boundaries — the
/// same cadence class as its limit checks — and fails with
/// [`ParseError::Cancelled`] instead of spinning through a hostile document.
/// It never blocks or spawns; a probe that never fires makes the parse
/// unbounded in time exactly like upstream.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cancel<'a> {
    flag: Option<&'a std::sync::atomic::AtomicBool>,
    deadline: Option<std::time::Instant>,
}

impl<'a> Cancel<'a> {
    /// A probe that never fires (upstream behaviour).
    pub fn none() -> Cancel<'static> {
        Cancel { flag: None, deadline: None }
    }

    /// Cancels once `flag` is set.
    pub fn from_flag(flag: &'a std::sync::atomic::AtomicBool) -> Self {
        Cancel { flag: Some(flag), deadline: None }
    }

    /// Cancels once `deadline` passes.
    pub fn from_deadline(deadline: std::time::Instant) -> Self {
        Cancel { flag: None, deadline: Some(deadline) }
    }

    /// Combines a flag and a deadline; either firing cancels.
    pub fn from_flag_and_deadline(
        flag: &'a std::sync::atomic::AtomicBool,
        deadline: Option<std::time::Instant>,
    ) -> Self {
        Cancel { flag: Some(flag), deadline }
    }

    fn check(&self) -> Result<(), ParseError> {
        if self.flag.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
            return Err(ParseError::Cancelled);
        }
        if self.deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err(ParseError::Cancelled);
        }
        Ok(())
    }
}

///Parses an Android binary XML into the ordered [`Document`] model.
///
/// The whole declared document length is consumed before success is returned:
/// a second root element, trailing structural garbage, unmatched end tags or
/// end namespaces, duplicate attributes, out-of-range string indices and
/// oversized structures are all errors, never silent truncation.
///
/// # Errors
///
/// Returns [`ParseError`] if `input` cannot be parsed completely within
/// `limits`.
pub fn parse_document(input: &[u8], limits: &DecodeLimits) -> Result<Document, ParseError> {
    parse_document_with(input, limits, Cancel::none())
}

/// [`parse_document`] with a cooperative [`Cancel`] probe consulted at chunk,
/// string and attribute boundaries (AX-P06).
pub fn parse_document_with(
    input: &[u8],
    limits: &DecodeLimits,
    cancel: Cancel<'_>,
) -> Result<Document, ParseError> {
    binaryxml::parse(input, limits, cancel)
}

#[cfg(test)]
mod tests;
