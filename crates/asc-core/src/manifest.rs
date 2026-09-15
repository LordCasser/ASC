//! AndroidManifest.xml domain decoding: the ordered manifest document model,
//! the AXML/plain-XML entries that build it, and bounded XML serialization.
//!
//! Layering (openspec interfaces §1/§3): the vendored AXML backend turns
//! bytes into a bounded ordered vendor model; this module owns the *domain*
//! model — ordered nodes with namespace decomposition, typed raw values with
//! a readable projection, string styles and resource ids in metadata — and
//! never leaks vendor types. Plain-XML entries are read here with quick-xml
//! in pure pull mode: UTF-8, XML 1.0, predefined/numeric character references
//! only, no DTD and no I/O of any kind.
//!
//! Rendering contract: XML declaration, four-space indentation, LF; elements
//! with non-whitespace text or CDATA content stay inline so indentation can
//! never change text; illegal XML characters and names are errors, never
//! silent replacements; output length is bounded.

use crate::error::{Error, ErrorKind};
use crate::model::{Diagnostic, DiagnosticCode, DexText, Report, Severity, Stage};

const ANDROID_RES_URI: &str = "http://schemas.android.com/apk/res/android";
const CANONICAL_ANDROID_PREFIX: &str = "android";

// ---------------------------------------------------------------------------
// Limits, control, render options
// ---------------------------------------------------------------------------

/// Decode budgets for the manifest entries; defaults are the initial values
/// from interfaces.md §5 (depth 256, xml-nodes/xml-attributes 1_000_000,
/// string-units 1_048_576).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XmlDecodeLimits {
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_attributes: usize,
    pub max_string_units: usize,
}

impl Default for XmlDecodeLimits {
    fn default() -> Self {
        Self {
            max_depth: 256,
            max_nodes: 1_000_000,
            max_attributes: 1_000_000,
            max_string_units: 1_048_576,
        }
    }
}

/// Serialization budgets; defaults are `result-bytes` (128 MiB) and `depth`
/// (256) from interfaces.md §5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XmlRenderOptions {
    pub max_output_bytes: usize,
    pub max_depth: usize,
}

impl Default for XmlRenderOptions {
    fn default() -> Self {
        Self { max_output_bytes: 128 * 1024 * 1024, max_depth: 256 }
    }
}

/// Cancellation/deadline handle for the manifest operations. This is the
/// manifest-local stand-in for the engine-level control (A10/A11 freeze the
/// shared shape); it already carries the contract that matters here: checks
/// are cooperative, cancellation maps to `Cancelled` with a cause, and
/// nothing installs signal handlers or spawns threads.
// OperationControl lives in bytes.rs (ungated); re-exported here for the
// manifest API surface.
pub use crate::bytes::OperationControl;

// ---------------------------------------------------------------------------
// Domain model
// ---------------------------------------------------------------------------

/// A namespace binding event recorded on the element whose scope it opens or
/// closes, in stream order. `prefix == ""` is the default namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamespaceEvent {
    Start { prefix: String, uri: String },
    End { prefix: String, uri: String },
}

/// An attribute: decomposed name plus its value. `namespace` is the bound URI
/// when the name carried a resolvable prefix; `prefix` is the prefix exactly
/// as the source spelled it (`None` for unprefixed names).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlAttribute {
    pub(crate) namespace: Option<String>,
    pub(crate) prefix: Option<String>,
    pub(crate) local_name: String,
    pub(crate) value: ManifestValue,
}

// The public readers below are the A07/A08 surface (and the contract-test
// facts projection); the binary target itself has no caller for them until
// the engine integration lands.
#[allow(dead_code)]
impl XmlAttribute {
    pub fn namespace(&self) -> Option<String> {
        self.namespace.clone()
    }

    pub fn prefix(&self) -> Option<String> {
        self.prefix.clone()
    }

    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    pub fn value(&self) -> &ManifestValue {
        &self.value
    }
}

/// An attribute value: plain text (plain-XML entries and AXML raw strings)
/// or an AXML typed value whose raw `type`/`data` pair is the single fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestValue {
    Text(DexText),
    Typed(TypedValue),
}

impl ManifestValue {
    /// The value as renderable text; `None` only for a typed value whose
    /// raw string contains an unpaired surrogate (impossible via the
    /// decoders, which reject invalid UTF-16).
    pub fn as_text(&self) -> Option<String> {
        match self {
            ManifestValue::Text(text) => text.as_str(),
            ManifestValue::Typed(value) => Some(value.format()),
        }
    }

    #[allow(dead_code)]
    pub fn raw_typed(&self) -> Option<&TypedValue> {
        match self {
            ManifestValue::Text(_) => None,
            ManifestValue::Typed(value) => Some(value),
        }
    }
}

/// One AXML typed value kept bit-exact: `type_byte` and `data` exactly as the
/// document stored them, plus the raw string the attribute carried when the
/// encoder wrote one. `format()` projects to the readable form the Android
/// toolchain prints; it is derived data, never the source of truth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedValue {
    pub type_byte: u8,
    pub data: u32,
    /// Raw string index content (`rawValue`), when present.
    pub raw_string: Option<DexText>,
}

#[allow(dead_code)]
impl TypedValue {
    pub fn type_byte(&self) -> u8 {
        self.type_byte
    }

    pub fn data(&self) -> u32 {
        self.data
    }

    pub fn raw_string(&self) -> Option<&DexText> {
        self.raw_string.as_ref()
    }

    /// The readable projection (aapt/Androguard-compatible formatting,
    /// including the `<0x.., type 0x..>` fallback for unnamed types).
    pub fn format(&self) -> String {
        // The exact powers of two (2^-8, 2^-15, 2^-23, 2^-31). Rounding them
        // to seven digits shifts a large mantissa in the sixth decimal
        // (fraction mantissa 16384, radix 1 must print 50.000000%).
        const RADIX_MULTS: [f64; 4] = [
            0.003_906_25,
            3.051_757_812_5e-05,
            1.192_092_895_507_812_5e-07,
            4.656_612_873_077_393e-10,
        ];
        const DIMENSION_UNITS: [&str; 6] = ["px", "dip", "sp", "pt", "in", "mm"];
        const FRACTION_UNITS: [&str; 2] = ["%", "%p"];

        let data = self.data;
        let package = if data >> 24 == 1 { "android:" } else { "" };
        // AXML integers are signed; the reference sign-extends from bit 31.
        let signed =
            i64::from(data & 0x7fff_ffff) - if data > 0x7fff_ffff { i64::from(0x8000_0000u32) } else { 0 };
        let complex = f64::from(data & 0xffff_ff00) * RADIX_MULTS[((data >> 4) & 3) as usize];
        let unit = (data & 0x0f) as usize;

        match self.type_byte {
            0x01 => format!("@{package}{data:08X}"),
            0x02 => format!("?{package}{data:08X}"),
            0x03 => self
                .raw_string
                .as_ref()
                .and_then(DexText::as_str)
                .unwrap_or_default(),
            0x04 => format!("{:.6}", f64::from(f32::from_bits(data))),
            0x05 => format!(
                "{complex:.6}{}",
                DIMENSION_UNITS.get(unit).copied().unwrap_or("")
            ),
            0x06 => format!(
                "{:.6}{}",
                complex * 100.0,
                FRACTION_UNITS.get(unit).copied().unwrap_or("")
            ),
            0x10 => format!("{signed}"),
            0x11 => format!("0x{data:08X}"),
            0x12 => (if data == 0 { "false" } else { "true" }).to_string(),
            0x1c..=0x1f => format!("#{data:08X}"),
            _ => format!("<0x{data:X}, type 0x{:02X}>", self.type_byte),
        }
    }
}

/// One string style span from the AXML string pool, kept as metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StringStyleSpan {
    pub name_index: u32,
    pub first_char: u32,
    pub last_char: u32,
}

/// A styled string retained as metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringStyle {
    pub string_index: u32,
    pub spans: Vec<StringStyleSpan>,
}

/// Where the manifest document came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestSource {
    BinaryAxml { utf8_pool: bool, string_count: usize },
    PlainXml,
}

/// Document-level metadata the XML text cannot carry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManifestMetadata {
    pub source: Option<ManifestSource>,
    pub string_styles: Vec<StringStyle>,
    pub resource_map: Vec<u32>,
}

/// Element-level metadata: AXML line numbers and comments, plus the
/// namespace events recorded on this element.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ElementMetadata {
    pub line_number: Option<u32>,
    pub comment: Option<String>,
    pub namespace_events: Vec<NamespaceEvent>,
}

/// One element. Children keep document order; text between child nodes is a
/// `Text` child in its position, so node order plus text nodes fully cover
/// text *and* tail text without a separate tail field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlElement {
    pub(crate) namespace: Option<String>,
    pub(crate) prefix: Option<String>,
    pub(crate) local_name: String,
    pub(crate) attributes: Vec<XmlAttribute>,
    pub(crate) children: Vec<XmlNode>,
    pub(crate) metadata: ElementMetadata,
}

#[allow(dead_code)]
impl XmlElement {
    pub fn namespace(&self) -> Option<String> {
        self.namespace.clone()
    }

    pub fn prefix(&self) -> Option<String> {
        self.prefix.clone()
    }

    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    pub fn attributes(&self) -> &[XmlAttribute] {
        &self.attributes
    }

    pub fn children(&self) -> &[XmlNode] {
        &self.children
    }

    pub fn metadata(&self) -> &ElementMetadata {
        &self.metadata
    }
}

/// A node inside an element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XmlNode {
    Text { text: DexText },
    Cdata { data: DexText },
    Comment { text: String },
    Pi { target: String, data: String },
    Element(XmlElement),
}

/// Prolog/epilog items (comments, processing instructions, whitespace text)
/// in document position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Misc {
    Text(DexText),
    Comment(String),
    Pi { target: String, data: String },
}

/// The manifest document: declaration, ordered prolog, single root, ordered
/// epilog, and the metadata no XML projection can carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub(crate) declaration: Option<XmlDeclaration>,
    pub(crate) prolog: Vec<Misc>,
    pub(crate) root: XmlElement,
    pub(crate) epilog: Vec<Misc>,
    pub(crate) metadata: ManifestMetadata,
    /// Reserved: verbatim source bytes for the plain-XML raw-bytes exception
    /// (interfaces §6: a legal UTF-8 plain-XML manifest may keep its original
    /// bytes, preserving original newlines/BOM). The CLI output wiring that
    /// consumes it lands with A07/A08; until then it stays `None`.
    pub(crate) raw_bytes: Option<Vec<u8>>,
}

/// The XML declaration of a plain-XML entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlDeclaration {
    pub version: String,
    pub encoding: Option<String>,
    pub standalone: Option<String>,
}

#[allow(dead_code)]
impl Manifest {
    pub fn declaration(&self) -> Option<&XmlDeclaration> {
        self.declaration.as_ref()
    }

    pub fn prolog(&self) -> &[Misc] {
        &self.prolog
    }

    pub fn root(&self) -> &XmlElement {
        &self.root
    }

    pub fn epilog(&self) -> &[Misc] {
        &self.epilog
    }

    pub fn metadata(&self) -> &ManifestMetadata {
        &self.metadata
    }

    /// Reserved raw-bytes field (see the struct docs).
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        self.raw_bytes.as_deref()
    }

    /// Serializes the document to canonical XML: declaration, four-space
    /// indentation, LF. Mixed-text elements stay inline; illegal characters
    /// or names are errors; output length and depth are bounded.
    pub fn to_xml(&self, options: &XmlRenderOptions, control: &OperationControl) -> Result<String, Error> {
        control.check()?;
        let mut writer = BoundedWriter::new(options.max_output_bytes, control);
        // Join semantics: the declaration line, every layout item (comments,
        // PIs) and the root are joined with single newlines, so the last line
        // carries no trailing newline and whitespace Misc items (which only
        // pin document position) contribute nothing to the text.
        writer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>")?;
        // The declaration line is written content, so every following item
        // starts on its own line.
        for item in &self.prolog {
            render_misc(item, 0, &mut writer, true)?;
        }
        writer.push_str("\n")?;
        render_element(&self.root, 0, &mut writer, options)?;
        for item in &self.epilog {
            render_misc(item, 0, &mut writer, true)?;
        }
        Ok(writer.finish())
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Decodes one manifest entry's bytes into the domain document.
///
/// Dispatch: valid UTF-8 whose first non-whitespace character is `<` (after a
/// UTF-8 BOM) is read as plain XML; a binary-XML document chunk is read as
/// AXML; anything else — including wrongly encoded text — is a malformed
/// input.
pub fn decode_manifest_entry(
    bytes: &[u8],
    limits: &XmlDecodeLimits,
    control: &OperationControl,
) -> Result<Report<Manifest>, Error> {
    control.check()?;
    if let Some(utf16_bom) = utf16_bom(bytes) {
        return Err(Error::new(ErrorKind::UnsupportedFormat).with_context(format!(
            "plain XML with a UTF-16 BOM ({utf16_bom}) is outside the supported matrix; \
             only UTF-8 is accepted"
        )));
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        if text.trim_start().starts_with('<') {
            return decode_plain_xml(text, limits, control);
        }
    }
    if looks_like_axml(bytes) {
        return decode_axml(bytes, limits, control);
    }
    Err(Error::malformed_input(
        "manifest entry is neither a binary AXML document nor UTF-8 XML text",
    ))
}

fn utf16_bom(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [0xFF, 0xFE, ..] => Some("FF FE"),
        [0xFE, 0xFF, ..] => Some("FE FF"),
        _ => None,
    }
}

fn looks_like_axml(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let type_word = u16::from_le_bytes([bytes[0], bytes[1]]);
    let header_size = u16::from_le_bytes([bytes[2], bytes[3]]);
    let size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    type_word == 0x0003 && header_size >= 8 && usize::try_from(size).is_ok_and(|s| s <= bytes.len())
}

fn malformed(message: impl Into<String>) -> Error {
    Error::malformed_input(message)
}

fn unsupported_format(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::UnsupportedFormat).with_context(message)
}

fn resource_limit(message: impl Into<String>) -> Error {
    Error::resource_limit(message)
}

// ---------------------------------------------------------------------------
// AXML entry: vendor document -> domain document
// ---------------------------------------------------------------------------

struct AxmlConverter {
    diagnostics: Vec<Diagnostic>,
    inferred_namespace: bool,
}

/// One binding on the namespace scope stack; `prefix == ""` is the default.
struct Binding {
    prefix: String,
    uri: String,
}

fn decode_axml(
    bytes: &[u8],
    limits: &XmlDecodeLimits,
    control: &OperationControl,
) -> Result<Report<Manifest>, Error> {
    let vendor_limits = axmldecoder::DecodeLimits {
        max_depth: limits.max_depth,
        max_nodes: limits.max_nodes,
        max_attributes: limits.max_attributes,
        max_string_units: limits.max_string_units,
    };
    // AX-P06: the vendor parser consults this probe at its chunk, string and
    // attribute checkpoints, so a hostile manifest is deadline-bounded
    // instead of only checkable between decodes.
    let cancel_flag = control.cancel_flag();
    let deadline = control.deadline();
    let cancel = match &cancel_flag {
        Some(flag) => axmldecoder::Cancel::from_flag_and_deadline(flag, deadline),
        None => match deadline {
            Some(deadline) => axmldecoder::Cancel::from_deadline(deadline),
            None => axmldecoder::Cancel::none(),
        },
    };
    let document =
        axmldecoder::parse_document_with(bytes, &vendor_limits, cancel).map_err(|error| match error {
            axmldecoder::ParseError::Malformed(message) => malformed(message),
            axmldecoder::ParseError::Limit(message) => resource_limit(message),
            axmldecoder::ParseError::Cancelled => {
                let cause = if control
                    .deadline()
                    .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                {
                    crate::error::CancelCause::Deadline
                } else {
                    crate::error::CancelCause::User
                };
                Error::new(ErrorKind::Cancelled { cause })
                    .with_context("manifest decode cancelled at a checkpoint")
            }
        })?;
    control.check()?;

    let mut converter = AxmlConverter { diagnostics: Vec::new(), inferred_namespace: false };
    let mut scopes: Vec<Binding> = Vec::new();
    let mut node_count: usize = 0;
    let root = convert_element(&document.root, &mut scopes, &mut converter, limits, &mut node_count, control)?;

    let metadata = ManifestMetadata {
        source: Some(ManifestSource::BinaryAxml {
            utf8_pool: document.string_pool.is_utf8,
            string_count: document.string_pool.strings.len(),
        }),
        string_styles: document
            .string_pool
            .styles
            .iter()
            .map(|(index, spans)| StringStyle {
                string_index: *index,
                spans: spans
                    .iter()
                    .map(|span| StringStyleSpan {
                        name_index: span.name,
                        first_char: span.first_char,
                        last_char: span.last_char,
                    })
                    .collect(),
            })
            .collect(),
        resource_map: document.resource_map.clone(),
    };
    Ok(Report::new(
        Manifest { declaration: None, prolog: Vec::new(), root, epilog: Vec::new(), metadata, raw_bytes: None },
        converter.diagnostics,
        crate::model::OperationStats::default(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn convert_element(
    element: &axmldecoder::Element,
    scopes: &mut Vec<Binding>,
    converter: &mut AxmlConverter,
    limits: &XmlDecodeLimits,
    node_count: &mut usize,
    control: &OperationControl,
) -> Result<XmlElement, Error> {
    *node_count += 1;
    if *node_count > limits.max_nodes {
        return Err(resource_limit(format!(
            "document exceeds the node limit of {}",
            limits.max_nodes
        )));
    }
    if scopes.len() + 1 > limits.max_depth {
        return Err(resource_limit(format!(
            "document nesting exceeds the depth limit of {}",
            limits.max_depth
        )));
    }
    let scope_depth = scopes.len();
    let mut attributes: Vec<XmlAttribute> = Vec::new();
    let mut events: Vec<NamespaceEvent> = Vec::new();

    // Namespace starts recorded on this element become explicit xmlns
    // attributes; ends unwind their binding. Events apply before names
    // resolve, matching the AXML stream where the start chunk precedes the
    // element it binds for.
    for event in &element.namespace_events {
        match event {
            axmldecoder::NamespaceEvent::Start { prefix, uri } => {
                scopes.push(Binding { prefix: prefix.clone(), uri: uri.clone() });
                events.push(NamespaceEvent::Start { prefix: prefix.clone(), uri: uri.clone() });
                // The binding becomes an explicit xmlns attribute; the empty
                // prefix is the default namespace (`xmlns="..."`).
                let (attr_prefix, attr_local) = if prefix.is_empty() {
                    (None, "xmlns".to_owned())
                } else {
                    (Some("xmlns".to_owned()), prefix.clone())
                };
                attributes.push(XmlAttribute {
                    namespace: None,
                    prefix: attr_prefix,
                    local_name: attr_local,
                    value: ManifestValue::Text(DexText::from_str_lossless(uri)),
                });
            }
            axmldecoder::NamespaceEvent::End { prefix, uri } => {
                events.push(NamespaceEvent::End { prefix: prefix.clone(), uri: uri.clone() });
                let position = scopes
                    .iter()
                    .rposition(|binding| &binding.prefix == prefix && &binding.uri == uri)
                    .ok_or_else(|| {
                        malformed(format!(
                            "end namespace ({prefix}, {uri}) has no matching binding in scope"
                        ))
                    })?;
                scopes.truncate(position);
            }
        }
    }

    let prefix_for = |scopes: &mut Vec<Binding>,
                      converter: &mut AxmlConverter,
                      uri: &str,
                      attributes: &mut Vec<XmlAttribute>,
                      allow_default: bool|
     -> Result<Option<String>, Error> {
        if let Some(prefix) = find_prefix(scopes, uri, allow_default) {
            if !allow_default && prefix.is_empty() {
                return Err(malformed(format!(
                    "namespace {uri} is only bound as the default namespace, which attributes \
                     cannot use"
                )));
            }
            return Ok(Some(prefix));
        }
        if uri == ANDROID_RES_URI {
            // The declaration is missing but the URI is unambiguous; add the
            // explicit canonical binding and report it once.
            scopes.push(Binding {
                prefix: CANONICAL_ANDROID_PREFIX.to_owned(),
                uri: uri.to_owned(),
            });
            attributes.push(XmlAttribute {
                namespace: None,
                prefix: Some("xmlns".to_owned()),
                local_name: CANONICAL_ANDROID_PREFIX.to_owned(),
                value: ManifestValue::Text(DexText::from_str_lossless(ANDROID_RES_URI)),
            });
            if !converter.inferred_namespace {
                converter.inferred_namespace = true;
                converter.diagnostics.push(Diagnostic::new(
                    DiagnosticCode::InferredNamespaceBinding,
                    Severity::Warning,
                    Stage::Manifest,
                    format!(
                        "the document declares no namespace binding for {ANDROID_RES_URI}; \
                         the canonical prefix '{CANONICAL_ANDROID_PREFIX}' was added explicitly"
                    ),
                ));
            }
            return Ok(Some(CANONICAL_ANDROID_PREFIX.to_owned()));
        }
        Err(malformed(format!(
            "cannot determine a prefix for namespace URI {uri}: the document declares no \
             binding for it"
        )))
    };

    let prefix = match &element.namespace {
        Some(uri) => {
            let prefix = prefix_for(scopes, converter, uri, &mut attributes, true)?;
            // The default namespace renders without a prefix.
            match prefix.as_deref() {
                Some("") | None => None,
                Some(prefix) => Some(prefix.to_owned()),
            }
        }
        None => None,
    };

    for attribute in &element.attributes {
        let attr_prefix = match &attribute.namespace {
            Some(uri) => {
                let found = prefix_for(scopes, converter, uri, &mut attributes, false)?;
                match found {
                    Some(p) if !p.is_empty() => Some(p),
                    _ => {
                        return Err(malformed(format!(
                            "attribute {} is in namespace {uri} which is only bound as the \
                             default namespace; attributes need an explicit prefix",
                            attribute.name
                        )))
                    }
                }
            }
            None => None,
        };
        let value = ManifestValue::Typed(TypedValue {
            type_byte: attribute.value.type_byte,
            data: attribute.value.data,
            raw_string: attribute.raw_value.as_deref().map(DexText::from_str_lossless),
        });
        attributes.push(XmlAttribute {
            namespace: attribute.namespace.clone(),
            prefix: attr_prefix,
            local_name: attribute.name.clone(),
            value,
        });
    }

    let mut children = Vec::new();
    for child in &element.children {
        match child {
            axmldecoder::Node::Element(inner) => {
                let converted =
                    convert_element(inner, scopes, converter, limits, node_count, control)?;
                children.push(XmlNode::Element(converted));
            }
            axmldecoder::Node::Cdata(cdata) => {
                *node_count += 1;
                if *node_count > limits.max_nodes {
                    return Err(resource_limit(format!(
                        "document exceeds the node limit of {}",
                        limits.max_nodes
                    )));
                }
                control.check()?;
                children.push(XmlNode::Cdata { data: DexText::from_str_lossless(&cdata.data) });
            }
        }
    }

    scopes.truncate(scope_depth);
    Ok(XmlElement {
        namespace: element.namespace.clone(),
        prefix,
        local_name: element.name.clone(),
        attributes,
        children,
        metadata: ElementMetadata {
            line_number: Some(element.line_number),
            comment: element.comment.clone(),
            namespace_events: events,
        },
    })
}

/// Innermost non-default prefix bound to `uri` (`allow_default` accepts the
/// empty prefix, which only elements may use).
fn find_prefix(scopes: &[Binding], uri: &str, allow_default: bool) -> Option<String> {
    scopes
        .iter()
        .rev()
        .find(|binding| binding.uri == uri && (allow_default || !binding.prefix.is_empty()))
        .map(|binding| binding.prefix.clone())
}

// ---------------------------------------------------------------------------
// Plain-XML entry (quick-xml pull reader)
// ---------------------------------------------------------------------------

struct PlainXmlBuilder {
    declaration: Option<XmlDeclaration>,
    prolog: Vec<Misc>,
    epilog: Vec<Misc>,
    stack: Vec<PlainOpenElement>,
    scopes: Vec<Binding>,
    root: Option<XmlElement>,
    node_count: usize,
    attribute_count: usize,
}

struct PlainOpenElement {
    namespace: Option<String>,
    prefix: Option<String>,
    local_name: String,
    qname: String,
    attributes: Vec<XmlAttribute>,
    children: Vec<XmlNode>,
    events: Vec<NamespaceEvent>,
}

fn decode_plain_xml(
    text: &str,
    limits: &XmlDecodeLimits,
    control: &OperationControl,
) -> Result<Report<Manifest>, Error> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(text);
    let config = reader.config_mut();
    config.check_end_names = true;
    config.check_comments = true;
    config.expand_empty_elements = false;

    let mut builder = PlainXmlBuilder {
        declaration: None,
        prolog: Vec::new(),
        epilog: Vec::new(),
        stack: Vec::new(),
        scopes: Vec::new(),
        root: None,
        node_count: 0,
        attribute_count: 0,
    };
    // A pending text run: quick-xml 0.42 splits text at entity references, so
    // raw segments and reassembled `&..;` forms accumulate here and unescape
    // once, when the run ends.
    let mut pending_text = String::new();

    loop {
        control.check()?;
        let event = reader
            .read_event()
            .map_err(|error| malformed(format!("plain XML is not well-formed: {error}")))?;
        let is_text_like = matches!(event, Event::Text(_) | Event::GeneralRef(_));
        if !is_text_like && !pending_text.is_empty() {
            let text = flush_text(&mut pending_text)?;
            push_plain_text(&mut builder, text, limits.max_nodes)?;
        }
        match event {
            Event::Decl(decl) => {
                if builder.declaration.is_some() || !builder.stack.is_empty() || builder.root.is_some() {
                    return Err(malformed("XML declaration appears after the document start"));
                }
                let version = decl
                    .version()
                    .map_err(|error| malformed(format!("unreadable XML declaration: {error}")))?
                    .to_string();
                if version != "1.0" {
                    return Err(unsupported_format(format!(
                        "XML version '{version}' is outside the supported matrix; only 1.0 is accepted"
                    )));
                }
                let encoding = match decl.encoding() {
                    Some(Ok(encoding)) => {
                        if !encoding.eq_ignore_ascii_case("utf-8") {
                            return Err(unsupported_format(format!(
                                "declared XML encoding '{encoding}' is outside the supported \
                                 matrix; only UTF-8 is accepted"
                            )));
                        }
                        Some(encoding.to_string())
                    }
                    Some(Err(error)) => {
                        return Err(malformed(format!("unreadable encoding declaration: {error}")))
                    }
                    None => None,
                };
                let standalone = match decl.standalone() {
                    Some(Ok(standalone)) => Some(standalone.to_string()),
                    Some(Err(error)) => {
                        return Err(malformed(format!("unreadable standalone declaration: {error}")))
                    }
                    None => None,
                };
                builder.declaration =
                    Some(XmlDeclaration { version, encoding, standalone });
            }
            Event::DocType(_) => {
                return Err(unsupported_format(
                    "DTD/DOCTYPE declarations are rejected: no DTD subset is processed and no \
                     external entity or file access of any kind is performed",
                ));
            }
            Event::PI(pi) => {
                let target = pi.target().to_owned();
                // The whitespace separating the target from the content is
                // not part of the content (XML 1.0 PI production).
                let data = pi
                    .content()
                    .trim_start_matches([' ', '\t', '\r', '\n'])
                    .to_owned();
                if target.eq_ignore_ascii_case("xml") {
                    return Err(malformed("reserved processing-instruction target 'xml'"));
                }
                if !is_valid_xml_name(&target) {
                    return Err(malformed(format!("invalid processing-instruction target {target:?}")));
                }
                builder.node_count += 1;
                check_node_limit(builder.node_count, limits)?;
                let node = Misc::Pi { target, data };
                place_misc(&mut builder, node)?;
            }
            Event::Comment(comment) => {
                let text = comment.as_ref().to_owned();
                if text.contains("--") || text.ends_with('-') {
                    return Err(malformed("comment content contains a forbidden '--' sequence"));
                }
                builder.node_count += 1;
                check_node_limit(builder.node_count, limits)?;
                let node = Misc::Comment(text);
                place_misc(&mut builder, node)?;
            }
            Event::Text(text) => {
                pending_text.push_str(&text.xml10_content());
            }
            Event::GeneralRef(reference) => {
                pending_text.push('&');
                pending_text.push_str(reference.as_ref());
                pending_text.push(';');
            }
            Event::CData(cdata) => {
                builder.node_count += 1;
                check_node_limit(builder.node_count, limits)?;
                if let Some(open) = builder.stack.last_mut() {
                    open.children
                        .push(XmlNode::Cdata { data: DexText::from_str_lossless(cdata.as_ref()) });
                } else {
                    return Err(malformed(
                        "CDATA is not allowed outside the root element",
                    ));
                }
            }
            Event::Start(start) => {
                let element = open_plain_element(&mut builder, &start, limits)?;
                builder.stack.push(element);
                if builder.stack.len() > limits.max_depth {
                    return Err(resource_limit(format!(
                        "document nesting exceeds the depth limit of {}",
                        limits.max_depth
                    )));
                }
            }
            Event::Empty(start) => {
                let element = open_plain_element(&mut builder, &start, limits)?;
                close_plain_element(&mut builder, element)?;
            }
            Event::End(end) => {
                let open = builder.stack.pop().ok_or_else(|| {
                    malformed(format!(
                        "end tag </{}> without a matching start tag",
                        end.as_ref()
                    ))
                })?;
                if open.qname != end.as_ref() {
                    return Err(malformed(format!(
                        "end tag </{}> does not match the open start tag <{}>",
                        end.as_ref(),
                        open.qname
                    )));
                }
                let element = finish_plain_element(open);
                attach_plain_element(&mut builder, element)?;
            }
            Event::Eof => break,
        }
    }
    if !pending_text.is_empty() {
        let text = flush_text(&mut pending_text)?;
        push_plain_text(&mut builder, text, limits.max_nodes)?;
    }
    if !builder.stack.is_empty() {
        return Err(malformed("unclosed element at the end of the document"));
    }
    let root = builder.root.take().ok_or_else(|| malformed("plain XML has no root element"))?;
    control.check()?;
    Ok(Report::new(
        Manifest {
            declaration: builder.declaration.take(),
            prolog: builder.prolog,
            root,
            epilog: builder.epilog,
            metadata: ManifestMetadata {
                source: Some(ManifestSource::PlainXml),
                string_styles: Vec::new(),
                resource_map: Vec::new(),
            },
            raw_bytes: None,
        },
        Vec::new(),
        crate::model::OperationStats::default(),
    ))
}

fn check_node_limit(count: usize, limits: &XmlDecodeLimits) -> Result<(), Error> {
    if count > limits.max_nodes {
        return Err(resource_limit(format!(
            "document exceeds the node limit of {}",
            limits.max_nodes
        )));
    }
    Ok(())
}

/// Unescapes one accumulated text run; only the predefined entities and
/// numeric character references are legal without a DTD.
fn flush_text(pending: &mut String) -> Result<DexText, Error> {
    let text = quick_xml::escape::unescape(pending)
        .map_err(|error| malformed(format!("undefined entity or bad character reference: {error}")))?
        .into_owned();
    pending.clear();
    Ok(DexText::from_str_lossless(&text))
}

fn push_plain_text(builder: &mut PlainXmlBuilder, text: DexText, max_nodes: usize) -> Result<(), Error> {
    let is_whitespace =
        text.as_str().is_some_and(|text| text.chars().all(char::is_whitespace));
    if builder.stack.last().is_some() && is_whitespace {
        // Layout whitespace between an element's tags is ignorable: the AXML
        // twin never carries it, so the domain model does not either. (Text
        // with any non-whitespace content, including leading/trailing
        // whitespace around it, is kept verbatim.)
        return Ok(());
    }
    builder.node_count += 1;
    if builder.node_count > max_nodes {
        return Err(resource_limit(format!(
            "document exceeds the node limit of {max_nodes}"
        )));
    }
    if let Some(open) = builder.stack.last_mut() {
        open.children.push(XmlNode::Text { text });
        Ok(())
    } else if is_whitespace {
        // Whitespace between prolog/epilog items is legal Misc filler.
        let misc = Misc::Text(text);
        place_misc(builder, misc)
    } else {
        Err(malformed("text content outside the root element"))
    }
}

/// Places a comment/PI/whitespace item in the prolog (before the root), the
/// current element, or the epilog.
fn place_misc(builder: &mut PlainXmlBuilder, node: Misc) -> Result<(), Error> {
    if let Some(open) = builder.stack.last_mut() {
        let node = match node {
            Misc::Comment(text) => XmlNode::Comment { text },
            Misc::Pi { target, data } => XmlNode::Pi { target, data },
            Misc::Text(text) => XmlNode::Text { text },
        };
        open.children.push(node);
        Ok(())
    } else if builder.root.is_none() {
        builder.prolog.push(node);
        Ok(())
    } else {
        builder.epilog.push(node);
        Ok(())
    }
}

fn open_plain_element(
    builder: &mut PlainXmlBuilder,
    start: &quick_xml::events::BytesStart<'_>,
    limits: &XmlDecodeLimits,
) -> Result<PlainOpenElement, Error> {
    builder.node_count += 1;
    check_node_limit(builder.node_count, limits)?;
    if builder.stack.is_empty() && builder.root.is_some() {
        return Err(malformed("document has a second root element"));
    }
    let qname = start.name().as_ref().to_owned();
    let (local_name, prefix) = split_qname(&qname);
    if !is_valid_xml_name(local_name) {
        return Err(malformed(format!("invalid element name {qname:?}")));
    }
    let mut open = PlainOpenElement {
        namespace: None,
        prefix: prefix.map(str::to_owned),
        local_name: local_name.to_owned(),
        qname,
        attributes: Vec::new(),
        children: Vec::new(),
        events: Vec::new(),
    };
    // Element bindings from xmlns attributes enter scope for this element.
    let mut new_bindings: Vec<Binding> = Vec::new();
    for attribute in start.attributes().with_checks(true) {
        let attribute =
            attribute.map_err(|error| malformed(format!("malformed attribute: {error}")))?;
        let key = attribute.key.as_ref();
        let value = attribute
            .normalized_value(quick_xml::XmlVersion::Explicit1_0)
            .map_err(|error| malformed(format!("malformed attribute value: {error}")))?
            .into_owned();
        if open.attributes.iter().any(|existing| {
            attribute_prefix_of(key) == existing.prefix && local_of(key) == existing.local_name
        }) {
            return Err(malformed(format!("duplicate attribute {key:?}")));
        }
        if key == "xmlns" {
            new_bindings.push(Binding { prefix: String::new(), uri: value.clone() });
            open.events.push(NamespaceEvent::Start { prefix: String::new(), uri: value.clone() });
            open.attributes.push(XmlAttribute {
                namespace: None,
                prefix: None,
                local_name: "xmlns".to_owned(),
                value: ManifestValue::Text(DexText::from_str_lossless(&value)),
            });
        } else if let Some(bound_prefix) = key.strip_prefix("xmlns:") {
            if !is_valid_xml_name(bound_prefix) {
                return Err(malformed(format!("invalid namespace prefix in {key:?}")));
            }
            new_bindings.push(Binding { prefix: bound_prefix.to_owned(), uri: value.clone() });
            open.events
                .push(NamespaceEvent::Start { prefix: bound_prefix.to_owned(), uri: value.clone() });
            open.attributes.push(XmlAttribute {
                namespace: None,
                prefix: Some("xmlns".to_owned()),
                local_name: bound_prefix.to_owned(),
                value: ManifestValue::Text(DexText::from_str_lossless(&value)),
            });
        } else {
            let (attr_local, attr_prefix) = split_qname(key);
            if let Some(prefix) = attr_prefix
                && !is_valid_xml_name(prefix)
            {
                return Err(malformed(format!("invalid attribute name {key:?}")));
            }
            if !is_valid_xml_name(attr_local) {
                return Err(malformed(format!("invalid attribute name {key:?}")));
            }
            open.attributes.push(XmlAttribute {
                namespace: None,
                prefix: attr_prefix.map(str::to_owned),
                local_name: attr_local.to_owned(),
                value: ManifestValue::Text(DexText::from_str_lossless(&value)),
            });
        }
        builder.attribute_count += 1;
        if builder.attribute_count > limits.max_attributes {
            return Err(resource_limit(format!(
                "document exceeds the attribute limit of {}",
                limits.max_attributes
            )));
        }
    }
    open.namespace = open
        .prefix
        .as_deref()
        .and_then(|prefix| find_uri(&builder.scopes, prefix).or_else(|| find_uri(&new_bindings, prefix)));
    builder.scopes.append(&mut new_bindings);
    // All of this element's xmlns declarations apply to its own prefixed
    // names too, wherever in the tag they appeared; resolve them now that
    // the bindings are in scope. An undeclared prefix keeps `namespace: None`
    // (the document stays well-formed XML, just not namespace-well-formed).
    for attribute in &mut open.attributes {
        if let Some(prefix) = attribute.prefix.as_deref()
            && prefix != "xmlns"
            && attribute.namespace.is_none()
        {
            attribute.namespace = find_uri(&builder.scopes, prefix);
        }
    }
    Ok(open)
}

fn find_uri(scopes: &[Binding], prefix: &str) -> Option<String> {
    scopes
        .iter()
        .rev()
        .find(|binding| binding.prefix == prefix)
        .map(|binding| binding.uri.clone())
}

fn split_qname(qname: &str) -> (&str, Option<&str>) {
    match qname.split_once(':') {
        Some((prefix, local)) => (local, Some(prefix)),
        None => (qname, None),
    }
}

fn local_of(key: &str) -> &str {
    split_qname(key).0
}

fn attribute_prefix_of(key: &str) -> Option<String> {
    split_qname(key).1.map(str::to_owned)
}

fn close_plain_element(builder: &mut PlainXmlBuilder, open: PlainOpenElement) -> Result<(), Error> {
    let element = finish_plain_element(open);
    attach_plain_element(builder, element)
}

fn finish_plain_element(open: PlainOpenElement) -> XmlElement {
    XmlElement {
        namespace: open.namespace,
        prefix: open.prefix,
        local_name: open.local_name,
        attributes: open.attributes,
        children: open.children,
        metadata: ElementMetadata {
            line_number: None,
            comment: None,
            namespace_events: open.events,
        },
    }
}

fn attach_plain_element(builder: &mut PlainXmlBuilder, element: XmlElement) -> Result<(), Error> {
    // Each xmlns declaration on this element pushed one binding.
    let pushed = element.metadata.namespace_events.len();
    match builder.stack.last_mut() {
        Some(parent) => parent.children.push(XmlNode::Element(element)),
        None => builder.root = Some(element),
    }
    let target = builder.scopes.len().saturating_sub(pushed);
    builder.scopes.truncate(target);
    Ok(())
}

// ---------------------------------------------------------------------------
// XML serialization
// ---------------------------------------------------------------------------

/// Output writer with a hard byte budget and cooperative cancellation
/// checkpoints every 64 KiB.
struct BoundedWriter<'a> {
    out: String,
    max: usize,
    since_check: usize,
    control: &'a OperationControl,
}

const CONTROL_CHECK_INTERVAL: usize = 64 * 1024;

impl BoundedWriter<'_> {
    fn new(max: usize, control: &OperationControl) -> BoundedWriter<'_> {
        BoundedWriter { out: String::new(), max, since_check: 0, control }
    }

    fn push_str(&mut self, chunk: &str) -> Result<(), Error> {
        if self.out.len().saturating_add(chunk.len()) > self.max {
            return Err(resource_limit(format!(
                "serialized XML exceeds the output limit of {} bytes",
                self.max
            )));
        }
        self.since_check += chunk.len();
        if self.since_check >= CONTROL_CHECK_INTERVAL {
            self.control.check()?;
            self.since_check = 0;
        }
        self.out.push_str(chunk);
        Ok(())
    }

    fn indent(&mut self, depth: usize) -> Result<(), Error> {
        for _ in 0..depth {
            self.push_str("    ")?;
        }
        Ok(())
    }

    fn finish(self) -> String {
        self.out
    }
}

/// Renders one prolog/epilog item; returns whether it contributed content
/// (whitespace text only pins document position and writes nothing). When
/// `pending_separator` is set the item starts on a fresh line.
fn render_misc(
    item: &Misc,
    depth: usize,
    writer: &mut BoundedWriter<'_>,
    pending_separator: bool,
) -> Result<bool, Error> {
    match item {
        Misc::Text(text) => {
            let text = text_string(text)?;
            if !text.chars().all(char::is_whitespace) {
                return Err(malformed("non-whitespace text outside the root element"));
            }
            Ok(false)
        }
        Misc::Comment(text) => {
            if pending_separator {
                writer.push_str("\n")?;
            }
            writer.indent(depth)?;
            write_comment(text, writer)?;
            Ok(true)
        }
        Misc::Pi { target, data } => {
            if pending_separator {
                writer.push_str("\n")?;
            }
            writer.indent(depth)?;
            if !is_valid_xml_name(target) || target.eq_ignore_ascii_case("xml") {
                return Err(malformed(format!("invalid processing-instruction target {target:?}")));
            }
            writer.push_str("<?")?;
            write_verbatim(target, writer)?;
            writer.push_str(" ")?;
            write_verbatim(data, writer)?;
            writer.push_str("?>")?;
            Ok(true)
        }
    }
}

/// Comment content: raw text, characters validated, no escaping (comments
/// have no entities and escaping would change their content).
fn write_comment(text: &str, writer: &mut BoundedWriter<'_>) -> Result<(), Error> {
    if text.contains("--") || text.ends_with('-') {
        return Err(malformed("comment content contains a forbidden '--' sequence"));
    }
    writer.push_str("<!--")?;
    write_verbatim(text, writer)?;
    writer.push_str("-->")
}

/// Validates every character and writes the text unchanged.
fn write_verbatim(text: &str, writer: &mut BoundedWriter<'_>) -> Result<(), Error> {
    for character in text.chars() {
        check_xml_char(character)?;
        writer.push_char(character)?;
    }
    Ok(())
}

/// `Err` only for unpaired surrogates, which the decoders reject; the model
/// can only hold them if constructed by hand.
fn text_string(text: &DexText) -> Result<String, Error> {
    text.as_str()
        .ok_or_else(|| Error::unsupported_encoding("text contains an unpaired UTF-16 surrogate"))
}

fn render_element(
    element: &XmlElement,
    depth: usize,
    writer: &mut BoundedWriter<'_>,
    options: &XmlRenderOptions,
) -> Result<(), Error> {
    if depth + 1 > options.max_depth {
        return Err(resource_limit(format!(
            "serialized XML nesting exceeds the render depth limit of {}",
            options.max_depth
        )));
    }
    writer.indent(depth)?;
    render_element_inline(element, depth, writer, options)
}

/// The element body without leading indentation; mixed content runs inline so
/// indentation can never change text (interfaces §1).
fn render_element_inline(
    element: &XmlElement,
    depth: usize,
    writer: &mut BoundedWriter<'_>,
    options: &XmlRenderOptions,
) -> Result<(), Error> {
    if depth + 1 > options.max_depth {
        return Err(resource_limit(format!(
            "serialized XML nesting exceeds the render depth limit of {}",
            options.max_depth
        )));
    }
    writer.push_str("<")?;
    write_qualified_name(element.prefix.as_deref(), &element.local_name, writer)?;
    for attribute in &element.attributes {
        writer.push_str(" ")?;
        write_qualified_name(attribute.prefix.as_deref(), &attribute.local_name, writer)?;
        writer.push_str("=\"")?;
        let value = attribute.value.as_text().ok_or_else(|| {
            Error::unsupported_encoding("attribute value contains an unpaired UTF-16 surrogate")
        })?;
        escape_attribute_value(&value, writer)?;
        writer.push_str("\"")?;
    }
    if element.children.is_empty() {
        writer.push_str(" />")?;
        return Ok(());
    }
    writer.push_str(">")?;
    // Mixed content: any non-whitespace text or CDATA keeps the element
    // inline, so indentation can never change text.
    let mixed = element.children.iter().any(|child| match child {
        XmlNode::Text { text } => !text
            .as_str()
            .map(|text| text.chars().all(char::is_whitespace))
            .unwrap_or(false),
        XmlNode::Cdata { .. } => true,
        XmlNode::Comment { .. } | XmlNode::Pi { .. } | XmlNode::Element(_) => false,
    });
    if mixed {
        for child in &element.children {
            render_child_inline(child, depth, writer, options)?;
        }
    } else {
        for child in &element.children {
            match child {
                XmlNode::Element(inner) => {
                    writer.push_str("\n")?;
                    render_element(inner, depth + 1, writer, options)?;
                }
                XmlNode::Text { .. } => {}
                XmlNode::Comment { text } => {
                    writer.push_str("\n")?;
                    writer.indent(depth + 1)?;
                    write_comment(text, writer)?;
                }
                XmlNode::Pi { target, data } => {
                    writer.push_str("\n")?;
                    writer.indent(depth + 1)?;
                    writer.push_str("<?")?;
                    write_verbatim(target, writer)?;
                    writer.push_str(" ")?;
                    write_verbatim(data, writer)?;
                    writer.push_str("?>")?;
                }
                XmlNode::Cdata { data } => {
                    writer.push_str("\n")?;
                    writer.indent(depth + 1)?;
                    write_cdata(data, writer)?;
                }
            }
        }
        writer.push_str("\n")?;
        writer.indent(depth)?;
    }
    writer.push_str("</")?;
    write_qualified_name(element.prefix.as_deref(), &element.local_name, writer)?;
    writer.push_str(">")?;
    Ok(())
}

fn render_child_inline(
    child: &XmlNode,
    depth: usize,
    writer: &mut BoundedWriter<'_>,
    options: &XmlRenderOptions,
) -> Result<(), Error> {
    match child {
        XmlNode::Text { text } => {
            let text = text_string(text)?;
            escape_text(&text, writer)?;
        }
        XmlNode::Cdata { data } => write_cdata(data, writer)?,
        XmlNode::Comment { text } => write_comment(text, writer)?,
        XmlNode::Pi { target, data } => {
            writer.push_str("<?")?;
            write_verbatim(target, writer)?;
            writer.push_str(" ")?;
            write_verbatim(data, writer)?;
            writer.push_str("?>")?;
        }
        XmlNode::Element(inner) => render_element_inline(inner, depth + 1, writer, options)?,
    }
    Ok(())
}

fn write_qualified_name(prefix: Option<&str>, local: &str, writer: &mut BoundedWriter<'_>) -> Result<(), Error> {
    // Prefix and local part are each validated as XML `Name`s; the combined
    // `prefix:local` form is exactly one colon apart, which the Name
    // production itself forbids but a qualified name requires.
    if !is_valid_xml_name(local) {
        return Err(malformed(format!("invalid XML name {local:?}")));
    }
    let name = match prefix {
        Some(prefix) if !prefix.is_empty() => {
            if !is_valid_xml_name(prefix) {
                return Err(malformed(format!("invalid XML name {prefix:?}")));
            }
            format!("{prefix}:{local}")
        }
        _ => local.to_owned(),
    };
    writer.push_str(&name)
}

fn write_cdata(data: &DexText, writer: &mut BoundedWriter<'_>) -> Result<(), Error> {
    let data = data.as_str().ok_or_else(|| {
        Error::unsupported_encoding("CDATA contains an unpaired UTF-16 surrogate")
    })?;
    writer.push_str("<![CDATA[")?;
    // Split `]]>` without inserting characters: `]]]]><![CDATA[>`.
    let mut rest = data.as_str();
    while let Some(at) = rest.find("]]>") {
        writer.push_str(&rest[..at + 2])?;
        writer.push_str("]]>")?;
        writer.push_str("<![CDATA[")?;
        rest = &rest[at + 2..];
    }
    writer.push_str(rest)?;
    writer.push_str("]]>")
}

/// Validates every character and escapes text content. `\r` becomes a
/// character reference so a round trip cannot normalize it away.
fn escape_text(text: &str, writer: &mut BoundedWriter<'_>) -> Result<(), Error> {
    for character in text.chars() {
        check_xml_char(character)?;
        match character {
            '&' => writer.push_str("&amp;")?,
            '<' => writer.push_str("&lt;")?,
            '>' => writer.push_str("&gt;")?,
            '\r' => writer.push_str("&#13;")?,
            _ => writer.push_char(character)?,
        }
    }
    Ok(())
}

/// Attribute values additionally escape the quotes and the whitespace that
/// attribute-value normalization would otherwise rewrite.
fn escape_attribute_value(value: &str, writer: &mut BoundedWriter<'_>) -> Result<(), Error> {
    for character in value.chars() {
        check_xml_char(character)?;
        match character {
            '&' => writer.push_str("&amp;")?,
            '<' => writer.push_str("&lt;")?,
            '>' => writer.push_str("&gt;")?,
            '"' => writer.push_str("&quot;")?,
            '\'' => writer.push_str("&apos;")?,
            '\r' => writer.push_str("&#13;")?,
            '\n' => writer.push_str("&#10;")?,
            '\t' => writer.push_str("&#9;")?,
            _ => writer.push_char(character)?,
        }
    }
    Ok(())
}

impl BoundedWriter<'_> {
    fn push_char(&mut self, character: char) -> Result<(), Error> {
        let mut buffer = [0u8; 4];
        self.push_str(character.encode_utf8(&mut buffer))
    }
}

fn check_xml_char(character: char) -> Result<(), Error> {
    let code = character as u32;
    let allowed = matches!(code, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD)
        || (0x10000..=0x10FFFF).contains(&code);
    if allowed {
        Ok(())
    } else {
        Err(Error::unsupported_encoding(format!(
            "character U+{code:04X} cannot be represented in XML"
        )))
    }
}

/// XML 1.0 `Name` production (fourth-edition ranges), sufficient for the
/// names the decoders accept and the renderer emits.
fn is_valid_xml_name(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !is_name_start_char(first) {
        return false;
    }
    characters.all(is_name_char)
}

fn is_name_start_char(character: char) -> bool {
    matches!(character,
        'A'..='Z' | '_' | 'a'..='z' | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}'
        | '\u{F8}'..='\u{2FF}' | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}'
        | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}'
        | '\u{3001}'..='\u{D7FF}' | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}'
        | '\u{10000}'..='\u{EFFFF}')
}

fn is_name_char(character: char) -> bool {
    is_name_start_char(character)
        || matches!(character,
            '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

// ---------------------------------------------------------------------------
// Document DTO projection (A08; schemas/cli-v1.schema.json $defs.document)
// ---------------------------------------------------------------------------

/// Writes the ordered manifest document as the frozen CLI JSON DTO: ordered
/// nodes, attributes with namespace decomposition, namespace scope events,
/// typed raw values and the string-style metadata. Fixed key order; the
/// document is the same object `to_xml` renders.
pub fn write_document_dto(w: &mut crate::model::dto::Writer, manifest: &Manifest) {
    w.begin_object();
    w.key("declaration");
    match manifest.declaration() {
        Some(declaration) => {
            w.begin_object();
            w.key("version");
            w.string(&declaration.version);
            w.key("encoding");
            match &declaration.encoding {
                Some(encoding) => w.string(encoding),
                None => w.null(),
            }
            w.key("standalone");
            match &declaration.standalone {
                Some(standalone) => w.string(standalone),
                None => w.null(),
            }
            w.end_object();
        }
        None => w.null(),
    }
    w.key("prolog");
    w.begin_array();
    for item in manifest.prolog() {
        write_misc_dto(w, item);
    }
    w.end_array();
    w.key("root");
    write_element_dto(w, manifest.root());
    w.key("epilog");
    w.begin_array();
    for item in manifest.epilog() {
        write_misc_dto(w, item);
    }
    w.end_array();
    w.key("metadata");
    write_document_metadata_dto(w, manifest.metadata());
    w.end_object();
}

fn write_misc_dto(w: &mut crate::model::dto::Writer, item: &Misc) {
    w.begin_object();
    match item {
        Misc::Text(text) => {
            w.key("kind");
            w.string("text");
            w.key("text");
            crate::model::dto::write_dex_text(w, text);
        }
        Misc::Comment(text) => {
            w.key("kind");
            w.string("comment");
            w.key("text");
            w.string(text);
        }
        Misc::Pi { target, data } => {
            w.key("kind");
            w.string("pi");
            w.key("target");
            w.string(target);
            w.key("data");
            w.string(data);
        }
    }
    w.end_object();
}

fn write_element_dto(w: &mut crate::model::dto::Writer, element: &XmlElement) {
    w.begin_object();
    w.key("namespace");
    write_optional_string(w, element.namespace());
    w.key("prefix");
    write_optional_string(w, element.prefix());
    w.key("local_name");
    w.string(element.local_name());
    w.key("attributes");
    w.begin_array();
    for attribute in element.attributes() {
        write_attribute_dto(w, attribute);
    }
    w.end_array();
    w.key("children");
    w.begin_array();
    for child in element.children() {
        write_node_dto(w, child);
    }
    w.end_array();
    w.key("metadata");
    write_element_metadata_dto(w, element.metadata());
    w.end_object();
}

fn write_node_dto(w: &mut crate::model::dto::Writer, node: &XmlNode) {
    w.begin_object();
    match node {
        XmlNode::Text { text } => {
            w.key("kind");
            w.string("text");
            w.key("text");
            crate::model::dto::write_dex_text(w, text);
        }
        XmlNode::Cdata { data } => {
            w.key("kind");
            w.string("cdata");
            w.key("text");
            crate::model::dto::write_dex_text(w, data);
        }
        XmlNode::Comment { text } => {
            w.key("kind");
            w.string("comment");
            w.key("text");
            w.string(text);
        }
        XmlNode::Pi { target, data } => {
            w.key("kind");
            w.string("pi");
            w.key("target");
            w.string(target);
            w.key("data");
            w.string(data);
        }
        XmlNode::Element(element) => {
            w.key("kind");
            w.string("element");
            write_element_fields_dto(w, element);
        }
    }
    w.end_object();
}

/// The element fields without the wrapping object, so `XmlNode::Element` can
/// nest them under its `kind` tag and the root can carry them directly.
fn write_element_fields_dto(w: &mut crate::model::dto::Writer, element: &XmlElement) {
    w.key("namespace");
    write_optional_string(w, element.namespace());
    w.key("prefix");
    write_optional_string(w, element.prefix());
    w.key("local_name");
    w.string(element.local_name());
    w.key("attributes");
    w.begin_array();
    for attribute in element.attributes() {
        write_attribute_dto(w, attribute);
    }
    w.end_array();
    w.key("children");
    w.begin_array();
    for child in element.children() {
        write_node_dto(w, child);
    }
    w.end_array();
    w.key("metadata");
    write_element_metadata_dto(w, element.metadata());
}

fn write_attribute_dto(w: &mut crate::model::dto::Writer, attribute: &XmlAttribute) {
    w.begin_object();
    w.key("namespace");
    write_optional_string(w, attribute.namespace());
    w.key("prefix");
    write_optional_string(w, attribute.prefix());
    w.key("local_name");
    w.string(attribute.local_name());
    w.key("value");
    write_manifest_value_dto(w, attribute.value());
    w.end_object();
}

fn write_manifest_value_dto(w: &mut crate::model::dto::Writer, value: &ManifestValue) {
    w.begin_object();
    match value {
        ManifestValue::Text(text) => {
            w.key("kind");
            w.string("text");
            w.key("text");
            crate::model::dto::write_dex_text(w, text);
        }
        ManifestValue::Typed(typed) => {
            w.key("kind");
            w.string("typed");
            w.key("type_byte");
            w.number(u64::from(typed.type_byte));
            w.key("data");
            w.hex_bits(u64::from(typed.data), 8);
            w.key("raw_string");
            match typed.raw_string.as_ref() {
                Some(raw) => crate::model::dto::write_dex_text(w, raw),
                None => w.null(),
            }
        }
    }
    w.end_object();
}

fn write_element_metadata_dto(w: &mut crate::model::dto::Writer, metadata: &ElementMetadata) {
    w.begin_object();
    w.key("line_number");
    match metadata.line_number {
        Some(line) => w.number(u64::from(line)),
        None => w.null(),
    }
    w.key("comment");
    match &metadata.comment {
        Some(comment) => w.string(comment),
        None => w.null(),
    }
    w.key("namespace_events");
    w.begin_array();
    for event in &metadata.namespace_events {
        w.begin_object();
        match event {
            NamespaceEvent::Start { prefix, uri } => {
                w.key("event");
                w.string("start");
                w.key("prefix");
                w.string(prefix);
                w.key("uri");
                w.string(uri);
            }
            NamespaceEvent::End { prefix, uri } => {
                w.key("event");
                w.string("end");
                w.key("prefix");
                w.string(prefix);
                w.key("uri");
                w.string(uri);
            }
        }
        w.end_object();
    }
    w.end_array();
    w.end_object();
}

fn write_document_metadata_dto(w: &mut crate::model::dto::Writer, metadata: &ManifestMetadata) {
    w.begin_object();
    w.key("source");
    match metadata.source {
        Some(ManifestSource::BinaryAxml { utf8_pool, string_count }) => {
            w.begin_object();
            w.key("kind");
            w.string("binary-axml");
            w.key("utf8_pool");
            w.boolean(utf8_pool);
            w.key("string_count");
            w.number(string_count as u64);
            w.end_object();
        }
        Some(ManifestSource::PlainXml) => {
            w.begin_object();
            w.key("kind");
            w.string("plain-xml");
            w.end_object();
        }
        None => w.null(),
    }
    w.key("string_styles");
    w.begin_array();
    for style in &metadata.string_styles {
        w.begin_object();
        w.key("string_index");
        w.number(style.string_index as u64);
        w.key("spans");
        w.begin_array();
        for span in &style.spans {
            w.begin_object();
            w.key("name_index");
            w.number(span.name_index as u64);
            w.key("first_char");
            w.number(span.first_char as u64);
            w.key("last_char");
            w.number(span.last_char as u64);
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
    w.end_array();
    w.key("resource_map");
    w.begin_array();
    for resource in &metadata.resource_map {
        w.number(*resource as u64);
    }
    w.end_array();
    w.end_object();
}

fn write_optional_string(w: &mut crate::model::dto::Writer, value: Option<String>) {
    match value {
        Some(value) => w.string(&value),
        None => w.null(),
    }
}
