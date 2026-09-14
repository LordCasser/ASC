//! The frozen domain model: identities, lossless text, query values, reports
//! and the DTO projection shared by the CLI contract tests.
//!
//! Shapes and invariants follow openspec/implementation/interfaces.md §1;
//! identities are constructed by the analysis layers (catalog/scan results)
//! and are opaque values to everyone else. Field-level rules:
//! - `DexText` keeps UTF-16 units; `as_str` succeeds only for valid Unicode.
//! - `Pattern` is either a UTF-16 literal substring or a compiled regex; both
//!   reject empty/all-whitespace patterns and preserve meaningful spaces.
//! - IDs are private-construction; equality/ordering ride on their parts.

use crate::error::Error;
use fancy_regex::RegexBuilder;
use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

/// SHA-256 of a whole input artifact; same bytes, same id.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactId([u8; 32]);

impl ArtifactId {
    pub(crate) fn from_digest(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Lowercase 64-hex display form.
    pub fn hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl fmt::Debug for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArtifactId({})", self.hex())
    }
}

/// One logical DEX: the physical archive entry it came from plus its ordinal
/// among that entry's logical members. Raw DEX input uses entry ordinal 0.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DexId {
    artifact: ArtifactId,
    entry_ordinal: u32,
    logical_ordinal: u32,
}

impl DexId {
    pub(crate) fn new(artifact: ArtifactId, entry_ordinal: u32, logical_ordinal: u32) -> Self {
        Self { artifact, entry_ordinal, logical_ordinal }
    }

    pub fn artifact(&self) -> ArtifactId {
        self.artifact
    }

    pub fn entry_ordinal(&self) -> u32 {
        self.entry_ordinal
    }

    pub fn logical_ordinal(&self) -> u32 {
        self.logical_ordinal
    }
}

impl fmt::Debug for DexId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DexId({}:{})", self.entry_ordinal, self.logical_ordinal)
    }
}

/// A class definition inside one logical DEX. The descriptor alone is *not*
/// the identity: a DEX may define the same descriptor twice.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClassId {
    dex: DexId,
    class_def_idx: u32,
}

impl ClassId {
    pub(crate) fn new(dex: DexId, class_def_idx: u32) -> Self {
        Self { dex, class_def_idx }
    }

    pub fn dex(&self) -> DexId {
        self.dex
    }

    pub fn class_def_idx(&self) -> u32 {
        self.class_def_idx
    }
}

impl fmt::Debug for ClassId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClassId({:?} #{})", self.dex, self.class_def_idx)
    }
}

/// A method table entry inside one logical DEX.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MethodId {
    dex: DexId,
    method_idx: u32,
}

impl MethodId {
    pub(crate) fn new(dex: DexId, method_idx: u32) -> Self {
        Self { dex, method_idx }
    }

    pub fn dex(&self) -> DexId {
        self.dex
    }

    pub fn method_idx(&self) -> u32 {
        self.method_idx
    }
}

impl fmt::Debug for MethodId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MethodId({:?} #{})", self.dex, self.method_idx)
    }
}

/// Which table a target belongs to; ordinals here are for stable output
/// ordering, not for parsing display text back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetKind {
    String,
    Type,
    Field,
    Method,
}

impl TargetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetKind::String => "string",
            TargetKind::Type => "type",
            TargetKind::Field => "field",
            TargetKind::Method => "method",
        }
    }
}

/// A table row a reference points at (string/type/field/method index).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TargetId {
    dex: DexId,
    kind: TargetKind,
    table_index: u32,
}

impl TargetId {
    pub(crate) fn new(dex: DexId, kind: TargetKind, table_index: u32) -> Self {
        Self { dex, kind, table_index }
    }

    pub fn dex(&self) -> DexId {
        self.dex
    }

    pub fn kind(&self) -> TargetKind {
        self.kind
    }

    pub fn table_index(&self) -> u32 {
        self.table_index
    }
}

impl fmt::Debug for TargetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TargetId({:?} {} #{})", self.dex, self.kind.as_str(), self.table_index)
    }
}

// ---------------------------------------------------------------------------
// Text and descriptors
// ---------------------------------------------------------------------------

/// DEX string content kept as raw UTF-16 code units: no replacement
/// characters, no merging of distinct unpaired surrogates.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct DexText {
    units: Vec<u16>,
}

impl DexText {
    pub(crate) fn from_utf16_units(units: Vec<u16>) -> Self {
        Self { units }
    }

    pub(crate) fn from_str_lossless(text: &str) -> Self {
        Self { units: text.encode_utf16().collect() }
    }

    pub fn utf16_units(&self) -> &[u16] {
        &self.units
    }

    /// `Some` only when the units are valid Unicode (every surrogate paired).
    /// Owned because the units are the single stored representation; distinct
    /// unpaired surrogates must never round-trip through a replacement.
    pub fn as_str(&self) -> Option<String> {
        String::from_utf16(&self.units).ok()
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    pub fn unit_len(&self) -> usize {
        self.units.len()
    }
}

impl fmt::Debug for DexText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(text) => write!(f, "DexText({text:?})"),
            None => write!(f, "DexText(utf16 {:?})", self.units),
        }
    }
}

/// A validated `Lpkg/Name;` class descriptor. Primitive and array forms are
/// rejected; the CLI converts Java dotted names before construction.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClassDescriptor {
    descriptor: String,
}

impl ClassDescriptor {
    /// Validates an already-normalized `L...;` descriptor.
    pub(crate) fn from_normalized(descriptor: String) -> Result<Self, Error> {
        validate_descriptor(&descriptor)?;
        Ok(Self { descriptor })
    }

    pub fn as_str(&self) -> &str {
        &self.descriptor
    }

    /// The `pkg/Name` body between `L` and `;`.
    pub fn body(&self) -> &str {
        &self.descriptor[1..self.descriptor.len() - 1]
    }
}

impl fmt::Debug for ClassDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClassDescriptor({})", self.descriptor)
    }
}

/// Accepts only `L<body>;` with a non-empty body containing no `;` or `[`.
fn validate_descriptor(descriptor: &str) -> Result<(), Error> {
    let invalid = || {
        Error::invalid_query(format!(
            "invalid class descriptor {descriptor:?}: expected Lpkg/Name; without ';' or '[' inside"
        ))
    };
    let body = descriptor
        .strip_prefix('L')
        .and_then(|rest| rest.strip_suffix(';'))
        .ok_or_else(invalid)?;
    if body.is_empty() || body.contains(';') || body.contains('[') {
        return Err(invalid());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DEX entries, classes, methods
// ---------------------------------------------------------------------------

/// DEX format versions the tooling understands; anything else is rejected at
/// validation time, not silently parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DexVersion {
    V035,
    V037,
    V038,
    V039,
    V040,
    V041,
}

impl DexVersion {
    /// `Some` only for the supported matrix; used by the input layer.
    pub fn from_magic_tail(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"035\0" => Some(DexVersion::V035),
            b"037\0" => Some(DexVersion::V037),
            b"038\0" => Some(DexVersion::V038),
            b"039\0" => Some(DexVersion::V039),
            b"040\0" => Some(DexVersion::V040),
            b"041\0" => Some(DexVersion::V041),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DexVersion::V035 => "035",
            DexVersion::V037 => "037",
            DexVersion::V038 => "038",
            DexVersion::V039 => "039",
            DexVersion::V040 => "040",
            DexVersion::V041 => "041",
        }
    }
}

/// One logical DEX as returned by `Engine::dexes`: its identity, its raw
/// archive name, display forms, version and header offset inside the entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DexEntry {
    id: DexId,
    raw_entry_name: Vec<u8>,
    display_name: DexText,
    logical_name: DexText,
    version: DexVersion,
    header_offset: u64,
}

impl DexEntry {
    pub(crate) fn new(
        id: DexId,
        raw_entry_name: Vec<u8>,
        display_name: DexText,
        logical_name: DexText,
        version: DexVersion,
        header_offset: u64,
    ) -> Self {
        Self { id, raw_entry_name, display_name, logical_name, version, header_offset }
    }

    pub fn id(&self) -> DexId {
        self.id
    }

    pub fn raw_entry_name(&self) -> &[u8] {
        &self.raw_entry_name
    }

    pub fn display_name(&self) -> &DexText {
        &self.display_name
    }

    pub fn logical_name(&self) -> &DexText {
        &self.logical_name
    }

    pub fn version(&self) -> DexVersion {
        self.version
    }

    pub fn header_offset(&self) -> u64 {
        self.header_offset
    }
}

/// A full method prototype; descriptors stay lossless.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Prototype {
    parameters: Vec<DexText>,
    return_type: DexText,
}

impl Prototype {
    pub(crate) fn new(parameters: Vec<DexText>, return_type: DexText) -> Self {
        Self { parameters, return_type }
    }

    pub fn parameters(&self) -> &[DexText] {
        &self.parameters
    }

    pub fn return_type(&self) -> &DexText {
        &self.return_type
    }
}

/// Everything that identifies a method result: table index, owning DEX,
/// declaring class, name and full prototype.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MethodIdentity {
    id: MethodId,
    dex: DexEntry,
    owner: DexText,
    name: DexText,
    prototype: Prototype,
}

impl MethodIdentity {
    pub(crate) fn new(
        id: MethodId,
        dex: DexEntry,
        owner: DexText,
        name: DexText,
        prototype: Prototype,
    ) -> Self {
        Self { id, dex, owner, name, prototype }
    }

    pub fn id(&self) -> MethodId {
        self.id
    }

    pub fn dex(&self) -> &DexEntry {
        &self.dex
    }

    pub fn owner(&self) -> &DexText {
        &self.owner
    }

    pub fn name(&self) -> &DexText {
        &self.name
    }

    pub fn prototype(&self) -> &Prototype {
        &self.prototype
    }
}

/// A class definition with its readable projections. The descriptor is the
/// primary value; java name/package/simple name are derived but kept lossless
/// (`DexText`, since DEX identifiers may be arbitrary UTF-16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class {
    id: ClassId,
    dex: DexEntry,
    descriptor: ClassDescriptor,
    java_name: DexText,
    package: DexText,
    simple_name: DexText,
}

impl Class {
    pub(crate) fn new(id: ClassId, dex: DexEntry, descriptor: ClassDescriptor) -> Self {
        let body = descriptor.body();
        let java = body.replace('/', ".");
        let (package, simple) = match body.rsplit_once('/') {
            Some((package, simple)) => (package.replace('/', "."), simple.to_owned()),
            None => (String::new(), java.clone()),
        };
        Self {
            id,
            dex,
            java_name: DexText::from_str_lossless(&java),
            package: DexText::from_str_lossless(&package),
            simple_name: DexText::from_str_lossless(&simple),
            descriptor,
        }
    }

    pub fn id(&self) -> ClassId {
        self.id
    }

    pub fn dex(&self) -> &DexEntry {
        &self.dex
    }

    pub fn descriptor(&self) -> &ClassDescriptor {
        &self.descriptor
    }

    pub fn java_name(&self) -> &DexText {
        &self.java_name
    }

    pub fn package(&self) -> &DexText {
        &self.package
    }

    pub fn simple_name(&self) -> &DexText {
        &self.simple_name
    }
}

// ---------------------------------------------------------------------------
// References
// ---------------------------------------------------------------------------

/// The full value of a referenced target, by kind. Descriptors and names stay
/// lossless (`DexText`); member targets carry their whole identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetValue {
    String(DexText),
    Type(DexText),
    Field { owner: DexText, name: DexText, field_type: DexText },
    Method { owner: DexText, name: DexText, prototype: Prototype },
}

/// One matched target of a reference query: identity, value and the ascending
/// deduplicated code-unit offsets where the caller references it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetMatch {
    id: TargetId,
    value: TargetValue,
    code_unit_offsets: Vec<u32>,
}

impl TargetMatch {
    pub(crate) fn new(id: TargetId, value: TargetValue, mut code_unit_offsets: Vec<u32>) -> Self {
        code_unit_offsets.sort_unstable();
        code_unit_offsets.dedup();
        Self { id, value, code_unit_offsets }
    }

    pub fn id(&self) -> TargetId {
        self.id
    }

    pub fn value(&self) -> &TargetValue {
        &self.value
    }

    pub fn code_unit_offsets(&self) -> &[u32] {
        &self.code_unit_offsets
    }
}

/// One caller and every queried target it references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    caller: MethodIdentity,
    targets: Vec<TargetMatch>,
}

impl Reference {
    pub(crate) fn new(caller: MethodIdentity, targets: Vec<TargetMatch>) -> Self {
        Self { caller, targets }
    }

    pub fn caller(&self) -> &MethodIdentity {
        &self.caller
    }

    pub fn targets(&self) -> &[TargetMatch] {
        &self.targets
    }
}

// ---------------------------------------------------------------------------
// Patterns and queries
// ---------------------------------------------------------------------------

/// Construction and execution budgets for one pattern. Defaults are the
/// initial values from interfaces.md §5; every field must stay a finite
/// positive number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatternLimits {
    /// Maximum UTF-8 length of the pattern itself.
    pub max_pattern_bytes: usize,
    /// `fancy-regex` delegate compile size (regex + DFA).
    pub regex_compile_bytes: usize,
    /// Per-candidate backtracking budget.
    pub regex_backtrack_limit: usize,
}

impl PatternLimits {
    pub const DEFAULT: PatternLimits = PatternLimits {
        max_pattern_bytes: 16 * 1024,
        regex_compile_bytes: 8 * 1024 * 1024,
        regex_backtrack_limit: 1_000_000,
    };
}

impl Default for PatternLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The outcome of matching one candidate against a pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchOutcome {
    Match,
    NoMatch,
    /// The candidate cannot participate in this match mode (an unpaired
    /// surrogate under a regex); the caller must not treat this as NoMatch.
    Unsupported,
}

/// A literal substring over UTF-16 units or a compiled regex, both carrying
/// their original source text.
#[derive(Clone)]
pub enum Pattern {
    Literal { source: String, units: Vec<u16> },
    Regex { source: String, regex: fancy_regex::Regex },
}

impl Pattern {
    /// Literal substring pattern; matched over UTF-16 code units.
    pub fn literal(text: &str, limits: &PatternLimits) -> Result<Self, Error> {
        reject_blank_pattern(text)?;
        check_pattern_bytes(text, limits)?;
        Ok(Pattern::Literal { source: text.to_owned(), units: text.encode_utf16().collect() })
    }

    /// Regex pattern compiled with the given budgets; unsupported syntax is
    /// an `InvalidQuery`, never a silent literal fallback.
    pub fn regex(pattern: &str, limits: &PatternLimits) -> Result<Self, Error> {
        reject_blank_pattern(pattern)?;
        check_pattern_bytes(pattern, limits)?;
        let regex = RegexBuilder::new(pattern)
            .backtrack_limit(limits.regex_backtrack_limit)
            .delegate_size_limit(limits.regex_compile_bytes)
            .delegate_dfa_size_limit(limits.regex_compile_bytes)
            .build()
            .map_err(|error| Error::invalid_query(format!("invalid regex {pattern:?}: {error}")))?;
        Ok(Pattern::Regex { source: pattern.to_owned(), regex })
    }

    /// The original pattern text as supplied by the caller.
    pub fn source(&self) -> &str {
        match self {
            Pattern::Literal { source, .. } | Pattern::Regex { source, .. } => source,
        }
    }

    /// Matches raw UTF-16 units. Literal: unit-wise substring. Regex: only
    /// candidates representable as Unicode can be decided; anything else is
    /// `Unsupported`. A runtime budget exhaustion is a `ResourceLimit` error.
    pub fn matches_utf16(&self, units: &[u16]) -> Result<MatchOutcome, Error> {
        match self {
            Pattern::Literal { units: needle, .. } => {
                Ok(if contains_units(units, needle) {
                    MatchOutcome::Match
                } else {
                    MatchOutcome::NoMatch
                })
            }
            Pattern::Regex { regex, .. } => {
                let Some(text) = String::from_utf16(units).ok() else {
                    return Ok(MatchOutcome::Unsupported);
                };
                regex
                    .is_match(&text)
                    .map(|hit| if hit { MatchOutcome::Match } else { MatchOutcome::NoMatch })
                    .map_err(|error| {
                        Error::resource_limit(format!("regex execution over limit: {error}"))
                    })
            }
        }
    }

    /// Convenience for callers that already hold valid Unicode text.
    pub fn matches_str(&self, text: &str) -> Result<MatchOutcome, Error> {
        match self {
            Pattern::Literal { .. } => {
                let units: Vec<u16> = text.encode_utf16().collect();
                self.matches_utf16(&units)
            }
            Pattern::Regex { regex, .. } => regex
                .is_match(text)
                .map(|hit| if hit { MatchOutcome::Match } else { MatchOutcome::NoMatch })
                .map_err(|error| {
                    Error::resource_limit(format!("regex execution over limit: {error}"))
                }),
        }
    }
}

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Pattern::Literal { source, .. } => write!(f, "Pattern::literal({source:?})"),
            Pattern::Regex { source, .. } => write!(f, "Pattern::regex({source:?})"),
        }
    }
}

/// Empty or all-whitespace patterns never select anything meaningful and are
/// rejected at construction; a non-blank pattern keeps every space.
fn reject_blank_pattern(pattern: &str) -> Result<(), Error> {
    if pattern.is_empty() || pattern.chars().all(char::is_whitespace) {
        return Err(Error::invalid_query(format!(
            "pattern {pattern:?} is empty or whitespace-only"
        )));
    }
    Ok(())
}

fn check_pattern_bytes(pattern: &str, limits: &PatternLimits) -> Result<(), Error> {
    if pattern.len() > limits.max_pattern_bytes {
        return Err(Error::resource_limit(format!(
            "pattern is {} bytes, above the {} byte limit",
            pattern.len(),
            limits.max_pattern_bytes
        )));
    }
    Ok(())
}

fn contains_units(haystack: &[u16], needle: &[u16]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// How a member query constrains the declaring class: an exact descriptor, or
/// a fuzzy pattern matched against the descriptor text.
#[derive(Clone, Debug)]
pub enum ClassConstraint {
    Exact(ClassDescriptor),
    Fuzzy(Pattern),
}

/// A field/method query: a name pattern and/or a declaring-class constraint;
/// at least one must be present, and only the target member is constrained.
#[derive(Clone, Debug)]
pub struct MemberQuery {
    pub(crate) name: Option<Pattern>,
    pub(crate) declaring_class: Option<ClassConstraint>,
}

impl MemberQuery {
    pub(crate) fn new(
        name: Option<Pattern>,
        declaring_class: Option<ClassConstraint>,
    ) -> Result<Self, Error> {
        if name.is_none() && declaring_class.is_none() {
            return Err(Error::invalid_query(
                "member query needs at least a name pattern or a class constraint",
            ));
        }
        Ok(Self { name, declaring_class })
    }

    pub fn name(&self) -> Option<&Pattern> {
        self.name.as_ref()
    }

    pub fn declaring_class(&self) -> Option<&ClassConstraint> {
        self.declaring_class.as_ref()
    }
}

/// The four reference queries.
#[derive(Clone, Debug)]
pub enum ReferenceQuery {
    String(Pattern),
    Type(Pattern),
    Field(MemberQuery),
    Method(MemberQuery),
}

/// Optional case-insensitive substring filter over Java-style class names.
/// An empty filter passes everything; unlike patterns it is not rejected when
/// blank, because `classes` treats the absence of a filter as meaningful.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClassFilter {
    units: Vec<u16>,
}

impl ClassFilter {
    pub fn none() -> Self {
        Self { units: Vec::new() }
    }

    /// Lowercases valid Unicode scalars (non-locale); unpaired surrogates in
    /// the input cannot be lowered and are kept as-is.
    pub fn new(filter: &str) -> Self {
        Self { units: lowercase_units(&filter.encode_utf16().collect::<Vec<_>>()) }
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    pub fn matches(&self, candidate: &DexText) -> bool {
        if self.units.is_empty() {
            return true;
        }
        let lowered = lowercase_units(candidate.utf16_units());
        contains_units(&lowered, &self.units)
    }
}

/// Per-scalar Unicode lowercasing over UTF-16 units; unpaired surrogates pass
/// through untouched.
fn lowercase_units(units: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(units.len());
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if let Some(decoded) = decode_surrogate_pair(units, index) {
            let mut buffer = [0u8; 4];
            for lowered in decoded.to_lowercase() {
                for piece in lowered.encode_utf8(&mut buffer).encode_utf16() {
                    out.push(piece);
                }
            }
            index += 2;
        } else if (0xD800..=0xDFFF).contains(&unit) {
            out.push(unit);
            index += 1;
        } else {
            let scalar = unit as u32;
            for lowered in char::from_u32(scalar).unwrap().to_lowercase() {
                let mut buffer = [0u8; 4];
                for piece in lowered.encode_utf8(&mut buffer).encode_utf16() {
                    out.push(piece);
                }
            }
            index += 1;
        }
    }
    out
}

fn decode_surrogate_pair(units: &[u16], index: usize) -> Option<char> {
    let high = *units.get(index)?;
    let low = *units.get(index + 1)?;
    if (0xD800..=0xDBFF).contains(&high) && (0xDC00..=0xDFFF).contains(&low) {
        let code = 0x1_0000 + (((high as u32) - 0xD800) << 10) + ((low as u32) - 0xDC00);
        char::from_u32(code)
    } else {
        None
    }
}

/// How `getclass` picks its class: by descriptor (optionally pinned to one
/// logical DEX) or by an exact `ClassId` (no second descriptor search).
#[derive(Clone, Debug)]
pub enum ClassSelector {
    Descriptor(ClassDescriptor, Option<DexId>),
    Id(ClassId),
}

// ---------------------------------------------------------------------------
// Diagnostics, stats, reports
// ---------------------------------------------------------------------------

/// Fixed stage order for diagnostic sorting and reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Input,
    Dex,
    Query,
    Decompile,
    Manifest,
}

impl Stage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Stage::Input => "input",
            Stage::Dex => "dex",
            Stage::Query => "query",
            Stage::Decompile => "decompile",
            Stage::Manifest => "manifest",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

/// Stable diagnostic codes. The list grows as layers add diagnostics; the
/// strings are contract, the `message` is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagnosticCode {
    /// DEX header checksum field disagrees with the bytes.
    DexChecksumMismatch,
    /// DEX header SHA-1 signature field disagrees with the bytes.
    DexSignatureMismatch,
    /// Two archive entries shared one name; the first was selected.
    DuplicateEntryName,
    /// A class with the same descriptor is defined in more than one place.
    DuplicateClassDefinition,
    /// A manifest-declared namespace was reconstructed from resource ids.
    InferredNamespaceBinding,
    /// Backend reported information it could not fully carry into source.
    DecompilationNotice,
}

impl DiagnosticCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiagnosticCode::DexChecksumMismatch => "dex-checksum-mismatch",
            DiagnosticCode::DexSignatureMismatch => "dex-signature-mismatch",
            DiagnosticCode::DuplicateEntryName => "duplicate-entry-name",
            DiagnosticCode::DuplicateClassDefinition => "duplicate-class-definition",
            DiagnosticCode::InferredNamespaceBinding => "inferred-namespace-binding",
            DiagnosticCode::DecompilationNotice => "decompilation-notice",
        }
    }
}

/// One diagnostic: stable code/severity/stage plus optional identity anchors
/// and a human message that is not part of machine identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub(crate) code: DiagnosticCode,
    pub(crate) severity: Severity,
    pub(crate) stage: Stage,
    pub(crate) dex: Option<DexId>,
    pub(crate) class: Option<ClassId>,
    pub(crate) method: Option<MethodId>,
    pub(crate) offset: Option<u32>,
    pub(crate) message: String,
}

impl Diagnostic {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        code: DiagnosticCode,
        severity: Severity,
        stage: Stage,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            severity,
            stage,
            dex: None,
            class: None,
            method: None,
            offset: None,
            message: message.into(),
        }
    }

    pub(crate) fn with_dex(mut self, dex: DexId) -> Self {
        self.dex = Some(dex);
        self
    }

    pub(crate) fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn code(&self) -> DiagnosticCode {
        self.code
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }

    pub fn dex(&self) -> Option<DexId> {
        self.dex
    }

    pub fn class(&self) -> Option<ClassId> {
        self.class
    }

    pub fn method(&self) -> Option<MethodId> {
        self.method
    }

    pub fn offset(&self) -> Option<u32> {
        self.offset
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Operation counters for `--debug`; never part of the success payload, so
/// debug output cannot change emitted bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperationStats {
    pub selected_dexes: u32,
    pub scanned_methods: u64,
    pub matched_targets: u64,
    pub result_items: u64,
}

/// The uniform operation result: the value, everything diagnosed along the
/// way, and stats. Stats do not participate in fact equality or the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report<T> {
    pub(crate) value: T,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: OperationStats,
}

impl<T> Report<T> {
    pub(crate) fn new(value: T, diagnostics: Vec<Diagnostic>, stats: OperationStats) -> Self {
        Self { value, diagnostics, stats }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn into_value(self) -> T {
        self.value
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn stats(&self) -> OperationStats {
        self.stats
    }
}

// ---------------------------------------------------------------------------
// Source and metadata (shapes frozen; population lands with A05/A07)
// ---------------------------------------------------------------------------

/// A DEX encoded value, bit-exact: floats and doubles keep their raw bits so
/// no textual rounding can change a constant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodedValue {
    Null,
    Boolean(bool),
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    Char(u16),
    Float(u32),
    Double(u64),
    String(DexText),
    Type(DexText),
    Field { owner: DexText, name: DexText, field_type: DexText },
    Method { owner: DexText, name: DexText, prototype: Prototype },
    Enum { owner: DexText, name: DexText },
    Array(Vec<EncodedValue>),
    Annotation(AnnotationRecord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnnotationVisibility {
    Build,
    Runtime,
    System,
}

/// One annotation: where it applies is carried by its container record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnotationRecord {
    pub(crate) visibility: AnnotationVisibility,
    pub(crate) type_descriptor: DexText,
    pub(crate) items: Vec<(DexText, EncodedValue)>,
}

impl AnnotationRecord {
    pub(crate) fn new(
        visibility: AnnotationVisibility,
        type_descriptor: DexText,
        items: Vec<(DexText, EncodedValue)>,
    ) -> Self {
        Self { visibility, type_descriptor, items }
    }

    pub fn visibility(&self) -> AnnotationVisibility {
        self.visibility
    }

    pub fn type_descriptor(&self) -> &DexText {
        &self.type_descriptor
    }

    pub fn items(&self) -> &[(DexText, EncodedValue)] {
        &self.items
    }
}

/// What an annotation is attached to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnnotationTarget {
    Class,
    Field { index: usize },
    Method { index: usize },
    Parameter { method_index: usize, parameter_index: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnotationEntry {
    pub(crate) target: AnnotationTarget,
    pub(crate) annotation: AnnotationRecord,
}

/// Debug-info projection for one method; absent entries mean "no debug info",
/// which is normal and not an error.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DebugInfo {
    pub(crate) parameter_names: Vec<Option<DexText>>,
    pub(crate) locals: Vec<LocalVariable>,
    pub(crate) lines: Vec<LineNumberEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalVariable {
    pub(crate) name: DexText,
    pub(crate) start_code_unit: u32,
    pub(crate) end_code_unit: u32,
    pub(crate) slot: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineNumberEntry {
    pub(crate) code_unit: u32,
    pub(crate) line: u32,
}

/// Class-level facts that source text alone may not express.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClassMetadata {
    pub(crate) access_flags: u32,
    pub(crate) super_class: Option<DexText>,
    pub(crate) interfaces: Vec<DexText>,
    pub(crate) source_file: Option<DexText>,
    pub(crate) generic_signature: Option<DexText>,
    pub(crate) enclosing: Option<EnclosingRecord>,
    pub(crate) inner_classes: Vec<InnerClassRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclosingRecord {
    pub(crate) outer_class: Option<DexText>,
    pub(crate) enclosing_method: Option<(DexText, DexText, Prototype)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InnerClassRecord {
    pub(crate) inner_class: DexText,
    pub(crate) outer_class: Option<DexText>,
    pub(crate) inner_name: Option<DexText>,
    pub(crate) access_flags: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldMetadata {
    pub(crate) name: DexText,
    pub(crate) field_type: DexText,
    pub(crate) access_flags: u32,
    pub(crate) generic_signature: Option<DexText>,
    pub(crate) initial_value: Option<EncodedValue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MethodMetadata {
    pub(crate) name: DexText,
    pub(crate) prototype: Prototype,
    pub(crate) access_flags: u32,
    pub(crate) generic_signature: Option<DexText>,
    pub(crate) throws: Vec<DexText>,
    pub(crate) annotations: Vec<AnnotationEntry>,
    pub(crate) parameter_signatures: Vec<Option<DexText>>,
    pub(crate) debug: Option<DebugInfo>,
}

/// The complete metadata of a decompiled class: original flags, relations,
/// annotations, signatures, throws and debug info. Missing optional data is
/// `None`, never a fabricated default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceMetadata {
    pub(crate) class: ClassMetadata,
    pub(crate) annotations: Vec<AnnotationEntry>,
    pub(crate) fields: Vec<FieldMetadata>,
    pub(crate) methods: Vec<MethodMetadata>,
}

/// A decompiled class: Java-style UTF-8 text and its metadata. It only exists
/// as the value of a complete success or as the partial payload of an
/// incomplete-decompilation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub(crate) class: Class,
    pub(crate) text: Arc<str>,
    pub(crate) metadata: SourceMetadata,
}

impl Source {
    pub(crate) fn new(class: Class, text: Arc<str>, metadata: SourceMetadata) -> Self {
        Self { class, text, metadata }
    }

    pub fn class(&self) -> &Class {
        &self.class
    }

    /// UTF-8, LF line endings, exactly one trailing LF.
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn metadata(&self) -> &SourceMetadata {
        &self.metadata
    }
}

// ---------------------------------------------------------------------------
// DTO projection (frozen CLI JSON, schema_version 1)
// ---------------------------------------------------------------------------
//
// The CLI renders domain values into JSON with fixed key order and raw UTF-8
// characters; these writers are the single source of that projection so the
// golden files in schemas/goldens/ stay authoritative. The library itself has
// no serde dependency; `stats` is never serialized.

pub(crate) mod dto {
    use super::*;

    /// Minimal JSON writer: fixed key order is call-ordered, control
    /// characters are `\u00xx`-escaped, non-ASCII characters are emitted raw.
    pub(crate) struct Writer {
        out: String,
        /// Per open container: whether a comma must precede the next element.
        need_comma: Vec<bool>,
    }

    impl Writer {
        pub(crate) fn new() -> Self {
            Self { out: String::new(), need_comma: vec![false] }
        }

        pub(crate) fn raw(value: &str) -> String {
            let mut writer = Writer::new();
            writer.string(value);
            writer.finish()
        }

        fn prefix(&mut self) {
            if let Some(flag) = self.need_comma.last_mut()
                && *flag
            {
                self.out.push(',');
                *flag = false;
            }
        }

        pub(crate) fn begin_object(&mut self) {
            self.prefix();
            self.out.push('{');
            self.need_comma.push(false);
        }

        pub(crate) fn end_object(&mut self) {
            self.need_comma.pop();
            self.out.push('}');
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        pub(crate) fn begin_array(&mut self) {
            self.prefix();
            self.out.push('[');
            self.need_comma.push(false);
        }

        pub(crate) fn end_array(&mut self) {
            self.need_comma.pop();
            self.out.push(']');
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        /// Writes `"key":`; the value write follows immediately.
        pub(crate) fn key(&mut self, key: &str) {
            self.prefix();
            self.string_unprefixed(key);
            self.out.push(':');
        }

        pub(crate) fn string(&mut self, value: &str) {
            self.prefix();
            self.string_unprefixed(value);
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        fn string_unprefixed(&mut self, value: &str) {
            self.out.push('"');
            for character in value.chars() {
                match character {
                    '"' => self.out.push_str("\\\""),
                    '\\' => self.out.push_str("\\\\"),
                    '\n' => self.out.push_str("\\n"),
                    '\r' => self.out.push_str("\\r"),
                    '\t' => self.out.push_str("\\t"),
                    '\u{08}' => self.out.push_str("\\b"),
                    '\u{0c}' => self.out.push_str("\\f"),
                    character if (character as u32) < 0x20 => {
                        self.out.push_str(&format!("\\u{:04x}", character as u32));
                    }
                    character => self.out.push(character),
                }
            }
            self.out.push('"');
        }

        pub(crate) fn number(&mut self, value: u64) {
            self.prefix();
            self.out.push_str(&value.to_string());
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        pub(crate) fn boolean(&mut self, value: bool) {
            self.prefix();
            self.out.push_str(if value { "true" } else { "false" });
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        pub(crate) fn null(&mut self) {
            self.prefix();
            self.out.push_str("null");
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        pub(crate) fn finish(self) -> String {
            self.out
        }
    }

    /// `{"artifact_id":"…","entry_ordinal":n,"logical_ordinal":n}` plus the
    /// kind-specific index key, in that fixed order.
    pub(crate) fn write_dex_id(w: &mut Writer, id: &DexId) {
        w.begin_object();
        w.key("artifact_id");
        w.string(&id.artifact().hex());
        w.key("entry_ordinal");
        w.number(id.entry_ordinal() as u64);
        w.key("logical_ordinal");
        w.number(id.logical_ordinal() as u64);
        w.end_object();
    }

    fn write_indexed_id(w: &mut Writer, id: &DexId, index_key: &str, index: u32) {
        w.begin_object();
        w.key("artifact_id");
        w.string(&id.artifact().hex());
        w.key("entry_ordinal");
        w.number(id.entry_ordinal() as u64);
        w.key("logical_ordinal");
        w.number(id.logical_ordinal() as u64);
        w.key(index_key);
        w.number(index as u64);
        w.end_object();
    }

    pub(crate) fn write_class_id(w: &mut Writer, id: &ClassId) {
        write_indexed_id(w, &id.dex(), "class_def_idx", id.class_def_idx());
    }

    pub(crate) fn write_method_id(w: &mut Writer, id: &MethodId) {
        write_indexed_id(w, &id.dex(), "method_idx", id.method_idx());
    }

    pub(crate) fn write_target_id(w: &mut Writer, id: &TargetId) {
        write_indexed_id(w, &id.dex(), "index", id.table_index());
    }

    /// `{"text":<string|null>,"utf16":[…]}` - lossless in both projections.
    pub(crate) fn write_dex_text(w: &mut Writer, text: &DexText) {
        w.begin_object();
        w.key("text");
        match text.as_str() {
            Some(value) => w.string(&value),
            None => w.null(),
        }
        w.key("utf16");
        w.begin_array();
        for unit in text.utf16_units() {
            w.number(*unit as u64);
        }
        w.end_array();
        w.end_object();
    }

    pub(crate) fn write_prototype(w: &mut Writer, prototype: &Prototype) {
        w.begin_object();
        w.key("parameters");
        w.begin_array();
        for parameter in prototype.parameters() {
            write_dex_text(w, parameter);
        }
        w.end_array();
        w.key("return_type");
        write_dex_text(w, prototype.return_type());
        w.end_object();
    }

    pub(crate) fn write_dex_entry(w: &mut Writer, entry: &DexEntry) {
        w.begin_object();
        w.key("id");
        write_dex_id(w, &entry.id());
        w.key("raw_entry_name");
        w.string(&String::from_utf8_lossy(entry.raw_entry_name()));
        w.key("display_name");
        write_dex_text(w, entry.display_name());
        w.key("logical_name");
        write_dex_text(w, entry.logical_name());
        w.key("version");
        w.string(entry.version().as_str());
        w.key("header_offset");
        w.number(entry.header_offset());
        w.end_object();
    }

    pub(crate) fn write_target_value(w: &mut Writer, value: &TargetValue) {
        match value {
            TargetValue::String(text) | TargetValue::Type(text) => write_dex_text(w, text),
            TargetValue::Field { owner, name, field_type } => {
                w.begin_object();
                w.key("owner");
                write_dex_text(w, owner);
                w.key("name");
                write_dex_text(w, name);
                w.key("field_type");
                write_dex_text(w, field_type);
                w.end_object();
            }
            TargetValue::Method { owner, name, prototype } => {
                w.begin_object();
                w.key("owner");
                write_dex_text(w, owner);
                w.key("name");
                write_dex_text(w, name);
                w.key("prototype");
                write_prototype(w, prototype);
                w.end_object();
            }
        }
    }

    pub(crate) fn write_reference(w: &mut Writer, reference: &Reference) {
        w.begin_object();
        w.key("caller");
        w.begin_object();
        w.key("id");
        write_method_id(w, &reference.caller().id());
        w.key("dex");
        write_dex_entry(w, reference.caller().dex());
        w.key("owner");
        write_dex_text(w, reference.caller().owner());
        w.key("name");
        write_dex_text(w, reference.caller().name());
        w.key("prototype");
        write_prototype(w, reference.caller().prototype());
        w.end_object();
        w.key("targets");
        w.begin_array();
        for target in reference.targets() {
            w.begin_object();
            w.key("id");
            write_target_id(w, &target.id());
            w.key("kind");
            w.string(target.id().kind().as_str());
            w.key("value");
            write_target_value(w, target.value());
            w.key("code_unit_offsets");
            w.begin_array();
            for offset in target.code_unit_offsets() {
                w.number(*offset as u64);
            }
            w.end_array();
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }

    pub(crate) fn write_class(w: &mut Writer, class: &Class) {
        w.begin_object();
        w.key("id");
        write_class_id(w, &class.id());
        w.key("dex");
        write_dex_entry(w, class.dex());
        w.key("descriptor");
        w.string(class.descriptor().as_str());
        w.key("java_name");
        write_dex_text(w, class.java_name());
        w.key("package");
        write_dex_text(w, class.package());
        w.key("simple_name");
        write_dex_text(w, class.simple_name());
        w.end_object();
    }

    /// Absent identity anchors are omitted; present keys keep this order.
    pub(crate) fn write_diagnostic(w: &mut Writer, diagnostic: &Diagnostic) {
        w.begin_object();
        w.key("code");
        w.string(diagnostic.code().as_str());
        w.key("severity");
        w.string(diagnostic.severity().as_str());
        w.key("stage");
        w.string(diagnostic.stage().as_str());
        if let Some(dex) = diagnostic.dex() {
            w.key("dex");
            write_dex_id(w, &dex);
        }
        if let Some(class) = diagnostic.class() {
            w.key("class");
            write_class_id(w, &class);
        }
        if let Some(method) = diagnostic.method() {
            w.key("method");
            write_method_id(w, &method);
        }
        if let Some(offset) = diagnostic.offset() {
            w.key("offset");
            w.number(offset as u64);
        }
        w.key("message");
        w.string(diagnostic.message());
        w.end_object();
    }

    /// The success envelope: fixed order `schema_version, operation,
    /// artifact_id, data, diagnostics`. `data` is written by `write_data`.
    pub(crate) fn write_envelope(
        operation: &str,
        artifact: &ArtifactId,
        diagnostics: &[Diagnostic],
        write_data: impl FnOnce(&mut Writer),
    ) -> String {
        let mut w = Writer::new();
        w.begin_object();
        w.key("schema_version");
        w.number(1);
        w.key("operation");
        w.string(operation);
        w.key("artifact_id");
        w.string(&artifact.hex());
        w.key("data");
        write_data(&mut w);
        w.key("diagnostics");
        w.begin_array();
        for diagnostic in diagnostics {
            write_diagnostic(&mut w, diagnostic);
        }
        w.end_array();
        w.end_object();
        w.finish()
    }

    /// The error object: `{"code":"…","context":[…],"diagnostics":[…]}`.
    pub(crate) fn write_error(error: &crate::error::Error) -> String {
        let mut w = Writer::new();
        w.begin_object();
        w.key("code");
        w.string(error.kind().code());
        w.key("context");
        w.begin_array();
        for context in error.context().iter().rev() {
            w.string(context);
        }
        w.end_array();
        w.key("diagnostics");
        w.begin_array();
        for diagnostic in error.diagnostics() {
            write_diagnostic(&mut w, diagnostic);
        }
        w.end_array();
        w.end_object();
        w.finish()
    }
}
