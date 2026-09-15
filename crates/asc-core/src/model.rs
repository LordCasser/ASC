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
use std::sync::atomic::{AtomicU64, Ordering};

/// A cloneable engine-memory charge. The model module is also compiled by the
/// standalone contract harnesses, so this small RAII type intentionally has no
/// dependency on the engine runtime module.
#[derive(Clone, Debug)]
pub(crate) struct MemoryPermit {
    #[allow(dead_code)]
    allocation: Arc<MemoryAllocation>,
}

impl MemoryPermit {
    pub(crate) fn new(account: Arc<AtomicU64>, bytes: u64) -> Self {
        Self {
            allocation: Arc::new(MemoryAllocation { account, bytes }),
        }
    }
}

#[derive(Debug)]
struct MemoryAllocation {
    account: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for MemoryAllocation {
    fn drop(&mut self) {
        self.account.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

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

/// Stable identity of one physical archive entry: the owning artifact and
/// its zero-based central-directory ordinal. Names are deliberately not part
/// of the identity, so duplicate and non-UTF-8 names remain addressable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArchiveEntryId {
    artifact: ArtifactId,
    ordinal: u32,
}

impl ArchiveEntryId {
    pub(crate) fn new(artifact: ArtifactId, ordinal: u32) -> Self {
        Self { artifact, ordinal }
    }

    pub fn artifact(&self) -> ArtifactId {
        self.artifact
    }

    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }
}

/// A lossless, immutable projection of one central-directory record.
/// `raw_name` is the identity-preserving representation; `display_name` is a
/// safe escaped rendering for humans and logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveEntry {
    id: ArchiveEntryId,
    raw_name: Vec<u8>,
    display_name: String,
    method: u16,
    compressed_size: u64,
    uncompressed_size: u64,
    crc32: u32,
    encrypted: bool,
    directory: bool,
}

impl ArchiveEntry {
    pub(crate) fn new(
        id: ArchiveEntryId,
        raw_name: Vec<u8>,
        display_name: String,
        method: u16,
        compressed_size: u64,
        uncompressed_size: u64,
        crc32: u32,
        encrypted: bool,
        directory: bool,
    ) -> Self {
        Self {
            id,
            raw_name,
            display_name,
            method,
            compressed_size,
            uncompressed_size,
            crc32,
            encrypted,
            directory,
        }
    }

    pub fn id(&self) -> ArchiveEntryId {
        self.id
    }

    pub fn raw_name(&self) -> &[u8] {
        &self.raw_name
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn method(&self) -> u16 {
        self.method
    }

    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn is_directory(&self) -> bool {
        self.directory
    }

    pub(crate) fn estimated_bytes(&self) -> usize {
        64usize
            .saturating_add(self.raw_name.len())
            .saturating_add(self.display_name.len())
    }
}

/// Bounds for one archive-directory projection. A query that would exceed a
/// bound fails with `ResourceLimit`; it never returns a silently truncated
/// catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveEntryQuery {
    pub max_items: usize,
    pub max_result_bytes: usize,
}

impl Default for ArchiveEntryQuery {
    fn default() -> Self {
        Self {
            max_items: 100_000,
            max_result_bytes: 16 * 1024 * 1024,
        }
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
        Self {
            artifact,
            entry_ordinal,
            logical_ordinal,
        }
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

    #[allow(dead_code)] // A07/A08 wiring surface; used by contract tests
    #[allow(dead_code)] // A07/A08 wiring surface
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
    #[allow(dead_code)] // A07/A08 wiring surface; used by contract tests
    pub(crate) fn new(dex: DexId, method_idx: u32) -> Self {
        Self { dex, method_idx }
    }

    #[allow(dead_code)] // A07/A08 wiring surface
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

/// A field table entry inside one logical DEX.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldId {
    dex: DexId,
    field_idx: u32,
}

impl FieldId {
    pub(crate) fn new(dex: DexId, field_idx: u32) -> Self {
        Self { dex, field_idx }
    }

    pub fn dex(&self) -> DexId {
        self.dex
    }

    pub fn field_idx(&self) -> u32 {
        self.field_idx
    }
}

impl fmt::Debug for FieldId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldId({:?} #{})", self.dex, self.field_idx)
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
        Self {
            dex,
            kind,
            table_index,
        }
    }

    #[allow(dead_code)] // A07/A08 wiring surface
    pub fn dex(&self) -> DexId {
        self.dex
    }

    #[allow(dead_code)] // A08 text projection
    pub fn kind(&self) -> TargetKind {
        self.kind
    }

    #[allow(dead_code)]
    pub fn table_index(&self) -> u32 {
        self.table_index
    }
}

impl fmt::Debug for TargetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TargetId({:?} {} #{})",
            self.dex,
            self.kind.as_str(),
            self.table_index
        )
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
        Self {
            units: text.encode_utf16().collect(),
        }
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

    #[allow(dead_code)] // A07/A08 wiring surface; used by contract tests
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    #[allow(dead_code)] // A07/A08 wiring surface; used by contract tests
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
    /// Validates an already-normalized `L...;` descriptor; hosts use the
    /// query builders (`query::exact_descriptor`) which call this.
    pub fn from_normalized(descriptor: String) -> Result<Self, Error> {
        validate_descriptor(&descriptor)?;
        Ok(Self { descriptor })
    }

    #[allow(dead_code)] // A07/A08 wiring surface; used by contract tests
    #[allow(dead_code)] // A07/A08 wiring surface
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

    #[allow(dead_code)] // A07/A08 wiring surface
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
        Self {
            id,
            raw_entry_name,
            display_name,
            logical_name,
            version,
            header_offset,
        }
    }

    pub fn id(&self) -> DexId {
        self.id
    }

    #[allow(dead_code)] // A07/A08 wiring surface; used by contract tests
    pub fn raw_entry_name(&self) -> &[u8] {
        &self.raw_entry_name
    }

    pub fn display_name(&self) -> &DexText {
        &self.display_name
    }

    #[allow(dead_code)] // A07/A08 wiring surface; used by contract tests
    pub fn logical_name(&self) -> &DexText {
        &self.logical_name
    }

    #[allow(dead_code)] // A07/A08 wiring surface; used by contract tests
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
        Self {
            parameters,
            return_type,
        }
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

/// The DEX range an operation is allowed to inspect. `Root` keeps the
/// existing selected `classes*.dex` policy; `Entries` names physical archive
/// records (all validated logical members are included); `Dexes` pins logical
/// members when a DEX041 container has to be addressed precisely;
/// `AllDetected` discovers DEX images across the complete archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MethodScope {
    Root,
    Entries(Vec<ArchiveEntryId>),
    Dexes(Vec<DexId>),
    AllDetected,
}

/// A precise method navigation target. `MethodId` identifies the method table
/// row and `ClassId` disambiguates declarations of the same descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MethodTarget {
    class: ClassId,
    method: MethodId,
}

impl MethodTarget {
    pub(crate) fn new(class: ClassId, method: MethodId) -> Self {
        Self { class, method }
    }

    pub fn class(&self) -> ClassId {
        self.class
    }

    pub fn method(&self) -> MethodId {
        self.method
    }
}

/// One declared method from class_data. This is an inventory fact, not a
/// projection inferred from emitted source or reference hits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MethodDeclaration {
    target: MethodTarget,
    identity: MethodIdentity,
    class: Class,
    access_flags: u32,
    is_direct: bool,
    has_code: bool,
    code_off: Option<u32>,
}

impl MethodDeclaration {
    pub(crate) fn new(
        target: MethodTarget,
        identity: MethodIdentity,
        class: Class,
        access_flags: u32,
        is_direct: bool,
        has_code: bool,
        code_off: u32,
    ) -> Self {
        Self {
            target,
            identity,
            class,
            access_flags,
            is_direct,
            has_code,
            code_off: has_code.then_some(code_off),
        }
    }

    pub fn target(&self) -> MethodTarget {
        self.target
    }

    pub fn id(&self) -> MethodId {
        self.target.method()
    }

    pub fn method_id(&self) -> MethodId {
        self.target.method()
    }

    pub fn class_id(&self) -> ClassId {
        self.target.class()
    }

    pub fn declaring_class(&self) -> ClassId {
        self.target.class()
    }

    pub fn identity(&self) -> &MethodIdentity {
        &self.identity
    }

    pub fn class(&self) -> &Class {
        &self.class
    }

    pub fn access_flags(&self) -> u32 {
        self.access_flags
    }

    pub fn is_direct(&self) -> bool {
        self.is_direct
    }

    pub fn has_code(&self) -> bool {
        self.has_code
    }

    pub fn code_off(&self) -> Option<u32> {
        self.code_off
    }
}

/// Method declarations plus the resolved DEX scope used to obtain them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MethodInventory {
    requested_scope: MethodScope,
    resolved_dexes: Vec<DexId>,
    dex_entries: Vec<DexEntry>,
    fields: Vec<FieldDeclaration>,
    methods: Vec<MethodDeclaration>,
}

/// One lossless string-pool declaration in a scoped logical DEX. String
/// declarations are inventory facts, so unreferenced strings remain visible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringDeclaration {
    dex: DexEntry,
    index: u32,
    value: DexText,
}

impl StringDeclaration {
    pub(crate) fn new(dex: DexEntry, index: u32, value: DexText) -> Self {
        Self { dex, index, value }
    }

    pub fn dex(&self) -> &DexEntry {
        &self.dex
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn value(&self) -> &DexText {
        &self.value
    }
}

/// One field declaration from class_data, including a static initializer when
/// the DEX carries one. The field-table identity is retained even when names
/// or descriptors are duplicated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDeclaration {
    id: FieldId,
    declaring_class: ClassId,
    owner: DexText,
    name: DexText,
    field_type: DexText,
    access_flags: u32,
    is_static: bool,
    initial_value: Option<EncodedValue>,
}

impl FieldDeclaration {
    pub(crate) fn new(
        id: FieldId,
        declaring_class: ClassId,
        owner: DexText,
        name: DexText,
        field_type: DexText,
        access_flags: u32,
        is_static: bool,
        initial_value: Option<EncodedValue>,
    ) -> Self {
        Self {
            id,
            declaring_class,
            owner,
            name,
            field_type,
            access_flags,
            is_static,
            initial_value,
        }
    }

    pub fn id(&self) -> FieldId {
        self.id
    }

    pub fn declaring_class(&self) -> ClassId {
        self.declaring_class
    }

    pub fn owner(&self) -> &DexText {
        &self.owner
    }

    pub fn name(&self) -> &DexText {
        &self.name
    }

    pub fn field_type(&self) -> &DexText {
        &self.field_type
    }

    pub fn access_flags(&self) -> u32 {
        self.access_flags
    }

    pub fn is_static(&self) -> bool {
        self.is_static
    }

    pub fn initial_value(&self) -> Option<&EncodedValue> {
        self.initial_value.as_ref()
    }
}

impl MethodInventory {
    pub(crate) fn new(
        requested_scope: MethodScope,
        resolved_dexes: Vec<DexId>,
        dex_entries: Vec<DexEntry>,
        fields: Vec<FieldDeclaration>,
        methods: Vec<MethodDeclaration>,
    ) -> Self {
        Self {
            requested_scope,
            resolved_dexes,
            dex_entries,
            fields,
            methods,
        }
    }

    pub fn requested_scope(&self) -> &MethodScope {
        &self.requested_scope
    }

    pub fn scope(&self) -> &MethodScope {
        &self.requested_scope
    }

    pub fn resolved_dexes(&self) -> &[DexId] {
        &self.resolved_dexes
    }

    /// Resolved logical DEX entries, including entries with zero class or
    /// method declarations. The order matches `resolved_dexes()`.
    pub fn dex_entries(&self) -> &[DexEntry] {
        &self.dex_entries
    }

    pub fn methods(&self) -> &[MethodDeclaration] {
        &self.methods
    }

    pub fn fields(&self) -> &[FieldDeclaration] {
        &self.fields
    }
}

impl MethodIdentity {
    pub(crate) fn new(
        id: MethodId,
        dex: DexEntry,
        owner: DexText,
        name: DexText,
        prototype: Prototype,
    ) -> Self {
        Self {
            id,
            dex,
            owner,
            name,
            prototype,
        }
    }

    pub fn id(&self) -> MethodId {
        self.id
    }

    #[allow(dead_code)] // A07/A08 wiring surface
    #[allow(dead_code)] // A07/A08 wiring surface
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

    #[allow(dead_code)] // A07/A08 wiring surface
    pub fn id(&self) -> ClassId {
        self.id
    }

    #[allow(dead_code)] // A07/A08 wiring surface
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

    #[allow(dead_code)] // A07/A08 wiring surface
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
    Field {
        owner: DexText,
        name: DexText,
        field_type: DexText,
    },
    Method {
        owner: DexText,
        name: DexText,
        prototype: Prototype,
    },
}

/// One reference call site. `pc` is the code-unit offset from the method's
/// `insns` array, `code_off` is the DEX file offset of that code item, and
/// `opcode` is the raw Dalvik opcode byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReferenceLocation {
    code_off: u32,
    pc: u32,
    opcode: u8,
}

impl ReferenceLocation {
    pub(crate) fn new(code_off: u32, pc: u32, opcode: u8) -> Self {
        Self {
            code_off,
            pc,
            opcode,
        }
    }

    pub fn code_off(&self) -> u32 {
        self.code_off
    }

    pub fn pc(&self) -> u32 {
        self.pc
    }

    pub fn opcode(&self) -> u8 {
        self.opcode
    }
}

/// One matched target of a reference query: identity, value and the ascending
/// deduplicated code-unit offsets where the caller references it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetMatch {
    id: TargetId,
    value: TargetValue,
    code_unit_offsets: Vec<u32>,
    locations: Vec<ReferenceLocation>,
}

impl TargetMatch {
    #[allow(dead_code)]
    pub(crate) fn new(id: TargetId, value: TargetValue, mut code_unit_offsets: Vec<u32>) -> Self {
        code_unit_offsets.sort_unstable();
        code_unit_offsets.dedup();
        Self {
            id,
            value,
            code_unit_offsets,
            locations: Vec::new(),
        }
    }

    pub(crate) fn with_locations(
        id: TargetId,
        value: TargetValue,
        mut locations: Vec<ReferenceLocation>,
    ) -> Self {
        locations.sort_unstable();
        locations.dedup();
        let code_unit_offsets = locations.iter().map(|location| location.pc).collect();
        Self {
            id,
            value,
            code_unit_offsets,
            locations,
        }
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

    pub fn locations(&self) -> &[ReferenceLocation] {
        &self.locations
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
// Typed instruction facts
// ---------------------------------------------------------------------------

/// A table operand retained by one decoded Dalvik instruction.
///
/// The index is local to the logical DEX identified by [`InstructionFact::dex`];
/// consumers resolve it through the corresponding public inventory.  Keeping
/// this as a typed value prevents adapters from re-decoding instruction bytes
/// or guessing a table from an opcode-shaped integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstructionReference {
    String { index: u32 },
    Type { index: u32 },
    Field { index: u32 },
    Method { index: u32 },
}

impl InstructionReference {
    pub fn index(&self) -> u32 {
        match self {
            Self::String { index }
            | Self::Type { index }
            | Self::Field { index }
            | Self::Method { index } => *index,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::String { .. } => "string",
            Self::Type { .. } => "type",
            Self::Field { .. } => "field",
            Self::Method { .. } => "method",
        }
    }
}

/// A scalar constant proved by an instruction encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstructionConstant {
    Int(i64),
    String { index: u32 },
}

/// One structurally decoded instruction in a selected logical DEX.
///
/// `pc` and branch targets are code-unit offsets from the start of `insns`;
/// `code_off` is the DEX file offset of the containing code item.  Register
/// sets are conservative operand facts: an empty set means the opcode does
/// not expose that class of operand (or the operand is outside this public
/// summary), never that a value is known to be unused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstructionFact {
    dex: DexEntry,
    method: MethodId,
    code_off: u32,
    pc: u32,
    opcode: u8,
    reads: Vec<u16>,
    writes: Vec<u16>,
    reference: Option<InstructionReference>,
    method_target: Option<MethodIdentity>,
    constant: Option<InstructionConstant>,
    branch_targets: Vec<u32>,
}

impl InstructionFact {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        dex: DexEntry,
        method: MethodId,
        code_off: u32,
        pc: u32,
        opcode: u8,
        reads: Vec<u16>,
        writes: Vec<u16>,
        reference: Option<InstructionReference>,
        method_target: Option<MethodIdentity>,
        constant: Option<InstructionConstant>,
        branch_targets: Vec<u32>,
    ) -> Self {
        Self {
            dex,
            method,
            code_off,
            pc,
            opcode,
            reads,
            writes,
            reference,
            method_target,
            constant,
            branch_targets,
        }
    }

    pub fn dex(&self) -> &DexEntry {
        &self.dex
    }

    pub fn method(&self) -> MethodId {
        self.method
    }

    pub fn code_off(&self) -> u32 {
        self.code_off
    }

    pub fn pc(&self) -> u32 {
        self.pc
    }

    pub fn opcode(&self) -> u8 {
        self.opcode
    }

    pub fn reads(&self) -> &[u16] {
        &self.reads
    }

    pub fn writes(&self) -> &[u16] {
        &self.writes
    }

    pub fn reference(&self) -> Option<InstructionReference> {
        self.reference
    }

    /// Full symbolic identity when `reference` is a method-table operand.
    /// External methods that are not declarations in the selected DEX still
    /// resolve here because the provider reads the method table directly.
    pub fn method_target(&self) -> Option<&MethodIdentity> {
        self.method_target.as_ref()
    }

    pub fn constant(&self) -> Option<InstructionConstant> {
        self.constant
    }

    pub fn branch_targets(&self) -> &[u32] {
        &self.branch_targets
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
    Literal {
        source: String,
        units: Vec<u16>,
    },
    Regex {
        source: String,
        regex: fancy_regex::Regex,
    },
}

impl Pattern {
    /// Literal substring pattern; matched over UTF-16 code units.
    pub fn literal(text: &str, limits: &PatternLimits) -> Result<Self, Error> {
        reject_blank_pattern(text)?;
        check_pattern_bytes(text, limits)?;
        Ok(Pattern::Literal {
            source: text.to_owned(),
            units: text.encode_utf16().collect(),
        })
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
        Ok(Pattern::Regex {
            source: pattern.to_owned(),
            regex,
        })
    }

    /// The original pattern text as supplied by the caller.
    #[allow(dead_code)] // A07/A08 wiring surface
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
            Pattern::Literal { units: needle, .. } => Ok(if contains_units(units, needle) {
                MatchOutcome::Match
            } else {
                MatchOutcome::NoMatch
            }),
            Pattern::Regex { regex, .. } => {
                let Some(text) = String::from_utf16(units).ok() else {
                    return Ok(MatchOutcome::Unsupported);
                };
                regex
                    .is_match(&text)
                    .map(|hit| {
                        if hit {
                            MatchOutcome::Match
                        } else {
                            MatchOutcome::NoMatch
                        }
                    })
                    .map_err(|error| {
                        Error::resource_limit(format!("regex execution over limit: {error}"))
                    })
            }
        }
    }

    /// Convenience for callers that already hold valid Unicode text.
    #[allow(dead_code)] // A07/A08 wiring surface
    pub fn matches_str(&self, text: &str) -> Result<MatchOutcome, Error> {
        match self {
            Pattern::Literal { .. } => {
                let units: Vec<u16> = text.encode_utf16().collect();
                self.matches_utf16(&units)
            }
            Pattern::Regex { regex, .. } => regex
                .is_match(text)
                .map(|hit| {
                    if hit {
                        MatchOutcome::Match
                    } else {
                        MatchOutcome::NoMatch
                    }
                })
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
        Ok(Self {
            name,
            declaring_class,
        })
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
    #[allow(dead_code)] // A07/A08 wiring surface
    pub fn none() -> Self {
        Self { units: Vec::new() }
    }

    /// Lowercases valid Unicode scalars (non-locale); unpaired surrogates in
    /// the input cannot be lowered and are kept as-is.
    pub fn new(filter: &str) -> Self {
        #[allow(dead_code)] // A07/A08 wiring surface; used by contract tests
        Self {
            units: lowercase_units(&filter.encode_utf16().collect::<Vec<_>>()),
        }
    }

    #[allow(dead_code)] // A07/A08 wiring surface
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
    #[allow(dead_code)] // A07/A08 wiring surface
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
    #[allow(dead_code)] // A07/A08 wiring surface
    Query,
    Decompile,
    Manifest,
}

impl Stage {
    #[allow(dead_code)] // A07/A08 wiring surface
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
    #[allow(dead_code)] // A07/A08 wiring surface
    Info,
    Warning,
    #[allow(dead_code)] // A07/A08 wiring surface
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
    #[allow(dead_code)] // A08 projection surface
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

    #[allow(dead_code)] // A08 diagnostic projection
    pub(crate) fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    #[allow(dead_code)] // A08 projection surface
    pub fn code(&self) -> DiagnosticCode {
        self.code
    }

    #[allow(dead_code)] // A08 projection surface
    pub fn severity(&self) -> Severity {
        self.severity
    }

    #[allow(dead_code)] // A08 projection surface
    pub fn stage(&self) -> Stage {
        self.stage
    }

    #[allow(dead_code)] // A08 projection surface
    pub fn dex(&self) -> Option<DexId> {
        self.dex
    }

    #[allow(dead_code)] // A08 projection surface
    pub fn class(&self) -> Option<ClassId> {
        self.class
    }

    #[allow(dead_code)] // A08 projection surface
    pub fn method(&self) -> Option<MethodId> {
        self.method
    }

    #[allow(dead_code)] // A08 projection surface
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
pub struct Report<T> {
    pub(crate) value: T,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: OperationStats,
    /// The measured result allocation remains charged while this report (or
    /// one of its clones) is alive. Consumer-side serialization is outside
    /// this core ledger.
    pub(crate) memory: Option<MemoryPermit>,
}

/*
 * Keep the accounting token out of debug output. Apart from being an
 * implementation detail, its Arc address would make otherwise identical
 * reports print differently across runs.
 */
impl<T: fmt::Debug> fmt::Debug for Report<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Report")
            .field("value", &self.value)
            .field("diagnostics", &self.diagnostics)
            .field("stats", &self.stats)
            .finish()
    }
}

impl<T> Report<T> {
    pub(crate) fn new(value: T, diagnostics: Vec<Diagnostic>, stats: OperationStats) -> Self {
        Self {
            value,
            diagnostics,
            stats,
            memory: None,
        }
    }

    pub(crate) fn with_memory(mut self, memory: MemoryPermit) -> Self {
        self.memory = Some(memory);
        self
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    #[allow(dead_code)] // A08 payload projection
    pub fn into_value(self) -> T {
        self.value
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[allow(dead_code)] // A08 debug surface (never in payload)
    pub fn stats(&self) -> OperationStats {
        self.stats
    }
}

impl<T: Clone> Clone for Report<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            diagnostics: self.diagnostics.clone(),
            stats: self.stats,
            memory: self.memory.clone(),
        }
    }
}

impl<T: PartialEq> PartialEq for Report<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
            && self.diagnostics == other.diagnostics
            && self.stats == other.stats
    }
}

impl<T: Eq> Eq for Report<T> {}

// ---------------------------------------------------------------------------
// Source and metadata (shapes frozen; population lands with A05/A07)
// ---------------------------------------------------------------------------

/// A DEX encoded value, bit-exact: floats and doubles keep their raw bits so
/// no textual rounding can change a constant.
/// A08/A12 projection surface: the typed values populate
/// `SourceMetadata`/annotation records as the backend exposes raw forms.
#[allow(dead_code)]
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
    Field {
        owner: DexText,
        name: DexText,
        field_type: DexText,
    },
    Method {
        owner: DexText,
        name: DexText,
        prototype: Prototype,
    },
    Enum {
        owner: DexText,
        name: DexText,
    },
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
    /// The backend's lossless rendering of the whole annotation element
    /// list. Typed reconstruction into `items` lands when the decompiler
    /// exposes raw encoded values across the checked API; until then this
    /// field is the lossless record (design §4: 元素渲染无损).
    pub(crate) rendered: String,
}

impl AnnotationRecord {
    pub(crate) fn new(
        visibility: AnnotationVisibility,
        type_descriptor: DexText,
        items: Vec<(DexText, EncodedValue)>,
        rendered: String,
    ) -> Self {
        Self {
            visibility,
            type_descriptor,
            items,
            rendered,
        }
    }

    #[allow(dead_code)] // A08 projection surface
    pub fn visibility(&self) -> AnnotationVisibility {
        self.visibility
    }

    #[allow(dead_code)] // A08 projection surface
    pub fn type_descriptor(&self) -> &DexText {
        &self.type_descriptor
    }

    #[allow(dead_code)] // A08 projection surface
    pub fn items(&self) -> &[(DexText, EncodedValue)] {
        &self.items
    }

    /// Lossless backend rendering of the element list (see `items`).
    #[allow(dead_code)] // A08 projection surface
    pub fn rendered(&self) -> &str {
        &self.rendered
    }
}

/// What an annotation is attached to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnnotationTarget {
    Class,
    Field {
        index: usize,
    },
    Method {
        index: usize,
    },
    Parameter {
        method_index: usize,
        parameter_index: usize,
    },
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
        Self {
            class,
            text,
            metadata,
        }
    }

    #[allow(dead_code)] // A08 projection surface
    pub fn class(&self) -> &Class {
        &self.class
    }

    /// UTF-8, LF line endings, exactly one trailing LF.
    pub fn text(&self) -> &str {
        &self.text
    }

    #[allow(dead_code)] // A08 projection surface
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

#[allow(dead_code)] // consumed by A08's renderer
pub mod dto {
    use super::*;

    /// Minimal JSON writer: fixed key order is call-ordered, control
    /// characters are `\u00xx`-escaped, non-ASCII characters are emitted raw.
    ///
    /// The writer carries an optional byte budget: once a push would grow the
    /// output past it, the push is refused and the writer freezes (never
    /// allocates beyond the budget), so a bounded serialization cannot grow
    /// without limit. `finish` keeps the historical unbounded behaviour for
    /// the golden tests; the CLI completes through `try_finish`.
    pub struct Writer {
        out: String,
        /// Per open container: whether a comma must precede the next element.
        need_comma: Vec<bool>,
        budget: usize,
        over: bool,
    }

    impl Default for Writer {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Writer {
        pub fn new() -> Self {
            Self {
                out: String::new(),
                need_comma: vec![false],
                budget: usize::MAX,
                over: false,
            }
        }

        pub fn raw(value: &str) -> String {
            let mut writer = Writer::new();
            writer.string(value);
            writer.finish()
        }

        /// Freezes the output once growth would exceed `max` bytes.
        pub fn set_budget(&mut self, max: usize) {
            self.budget = max;
        }

        /// Bytes written so far (frozen at the budget once over).
        pub fn len(&self) -> usize {
            self.out.len()
        }

        pub fn is_empty(&self) -> bool {
            self.out.is_empty()
        }

        /// True once a push was refused for exceeding the budget.
        pub fn over_budget(&self) -> bool {
            self.over
        }

        /// The bounded completion: a writer that crossed its budget is a
        /// `ResourceLimit`, never a truncated payload.
        pub fn try_finish(self) -> Result<String, Error> {
            if self.over {
                return Err(Error::resource_limit(format!(
                    "serialized payload exceeds the {} byte result-bytes limit",
                    self.budget
                )));
            }
            Ok(self.out)
        }

        /// Single funnel for all output growth: refuses (and freezes) the
        /// push that would cross the budget, before allocating for it.
        fn push_raw(&mut self, text: &str) {
            if self.over {
                return;
            }
            if self.out.len() + text.len() > self.budget {
                self.over = true;
                return;
            }
            self.out.push_str(text);
        }

        fn push_char(&mut self, character: char) {
            if self.over {
                return;
            }
            if self.out.len() + character.len_utf8() > self.budget {
                self.over = true;
                return;
            }
            self.out.push(character);
        }

        fn prefix(&mut self) {
            if *self.need_comma.last().unwrap_or(&false) {
                self.push_raw(",");
                if let Some(flag) = self.need_comma.last_mut() {
                    *flag = false;
                }
            }
        }

        pub fn begin_object(&mut self) {
            self.prefix();
            self.push_raw("{");
            self.need_comma.push(false);
        }

        pub fn end_object(&mut self) {
            self.need_comma.pop();
            self.push_raw("}");
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        pub fn begin_array(&mut self) {
            self.prefix();
            self.push_raw("[");
            self.need_comma.push(false);
        }

        pub fn end_array(&mut self) {
            self.need_comma.pop();
            self.push_raw("]");
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        /// Writes `"key":`; the value write follows immediately.
        pub fn key(&mut self, key: &str) {
            self.prefix();
            self.string_unprefixed(key);
            self.push_raw(":");
        }

        pub fn string(&mut self, value: &str) {
            self.prefix();
            self.string_unprefixed(value);
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        fn string_unprefixed(&mut self, value: &str) {
            self.push_raw("\"");
            for character in value.chars() {
                match character {
                    '"' => self.push_raw("\\\""),
                    '\\' => self.push_raw("\\\\"),
                    '\n' => self.push_raw("\\n"),
                    '\r' => self.push_raw("\\r"),
                    '\t' => self.push_raw("\\t"),
                    '\u{08}' => self.push_raw("\\b"),
                    '\u{0c}' => self.push_raw("\\f"),
                    character if (character as u32) < 0x20 => {
                        self.push_raw(&format!("\\u{:04x}", character as u32));
                    }
                    character => self.push_char(character),
                }
            }
            self.push_raw("\"");
        }

        pub fn number(&mut self, value: u64) {
            self.prefix();
            self.push_raw(&value.to_string());
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        /// Writes a signed integer without going through a u64 cast.
        pub fn signed(&mut self, value: i64) {
            self.prefix();
            self.push_raw(&value.to_string());
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        /// Fixed-width lowercase hex string for raw typed bits (float/double/
        /// long words), so no JS consumer can lose precision on them.
        pub fn hex_bits(&mut self, bits: u64, width: usize) {
            self.prefix();
            self.push_raw(&format!("\"0x{bits:0width$x}\""));
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        pub fn boolean(&mut self, value: bool) {
            self.prefix();
            self.push_raw(if value { "true" } else { "false" });
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        pub fn null(&mut self) {
            self.prefix();
            self.push_raw("null");
            if let Some(flag) = self.need_comma.last_mut() {
                *flag = true;
            }
        }

        pub fn finish(self) -> String {
            self.out
        }
    }

    /// `{"artifact_id":"…","entry_ordinal":n,"logical_ordinal":n}` plus the
    /// kind-specific index key, in that fixed order.
    pub fn write_dex_id(w: &mut Writer, id: &DexId) {
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

    pub fn write_class_id(w: &mut Writer, id: &ClassId) {
        write_indexed_id(w, &id.dex(), "class_def_idx", id.class_def_idx());
    }

    pub fn write_method_id(w: &mut Writer, id: &MethodId) {
        write_indexed_id(w, &id.dex(), "method_idx", id.method_idx());
    }

    pub fn write_target_id(w: &mut Writer, id: &TargetId) {
        write_indexed_id(w, &id.dex(), "index", id.table_index());
    }

    /// `{"text":<string|null>,"utf16":[…]}` - lossless in both projections.
    pub fn write_dex_text(w: &mut Writer, text: &DexText) {
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

    pub fn write_prototype(w: &mut Writer, prototype: &Prototype) {
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

    pub fn write_dex_entry(w: &mut Writer, entry: &DexEntry) {
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

    pub fn write_target_value(w: &mut Writer, value: &TargetValue) {
        match value {
            TargetValue::String(text) | TargetValue::Type(text) => write_dex_text(w, text),
            TargetValue::Field {
                owner,
                name,
                field_type,
            } => {
                w.begin_object();
                w.key("owner");
                write_dex_text(w, owner);
                w.key("name");
                write_dex_text(w, name);
                w.key("field_type");
                write_dex_text(w, field_type);
                w.end_object();
            }
            TargetValue::Method {
                owner,
                name,
                prototype,
            } => {
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

    /// One `targets` entry: `{"id":…,"kind":…,"value":…,"code_unit_offsets":[…]}`.
    /// Shared by `write_reference` and the CLI's text-mode targets-json column.
    pub fn write_target_match(w: &mut Writer, target: &TargetMatch) {
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

    pub fn write_reference(w: &mut Writer, reference: &Reference) {
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
            write_target_match(w, target);
        }
        w.end_array();
        w.end_object();
    }

    pub fn write_class(w: &mut Writer, class: &Class) {
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
    pub fn write_diagnostic(w: &mut Writer, diagnostic: &Diagnostic) {
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
    pub fn write_envelope(
        operation: &str,
        artifact: &ArtifactId,
        diagnostics: &[Diagnostic],
        write_data: impl FnOnce(&mut Writer),
    ) -> String {
        write_envelope_result(operation, artifact, diagnostics, |writer| {
            write_data(writer);
            Ok(())
        })
        .expect("unbudgeted envelope cannot fail")
    }

    /// Same envelope, but the data writer may fail (budget/cancel checks) and
    /// the completion refuses a writer that crossed its byte budget. The CLI's
    /// bounded serialization path drives this variant.
    pub fn write_envelope_result(
        operation: &str,
        artifact: &ArtifactId,
        diagnostics: &[Diagnostic],
        write_data: impl FnOnce(&mut Writer) -> Result<(), Error>,
    ) -> Result<String, Error> {
        let mut w = Writer::new();
        w.begin_object();
        w.key("schema_version");
        w.number(1);
        w.key("operation");
        w.string(operation);
        w.key("artifact_id");
        w.string(&artifact.hex());
        w.key("data");
        write_data(&mut w)?;
        w.key("diagnostics");
        w.begin_array();
        for diagnostic in diagnostics {
            write_diagnostic(&mut w, diagnostic);
        }
        w.end_array();
        w.end_object();
        w.try_finish()
    }

    /// The error object: `{"code":"…","context":[…],"diagnostics":[…]}`.
    pub fn write_error(error: &crate::error::Error) -> String {
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

    // -- SourceMetadata projection (getclass `metadata`) --------------------
    //
    // Frozen shapes for schemas/cli-v1.schema.json $defs.source_metadata;
    // absent optional data serializes as null, never a fabricated default.
    // Raw typed bits (float/double/long words) use fixed-width hex strings.

    pub fn write_source_metadata(w: &mut Writer, metadata: &SourceMetadata) {
        w.begin_object();
        w.key("class");
        write_class_metadata(w, &metadata.class);
        w.key("annotations");
        w.begin_array();
        for entry in &metadata.annotations {
            write_annotation_entry(w, entry);
        }
        w.end_array();
        w.key("fields");
        w.begin_array();
        for field in &metadata.fields {
            write_field_metadata(w, field);
        }
        w.end_array();
        w.key("methods");
        w.begin_array();
        for method in &metadata.methods {
            write_method_metadata(w, method);
        }
        w.end_array();
        w.end_object();
    }

    fn write_class_metadata(w: &mut Writer, class: &ClassMetadata) {
        w.begin_object();
        w.key("access_flags");
        w.number(class.access_flags as u64);
        w.key("super_class");
        write_optional_text(w, class.super_class.as_ref());
        w.key("interfaces");
        w.begin_array();
        for interface in &class.interfaces {
            write_dex_text(w, interface);
        }
        w.end_array();
        w.key("source_file");
        write_optional_text(w, class.source_file.as_ref());
        w.key("generic_signature");
        write_optional_text(w, class.generic_signature.as_ref());
        w.key("enclosing");
        match &class.enclosing {
            Some(enclosing) => write_enclosing_record(w, enclosing),
            None => w.null(),
        }
        w.key("inner_classes");
        w.begin_array();
        for inner in &class.inner_classes {
            write_inner_class_record(w, inner);
        }
        w.end_array();
        w.end_object();
    }

    fn write_enclosing_record(w: &mut Writer, enclosing: &EnclosingRecord) {
        w.begin_object();
        w.key("outer_class");
        write_optional_text(w, enclosing.outer_class.as_ref());
        w.key("enclosing_method");
        match &enclosing.enclosing_method {
            // The model keeps a positional triple (rendered text, name,
            // prototype); serialized positionally until A12 types it.
            Some((first, second, prototype)) => {
                w.begin_array();
                write_dex_text(w, first);
                write_dex_text(w, second);
                write_prototype(w, prototype);
                w.end_array();
            }
            None => w.null(),
        }
        w.end_object();
    }

    fn write_inner_class_record(w: &mut Writer, inner: &InnerClassRecord) {
        w.begin_object();
        w.key("inner_class");
        write_dex_text(w, &inner.inner_class);
        w.key("outer_class");
        write_optional_text(w, inner.outer_class.as_ref());
        w.key("inner_name");
        write_optional_text(w, inner.inner_name.as_ref());
        w.key("access_flags");
        w.number(inner.access_flags as u64);
        w.end_object();
    }

    fn write_annotation_entry(w: &mut Writer, entry: &AnnotationEntry) {
        w.begin_object();
        w.key("target");
        write_annotation_target(w, &entry.target);
        w.key("annotation");
        write_annotation_record(w, &entry.annotation);
        w.end_object();
    }

    fn write_annotation_target(w: &mut Writer, target: &AnnotationTarget) {
        w.begin_object();
        match target {
            AnnotationTarget::Class => {
                w.key("target");
                w.string("class");
            }
            AnnotationTarget::Field { index } => {
                w.key("target");
                w.string("field");
                w.key("index");
                w.number(*index as u64);
            }
            AnnotationTarget::Method { index } => {
                w.key("target");
                w.string("method");
                w.key("index");
                w.number(*index as u64);
            }
            AnnotationTarget::Parameter {
                method_index,
                parameter_index,
            } => {
                w.key("target");
                w.string("parameter");
                w.key("method_index");
                w.number(*method_index as u64);
                w.key("parameter_index");
                w.number(*parameter_index as u64);
            }
        }
        w.end_object();
    }

    fn write_annotation_record(w: &mut Writer, annotation: &AnnotationRecord) {
        w.begin_object();
        w.key("visibility");
        let visibility = match annotation.visibility() {
            AnnotationVisibility::Build => "build",
            AnnotationVisibility::Runtime => "runtime",
            AnnotationVisibility::System => "system",
        };
        w.string(visibility);
        w.key("type_descriptor");
        write_dex_text(w, annotation.type_descriptor());
        w.key("items");
        w.begin_array();
        for (name, value) in annotation.items() {
            w.begin_object();
            w.key("name");
            write_dex_text(w, name);
            w.key("value");
            write_encoded_value(w, value);
            w.end_object();
        }
        w.end_array();
        w.key("rendered");
        w.string(annotation.rendered());
        w.end_object();
    }

    fn write_encoded_value(w: &mut Writer, value: &EncodedValue) {
        w.begin_object();
        w.key("type");
        match value {
            EncodedValue::Null => {
                w.string("null");
                w.key("value");
                w.null();
            }
            EncodedValue::Boolean(inner) => {
                w.string("boolean");
                w.key("value");
                w.boolean(*inner);
            }
            EncodedValue::Byte(inner) => {
                w.string("byte");
                w.key("value");
                w.signed(i64::from(*inner));
            }
            EncodedValue::Short(inner) => {
                w.string("short");
                w.key("value");
                w.signed(i64::from(*inner));
            }
            EncodedValue::Int(inner) => {
                w.string("int");
                w.key("value");
                w.signed(i64::from(*inner));
            }
            // 64-bit words keep their exact bit pattern in a fixed-width hex
            // string; a JSON number would lose precision in JS consumers.
            EncodedValue::Long(inner) => {
                w.string("long");
                w.key("value");
                w.hex_bits(*inner as u64, 16);
            }
            EncodedValue::Char(inner) => {
                w.string("char");
                w.key("value");
                w.number(u64::from(*inner));
            }
            EncodedValue::Float(bits) => {
                w.string("float");
                w.key("bits");
                w.hex_bits(u64::from(*bits), 8);
            }
            EncodedValue::Double(bits) => {
                w.string("double");
                w.key("bits");
                w.hex_bits(*bits, 16);
            }
            EncodedValue::String(inner) => {
                w.string("string");
                w.key("value");
                write_dex_text(w, inner);
            }
            EncodedValue::Type(inner) => {
                w.string("type");
                w.key("value");
                write_dex_text(w, inner);
            }
            EncodedValue::Field {
                owner,
                name,
                field_type,
            } => {
                w.string("field");
                w.key("value");
                w.begin_object();
                w.key("owner");
                write_dex_text(w, owner);
                w.key("name");
                write_dex_text(w, name);
                w.key("field_type");
                write_dex_text(w, field_type);
                w.end_object();
            }
            EncodedValue::Method {
                owner,
                name,
                prototype,
            } => {
                w.string("method");
                w.key("value");
                w.begin_object();
                w.key("owner");
                write_dex_text(w, owner);
                w.key("name");
                write_dex_text(w, name);
                w.key("prototype");
                write_prototype(w, prototype);
                w.end_object();
            }
            EncodedValue::Enum { owner, name } => {
                w.string("enum");
                w.key("value");
                w.begin_object();
                w.key("owner");
                write_dex_text(w, owner);
                w.key("name");
                write_dex_text(w, name);
                w.end_object();
            }
            EncodedValue::Array(inner) => {
                w.string("array");
                w.key("value");
                w.begin_array();
                for element in inner {
                    write_encoded_value(w, element);
                }
                w.end_array();
            }
            EncodedValue::Annotation(inner) => {
                w.string("annotation");
                w.key("value");
                write_annotation_record(w, inner);
            }
        }
        w.end_object();
    }

    fn write_field_metadata(w: &mut Writer, field: &FieldMetadata) {
        w.begin_object();
        w.key("name");
        write_dex_text(w, &field.name);
        w.key("field_type");
        write_dex_text(w, &field.field_type);
        w.key("access_flags");
        w.number(field.access_flags as u64);
        w.key("generic_signature");
        write_optional_text(w, field.generic_signature.as_ref());
        w.key("initial_value");
        match &field.initial_value {
            Some(value) => write_encoded_value(w, value),
            None => w.null(),
        }
        w.end_object();
    }

    fn write_method_metadata(w: &mut Writer, method: &MethodMetadata) {
        w.begin_object();
        w.key("name");
        write_dex_text(w, &method.name);
        w.key("prototype");
        write_prototype(w, &method.prototype);
        w.key("access_flags");
        w.number(method.access_flags as u64);
        w.key("generic_signature");
        write_optional_text(w, method.generic_signature.as_ref());
        w.key("throws");
        w.begin_array();
        for throws in &method.throws {
            write_dex_text(w, throws);
        }
        w.end_array();
        w.key("annotations");
        w.begin_array();
        for entry in &method.annotations {
            write_annotation_entry(w, entry);
        }
        w.end_array();
        w.key("parameter_signatures");
        w.begin_array();
        for signature in &method.parameter_signatures {
            write_optional_text(w, signature.as_ref());
        }
        w.end_array();
        w.key("debug");
        match &method.debug {
            Some(debug) => write_debug_info(w, debug),
            None => w.null(),
        }
        w.end_object();
    }

    fn write_debug_info(w: &mut Writer, debug: &DebugInfo) {
        w.begin_object();
        w.key("parameter_names");
        w.begin_array();
        for name in &debug.parameter_names {
            write_optional_text(w, name.as_ref());
        }
        w.end_array();
        w.key("locals");
        w.begin_array();
        for local in &debug.locals {
            w.begin_object();
            w.key("name");
            write_dex_text(w, &local.name);
            w.key("start_code_unit");
            w.number(local.start_code_unit as u64);
            w.key("end_code_unit");
            w.number(local.end_code_unit as u64);
            w.key("slot");
            w.number(u64::from(local.slot));
            w.end_object();
        }
        w.end_array();
        w.key("lines");
        w.begin_array();
        for line in &debug.lines {
            w.begin_object();
            w.key("code_unit");
            w.number(line.code_unit as u64);
            w.key("line");
            w.number(line.line as u64);
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }

    fn write_optional_text(w: &mut Writer, text: Option<&DexText>) {
        match text {
            Some(text) => write_dex_text(w, text),
            None => w.null(),
        }
    }
}
