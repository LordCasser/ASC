//! Borrowed-buffer DEX reader and reference scanner.
//!
//! The scanner deliberately avoids a full DEX object model: it reads the tables it
//! needs straight out of the inflated bytes, walks class data with checked bounds
//! and decodes only instructions that can carry a reference. Two invariants keep
//! that fast and correct - every reference instruction stores its index as a
//! little-endian operand at `pc + 2` (which is what the target pre-filter relies
//! on), and the opcode width/kind tables are mirrored by independently written
//! transcriptions in the tests.
//!
//! Two entry layers live here:
//! - the *contract* layer ([`scan_references`]) produces the frozen domain
//!   results (full caller/target identity, code-unit offsets, limits and
//!   cancellation) from one [`DexView`]; tests/contract_references.rs is its
//!   consumer today and A07 wires it into the CLI;
//! - the *legacy* layer (`find_references`/`defines_class`/`class_names`) is
//!   the text-row bridge `apk.rs` still calls. A07 deletes it; do not extend.

pub(crate) mod container;
mod filter;
mod mutf8;
mod opcodes;
pub(crate) mod prefix;

use crate::bytes::{ControlProbe, read_u16, read_u32};
use crate::error::Error;
use crate::model::{
    ClassConstraint, DexEntry, DexText, MatchOutcome, MemberQuery as ContractMemberQuery,
    MethodIdentity, MethodId, Pattern, Prototype, Reference, ReferenceQuery, TargetId,
    TargetKind, TargetMatch, TargetValue,
};
use crate::query::{ClassQuery, MemberQuery, Query};
use anyhow::{Context, Result, bail};
use filter::Targets;
use memchr::memmem::Finder;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

/// Class lists at least this large are split across workers during the scan.
const PARALLEL_SCAN_CLASSES: usize = 64;
/// Minimum classes per split; keeps splitting overhead negligible on huge DEXes.
const PARALLEL_SCAN_MIN_CHUNK: usize = 8;

#[derive(Clone, Copy, Debug)]
struct Header {
    strings_size: usize,
    strings_off: usize,
    types_size: usize,
    types_off: usize,
    protos_size: usize,
    protos_off: usize,
    fields_size: usize,
    fields_off: usize,
    methods_size: usize,
    methods_off: usize,
    classes_size: usize,
    classes_off: usize,
}

#[derive(Clone, Copy, Debug)]
struct MemberId {
    class_idx: u16,
    name_idx: u32,
}

/// Legacy bridge kept for `apk.rs`; replaced by [`scan_references`] and
/// deleted by A07.
pub fn defines_class(data: &[u8], descriptor: &[u8]) -> Result<bool> {
    let dex = Dex::parse(data)?;
    // Resolve each class_def's own type id rather than looking up "the" type id
    // for the descriptor: a DEX may repeat a descriptor across several type ids
    // (the spec only requires them to be sorted, and crafted or merged files do
    // repeat one), and `class_names` reads each class_def's own id. A
    // first-match-only lookup would make `classes` list a class that `getclass`
    // then cannot find.
    for index in 0..dex.header.classes_size {
        let offset = dex.header.classes_off + index * 32;
        let type_idx = dex.u32(offset)? as usize;
        if let Ok(string_idx) = dex.type_string_idx(type_idx)
            && dex.string_bytes(string_idx)? == descriptor
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Legacy bridge kept for `apk.rs`; replaced by [`scan_references`] and
/// deleted by A07.
pub fn class_names(data: &[u8]) -> Result<Vec<String>> {
    let dex = Dex::parse(data)?;
    let mut names = Vec::with_capacity(dex.header.classes_size);
    for index in 0..dex.header.classes_size {
        let class_def = dex.header.classes_off + index * 32;
        names.push(dex.type_name(dex.u32(class_def)? as usize)?);
    }
    Ok(names)
}

/// One reference hit: where it was found, what references the target, and which
/// of the query's targets that method references.
///
/// The scanner returns these as data; rendering them into output lines is the
/// CLI's job, so the output format lives in exactly one place.
///
/// Legacy text-row shape kept for `apk.rs`; replaced by [`scan_references`]
/// and deleted by A07.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceRow {
    /// Descriptor of the defining class, e.g. `Lcom/foo/Main;`.
    pub class_name: String,
    /// Name of the referencing method.
    pub method_name: String,
    /// Names of the referenced targets, in ascending index order.
    pub matched: Vec<String>,
}

/// Legacy bridge kept for `apk.rs`; replaced by [`scan_references`] and
/// deleted by A07.
pub fn find_references(data: &[u8], query: &Query) -> Result<Vec<ReferenceRow>> {
    let dex = Dex::parse(data)?;
    let (kind, targets) = dex.resolve_targets(query)?;
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let targets = Targets::new(targets);
    let hits = dex.scan_all_classes(kind, &targets)?;
    let mut rows = Vec::with_capacity(hits.len());
    for (method_idx, matched) in hits {
        let method = dex.method(method_idx as usize)?;
        let mut matched_names = Vec::with_capacity(matched.len());
        for index in matched {
            matched_names.push(dex.target_name(kind, index as usize)?);
        }
        rows.push(ReferenceRow {
            class_name: dex.type_name(method.class_idx as usize)?,
            method_name: dex.string(method.name_idx as usize)?,
            matched: matched_names,
        });
    }
    Ok(rows)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefKind {
    String,
    Type,
    Method,
    Field,
}

impl RefKind {
    /// Bit used by the per-opcode kind mask.
    const fn bit(self) -> u8 {
        match self {
            RefKind::String => 1,
            RefKind::Type => 2,
            RefKind::Method => 4,
            RefKind::Field => 8,
        }
    }
}

struct Dex<'a> {
    data: &'a [u8],
    header: Header,
}

impl<'a> Dex<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x70 || !data.starts_with(b"dex\n") {
            bail!("invalid DEX header");
        }
        let header = Header {
            strings_size: read_u32(data, 0x38)? as usize,
            strings_off: read_u32(data, 0x3c)? as usize,
            types_size: read_u32(data, 0x40)? as usize,
            types_off: read_u32(data, 0x44)? as usize,
            protos_size: read_u32(data, 0x48)? as usize,
            protos_off: read_u32(data, 0x4c)? as usize,
            fields_size: read_u32(data, 0x50)? as usize,
            fields_off: read_u32(data, 0x54)? as usize,
            methods_size: read_u32(data, 0x58)? as usize,
            methods_off: read_u32(data, 0x5c)? as usize,
            classes_size: read_u32(data, 0x60)? as usize,
            classes_off: read_u32(data, 0x64)? as usize,
        };
        for (offset, count, width, name) in [
            (header.strings_off, header.strings_size, 4, "string_ids"),
            (header.types_off, header.types_size, 4, "type_ids"),
            (header.protos_off, header.protos_size, 12, "proto_ids"),
            (header.fields_off, header.fields_size, 8, "field_ids"),
            (header.methods_off, header.methods_size, 8, "method_ids"),
            (header.classes_off, header.classes_size, 32, "class_defs"),
        ] {
            check_table(data, offset, count, width, name)?;
        }
        Ok(Self { data, header })
    }

    fn u32(&self, offset: usize) -> Result<u32> {
        read_u32(self.data, offset)
    }

    fn string_bytes(&self, index: usize) -> Result<&'a [u8]> {
        if index >= self.header.strings_size {
            bail!("string index out of range");
        }
        let mut offset = self.u32(self.header.strings_off + index * 4)? as usize;
        if offset >= self.data.len() {
            bail!("string_data_off outside DEX");
        }
        read_uleb(self.data, &mut offset)?;
        let tail = self.data.get(offset..).context("bad string data offset")?;
        let end = memchr::memchr(0, tail).context("unterminated DEX string")?;
        Ok(&tail[..end])
    }

    fn string(&self, index: usize) -> Result<String> {
        let bytes = self.string_bytes(index)?;
        Ok(mutf8::decode_lossy_string(bytes))
    }

    fn type_string_idx(&self, index: usize) -> Result<usize> {
        if index >= self.header.types_size {
            bail!("type index out of range");
        }
        Ok(self.u32(self.header.types_off + index * 4)? as usize)
    }

    fn type_name(&self, index: usize) -> Result<String> {
        self.string(self.type_string_idx(index)?)
    }

    fn method(&self, index: usize) -> Result<MemberId> {
        self.member(self.header.methods_off, self.header.methods_size, index)
    }

    fn field(&self, index: usize) -> Result<MemberId> {
        self.member(self.header.fields_off, self.header.fields_size, index)
    }

    fn member(&self, base: usize, size: usize, index: usize) -> Result<MemberId> {
        if index >= size {
            bail!("member index out of range");
        }
        let offset = base + index * 8;
        Ok(MemberId {
            class_idx: read_u16(self.data, offset)?,
            name_idx: self.u32(offset + 4)?,
        })
    }

    fn matching_strings(&self, pattern: &str) -> Result<Vec<u32>> {
        if pattern.is_empty() {
            return Ok(Vec::new());
        }
        let needle = mutf8::encode_mutf8(pattern);
        let finder = Finder::new(&needle);
        let mut out = Vec::new();
        for index in 0..self.header.strings_size {
            if finder.find(self.string_bytes(index)?).is_some() {
                out.push(index as u32);
            }
        }
        Ok(out)
    }

    fn matching_types(&self, pattern: &str) -> Result<Vec<u32>> {
        let strings: BTreeSet<u32> = self.matching_strings(pattern)?.into_iter().collect();
        let mut out = Vec::new();
        for index in 0..self.header.types_size {
            if strings.contains(&(self.type_string_idx(index)? as u32)) {
                out.push(index as u32);
            }
        }
        Ok(out)
    }

    fn resolve_targets(&self, query: &Query) -> Result<(RefKind, Vec<u32>)> {
        match query {
            Query::String(pattern) => Ok((RefKind::String, self.matching_strings(pattern)?)),
            Query::Type(pattern) => Ok((RefKind::Type, self.matching_types(pattern)?)),
            Query::Method(query) => Ok((RefKind::Method, self.matching_members(query, true)?)),
            Query::Field(query) => Ok((RefKind::Field, self.matching_members(query, false)?)),
        }
    }

    fn matching_members(&self, query: &MemberQuery, methods: bool) -> Result<Vec<u32>> {
        let (base, size) = if methods {
            (self.header.methods_off, self.header.methods_size)
        } else {
            (self.header.fields_off, self.header.fields_size)
        };
        let name_finder = query
            .name
            .as_deref()
            .map(|pattern| Finder::new(pattern.as_bytes()));
        let class_finder = match &query.class {
            Some(ClassQuery::Fuzzy(pattern)) => Some(Finder::new(pattern.as_bytes())),
            _ => None,
        };
        let mut out = Vec::new();
        for index in 0..size {
            let member = self.member(base, size, index)?;
            let name_matches = match &name_finder {
                Some(finder) => finder
                    .find(self.string_bytes(member.name_idx as usize)?)
                    .is_some(),
                None => true,
            };
            if !name_matches {
                continue;
            }
            let class_name_idx = self.type_string_idx(member.class_idx as usize)?;
            let class_bytes = self.string_bytes(class_name_idx)?;
            let class_matches = match &query.class {
                None => true,
                Some(ClassQuery::Exact(name)) => class_bytes == name.as_bytes(),
                Some(ClassQuery::Fuzzy(_)) => class_finder
                    .as_ref()
                    .is_some_and(|finder| finder.find(class_bytes).is_some()),
            };
            if class_matches {
                out.push(index as u32);
            }
        }
        Ok(out)
    }

    fn target_name(&self, kind: RefKind, index: usize) -> Result<String> {
        match kind {
            RefKind::String => self.string(index),
            RefKind::Type => self.type_name(index),
            RefKind::Method | RefKind::Field => {
                let member = if kind == RefKind::Method {
                    self.method(index)?
                } else {
                    self.field(index)?
                };
                Ok(format!(
                    "{}->{}",
                    self.type_name(member.class_idx as usize)?,
                    self.string(member.name_idx as usize)?
                ))
            }
        }
    }

    /// Scans every class definition, optionally splitting the class list across
    /// idle workers.
    ///
    /// A single large DEX otherwise owns one worker for the whole scan while the
    /// rest of the pool waits, which shows up as tail latency once the smaller
    /// entries are done. Hit sets are unioned, so the merged result does not
    /// depend on how the split happened to be stolen.
    fn scan_all_classes(
        &self,
        kind: RefKind,
        targets: &Targets,
    ) -> Result<BTreeMap<u32, BTreeSet<u32>>> {
        if self.header.classes_size < PARALLEL_SCAN_CLASSES {
            self.scan_all_classes_sequential(kind, targets)
        } else {
            self.scan_all_classes_parallel(kind, targets)
        }
    }

    fn scan_all_classes_sequential(
        &self,
        kind: RefKind,
        targets: &Targets,
    ) -> Result<BTreeMap<u32, BTreeSet<u32>>> {
        let mut hits = BTreeMap::new();
        for class_index in 0..self.header.classes_size {
            self.scan_class_index(class_index, kind, targets, &mut hits)?;
        }
        Ok(hits)
    }

    fn scan_all_classes_parallel(
        &self,
        kind: RefKind,
        targets: &Targets,
    ) -> Result<BTreeMap<u32, BTreeSet<u32>>> {
        (0..self.header.classes_size)
            .into_par_iter()
            .with_min_len(PARALLEL_SCAN_MIN_CHUNK)
            .try_fold(BTreeMap::new, |mut hits, class_index| {
                self.scan_class_index(class_index, kind, targets, &mut hits)?;
                Ok(hits)
            })
            .try_reduce(BTreeMap::new, |mut left, right| {
                for (method_idx, matched) in right {
                    left.entry(method_idx).or_default().extend(matched);
                }
                Ok(left)
            })
    }

    fn scan_class_index(
        &self,
        class_index: usize,
        kind: RefKind,
        targets: &Targets,
        hits: &mut BTreeMap<u32, BTreeSet<u32>>,
    ) -> Result<()> {
        let class_def = self.header.classes_off + class_index * 32;
        let class_data_off = self.u32(class_def + 24)? as usize;
        if class_data_off != 0 {
            self.scan_class_data(class_data_off, kind, targets, hits)?;
        }
        Ok(())
    }

    fn scan_class_data(
        &self,
        offset: usize,
        kind: RefKind,
        targets: &Targets,
        hits: &mut BTreeMap<u32, BTreeSet<u32>>,
    ) -> Result<()> {
        let mut cursor = offset;
        let static_fields = read_uleb(self.data, &mut cursor)? as usize;
        let instance_fields = read_uleb(self.data, &mut cursor)? as usize;
        let direct_methods = read_uleb(self.data, &mut cursor)? as usize;
        let virtual_methods = read_uleb(self.data, &mut cursor)? as usize;
        for _ in 0..static_fields + instance_fields {
            read_uleb(self.data, &mut cursor)?;
            read_uleb(self.data, &mut cursor)?;
        }
        for count in [direct_methods, virtual_methods] {
            let mut method_idx = 0u32;
            for _ in 0..count {
                method_idx = method_idx
                    .checked_add(read_uleb(self.data, &mut cursor)?)
                    .context("method index overflow")?;
                read_uleb(self.data, &mut cursor)?;
                let code_off = read_uleb(self.data, &mut cursor)? as usize;
                if code_off != 0 {
                    self.scan_code(method_idx, code_off, kind, targets, hits)?;
                }
            }
        }
        Ok(())
    }

    fn scan_code(
        &self,
        method_idx: u32,
        code_off: usize,
        kind: RefKind,
        targets: &Targets,
        hits: &mut BTreeMap<u32, BTreeSet<u32>>,
    ) -> Result<()> {
        let insns_size = self.u32(code_off + 12)? as usize;
        let start = code_off.checked_add(16).context("code offset overflow")?;
        let end = start
            .checked_add(insns_size.checked_mul(2).context("code size overflow")?)
            .context("code range overflow")?;
        let code = self.data.get(start..end).context("code item outside DEX")?;
        if !targets.might_reference(code) {
            return Ok(());
        }
        let kind_bit = kind.bit();
        let mut pc = 0usize;
        while pc + 2 <= code.len() {
            let opcode = code[pc];
            let units = opcodes::OPCODE_UNITS[opcode as usize] as usize;
            let units = if units == 0 {
                opcodes::instruction_units(code, pc)?
            } else {
                units
            };
            if units == 0 || pc + units * 2 > code.len() {
                bail!("invalid instruction width at code offset {}", start + pc);
            }
            // 0x1b is the only reference instruction with a 32-bit index, and
            // only the string mask can reach it.
            if opcodes::OPCODE_KINDS[opcode as usize] & kind_bit != 0 {
                let index = if opcode == 0x1b {
                    read_u32(code, pc + 2)?
                } else {
                    read_u16(code, pc + 2)? as u32
                };
                if targets.contains(index) {
                    hits.entry(method_idx).or_default().insert(index);
                }
            }
            pc += units * 2;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Structured scan (A03 contract layer; A07 wires it into the CLI)
// ---------------------------------------------------------------------------
//
// Everything below produces the frozen domain results (Reference with full
// caller/target identity, code-unit offsets, limits and cancellation) from
// one logical DEX view. tests/contract_references.rs consumes it today, so
// items not yet called from the binary carry `allow(dead_code)` until A07.

/// One logical DEX offered to the structured scanner: the physical bytes plus
/// the [`DexEntry`] whose `header_offset` says where this member's header
/// lives inside them (0 for a plain DEX, container-relative for 041 members).
///
/// This adapts A02's `container::ValidatedDexView` handover (bytes +
/// header_offset + id + version; interfaces.md §3) to the full identity the
/// results need: `DexView::new(views.dex_entry(logical), view.bytes())` is
/// the whole adapter, because table offsets read from a member header are
/// absolute positions inside the shared bytes.
#[allow(dead_code)]
pub(crate) struct DexView<'a> {
    entry: DexEntry,
    bytes: &'a [u8],
}

#[allow(dead_code)]
impl<'a> DexView<'a> {
    #[allow(dead_code)]
    pub(crate) fn new(entry: DexEntry, bytes: &'a [u8]) -> Self {
        Self { entry, bytes }
    }

    #[allow(dead_code)]
    pub(crate) fn entry(&self) -> &DexEntry {
        &self.entry
    }
}

/// Scan-scope budgets: the interfaces.md §5 initial values that the scanner
/// itself enforces. A11 folds this struct into the engine-wide Limits table;
/// every field must stay a finite positive number.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScanLimits {
    /// Maximum number of returned top-level `Reference` items.
    pub(crate) max_result_items: usize,
    /// Maximum number of accumulated target code-unit offsets.
    pub(crate) max_reference_locations: u64,
    /// Maximum declared UTF-16 length of one decoded DEX string.
    pub(crate) max_string_units: usize,
    /// Maximum number of rows in one DEX id table.
    pub(crate) max_table_items: usize,
    /// Coarse byte-estimate ceiling for the assembled result.
    pub(crate) max_result_bytes: usize,
}

#[allow(dead_code)]
impl ScanLimits {
    #[allow(dead_code)]
    pub(crate) const DEFAULT: ScanLimits = ScanLimits {
        max_result_items: 250_000,
        max_reference_locations: 1_000_000,
        max_string_units: 1_048_576,
        max_table_items: 4_000_000,
        max_result_bytes: 128 * 1024 * 1024,
    };
}

// Cooperative cancellation for one scan: A02's `bytes::ControlProbe` (an
// external flag plus an optional deadline). The scanner checks it once per
// method and inside long loops at least every [`CHECK_EVERY_CODE_UNITS`]
// code units; A11 renames the wiring into `OperationControl`, not the
// checkpoint contract.

/// Everything the structured scan needs beyond the query itself.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) struct ScanOptions<'a> {
    pub(crate) limits: ScanLimits,
    pub(crate) control: Option<&'a ControlProbe<'a>>,
    /// Whether the byte-level operand pre-filter may skip method bodies. It is
    /// a pure acceleration: on and off must produce identical results.
    pub(crate) prefilter: bool,
}

/// Cancellation checkpoint density inside instruction loops (code units).
const CHECK_EVERY_CODE_UNITS: usize = 4096;
/// Coarse per-row byte estimates for the result-size budget (interfaces.md
/// §5 asks for a checked estimate, not an allocator accounting).
const ESTIMATED_BYTES_PER_CALLER: usize = 320;
const ESTIMATED_BYTES_PER_TARGET: usize = 64;
const ESTIMATED_BYTES_PER_LOCATION: usize = 8;

/// Scans one logical DEX for every reference matching `query`, producing the
/// full caller and target identities with ascending deduplicated code-unit
/// offsets. Rows are ordered by method index, a method's targets by table
/// index; methods sharing a code_item each keep their own row.
#[allow(dead_code)]
pub(crate) fn scan_references(
    view: &DexView<'_>,
    query: &ReferenceQuery,
    options: &ScanOptions<'_>,
) -> Result<Vec<Reference>, Error> {
    let dex = ScanDex::parse(view, &options.limits)?;
    check_control(options.control)?;
    let (kind, values) = dex.match_targets(query, &options.limits, options.control)?;
    // No early exit on an empty target set: a successful result certifies the
    // walked class data and instruction boundaries, so the class walk runs
    // even when the query matched nothing.
    let targets = Targets::with_prefilter(values.keys().copied(), options.prefilter);
    let hits = dex.scan_classes(kind, &targets, options.control)?;
    dex.assemble_references(view, kind, &values, hits, &options.limits, options.control)
}

#[allow(dead_code)]
fn check_control(control: Option<&ControlProbe<'_>>) -> Result<(), Error> {
    control.map_or(Ok(()), ControlProbe::check)
}

/// An unpaired-surrogate candidate that a regex would have to decide: the
/// contract makes this a hard error, never a quiet NoMatch.
#[allow(dead_code)]
fn unsupported_candidate(what: &str, index: u32, units: &[u16]) -> Error {
    let rendered: Vec<String> = units.iter().map(|unit| format!("0x{unit:04x}")).collect();
    Error::unsupported_encoding(format!(
        "candidate {what} #{index} keeps unpaired surrogates (units [{}]) that a regex cannot decide",
        rendered.join(", ")
    ))
}

/// Per-method hits: target index → instruction start offsets in code units.
type MethodHits = BTreeMap<u32, Vec<u32>>;
type Hits = BTreeMap<u32, MethodHits>;

/// The structured scanner's reader over one view. Table offsets read from the
/// member header are absolute positions inside `data` (plain DEX: the file
/// itself; 041 member: the whole container), which is how both layouts keep
/// one address space.
struct ScanDex<'a> {
    data: &'a [u8],
    header: Header,
}

#[allow(dead_code)]
impl<'a> ScanDex<'a> {
    fn parse(view: &DexView<'a>, limits: &ScanLimits) -> Result<Self, Error> {
        let base = view.entry.header_offset() as usize;
        let data = view.bytes;
        let Some(header_end) = base.checked_add(0x70) else {
            return Err(Error::malformed_input("DEX header offset overflows the entry"));
        };
        if data.len() < header_end {
            return Err(Error::malformed_input("DEX header outside the entry bytes"));
        }
        if data.get(base..base + 4) != Some(b"dex\n") {
            return Err(Error::malformed_input("missing DEX magic at the header offset"));
        }
        let read = |offset: usize| -> Result<u32, Error> {
            read_u32(data, base + offset)
                .map_err(|_| Error::malformed_input("truncated DEX header"))
        };
        let header = Header {
            strings_size: read(0x38)? as usize,
            strings_off: read(0x3c)? as usize,
            types_size: read(0x40)? as usize,
            types_off: read(0x44)? as usize,
            protos_size: read(0x48)? as usize,
            protos_off: read(0x4c)? as usize,
            fields_size: read(0x50)? as usize,
            fields_off: read(0x54)? as usize,
            methods_size: read(0x58)? as usize,
            methods_off: read(0x5c)? as usize,
            classes_size: read(0x60)? as usize,
            classes_off: read(0x64)? as usize,
        };
        for (offset, count, width, name) in [
            (header.strings_off, header.strings_size, 4, "string_ids"),
            (header.types_off, header.types_size, 4, "type_ids"),
            (header.protos_off, header.protos_size, 12, "proto_ids"),
            (header.fields_off, header.fields_size, 8, "field_ids"),
            (header.methods_off, header.methods_size, 8, "method_ids"),
            (header.classes_off, header.classes_size, 32, "class_defs"),
        ] {
            check_limited_table(data, offset, count, width, name, limits.max_table_items)?;
        }
        Ok(Self { data, header })
    }

    fn u32(&self, offset: usize) -> Result<u32, Error> {
        read_u32(self.data, offset)
            .map_err(|_| Error::malformed_input(format!("u32 read at 0x{offset:x} outside the DEX")))
    }

    fn u16(&self, offset: usize) -> Result<u16, Error> {
        read_u16(self.data, offset)
            .map_err(|_| Error::malformed_input(format!("u16 read at 0x{offset:x} outside the DEX")))
    }

    fn uleb(&self, cursor: &mut usize) -> Result<u32, Error> {
        read_uleb(self.data, cursor)
            .map_err(|_| Error::malformed_input("truncated ULEB128 inside class data"))
    }

    /// `(declared unit count, bytes after the length prefix)` of string
    /// `index`. The length prefix counts UTF-16 units, not bytes; the payload
    /// region is left untrimmed here because the unit-count-bounded decode in
    /// [`Self::decode_string_into`] decides where the payload must end.
    fn string_payload(&self, index: u32, limits: &ScanLimits) -> Result<(u32, &'a [u8]), Error> {
        if index as usize >= self.header.strings_size {
            return Err(Error::malformed_input(format!(
                "string index {index} outside the string table"
            )));
        }
        let data_off = self.u32(self.header.strings_off + index as usize * 4)? as usize;
        if data_off >= self.data.len() {
            return Err(Error::malformed_input(format!(
                "string #{index} data offset 0x{data_off:x} outside the DEX"
            )));
        }
        let mut cursor = data_off;
        let declared = self.uleb(&mut cursor)?;
        if declared as usize > limits.max_string_units {
            return Err(Error::resource_limit(format!(
                "string #{index} declares {declared} UTF-16 units, above the {} unit limit",
                limits.max_string_units
            )));
        }
        let tail = self
            .data
            .get(cursor..)
            .ok_or_else(|| Error::malformed_input(format!("string #{index} data offset outside the DEX")))?;
        Ok((declared, tail))
    }

    /// Decodes string `index` into `scratch` (cleared first): exactly the
    /// declared number of UTF-16 units, with the terminating NUL required at
    /// that position. A string can therefore never read past its own data -
    /// into a neighbour payload or the alignment padding after the pool - and
    /// a declared count that disagrees with the payload is MalformedInput.
    fn decode_string_into(
        &self,
        index: u32,
        scratch: &mut Vec<u16>,
        limits: &ScanLimits,
    ) -> Result<(), Error> {
        let (declared, payload) = self.string_payload(index, limits)?;
        let consumed = mutf8::decode_units(payload, declared as usize, scratch).map_err(|error| {
            Error::malformed_input(format!("string #{index}: {}", error.describe()))
        })?;
        match payload.get(consumed) {
            Some(0) => Ok(()),
            Some(_) | None => Err(Error::malformed_input(format!(
                "string #{index} is not NUL-terminated"
            ))),
        }
    }

    fn string_text(&self, index: u32, limits: &ScanLimits) -> Result<DexText, Error> {
        let mut scratch = Vec::new();
        self.decode_string_into(index, &mut scratch, limits)?;
        Ok(DexText::from_utf16_units(scratch))
    }

    fn type_string_index(&self, type_idx: u32) -> Result<u32, Error> {
        if type_idx as usize >= self.header.types_size {
            return Err(Error::malformed_input(format!(
                "type index {type_idx} outside the type table"
            )));
        }
        self.u32(self.header.types_off + type_idx as usize * 4)
    }

    fn type_text(&self, type_idx: u32, limits: &ScanLimits) -> Result<DexText, Error> {
        self.string_text(self.type_string_index(type_idx)?, limits)
    }

    /// The full prototype of `proto_idx`, resolved through proto_ids and the
    /// parameter type list; descriptors stay lossless.
    fn prototype(&self, proto_idx: u32, limits: &ScanLimits) -> Result<Prototype, Error> {
        if proto_idx as usize >= self.header.protos_size {
            return Err(Error::malformed_input(format!(
                "proto index {proto_idx} outside the proto table"
            )));
        }
        let offset = self.header.protos_off + proto_idx as usize * 12;
        let shorty_idx = self.u32(offset)?;
        if shorty_idx as usize >= self.header.strings_size {
            return Err(Error::malformed_input(format!(
                "proto #{proto_idx} shorty index outside the string table"
            )));
        }
        let return_type = self.type_text(self.u32(offset + 4)?, limits)?;
        let parameters_off = self.u32(offset + 8)? as usize;
        let mut parameters = Vec::new();
        if parameters_off != 0 {
            let size = self.u32(parameters_off)? as usize;
            let bytes = size
                .checked_mul(4)
                .ok_or_else(|| Error::malformed_input("type list size overflows"))?;
            let end = parameters_off
                .checked_add(4)
                .and_then(|start| start.checked_add(bytes))
                .ok_or_else(|| Error::malformed_input("type list range overflows"))?;
            if end > self.data.len() {
                return Err(Error::malformed_input(format!(
                    "type list at 0x{parameters_off:x} outside the DEX"
                )));
            }
            for position in 0..size {
                parameters.push(
                    self.type_text(self.u32(parameters_off + 4 + position * 4)?, limits)?,
                );
            }
        }
        Ok(Prototype::new(parameters, return_type))
    }

    /// `(class_idx, proto_or_type_idx, name_idx)` of one field/method row.
    fn member_row(&self, methods: bool, index: u32) -> Result<(u16, u16, u32), Error> {
        let (base, size, what) = if methods {
            (self.header.methods_off, self.header.methods_size, "method")
        } else {
            (self.header.fields_off, self.header.fields_size, "field")
        };
        if index as usize >= size {
            return Err(Error::malformed_input(format!(
                "{what} index {index} outside the table"
            )));
        }
        let offset = base + index as usize * 8;
        Ok((self.u16(offset)?, self.u16(offset + 2)?, self.u32(offset + 4)?))
    }

    fn method_identity(
        &self,
        entry: &DexEntry,
        method_idx: u32,
        limits: &ScanLimits,
    ) -> Result<MethodIdentity, Error> {
        let (class_idx, proto_idx, name_idx) = self.member_row(true, method_idx)?;
        let owner = self.type_text(u32::from(class_idx), limits)?;
        let name = self.string_text(name_idx, limits)?;
        let prototype = self.prototype(u32::from(proto_idx), limits)?;
        Ok(MethodIdentity::new(
            MethodId::new(entry.id(), method_idx),
            entry.clone(),
            owner,
            name,
            prototype,
        ))
    }

    /// Resolves the query's target set: every table row whose decoded value
    /// matches, together with the full target value for the result rows.
    fn match_targets(
        &self,
        query: &ReferenceQuery,
        limits: &ScanLimits,
        control: Option<&ControlProbe<'_>>,
    ) -> Result<(TargetKind, BTreeMap<u32, TargetValue>), Error> {
        match query {
            ReferenceQuery::String(pattern) => Ok((
                TargetKind::String,
                self.match_string_table(pattern, limits, control)?,
            )),
            ReferenceQuery::Type(pattern) => Ok((
                TargetKind::Type,
                self.match_type_table(pattern, limits, control)?,
            )),
            ReferenceQuery::Field(member) => Ok((
                TargetKind::Field,
                self.match_member_table(false, member, limits, control)?,
            )),
            ReferenceQuery::Method(member) => Ok((
                TargetKind::Method,
                self.match_member_table(true, member, limits, control)?,
            )),
        }
    }

    fn match_string_table(
        &self,
        pattern: &Pattern,
        limits: &ScanLimits,
        control: Option<&ControlProbe<'_>>,
    ) -> Result<BTreeMap<u32, TargetValue>, Error> {
        let mut values = BTreeMap::new();
        let mut scratch = Vec::new();
        for index in 0..self.header.strings_size as u32 {
            if index > 0 && index.is_multiple_of(4096) {
                check_control(control)?;
            }
            self.decode_string_into(index, &mut scratch, limits)?;
            match pattern.matches_utf16(&scratch)? {
                MatchOutcome::Match => {
                    values.insert(index, TargetValue::String(DexText::from_utf16_units(scratch.clone())));
                }
                MatchOutcome::NoMatch => {}
                MatchOutcome::Unsupported => {
                    return Err(unsupported_candidate("string", index, &scratch));
                }
            }
        }
        Ok(values)
    }

    fn match_type_table(
        &self,
        pattern: &Pattern,
        limits: &ScanLimits,
        control: Option<&ControlProbe<'_>>,
    ) -> Result<BTreeMap<u32, TargetValue>, Error> {
        let mut values = BTreeMap::new();
        let mut scratch = Vec::new();
        for index in 0..self.header.types_size as u32 {
            if index > 0 && index.is_multiple_of(4096) {
                check_control(control)?;
            }
            let string_idx = self.type_string_index(index)?;
            self.decode_string_into(string_idx, &mut scratch, limits)?;
            match pattern.matches_utf16(&scratch)? {
                MatchOutcome::Match => {
                    values.insert(index, TargetValue::Type(DexText::from_utf16_units(scratch.clone())));
                }
                MatchOutcome::NoMatch => {}
                MatchOutcome::Unsupported => {
                    return Err(unsupported_candidate("type descriptor", index, &scratch));
                }
            }
        }
        Ok(values)
    }

    /// Field/method rows against a member query. The name pattern and the
    /// declaring-class constraint are evaluated independently; the exact class
    /// runs first because it is always decidable and may therefore exclude a
    /// candidate before any regex decision is needed.
    fn match_member_table(
        &self,
        methods: bool,
        member: &ContractMemberQuery,
        limits: &ScanLimits,
        control: Option<&ControlProbe<'_>>,
    ) -> Result<BTreeMap<u32, TargetValue>, Error> {
        let size = if methods { self.header.methods_size } else { self.header.fields_size };
        let what = if methods { "method" } else { "field" };
        let exact_units = match member.declaring_class() {
            Some(ClassConstraint::Exact(descriptor)) => {
                Some(descriptor.as_str().encode_utf16().collect::<Vec<u16>>())
            }
            _ => None,
        };
        let mut values = BTreeMap::new();
        let mut scratch = Vec::new();
        for index in 0..size as u32 {
            if index > 0 && index.is_multiple_of(4096) {
                check_control(control)?;
            }
            let (class_idx, proto_or_type_idx, name_idx) = self.member_row(methods, index)?;
            if let Some(exact) = &exact_units {
                let class_string = self.type_string_index(u32::from(class_idx))?;
                self.decode_string_into(class_string, &mut scratch, limits)?;
                if &scratch != exact {
                    continue;
                }
            }
            if let Some(name) = member.name() {
                self.decode_string_into(name_idx, &mut scratch, limits)?;
                match name.matches_utf16(&scratch)? {
                    MatchOutcome::Match => {}
                    MatchOutcome::NoMatch => continue,
                    MatchOutcome::Unsupported => {
                        return Err(unsupported_candidate(&format!("{what} name"), index, &scratch));
                    }
                }
            }
            if let Some(ClassConstraint::Fuzzy(pattern)) = member.declaring_class() {
                let class_string = self.type_string_index(u32::from(class_idx))?;
                self.decode_string_into(class_string, &mut scratch, limits)?;
                match pattern.matches_utf16(&scratch)? {
                    MatchOutcome::Match => {}
                    MatchOutcome::NoMatch => continue,
                    MatchOutcome::Unsupported => {
                        return Err(unsupported_candidate(
                            "declaring class descriptor",
                            index,
                            &scratch,
                        ));
                    }
                }
            }
            let owner = self.type_text(u32::from(class_idx), limits)?;
            let name = self.string_text(name_idx, limits)?;
            let value = if methods {
                let prototype = self.prototype(u32::from(proto_or_type_idx), limits)?;
                TargetValue::Method { owner, name, prototype }
            } else {
                let field_type = self.type_text(u32::from(proto_or_type_idx), limits)?;
                TargetValue::Field { owner, name, field_type }
            };
            values.insert(index, value);
        }
        Ok(values)
    }

    fn scan_classes(
        &self,
        kind: TargetKind,
        targets: &Targets,
        control: Option<&ControlProbe<'_>>,
    ) -> Result<Hits, Error> {
        let mut hits = Hits::new();
        for class_index in 0..self.header.classes_size {
            let class_def = self.header.classes_off + class_index * 32;
            let class_data_off = self.u32(class_def + 24)? as usize;
            if class_data_off != 0 {
                self.scan_class_data(class_data_off, kind, targets, &mut hits, control)?;
            }
        }
        Ok(hits)
    }

    fn scan_class_data(
        &self,
        offset: usize,
        kind: TargetKind,
        targets: &Targets,
        hits: &mut Hits,
        control: Option<&ControlProbe<'_>>,
    ) -> Result<(), Error> {
        let mut cursor = offset;
        let static_fields = self.uleb(&mut cursor)? as usize;
        let instance_fields = self.uleb(&mut cursor)? as usize;
        let direct_methods = self.uleb(&mut cursor)? as usize;
        let virtual_methods = self.uleb(&mut cursor)? as usize;
        let field_count = static_fields
            .checked_add(instance_fields)
            .ok_or_else(|| Error::malformed_input("field count overflow in class data"))?;
        for _ in 0..field_count {
            self.uleb(&mut cursor)?; // field index delta
            self.uleb(&mut cursor)?; // access flags
        }
        let kind_bit = ref_kind(kind).bit();
        for count in [direct_methods, virtual_methods] {
            let mut method_idx = 0u32;
            for _ in 0..count {
                method_idx = method_idx.checked_add(self.uleb(&mut cursor)?).ok_or_else(|| {
                    Error::malformed_input("method index overflow in class data")
                })?;
                self.uleb(&mut cursor)?; // access flags
                let code_off = self.uleb(&mut cursor)? as usize;
                if code_off != 0 {
                    self.scan_code(method_idx, code_off, kind_bit, targets, hits, control)?;
                }
            }
        }
        Ok(())
    }

    /// Walks one code_item's instructions, recording every reference operand
    /// that names a query target. Unknown opcodes and truncated instruction
    /// streams are MalformedInput with the method and code-unit offset; the
    /// packed-switch/sparse-switch/fill-array payloads are consumed whole by
    /// their ident-prefixed widths, so their interior bytes can never produce
    /// references.
    ///
    /// Every instruction boundary is decoded and checked no matter what the
    /// pre-filter decides: the byte filter is a pure acceleration, so it may
    /// only skip the operand matching, never the structural walk (otherwise
    /// pre-filter on/off would disagree about malformed code).
    fn scan_code(
        &self,
        method_idx: u32,
        code_off: usize,
        kind_bit: u8,
        targets: &Targets,
        hits: &mut Hits,
        control: Option<&ControlProbe<'_>>,
    ) -> Result<(), Error> {
        check_control(control)?;
        let malformed = |message: String| Error::malformed_input(format!("method #{method_idx}: {message}"));
        let insns_size = self.u32(code_off + 12)? as usize;
        let Some(start) = code_off.checked_add(16) else {
            return Err(malformed("code item offset overflow".to_owned()));
        };
        let Some(end) = start.checked_add(
            insns_size
                .checked_mul(2)
                .ok_or_else(|| malformed("code size overflow".to_owned()))?,
        ) else {
            return Err(malformed(format!("code range of {insns_size} units overflows")));
        };
        let Some(code) = self.data.get(start..end) else {
            return Err(malformed(format!(
                "code item at 0x{code_off:x} ({insns_size} units) outside the DEX"
            )));
        };
        let match_operands = targets.might_reference(code);
        let mut pc = 0usize;
        let mut next_check = 2 * CHECK_EVERY_CODE_UNITS;
        while pc + 2 <= code.len() {
            if pc >= next_check {
                check_control(control)?;
                next_check = pc + 2 * CHECK_EVERY_CODE_UNITS;
            }
            let opcode = code[pc];
            let units = opcodes::OPCODE_UNITS[opcode as usize] as usize;
            let units = if units == 0 {
                opcodes::instruction_units(code, pc)
                    .map_err(|error| malformed(format!("code unit {pc}: {error}")))?
            } else {
                units
            };
            if units == 0 || pc + units * 2 > code.len() {
                return Err(malformed(format!(
                    "code unit {pc}: invalid instruction width {units}"
                )));
            }
            if match_operands && opcodes::OPCODE_KINDS[opcode as usize] & kind_bit != 0 {
                let operand_error = || malformed(format!("code unit {pc}: operand outside the code item"));
                // 0x1b (const-string/jumbo) is the only reference
                // instruction with a 32-bit index.
                let index = if opcode == 0x1b {
                    read_u32(code, pc + 2).map_err(|_| operand_error())?
                } else {
                    u32::from(read_u16(code, pc + 2).map_err(|_| operand_error())?)
                };
                if targets.contains(index) {
                    // `pc` walks bytes; the reported offsets are 16-bit code
                    // units from the start of the insns array.
                    hits
                        .entry(method_idx)
                        .or_default()
                        .entry(index)
                        .or_default()
                        .push((pc / 2) as u32);
                }
            }
            pc += units * 2;
        }
        Ok(())
    }

    fn assemble_references(
        &self,
        view: &DexView<'_>,
        kind: TargetKind,
        values: &BTreeMap<u32, TargetValue>,
        hits: Hits,
        limits: &ScanLimits,
        control: Option<&ControlProbe<'_>>,
    ) -> Result<Vec<Reference>, Error> {
        let entry = view.entry();
        let mut references = Vec::new();
        let mut locations = 0u64;
        let mut estimated_bytes = 0usize;
        for (method_idx, per_target) in hits {
            check_control(control)?;
            let caller = self.method_identity(entry, method_idx, limits)?;
            let mut matches = Vec::with_capacity(per_target.len());
            for (index, offsets) in per_target {
                locations += offsets.len() as u64;
                if locations > limits.max_reference_locations {
                    return Err(Error::resource_limit(format!(
                        "reference locations reached {locations}, above the {} limit",
                        limits.max_reference_locations
                    )));
                }
                estimated_bytes +=
                    ESTIMATED_BYTES_PER_TARGET + offsets.len() * ESTIMATED_BYTES_PER_LOCATION;
                let value = values.get(&index).cloned().ok_or_else(|| {
                    Error::malformed_input(format!("target {index} lost its resolved value"))
                })?;
                matches.push(TargetMatch::new(
                    TargetId::new(entry.id(), kind, index),
                    value,
                    offsets,
                ));
            }
            estimated_bytes += ESTIMATED_BYTES_PER_CALLER;
            if estimated_bytes > limits.max_result_bytes {
                return Err(Error::resource_limit(format!(
                    "estimated result size reached {estimated_bytes} bytes, above the {} byte limit",
                    limits.max_result_bytes
                )));
            }
            references.push(Reference::new(caller, matches));
            if references.len() > limits.max_result_items {
                return Err(Error::resource_limit(format!(
                    "result reached {} reference rows, above the {} item limit",
                    references.len(),
                    limits.max_result_items
                )));
            }
        }
        Ok(references)
    }
}

/// Bounds- and budget-checked id table range.
fn check_limited_table(
    data: &[u8],
    offset: usize,
    count: usize,
    width: usize,
    name: &str,
    max_items: usize,
) -> Result<(), Error> {
    if count > max_items {
        return Err(Error::resource_limit(format!(
            "{name} holds {count} rows, above the {max_items} table-item limit"
        )));
    }
    let bytes = count
        .checked_mul(width)
        .ok_or_else(|| Error::malformed_input(format!("{name} size overflows")))?;
    let end = offset
        .checked_add(bytes)
        .ok_or_else(|| Error::malformed_input(format!("{name} range overflows")))?;
    if end > data.len() {
        return Err(Error::malformed_input(format!(
            "{name} range 0x{offset:x}..0x{end:x} outside the DEX"
        )));
    }
    Ok(())
}

/// Maps the contract kind onto the opcode-table bit values.
fn ref_kind(kind: TargetKind) -> RefKind {
    match kind {
        TargetKind::String => RefKind::String,
        TargetKind::Type => RefKind::Type,
        TargetKind::Field => RefKind::Field,
        TargetKind::Method => RefKind::Method,
    }
}

fn check_table(data: &[u8], offset: usize, count: usize, width: usize, name: &str) -> Result<()> {
    let end = offset
        .checked_add(count.checked_mul(width).context("table size overflow")?)
        .context("table range overflow")?;
    if end > data.len() {
        bail!("bad {name} range");
    }
    Ok(())
}

fn read_uleb(data: &[u8], offset: &mut usize) -> Result<u32> {
    let mut result = 0u32;
    for shift in [0, 7, 14, 21, 28] {
        let byte = *data.get(*offset).context("truncated ULEB128")?;
        *offset += 1;
        result |= u32::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(result);
        }
    }
    bail!("ULEB128 exceeds 5 bytes")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn push_uleb(out: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return;
            }
        }
    }

    /// Builds a DEX 041 container holding one fixture per entry of `class_counts`.
    ///
    /// Each logical DEX gets a 0x78-byte header whose section offsets point into
    /// the container, and every header records the container size and its own
    /// offset, which is what `logical_dexes` validates.
    pub(crate) fn dex041_container(class_counts: &[usize]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut headers = Vec::new();
        for &count in class_counts {
            let offset = out.len();
            out.extend_from_slice(&const_string_fixture_041(count, offset as u32));
            out[offset..offset + 8].copy_from_slice(b"dex\n041\0");
            write_u32(&mut out, offset + 0x74, offset as u32);
            headers.push(offset);
        }
        let total = out.len() as u32;
        for header in headers {
            // `container_size` is the whole container; each member keeps its own
            // `file_size`, which is what enumerates the members (the reference
            // implementation advances the same way).
            write_u32(&mut out, header + 0x70, total);
        }
        out
    }

    /// Builds a DEX where every class has one direct method whose body is
    /// `const-string v0, "Authorization"` followed by `return-void`.
    ///
    /// The class count is the knob that selects the sequential or the parallel
    /// scan path, so the same fixture can be used to compare the two directly.
    /// DEX header checksum, as droidsaw-dex validates it before parsing.
    fn adler32(bytes: &[u8]) -> u32 {
        let (mut a, mut b) = (1u32, 0u32);
        for byte in bytes {
            a = (a + u32::from(*byte)) % 65521;
            b = (b + a) % 65521;
        }
        (b << 16) | a
    }

    pub(crate) fn const_string_fixture(class_count: usize) -> Vec<u8> {
        const_string_fixture_with(class_count, 0, 0x70)
    }

    /// `const_string_fixture` with a 0x78-byte DEX 041 header, its section offsets
    /// shifted by `base` so the fixture can sit at that container offset.
    fn const_string_fixture_041(class_count: usize, base: u32) -> Vec<u8> {
        const_string_fixture_with(class_count, base, 0x78)
    }

    fn const_string_fixture_with(class_count: usize, base: u32, header_size: usize) -> Vec<u8> {
        assert!(class_count > 0);
        let mut strings = vec!["Authorization".to_owned()];
        for index in 0..class_count {
            strings.push(format!("LFixture{index};"));
        }
        for index in 0..class_count {
            strings.push(format!("m{index}"));
        }
        // "V" (void) backs the single method prototype; without a proto_ids
        // section droidsaw rejects the fixture before decompiling.
        strings.insert(class_count + 1, "V".to_owned());
        let n_strings = strings.len();
        let n_types = class_count + 2;

        let string_ids_off = header_size;
        let type_ids_off = string_ids_off + n_strings * 4;
        let proto_ids_off = type_ids_off + n_types * 4;
        let method_ids_off = proto_ids_off + 12;
        let class_defs_off = method_ids_off + class_count * 8;
        let data_off = class_defs_off + class_count * 32;

        let mut data = Vec::new();
        let mut string_offsets = Vec::with_capacity(n_strings);
        for value in &strings {
            string_offsets.push(data_off + data.len());
            push_uleb(&mut data, value.len() as u32);
            data.extend_from_slice(value.as_bytes());
            data.push(0);
        }

        let mut class_data_offsets = Vec::with_capacity(class_count);
        for index in 0..class_count {
            while !(data_off + data.len()).is_multiple_of(4) {
                data.push(0);
            }
            let code_off = ((data_off + data.len()) as u32) + base;
            data.extend_from_slice(&1_u16.to_le_bytes()); // registers_size: v0
            data.extend_from_slice(&0_u16.to_le_bytes()); // ins_size
            data.extend_from_slice(&0_u16.to_le_bytes()); // outs_size
            data.extend_from_slice(&0_u16.to_le_bytes()); // tries_size
            data.extend_from_slice(&0_u32.to_le_bytes()); // debug_info_off
            data.extend_from_slice(&3_u32.to_le_bytes()); // insns_size in code units
            data.extend_from_slice(&0x001a_u16.to_le_bytes()); // const-string v0, #0
            data.extend_from_slice(&0_u16.to_le_bytes());
            data.extend_from_slice(&0x000e_u16.to_le_bytes()); // return-void

            class_data_offsets.push(data_off + data.len());
            data.push(0); // static_fields_size
            data.push(0); // instance_fields_size
            data.push(1); // direct_methods_size
            data.push(0); // virtual_methods_size
            push_uleb(&mut data, index as u32); // method_idx_diff
            push_uleb(&mut data, 0); // access_flags
            push_uleb(&mut data, code_off);
        }

        let total = data_off + data.len();
        let mut out = vec![0_u8; total];
        out[..8].copy_from_slice(b"dex\n039\0");
        write_u32(&mut out, 0x20, total as u32);
        write_u32(&mut out, 0x24, header_size as u32);
        write_u32(&mut out, 0x28, 0x1234_5678);
        write_u32(&mut out, 0x38, n_strings as u32);
        write_u32(&mut out, 0x3c, (string_ids_off as u32) + base);
        write_u32(&mut out, 0x40, n_types as u32);
        write_u32(&mut out, 0x44, (type_ids_off as u32) + base);
        write_u32(&mut out, 0x48, 1); // proto_ids_size
        write_u32(&mut out, 0x4c, (proto_ids_off as u32) + base);
        write_u32(&mut out, 0x58, class_count as u32);
        write_u32(&mut out, 0x5c, (method_ids_off as u32) + base);
        write_u32(&mut out, 0x60, class_count as u32);
        write_u32(&mut out, 0x64, (class_defs_off as u32) + base);

        for (index, offset) in string_offsets.iter().enumerate() {
            write_u32(
                &mut out,
                string_ids_off + index * 4,
                (*offset as u32) + base,
            );
        }
        write_u32(&mut out, type_ids_off, 0);
        // type_ids[class_count + 1] -> "V", the prototype's return type.
        write_u32(
            &mut out,
            type_ids_off + (class_count + 1) * 4,
            (1 + class_count) as u32,
        );
        // One prototype: shorty "V", returns void, takes no parameters.
        write_u32(&mut out, proto_ids_off, (1 + class_count) as u32);
        write_u32(&mut out, proto_ids_off + 4, (class_count + 1) as u32);
        write_u32(&mut out, proto_ids_off + 8, 0);
        for (index, class_data_off) in class_data_offsets.iter().enumerate() {
            write_u32(&mut out, type_ids_off + (index + 1) * 4, (index + 1) as u32);

            let method = method_ids_off + index * 8;
            write_u16(&mut out, method, (index + 1) as u16);
            write_u16(&mut out, method + 2, 0);
            write_u32(&mut out, method + 4, (2 + class_count + index) as u32);

            let class_def = class_defs_off + index * 32;
            write_u32(&mut out, class_def, (index + 1) as u32);
            write_u32(&mut out, class_def + 8, u32::MAX);
            write_u32(&mut out, class_def + 16, u32::MAX);
            write_u32(&mut out, class_def + 24, (*class_data_off as u32) + base);
        }
        out[data_off..].copy_from_slice(&data);
        // The scanner ignores the checksum, but droidsaw validates it before
        // parsing, so the fixture carries a correct Adler-32 over the payload
        // (everything after the 12-byte checksum/signature prefix).
        let checksum = adler32(&out[12..]);
        write_u32(&mut out, 0x08, checksum);
        out
    }

    /// Rows for `find_references` are grouped by ascending method index, which is
    /// the order the hit map iterates in. Cross-DEX ordering/aggregation happens
    /// later in the APK layer.
    fn expected_rows(class_count: usize) -> Vec<ReferenceRow> {
        (0..class_count)
            .map(|index| ReferenceRow {
                class_name: format!("LFixture{index};"),
                method_name: format!("m{index}"),
                matched: vec!["Authorization".to_owned()],
            })
            .collect()
    }

    #[test]
    fn parallel_and_sequential_scans_produce_identical_hits() {
        let data = const_string_fixture(PARALLEL_SCAN_CLASSES);
        let dex = Dex::parse(&data).unwrap();
        let (kind, targets) = dex
            .resolve_targets(&Query::String("Authorization".to_owned()))
            .unwrap();
        let targets = Targets::new(targets);
        let sequential = dex.scan_all_classes_sequential(kind, &targets).unwrap();
        let parallel = dex.scan_all_classes_parallel(kind, &targets).unwrap();
        assert_eq!(sequential.len(), PARALLEL_SCAN_CLASSES);
        assert_eq!(sequential, parallel);
    }

    #[test]
    fn multi_chunk_parallel_scan_keeps_every_hit() {
        let class_count = PARALLEL_SCAN_CLASSES * 3 + 1;
        let data = const_string_fixture(class_count);
        let rows = find_references(&data, &Query::String("Authorization".to_owned())).unwrap();
        assert_eq!(rows, expected_rows(class_count));
    }

    fn minimal_class_dex(descriptor: &[u8]) -> Vec<u8> {
        let string_ids_off = 0x70;
        let type_ids_off = 0x74;
        let class_defs_off = 0x78;
        let string_data_off = 0x98;
        let mut data = vec![0; string_data_off + descriptor.len() + 2];
        data[..8].copy_from_slice(b"dex\n039\0");
        data[0x38..0x3c].copy_from_slice(&1_u32.to_le_bytes());
        data[0x3c..0x40].copy_from_slice(&(string_ids_off as u32).to_le_bytes());
        data[0x40..0x44].copy_from_slice(&1_u32.to_le_bytes());
        data[0x44..0x48].copy_from_slice(&(type_ids_off as u32).to_le_bytes());
        data[0x60..0x64].copy_from_slice(&1_u32.to_le_bytes());
        data[0x64..0x68].copy_from_slice(&(class_defs_off as u32).to_le_bytes());
        data[string_ids_off..string_ids_off + 4]
            .copy_from_slice(&(string_data_off as u32).to_le_bytes());
        data[string_data_off] = descriptor.len() as u8;
        data[string_data_off + 1..string_data_off + 1 + descriptor.len()]
            .copy_from_slice(descriptor);
        data
    }

    #[test]
    fn lists_defined_classes_from_class_defs() {
        let data = minimal_class_dex(b"Lcom/example/Main;");
        assert_eq!(class_names(&data).unwrap(), ["Lcom/example/Main;"]);
        assert!(defines_class(&data, b"Lcom/example/Main;").unwrap());
    }

    #[test]
    fn fuzzy_patterns_are_literal_substrings() {
        assert!(Finder::new(b".b[").find(b"a.b[c]").is_some());
        assert!(Finder::new(b"a.c").find(b"abc").is_none());
    }

    // -----------------------------------------------------------------------
    // Structured scan unit tests (the full contract matrix lives in
    // tests/contract_references.rs)
    // -----------------------------------------------------------------------

    use crate::error::ErrorKind;
    use crate::model::{DexVersion, PatternLimits};
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    fn structured_view<'a>(data: &'a [u8]) -> DexView<'a> {
        let digest = crate::model::ArtifactId::from_digest([0x5a; 32]);
        let id = crate::model::DexId::new(digest, 0, 0);
        let name = crate::model::DexText::from_str_lossless("classes.dex");
        let entry = crate::model::DexEntry::new(
            id,
            b"classes.dex".to_vec(),
            name.clone(),
            name,
            DexVersion::from_magic_tail(&data[4..8]).expect("supported version"),
            0,
        );
        DexView::new(entry, data)
    }

    #[test]
    fn structured_scan_reports_full_identities() {
        let data = const_string_fixture(3);
        let view = structured_view(&data);
        let query = ReferenceQuery::String(
            Pattern::literal("Auth", &PatternLimits::default()).expect("pattern"),
        );
        let options = ScanOptions {
            limits: ScanLimits::DEFAULT,
            control: None,
            prefilter: true,
        };
        let references = scan_references(&view, &query, &options).unwrap();
        assert_eq!(references.len(), 3, "one row per method");
        let first = &references[0];
        assert_eq!(first.caller().id().method_idx(), 0, "method 0 scans normally");
        assert_eq!(first.caller().dex().id().entry_ordinal(), 0);
        assert_eq!(first.caller().owner().as_str().as_deref(), Some("LFixture0;"));
        assert_eq!(first.caller().name().as_str().as_deref(), Some("m0"));
        assert_eq!(
            first.caller().prototype().return_type().as_str().as_deref(),
            Some("V")
        );
        let target = &first.targets()[0];
        assert_eq!(target.id().table_index(), 0);
        let TargetValue::String(text) = target.value() else {
            panic!("string query must yield a string target");
        };
        assert_eq!(text.as_str().as_deref(), Some("Authorization"));
        assert_eq!(target.code_unit_offsets(), &[0]);
    }

    #[test]
    fn structured_scan_honors_cancellation_and_deadline() {
        let data = const_string_fixture(3);
        let view = structured_view(&data);
        let query = ReferenceQuery::String(
            Pattern::literal("Auth", &PatternLimits::default()).expect("pattern"),
        );
        let cancelled = AtomicBool::new(true);
        let probe = ControlProbe { cancelled: &cancelled, deadline: None };
        let options = ScanOptions {
            limits: ScanLimits::DEFAULT,
            control: Some(&probe),
            prefilter: true,
        };
        let error = scan_references(&view, &query, &options).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::Cancelled { cause: crate::error::CancelCause::User }));

        let live = AtomicBool::new(false);
        let probe = ControlProbe {
            cancelled: &live,
            deadline: Some(Instant::now() - Duration::from_millis(1)),
        };
        let options = ScanOptions {
            limits: ScanLimits::DEFAULT,
            control: Some(&probe),
            prefilter: true,
        };
        let error = scan_references(&view, &query, &options).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::Cancelled { cause: crate::error::CancelCause::Deadline }));
    }

    #[test]
    fn structured_scan_enforces_the_string_unit_limit() {
        let data = const_string_fixture(1);
        let view = structured_view(&data);
        let query = ReferenceQuery::String(
            Pattern::literal("Auth", &PatternLimits::default()).expect("pattern"),
        );
        let options = ScanOptions {
            limits: ScanLimits { max_string_units: 4, ..ScanLimits::DEFAULT },
            control: None,
            prefilter: true,
        };
        let error = scan_references(&view, &query, &options).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::ResourceLimit), "{error}");
    }
}
