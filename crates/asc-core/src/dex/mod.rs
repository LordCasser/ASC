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

use crate::bytes::{ControlProbe, read_u16, read_u32};
use crate::error::Error;
use crate::model::{
    Class, ClassConstraint, ClassDescriptor, ClassId, DexEntry, DexText, MatchOutcome,
    MemberQuery as ContractMemberQuery, MethodId, MethodIdentity, Pattern, Prototype, Reference,
    InstructionConstant, InstructionFact, InstructionReference, ReferenceLocation,
    ReferenceQuery, TargetId, TargetKind, TargetMatch, TargetValue,
};
use filter::Targets;
use std::collections::BTreeMap;

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

/// Conservative upper bound for scanner-owned working structures for one
/// logical DEX. The input bytes themselves are charged by the caller when an
/// archive entry was inflated; this estimate covers table/index maps and a
/// code-sized allowance for hit locations that can be much larger than the
/// final result.
pub(crate) fn estimated_scan_work(
    view: &DexView<'_>,
    limits: &ScanLimits,
) -> Result<u64, Error> {
    let dex = ScanDex::parse(view, limits)?;
    let mut bytes = 4096u64.saturating_add(view.bytes.len() as u64);
    for (count, per_row) in [
        (dex.header.strings_size, 64u64),
        (dex.header.types_size, 32),
        (dex.header.protos_size, 64),
        (dex.header.fields_size, 96),
        (dex.header.methods_size, 128),
        (dex.header.classes_size, 256),
    ] {
        bytes = bytes.saturating_add(
            u64::try_from(count)
                .unwrap_or(u64::MAX)
                .saturating_mul(per_row),
        );
    }
    Ok(bytes)
}

/// Scan-scope budgets: the interfaces.md §5 initial values that the scanner
/// itself enforces. A11 folds this struct into the engine-wide Limits table;
/// every field must stay a finite positive number.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanLimits {
    /// Maximum number of returned top-level `Reference` items.
    pub max_result_items: usize,
    /// Maximum number of accumulated target code-unit offsets.
    pub max_reference_locations: u64,
    /// Maximum declared UTF-16 length of one decoded DEX string.
    pub max_string_units: usize,
    /// Maximum number of rows in one DEX id table.
    pub max_table_items: usize,
    /// Coarse byte-estimate ceiling for the assembled result.
    pub max_result_bytes: usize,
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

/// Every class definition of one view, in class_def order — the rows of
/// the `classes` operation. Duplicate descriptors are kept: the identity
/// is `(DexId, class_def_idx)`, never the descriptor text.
pub(crate) fn list_classes(
    view: &DexView<'_>,
    limits: &ScanLimits,
    control: Option<&ControlProbe<'_>>,
) -> Result<Vec<Class>, Error> {
    let dex = ScanDex::parse(view, limits)?;
    check_control(control)?;
    let mut out = Vec::with_capacity(dex.header.classes_size);
    for index in 0..dex.header.classes_size {
        let class_def = dex.header.classes_off + index * 32;
        let type_idx = dex.u32(class_def)?;
        let descriptor = dex.type_text(type_idx, limits)?;
        let text = descriptor.as_str().ok_or_else(|| {
            Error::malformed_input(format!(
                "class_def #{index}: descriptor {descriptor:?} is not representable Unicode"
            ))
        })?;
        let validated = ClassDescriptor::from_normalized(text.clone()).map_err(|_| {
            Error::malformed_input(format!(
                "class_def #{index}: descriptor {text} violates the L..; class descriptor grammar"
            ))
        })?;
        out.push(Class::new(
            ClassId::new(view.entry().id(), index as u32),
            view.entry().clone(),
            validated,
        ));
    }
    Ok(out)
}

/// Every string-pool row in one logical DEX, including strings that no code
/// item references. The pool index is part of the returned identity.
pub(crate) fn list_strings(
    view: &DexView<'_>,
    limits: &ScanLimits,
    control: Option<&ControlProbe<'_>>,
) -> Result<Vec<(u32, DexText)>, Error> {
    let dex = ScanDex::parse(view, limits)?;
    check_control(control)?;
    let mut out = Vec::with_capacity(dex.header.strings_size);
    for index in 0..dex.header.strings_size as u32 {
        if index > 0 && index.is_multiple_of(4096) {
            check_control(control)?;
        }
        out.push((index, dex.string_text(index, limits)?));
    }
    Ok(out)
}

/// Every structurally decoded instruction in one logical DEX.  This is the
/// small typed provider used by adapters that need bounded value propagation;
/// it shares the scanner's checked width walk and never exposes the borrowed
/// DEX bytes.
pub(crate) fn list_instructions(
    view: &DexView<'_>,
    limits: &ScanLimits,
    control: Option<&ControlProbe<'_>>,
) -> Result<Vec<InstructionFact>, Error> {
    let dex = ScanDex::parse(view, limits)?;
    check_control(control)?;
    let mut out = Vec::new();
    for class_index in 0..dex.header.classes_size {
        let class_def = dex.header.classes_off + class_index * 32;
        let class_data_off = dex.u32(class_def + 24)? as usize;
        if class_data_off == 0 {
            continue;
        }
        let mut cursor = class_data_off;
        let static_fields = dex.uleb(&mut cursor)? as usize;
        let instance_fields = dex.uleb(&mut cursor)? as usize;
        let direct_methods = dex.uleb(&mut cursor)? as usize;
        let virtual_methods = dex.uleb(&mut cursor)? as usize;
        for _ in 0..static_fields.saturating_add(instance_fields) {
            dex.uleb(&mut cursor)?;
            dex.uleb(&mut cursor)?;
        }
        let mut method_idx = 0u32;
        for method_count in [direct_methods, virtual_methods] {
            for _ in 0..method_count {
                method_idx = method_idx
                    .checked_add(dex.uleb(&mut cursor)?)
                    .ok_or_else(|| Error::malformed_input("method index overflow in class data"))?;
                dex.uleb(&mut cursor)?; // access flags
                let code_off = dex.uleb(&mut cursor)? as usize;
                if code_off != 0 {
                    dex.list_code_instructions(
                        method_idx,
                        code_off,
                        view.entry().clone(),
                        limits,
                        control,
                        &mut out,
                    )?;
                }
            }
        }
    }
    Ok(out)
}

/// The class_def indices of one view whose descriptor equals `descriptor`.
/// More than one index is legal (a DEX may define the same descriptor
/// twice); the caller keeps every definition and selects by identity.
pub(crate) fn locate_class(
    view: &DexView<'_>,
    descriptor: &ClassDescriptor,
    limits: &ScanLimits,
    control: Option<&ControlProbe<'_>>,
) -> Result<Vec<u32>, Error> {
    let dex = ScanDex::parse(view, limits)?;
    check_control(control)?;
    let wanted: Vec<u16> = descriptor.as_str().encode_utf16().collect();
    let mut out = Vec::new();
    for index in 0..dex.header.classes_size {
        let class_def = dex.header.classes_off + index * 32;
        let type_idx = dex.u32(class_def)?;
        let text = dex.type_text(type_idx, limits)?;
        if text.utf16_units() == wanted.as_slice() {
            out.push(index as u32);
        }
    }
    Ok(out)
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
type MethodHits = BTreeMap<u32, Vec<ReferenceLocation>>;
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
            return Err(Error::malformed_input(
                "DEX header offset overflows the entry",
            ));
        };
        if data.len() < header_end {
            return Err(Error::malformed_input("DEX header outside the entry bytes"));
        }
        if data.get(base..base + 4) != Some(b"dex\n") {
            return Err(Error::malformed_input(
                "missing DEX magic at the header offset",
            ));
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
        read_u32(self.data, offset).map_err(|_| {
            Error::malformed_input(format!("u32 read at 0x{offset:x} outside the DEX"))
        })
    }

    fn u16(&self, offset: usize) -> Result<u16, Error> {
        read_u16(self.data, offset).map_err(|_| {
            Error::malformed_input(format!("u16 read at 0x{offset:x} outside the DEX"))
        })
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
        let tail = self.data.get(cursor..).ok_or_else(|| {
            Error::malformed_input(format!("string #{index} data offset outside the DEX"))
        })?;
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
        let consumed =
            mutf8::decode_units(payload, declared as usize, scratch).map_err(|error| {
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
            // PATCHED (asc, A07): type_list entries are 16-bit type indexes
            // (DEX spec §type-list), not 32-bit — the u32 stride read garbage
            // on every real prototype that takes parameters (all synthetic
            // fixtures had zero-parameter prototypes, so tests never hit it).
            let bytes = size
                .checked_mul(2)
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
                    self.type_text(self.u16(parameters_off + 4 + position * 2)? as u32, limits)?,
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
        Ok((
            self.u16(offset)?,
            self.u16(offset + 2)?,
            self.u32(offset + 4)?,
        ))
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
                    values.insert(
                        index,
                        TargetValue::String(DexText::from_utf16_units(scratch.clone())),
                    );
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
                    values.insert(
                        index,
                        TargetValue::Type(DexText::from_utf16_units(scratch.clone())),
                    );
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
        let size = if methods {
            self.header.methods_size
        } else {
            self.header.fields_size
        };
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
                        return Err(unsupported_candidate(
                            &format!("{what} name"),
                            index,
                            &scratch,
                        ));
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
                TargetValue::Method {
                    owner,
                    name,
                    prototype,
                }
            } else {
                let field_type = self.type_text(u32::from(proto_or_type_idx), limits)?;
                TargetValue::Field {
                    owner,
                    name,
                    field_type,
                }
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
                method_idx = method_idx
                    .checked_add(self.uleb(&mut cursor)?)
                    .ok_or_else(|| Error::malformed_input("method index overflow in class data"))?;
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
        let malformed =
            |message: String| Error::malformed_input(format!("method #{method_idx}: {message}"));
        let insns_size = self.u32(code_off + 12)? as usize;
        let Some(start) = code_off.checked_add(16) else {
            return Err(malformed("code item offset overflow".to_owned()));
        };
        let Some(end) = start.checked_add(
            insns_size
                .checked_mul(2)
                .ok_or_else(|| malformed("code size overflow".to_owned()))?,
        ) else {
            return Err(malformed(format!(
                "code range of {insns_size} units overflows"
            )));
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
                let operand_error =
                    || malformed(format!("code unit {pc}: operand outside the code item"));
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
                    hits.entry(method_idx)
                        .or_default()
                        .entry(index)
                        .or_default()
                        .push(ReferenceLocation::new(
                            u32::try_from(code_off).map_err(|_| {
                                malformed("code item offset exceeds the public u32 range".to_owned())
                            })?,
                            u32::try_from(pc / 2).map_err(|_| {
                                malformed("code-unit pc exceeds the public u32 range".to_owned())
                            })?,
                            opcode,
                        ));
                }
            }
            pc += units * 2;
        }
        Ok(())
    }

    /// Decode one method's code item into typed operand facts.  The width and
    /// payload checks intentionally share the scanner's opcode table; operand
    /// details are additive and can never make malformed code appear valid.
    fn list_code_instructions(
        &self,
        method_idx: u32,
        code_off: usize,
        entry: DexEntry,
        limits: &ScanLimits,
        control: Option<&ControlProbe<'_>>,
        out: &mut Vec<InstructionFact>,
    ) -> Result<(), Error> {
        check_control(control)?;
        let malformed = |message: String| {
            Error::malformed_input(format!("method #{method_idx}: {message}"))
        };
        let insns_size = self.u32(code_off + 12)? as usize;
        let start = code_off
            .checked_add(16)
            .ok_or_else(|| malformed("code item offset overflow".to_owned()))?;
        let end = start
            .checked_add(
                insns_size
                    .checked_mul(2)
                    .ok_or_else(|| malformed("code size overflow".to_owned()))?,
            )
            .ok_or_else(|| malformed(format!("code range of {insns_size} units overflows")))?;
        let code = self.data.get(start..end).ok_or_else(|| {
            malformed(format!(
                "code item at 0x{code_off:x} ({insns_size} units) outside the DEX"
            ))
        })?;
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
                opcodes::instruction_units(code, pc).map_err(|error| {
                    malformed(format!("code unit {}: {error}", pc / 2))
                })?
            } else {
                units
            };
            if units == 0 || pc + units * 2 > code.len() {
                return Err(malformed(format!(
                    "code unit {}: invalid instruction width {units}",
                    pc / 2
                )));
            }
            let read16 = |offset: usize| -> Result<u16, Error> {
                read_u16(code, pc + offset)
                    .map_err(|_| malformed(format!("code unit {}: operand outside code item", pc / 2)))
            };
            let read32 = |offset: usize| -> Result<u32, Error> {
                read_u32(code, pc + offset)
                    .map_err(|_| malformed(format!("code unit {}: operand outside code item", pc / 2)))
            };
            let first = read16(0)?;
            let second = (units > 1).then(|| read16(2)).transpose()?;
            let third = (units > 2).then(|| read16(4)).transpose()?;
            let fourth = (units > 3).then(|| read16(6)).transpose()?;
            let mut reads = Vec::new();
            let mut writes = Vec::new();
            let mut reference = None;
            let mut constant = None;
            let mut branch_targets = Vec::new();
            let a = ((first >> 8) & 0x0f) as u16;
            let b = ((first >> 12) & 0x0f) as u16;
            let aa = (first >> 8) as u16;
            let add_branch = |delta: i64, branches: &mut Vec<u32>| {
                let target = (pc / 2) as i64 + delta;
                if (0..=u32::MAX as i64).contains(&target) {
                    branches.push(target as u32);
                }
            };
            let add_switch_targets = |delta: i64, branches: &mut Vec<u32>| -> Result<(), Error> {
                let payload_units = (pc / 2) as i64 + delta;
                if payload_units < 0 {
                    return Err(malformed(format!(
                        "code unit {}: switch payload is before the code item",
                        pc / 2
                    )));
                }
                let payload = (payload_units as usize)
                    .checked_mul(2)
                    .ok_or_else(|| malformed("switch payload offset overflows".to_owned()))?;
                let payload_header_end = payload
                    .checked_add(4)
                    .ok_or_else(|| malformed("switch payload header overflows".to_owned()))?;
                if payload_header_end > code.len() {
                    return Err(malformed(format!(
                        "code unit {}: switch payload header outside code item",
                        pc / 2
                    )));
                }
                let ident = read_u16(code, payload)
                    .map_err(|_| malformed(format!("code unit {}: switch payload outside code item", pc / 2)))?;
                let size = usize::from(read_u16(code, payload + 2).map_err(|_| {
                    malformed(format!("code unit {}: switch payload size outside code item", pc / 2))
                })?);
                let (target_offset, target_count) = match ident {
                    0x0100 => (payload.checked_add(8).ok_or_else(|| {
                        malformed("packed-switch target offset overflows".to_owned())
                    })?, size),
                    0x0200 => {
                        let keys = size
                            .checked_mul(4)
                            .ok_or_else(|| malformed("sparse-switch key table overflows".to_owned()))?;
                        (payload
                            .checked_add(4)
                            .and_then(|offset| offset.checked_add(keys))
                            .ok_or_else(|| malformed("sparse-switch target offset overflows".to_owned()))?, size)
                    }
                    _ => return Err(malformed(format!(
                        "code unit {}: unknown switch payload ident 0x{ident:04x}",
                        pc / 2
                    ))),
                };
                let target_bytes = target_count
                    .checked_mul(4)
                    .ok_or_else(|| malformed("switch target table overflows".to_owned()))?;
                let target_end = target_offset
                    .checked_add(target_bytes)
                    .ok_or_else(|| malformed("switch target range overflows".to_owned()))?;
                if target_end > code.len() {
                    return Err(malformed(format!(
                        "code unit {}: switch targets outside code item",
                        pc / 2
                    )));
                }
                for index in 0..target_count {
                    let offset = target_offset + index * 4;
                    let low = read_u16(code, offset)
                        .map_err(|_| malformed("switch target offset outside code item".to_owned()))?;
                    let high = read_u16(code, offset + 2)
                        .map_err(|_| malformed("switch target offset outside code item".to_owned()))?;
                    let relative = i32::from_le_bytes([
                        low as u8,
                        (low >> 8) as u8,
                        high as u8,
                        (high >> 8) as u8,
                    ]);
                    let target = (pc / 2) as i64 + i64::from(relative);
                    if (0..=u32::MAX as i64).contains(&target) {
                        branches.push(target as u32);
                    }
                }
                Ok(())
            };
            match opcode {
                // 12x register moves and unary arithmetic.
                0x01 | 0x04 | 0x07 | 0x7b..=0x8f => {
                    writes.push(a);
                    reads.push(b);
                }
                // 22x move/from16, and the 22c forms that have register
                // effects handled below.
                0x02 | 0x05 | 0x08 => {
                    writes.push(aa);
                    reads.push(second.unwrap_or_default());
                }
                // 32x move/16.
                0x03 | 0x06 | 0x09 => {
                    writes.push(second.unwrap_or_default());
                    reads.push(third.unwrap_or_default());
                }
                // move-result* and move-exception.
                0x0a..=0x0d => writes.push(aa),
                // return*; return-void has no register.
                0x0f..=0x11 => reads.push(aa),
                // const/4, const/16, const, const/high16 and wide forms.
                0x12 => {
                    writes.push(a);
                    constant = Some(InstructionConstant::Int(((first as i8) >> 4) as i64));
                }
                0x13 | 0x16 => {
                    writes.push(aa);
                    constant = Some(InstructionConstant::Int(
                        second.unwrap_or_default() as i16 as i64,
                    ));
                }
                0x14 => {
                    writes.push(aa);
                    let low = u32::from(second.unwrap_or_default());
                    let high = u32::from(third.unwrap_or_default());
                    constant = Some(InstructionConstant::Int(((high << 16) | low) as i32 as i64));
                }
                0x15 => {
                    writes.push(aa);
                    constant = Some(InstructionConstant::Int(
                        (second.unwrap_or_default() as i16 as i32 as i64) << 16,
                    ));
                }
                0x17 => {
                    writes.push(aa);
                    let low = u32::from(second.unwrap_or_default());
                    let high = u32::from(third.unwrap_or_default());
                    constant = Some(InstructionConstant::Int(
                        i32::from_le_bytes([
                            low as u8,
                            (low >> 8) as u8,
                            high as u8,
                            (high >> 8) as u8,
                        ]) as i64,
                    ));
                }
                0x18 => {
                    writes.push(aa);
                    let words = [
                        u64::from(second.unwrap_or_default()),
                        u64::from(third.unwrap_or_default()),
                        u64::from(fourth.unwrap_or_default()),
                        u64::from(read16(8)?),
                    ];
                    let value = words
                        .into_iter()
                        .enumerate()
                        .fold(0u64, |value, (index, word)| value | (word << (index * 16)));
                    constant = Some(InstructionConstant::Int(value as i64));
                }
                0x19 => {
                    writes.push(aa);
                    constant = Some(InstructionConstant::Int(
                        (second.unwrap_or_default() as i16 as i64) << 48,
                    ));
                }
                // const-string and type references.
                0x1a => {
                    writes.push(aa);
                    let index = u32::from(second.unwrap_or_default());
                    reference = Some(InstructionReference::String { index });
                    constant = Some(InstructionConstant::String { index });
                }
                0x1b => {
                    writes.push(aa);
                    let index = read32(2)?;
                    reference = Some(InstructionReference::String { index });
                    constant = Some(InstructionConstant::String { index });
                }
                0x1c => {
                    writes.push(aa);
                    reference = Some(InstructionReference::Type {
                        index: u32::from(second.unwrap_or_default()),
                    });
                }
                0x1d | 0x1e | 0x27 => reads.push(aa),
                0x1f => {
                    reads.push(aa);
                    writes.push(aa);
                    reference = Some(InstructionReference::Type {
                        index: u32::from(second.unwrap_or_default()),
                    });
                }
                0x20 => {
                    reads.push(b);
                    writes.push(a);
                    reference = Some(InstructionReference::Type {
                        index: u32::from(second.unwrap_or_default()),
                    });
                }
                0x21 => {
                    reads.push(b);
                    writes.push(a);
                }
                0x22 => {
                    writes.push(aa);
                    reference = Some(InstructionReference::Type {
                        index: u32::from(second.unwrap_or_default()),
                    });
                }
                0x23 => {
                    reads.push(b);
                    writes.push(a);
                    reference = Some(InstructionReference::Type {
                        index: u32::from(second.unwrap_or_default()),
                    });
                }
                0x24 | 0x25 => {
                    let count = ((first >> 8) & 0xff) as usize;
                    let word = third.unwrap_or_default();
                    for index in 0..count.min(5) {
                        reads.push(match index {
                            0 => (word & 0x0f) as u16,
                            1 => ((word >> 4) & 0x0f) as u16,
                            2 => ((word >> 8) & 0x0f) as u16,
                            3 => ((word >> 12) & 0x0f) as u16,
                            _ => ((first >> 12) & 0x0f) as u16,
                        });
                    }
                    reference = Some(InstructionReference::Type {
                        index: u32::from(second.unwrap_or_default()),
                    });
                }
                // unconditional and conditional branches
                0x28 => add_branch((first >> 8) as i8 as i64, &mut branch_targets),
                0x29 => add_branch(second.unwrap_or_default() as i16 as i64, &mut branch_targets),
                0x2a => {
                    let low = second.unwrap_or_default();
                    let high = third.unwrap_or_default();
                    let delta = i32::from_le_bytes([
                        low as u8,
                        (low >> 8) as u8,
                        high as u8,
                        (high >> 8) as u8,
                    ]);
                    add_branch(i64::from(delta), &mut branch_targets);
                }
                0x2b | 0x2c => {
                    reads.push(aa);
                    let low = second.unwrap_or_default();
                    let high = third.unwrap_or_default();
                    let delta = i32::from_le_bytes([
                        low as u8,
                        (low >> 8) as u8,
                        high as u8,
                        (high >> 8) as u8,
                    ]);
                    add_switch_targets(i64::from(delta), &mut branch_targets)?;
                }
                0x2d..=0x31 => {
                    writes.push(a);
                    reads.push(b);
                    reads.push((second.unwrap_or_default() >> 8) as u16);
                }
                0x32..=0x37 => {
                    reads.push(a);
                    reads.push(b);
                    add_branch(second.unwrap_or_default() as i16 as i64, &mut branch_targets);
                }
                0x38..=0x3d => {
                    reads.push(aa);
                    add_branch(second.unwrap_or_default() as i16 as i64, &mut branch_targets);
                }
                // array get/put: A is the result for get and the value for put;
                // B is the array and C is the index.
                0x44..=0x4a => {
                    writes.push(a);
                    reads.push(b);
                    reads.push((second.unwrap_or_default() >> 8) as u16);
                }
                0x4b..=0x51 => {
                    reads.push(a);
                    reads.push(b);
                    reads.push((second.unwrap_or_default() >> 8) as u16);
                }
                // field references and their register effects
                0x52..=0x58 => {
                    writes.push(a);
                    reads.push(b);
                    reference = Some(InstructionReference::Field {
                        index: u32::from(second.unwrap_or_default()),
                    });
                }
                0x59..=0x5f => {
                    reads.push(a);
                    reads.push(b);
                    reference = Some(InstructionReference::Field {
                        index: u32::from(second.unwrap_or_default()),
                    });
                }
                0x60..=0x66 => {
                    writes.push(a);
                    reference = Some(InstructionReference::Field {
                        index: u32::from(second.unwrap_or_default()),
                    });
                }
                0x67..=0x6d => {
                    reads.push(a);
                    reference = Some(InstructionReference::Field {
                        index: u32::from(second.unwrap_or_default()),
                    });
                }
                // invoke {vA..}, method@idx; both 35c and 3rc families
                0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb => {
                    let count = if opcode == 0xfa || opcode == 0xfb {
                        ((first >> 8) & 0xff) as usize
                    } else {
                        ((first >> 12) & 0x0f) as usize
                    };
                    if (0x74..=0x78).contains(&opcode) || opcode == 0xfb {
                        let start = if opcode == 0xfb {
                            fourth.unwrap_or_default()
                        } else {
                            third.unwrap_or_default()
                        };
                        for reg in 0..count.min(255) {
                            reads.push(start.saturating_add(reg as u16));
                        }
                    } else {
                        let word = third.unwrap_or_default();
                        for reg in 0..count.min(5) {
                            reads.push(match reg {
                                0 => (word & 0x0f) as u16,
                                1 => ((word >> 4) & 0x0f) as u16,
                                2 => ((word >> 8) & 0x0f) as u16,
                                3 => ((word >> 12) & 0x0f) as u16,
                                _ => ((first >> 8) & 0x0f) as u16,
                            });
                        }
                    }
                    reference = Some(InstructionReference::Method {
                        index: u32::from(second.unwrap_or_default()),
                    });
                }
                // 23x binary arithmetic and comparisons.
                0x90..=0xaf => {
                    writes.push(a);
                    reads.push(b);
                    reads.push((second.unwrap_or_default() >> 8) as u16);
                }
                // 2addr arithmetic.
                0xb0..=0xcf => {
                    writes.push(a);
                    reads.push(a);
                    reads.push(b);
                }
                // 22s/22b literal arithmetic.
                0xd0..=0xe2 => {
                    writes.push(a);
                    reads.push(b);
                }
                _ => {}
            }
            reads.sort_unstable();
            reads.dedup();
            writes.sort_unstable();
            writes.dedup();
            branch_targets.sort_unstable();
            branch_targets.dedup();
            if out.len() >= limits.max_result_items {
                return Err(Error::resource_limit(format!(
                    "instruction facts exceed the {} result-item limit",
                    limits.max_result_items
                )));
            }
            let method_target = match reference {
                Some(InstructionReference::Method { index }) => {
                    Some(self.method_identity(&entry, index, limits)?)
                }
                _ => None,
            };
            out.push(InstructionFact::new(
                entry.clone(),
                MethodId::new(entry.id(), method_idx),
                u32::try_from(code_off)
                    .map_err(|_| malformed("code item offset exceeds u32".to_owned()))?,
                u32::try_from(pc / 2)
                    .map_err(|_| malformed("code-unit pc exceeds u32".to_owned()))?,
                opcode,
                reads,
                writes,
                reference,
                method_target,
                constant,
                branch_targets,
            ));
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
                locations = locations.saturating_add(offsets.len() as u64);
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
                matches.push(TargetMatch::with_locations(
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

/// Which opcode family a target kind scans; bit values match the
/// per-opcode kind mask in `opcodes.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefKind {
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

/// ULEB128 reader shared by the structured scanner; errors carry the
/// domain kind so callers never see anyhow in analysis paths.
pub(crate) fn read_uleb(data: &[u8], offset: &mut usize) -> Result<u32, Error> {
    let mut result = 0u32;
    for shift in [0, 7, 14, 21, 28] {
        let byte = *data
            .get(*offset)
            .ok_or_else(|| Error::malformed_input("truncated ULEB128"))?;
        *offset += 1;
        result |= u32::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(result);
        }
    }
    Err(Error::malformed_input("ULEB128 exceeds 5 bytes"))
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::model::PatternLimits;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    /// A DexView over raw fixture bytes with a fixed identity.
    fn structured_view<'a>(data: &'a [u8]) -> DexView<'a> {
        let entry = crate::model::DexEntry::new(
            crate::model::DexId::new(crate::model::ArtifactId::from_digest([0u8; 32]), 0, 0),
            b"classes.dex".to_vec(),
            crate::model::DexText::from_str_lossless("classes.dex"),
            crate::model::DexText::from_str_lossless("classes.dex"),
            crate::model::DexVersion::V035,
            0,
        );
        DexView::new(entry, data)
    }

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
    /// offset, which is what the validated member chain checks.
    #[allow(dead_code)] // legacy-era fixture; A09 corpus tests may reuse
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
    #[allow(dead_code)] // legacy-era fixture
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
        let mut code_offset_first = u32::MAX;
        for index in 0..class_count {
            while !(data_off + data.len()).is_multiple_of(4) {
                data.push(0);
            }
            let code_off = ((data_off + data.len()) as u32) + base;
            if code_offset_first == u32::MAX {
                code_offset_first = code_off;
            }
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

        let pre_map = data_off + data.len();
        let map_pad = (4 - pre_map % 4) % 4;
        let map_off = pre_map + map_pad;
        let map_size = 4 + 10 * 12;
        let total = map_off + map_size;
        let mut out = vec![0_u8; total];
        out[..8].copy_from_slice(b"dex\n039\0");
        write_u32(&mut out, 0x20, total as u32);
        // data region: string data + class data + code + map, tiling to EOF
        // (the A02 container validator checks the tiling invariant).
        write_u32(&mut out, 0x68, (total - data_off) as u32);
        write_u32(&mut out, 0x6c, data_off as u32);
        write_u32(&mut out, 0x34, map_off as u32);
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
        out[data_off..data_off + data.len()].copy_from_slice(&data);
        // map_list (A02's container validator requires header.map_off).
        let map_items: [(u16, u32, u32); 10] = [
            (0x0000, 1, 0),
            (0x0001, n_strings as u32, string_ids_off as u32 + base),
            (0x0002, n_types as u32, type_ids_off as u32 + base),
            (0x0003, 1, proto_ids_off as u32 + base),
            (0x0005, class_count as u32, method_ids_off as u32 + base),
            (0x0006, class_count as u32, class_defs_off as u32 + base),
            (0x1000, 1, map_off as u32),
            (
                0x2000,
                class_count as u32,
                data_off as u32 + class_data_offsets[0] as u32 + base,
            ),
            (
                0x2001,
                class_count as u32,
                data_off as u32 + code_offset_first + base,
            ),
            (0x2002, n_strings as u32, data_off as u32 + base),
        ];
        write_u32(&mut out, map_off, map_items.len() as u32);
        for (index, (ty, size, off)) in map_items.iter().enumerate() {
            let row = map_off + 4 + index * 12;
            write_u16(&mut out, row, *ty);
            write_u16(&mut out, row + 2, 0);
            write_u32(&mut out, row + 4, *size);
            write_u32(&mut out, row + 8, *off);
        }
        // The scanner ignores the checksum, but droidsaw validates it before
        // parsing, so the fixture carries a correct Adler-32 over the payload
        // (everything after the 12-byte checksum/signature prefix).
        let checksum = adler32(&out[12..]);
        write_u32(&mut out, 0x08, checksum);
        out
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
        assert_eq!(
            first.caller().id().method_idx(),
            0,
            "method 0 scans normally"
        );
        assert_eq!(first.caller().dex().id().entry_ordinal(), 0);
        assert_eq!(
            first.caller().owner().as_str().as_deref(),
            Some("LFixture0;")
        );
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
    fn typed_instruction_provider_exposes_const_string_and_registers() {
        let data = const_string_fixture(1);
        let view = structured_view(&data);
        let facts = list_instructions(&view, &ScanLimits::DEFAULT, None).unwrap();
        assert_eq!(facts.len(), 2, "const-string plus return-void");
        let first = &facts[0];
        assert_eq!(first.method().method_idx(), 0);
        assert_eq!(first.pc(), 0);
        assert_eq!(first.opcode(), 0x1a);
        assert_eq!(first.reads(), &[] as &[u16]);
        assert_eq!(first.writes(), &[0]);
        assert_eq!(
            first.reference(),
            Some(InstructionReference::String { index: 0 })
        );
        assert_eq!(
            first.constant(),
            Some(InstructionConstant::String { index: 0 })
        );
        assert!(facts[1].reads().is_empty());
        assert!(facts[1].writes().is_empty());
    }

    #[test]
    fn structured_scan_honors_cancellation_and_deadline() {
        let data = const_string_fixture(3);
        let view = structured_view(&data);
        let query = ReferenceQuery::String(
            Pattern::literal("Auth", &PatternLimits::default()).expect("pattern"),
        );
        let cancelled = AtomicBool::new(true);
        let probe = ControlProbe {
            cancelled: &cancelled,
            deadline: None,
        };
        let options = ScanOptions {
            limits: ScanLimits::DEFAULT,
            control: Some(&probe),
            prefilter: true,
        };
        let error = scan_references(&view, &query, &options).unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::Cancelled {
                cause: crate::error::CancelCause::User
            }
        ));

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
        assert!(matches!(
            error.kind(),
            ErrorKind::Cancelled {
                cause: crate::error::CancelCause::Deadline
            }
        ));
    }

    #[test]
    fn structured_scan_enforces_the_string_unit_limit() {
        let data = const_string_fixture(1);
        let view = structured_view(&data);
        let query = ReferenceQuery::String(
            Pattern::literal("Auth", &PatternLimits::default()).expect("pattern"),
        );
        let options = ScanOptions {
            limits: ScanLimits {
                max_string_units: 4,
                ..ScanLimits::DEFAULT
            },
            control: None,
            prefilter: true,
        };
        let error = scan_references(&view, &query, &options).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::ResourceLimit), "{error}");
    }
}
