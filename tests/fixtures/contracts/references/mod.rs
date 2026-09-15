//! Byte-exact builders for the A03 reference-scan fixtures (REF-02/03/04).
//!
//! Unlike `tests/support/dex.rs` (the frozen A00 builders), this module is
//! owned by A03 and exposes the knobs the reference cases need: raw MUTF-8
//! string payloads (unpaired surrogates, embedded NUL, declared-length
//! overrides, missing terminators), non-contiguous string pools with aliased
//! offsets, arbitrary instruction streams (opcode families, payloads, jumbo,
//! polymorphic invokes, unknown opcodes) and a minimal-map variant for the
//! map-fallback scenario. Expected facts in `tests/fixtures/contracts/
//! expected/ref0*.json` were derived from these layouts by hand, not from
//! candidate output.

use crate::support::sha;

// ---------------------------------------------------------------------------
// Declarative pieces
// ---------------------------------------------------------------------------

/// One string_data payload: its UTF-16 units, an optional declared-unit-count
/// override (for the malformed variants) and whether the NUL terminator is
/// written.
pub struct StringSpec {
    pub units: Vec<u16>,
    pub declared: Option<u32>,
    pub terminated: bool,
}

pub fn string(text: &str) -> StringSpec {
    StringSpec { units: text.encode_utf16().collect(), declared: None, terminated: true }
}

pub fn string_units(units: &[u16]) -> StringSpec {
    StringSpec { units: units.to_vec(), declared: None, terminated: true }
}

/// A payload whose declared length disagrees with its actual units.
pub fn mismatched_string(units: &[u16], declared: u32) -> StringSpec {
    StringSpec { units: units.to_vec(), declared: Some(declared), terminated: true }
}

/// A payload with no NUL terminator (truncation variant).
pub fn unterminated_string(units: &[u16]) -> StringSpec {
    StringSpec { units: units.to_vec(), declared: None, terminated: false }
}

/// One code item: register count plus the raw instruction stream in code
/// units; `declared_size` can lie about `insns_size` (truncation variant).
#[derive(Clone)]
pub struct CodeSpec {
    pub registers: u16,
    pub insns: Vec<u16>,
    pub declared_size: Option<u32>,
}

pub fn code(insns: Vec<u16>) -> CodeSpec {
    CodeSpec { registers: 8, insns, declared_size: None }
}

pub fn code_sized(insns: Vec<u16>, declared_size: u32) -> CodeSpec {
    CodeSpec { registers: 8, insns, declared_size: Some(declared_size) }
}

/// One direct method of a class_data item.
#[derive(Clone)]
pub struct MethodDecl {
    pub method_idx: u32,
    pub code: Option<CodeSpec>,
}

pub fn method(method_idx: u32, code: Option<CodeSpec>) -> MethodDecl {
    MethodDecl { method_idx, code }
}

/// Whether the emitted map_list registers every section or only the header
/// and map itself (the REF-03 map-fallback variant).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MapStyle {
    Full,
    HeaderOnly,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub struct FixtureDex {
    /// string_data payloads in emission order (ids into this vector).
    payloads: Vec<StringSpec>,
    /// string index -> payload id; several indices may share one payload.
    string_ids: Vec<usize>,
    /// Optional emission order override (a permutation of payload ids) that
    /// makes the string_ids offsets non-monotonic.
    payload_order: Option<Vec<usize>>,
    types: Vec<u32>,
    /// (shorty string idx, return type idx, parameter type idxs)
    protos: Vec<(u32, u32, Vec<u32>)>,
    /// (class type idx, field type idx, name string idx)
    fields: Vec<(u32, u32, u32)>,
    /// (class type idx, proto idx, name string idx)
    methods: Vec<(u32, u32, u32)>,
    /// (class type idx, super type idx, direct methods)
    classes: Vec<(u32, u32, Vec<MethodDecl>)>,
    map_style: MapStyle,
}

impl FixtureDex {
    pub fn new() -> Self {
        FixtureDex {
            payloads: Vec::new(),
            string_ids: Vec::new(),
            payload_order: None,
            types: Vec::new(),
            protos: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            classes: Vec::new(),
            map_style: MapStyle::Full,
        }
    }

    /// Adds one emitted payload and returns its string index.
    pub fn add_string(&mut self, spec: StringSpec) -> u32 {
        self.payloads.push(spec);
        let index = self.string_ids.len() as u32;
        self.string_ids.push(self.payloads.len() - 1);
        index
    }

    /// Adds a string index that reuses an earlier payload's data offset
    /// (repeated string offsets in the pool).
    pub fn add_alias(&mut self, target: u32) -> u32 {
        self.string_ids.push(self.string_ids[target as usize]);
        self.string_ids.len() as u32 - 1
    }

    /// Overrides the payload emission order (non-contiguous pool).
    pub fn set_payload_order(&mut self, order: &[usize]) {
        assert_eq!(order.len(), self.payloads.len(), "order must be a permutation");
        self.payload_order = Some(order.to_vec());
    }

    pub fn add_type(&mut self, string_idx: u32) -> u32 {
        self.types.push(string_idx);
        self.types.len() as u32 - 1
    }

    pub fn add_proto(&mut self, shorty: u32, return_type: u32, parameters: &[u32]) -> u32 {
        self.protos.push((shorty, return_type, parameters.to_vec()));
        self.protos.len() as u32 - 1
    }

    pub fn add_field(&mut self, class: u32, field_type: u32, name: u32) -> u32 {
        self.fields.push((class, field_type, name));
        self.fields.len() as u32 - 1
    }

    pub fn add_method(&mut self, class: u32, proto: u32, name: u32) -> u32 {
        self.methods.push((class, proto, name));
        self.methods.len() as u32 - 1
    }

    pub fn add_class(&mut self, class_idx: u32, super_idx: u32, direct: &[MethodDecl]) {
        let mut sorted = direct.to_vec();
        assert!(
            sorted.windows(2).all(|pair| pair[0].method_idx < pair[1].method_idx),
            "class_data method_idx values must be strictly ascending"
        );
        sorted.sort_by_key(|decl| decl.method_idx);
        self.classes.push((class_idx, super_idx, sorted));
    }

    pub fn set_map_style(&mut self, style: MapStyle) {
        self.map_style = style;
    }

    pub fn finish(&self) -> Vec<u8> {
        let mut out = vec![0u8; 112];
        let mut entries: Vec<(u16, u32, u32)> = vec![(0x0000, 1, 0)];

        let string_ids_off = push_section(
            &mut out,
            &mut entries,
            0x0001,
            self.string_ids.len() as u32,
            &vec![0u8; self.string_ids.len() * 4],
            4,
        );
        let type_ids_off = push_section(
            &mut out,
            &mut entries,
            0x0002,
            self.types.len() as u32,
            &words(&self.types),
            4,
        );
        // proto_id_item placeholders; parameters_off is patched once the
        // type lists have been emitted.
        let mut proto_bytes = Vec::new();
        for (shorty, return_type, _) in &self.protos {
            proto_bytes.extend_from_slice(&shorty.to_le_bytes());
            proto_bytes.extend_from_slice(&return_type.to_le_bytes());
            proto_bytes.extend_from_slice(&0u32.to_le_bytes());
        }
        let proto_ids_off = push_section(
            &mut out,
            &mut entries,
            0x0003,
            self.protos.len() as u32,
            &proto_bytes,
            4,
        );
        // field_id_item / method_id_item: class u16, proto-or-type u16, name u32.
        let mut field_bytes = Vec::new();
        for (class, field_type, name) in &self.fields {
            field_bytes.extend_from_slice(&(*class as u16).to_le_bytes());
            field_bytes.extend_from_slice(&(*field_type as u16).to_le_bytes());
            field_bytes.extend_from_slice(&name.to_le_bytes());
        }
        let field_ids_off = push_section(
            &mut out,
            &mut entries,
            0x0004,
            self.fields.len() as u32,
            &field_bytes,
            4,
        );
        let mut method_bytes = Vec::new();
        for (class, proto, name) in &self.methods {
            method_bytes.extend_from_slice(&(*class as u16).to_le_bytes());
            method_bytes.extend_from_slice(&(*proto as u16).to_le_bytes());
            method_bytes.extend_from_slice(&name.to_le_bytes());
        }
        let method_ids_off = push_section(
            &mut out,
            &mut entries,
            0x0005,
            self.methods.len() as u32,
            &method_bytes,
            4,
        );
        let class_count = self.classes.len() as u32;
        let class_defs_off = push_section(
            &mut out,
            &mut entries,
            0x0006,
            class_count,
            &vec![0u8; self.classes.len() * 32],
            4,
        );
        let data_off = out.len();

        // Parameter type lists, before the rest of the data section so the
        // proto placeholders above can point at them.
        let mut type_list_offsets = vec![0u32; self.protos.len()];
        let mut list_bytes = Vec::new();
        let lists_base = out.len();
        for (position, (_, _, parameters)) in self.protos.iter().enumerate() {
            if parameters.is_empty() {
                continue;
            }
            while !(lists_base + list_bytes.len()).is_multiple_of(4) {
                list_bytes.push(0);
            }
            type_list_offsets[position] = (lists_base + list_bytes.len()) as u32;
            list_bytes.extend_from_slice(&(parameters.len() as u32).to_le_bytes());
            for type_idx in parameters {
                list_bytes.extend_from_slice(&type_idx.to_le_bytes());
            }
        }
        if !list_bytes.is_empty() {
            push_section(&mut out, &mut entries, 0x1001, self.protos.len() as u32, &list_bytes, 4);
        }
        for (position, offset) in type_list_offsets.iter().enumerate() {
            if *offset != 0 {
                let at = proto_ids_off + position * 12 + 8;
                out[at..at + 4].copy_from_slice(&offset.to_le_bytes());
            }
        }

        // string_data payloads, in the requested emission order.
        let order: Vec<usize> =
            self.payload_order.clone().unwrap_or_else(|| (0..self.payloads.len()).collect());
        let mut payload_offsets = vec![0u32; self.payloads.len()];
        let mut data = Vec::new();
        let strings_base = out.len();
        for payload_id in &order {
            let spec = &self.payloads[*payload_id];
            let declared = spec.declared.unwrap_or(spec.units.len() as u32);
            payload_offsets[*payload_id] = (strings_base + data.len()) as u32;
            data.extend_from_slice(&uleb(declared));
            data.extend_from_slice(&mutf8_bytes(&spec.units));
            if spec.terminated {
                data.push(0);
            }
        }
        push_section(&mut out, &mut entries, 0x2002, order.len() as u32, &data, 1);
        for (index, payload_id) in self.string_ids.iter().enumerate() {
            let at = string_ids_off + index * 4;
            out[at..at + 4].copy_from_slice(&payload_offsets[*payload_id].to_le_bytes());
        }

        // code items (one map entry each).
        let mut code_offsets = Vec::new();
        for (_, _, direct) in &self.classes {
            for decl in direct {
                let Some(code) = &decl.code else { continue };
                while !out.len().is_multiple_of(4) {
                    out.push(0);
                }
                code_offsets.push(out.len() as u32);
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&code.registers.to_le_bytes());
                bytes.extend_from_slice(&0u16.to_le_bytes()); // ins_size
                bytes.extend_from_slice(&4u16.to_le_bytes()); // outs_size
                bytes.extend_from_slice(&0u16.to_le_bytes()); // tries_size
                bytes.extend_from_slice(&0u32.to_le_bytes()); // debug_info_off
                bytes.extend_from_slice(
                    &code.declared_size.unwrap_or(code.insns.len() as u32).to_le_bytes(),
                );
                for unit in &code.insns {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                entries.push((0x2001, 1, out.len() as u32));
                out.extend_from_slice(&bytes);
            }
        }

        // class_data items (one map entry each).
        let mut class_data_offsets = Vec::new();
        for (_, _, direct) in &self.classes {
            class_data_offsets.push(out.len() as u32);
            let mut bytes = Vec::new();
            uleb_into(&mut bytes, 0); // static fields
            uleb_into(&mut bytes, 0); // instance fields
            uleb_into(&mut bytes, direct.len() as u32);
            uleb_into(&mut bytes, 0); // virtual methods
            let mut previous = 0u32;
            let mut codes = code_offsets.iter();
            for decl in direct {
                uleb_into(&mut bytes, decl.method_idx - previous);
                previous = decl.method_idx;
                uleb_into(&mut bytes, 0x9); // access flags: public static
                uleb_into(&mut bytes, if decl.code.is_some() { *codes.next().unwrap() } else { 0 });
            }
            entries.push((0x2000, 1, out.len() as u32));
            out.extend_from_slice(&bytes);
        }

        // class_defs.
        for (position, (class_idx, super_idx, _)) in self.classes.iter().enumerate() {
            let at = class_defs_off + position * 32;
            out[at..at + 4].copy_from_slice(&class_idx.to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes()); // access: public
            out[at + 8..at + 12].copy_from_slice(&super_idx.to_le_bytes());
            out[at + 12..at + 16].copy_from_slice(&0u32.to_le_bytes()); // interfaces_off
            out[at + 16..at + 20].copy_from_slice(&0xffff_ffffu32.to_le_bytes()); // source_file_idx
            out[at + 20..at + 24].copy_from_slice(&0u32.to_le_bytes()); // annotations_off
            out[at + 24..at + 28].copy_from_slice(&class_data_offsets[position].to_le_bytes());
            out[at + 28..at + 32].copy_from_slice(&0u32.to_le_bytes()); // static_values_off
        }

        // map_list.
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        let map_off = out.len();
        entries.push((0x1000, 1, map_off as u32));
        let visible: Vec<(u16, u32, u32)> = match self.map_style {
            MapStyle::Full => entries.clone(),
            MapStyle::HeaderOnly => entries
                .iter()
                .filter(|(kind, _, _)| matches!(kind, 0x0000 | 0x1000))
                .copied()
                .collect(),
        };
        let mut map = (visible.len() as u32).to_le_bytes().to_vec();
        for (kind, size, offset) in &visible {
            map.extend_from_slice(&kind.to_le_bytes());
            map.extend_from_slice(&0u16.to_le_bytes());
            map.extend_from_slice(&size.to_le_bytes());
            map.extend_from_slice(&offset.to_le_bytes());
        }
        out.extend_from_slice(&map);

        // Header.
        out[..8].copy_from_slice(b"dex\n035\0");
        let file_size = out.len() as u32;
        write_u32(&mut out, 0x20, file_size);
        write_u32(&mut out, 0x24, 112);
        write_u32(&mut out, 0x28, 0x1234_5678);
        write_u32(&mut out, 0x2c, 0);
        write_u32(&mut out, 0x30, 0);
        write_u32(&mut out, 0x34, map_off as u32);
        write_u32(&mut out, 0x38, self.string_ids.len() as u32);
        write_u32(&mut out, 0x3c, string_ids_off as u32);
        write_u32(&mut out, 0x40, self.types.len() as u32);
        write_u32(&mut out, 0x44, type_ids_off as u32);
        write_u32(&mut out, 0x48, self.protos.len() as u32);
        write_u32(&mut out, 0x4c, proto_ids_off as u32);
        write_u32(&mut out, 0x50, self.fields.len() as u32);
        write_u32(&mut out, 0x54, field_ids_off as u32);
        write_u32(&mut out, 0x58, self.methods.len() as u32);
        write_u32(&mut out, 0x5c, method_ids_off as u32);
        write_u32(&mut out, 0x60, class_count);
        write_u32(&mut out, 0x64, class_defs_off as u32);
        write_u32(&mut out, 0x68, file_size - data_off as u32);
        write_u32(&mut out, 0x6c, data_off as u32);

        let signature = sha::sha1(&out[32..]);
        out[12..32].copy_from_slice(&signature);
        let checksum = sha::adler32(&out[12..]);
        write_u32(&mut out, 8, checksum);
        out
    }
}

impl Default for FixtureDex {
    fn default() -> Self {
        Self::new()
    }
}

fn push_section(
    out: &mut Vec<u8>,
    entries: &mut Vec<(u16, u32, u32)>,
    kind: u16,
    count: u32,
    data: &[u8],
    align: usize,
) -> usize {
    while !out.len().is_multiple_of(align) {
        out.push(0);
    }
    let offset = out.len();
    entries.push((kind, count, offset as u32));
    out.extend_from_slice(data);
    offset
}

fn words(values: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 4);
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn uleb(value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    uleb_into(&mut out, value);
    out
}

fn uleb_into(out: &mut Vec<u8>, mut value: u32) {
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

/// MUTF-8 encoding of raw UTF-16 units (surrogates included).
fn mutf8_bytes(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in units {
        match *unit {
            0 => out.extend_from_slice(&[0xc0, 0x80]),
            0x0001..=0x007f => out.push(*unit as u8),
            0x0080..=0x07ff => {
                out.push((0xc0 | (unit >> 6)) as u8);
                out.push((0x80 | (unit & 0x3f)) as u8);
            }
            _ => {
                out.push((0xe0 | (unit >> 12)) as u8);
                out.push((0x80 | ((unit >> 6) & 0x3f)) as u8);
                out.push((0x80 | (unit & 0x3f)) as u8);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Instruction encoding helpers (formats used by the fixtures)
// ---------------------------------------------------------------------------

pub fn insns(parts: &[&[u16]]) -> Vec<u16> {
    parts.iter().flat_map(|part| part.iter().copied()).collect()
}

pub fn return_void() -> [u16; 1] {
    [0x000e]
}

pub fn nop() -> [u16; 1] {
    [0x0000]
}

/// const/4 vA, #+B (11n).
pub fn const4(register: u8, literal: u8) -> [u16; 1] {
    [((literal as u16) << 12) | ((register as u16) << 8) | 0x12]
}

/// const/16 vAA, #+BBBB (31i).
pub fn const16(register: u8, literal: u16) -> [u16; 2] {
    [((register as u16) << 8) | 0x13, literal]
}

/// const-wide vAA, #+BBBBBBBBBBBBBBBB (51l).
pub fn const_wide(register: u8, literal: [u16; 4]) -> [u16; 5] {
    [((register as u16) << 8) | 0x18, literal[0], literal[1], literal[2], literal[3]]
}

/// const-string vAA, string@BBBB (21c).
pub fn const_string(register: u8, index: u16) -> [u16; 2] {
    [((register as u16) << 8) | 0x1a, index]
}

/// const-string/jumbo vAA, string@BBBBBBBB (31c).
pub fn const_string_jumbo(register: u8, index: u32) -> [u16; 3] {
    [((register as u16) << 8) | 0x1b, index as u16, (index >> 16) as u16]
}

/// const-class vAA, type@BBBB (21c); also check-cast (0x1f).
pub fn const_class(register: u8, index: u16) -> [u16; 2] {
    [((register as u16) << 8) | 0x1c, index]
}

pub fn check_cast(register: u8, index: u16) -> [u16; 2] {
    [((register as u16) << 8) | 0x1f, index]
}

/// instance-of vA, vB, type@CCCC (22c); also new-array (0x23).
pub fn instance_of(result: u8, reference: u8, index: u16) -> [u16; 2] {
    [((result as u16) << 12) | ((reference as u16) << 8) | 0x20, index]
}

pub fn new_instance(register: u8, index: u16) -> [u16; 2] {
    [((register as u16) << 8) | 0x22, index]
}

pub fn new_array(result: u8, size: u8, index: u16) -> [u16; 2] {
    [((result as u16) << 12) | ((size as u16) << 8) | 0x23, index]
}

/// filled-new-array {vC..vG}, type@CCCC (35c), one argument.
pub fn filled_new_array(index: u16) -> [u16; 3] {
    [0x1024, index, 0x0000]
}

/// filled-new-array/range {vC..vN}, type@BBBB (3rc), one argument.
pub fn filled_new_array_range(index: u16) -> [u16; 3] {
    [0x0125, index, 0x0000]
}

/// The iget/iput/sget/sput family (22c/21c): opcode, registers, field index.
pub fn field22(opcode: u8, result: u8, object: u8, index: u16) -> [u16; 2] {
    [((result as u16) << 12) | ((object as u16) << 8) | opcode as u16, index]
}

pub fn field21(opcode: u8, register: u8, index: u16) -> [u16; 2] {
    [((register as u16) << 8) | opcode as u16, index]
}

/// invoke-kind {vC..vG}, method@BBBB (35c), one argument.
pub fn invoke35(opcode: u8, index: u16) -> [u16; 3] {
    [0x1000 | opcode as u16, index, 0x0000]
}

/// invoke-kind/range {vC..vN}, method@BBBB (3rc), one argument.
pub fn invoke_range(opcode: u8, index: u16) -> [u16; 3] {
    [0x0100 | opcode as u16, index, 0x0000]
}

/// invoke-polymorphic {vC..vG}, method@BBBB, proto@CCCC (45cc).
pub fn invoke_polymorphic(method: u16, proto: u16) -> [u16; 4] {
    [0x10fa, method, proto, 0x0000]
}

/// invoke-polymorphic/range {vC..vN}, method@BBBB, proto@CCCC (4rc-c).
pub fn invoke_polymorphic_range(method: u16, proto: u16) -> [u16; 4] {
    [0x01fb, method, proto, 0x0000]
}

/// invoke-custom {vC..vG}, call_site@BBBB (35c).
pub fn invoke_custom(call_site: u16) -> [u16; 3] {
    [0x10fc, call_site, 0x0000]
}

/// invoke-custom/range {vC..vN}, call_site@BBBB (3rc).
pub fn invoke_custom_range(call_site: u16) -> [u16; 3] {
    [0x01fd, call_site, 0x0000]
}

/// const-method-handle vAA, handle@BBBB (21c).
pub fn const_method_handle(register: u8, index: u16) -> [u16; 2] {
    [((register as u16) << 8) | 0xfe, index]
}

/// const-method-type vAA, proto@BBBB (21c).
pub fn const_method_type(register: u8, index: u16) -> [u16; 2] {
    [((register as u16) << 8) | 0xff, index]
}

/// packed-switch vAA, +BBBBBBBB (31t); offset in code units from this insn.
pub fn packed_switch(register: u8, offset: u32) -> [u16; 3] {
    [((register as u16) << 8) | 0x2b, offset as u16, (offset >> 16) as u16]
}

/// sparse-switch vAA, +BBBBBBBB (31t).
pub fn sparse_switch(register: u8, offset: u32) -> [u16; 3] {
    [((register as u16) << 8) | 0x2c, offset as u16, (offset >> 16) as u16]
}

/// fill-array-data vAA, +BBBBBBBB (31t).
pub fn fill_array_data(register: u8, offset: u32) -> [u16; 3] {
    [((register as u16) << 8) | 0x26, offset as u16, (offset >> 16) as u16]
}

/// packed-switch-payload: ident 0x0100, size, first_key (s32), targets.
pub fn packed_switch_payload(first_key: [u16; 2], targets: &[[u16; 2]]) -> Vec<u16> {
    let mut out = vec![0x0100, targets.len() as u16, first_key[0], first_key[1]];
    for target in targets {
        out.extend_from_slice(target);
    }
    out
}

/// sparse-switch-payload: ident 0x0200, size, keys then targets.
pub fn sparse_switch_payload(keys: &[[u16; 2]], targets: &[[u16; 2]]) -> Vec<u16> {
    assert_eq!(keys.len(), targets.len());
    let mut out = vec![0x0200, keys.len() as u16];
    for key in keys {
        out.extend_from_slice(key);
    }
    for target in targets {
        out.extend_from_slice(target);
    }
    out
}

/// fill-array-data-payload: ident 0x0300, element_width, element count, data.
pub fn fill_array_payload(element_width: u16, data: &[u16]) -> Vec<u16> {
    let elements = (data.len() * 2 / element_width as usize) as u32;
    let mut out = vec![0x0300, element_width, elements as u16, (elements >> 16) as u16];
    out.extend_from_slice(data);
    out
}

// ---------------------------------------------------------------------------
// The A03 fixture DEXes
// ---------------------------------------------------------------------------

/// REF-02 pool A: valid-Unicode string values with every lossless trap.
///
/// Layout (string indices; payload emission order [0,5,2,3,4,1,...] keeps
/// "tok"/"en" adjacent for the cross-string regex-dot trap while making the
/// string_ids offsets non-monotonic; index 14 aliases index 0's offset):
///
/// ```text
/// 0 "alpha"           5 "a"                 10 "I"
/// 1 "emoji😀end"      6 "Lexample/Pool;"     11 "main"
/// 2 "a\0b"            7 "Ljava/lang/Object;" 12 "fi😀eld"
/// 3 "tok"             8 "V"                 13 "m😀th"
/// 4 "en"              9 "Lpo😀ol;"          14 alias of 0
/// ```
///
/// Types 0..4 -> strings 6,7,8,9,10 (so type 3 is "Lpo😀ol;"). Field 0:
/// class 0, type I, name 12. Methods: 0 main()V name 11, 1 m😀th()V name 13.
/// `main` (method 0, ()V): string@0 @0, string@1 @2, string@2 @4, string@3
/// @6, string@4 @8, type@3 @10 (const-class), field@0 @12 (sget), method@1
/// @14 (invoke-static), string@14 @17, return-void @19; insns_size 20.
pub fn pool_a() -> Vec<u8> {
    let mut dex = FixtureDex::new();
    let s_alpha = dex.add_string(string("alpha"));
    let s_emoji = dex.add_string(string("emoji\u{1f600}end"));
    let s_a_nul_b = dex.add_string(string("a\0b"));
    let s_tok = dex.add_string(string("tok"));
    let s_en = dex.add_string(string("en"));
    let s_bare_a = dex.add_string(string("a"));
    let s_pool = dex.add_string(string("Lexample/Pool;"));
    let s_object = dex.add_string(string("Ljava/lang/Object;"));
    let s_v = dex.add_string(string("V"));
    let s_emoji_type = dex.add_string(string("Lpo\u{1f600}ol;"));
    let s_i = dex.add_string(string("I"));
    let s_main = dex.add_string(string("main"));
    let s_field = dex.add_string(string("fi\u{1f600}eld"));
    let s_method = dex.add_string(string("m\u{1f600}th"));
    let s_alias = dex.add_alias(s_alpha);
    dex.set_payload_order(&[0, 5, 2, 3, 4, 1, 6, 7, 8, 10, 9, 11, 12, 13]);

    let t_pool = dex.add_type(s_pool);
    let t_object = dex.add_type(s_object);
    let t_v = dex.add_type(s_v);
    let t_emoji = dex.add_type(s_emoji_type);
    let t_i = dex.add_type(s_i);

    let p_void = dex.add_proto(s_v, t_v, &[]);
    let f0 = dex.add_field(t_pool, t_i, s_field);
    let m_main = dex.add_method(t_pool, p_void, s_main);
    let m_emoji = dex.add_method(t_pool, p_void, s_method);
    assert_eq!((s_alpha, s_emoji, s_a_nul_b, s_tok, s_en, s_bare_a), (0, 1, 2, 3, 4, 5));
    assert_eq!((t_emoji, f0, m_main, m_emoji, s_alias), (3, 0, 0, 1, 14));

    let body = insns(&[
        &const_string(0, s_alpha as u16),
        &const_string(0, s_emoji as u16),
        &const_string(0, s_a_nul_b as u16),
        &const_string(0, s_tok as u16),
        &const_string(0, s_en as u16),
        &const_class(0, t_emoji as u16),
        &field21(0x60, 0, f0 as u16),
        &invoke35(0x71, m_emoji as u16),
        &const_string(0, s_alias as u16),
        &return_void(),
    ]);
    assert_eq!(body.len(), 20, "main insns cover 20 code units");
    dex.add_class(t_pool, t_object, &[method(m_main, Some(code(body)))]);
    dex.finish()
}

/// REF-02 pool B: one string keeps an unpaired high surrogate, so regex
/// queries over the pool are UnsupportedEncoding while literals stay decidable.
///
/// Strings: 0 = units [62, 0xD800, 63]; 1 "Lexample/B;"; 2 Object; 3 "V";
/// 4 "b" (method 0's name). Method 0 "b" ()V loads string@0 @0, returns @2.
pub fn pool_b() -> Vec<u8> {
    let mut dex = FixtureDex::new();
    let s_broken = dex.add_string(string_units(&[0x62, 0xd800, 0x63]));
    let s_class = dex.add_string(string("Lexample/B;"));
    let s_object = dex.add_string(string("Ljava/lang/Object;"));
    let s_v = dex.add_string(string("V"));
    let s_name = dex.add_string(string("b"));
    let t_class = dex.add_type(s_class);
    let t_object = dex.add_type(s_object);
    let t_v = dex.add_type(s_v);
    let p_void = dex.add_proto(s_v, t_v, &[]);
    let m0 = dex.add_method(t_class, p_void, s_name);
    let body = insns(&[&const_string(0, s_broken as u16), &return_void()]);
    dex.add_class(t_class, t_object, &[method(m0, Some(code(body)))]);
    dex.finish()
}

/// REF-02 malformed variant: string 4 declares 5 UTF-16 units but decodes to
/// 2 ("ab"), so any string-decoding query fails MalformedInput.
pub fn bad_mutf8() -> Vec<u8> {
    let mut dex = FixtureDex::new();
    let s_class = dex.add_string(string("Lexample/Bad;"));
    let s_object = dex.add_string(string("Ljava/lang/Object;"));
    let s_v = dex.add_string(string("V"));
    let s_name = dex.add_string(string("x"));
    let _s_bad = dex.add_string(mismatched_string(&[0x61, 0x62], 5));
    let t_class = dex.add_type(s_class);
    let t_object = dex.add_type(s_object);
    let t_v = dex.add_type(s_v);
    let p_void = dex.add_proto(s_v, t_v, &[]);
    let m0 = dex.add_method(t_class, p_void, s_name);
    let body = insns(&[&return_void()]);
    dex.add_class(t_class, t_object, &[method(m0, Some(code(body)))]);
    dex.finish()
}

/// REF-02 malformed variant: a payload with no NUL terminator.
///
/// The unterminated payload is *not* the last one emitted: the builder's
/// 4-byte alignment padding before the following code item would otherwise
/// terminate it by accident (a stray zero byte), and the truncated string
/// would parse as valid. With `z` emitted after it, the byte following
/// `cat` is the next payload's ULEB length, so the missing terminator is
/// what the scanner reports.
pub fn unterminated_mutf8() -> Vec<u8> {
    let mut dex = FixtureDex::new();
    let s_class = dex.add_string(string("Lexample/Bad2;"));
    let s_object = dex.add_string(string("Ljava/lang/Object;"));
    let s_v = dex.add_string(string("V"));
    let s_name = dex.add_string(string("x"));
    let s_tail = dex.add_string(unterminated_string(&[0x63, 0x61, 0x74]));
    let _s_after = dex.add_string(string("z"));
    assert_eq!(s_tail, 4, "the truncated payload must be string #4");
    let t_class = dex.add_type(s_class);
    let t_object = dex.add_type(s_object);
    let t_v = dex.add_type(s_v);
    let p_void = dex.add_proto(s_v, t_v, &[]);
    let m0 = dex.add_method(t_class, p_void, s_name);
    let body = insns(&[&return_void()]);
    dex.add_class(t_class, t_object, &[method(m0, Some(code(body)))]);
    dex.finish()
}

/// REF-03: every reference opcode family plus the pseudo-reference traps.
///
/// Strings 0..18: 0 "Lexample/Ops;", 1 Object, 2 "V", 3 "I", 4 "strA",
/// 5 "strB", 6 "LOpsType;", 7..14 method names (mstrings..mpayload),
/// 15 "target", 16 "poly", 17 "fTarget", 18 "VI".
/// Types 0..4: Ops, Object, V, I, LOpsType;. Protos: 0 ()V, 1 (I)V.
/// Field 0: Ops fTarget:I. Methods 0..7 = callers, 8 target()V, 9 poly(I)V.
pub fn opcode_families(map: MapStyle) -> Vec<u8> {
    let mut dex = FixtureDex::new();
    let s_ops = dex.add_string(string("Lexample/Ops;"));
    let s_object = dex.add_string(string("Ljava/lang/Object;"));
    let s_v = dex.add_string(string("V"));
    let s_i = dex.add_string(string("I"));
    let s_str_a = dex.add_string(string("strA"));
    let s_str_b = dex.add_string(string("strB"));
    let s_type = dex.add_string(string("LOpsType;"));
    let s_mstrings = dex.add_string(string("mstrings"));
    let s_mtypes = dex.add_string(string("mtypes"));
    let s_mfields = dex.add_string(string("mfields"));
    let s_minvoke = dex.add_string(string("minvoke"));
    let s_mpoly = dex.add_string(string("mpoly"));
    let s_mskip = dex.add_string(string("mskip"));
    let s_mtrap = dex.add_string(string("mtrap"));
    let s_mpayload = dex.add_string(string("mpayload"));
    let s_target = dex.add_string(string("target"));
    let s_poly = dex.add_string(string("poly"));
    let s_field = dex.add_string(string("fTarget"));
    let s_vi = dex.add_string(string("VI"));

    let t_ops = dex.add_type(s_ops);
    let t_object = dex.add_type(s_object);
    let t_v = dex.add_type(s_v);
    let t_i = dex.add_type(s_i);
    let t_ops_type = dex.add_type(s_type);

    let p_void = dex.add_proto(s_v, t_v, &[]);
    let p_int_v = dex.add_proto(s_vi, t_v, &[t_i]);

    let f_target = dex.add_field(t_ops, t_i, s_field);
    let m_mstrings = dex.add_method(t_ops, p_void, s_mstrings);
    let m_mtypes = dex.add_method(t_ops, p_void, s_mtypes);
    let m_mfields = dex.add_method(t_ops, p_void, s_mfields);
    let m_minvoke = dex.add_method(t_ops, p_void, s_minvoke);
    let m_mpoly = dex.add_method(t_ops, p_void, s_mpoly);
    let m_mskip = dex.add_method(t_ops, p_void, s_mskip);
    let m_mtrap = dex.add_method(t_ops, p_void, s_mtrap);
    let m_mpayload = dex.add_method(t_ops, p_void, s_mpayload);
    let m_target = dex.add_method(t_ops, p_void, s_target);
    let m_poly = dex.add_method(t_ops, p_int_v, s_poly);
    assert_eq!(
        (s_str_a, s_str_b, t_ops_type, f_target, m_target, m_poly),
        (4, 5, 4, 0, 8, 9),
        "table indices must match the hand-written facts"
    );

    // mstrings: const-string @0, const-string/jumbo @2, return @5.
    let mstrings = insns(&[
        &const_string(0, s_str_a as u16),
        &const_string_jumbo(0, s_str_b as u32),
        &return_void(),
    ]);
    // mtypes: the seven type-carrying forms at offsets 0,2,4,6,8,10,13.
    let mtypes = insns(&[
        &const_class(0, t_ops_type as u16),
        &check_cast(0, t_ops_type as u16),
        &instance_of(0, 1, t_ops_type as u16),
        &new_instance(0, t_ops_type as u16),
        &new_array(0, 1, t_ops_type as u16),
        &filled_new_array(t_ops_type as u16),
        &filled_new_array_range(t_ops_type as u16),
        &return_void(),
    ]);
    assert_eq!(mtypes.len(), 17);
    // mfields: iget/iput/sget/sput incl. wide/object forms, 2 units each.
    let mfields = insns(&[
        &field22(0x52, 0, 1, f_target as u16), // iget
        &field22(0x53, 0, 1, f_target as u16), // iget-wide
        &field22(0x54, 0, 1, f_target as u16), // iget-object
        &field22(0x59, 0, 1, f_target as u16), // iput
        &field22(0x5a, 0, 1, f_target as u16), // iput-wide
        &field22(0x5b, 0, 1, f_target as u16), // iput-object
        &field21(0x60, 0, f_target as u16),    // sget
        &field21(0x61, 0, f_target as u16),    // sget-wide
        &field21(0x62, 0, f_target as u16),    // sget-object
        &field21(0x67, 0, f_target as u16),    // sput
        &field21(0x68, 0, f_target as u16),    // sput-wide
        &field21(0x69, 0, f_target as u16),    // sput-object
        &return_void(),
    ]);
    assert_eq!(mfields.len(), 25);
    // minvoke: 5x 35c + 5x range, 3 units each, offsets 0,3,..,27.
    let minvoke = insns(&[
        &invoke35(0x6e, m_target as u16),
        &invoke35(0x6f, m_target as u16),
        &invoke35(0x70, m_target as u16),
        &invoke35(0x71, m_target as u16),
        &invoke35(0x72, m_target as u16),
        &invoke_range(0x74, m_target as u16),
        &invoke_range(0x75, m_target as u16),
        &invoke_range(0x76, m_target as u16),
        &invoke_range(0x77, m_target as u16),
        &invoke_range(0x78, m_target as u16),
        &return_void(),
    ]);
    assert_eq!(minvoke.len(), 31);
    // mpoly: fa/fb carry the method index (proto operand excluded), @0 and @4.
    let mpoly = insns(&[
        &invoke_polymorphic(m_poly as u16, p_int_v as u16),
        &invoke_polymorphic_range(m_poly as u16, p_int_v as u16),
        &return_void(),
    ]);
    assert_eq!(mpoly.len(), 9);
    // mskip: call-site / method-handle / method-type operands, width only.
    let mskip = insns(&[
        &invoke_custom(0),
        &invoke_custom_range(0),
        &const_method_handle(0, 0),
        &const_method_type(0, p_int_v as u16),
        &return_void(),
    ]);
    assert_eq!(mskip.len(), 11);
    // mtrap: immediates whose bytes mimic reference instructions.
    let mtrap = insns(&[
        &const16(0, s_str_a as u16), // 13 00 04 00: "const-string@4" bytes
        &const_wide(0, [0x0000, 0x001a, 0x0004, 0x0000]), // embeds 1a 00 04 00
        &return_void(),
    ]);
    assert_eq!(mtrap.len(), 8);
    // mpayload: switch/array payloads with reference-like interior bytes.
    // Layout: const/4 @0 (1u); packed-switch @1 (3u) -> payload1 @4 (6u);
    // sparse-switch @10 (3u); const/4 @13 (1u); payload2 @14 (6u);
    // fill-array-data @20 (3u); nop @23 (1u); payload3 @24 (6u); return @30.
    let mpayload = insns(&[
        &const4(0, 1),
        &packed_switch(0, 3),
        &packed_switch_payload([0x001a, 0x0004], &[[0x0000, 0x0000]]),
        &sparse_switch(0, 4),
        &const4(1, 2),
        &sparse_switch_payload(&[[0x001a, 0x0004]], &[[0x0000, 0x0000]]),
        &fill_array_data(0, 4),
        &nop(),
        &fill_array_payload(2, &[0x001a, 0x0004]),
        &return_void(),
    ]);
    assert_eq!(mpayload.len(), 31);

    dex.add_class(
        t_ops,
        t_object,
        &[
            method(m_mstrings, Some(code(mstrings))),
            method(m_mtypes, Some(code(mtypes))),
            method(m_mfields, Some(code(mfields))),
            method(m_minvoke, Some(code(minvoke))),
            method(m_mpoly, Some(code(mpoly))),
            method(m_mskip, Some(code(mskip))),
            method(m_mtrap, Some(code(mtrap))),
            method(m_mpayload, Some(code(mpayload))),
        ],
    );
    dex.set_map_style(map);
    dex.finish()
}

/// REF-03 malformed variant: method 0's body starts with the unused opcode
/// 0x73, which must fail MalformedInput instead of being guessed over.
pub fn unknown_opcode() -> Vec<u8> {
    let mut dex = FixtureDex::new();
    let s_class = dex.add_string(string("Lexample/BadOp;"));
    let s_object = dex.add_string(string("Ljava/lang/Object;"));
    let s_v = dex.add_string(string("V"));
    let s_name = dex.add_string(string("m"));
    let t_class = dex.add_type(s_class);
    let t_object = dex.add_type(s_object);
    let t_v = dex.add_type(s_v);
    let p_void = dex.add_proto(s_v, t_v, &[]);
    let m0 = dex.add_method(t_class, p_void, s_name);
    let body = vec![0x0073, 0x0000, 0x000e];
    dex.add_class(t_class, t_object, &[method(m0, Some(code(body)))]);
    dex.finish()
}

/// REF-04: full identity - method 0 as a caller, overloads, shared code_item,
/// repeated targets, control characters.
///
/// Strings 0..12: 0 "Lexample/Ident;", 1 Object, 2 "V", 3 "I", 4 "tok",
/// 5 "a\tb\nc", 6 "main", 7 "run", 8 "alpha", 9 "beta", 10 "f\nield",
/// 11 "Lctrl/Type;", 12 "VI". Types 0..4 = Ident/Object/V/I/Lctrl/Type;.
/// Protos: 0 ()V, 1 (I)V. Field 0: Ident f\nield:I.
/// Methods: 0 main()V, 1 run()V, 2 run(I)V, 3 alpha()V, 4 beta()V (3 and 4
/// share one code_item).
pub fn identity() -> Vec<u8> {
    let mut dex = FixtureDex::new();
    let s_class = dex.add_string(string("Lexample/Ident;"));
    let s_object = dex.add_string(string("Ljava/lang/Object;"));
    let s_v = dex.add_string(string("V"));
    let s_i = dex.add_string(string("I"));
    let s_tok = dex.add_string(string("tok"));
    let s_ctl = dex.add_string(string("a\tb\nc"));
    let s_main = dex.add_string(string("main"));
    let s_run = dex.add_string(string("run"));
    let s_alpha = dex.add_string(string("alpha"));
    let s_beta = dex.add_string(string("beta"));
    let s_field = dex.add_string(string("f\nield"));
    let s_type = dex.add_string(string("Lctrl/Type;"));
    let s_vi = dex.add_string(string("VI"));

    let t_class = dex.add_type(s_class);
    let t_object = dex.add_type(s_object);
    let t_v = dex.add_type(s_v);
    let t_i = dex.add_type(s_i);
    let t_ctrl = dex.add_type(s_type);

    let p_void = dex.add_proto(s_v, t_v, &[]);
    let p_int_v = dex.add_proto(s_vi, t_v, &[t_i]);

    let f_field = dex.add_field(t_class, t_i, s_field);
    let m_main = dex.add_method(t_class, p_void, s_main);
    let m_run_void = dex.add_method(t_class, p_void, s_run);
    let m_run_int = dex.add_method(t_class, p_int_v, s_run);
    let m_alpha = dex.add_method(t_class, p_void, s_alpha);
    let m_beta = dex.add_method(t_class, p_void, s_beta);
    assert_eq!((s_tok, s_ctl, t_ctrl, f_field), (4, 5, 4, 0));
    assert_eq!((m_main, m_run_void, m_run_int, m_alpha, m_beta), (0, 1, 2, 3, 4));

    // main: tok @0 and @2 (same target twice), a\tb\nc @4, const-class @6,
    // invoke run()V @8, invoke run(I)V @11, sget f\nield @14, return @16.
    let main = insns(&[
        &const_string(0, s_tok as u16),
        &const_string(0, s_tok as u16),
        &const_string(0, s_ctl as u16),
        &const_class(0, t_ctrl as u16),
        &invoke35(0x6e, m_run_void as u16),
        &[0x116e, m_run_int as u16, 0x0000], // invoke-virtual {v1}, method@2
        &field21(0x60, 0, f_field as u16),
        &return_void(),
    ]);
    assert_eq!(main.len(), 17);
    // run()V and the shared alpha/beta body: tok @0, return @2.
    let tok_once = insns(&[&const_string(0, s_tok as u16), &return_void()]);
    // run(I)V: tok @0 and @2.
    let tok_twice = insns(&[
        &const_string(0, s_tok as u16),
        &const_string(0, s_tok as u16),
        &return_void(),
    ]);

    dex.add_class(
        t_class,
        t_object,
        &[
            method(m_main, Some(code(main))),
            method(m_run_void, Some(code(tok_once.clone()))),
            method(m_run_int, Some(code(tok_twice))),
            method(m_alpha, Some(code(tok_once.clone()))),
            method(m_beta, Some(code(tok_once.clone()))),
        ],
    );
    dex.finish()
}

/// In-test variant for the truncated-instruction-stream error: `insns_size`
/// claims far more units than the code item carries.
pub fn truncated_insns() -> Vec<u8> {
    let mut dex = FixtureDex::new();
    let s_class = dex.add_string(string("Lexample/BadCode;"));
    let s_object = dex.add_string(string("Ljava/lang/Object;"));
    let s_v = dex.add_string(string("V"));
    let s_tok = dex.add_string(string("tok"));
    let s_name = dex.add_string(string("m"));
    let t_class = dex.add_type(s_class);
    let t_object = dex.add_type(s_object);
    let t_v = dex.add_type(s_v);
    let p_void = dex.add_proto(s_v, t_v, &[]);
    let m0 = dex.add_method(t_class, p_void, s_name);
    let body = insns(&[&const_string(0, s_tok as u16), &return_void()]);
    dex.add_class(t_class, t_object, &[method(m0, Some(code_sized(body, 4096)))]);
    dex.finish()
}

/// REF-02 in-test variant: types/fields/methods whose names keep unpaired
/// surrogates, for the member-query UnsupportedEncoding matrix.
///
/// Strings: 0 "Lexample/U;", 1 Object, 2 "V", 3 "I", 4 = [0xD800] alone,
/// 5 = "Lbrok\xD800en;" units, 6 "plain", 7 "VI". Type 3 uses string 5;
/// method 1 and field 1 are declared on type 3 with name string 4.
/// `plain` (method 0) references field@0 @0, field@1 @2, method@0 @4,
/// method@1 @6, type@3 @8, return @10.
pub fn unpaired_members() -> Vec<u8> {
    let mut dex = FixtureDex::new();
    let s_class = dex.add_string(string("Lexample/U;"));
    let s_object = dex.add_string(string("Ljava/lang/Object;"));
    let s_v = dex.add_string(string("V"));
    let s_i = dex.add_string(string("I"));
    let s_broken_name = dex.add_string(string_units(&[0xd800]));
    let s_broken_type = dex.add_string(string_units(&[
        0x4c, 0x62, 0x72, 0x6f, 0x6b, 0xd800, 0x65, 0x6e, 0x3b,
    ]));
    let s_plain = dex.add_string(string("plain"));
    let t_class = dex.add_type(s_class);
    let t_object = dex.add_type(s_object);
    let t_v = dex.add_type(s_v);
    let t_i = dex.add_type(s_i);
    let t_broken = dex.add_type(s_broken_type);
    let p_void = dex.add_proto(s_v, t_v, &[]);
    let m_plain = dex.add_method(t_class, p_void, s_plain);
    let m_broken = dex.add_method(t_broken, p_void, s_broken_name);
    let f_plain = dex.add_field(t_class, t_i, s_plain);
    let f_broken = dex.add_field(t_broken, t_i, s_broken_name);
    let body = insns(&[
        &field21(0x60, 0, f_plain as u16),
        &field21(0x60, 0, f_broken as u16),
        &invoke35(0x71, m_plain as u16),
        &invoke35(0x71, m_broken as u16),
        &const_class(0, t_broken as u16),
        &return_void(),
    ]);
    dex.add_class(t_class, t_object, &[method(m_plain, Some(code(body)))]);
    dex.finish()
}
