//! Byte-exact ports of the Python baseline DEX fixture builders.
//!
//! `make_dex` and `make_static_field_dex` reproduce
//! `asc-ref/python-main/tests/dex_fixture.py` output byte for byte; the
//! harness pins both against the Python outputs' SHA-256 (recorded as
//! constants in `tests/contract_harness.rs`). `make_regex_string_dex` is the
//! ASC-owned extension used by the G01 regex fixture. The builder mirrors the
//! Python section helper: sections register themselves in map order, and the
//! header, signature and checksum are finalized once at the end.

use super::sha;

/// ULEB128 encoding, matching `dex_fixture.uleb`.
pub fn uleb128(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}

/// One map_list entry registered while a section is emitted.
struct MapEntry {
    kind: u16,
    size: u32,
    offset: u32,
}

/// Table sizes/offsets for the DEX header's second half (bytes 56..112).
struct HeaderTables {
    strings: u32,
    string_ids: usize,
    types: u32,
    type_ids: usize,
    protos: u32,
    proto_ids: usize,
    fields: u32,
    field_ids: usize,
    methods: u32,
    method_ids: usize,
    classes: u32,
    class_defs: usize,
    data_off: usize,
}

pub struct DexBuilder {
    buf: Vec<u8>,
    sections: Vec<MapEntry>,
}

impl DexBuilder {
    /// 112-byte zeroed header; the map_list starts with the header entry.
    fn new() -> Self {
        DexBuilder {
            buf: vec![0; 112],
            sections: vec![MapEntry { kind: 0, size: 1, offset: 0 }],
        }
    }

    fn len(&self) -> usize {
        self.buf.len()
    }

    /// Align, remember the section in map order, append its payload.
    fn section(&mut self, kind: u16, size: u32, data: &[u8], align: usize) -> usize {
        while !self.buf.len().is_multiple_of(align) {
            self.buf.push(0);
        }
        let offset = self.buf.len();
        self.sections.push(MapEntry { kind, size, offset: offset as u32 });
        self.buf.extend_from_slice(data);
        offset
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        self.buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// The single class_def used by every fixture so far, with the fixed
    /// public/extends-Object framing the Python builders also hard-code.
    fn write_class_def(
        &mut self,
        class_defs: usize,
        class_idx: u32,
        access: u32,
        super_idx: u32,
        class_data_off: u32,
        static_values_off: u32,
    ) {
        let values = [
            class_idx,
            access,
            super_idx,
            0,
            0xffff_ffff,
            0,
            class_data_off,
            static_values_off,
        ];
        for (index, value) in values.iter().enumerate() {
            self.write_u32(class_defs + index * 4, *value);
        }
    }

    /// Emit the remaining map_list, then patch magic, header and tables, and
    /// compute signature and checksum in the same order as the Python code.
    fn finish(mut self, tables: HeaderTables) -> Vec<u8> {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        let map_off = self.buf.len();
        self.sections.push(MapEntry { kind: 0x1000, size: 1, offset: map_off as u32 });
        let mut map = (self.sections.len() as u32).to_le_bytes().to_vec();
        for entry in &self.sections {
            map.extend_from_slice(&entry.kind.to_le_bytes());
            map.extend_from_slice(&0u16.to_le_bytes());
            map.extend_from_slice(&entry.size.to_le_bytes());
            map.extend_from_slice(&entry.offset.to_le_bytes());
        }
        self.buf.extend_from_slice(&map);

        self.buf[..8].copy_from_slice(b"dex\n035\0");
        let file_size = self.buf.len() as u32;
        self.write_u32(0x20, file_size);
        self.write_u32(0x24, 112);
        self.write_u32(0x28, 0x1234_5678);
        self.write_u32(0x2c, 0);
        self.write_u32(0x30, 0);
        self.write_u32(0x34, map_off as u32);

        let fields = [
            (0x38, tables.strings),
            (0x3c, tables.string_ids as u32),
            (0x40, tables.types),
            (0x44, tables.type_ids as u32),
            (0x48, tables.protos),
            (0x4c, tables.proto_ids as u32),
            (0x50, tables.fields),
            (0x54, tables.field_ids as u32),
            (0x58, tables.methods),
            (0x5c, tables.method_ids as u32),
            (0x60, tables.classes),
            (0x64, tables.class_defs as u32),
            (0x68, file_size - tables.data_off as u32),
            (0x6c, tables.data_off as u32),
        ];
        for (offset, value) in fields {
            self.write_u32(offset, value);
        }

        let signature = sha::sha1(&self.buf[32..]);
        self.buf[12..32].copy_from_slice(&signature);
        self.write_u32(8, sha::adler32(&self.buf[12..]));
        self.buf
    }

    /// Emit string_data items and back-fill string_ids with running offsets.
    fn write_string_pool(&mut self, string_ids: usize, strings: &[&[u8]]) {
        let mut data = Vec::new();
        for value in strings {
            data.extend_from_slice(&uleb128(value.len() as u32));
            data.extend_from_slice(value);
            data.push(0);
        }
        let base = self.section(0x2002, strings.len() as u32, &data, 1);
        let mut offset = base;
        for (index, value) in strings.iter().enumerate() {
            self.write_u32(string_ids + 4 * index, offset as u32);
            offset += uleb128(value.len() as u32).len() + value.len() + 1;
        }
    }
}

/// code_item header: registers/ins/outs/tries, debug_info_off, insns_size.
fn code_item_header(registers: u16, insns_size: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&registers.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // ins_size
    out.extend_from_slice(&0u16.to_le_bytes()); // outs_size
    out.extend_from_slice(&0u16.to_le_bytes()); // tries_size
    out.extend_from_slice(&0u32.to_le_bytes()); // debug_info_off
    out.extend_from_slice(&insns_size.to_le_bytes());
    out
}

/// Concatenated method_id_items: (class_idx, proto_idx, name_idx).
fn method_id_items(items: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(items.len() * 8);
    for (class_idx, proto_idx, name_idx) in items {
        out.extend_from_slice(&class_idx.to_le_bytes());
        out.extend_from_slice(&proto_idx.to_le_bytes());
        out.extend_from_slice(&name_idx.to_le_bytes());
    }
    out
}

/// Concatenated field_id_items: (class_idx, type_idx, name_idx).
fn field_id_items(items: &[(u16, u16, u32)]) -> Vec<u8> {
    method_id_items(items)
}

/// Little-endian u32 words as bytes (type_ids and proto_ids payloads).
fn u32_words(values: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 4);
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

/// Port of `dex_fixture.make_dex`: one class with two direct methods sharing
/// one code_item that references string@5 ("token").
pub fn make_dex() -> Vec<u8> {
    let strings: [&[u8]; 6] =
        [b"Lexample/Test;", b"Ljava/lang/Object;", b"V", b"first", b"second", b"token"];
    let mut builder = DexBuilder::new();
    let string_ids = builder.section(1, strings.len() as u32, &[0u8; 24], 4);
    let type_ids = builder.section(2, 3, &u32_words(&[0, 1, 2]), 4);
    let proto_ids = builder.section(3, 1, &u32_words(&[2, 2, 0]), 4);
    let method_ids =
        builder.section(5, 2, &method_id_items(&[(0, 0, 3), (0, 0, 4)]), 4);
    let class_defs = builder.section(6, 1, &[0u8; 32], 4);
    let data_off = builder.len();
    builder.write_string_pool(string_ids, &strings);

    // const-string v0, string@5; return-void
    let mut code = code_item_header(1, 3);
    code.extend_from_slice(&[0x1a, 0x00, 0x05, 0x00, 0x0e, 0x00]);
    let code_off = builder.section(0x2001, 1, &code, 4);

    // class_data: two direct methods (first, second) sharing that code_item.
    let mut class_data = vec![0, 0, 2, 0];
    class_data.extend_from_slice(&[0x00, 0x09]);
    class_data.extend_from_slice(&uleb128(code_off as u32));
    class_data.extend_from_slice(&[0x01, 0x09]);
    class_data.extend_from_slice(&uleb128(code_off as u32));
    let class_data_off = builder.section(0x2000, 1, &class_data, 1);

    builder.write_class_def(class_defs, 0, 1, 1, class_data_off as u32, 0);
    builder.finish(HeaderTables {
        strings: 6,
        string_ids,
        types: 3,
        type_ids,
        protos: 1,
        proto_ids,
        fields: 0,
        field_ids: 0,
        methods: 2,
        method_ids,
        classes: 1,
        class_defs,
        data_off,
    })
}

/// Port of `dex_fixture.make_static_field_dex`: static int FIRST=11/SECOND=22
/// from an encoded array, and getSecond() returning the sget of field@1.
pub fn make_static_field_dex() -> Vec<u8> {
    let strings: [&[u8]; 6] = [
        b"Lexample/Statics;",
        b"Ljava/lang/Object;",
        b"I",
        b"FIRST",
        b"SECOND",
        b"getSecond",
    ];
    let mut builder = DexBuilder::new();
    let string_ids = builder.section(1, strings.len() as u32, &[0u8; 24], 4);
    let type_ids = builder.section(2, 3, &u32_words(&[0, 1, 2]), 4);
    let proto_ids = builder.section(3, 1, &u32_words(&[2, 2, 0]), 4);
    let field_ids = builder.section(4, 2, &field_id_items(&[(0, 2, 3), (0, 2, 4)]), 4);
    let method_ids = builder.section(5, 1, &method_id_items(&[(0, 0, 5)]), 4);
    let class_defs = builder.section(6, 1, &[0u8; 32], 4);
    let data_off = builder.len();
    builder.write_string_pool(string_ids, &strings);

    // sget v0, field@1 (SECOND); return v0
    let mut code = code_item_header(1, 3);
    code.extend_from_slice(&[0x60, 0x00, 0x01, 0x00, 0x0f, 0x00]);
    let code_off = builder.section(0x2001, 1, &code, 4);

    // class_data: two static fields then one direct method.
    let mut class_data = vec![2, 0, 1, 0];
    class_data.extend_from_slice(&[0x00, 0x09, 0x01, 0x09]);
    class_data.extend_from_slice(&[0x00, 0x09]);
    class_data.extend_from_slice(&uleb128(code_off as u32));
    let class_data_off = builder.section(0x2000, 1, &class_data, 1);

    // static_values: encoded array [11, 22] as one-byte INT values.
    let static_values = builder.section(0x2005, 1, &[0x02, 0x04, 0x0b, 0x04, 0x16], 1);

    builder.write_class_def(
        class_defs,
        0,
        1,
        1,
        class_data_off as u32,
        static_values as u32,
    );
    builder.finish(HeaderTables {
        strings: 6,
        string_ids,
        types: 3,
        type_ids,
        protos: 1,
        proto_ids,
        fields: 2,
        field_ids,
        methods: 1,
        method_ids,
        classes: 1,
        class_defs,
        data_off,
    })
}

/// ASC-owned G01 fixture: one method whose code references string@4 ("token")
/// and string@5 ("tokens"), so literal and regex queries hit different sets.
///
/// Layout mirrors `make_dex` (same section order and header framing); only
/// the string pool, method list and instruction stream differ.
pub fn make_regex_string_dex() -> Vec<u8> {
    let strings: [&[u8]; 6] = [
        b"Lexample/Regex;",
        b"Ljava/lang/Object;",
        b"V",
        b"mark",
        b"token",
        b"tokens",
    ];
    let mut builder = DexBuilder::new();
    let string_ids = builder.section(1, strings.len() as u32, &[0u8; 24], 4);
    let type_ids = builder.section(2, 3, &u32_words(&[0, 1, 2]), 4);
    let proto_ids = builder.section(3, 1, &u32_words(&[2, 2, 0]), 4);
    let method_ids = builder.section(5, 1, &method_id_items(&[(0, 0, 3)]), 4);
    let class_defs = builder.section(6, 1, &[0u8; 32], 4);
    let data_off = builder.len();
    builder.write_string_pool(string_ids, &strings);

    // const-string v0, string@4 ("token") at code unit 0;
    // const-string v0, string@5 ("tokens") at code unit 2; return-void.
    let mut code = code_item_header(1, 5);
    code.extend_from_slice(&[0x1a, 0x00, 0x04, 0x00]);
    code.extend_from_slice(&[0x1a, 0x00, 0x05, 0x00]);
    code.extend_from_slice(&[0x0e, 0x00]);
    let code_off = builder.section(0x2001, 1, &code, 4);

    // class_data: one direct method (mark).
    let mut class_data = vec![0, 0, 1, 0];
    class_data.extend_from_slice(&[0x00, 0x09]);
    class_data.extend_from_slice(&uleb128(code_off as u32));
    let class_data_off = builder.section(0x2000, 1, &class_data, 1);

    builder.write_class_def(class_defs, 0, 1, 1, class_data_off as u32, 0);
    builder.finish(HeaderTables {
        strings: 6,
        string_ids,
        types: 3,
        type_ids,
        protos: 1,
        proto_ids,
        fields: 0,
        field_ids: 0,
        methods: 1,
        method_ids,
        classes: 1,
        class_defs,
        data_off,
    })
}

/// Zero the header checksum (offset 8..12) and SHA-1 signature (12..32),
/// leaving the structure intact - the G03 fixture shape.
pub fn zero_checksum_header(dex: &[u8]) -> Vec<u8> {
    let mut out = dex.to_vec();
    out[8..12].fill(0);
    out[12..32].fill(0);
    out
}
