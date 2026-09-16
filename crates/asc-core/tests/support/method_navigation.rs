//! Deterministic DEX fixture for the method-navigation golden matrix.
//!
//! The fixture is deliberately small but exercises declaration identity rather
//! than source-text inference: constructors, overloads, native/abstract
//! declaration-only methods, a method with no reference caller, annotations,
//! and debug parameter names all live in one class_data record.

use super::sha;

#[derive(Clone, Copy)]
struct MapEntry {
    kind: u16,
    size: u32,
    offset: u32,
}

struct Builder {
    bytes: Vec<u8>,
    map: Vec<MapEntry>,
}

impl Builder {
    fn new() -> Self {
        Self {
            bytes: vec![0; 112],
            map: vec![MapEntry {
                kind: 0,
                size: 1,
                offset: 0,
            }],
        }
    }

    fn align(&mut self, alignment: usize) {
        while !self.bytes.len().is_multiple_of(alignment) {
            self.bytes.push(0);
        }
    }

    fn section(&mut self, kind: u16, size: u32, payload: &[u8], alignment: usize) -> usize {
        self.align(alignment);
        let offset = self.bytes.len();
        self.map.push(MapEntry {
            kind,
            size,
            offset: offset as u32,
        });
        self.bytes.extend_from_slice(payload);
        offset
    }

    fn word(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn finish(mut self, tables: Tables) -> Vec<u8> {
        self.align(4);
        let map_offset = self.bytes.len();
        self.map.push(MapEntry {
            kind: 0x1000,
            size: 1,
            offset: map_offset as u32,
        });
        let mut map = Vec::with_capacity(4 + self.map.len() * 12);
        map.extend_from_slice(&(self.map.len() as u32).to_le_bytes());
        for entry in &self.map {
            map.extend_from_slice(&entry.kind.to_le_bytes());
            map.extend_from_slice(&0u16.to_le_bytes());
            map.extend_from_slice(&entry.size.to_le_bytes());
            map.extend_from_slice(&entry.offset.to_le_bytes());
        }
        self.bytes.extend_from_slice(&map);

        self.bytes[..8].copy_from_slice(b"dex\n035\0");
        let file_size = self.bytes.len() as u32;
        self.word(0x20, file_size);
        self.word(0x24, 112);
        self.word(0x28, 0x1234_5678);
        self.word(0x2c, 0);
        self.word(0x30, 0);
        self.word(0x34, map_offset as u32);
        for (offset, value) in [
            (0x38, tables.string_count),
            (0x3c, tables.string_ids as u32),
            (0x40, tables.type_count),
            (0x44, tables.type_ids as u32),
            (0x48, tables.proto_count),
            (0x4c, tables.proto_ids as u32),
            (0x50, tables.field_count),
            (0x54, tables.field_ids as u32),
            (0x58, tables.method_count),
            (0x5c, tables.method_ids as u32),
            (0x60, tables.class_count),
            (0x64, tables.class_defs as u32),
            (0x68, file_size - tables.data_offset as u32),
            (0x6c, tables.data_offset as u32),
        ] {
            self.word(offset, value);
        }
        let signature = sha::sha1(&self.bytes[32..]);
        self.bytes[12..32].copy_from_slice(&signature);
        self.word(8, sha::adler32(&self.bytes[12..]));
        self.bytes
    }
}

struct Tables {
    string_count: u32,
    string_ids: usize,
    type_count: u32,
    type_ids: usize,
    proto_count: u32,
    proto_ids: usize,
    field_count: u32,
    field_ids: usize,
    method_count: u32,
    method_ids: usize,
    class_count: u32,
    class_defs: usize,
    data_offset: usize,
}

fn uleb(mut value: u32) -> Vec<u8> {
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

fn words(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn method_ids(items: &[(u16, u16, u32)]) -> Vec<u8> {
    items
        .iter()
        .flat_map(|(class_idx, proto_idx, name_idx)| {
            class_idx
                .to_le_bytes()
                .into_iter()
                .chain(proto_idx.to_le_bytes())
                .chain(name_idx.to_le_bytes())
        })
        .collect()
}

fn code_item(registers: u16, ins: u16, debug_info_off: u32, insns: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + insns.len() * 2);
    out.extend_from_slice(&registers.to_le_bytes());
    out.extend_from_slice(&ins.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // outs_size
    out.extend_from_slice(&0u16.to_le_bytes()); // tries_size
    out.extend_from_slice(&debug_info_off.to_le_bytes());
    out.extend_from_slice(&(insns.len() as u32).to_le_bytes());
    for insn in insns {
        out.extend_from_slice(&insn.to_le_bytes());
    }
    out
}

fn annotation_item(visibility: u8, type_idx: u32, elements: &[(u32, u32)]) -> Vec<u8> {
    let mut out = vec![visibility];
    out.extend_from_slice(&uleb(type_idx));
    out.extend_from_slice(&uleb(elements.len() as u32));
    for (name_idx, string_idx) in elements {
        out.extend_from_slice(&uleb(*name_idx));
        // VALUE_STRING, one-byte payload (value_arg = 0).
        out.push(0x17);
        out.push(*string_idx as u8);
    }
    out
}

fn annotation_set(item_offset: u32) -> Vec<u8> {
    let mut out = 1u32.to_le_bytes().to_vec();
    out.extend_from_slice(&item_offset.to_le_bytes());
    out
}

fn type_list(type_idx: u32) -> Vec<u8> {
    let mut out = 1u32.to_le_bytes().to_vec();
    out.extend_from_slice(&(type_idx as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // four-byte alignment
    out
}

/// Build a valid DEX 035 with one `Lfixture/Navigation;` class.
pub fn fixture() -> Vec<u8> {
    // String IDs must be ART/code-point sorted. Keeping this list explicit
    // makes every table index below stable and reviewable.
    let strings: [&[u8]; 20] = [
        b"<init>",
        b"I",
        b"II",
        b"IL",
        b"Lfixture/Marker;",
        b"Lfixture/Navigation;",
        b"Lfixture/Param;",
        b"Ljava/lang/Object;",
        b"Ljava/lang/String;",
        b"V",
        b"VI",
        b"VL",
        b"abstractApi",
        b"count",
        b"nativeApi",
        b"overload",
        b"parameterMethod",
        b"source",
        b"value",
        b"annotated",
    ];
    // `annotated` sorts before `count`; the array above intentionally keeps
    // the prose groups readable, so sort the actual pool before indexing.
    let mut sorted = strings.to_vec();
    sorted.sort_unstable();
    let index = |needle: &[u8]| -> u32 {
        sorted
            .iter()
            .position(|value| *value == needle)
            .expect("fixture string") as u32
    };
    let mut builder = Builder::new();
    let string_ids = builder.section(1, sorted.len() as u32, &vec![0; sorted.len() * 4], 4);
    let type_descriptors = [
        b"I".as_slice(),
        b"Lfixture/Marker;".as_slice(),
        b"Lfixture/Navigation;".as_slice(),
        b"Lfixture/Param;".as_slice(),
        b"Ljava/lang/Object;".as_slice(),
        b"Ljava/lang/String;".as_slice(),
        b"V".as_slice(),
    ];
    let type_ids = builder.section(
        2,
        type_descriptors.len() as u32,
        &words(&type_descriptors.map(index)),
        4,
    );
    let type_index = |descriptor: &[u8]| -> u32 {
        type_descriptors
            .iter()
            .position(|value| *value == descriptor)
            .expect("fixture type") as u32
    };

    // Proto IDs are ordered by return type then parameter type list.
    let proto_specs: [(u32, u32, &[u8]); 5] = [
        (type_index(b"I"), 0, b"II"),
        (type_index(b"I"), 0, b"IL"),
        (type_index(b"V"), 0, b"V"),
        (type_index(b"V"), 0, b"VI"),
        (type_index(b"V"), 0, b"VL"),
    ];
    let proto_ids = builder.section(
        3,
        proto_specs.len() as u32,
        &words(
            &proto_specs
                .iter()
                .flat_map(|(ret, params, shorty)| [index(shorty), *ret, *params])
                .collect::<Vec<_>>(),
        ),
        4,
    );

    // method_ids are sorted by class, name, proto. The two overload rows stay
    // distinct because they have different proto IDs.
    let class_type_idx = type_index(b"Lfixture/Navigation;") as u16;
    let method_specs = [
        (class_type_idx, 2u16, index(b"<init>")),
        (class_type_idx, 3u16, index(b"<init>")),
        (class_type_idx, 3u16, index(b"abstractApi")),
        (class_type_idx, 1u16, index(b"nativeApi")),
        (class_type_idx, 3u16, index(b"overload")),
        (class_type_idx, 4u16, index(b"overload")),
        (class_type_idx, 0u16, index(b"parameterMethod")),
    ];
    let method_ids = builder.section(5, method_specs.len() as u32, &method_ids(&method_specs), 4);
    let class_defs = builder.section(6, 1, &[0; 32], 4);
    let data_offset = builder.bytes.len();

    // String data and string-id pointers.
    let mut string_data = Vec::new();
    let mut string_offsets = Vec::with_capacity(sorted.len());
    for value in &sorted {
        string_offsets.push(string_data.len() as u32);
        string_data.extend_from_slice(&uleb(value.len() as u32));
        string_data.extend_from_slice(value);
        string_data.push(0);
    }
    let string_data_offset = builder.section(0x2002, sorted.len() as u32, &string_data, 1);
    for (offset, relative) in string_offsets.iter().enumerate() {
        builder.word(
            string_ids + offset * 4,
            (string_data_offset as u32) + relative,
        );
    }

    // Parameter type lists. One list for I and one for String.
    let params_i_offset = builder.section(0x1001, 1, &type_list(type_index(b"I")), 4);
    let params_string_offset =
        builder.section(0x1001, 1, &type_list(type_index(b"Ljava/lang/String;")), 4);
    // Proto rows carry the on-disk offsets, not logical type-list ordinals.
    let proto_rows = [
        (index(b"II"), type_index(b"I"), params_i_offset as u32),
        (index(b"IL"), type_index(b"I"), params_string_offset as u32),
        (index(b"V"), type_index(b"V"), 0u32),
        (index(b"VI"), type_index(b"V"), params_i_offset as u32),
        (index(b"VL"), type_index(b"V"), params_string_offset as u32),
    ];
    for (row, (shorty, ret, params)) in proto_rows.iter().enumerate() {
        builder.word(proto_ids + row * 12, *shorty);
        builder.word(proto_ids + row * 12 + 4, *ret);
        builder.word(proto_ids + row * 12 + 8, *params);
    }

    // Debug info for parameterMethod(I)I: line_start=42, one explicit
    // parameter named `count`, then end-sequence.
    let debug = [42u8, 1, (index(b"count") as u8).saturating_add(1), 0];
    let debug_offset = builder.section(0x2003, 1, &debug, 1);

    let mut code_offsets = Vec::new();
    for (registers, ins, debug_info, insns) in [
        (1, 1, 0, vec![0x000e]),                   // <init>()V
        (2, 2, 0, vec![0x000e]),                   // <init>(I)V
        (2, 2, 0, vec![0x000e]),                   // overload(I)V
        (2, 2, 0, vec![0x000e]),                   // overload(String)V
        (2, 2, debug_offset as u32, vec![0x010f]), // parameterMethod(I)I
    ] {
        let bytes = code_item(registers, ins, debug_info, &insns);
        code_offsets.push(builder.section(0x2001, 1, &bytes, 4) as u32);
    }

    // Three annotation items: class marker, method marker, parameter marker.
    let mut annotation_items = Vec::new();
    let class_item_start = builder.bytes.len();
    let class_item = annotation_item(
        1,
        type_index(b"Lfixture/Marker;"),
        &[(index(b"value"), index(b"annotated"))],
    );
    annotation_items.extend_from_slice(&class_item);
    let method_item_start = class_item_start + annotation_items.len();
    let method_item = annotation_item(
        0,
        type_index(b"Lfixture/Marker;"),
        &[(index(b"value"), index(b"annotated"))],
    );
    annotation_items.extend_from_slice(&method_item);
    let parameter_item_start = class_item_start + annotation_items.len();
    let parameter_item = annotation_item(0, type_index(b"Lfixture/Param;"), &[]);
    annotation_items.extend_from_slice(&parameter_item);
    builder.section(0x2004, 3, &annotation_items, 1);

    let class_set = builder.section(0x1003, 1, &annotation_set(class_item_start as u32), 4);
    let method_set = builder.section(0x1003, 1, &annotation_set(method_item_start as u32), 4);
    let parameter_set = builder.section(0x1003, 1, &annotation_set(parameter_item_start as u32), 4);
    let parameter_refs = builder.section(0x1002, 1, &words(&[1, parameter_set as u32]), 4);
    let mut directory = Vec::with_capacity(16 + 16);
    directory.extend_from_slice(&(class_set as u32).to_le_bytes());
    directory.extend_from_slice(&0u32.to_le_bytes()); // fields_size
    directory.extend_from_slice(&1u32.to_le_bytes()); // methods_size
    directory.extend_from_slice(&1u32.to_le_bytes()); // parameters_size
    directory.extend_from_slice(&6u32.to_le_bytes()); // method_idx parameterMethod
    directory.extend_from_slice(&(method_set as u32).to_le_bytes());
    directory.extend_from_slice(&6u32.to_le_bytes());
    directory.extend_from_slice(&(parameter_refs as u32).to_le_bytes());
    let directory_offset = builder.section(0x2006, 1, &directory, 4);

    // Fill class_def: public class Navigation extends Object, source file,
    // annotation directory and class_data.
    let mut class_data = vec![0, 0, 2, 5]; // static, instance, direct, virtual
    // direct <init>()V (idx 0), <init>(I)V (idx delta 1)
    class_data.extend_from_slice(&[0]);
    class_data.extend_from_slice(&uleb(0x0001_0001));
    class_data.extend_from_slice(&uleb(code_offsets[0]));
    class_data.extend_from_slice(&[1]);
    class_data.extend_from_slice(&uleb(0x0001_0001));
    class_data.extend_from_slice(&uleb(code_offsets[1]));
    // virtual abstract/native/overloads/parameterMethod, with absolute method
    // deltas 2, 1, 1, 1, 1 and the expected access flags.
    for (delta, flags, code) in [
        (2u32, 0x0401u32, 0u32), // abstractApi(I)V
        (1, 0x0101, 0),          // nativeApi(String)I
        (1, 0x0001, code_offsets[2]),
        (1, 0x0001, code_offsets[3]),
        (1, 0x0001, code_offsets[4]),
    ] {
        class_data.extend_from_slice(&uleb(delta));
        class_data.extend_from_slice(&uleb(flags));
        class_data.extend_from_slice(&uleb(code));
    }
    let class_data_offset = builder.section(0x2000, 1, &class_data, 1);
    builder.word(class_defs, type_index(b"Lfixture/Navigation;"));
    builder.word(class_defs + 4, 0x0001); // public
    builder.word(class_defs + 8, type_index(b"Ljava/lang/Object;"));
    builder.word(class_defs + 12, 0); // interfaces_off
    builder.word(class_defs + 16, index(b"source"));
    builder.word(class_defs + 20, directory_offset as u32);
    builder.word(class_defs + 24, class_data_offset as u32);
    builder.word(class_defs + 28, 0); // static_values_off

    builder.finish(Tables {
        string_count: sorted.len() as u32,
        string_ids,
        type_count: type_descriptors.len() as u32,
        type_ids,
        proto_count: proto_specs.len() as u32,
        proto_ids,
        field_count: 0,
        field_ids: 0,
        method_count: method_specs.len() as u32,
        method_ids,
        class_count: 1,
        class_defs,
        data_offset,
    })
}
