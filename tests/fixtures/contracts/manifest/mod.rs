//! Manifest contract fixtures (A06): APK/AXML builders and a minimal stored
//! ZIP reader for the tests. Owned by the A06 work package; the shared
//! `tests/support` stays untouched (its APK helper writes single-entry
//! archives only, while the MAN cases need duplicate manifest entries and
//! arbitrary stored members).
//!
//! Everything here is deterministic: fixed timestamps, stored entries, and
//! byte-exact AXML chunks, so the committed fixture APKs regenerate to the
//! same SHA-256 values registered in `tests/fixtures/contracts/manifest.json`.

// ---------------------------------------------------------------------------
// Minimal stored-ZIP writer
// ---------------------------------------------------------------------------

/// Reflected CRC-32 (the ZIP check value), bitwise, standard-library only.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

const DOS_TIME: u16 = 0x0000; // 00:00:00
const DOS_DATE: u16 = 0x0021; // 1980-01-01

/// A stored (uncompressed) ZIP with the given entries, in order. Duplicate
/// names are preserved: the manifest entry selection takes the LAST record
/// carrying the name, mirroring `zipfile`/`read_entry`.
pub fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let name = name.as_bytes();
        let crc = crc32(data);
        let size = data.len() as u32;
        let local_offset = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut out, 20); // version needed
        push_u16(&mut out, 0); // flags
        push_u16(&mut out, 0); // method: stored
        push_u16(&mut out, DOS_TIME);
        push_u16(&mut out, DOS_DATE);
        push_u32(&mut out, crc);
        push_u32(&mut out, size);
        push_u32(&mut out, size);
        push_u16(&mut out, name.len() as u16);
        push_u16(&mut out, 0); // extra length
        out.extend_from_slice(name);
        out.extend_from_slice(data);

        central.extend_from_slice(b"PK\x01\x02");
        push_u16(&mut central, 20); // version made by
        push_u16(&mut central, 20); // version needed
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, DOS_TIME);
        push_u16(&mut central, DOS_DATE);
        push_u32(&mut central, crc);
        push_u32(&mut central, size);
        push_u32(&mut central, size);
        push_u16(&mut central, name.len() as u16);
        push_u16(&mut central, 0); // extra
        push_u16(&mut central, 0); // comment
        push_u16(&mut central, 0); // disk start
        push_u16(&mut central, 0); // internal attrs
        push_u32(&mut central, 0); // external attrs
        push_u32(&mut central, local_offset);
        central.extend_from_slice(name);
    }
    let central_offset = out.len() as u32;
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut out, 0); // this disk
    push_u16(&mut out, 0); // CD disk
    push_u16(&mut out, entries.len() as u16);
    push_u16(&mut out, entries.len() as u16);
    push_u32(&mut out, central_size);
    push_u32(&mut out, central_offset);
    push_u16(&mut out, 0); // comment
    out
}

// ---------------------------------------------------------------------------
// Minimal stored-ZIP reader (entry lookup only)
// ---------------------------------------------------------------------------

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// All entry names in central-directory order.
pub fn entry_names(zip: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let Some(eocd) = find_eocd(zip) else {
        return names;
    };
    let count = u16_at(zip, eocd + 10) as usize;
    let mut at = u32_at(zip, eocd + 16) as usize;
    for _ in 0..count {
        if at + 46 > zip.len() || &zip[at..at + 4] != b"PK\x01\x02" {
            break;
        }
        let name_len = u16_at(zip, at + 28) as usize;
        let extra_len = u16_at(zip, at + 30) as usize;
        let comment_len = u16_at(zip, at + 32) as usize;
        let name = String::from_utf8_lossy(&zip[at + 46..at + 46 + name_len]).into_owned();
        names.push(name);
        at += 46 + name_len + extra_len + comment_len;
    }
    names
}

fn find_eocd(zip: &[u8]) -> Option<usize> {
    let mut at = zip.len().checked_sub(22)?;
    loop {
        if &zip[at..at + 4] == b"PK\x05\x06" {
            return Some(at);
        }
        if at == 0 {
            return None;
        }
        at -= 1;
    }
}

/// The bytes of the LAST entry named `wanted`, mirroring the reference
/// implementation's `zipfile` resolution and rasc's `read_entry`.
pub fn last_entry(zip: &[u8], wanted: &str) -> Option<Vec<u8>> {
    let eocd = find_eocd(zip)?;
    let count = u16_at(zip, eocd + 10) as usize;
    let mut at = u32_at(zip, eocd + 16) as usize;
    let mut found = None;
    for _ in 0..count {
        if at + 46 > zip.len() || &zip[at..at + 4] != b"PK\x01\x02" {
            break;
        }
        let name_len = u16_at(zip, at + 28) as usize;
        let extra_len = u16_at(zip, at + 30) as usize;
        let comment_len = u16_at(zip, at + 32) as usize;
        let local = u32_at(zip, at + 42) as usize;
        let name = String::from_utf8_lossy(&zip[at + 46..at + 46 + name_len]).into_owned();
        if name == wanted {
            found = Some(read_stored_local(zip, local));
        }
        at += 46 + name_len + extra_len + comment_len;
    }
    found
}

fn read_stored_local(zip: &[u8], local: usize) -> Vec<u8> {
    let name_len = u16_at(zip, local + 26) as usize;
    let extra_len = u16_at(zip, local + 28) as usize;
    let size = u32_at(zip, local + 18) as usize;
    let start = local + 30 + name_len + extra_len;
    zip.get(start..start + size).map(<[u8]>::to_vec).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// AXML builder
// ---------------------------------------------------------------------------

const NONE: u32 = 0xFFFF_FFFF;
pub const ANDROID_URI: &str = "http://schemas.android.com/apk/res/android";

/// One attribute: ns/name string indices, rawValue index, typed type+data.
#[derive(Clone, Copy)]
pub struct Attr(pub u32, pub u32, pub u32, pub u8, pub u32);

/// One stream node of the binary XML document.
pub enum Chunk {
    StartNs(u32, u32),
    EndNs(u32, u32),
    Start { ns: u32, name: u32, comment: u32, attrs: Vec<Attr> },
    End(u32, u32),
    Cdata(u32),
}

/// A whole binary XML document spec.
pub struct AxmlSpec {
    pub utf8: bool,
    pub strings: Vec<String>,
    /// (string index, spans of [name, first, last]) — entry i belongs to
    /// string i, so every index below the highest styled one gets an entry.
    pub styles: Vec<(usize, Vec<[u32; 3]>)>,
    pub resource_map: Vec<u32>,
    pub nodes: Vec<Chunk>,
}

impl Default for AxmlSpec {
    fn default() -> Self {
        Self {
            utf8: true,
            strings: Vec::new(),
            styles: Vec::new(),
            resource_map: Vec::new(),
            nodes: Vec::new(),
        }
    }
}

fn len8(out: &mut Vec<u8>, value: usize) {
    if value >= 0x80 {
        out.push(0x80 | (value >> 8) as u8);
    }
    out.push(value as u8);
}

fn len16(out: &mut Vec<u8>, value: usize) {
    if value < 0x8000 {
        push_u16(out, value as u16);
    } else {
        push_u16(out, 0x8000 | (value >> 16) as u16);
        push_u16(out, (value & 0xffff) as u16);
    }
}

fn string_pool(spec: &AxmlSpec) -> Vec<u8> {
    let header_size: usize = 28;
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for string in &spec.strings {
        offsets.push(data.len() as u32);
        if spec.utf8 {
            len8(&mut data, string.chars().count());
            len8(&mut data, string.len());
            data.extend_from_slice(string.as_bytes());
            data.push(0);
        } else {
            let units: Vec<u16> = string.encode_utf16().collect();
            len16(&mut data, units.len());
            for unit in units {
                push_u16(&mut data, unit);
            }
            push_u16(&mut data, 0);
        }
    }
    let styled_upto = spec.styles.iter().map(|&(index, _)| index + 1).max().unwrap_or(0);
    let mut style_data = Vec::new();
    let mut style_offsets = Vec::new();
    for index in 0..styled_upto {
        style_offsets.push(style_data.len() as u32);
        let spans = spec
            .styles
            .iter()
            .find(|&&(styled, _)| styled == index)
            .map(|(_, spans)| spans.as_slice())
            .unwrap_or([].as_slice());
        for span in spans {
            push_u32(&mut style_data, span[0]);
            push_u32(&mut style_data, span[1]);
            push_u32(&mut style_data, span[2]);
        }
        push_u32(&mut style_data, NONE); // end of the span list
    }
    let mut out = Vec::new();
    let size_pos = out.len() + 4;
    push_u16(&mut out, 0x0001);
    push_u16(&mut out, header_size as u16);
    push_u32(&mut out, 0);
    push_u32(&mut out, spec.strings.len() as u32);
    push_u32(&mut out, styled_upto as u32);
    push_u32(&mut out, if spec.utf8 { 0x0000_0100 } else { 0 });
    let strings_start = header_size + 4 * spec.strings.len() + 4 * styled_upto;
    push_u32(&mut out, strings_start as u32);
    let styles_start = strings_start + data.len();
    push_u32(&mut out, if styled_upto == 0 { 0 } else { styles_start as u32 });
    for offset in &offsets {
        push_u32(&mut out, *offset);
    }
    for offset in &style_offsets {
        push_u32(&mut out, *offset);
    }
    out.extend_from_slice(&data);
    out.extend_from_slice(&style_data);
    let size = out.len();
    out[size_pos..size_pos + 4].copy_from_slice(&(size as u32).to_le_bytes());
    out
}

fn node_header(out: &mut Vec<u8>, typ: u16, line: u32, comment: u32) -> usize {
    push_u16(out, typ);
    push_u16(out, 16);
    let size_pos = out.len();
    push_u32(out, 0);
    push_u32(out, line);
    push_u32(out, comment);
    size_pos
}

fn finish_node(out: &mut [u8], size_pos: usize) {
    let size = out.len() - size_pos + 4;
    out[size_pos..size_pos + 4].copy_from_slice(&(size as u32).to_le_bytes());
}

/// Serializes the spec to binary AXML bytes.
pub fn axml(spec: &AxmlSpec) -> Vec<u8> {
    let mut nodes = Vec::new();
    for chunk in &spec.nodes {
        match chunk {
            Chunk::StartNs(prefix, uri) => {
                let size_pos = node_header(&mut nodes, 0x0100, 1, NONE);
                push_u32(&mut nodes, *prefix);
                push_u32(&mut nodes, *uri);
                finish_node(&mut nodes, size_pos);
            }
            Chunk::EndNs(prefix, uri) => {
                let size_pos = node_header(&mut nodes, 0x0101, 1, NONE);
                push_u32(&mut nodes, *prefix);
                push_u32(&mut nodes, *uri);
                finish_node(&mut nodes, size_pos);
            }
            Chunk::Start { ns, name, comment, attrs } => {
                let size_pos = node_header(&mut nodes, 0x0102, 7, *comment);
                push_u32(&mut nodes, *ns);
                push_u32(&mut nodes, *name);
                push_u16(&mut nodes, 20);
                push_u16(&mut nodes, 20);
                push_u16(&mut nodes, attrs.len() as u16);
                push_u16(&mut nodes, 0);
                push_u16(&mut nodes, 0);
                push_u16(&mut nodes, 0);
                for Attr(ns, name, raw, ty, data) in attrs {
                    push_u32(&mut nodes, *ns);
                    push_u32(&mut nodes, *name);
                    push_u32(&mut nodes, *raw);
                    push_u16(&mut nodes, 8);
                    nodes.push(0);
                    nodes.push(*ty);
                    push_u32(&mut nodes, *data);
                }
                finish_node(&mut nodes, size_pos);
            }
            Chunk::End(ns, name) => {
                let size_pos = node_header(&mut nodes, 0x0103, 7, NONE);
                push_u32(&mut nodes, *ns);
                push_u32(&mut nodes, *name);
                finish_node(&mut nodes, size_pos);
            }
            Chunk::Cdata(data) => {
                let size_pos = node_header(&mut nodes, 0x0104, 7, NONE);
                push_u32(&mut nodes, *data);
                push_u16(&mut nodes, 8);
                nodes.push(0);
                nodes.push(0x03);
                push_u32(&mut nodes, *data);
                finish_node(&mut nodes, size_pos);
            }
        }
    }

    let mut out = Vec::new();
    push_u16(&mut out, 0x0003);
    push_u16(&mut out, 8);
    let size_pos = out.len();
    push_u32(&mut out, 0);
    out.extend_from_slice(&string_pool(spec));
    // Resource map chunk.
    push_u16(&mut out, 0x0180);
    push_u16(&mut out, 8);
    push_u32(&mut out, (8 + 4 * spec.resource_map.len()) as u32);
    for id in &spec.resource_map {
        push_u32(&mut out, *id);
    }
    out.extend_from_slice(&nodes);
    let size = out.len();
    out[size_pos..size_pos + 4].copy_from_slice(&(size as u32).to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// The registered fixtures
// ---------------------------------------------------------------------------

/// Index helper over a spec's string list.
fn idx(spec: &AxmlSpec, needle: &str) -> u32 {
    spec.strings
        .iter()
        .position(|string| string == needle)
        .unwrap_or_else(|| panic!("string {needle:?} missing from the fixture pool")) as u32
}

/// MAN-01 pass fixture: UTF-8 AXML with a long package string (two-byte
/// length form), a styled pool string, an escaped label and CDATA content.
/// The APK carries an older plain-XML manifest first; the last entry wins.
pub fn man01_last_manifest_entry_apk() -> Vec<u8> {
    let long_package = format!("com.example.{}", "l".repeat(188));
    let mut spec = AxmlSpec {
        utf8: true,
        strings: vec![
            "manifest".to_owned(),
            ANDROID_URI.to_owned(),
            "android".to_owned(),
            "package".to_owned(),
            long_package.clone(),
            "application".to_owned(),
            "label".to_owned(),
            "Example & <app>\"q".to_owned(),
            "versionCode".to_owned(),
            "styled text here".to_owned(),
            "note".to_owned(),
            "a ]]> b".to_owned(),
        ],
        styles: vec![(9, vec![[6, 0, 5], [6, 6, 16]])],
        resource_map: vec![],
        nodes: Vec::new(),
    };
    let android_uri = idx(&spec, ANDROID_URI);
    let android = idx(&spec, "android");
    spec.nodes = vec![
        Chunk::StartNs(android, android_uri),
        Chunk::Start {
            ns: NONE,
            name: idx(&spec, "manifest"),
            comment: NONE,
            attrs: vec![
                Attr(NONE, idx(&spec, "package"), idx(&spec, &long_package), 0x03, idx(&spec, &long_package)),
                Attr(android_uri, idx(&spec, "versionCode"), NONE, 0x10, 42),
            ],
        },
        Chunk::Start {
            ns: NONE,
            name: idx(&spec, "application"),
            comment: idx(&spec, "note"),
            attrs: vec![Attr(android_uri, idx(&spec, "label"), idx(&spec, "Example & <app>\"q"), 0x03, idx(&spec, "Example & <app>\"q"))],
        },
        Chunk::Cdata(idx(&spec, "a ]]> b")),
        Chunk::End(NONE, idx(&spec, "application")),
        Chunk::End(NONE, idx(&spec, "manifest")),
        Chunk::EndNs(android, android_uri),
    ];
    let older = b"<?xml version=\"1.0\"?><manifest package=\"old\" />";
    stored_zip(&[
        ("AndroidManifest.xml", older.as_slice()),
        ("AndroidManifest.xml", &axml(&spec)),
        ("classes.dex", b"placeholder-not-a-dex"),
    ])
}

/// MAN-01 missing-manifest fixture: an APK without any manifest entry.
pub fn man01_missing_manifest_apk() -> Vec<u8> {
    stored_zip(&[
        ("classes.dex", b"placeholder-not-a-dex"),
        ("res/values.xml", b"<resources/>"),
    ])
}

/// MAN-01 fake-text fixture: a manifest entry that starts like XML text but
/// is not well-formed.
pub fn man01_plain_xml_text_rejected_apk() -> Vec<u8> {
    stored_zip(&[(
        "AndroidManifest.xml",
        b"<?xml version=\"1.0\"?><manifest package=\"x\"><activity name=\".Main\"",
    )])
}

/// MAN-02 typed-value matrix fixture: a UTF-16 AXML exercising every typed
/// value form, including the raw-precision cases.
pub fn man02_typed_value_matrix_apk() -> Vec<u8> {
    let mut spec = AxmlSpec {
        utf8: false,
        strings: vec![
            "matrix".to_owned(),
            ANDROID_URI.to_owned(),
            "android".to_owned(),
            "hello & <world>".to_owned(),
        ],
        styles: vec![],
        resource_map: vec![],
        nodes: Vec::new(),
    };
    // Attribute names n01..n33 as pool strings.
    for number in 1..=33 {
        spec.strings.push(format!("n{number:02}"));
    }
    let android_uri = idx(&spec, ANDROID_URI);
    let hello = idx(&spec, "hello & <world>");
    let name = |spec: &AxmlSpec, number: usize| idx(spec, &format!("n{number:02}"));

    // (name number, typed type, typed data, rawValue index)
    let matrix: &[(usize, u8, u32, u32)] = &[
        (1, 0x01, 0x7F0D_0001, NONE),                    // @app reference
        (2, 0x01, 0x0103_0007, NONE),                    // @android reference
        (3, 0x02, 0x7F0D_0002, NONE),                    // ?app attribute
        (4, 0x02, 0x0103_0008, NONE),                    // ?android attribute
        (5, 0x03, hello, hello),                         // string with raw
        (6, 0x04, 0x4000_0000, NONE),                    // 2.0f
        (7, 0x04, 0x7F80_0000, NONE),                    // +inf
        (8, 0x04, 0xFF80_0000, NONE),                    // -inf
        (9, 0x04, 0x7FC0_0000, NONE),                    // NaN
        (10, 0x05, (100 << 8), NONE),                    // 100px, unit 0
        (11, 0x05, (16 << 8) | 1, NONE),                 // 16dip
        (12, 0x05, (20 << 8) | 2, NONE),                 // 20sp
        (13, 0x05, (30 << 8) | 3, NONE),                 // 30pt
        (14, 0x05, (40 << 8) | 4, NONE),                 // 40in
        (15, 0x05, (50 << 8) | 5, NONE),                 // 50mm
        (16, 0x06, (0x40 << 8) | (1 << 4), NONE),        // 50%, radix 1
        (17, 0x06, (1 << 8) | 1, NONE),                  // 100%p, radix 0
        (18, 0x10, 42, NONE),                            // dec
        (19, 0x10, 0xFFFF_FFFF, NONE),                   // -1
        (20, 0x10, 0x8000_0000, NONE),                   // INT_MIN
        (21, 0x11, 0x4000_3FB4, NONE),                   // hex
        (22, 0x12, 1, NONE),                             // true
        (23, 0x12, 0, NONE),                             // false
        (24, 0x1c, 0xFF11_2233, NONE),                   // ARGB color
        (25, 0x1d, 0x0011_2233, NONE),                   // RGB color, 0x1d
        (26, 0x1e, 0x1122_3344, NONE),                   // 0x1e
        (27, 0x1f, 0xAABB_CCDD, NONE),                   // 0x1f
        (28, 0x07, 0x7F00_0001, NONE),                   // dynamic reference
        (29, 0x08, 5, NONE),                             // dynamic attribute
        (30, 0x13, 9, NONE),                             // reserved type
        (31, 0x33, 0x1234, NONE),                        // unknown type
        (32, 0x00, 0, NONE),                             // null type
        (33, 0x05, (7 << 8) | 9, NONE),                  // dimension, unknown unit
    ];
    let attrs = matrix
        .iter()
        .map(|&(number, ty, data, raw)| Attr(android_uri, name(&spec, number), raw, ty, data))
        .collect();
    spec.nodes = vec![
        Chunk::StartNs(idx(&spec, "android"), android_uri),
        Chunk::Start { ns: NONE, name: idx(&spec, "matrix"), comment: NONE, attrs },
        Chunk::End(NONE, idx(&spec, "matrix")),
        Chunk::EndNs(idx(&spec, "android"), android_uri),
    ];
    stored_zip(&[("AndroidManifest.xml", &axml(&spec))])
}

/// MAN-03 AXML fixture: prefix shadowing with scope recovery, a default
/// namespace, attributes in namespaces, node order with CDATA and comment
/// metadata, an inferred android binding, and a namespace end after the
/// root that must still be consumed.
pub fn man03_cdata_pi_node_order_apk() -> Vec<u8> {
    let mut spec = AxmlSpec {
        utf8: true,
        strings: vec![
            "manifest".to_owned(),
            "http://a".to_owned(),
            "app".to_owned(),
            ANDROID_URI.to_owned(),
            "outer".to_owned(),
            "inner".to_owned(),
            "tag".to_owned(),
            "x".to_owned(),
            "label".to_owned(),
            "Example".to_owned(),
            "child".to_owned(),
            "a ]]> b".to_owned(),
            " tail text ".to_owned(),
            "http://b".to_owned(),
            "http://d".to_owned(),
            "dchild".to_owned(),
            "note".to_owned(),
            String::new(),
        ],
        styles: vec![],
        resource_map: vec![],
        nodes: Vec::new(),
    };
    let s = |needle: &str| idx(&spec, needle);
    let android_uri = s(ANDROID_URI);
    let app = s("app");
    spec.nodes = vec![
        Chunk::StartNs(app, s("http://a")),
        Chunk::Start {
            ns: NONE,
            name: s("manifest"),
            comment: NONE,
            // The android namespace is never declared: the binding must be
            // inferred with a warning diagnostic.
            attrs: vec![Attr(android_uri, s("label"), s("Example"), 0x03, s("Example"))],
        },
        Chunk::Start { ns: NONE, name: s("outer"), comment: NONE, attrs: vec![] },
        Chunk::StartNs(app, s("http://b")),
        Chunk::Start {
            ns: NONE,
            name: s("inner"),
            comment: s("note"),
            attrs: vec![
                // The attribute `ns` field carries the URI string index, not
                // the prefix index (the aapt layout; only the namespace
                // chunks pair prefix and uri).
                Attr(s("http://b"), s("tag"), s("x"), 0x03, s("x")),
                Attr(android_uri, s("label"), s("Example"), 0x03, s("Example")),
            ],
        },
        Chunk::Cdata(s("a ]]> b")),
        Chunk::Cdata(s(" tail text ")),
        Chunk::End(NONE, s("inner")),
        Chunk::EndNs(app, s("http://b")),
        Chunk::StartNs(s(""), s("http://d")),
        Chunk::Start { ns: s("http://d"), name: s("dchild"), comment: NONE, attrs: vec![] },
        Chunk::End(s("http://d"), s("dchild")),
        Chunk::EndNs(s(""), s("http://d")),
        Chunk::Start { ns: NONE, name: s("child"), comment: NONE, attrs: vec![] },
        Chunk::End(NONE, s("child")),
        Chunk::End(NONE, s("outer")),
        Chunk::End(NONE, s("manifest")),
        Chunk::EndNs(app, s("http://a")),
    ];
    stored_zip(&[("AndroidManifest.xml", &axml(&spec))])
}

/// MAN-03 plain-XML fixture: prolog/epilog comments and PIs, mixed content
/// with text tails, CDATA, entity and character references.
pub const MAN03_PLAIN_XML: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
    "<!--built by hand-->\n",
    "<?tool mode=gen?>\n",
    "<manifest package=\"com.example\" extra=\"line&#10;break&amp;more\">\n",
    "    <uses-sdk android:minSdkVersion=\"21\" />\n",
    "    <!--inner comment-->\n",
    "    <activity name=\".Main\">text before <intent-filter/> tail &amp; after &#65;<![CDATA[raw <> &]]> end</activity>\n",
    "</manifest>\n",
    "<?epilog pi?>\n",
    "<!--epilog comment-->\n",
);

pub fn man03_plain_xml_tree_apk() -> Vec<u8> {
    stored_zip(&[("AndroidManifest.xml", MAN03_PLAIN_XML.as_bytes())])
}

/// MAN-04 second-root fixture: a structurally readable single root followed
/// by another root element.
pub fn man04_second_root_apk() -> Vec<u8> {
    let spec = AxmlSpec {
        utf8: true,
        strings: vec!["root".to_owned(), "other".to_owned()],
        styles: vec![],
        resource_map: vec![],
        nodes: vec![
            Chunk::Start { ns: NONE, name: 0, comment: NONE, attrs: vec![] },
            Chunk::End(NONE, 0),
            Chunk::Start { ns: NONE, name: 1, comment: NONE, attrs: vec![] },
            Chunk::End(NONE, 1),
        ],
    };
    stored_zip(&[("AndroidManifest.xml", &axml(&spec))])
}

/// MAN-04 DTD fixture: a plain-XML manifest with a DOCTYPE declaration.
pub fn man04_dtd_rejected_apk() -> Vec<u8> {
    let text = concat!(
        "<?xml version=\"1.0\"?>\n",
        "<!DOCTYPE manifest PUBLIC \"-//Example//DTD//EN\" \"http://example.invalid/dtd\">\n",
        "<manifest package=\"x\" />\n",
    );
    stored_zip(&[("AndroidManifest.xml", text.as_bytes())])
}

/// MAN-04 limit fixture: three nested elements; decoding with a depth limit
/// of two must fail with ResourceLimit while the default limits succeed.
pub fn man04_limit_boundaries_apk() -> Vec<u8> {
    let spec = AxmlSpec {
        utf8: true,
        strings: vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
        styles: vec![],
        resource_map: vec![],
        nodes: vec![
            Chunk::Start { ns: NONE, name: 0, comment: NONE, attrs: vec![] },
            Chunk::Start { ns: NONE, name: 1, comment: NONE, attrs: vec![] },
            Chunk::Start { ns: NONE, name: 2, comment: NONE, attrs: vec![] },
            Chunk::End(NONE, 2),
            Chunk::End(NONE, 1),
            Chunk::End(NONE, 0),
        ],
    };
    stored_zip(&[("AndroidManifest.xml", &axml(&spec))])
}
