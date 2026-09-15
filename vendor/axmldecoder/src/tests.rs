//! Vendor regression tests for the rasc patches (AX-P01..AX-P04).
//!
//! The fixtures are built by hand here: the byte-level builder mirrors the
//! binary XML chunk layout (see AOSP `ResourceTypes.h`), so every test can
//! state exactly which structural property it exercises. These tests run with
//! `cargo test --manifest-path vendor/axmldecoder/Cargo.toml`; the ASC
//! contract tests in `tests/contract_manifest.rs` cover the core-side
//! behaviour on top of the same parser.

use crate::DecodeLimits;

const NONE: u32 = 0xFFFF_FFFF;
const ANDROID: &str = "http://schemas.android.com/apk/res/android";

fn limits() -> DecodeLimits {
    DecodeLimits::default()
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u32_of(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// One UTF-8 length: one byte, or two when the high bit of the first is set.
fn len8(out: &mut Vec<u8>, value: usize) {
    if value >= 0x80 {
        out.push(0x80 | (value >> 8) as u8);
    }
    out.push(value as u8);
}

/// One UTF-16 length: one unit, or the extended two-unit form.
fn len16(out: &mut Vec<u8>, value: usize) {
    if value < 0x8000 {
        push_u16(out, value as u16);
    } else {
        push_u16(out, 0x8000 | (value >> 16) as u16);
        push_u16(out, (value & 0xffff) as u16);
    }
}

/// A string pool over `strings`. Style entry `i` (as the format defines it)
/// belongs to string `i`; pass spans for the styled indices and every index
/// below the highest styled one gets an (empty or given) entry.
fn string_pool(utf8: bool, strings: &[&str], styles: &[(usize, &[[u32; 3]])]) -> Vec<u8> {
    let header_size: usize = 28;
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for string in strings {
        offsets.push(data.len() as u32);
        if utf8 {
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
    let styled_upto = styles.iter().map(|&(index, _)| index + 1).max().unwrap_or(0);
    let mut style_data = Vec::new();
    let mut style_offsets = Vec::new();
    for index in 0..styled_upto {
        style_offsets.push(style_data.len() as u32);
        let spans = styles
            .iter()
            .find(|&&(styled, _)| styled == index)
            .map(|&(_, spans)| spans)
            .unwrap_or(&[]);
        for span in spans {
            push_u32(&mut style_data, span[0]);
            push_u32(&mut style_data, span[1]);
            push_u32(&mut style_data, span[2]);
        }
        push_u32(&mut style_data, 0xFFFF_FFFF); // end of the span list
    }
    while style_data.len() % 4 != 0 {
        style_data.push(0);
    }

    let mut out = Vec::new();
    let size_pos = out.len() + 4;
    push_u16(&mut out, 0x0001);
    push_u16(&mut out, header_size as u16);
    push_u32(&mut out, 0); // patched below
    push_u32(&mut out, strings.len() as u32);
    push_u32(&mut out, styled_upto as u32);
    push_u32(&mut out, if utf8 { 0x0000_0100 } else { 0 });
    let strings_start = header_size + 4 * strings.len() + 4 * styled_upto;
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

fn resource_map(ids: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 0x0180);
    push_u16(&mut out, 8);
    push_u32(&mut out, (8 + 4 * ids.len()) as u32);
    for id in ids {
        push_u32(&mut out, *id);
    }
    out
}

/// Node chunk header: type, header size (16), size, line, comment.
fn node_header(out: &mut Vec<u8>, typ: u16, comment: u32) -> usize {
    push_u16(out, typ);
    push_u16(out, 16);
    let size_pos = out.len();
    push_u32(out, 0); // patched by finish_node
    push_u32(out, 7); // line number
    push_u32(out, comment);
    size_pos
}

fn finish_node(out: &mut [u8], size_pos: usize) {
    let size = out.len() - size_pos + 4;
    out[size_pos..size_pos + 4].copy_from_slice(&(size as u32).to_le_bytes());
}

fn start_element(
    out: &mut Vec<u8>,
    ns: u32,
    name: u32,
    comment: u32,
    attributes: &[(u32, u32, u32, u8, u32)],
) {
    let size_pos = node_header(out, 0x0102, comment);
    push_u32(out, ns);
    push_u32(out, name);
    push_u16(out, 20); // attribute start
    push_u16(out, 20); // attribute size
    push_u16(out, attributes.len() as u16);
    push_u16(out, 0); // id index
    push_u16(out, 0); // class index
    push_u16(out, 0); // style index
    for &(ns, name, raw, ty, data) in attributes {
        push_u32(out, ns);
        push_u32(out, name);
        push_u32(out, raw);
        push_u16(out, 8);
        out.push(0);
        out.push(ty);
        push_u32(out, data);
    }
    finish_node(out, size_pos);
}

fn end_element(out: &mut Vec<u8>, ns: u32, name: u32) {
    let size_pos = node_header(out, 0x0103, NONE);
    push_u32(out, ns);
    push_u32(out, name);
    finish_node(out, size_pos);
}

fn cdata_node(out: &mut Vec<u8>, data: u32, ty: u8, value: u32) {
    let size_pos = node_header(out, 0x0104, NONE);
    push_u32(out, data);
    push_u16(out, 8);
    out.push(0);
    out.push(ty);
    push_u32(out, value);
    finish_node(out, size_pos);
}

fn namespace(out: &mut Vec<u8>, start: bool, prefix: u32, uri: u32) {
    let size_pos = node_header(out, if start { 0x0100 } else { 0x0101 }, NONE);
    push_u32(out, prefix);
    push_u32(out, uri);
    finish_node(out, size_pos);
}

fn document(pool: Vec<u8>, map: Vec<u8>, nodes: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 0x0003);
    push_u16(&mut out, 8);
    let size_pos = out.len();
    push_u32(&mut out, 0);
    out.extend_from_slice(&pool);
    out.extend_from_slice(&map);
    out.extend_from_slice(&nodes);
    let size = out.len();
    out[size_pos..size_pos + 4].copy_from_slice(&(size as u32).to_le_bytes());
    out
}

/// The resource id whose framework name is `name`, straight from the table.
fn resource_id_of(name: &str) -> u32 {
    (0x0101_0000..0x0102_0000)
        .find(|&id| crate::xml::attribute_name_for_resource(id) == Some(name))
        .unwrap_or_else(|| panic!("{name} missing from the resource table"))
}

fn basic_document() -> Vec<u8> {
    let strings = [
        "manifest",
        ANDROID,
        "android",
        "package",
        "com.example",
        "application",
        "label",
        "Example & <app>",
        "a ]]> b",
        "note",
        "", // empty name at index 10, resolved through the resource map
    ];
    let pool = string_pool(true, &strings, &[]);
    let version_code = resource_id_of("versionCode");
    let map = resource_map(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, version_code,
    ]);
    let android = 2u32;
    let mut nodes = Vec::new();
    namespace(&mut nodes, true, android, 1);
    start_element(
        &mut nodes,
        NONE,
        0,
        NONE,
        &[(NONE, 3, 4, 0x03, 4), (android, 10, NONE, 0x10, 42)],
    );
    start_element(&mut nodes, NONE, 5, 9, &[(android, 6, 7, 0x03, 7)]);
    cdata_node(&mut nodes, 8, 0x03, 8);
    end_element(&mut nodes, NONE, 5);
    end_element(&mut nodes, NONE, 0);
    namespace(&mut nodes, false, android, 1);
    document(pool, map, nodes)
}

#[test]
fn reads_back_the_ordered_tree() {
    let doc = crate::parse_document(&basic_document(), &limits()).unwrap();
    let root = &doc.root;
    assert_eq!(root.name, "manifest");
    assert_eq!(root.line_number, 7);
    assert_eq!(root.comment, None);
    assert_eq!(root.attributes.len(), 2);
    assert_eq!(root.attributes[0].name, "package");
    assert_eq!(root.attributes[0].value.type_byte, 0x03);
    assert_eq!(root.attributes[0].value.data, 4);
    assert_eq!(root.attributes[0].raw_value.as_deref(), Some("com.example"));
    // The empty name string at index 10 resolves through the resource map.
    assert_eq!(root.attributes[1].name, "versionCode");
    assert_eq!(root.attributes[1].value.type_byte, 0x10);
    assert_eq!(root.attributes[1].value.data, 42);
    let application = match &root.children[0] {
        crate::Node::Element(element) => element,
        crate::Node::Cdata(_) => panic!("expected an element"),
    };
    assert_eq!(application.name, "application");
    assert_eq!(application.comment.as_deref(), Some("note"));
    assert_eq!(application.attributes[0].name, "label");
    assert_eq!(
        application.attributes[0].raw_value.as_deref(),
        Some("Example & <app>")
    );
    match &application.children[0] {
        crate::Node::Cdata(cdata) => {
            assert_eq!(cdata.data, "a ]]> b");
            assert_eq!(cdata.value.type_byte, 0x03);
        }
        crate::Node::Element(_) => panic!("expected cdata"),
    }
    // The start namespace attached to the root element.
    assert_eq!(root.namespace_events.len(), 1);
    assert!(matches!(
        &root.namespace_events[0],
        crate::NamespaceEvent::Start { prefix, uri }
            if prefix == "android" && uri == ANDROID
    ));
    // The matching end namespace after the root survives in the epilog.
    assert_eq!(doc.epilog_namespaces.len(), 1);
    assert!(matches!(
        &doc.epilog_namespaces[0],
        crate::NamespaceEvent::End { prefix, uri }
            if prefix == "android" && uri == ANDROID
    ));
}

#[test]
fn extended_lengths_decode_in_both_pool_encodings() {
    // A 200-byte UTF-8 string needs the two-byte byte-length form; a
    // 40000-unit UTF-16 string needs the extended UTF-16 length form.
    let long_utf8 = "y".repeat(200);
    let long_utf16 = "z".repeat(40_000);
    let pool = string_pool(true, &[&long_utf8], &[]);
    let mut nodes = Vec::new();
    start_element(&mut nodes, NONE, 0, NONE, &[]);
    end_element(&mut nodes, NONE, 0);
    let doc = crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap();
    assert_eq!(doc.string_pool.strings[0], long_utf8);

    let pool = string_pool(false, &[&long_utf16], &[]);
    let mut nodes = Vec::new();
    start_element(&mut nodes, NONE, 0, NONE, &[]);
    end_element(&mut nodes, NONE, 0);
    let doc = crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap();
    assert_eq!(doc.string_pool.strings[0], long_utf16);
    assert_eq!(doc.string_pool.strings[0].len(), 40_000);
}

#[test]
fn style_spans_survive_as_metadata() {
    // String 1 carries two spans; string 0 has an empty style entry.
    let strings = ["plain", "styled text"];
    let spans = [[0u32, 0, 6], [0, 7, 11]];
    let pool = string_pool(false, &strings, &[(1, &spans)]);
    let mut nodes = Vec::new();
    start_element(&mut nodes, NONE, 0, NONE, &[]);
    end_element(&mut nodes, NONE, 0);
    let doc = crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap();
    assert_eq!(doc.string_pool.styles.len(), 1);
    let (index, spans) = &doc.string_pool.styles[0];
    assert_eq!(*index, 1);
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0].first_char, 0);
    assert_eq!(spans[0].last_char, 6);
    assert_eq!(spans[1].name, 0);
}

#[test]
fn prefix_shadowing_attends_to_scopes() {
    // Root binds android->URI(A); an inner element rebinds android->URI(B)
    // and closes the rebinding before the root's own binding ends.
    let strings = ["root", "android", "http://a", "http://b", "child"];
    let pool = string_pool(true, &strings, &[]);
    let mut nodes = Vec::new();
    namespace(&mut nodes, true, 1, 2);
    start_element(&mut nodes, NONE, 0, NONE, &[]);
    namespace(&mut nodes, true, 1, 3);
    start_element(&mut nodes, NONE, 4, NONE, &[]);
    end_element(&mut nodes, NONE, 4);
    namespace(&mut nodes, false, 1, 3);
    end_element(&mut nodes, NONE, 0);
    namespace(&mut nodes, false, 1, 2);
    let doc = crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap();
    let child = match &doc.root.children[0] {
        crate::Node::Element(child) => child,
        crate::Node::Cdata(_) => panic!("expected an element"),
    };
    // The shadowing start attached to the inner element.
    assert_eq!(child.namespace_events.len(), 1);
    assert!(matches!(
        &child.namespace_events[0],
        crate::NamespaceEvent::Start { prefix, uri }
            if prefix == "android" && uri == "http://b"
    ));
    // The root's own binding outlives the subtree and ends in the epilog.
    assert_eq!(doc.epilog_namespaces.len(), 1);
    assert!(matches!(
        &doc.epilog_namespaces[0],
        crate::NamespaceEvent::End { prefix, uri }
            if prefix == "android" && uri == "http://a"
    ));
}

#[test]
fn a_second_root_is_rejected() {
    let pool = string_pool(true, &["root"], &[]);
    let mut nodes = Vec::new();
    start_element(&mut nodes, NONE, 0, NONE, &[]);
    end_element(&mut nodes, NONE, 0);
    start_element(&mut nodes, NONE, 0, NONE, &[]);
    end_element(&mut nodes, NONE, 0);
    let error =
        crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap_err();
    assert!(error.to_string().contains("second root"), "{error}");
}

#[test]
fn structural_garbage_after_the_root_is_rejected() {
    // The document declares more bytes than it has: not consumed silently.
    let mut data = basic_document();
    let declared = u32_of(&data, 4) as usize;
    data.truncate(declared - 10);
    let error = crate::parse_document(&data, &limits()).unwrap_err();
    assert!(error.to_string().contains("declares"), "{error}");

    // Trailing bytes after the declared document end are equally refused.
    let mut padded = basic_document();
    padded.extend_from_slice(&[0, 0, 0, 0]);
    let error = crate::parse_document(&padded, &limits()).unwrap_err();
    assert!(error.to_string().contains("bytes but the input"), "{error}");
}

#[test]
fn an_unmatched_end_element_is_rejected() {
    let pool = string_pool(true, &["root", "other"], &[]);
    let mut nodes = Vec::new();
    start_element(&mut nodes, NONE, 0, NONE, &[]);
    end_element(&mut nodes, NONE, 1);
    let error =
        crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap_err();
    assert!(
        error.to_string().contains("does not match the open start element"),
        "{error}"
    );
}

#[test]
fn an_unmatched_end_namespace_is_rejected() {
    let pool = string_pool(true, &["root", "android", "http://a", "http://b"], &[]);
    let mut nodes = Vec::new();
    namespace(&mut nodes, true, 1, 2);
    start_element(&mut nodes, NONE, 0, NONE, &[]);
    end_element(&mut nodes, NONE, 0);
    namespace(&mut nodes, false, 1, 3);
    let error =
        crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap_err();
    assert!(error.to_string().contains("does not match the innermost"), "{error}");
}

#[test]
fn duplicate_attributes_are_rejected() {
    let pool = string_pool(true, &["root", "name"], &[]);
    let mut nodes = Vec::new();
    start_element(
        &mut nodes,
        NONE,
        0,
        NONE,
        &[(NONE, 1, NONE, 0x03, 1), (NONE, 1, NONE, 0x03, 2)],
    );
    end_element(&mut nodes, NONE, 0);
    let error =
        crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap_err();
    assert!(error.to_string().contains("duplicate attribute"), "{error}");
}

#[test]
fn cdata_outside_any_element_is_rejected() {
    let pool = string_pool(true, &["text"], &[]);
    let mut nodes = Vec::new();
    cdata_node(&mut nodes, 0, 0x03, 0);
    let error =
        crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap_err();
    assert!(error.to_string().contains("outside any element"), "{error}");
}

#[test]
fn a_document_without_a_root_is_rejected() {
    let pool = string_pool(true, &["root"], &[]);
    let error =
        crate::parse_document(&document(pool, resource_map(&[]), Vec::new()), &limits()).unwrap_err();
    assert!(error.to_string().contains("no root element"), "{error}");
}

#[test]
fn string_indices_outside_the_pool_are_rejected() {
    let pool = string_pool(true, &["root"], &[]);
    let mut nodes = Vec::new();
    start_element(&mut nodes, NONE, 9, NONE, &[]);
    end_element(&mut nodes, NONE, 9);
    let error =
        crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap_err();
    assert!(error.to_string().contains("outside the pool"), "{error}");
}

#[test]
fn unknown_node_chunk_types_are_rejected() {
    let pool = string_pool(true, &["root"], &[]);
    let mut nodes = Vec::new();
    let size_pos = node_header(&mut nodes, 0x0105, NONE);
    push_u32(&mut nodes, 0);
    finish_node(&mut nodes, size_pos);
    let error =
        crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap_err();
    assert!(error.to_string().contains("unknown node chunk type"), "{error}");
}

#[test]
fn limits_are_enforced() {
    let mut deep = Vec::new();
    for name in 0u32..3 {
        start_element(&mut deep, NONE, name, NONE, &[]);
    }
    for name in (0u32..3).rev() {
        end_element(&mut deep, NONE, name);
    }
    let deep_doc = document(string_pool(true, &["a", "b", "c"], &[]), resource_map(&[]), deep);

    let error = crate::parse_document(
        &deep_doc,
        &DecodeLimits { max_depth: 2, ..limits() },
    )
    .unwrap_err();
    assert!(error.to_string().contains("depth limit"), "{error}");
    assert!(crate::parse_document(
        &deep_doc,
        &DecodeLimits { max_depth: 3, ..limits() }
    )
    .is_ok());

    let error = crate::parse_document(
        &deep_doc,
        &DecodeLimits { max_nodes: 2, ..limits() },
    )
    .unwrap_err();
    assert!(error.to_string().contains("node limit"), "{error}");

    let mut wide = Vec::new();
    let attributes: Vec<(u32, u32, u32, u8, u32)> =
        (0..4u32).map(|i| (NONE, i, NONE, 0x03, i)).collect();
    start_element(&mut wide, NONE, 0, NONE, &attributes);
    end_element(&mut wide, NONE, 0);
    let wide_doc = document(string_pool(true, &["a", "b", "c", "d"], &[]), resource_map(&[]), wide);
    let error = crate::parse_document(
        &wide_doc,
        &DecodeLimits { max_attributes: 3, ..limits() },
    )
    .unwrap_err();
    assert!(error.to_string().contains("attribute limit"), "{error}");

    let mut long = Vec::new();
    let long_string = "l".repeat(300);
    let attributes = [(NONE, 0, NONE, 0x03, 0)];
    start_element(&mut long, NONE, 0, NONE, &attributes);
    end_element(&mut long, NONE, 0);
    let long_doc = document(
        string_pool(true, &[&long_string], &[]),
        resource_map(&[]),
        long,
    );
    let error = crate::parse_document(
        &long_doc,
        &DecodeLimits { max_string_units: 200, ..limits() },
    )
    .unwrap_err();
    assert!(error.to_string().contains("UTF-16 units"), "{error}");
}

#[test]
fn unknown_raw_type_bytes_survive() {
    // 0x07 (dynamic reference) and 0x33 are not named types; the raw pair is
    // the fact (AX-P03).
    let pool = string_pool(true, &["a", "b"], &[]);
    let mut nodes = Vec::new();
    start_element(
        &mut nodes,
        NONE,
        0,
        NONE,
        &[(NONE, 1, NONE, 0x07, 0x7F00_0001), (NONE, 0, NONE, 0x33, 9)],
    );
    end_element(&mut nodes, NONE, 0);
    let doc = crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap();
    assert_eq!(doc.root.attributes[0].name, "b");
    assert_eq!(doc.root.attributes[0].value.type_byte, 0x07);
    assert_eq!(doc.root.attributes[0].value.data, 0x7F00_0001);
    assert_eq!(doc.root.attributes[1].value.type_byte, 0x33);
    assert_eq!(doc.root.attributes[1].value.data, 9);
}

#[test]
fn element_namespaces_resolve_through_the_pool() {
    let pool = string_pool(true, &["http://ns", "child"], &[]);
    let mut nodes = Vec::new();
    start_element(&mut nodes, 0, 1, NONE, &[]);
    end_element(&mut nodes, 0, 1);
    let doc = crate::parse_document(&document(pool, resource_map(&[]), nodes), &limits()).unwrap();
    assert_eq!(doc.root.namespace.as_deref(), Some("http://ns"));
    assert_eq!(doc.root.name, "child");
}

#[test]
fn parses_without_a_resource_map() {
    // The resource map chunk is optional in AOSP; a document without one must
    // still decode when no attribute needs a resource-name lookup.
    let pool = string_pool(true, &["root", "name"], &[]);
    let mut nodes = Vec::new();
    start_element(&mut nodes, NONE, 0, NONE, &[(NONE, 1, NONE, 0x03, 0)]);
    end_element(&mut nodes, NONE, 0);
    let doc = crate::parse_document(&document(pool, Vec::new(), nodes), &limits()).unwrap();
    assert_eq!(doc.root.attributes[0].name, "name");
    assert!(doc.resource_map.is_empty());
}

#[test]
fn mutation_smoke_never_panics() {
    // Deterministic pseudo-random byte flips over a valid document: every
    // mutated input must come back as Ok or Err, never as a panic.
    let original = basic_document();
    let mut state: u64 = 0x1234_5678_9abc_def0;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..2_000 {
        let mut data = original.clone();
        let flips = 1 + (next() % 3) as usize;
        for _ in 0..flips {
            let at = (next() as usize) % data.len();
            data[at] ^= (next() % 255 + 1) as u8;
        }
        let outcome = crate::parse_document(&data, &limits());
        assert!(
            outcome.is_ok() || outcome.is_err(),
            "mutation must return, not panic"
        );
    }
}
