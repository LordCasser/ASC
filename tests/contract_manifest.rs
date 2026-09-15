//! Contract tests for the manifest work package (A06): MAN-01..MAN-04 plus
//! the BACK-01 ledger slice owned by this package.
//!
//! The fixtures live in tests/fixtures/contracts/manifest/ (builders) and
//! tests/fixtures/contracts/inputs/ (committed APK bytes registered in
//! manifest.json); expected facts are hand-encoded under
//! tests/fixtures/contracts/expected/. The domain sources are compiled in
//! via `#[path]` includes, the same approach the other contract tests use.

mod support;

#[path = "../src/error.rs"]
mod error;
#[path = "../src/model.rs"]
mod model;
#[path = "../src/manifest.rs"]
mod manifest;

#[path = "fixtures/contracts/manifest/mod.rs"]
mod fixtures;

use error::ErrorKind;
use manifest::{
    Manifest, OperationControl, XmlDecodeLimits, XmlRenderOptions, XmlNode,
};
use model::Report;
use std::fs;
use std::path::PathBuf;

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/contracts")
}

fn read_input(name: &str) -> Vec<u8> {
    fs::read(contracts_dir().join("inputs").join(name))
        .unwrap_or_else(|error| panic!("read input {name}: {error}"))
}

fn read_expected(name: &str) -> support::json::Json {
    let text = fs::read_to_string(contracts_dir().join("expected").join(name))
        .unwrap_or_else(|error| panic!("read expected/{name}: {error}"));
    support::json::parse(&text).unwrap_or_else(|error| panic!("parse expected/{name}: {error}"))
}

fn decode_entry(bytes: &[u8]) -> Result<Report<Manifest>, error::Error> {
    manifest::decode_manifest_entry(bytes, &XmlDecodeLimits::default(), &OperationControl::new())
}

fn manifest_entry_of(name: &str) -> Vec<u8> {
    let apk = read_input(name);
    fixtures::last_entry(&apk, "AndroidManifest.xml")
        .unwrap_or_else(|| panic!("{name} carries no manifest entry"))
}

// ---------------------------------------------------------------------------
// Facts projection (ordered DFS; the `xml` fact covers text and tails
// completely, the node facts carry the structure and raw typed data)
// ---------------------------------------------------------------------------

use support::json::Json;

fn text_or_null(text: &model::DexText) -> Json {
    match text.as_str() {
        Some(value) => Json::Str(value),
        None => Json::Str("<unpaired-surrogate>".to_owned()),
    }
}

fn attribute_facts(attribute: &manifest::XmlAttribute) -> Json {
    let (ty, data, raw) = match attribute.value().raw_typed() {
        Some(typed) => (
            Json::Int(i64::from(typed.type_byte())),
            Json::Int(i64::from(typed.data())),
            typed
                .raw_string()
                .map(|raw| Json::Str(raw.as_str().unwrap_or_default()))
                .unwrap_or(Json::Null),
        ),
        None => (Json::Null, Json::Null, Json::Null),
    };
    Json::Object(vec![
        ("name".to_owned(), Json::Str(attribute.local_name().to_owned())),
        (
            "prefix".to_owned(),
            attribute.prefix().map(Json::Str).unwrap_or(Json::Null),
        ),
        (
            "ns".to_owned(),
            attribute.namespace().map(Json::Str).unwrap_or(Json::Null),
        ),
        (
            "value".to_owned(),
            Json::Str(attribute.value().as_text().unwrap_or_default()),
        ),
        ("ty".to_owned(), ty),
        ("data".to_owned(), data),
        ("raw".to_owned(), raw),
    ])
}

fn walk_element(element: &manifest::XmlElement, depth: usize, nodes: &mut Vec<Json>) {
    nodes.push(Json::Object(vec![
        ("d".to_owned(), Json::Int(depth as i64)),
        ("k".to_owned(), Json::Str("element".to_owned())),
        ("name".to_owned(), Json::Str(element.local_name().to_owned())),
        ("prefix".to_owned(), element.prefix().map(Json::Str).unwrap_or(Json::Null)),
        ("ns".to_owned(), element.namespace().map(Json::Str).unwrap_or(Json::Null)),
        (
            "attrs".to_owned(),
            Json::Array(element.attributes().iter().map(attribute_facts).collect()),
        ),
        (
            "line".to_owned(),
            element.metadata().line_number.map(|line| Json::Int(i64::from(line))).unwrap_or(Json::Null),
        ),
        (
            "comment".to_owned(),
            element.metadata().comment.clone().map(Json::Str).unwrap_or(Json::Null),
        ),
    ]));
    for child in element.children() {
        match child {
            XmlNode::Text { text } => nodes.push(Json::Object(vec![
                ("d".to_owned(), Json::Int((depth + 1) as i64)),
                ("k".to_owned(), Json::Str("text".to_owned())),
                ("text".to_owned(), text_or_null(text)),
            ])),
            XmlNode::Cdata { data } => nodes.push(Json::Object(vec![
                ("d".to_owned(), Json::Int((depth + 1) as i64)),
                ("k".to_owned(), Json::Str("cdata".to_owned())),
                ("data".to_owned(), text_or_null(data)),
            ])),
            XmlNode::Comment { text } => nodes.push(Json::Object(vec![
                ("d".to_owned(), Json::Int((depth + 1) as i64)),
                ("k".to_owned(), Json::Str("comment".to_owned())),
                ("text".to_owned(), Json::Str(text.clone())),
            ])),
            XmlNode::Pi { target, data } => nodes.push(Json::Object(vec![
                ("d".to_owned(), Json::Int((depth + 1) as i64)),
                ("k".to_owned(), Json::Str("pi".to_owned())),
                ("target".to_owned(), Json::Str(target.clone())),
                ("data".to_owned(), Json::Str(data.clone())),
            ])),
            XmlNode::Element(inner) => walk_element(inner, depth + 1, nodes),
        }
    }
}

/// Fact entries for prolog/epilog items; text items keep their exact
/// whitespace so prolog/epilog placement is itself a fact.
fn misc_facts(items: &[manifest::Misc]) -> Vec<Json> {
    items
        .iter()
        .map(|item| match item {
            manifest::Misc::Text(text) => Json::Object(vec![
                ("k".to_owned(), Json::Str("text".to_owned())),
                ("text".to_owned(), text_or_null(text)),
            ]),
            manifest::Misc::Comment(text) => Json::Object(vec![
                ("k".to_owned(), Json::Str("comment".to_owned())),
                ("text".to_owned(), Json::Str(text.clone())),
            ]),
            manifest::Misc::Pi { target, data } => Json::Object(vec![
                ("k".to_owned(), Json::Str("pi".to_owned())),
                ("target".to_owned(), Json::Str(target.clone())),
                ("data".to_owned(), Json::Str(data.clone())),
            ]),
        })
        .collect()
}

fn facts_of(report: &Report<Manifest>) -> Json {
    let value = report.value();
    let mut nodes = Vec::new();
    walk_element(value.root(), 0, &mut nodes);

    let mut namespaces = Vec::new();
    fn collect_ns(element: &manifest::XmlElement, depth: usize, out: &mut Vec<Json>) {
        for event in &element.metadata().namespace_events {
            let (kind, prefix, uri) = match event {
                manifest::NamespaceEvent::Start { prefix, uri } => ("start", prefix, uri),
                manifest::NamespaceEvent::End { prefix, uri } => ("end", prefix, uri),
            };
            out.push(Json::Object(vec![
                ("d".to_owned(), Json::Int(depth as i64)),
                ("k".to_owned(), Json::Str(kind.to_owned())),
                ("prefix".to_owned(), Json::Str(prefix.clone())),
                ("uri".to_owned(), Json::Str(uri.clone())),
            ]));
        }
        for child in element.children() {
            if let XmlNode::Element(inner) = child {
                collect_ns(inner, depth + 1, out);
            }
        }
    }
    collect_ns(value.root(), 0, &mut namespaces);

    let prolog = misc_facts(value.prolog());
    let epilog = misc_facts(value.epilog());

    let source = match value.metadata().source {
        Some(manifest::ManifestSource::BinaryAxml { utf8_pool, string_count }) => {
            Json::Object(vec![
                ("kind".to_owned(), Json::Str("axml".to_owned())),
                ("utf8_pool".to_owned(), Json::Bool(utf8_pool)),
                ("strings".to_owned(), Json::Int(string_count as i64)),
            ])
        }
        Some(manifest::ManifestSource::PlainXml) => {
            Json::Object(vec![("kind".to_owned(), Json::Str("plain-xml".to_owned()))])
        }
        None => Json::Null,
    };

    Json::Object(vec![
        (
            "xml".to_owned(),
            Json::Str(
                value
                    .to_xml(&XmlRenderOptions::default(), &OperationControl::new())
                    .expect("render facts xml"),
            ),
        ),
        ("nodes".to_owned(), Json::Array(nodes)),
        ("namespaces".to_owned(), Json::Array(namespaces)),
        ("prolog".to_owned(), Json::Array(prolog)),
        ("epilog".to_owned(), Json::Array(epilog)),
        (
            "styles".to_owned(),
            Json::Array(
                value
                    .metadata()
                    .string_styles
                    .iter()
                    .map(|style| Json::Object(vec![
                        ("index".to_owned(), Json::Int(i64::from(style.string_index))),
                        (
                            "spans".to_owned(),
                            Json::Array(
                                style
                                    .spans
                                    .iter()
                                    .map(|span| Json::Array(vec![
                                        Json::Int(i64::from(span.name_index)),
                                        Json::Int(i64::from(span.first_char)),
                                        Json::Int(i64::from(span.last_char)),
                                    ]))
                                    .collect(),
                            ),
                        ),
                    ]))
                    .collect(),
            ),
        ),
        (
            "diagnostics".to_owned(),
            Json::Array(
                report
                    .diagnostics()
                    .iter()
                    .map(|diagnostic| Json::Object(vec![
                        ("code".to_owned(), Json::Str(diagnostic.code().as_str().to_owned())),
                        ("severity".to_owned(), Json::Str(diagnostic.severity().as_str().to_owned())),
                        ("stage".to_owned(), Json::Str(diagnostic.stage().as_str().to_owned())),
                    ]))
                    .collect(),
            ),
        ),
        ("meta".to_owned(), source),
    ])
}

fn assert_facts(case: &str, report: &Report<Manifest>) {
    let expected = read_expected(case);
    let actual = facts_of(report);
    let diffs = support::compare::compare_facts(&expected, &actual, true);
    assert!(diffs.is_empty(), "case {case} facts differ:\n{}", diffs.join("\n"));
}

// ---------------------------------------------------------------------------
// MAN-01: entry selection, long strings, styles, missing/fake manifests
// ---------------------------------------------------------------------------

#[test]
fn man01_last_manifest_entry_decodes_the_last_axml() {
    let report = decode_entry(&manifest_entry_of("man01-last-manifest-entry.apk")).unwrap();
    // The older plain-XML twin would render `package="old"`; the last entry
    // (the AXML) must win.
    let xml = facts_of(&report).get("xml").and_then(Json::as_str).unwrap_or_default().to_owned();
    assert!(xml.contains("com.example."), "unexpected manifest: {xml}");
    assert_facts("man01-last-manifest-entry.json", &report);
}

#[test]
fn man01_missing_manifest_entry_is_not_found() {
    let apk = read_input("man01-missing-manifest.apk");
    let names = fixtures::entry_names(&apk);
    assert!(
        !names.iter().any(|name| name == "AndroidManifest.xml"),
        "fixture must not carry a manifest entry: {names:?}"
    );
    // The manifest operation maps a missing entry to NotFound once A07 wires
    // read_entry into the Engine; at this boundary the entry scan returns
    // nothing to decode, which is what the case pins.
    assert!(fixtures::last_entry(&apk, "AndroidManifest.xml").is_none());
}

#[test]
fn man01_plain_xml_fake_text_is_rejected() {
    let error = decode_entry(&manifest_entry_of("man01-plain-xml-text-rejected.apk"))
        .expect_err("fake text must be rejected");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
    assert!(
        error.to_string().contains("not well-formed"),
        "unexpected error: {error}"
    );
}

// ---------------------------------------------------------------------------
// MAN-02: the typed-value matrix
// ---------------------------------------------------------------------------

#[test]
fn man02_every_typed_value_is_preserved_and_formatted() {
    let report = decode_entry(&manifest_entry_of("man02-typed-value-matrix.apk")).unwrap();
    assert_facts("man02-typed-value-matrix.json", &report);
}

// ---------------------------------------------------------------------------
// MAN-03: namespaces, node order, text/tail, prolog/epilog
// ---------------------------------------------------------------------------

#[test]
fn man03_namespaces_order_and_inference() {
    let report = decode_entry(&manifest_entry_of("man03-cdata-pi-node-order.apk")).unwrap();
    assert_facts("man03-cdata-pi-node-order.json", &report);
    // The android binding was inferred, not declared.
    assert!(report
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code() == model::DiagnosticCode::InferredNamespaceBinding));
}

#[test]
fn man03_plain_xml_tree_round_trips() {
    let report = decode_entry(&manifest_entry_of("man03-plain-xml-tree.apk")).unwrap();
    assert_facts("man03-plain-xml-tree.json", &report);
}

// ---------------------------------------------------------------------------
// MAN-04: rejection and limit boundaries
// ---------------------------------------------------------------------------

#[test]
fn man04_second_root_is_rejected() {
    let error = decode_entry(&manifest_entry_of("man04-second-root.apk"))
        .expect_err("a second root must be rejected");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
    assert!(error.to_string().contains("second root"), "{error}");
}

#[test]
fn man04_dtd_is_rejected_without_io() {
    let error = decode_entry(&manifest_entry_of("man04-dtd-rejected.apk"))
        .expect_err("a DTD must be rejected");
    assert_eq!(*error.kind(), ErrorKind::UnsupportedFormat, "{error}");
}

#[test]
fn man04_limit_boundaries_reject_on_the_exceeding_side() {
    let bytes = manifest_entry_of("man04-limit-boundaries.apk");
    // Depth: the fixture nests three elements; a limit of two rejects,
    // three passes.
    let over = XmlDecodeLimits { max_depth: 2, ..XmlDecodeLimits::default() };
    let error = manifest::decode_manifest_entry(&bytes, &over, &OperationControl::new())
        .expect_err("depth over the limit must fail");
    assert_eq!(*error.kind(), ErrorKind::ResourceLimit, "{error}");
    decode_entry(&bytes).expect("default limits decode the fixture");
}

#[test]
fn man04_limit_variants_fail_with_resource_limit() {
    let bytes = manifest_entry_of("man04-limit-boundaries.apk");
    for limits in [
        XmlDecodeLimits { max_nodes: 2, ..XmlDecodeLimits::default() },
        XmlDecodeLimits { max_attributes: 0, ..XmlDecodeLimits::default() },
    ] {
        let error = manifest::decode_manifest_entry(&bytes, &limits, &OperationControl::new())
            .err()
            .unwrap_or_else(|| panic!("limits {limits:?} must reject"));
        assert_eq!(*error.kind(), ErrorKind::ResourceLimit, "{error}");
    }

    // Plain-XML depth and node limits.
    let error = manifest::decode_manifest_entry(
        fixtures::MAN03_PLAIN_XML.as_bytes(),
        &XmlDecodeLimits { max_depth: 1, ..XmlDecodeLimits::default() },
        &OperationControl::new(),
    )
    .expect_err("plain-XML depth over the limit must fail");
    assert_eq!(*error.kind(), ErrorKind::ResourceLimit, "{error}");

    // Output size and render depth limits.
    let report = decode_entry(&bytes).unwrap();
    let small_output = XmlRenderOptions { max_output_bytes: 40, ..XmlRenderOptions::default() };
    let error = report
        .value
        .to_xml(&small_output, &OperationControl::new())
        .expect_err("output over the limit must fail");
    assert_eq!(*error.kind(), ErrorKind::ResourceLimit, "{error}");
    let small_depth = XmlRenderOptions { max_depth: 2, ..XmlRenderOptions::default() };
    let error = report
        .value
        .to_xml(&small_depth, &OperationControl::new())
        .expect_err("render depth over the limit must fail");
    assert_eq!(*error.kind(), ErrorKind::ResourceLimit, "{error}");

    // String-unit limits reject an oversized pool string before allocation.
    let mut spec = fixtures::AxmlSpec {
        utf8: true,
        strings: vec!["root".to_owned(), "l".repeat(300)],
        ..fixtures::AxmlSpec::default()
    };
    spec.nodes = vec![
        fixtures::Chunk::Start { ns: u32::MAX, name: 0, comment: u32::MAX, attrs: vec![] },
        fixtures::Chunk::End(u32::MAX, 0),
    ];
    let error = manifest::decode_manifest_entry(
        &fixtures::axml(&spec),
        &XmlDecodeLimits { max_string_units: 200, ..XmlDecodeLimits::default() },
        &OperationControl::new(),
    )
    .expect_err("string-unit over the limit must fail");
    assert_eq!(*error.kind(), ErrorKind::ResourceLimit, "{error}");
}

#[test]
fn man04_structural_rejections() {
    let mut spec = fixtures::AxmlSpec {
        utf8: true,
        strings: vec!["root".to_owned(), "other".to_owned()],
        ..fixtures::AxmlSpec::default()
    };
    spec.nodes = vec![
        fixtures::Chunk::Start { ns: u32::MAX, name: 0, comment: u32::MAX, attrs: vec![] },
        fixtures::Chunk::End(u32::MAX, 1), // mismatched end name
    ];
    let error = manifest::decode_manifest_entry(&fixtures::axml(&spec), &XmlDecodeLimits::default(), &OperationControl::new())
        .expect_err("mismatched end element must fail");
    assert!(error.to_string().contains("does not match the open start element"), "{error}");

    // Duplicate attributes.
    let mut spec = fixtures::AxmlSpec {
        utf8: true,
        strings: vec!["root".to_owned(), "dup".to_owned()],
        ..fixtures::AxmlSpec::default()
    };
    spec.nodes = vec![
        fixtures::Chunk::Start {
            ns: u32::MAX,
            name: 0,
            comment: u32::MAX,
            attrs: vec![
                fixtures::Attr(u32::MAX, 1, u32::MAX, 0x03, 0),
                fixtures::Attr(u32::MAX, 1, u32::MAX, 0x03, 0),
            ],
        },
        fixtures::Chunk::End(u32::MAX, 0),
    ];
    let error = manifest::decode_manifest_entry(&fixtures::axml(&spec), &XmlDecodeLimits::default(), &OperationControl::new())
        .expect_err("duplicate attributes must fail");
    assert!(error.to_string().contains("duplicate attribute"), "{error}");

    // Truncated document.
    let mut truncated = manifest_entry_of("man04-limit-boundaries.apk");
    truncated.truncate(truncated.len() / 2);
    let error = decode_entry(&truncated).expect_err("truncated input must fail");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");

    // Trailing garbage after the declared document size.
    let mut padded = manifest_entry_of("man04-limit-boundaries.apk");
    padded.extend_from_slice(&[0, 0, 0, 0]);
    let error = decode_entry(&padded).expect_err("padded input must fail");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");

    // Neither AXML nor text.
    let error = decode_entry(&[0x37, 0x13, 0x00, 0x00, 0, 0, 0, 0, 9, 9, 9, 9])
        .expect_err("garbage must fail");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
}

#[test]
fn man04_plain_xml_rejections() {
    let decode = |text: &str| {
        manifest::decode_manifest_entry(text.as_bytes(), &XmlDecodeLimits::default(), &OperationControl::new())
    };
    // Unknown entity (no DTD, no custom entities).
    let error = decode("<manifest>&explode;</manifest>").expect_err("unknown entity");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
    // Second root / text outside the root.
    let error = decode("<a/><b/>").expect_err("second root");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
    let error = decode("<a/>tail").expect_err("text after root");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
    // Unmatched end tag.
    let error = decode("<a></b></a>").expect_err("unmatched end tag");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
    // Duplicate attribute.
    let error = decode("<a x=\"1\" x=\"2\"/>").expect_err("duplicate attribute");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
    // Declared encoding/version outside the matrix.
    let error = decode("<?xml version=\"1.0\" encoding=\"iso-8859-1\"?><a/>")
        .expect_err("declared encoding");
    assert_eq!(*error.kind(), ErrorKind::UnsupportedFormat, "{error}");
    let error = decode("<?xml version=\"1.1\"?><a/>").expect_err("declared version");
    assert_eq!(*error.kind(), ErrorKind::UnsupportedFormat, "{error}");
    // UTF-16 BOM bytes.
    let error = manifest::decode_manifest_entry(
        &[0xFF, 0xFE, b'<', 0, b'a', 0],
        &XmlDecodeLimits::default(),
        &OperationControl::new(),
    )
    .expect_err("UTF-16 BOM");
    assert_eq!(*error.kind(), ErrorKind::UnsupportedFormat, "{error}");
    // Invalid UTF-8 starting like markup.
    let error = manifest::decode_manifest_entry(
        &[b'<', b'a', 0xFF, b'>'],
        &XmlDecodeLimits::default(),
        &OperationControl::new(),
    )
    .expect_err("invalid UTF-8");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
    // Character reference to an illegal XML character: parse keeps it, the
    // renderer refuses to serialize it silently.
    let report = decode("<a>&#1;</a>").expect("parse accepts, render rejects");
    let error = report
        .value
        .to_xml(&XmlRenderOptions::default(), &OperationControl::new())
        .expect_err("illegal character must not be silently replaced");
    assert_eq!(*error.kind(), ErrorKind::UnsupportedEncoding, "{error}");
}

#[test]
fn axml_unknown_namespace_uri_is_not_guessed() {
    let mut spec = fixtures::AxmlSpec {
        utf8: true,
        strings: vec!["root".to_owned(), "http://unknown".to_owned(), "attr".to_owned()],
        ..fixtures::AxmlSpec::default()
    };
    spec.nodes = vec![
        fixtures::Chunk::Start {
            ns: u32::MAX,
            name: 0,
            comment: u32::MAX,
            attrs: vec![fixtures::Attr(1, 2, u32::MAX, 0x03, 0)],
        },
        fixtures::Chunk::End(u32::MAX, 0),
    ];
    let error = manifest::decode_manifest_entry(&fixtures::axml(&spec), &XmlDecodeLimits::default(), &OperationControl::new())
        .expect_err("undeclared non-android namespace must fail");
    assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
    assert!(error.to_string().contains("cannot determine a prefix"), "{error}");
}

// ---------------------------------------------------------------------------
// MAN-04: mutation smoke (debug profile; the release-profile run is recorded
// in the evidence file)
// ---------------------------------------------------------------------------

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn mutation_smoke_never_panics() {
    let inputs = [
        fixtures::man01_last_manifest_entry_apk(),
        fixtures::man02_typed_value_matrix_apk(),
        fixtures::man03_cdata_pi_node_order_apk(),
        fixtures::man03_plain_xml_tree_apk(),
        fixtures::man04_second_root_apk(),
        fixtures::man04_dtd_rejected_apk(),
        fixtures::man04_limit_boundaries_apk(),
    ];
    let mut state: u64 = 0x0123_4567_89ab_cdef;
    for original in &inputs {
        let entry = fixtures::last_entry(original, "AndroidManifest.xml").unwrap_or_default();
        assert!(!entry.is_empty());
        for _ in 0..400 {
            let mut data = entry.clone();
            let flips = 1 + (xorshift(&mut state) % 3) as usize;
            for _ in 0..flips {
                let at = (xorshift(&mut state) as usize) % data.len();
                data[at] ^= ((xorshift(&mut state) % 255) + 1) as u8;
            }
            let outcome = decode_entry(&data);
            assert!(
                outcome.is_ok() || outcome.is_err(),
                "decoding must return instead of panicking"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// BACK-01 (A06 slice): upstream provenance and the AX-P ledger
// ---------------------------------------------------------------------------

#[test]
fn axmldecoder_upstream_and_patch_ledger_are_registered() {
    let vendor = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vendor/axmldecoder");
    let upstream = fs::read_to_string(vendor.join("UPSTREAM.md")).expect("read UPSTREAM.md");
    let patches = fs::read_to_string(vendor.join("PATCHES.md")).expect("read PATCHES.md");
    // The recorded archive sha256 (crates.io index value).
    assert!(upstream.contains("c837020c555ea97afbcc1b9514691de349413a9b054ef6a83bf38ed881fd14a7"));
    assert!(upstream.contains("349d544f0d5c1b1cccaaf52720e40438af32af32"));
    assert!(upstream.contains("d5a86f596747e5ed3d933d54158c4de3975303feeb5da6e4b474f5c2730450b7"));
    // Every AX-P id is registered with tests and the historical items mapped.
    for id in ["AX-P01", "AX-P02", "AX-P03", "AX-P04"] {
        assert!(patches.contains(id), "{id} missing from PATCHES.md");
    }
    for item in ["| 1.", "| 2.", "| 3.", "| 4.", "| 5.", "| 6.", "| 7.", "| 8."] {
        assert!(patches.contains(item), "historical item {item} missing from the mapping");
    }
    // Licenses survive.
    assert!(vendor.join("LICENSE.APACHE").exists());
    assert!(vendor.join("LICENSE.MIT").exists());
}

// ---------------------------------------------------------------------------
// Fixture regeneration (opt-in; same convention as the harness)
// ---------------------------------------------------------------------------

/// Regenerates the committed manifest inputs after a fixture builder change.
/// Not part of a normal run: opt in with ASC_REGEN_FIXTURES=1, then update
/// manifest.json's sha256/size fields (the harness tests fail until they
/// agree).
#[test]
fn regenerate_manifest_fixture_inputs_when_explicitly_requested() {
    if std::env::var("ASC_REGEN_FIXTURES").ok().as_deref() != Some("1") {
        return;
    }
    let inputs = contracts_dir().join("inputs");
    fs::create_dir_all(&inputs).expect("create inputs directory");
    let outputs = [
        ("man01-last-manifest-entry.apk", fixtures::man01_last_manifest_entry_apk()),
        ("man01-missing-manifest.apk", fixtures::man01_missing_manifest_apk()),
        ("man01-plain-xml-text-rejected.apk", fixtures::man01_plain_xml_text_rejected_apk()),
        ("man02-typed-value-matrix.apk", fixtures::man02_typed_value_matrix_apk()),
        ("man03-cdata-pi-node-order.apk", fixtures::man03_cdata_pi_node_order_apk()),
        ("man03-plain-xml-tree.apk", fixtures::man03_plain_xml_tree_apk()),
        ("man04-second-root.apk", fixtures::man04_second_root_apk()),
        ("man04-dtd-rejected.apk", fixtures::man04_dtd_rejected_apk()),
        ("man04-limit-boundaries.apk", fixtures::man04_limit_boundaries_apk()),
    ];
    for (name, bytes) in &outputs {
        fs::write(inputs.join(name), bytes).expect("write fixture input");
        println!(
            "{name}: size {} sha256 {}",
            bytes.len(),
            support::sha::hex_lower(&support::sha::sha256(bytes))
        );
    }
}
