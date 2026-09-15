//! Contract tests for the A03 structured reference scanner: REF-01..04.
//!
//! The scanner sources are compiled into this test via `#[path]` includes
//! (the same approach tests/contract_query.rs uses), and the fixture
//! builders live under tests/fixtures/contracts/references/. Expected facts
//! under tests/fixtures/contracts/expected/ were hand-derived from the
//! documented fixture layouts, never generated from candidate output.

// The #[path] includes pull in whole modules whose siblings this test does
// not exercise (the support library, the legacy scanner half); the binary
// crate owns their liveness.
#![allow(dead_code)]

mod support;

#[path = "../../../tests/fixtures/contracts/references/mod.rs"]
mod reference_fixtures;

#[path = "../src/bytes.rs"]
mod bytes;
#[path = "../src/error.rs"]
mod error;
#[path = "../src/model.rs"]
mod model;
#[path = "../src/query.rs"]
mod query;
#[path = "../src/zip.rs"]
mod zip;
#[path = "../src/dex/mod.rs"]
mod dex;

use dex::{DexView, ScanLimits, ScanOptions};
use error::{CancelCause, ErrorKind};
use model::{
    ArtifactId, DexEntry, DexId, DexText, DexVersion, PatternLimits, Reference,
    ReferenceQuery as ContractQuery, TargetValue,
};
use query::{ClassSpec, MatchMode, MemberSpec};
use reference_fixtures::MapStyle;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use support::compare::compare_facts;
use support::json::{self, Json};
use support::sha;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn contracts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/contracts")
}

fn input_bytes(name: &str) -> Vec<u8> {
    fs::read(contracts_dir().join("inputs").join(name))
        .unwrap_or_else(|error| panic!("read input {name}: {error}"))
}

fn load_facts(name: &str) -> Json {
    let text = fs::read_to_string(contracts_dir().join("expected").join(name))
        .unwrap_or_else(|error| panic!("read facts {name}: {error}"));
    json::parse(&text).unwrap_or_else(|error| panic!("parse facts {name}: {error}"))
}

fn pattern_limits() -> PatternLimits {
    PatternLimits::default()
}

/// A raw-DEX view of `bytes` named like the interfaces' `<memory.dex>`.
///
/// The artifact id is a harness constant, not a per-input digest: REF-03's
/// map-fallback case compares the scans of two byte-different twins of the
/// same fixture (full map vs header-only map), and an identity derived from
/// the input digest would make those results differ in their artifact bytes
/// alone. Content assertions project ordinals only, so one stable id keeps
/// every cross-input comparison about scan content.
fn memory_view(bytes: &[u8]) -> DexView<'_> {
    let artifact = ArtifactId::from_digest([0x41; 32]);
    let id = DexId::new(artifact, 0, 0);
    let name = DexText::from_str_lossless("<memory.dex>");
    let entry = DexEntry::new(
        id,
        b"<memory.dex>".to_vec(),
        name.clone(),
        name,
        DexVersion::from_magic_tail(&bytes[4..8]).expect("supported version"),
        0,
    );
    DexView::new(entry, bytes)
}

/// A view whose entry is the named archive member (the g01 APK twin).
fn named_view<'a>(bytes: &'a [u8], raw_name: &str) -> DexView<'a> {
    let artifact = ArtifactId::from_digest([0x41; 32]);
    let id = DexId::new(artifact, 0, 0);
    let name = DexText::from_str_lossless(raw_name);
    let entry = DexEntry::new(
        id,
        raw_name.as_bytes().to_vec(),
        name.clone(),
        name,
        DexVersion::from_magic_tail(&bytes[4..8]).expect("supported version"),
        0,
    );
    DexView::new(entry, bytes)
}

fn default_options() -> ScanOptions<'static> {
    ScanOptions { limits: ScanLimits::DEFAULT, control: None, prefilter: true }
}

fn scan(bytes: &[u8], query: &ContractQuery) -> Result<Vec<Reference>, error::Error> {
    let view = memory_view(bytes);
    dex::scan_references(&view, query, &default_options())
}

fn scan_with(
    bytes: &[u8],
    query: &ContractQuery,
    limits: ScanLimits,
    prefilter: bool,
) -> Result<Vec<Reference>, error::Error> {
    let view = memory_view(bytes);
    let options = ScanOptions { limits, control: None, prefilter };
    dex::scan_references(&view, query, &options)
}

// --- JSON helpers -----------------------------------------------------------

fn json_str(text: &str) -> Json {
    Json::Str(text.to_owned())
}

fn json_int(value: i64) -> Json {
    Json::Int(value)
}

fn json_obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Object(pairs.into_iter().map(|(key, value)| (key.to_owned(), value)).collect())
}

fn json_arr(items: Vec<Json>) -> Json {
    Json::Array(items)
}

fn text_json(text: &DexText) -> Json {
    json_str(&text.as_str().expect("pass fixtures keep valid Unicode values"))
}

fn prototype_text(prototype: &model::Prototype) -> String {
    let mut out = String::from("(");
    for parameter in prototype.parameters() {
        out.push_str(&parameter.as_str().expect("valid Unicode descriptor"));
    }
    out.push(')');
    out.push_str(&prototype.return_type().as_str().expect("valid Unicode descriptor"));
    out
}

fn target_value_json(value: &TargetValue) -> Json {
    match value {
        TargetValue::String(text) | TargetValue::Type(text) => text_json(text),
        TargetValue::Field { owner, name, field_type } => json_obj(vec![
            ("owner", text_json(owner)),
            ("name", text_json(name)),
            ("field_type", text_json(field_type)),
        ]),
        TargetValue::Method { owner, name, prototype } => json_obj(vec![
            ("owner", text_json(owner)),
            ("name", text_json(name)),
            ("prototype", json_str(&prototype_text(prototype))),
        ]),
    }
}

/// The A03 facts shape: full numeric identity (dex ordinals, method_idx,
/// table index) so no display string can mask an identity mixup.
fn reference_json_full(reference: &Reference) -> Json {
    let caller = reference.caller();
    json_obj(vec![
        (
            "dex",
            json_str(&format!(
                "{}:{}",
                caller.dex().id().entry_ordinal(),
                caller.dex().id().logical_ordinal()
            )),
        ),
        ("method_idx", json_int(caller.id().method_idx() as i64)),
        ("owner", text_json(caller.owner())),
        ("name", text_json(caller.name())),
        ("prototype", json_str(&prototype_text(caller.prototype()))),
        (
            "targets",
            json_arr(reference.targets().iter().map(|target| {
                json_obj(vec![
                    ("kind", json_str(target.id().kind().as_str())),
                    ("index", json_int(target.id().table_index() as i64)),
                    ("value", target_value_json(target.value())),
                    (
                        "code_unit_offsets",
                        json_arr(
                            target.code_unit_offsets().iter().map(|o| json_int(*o as i64)).collect(),
                        ),
                    ),
                ])
            }).collect()),
        ),
    ])
}

/// The A00 minimal shape used by the g01 facts (values only, no indexes).
fn reference_json_minimal(reference: &Reference) -> Json {
    let caller = reference.caller();
    json_obj(vec![
        (
            "caller",
            json_obj(vec![
                ("owner", text_json(caller.owner())),
                ("name", text_json(caller.name())),
                ("prototype", json_str(&prototype_text(caller.prototype()))),
            ]),
        ),
        (
            "targets",
            json_arr(reference.targets().iter().map(|target| {
                json_obj(vec![
                    ("kind", json_str(target.id().kind().as_str())),
                    ("value", target_value_json(target.value())),
                    (
                        "code_unit_offsets",
                        json_arr(
                            target.code_unit_offsets().iter().map(|o| json_int(*o as i64)).collect(),
                        ),
                    ),
                ])
            }).collect()),
        ),
    ])
}

/// Builds the domain query described by one facts `query` object:
/// string/type use `{kind, mode, pattern}`; members carry the name pattern in
/// `name` (the inline scan cases pass it as `pattern`), optional
/// `class_exact` and `class_fuzzy`, and at least one constraint present.
///
/// `query::member_query`'s first argument selects the *field* table
/// (contract_query.rs freezes that signature), so the kind maps through
/// `kind == "field"`.
fn build_query(spec: &Json) -> ContractQuery {
    let kind = spec.get("kind").and_then(Json::as_str).expect("query kind");
    let mode = match spec.get("mode").and_then(Json::as_str).expect("query mode") {
        "literal" => MatchMode::Literal,
        "regex" => MatchMode::Regex,
        other => panic!("unknown mode {other}"),
    };
    match kind {
        "string" => query::string_query(
            spec.get("pattern").and_then(Json::as_str).expect("pattern"),
            mode,
            &pattern_limits(),
        )
        .expect("string query"),
        "type" => query::type_query(
            spec.get("pattern").and_then(Json::as_str).expect("pattern"),
            mode,
            &pattern_limits(),
        )
        .expect("type query"),
        "field" | "method" => {
            let class = spec
                .get("class_exact")
                .and_then(Json::as_str)
                .map(ClassSpec::Exact)
                .or_else(|| spec.get("class_fuzzy").and_then(Json::as_str).map(ClassSpec::Fuzzy));
            let name = spec
                .get("name")
                .or_else(|| spec.get("pattern"))
                .and_then(Json::as_str);
            let member = MemberSpec { name, mode, class };
            query::member_query(kind == "field", member, &pattern_limits())
                .expect("member query")
        }
        other => panic!("unknown query kind {other}"),
    }
}

/// Runs every query of a facts document against `bytes` and compares the
/// whole projected document against the expected facts. Each facts `queries`
/// entry is `{query, references}`; the scan is driven by the inner `query`
/// object and the projection must reproduce the entry exactly.
fn run_references_case(
    input_name: &str,
    facts_name: &str,
    view_of: impl Fn(&[u8]) -> DexView<'_>,
    reference_json: fn(&Reference) -> Json,
) {
    let bytes = input_bytes(input_name);
    let facts = load_facts(facts_name);
    let mut actual_queries = Vec::new();
    for entry in facts.get("queries").and_then(Json::as_array).expect("queries") {
        let query_spec = entry.get("query").expect("facts entry query object");
        let contract_query = build_query(query_spec);
        let references = dex::scan_references(&view_of(&bytes), &contract_query, &default_options())
            .unwrap_or_else(|error| panic!("{facts_name}: {input_name}: {error}"));
        actual_queries.push(json_obj(vec![
            ("query", query_spec.clone()),
            (
                "references",
                json_arr(references.iter().map(reference_json).collect()),
            ),
        ]));
    }
    let actual = json_obj(vec![
        ("facts_kind", json_str("references")),
        (
            "artifact",
            json_obj(vec![
                (
                    "input",
                    facts
                        .get("artifact")
                        .and_then(|artifact| artifact.get("input"))
                        .cloned()
                        .expect("input path"),
                ),
                ("dex_catalog", project_catalog(&view_of(&bytes))),
            ]),
        ),
        ("queries", json_arr(actual_queries)),
    ]);
    let diffs = compare_facts(&facts, &actual, false);
    assert!(diffs.is_empty(), "{facts_name} vs scan output:\n{}", diffs.join("\n"));
}

fn project_catalog(view: &DexView<'_>) -> Json {
    let entry = view.entry();
    json_arr(vec![json_obj(vec![
        ("entry_ordinal", json_int(entry.id().entry_ordinal() as i64)),
        ("logical_ordinal", json_int(entry.id().logical_ordinal() as i64)),
        ("raw_entry_name", json_str(&String::from_utf8_lossy(entry.raw_entry_name()))),
        ("version", json_str(entry.version().as_str())),
        ("header_offset", json_int(entry.header_offset() as i64)),
    ])])
}

// ---------------------------------------------------------------------------
// REF-01: query semantics end to end (g01 facts, hand-frozen by A00)
// ---------------------------------------------------------------------------

#[test]
fn ref01_g01_regex_string_facts_match_the_scan() {
    run_references_case(
        "g01-regex-string.dex",
        "g01-regex-string.json",
        |bytes| named_view(bytes, "classes.dex"),
        reference_json_minimal,
    );
}

#[test]
fn ref01_literal_and_regex_semantics_differ_on_the_same_pool() {
    let bytes = input_bytes("g01-regex-string.dex");
    // The spec scenario: regex tok.n hits both strings, literal tok.n neither.
    let literal = scan(&bytes, &query::string_query("tok.n", MatchMode::Literal, &pattern_limits()).unwrap()).unwrap();
    assert!(literal.is_empty(), "literal tok.n must not match token/tokens");
    let regex = scan(&bytes, &query::string_query("tok.n", MatchMode::Regex, &pattern_limits()).unwrap()).unwrap();
    assert_eq!(regex.len(), 1);
    assert_eq!(regex[0].targets().len(), 2, "regex tok.n hits token and tokens");

    // Anchors decide per candidate: ^token$ only the exact string.
    let anchored = scan(&bytes, &query::string_query("^token$", MatchMode::Regex, &pattern_limits()).unwrap()).unwrap();
    assert_eq!(anchored.len(), 1);
    assert_eq!(anchored[0].targets().len(), 1);
    let TargetValue::String(text) = anchored[0].targets()[0].value() else {
        panic!("string target");
    };
    assert_eq!(text.as_str().as_deref(), Some("token"));
}

// ---------------------------------------------------------------------------
// REF-02: MUTF-8 / lossless pools
// ---------------------------------------------------------------------------

#[test]
fn ref02_mutf8_pool_facts_match_the_scan() {
    run_references_case(
        "ref02-mutf8-strings.dex",
        "ref02-mutf8-surrogate-strings.json",
        memory_view,
        reference_json_full,
    );
}

#[test]
fn ref02_unpaired_surrogate_regex_is_unsupported_not_nomatch() {
    let bytes = input_bytes("ref02-unpaired-surrogate-regex.dex");
    let regex = scan(&bytes, &query::string_query("b.c", MatchMode::Regex, &pattern_limits()).unwrap()).unwrap_err();
    assert!(
        matches!(regex.kind(), ErrorKind::UnsupportedEncoding),
        "regex over an unpaired surrogate pool: {regex}"
    );
    // A literal over the same pool is decidable and reports the hit.
    let literal = scan(&bytes, &query::string_query("b", MatchMode::Literal, &pattern_limits()).unwrap()).unwrap();
    assert_eq!(literal.len(), 1);
    let TargetValue::String(text) = literal[0].targets()[0].value() else {
        panic!("string target");
    };
    // The raw units survive: 0x62, 0xD800, 0x63.
    assert_eq!(text.utf16_units(), &[0x62, 0xd800, 0x63]);
    assert!(text.as_str().is_none());
}

#[test]
fn ref02_bad_mutf8_declared_length_is_rejected() {
    let bytes = input_bytes("ref02-bad-mutf8-rejected.dex");
    let error = scan(&bytes, &query::string_query("x", MatchMode::Literal, &pattern_limits()).unwrap()).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::MalformedInput), "{error}");
    assert!(format!("{error}").contains("#4"), "context names the offending string: {error}");
}

#[test]
fn ref02_mutf8_edge_variants_fail_malformed() {
    // Unterminated payload: the decoder must not read past the string data.
    let bytes = reference_fixtures::unterminated_mutf8();
    let error = scan(&bytes, &query::string_query("x", MatchMode::Literal, &pattern_limits()).unwrap()).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::MalformedInput), "{error}");
    assert!(
        format!("{error}").contains("not NUL-terminated") || format!("{error}").contains("#4"),
        "context names the offending string: {error}"
    );
}

#[test]
fn ref02_member_and_type_paths_enforce_the_surrogate_rule() {
    let bytes = reference_fixtures::unpaired_members();

    // A regex type query must fail on the broken descriptor (type 3).
    let error = scan(&bytes, &query::type_query("brok", MatchMode::Regex, &pattern_limits()).unwrap()).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::UnsupportedEncoding), "{error}");

    // A regex method-name pattern over the broken name (method 1) fails...
    // (member_query's first argument selects the field table, so a method
    // query passes false.)
    let error = scan(
        &bytes,
        &query::member_query(
            false,
            MemberSpec { name: Some("."), mode: MatchMode::Regex, class: None },
            &pattern_limits(),
        )
        .unwrap(),
    )
    .unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::UnsupportedEncoding), "{error}");

    // ...unless an exact class constraint excludes that member first: the
    // broken method is declared on Lbrok<surrogate>en;, not Lexample/U;.
    let excluded = scan(
        &bytes,
        &query::member_query(
            false,
            MemberSpec {
                name: Some("."),
                mode: MatchMode::Regex,
                class: Some(ClassSpec::Exact("Lexample/U;")),
            },
            &pattern_limits(),
        )
        .unwrap(),
    )
    .unwrap();
    // Only method 0 survives the class constraint; the code invokes it @4.
    assert_eq!(excluded.len(), 1);
    assert_eq!(excluded[0].targets().len(), 1);
    assert_eq!(excluded[0].targets()[0].id().table_index(), 0);
    assert_eq!(excluded[0].targets()[0].code_unit_offsets(), &[4]);

    // A literal name pattern over the broken pool stays decidable and hits
    // (a field query: member_query's first argument selects the field table).
    let literal = scan(
        &bytes,
        &query::member_query(
            true,
            MemberSpec { name: Some("plain"), mode: MatchMode::Literal, class: None },
            &pattern_limits(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(literal.len(), 1, "sget of field@0 at code unit 0");
    assert_eq!(literal[0].targets()[0].code_unit_offsets(), &[0]);

    // Fuzzy class regex over the broken descriptor fails when the name does
    // not exclude the member first. The regex mode is load-bearing here: a
    // literal pattern is decidable over every UTF-16 candidate, so only a
    // regex can make the broken descriptor's decision an UnsupportedEncoding
    // (the member name pattern is a regex too and fails the same way first).
    let error = scan(
        &bytes,
        &query::member_query(
            false,
            MemberSpec {
                name: Some("plain"),
                mode: MatchMode::Regex,
                class: Some(ClassSpec::Fuzzy("brok")),
            },
            &pattern_limits(),
        )
        .unwrap(),
    )
    .unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::UnsupportedEncoding), "{error}");

    // ...but a name literal that misses skips before the fuzzy regex runs.
    let skipped = scan(
        &bytes,
        &query::member_query(
            false,
            MemberSpec {
                name: Some("nomatch"),
                mode: MatchMode::Literal,
                class: Some(ClassSpec::Fuzzy("brok")),
            },
            &pattern_limits(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(skipped.is_empty());
}

// ---------------------------------------------------------------------------
// REF-03: opcode families, operands, payloads
// ---------------------------------------------------------------------------

#[test]
fn ref03_opcode_family_facts_match_the_scan() {
    run_references_case(
        "ref03-opcode-families.dex",
        "ref03-opcode-family-matrix.json",
        memory_view,
        reference_json_full,
    );
}

#[test]
fn ref03_unknown_instruction_fails() {
    let bytes = input_bytes("ref03-unknown-instruction.dex");
    let error = scan(&bytes, &query::string_query("tok", MatchMode::Literal, &pattern_limits()).unwrap()).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::MalformedInput), "{error}");
    assert!(format!("{error}").contains("method #0"), "{error}");

    // In-test variants: unused opcodes 0xe3/0xf9 and a truncated stream.
    for opcode in [0x0073u16, 0x00e3, 0x00f9] {
        let bytes = reference_fixtures::unknown_opcode();
        let mut patched = bytes.clone();
        // Patch the first code unit of the only method body.
        let code_off = find_first_code_offset(&patched);
        patched[code_off + 16..code_off + 18].copy_from_slice(&opcode.to_le_bytes());
        let error = scan(&patched, &query::string_query("x", MatchMode::Literal, &pattern_limits()).unwrap()).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::MalformedInput), "opcode {opcode:#06x}: {error}");
    }
    let truncated = reference_fixtures::truncated_insns();
    let error = scan(&truncated, &query::string_query("tok", MatchMode::Literal, &pattern_limits()).unwrap()).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::MalformedInput), "{error}");
}

/// The first code_item offset in a one-class fixture: read class_data_off
/// from the single class_def (the fixtures always place it last).
fn find_first_code_offset(bytes: &[u8]) -> usize {
    // classes_off (0x64) + 24 -> class_data_off; the uleb at class_data_off
    // skips counts (0,0,1,0), then delta, access, code_off.
    let classes_off = u32::from_le_bytes(bytes[0x64..0x68].try_into().unwrap()) as usize;
    let class_data_off = u32::from_le_bytes(
        bytes[classes_off + 24..classes_off + 28].try_into().unwrap(),
    ) as usize;
    let mut cursor = class_data_off + 4; // skip the four zero counts
    let mut value = 0u32;
    loop {
        let byte = bytes[cursor];
        cursor += 1;
        value |= u32::from(byte & 0x7f);
        if byte < 0x80 {
            break;
        }
        value <<= 7;
    }
    let _ = value; // method_idx delta
    let mut value = 0u32;
    loop {
        let byte = bytes[cursor];
        cursor += 1;
        value |= u32::from(byte & 0x7f);
        if byte < 0x80 {
            break;
        }
        value <<= 7;
    }
    let _ = value; // access flags
    let mut code_off = 0u32;
    let mut shift = 0;
    loop {
        let byte = bytes[cursor];
        cursor += 1;
        code_off |= u32::from(byte & 0x7f) << shift;
        shift += 7;
        if byte < 0x80 {
            break;
        }
    }
    code_off as usize
}

#[test]
fn ref03_map_fallback_keeps_the_same_hits() {
    let full = reference_fixtures::opcode_families(MapStyle::Full);
    let minimal = reference_fixtures::opcode_families(MapStyle::HeaderOnly);
    for (kind, mode, pattern) in [
        ("string", "literal", "str"),
        ("type", "literal", "OpsType"),
        ("field", "literal", "fTarget"),
        ("method", "literal", "target"),
    ] {
        let spec = json_obj(vec![
            ("kind", json_str(kind)),
            ("mode", json_str(mode)),
            ("pattern", json_str(pattern)),
        ]);
        let contract_query = build_query(&spec);
        let from_full = scan(&full, &contract_query).unwrap();
        let from_minimal = scan(&minimal, &contract_query).unwrap();
        assert_eq!(from_full, from_minimal, "{kind} {pattern}");
        assert!(!from_full.is_empty(), "{kind} {pattern} must hit");
    }
}

#[test]
// The case matrix reads naturally as inline tuples; the alias would bury the
// scenario shape, so the lint is silenced for this one test body instead.
#[allow(clippy::type_complexity)]
fn ref03_prefilter_toggle_is_result_equivalent() {
    let cases: Vec<(&str, Vec<(&str, &str, &str)>)> = vec![
        (
            "ref02-mutf8-strings.dex",
            vec![
                ("string", "literal", "alpha"),
                ("string", "literal", "a"),
                ("string", "regex", "e.oji"),
                ("type", "literal", "po\u{1f600}ol"),
            ],
        ),
        (
            "ref03-opcode-families.dex",
            vec![
                ("string", "literal", "str"),
                ("type", "literal", "OpsType"),
                ("field", "literal", "fTarget"),
                ("method", "literal", "target"),
            ],
        ),
        ("ref04-shared-code-and-overloads.dex", vec![("string", "literal", "tok")]),
    ];
    for (input, queries) in cases {
        let bytes = input_bytes(input);
        for (kind, mode, pattern) in queries {
            let spec = json_obj(vec![
                ("kind", json_str(kind)),
                ("mode", json_str(mode)),
                ("pattern", json_str(pattern)),
            ]);
            let contract_query = build_query(&spec);
            let on = scan_with(&bytes, &contract_query, ScanLimits::DEFAULT, true).unwrap();
            let off = scan_with(&bytes, &contract_query, ScanLimits::DEFAULT, false).unwrap();
            assert_eq!(on, off, "{input} {kind} {pattern}");
        }
    }
}

// ---------------------------------------------------------------------------
// REF-04: aggregation and full identity
// ---------------------------------------------------------------------------

#[test]
fn ref04_identity_facts_match_the_scan() {
    run_references_case(
        "ref04-shared-code-and-overloads.dex",
        "ref04-shared-code-item-and-overloads.json",
        memory_view,
        reference_json_full,
    );
}

#[test]
fn ref04_rows_and_targets_are_ordered_and_distinct() {
    let bytes = input_bytes("ref04-shared-code-and-overloads.dex");
    let references = scan(&bytes, &query::string_query("tok", MatchMode::Literal, &pattern_limits()).unwrap()).unwrap();
    let method_ids: Vec<u32> = references.iter().map(|row| row.caller().id().method_idx()).collect();
    assert_eq!(method_ids, vec![0, 1, 2, 3, 4], "rows ascend by method_idx");

    // The overloads stay two rows with distinct prototypes.
    let run_void = &references[1];
    let run_int = &references[2];
    assert_eq!(run_void.caller().name().as_str(), run_int.caller().name().as_str());
    assert_eq!(prototype_text(run_void.caller().prototype()), "()V");
    assert_eq!(prototype_text(run_int.caller().prototype()), "(I)V");

    // Shared code_item: alpha and beta each keep a row with the same offsets.
    let alpha = &references[3];
    let beta = &references[4];
    assert_eq!(alpha.caller().id().method_idx(), 3);
    assert_eq!(beta.caller().id().method_idx(), 4);
    assert_eq!(alpha.targets()[0].code_unit_offsets(), beta.targets()[0].code_unit_offsets());

    // Multiple positions of one target and multiple targets per method.
    assert_eq!(references[0].targets()[0].code_unit_offsets(), &[0, 2]);
    let run_query = scan(
        &bytes,
        &query::member_query(
            false,
            MemberSpec { name: Some("run"), mode: MatchMode::Literal, class: None },
            &pattern_limits(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(run_query.len(), 1);
    let targets: Vec<u32> = run_query[0].targets().iter().map(|t| t.id().table_index()).collect();
    assert_eq!(targets, vec![1, 2], "targets ascend by table index");
}

#[test]
fn ref04_control_character_values_round_trip_losslessly() {
    let bytes = input_bytes("ref04-shared-code-and-overloads.dex");
    let references = scan(&bytes, &query::string_query("a\tb\nc", MatchMode::Literal, &pattern_limits()).unwrap()).unwrap();
    assert_eq!(references.len(), 1);
    let TargetValue::String(text) = references[0].targets()[0].value() else {
        panic!("string target");
    };
    // Raw UTF-16 units, not a sanitized display form.
    assert_eq!(text.utf16_units(), &[0x61, 0x09, 0x62, 0x0a, 0x63]);
    assert_eq!(text.as_str().as_deref(), Some("a\tb\nc"));

    let fields = scan(
        &bytes,
        &query::member_query(
            true,
            MemberSpec { name: Some("f\nield"), mode: MatchMode::Literal, class: None },
            &pattern_limits(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(fields.len(), 1);
    let TargetValue::Field { name, field_type, .. } = fields[0].targets()[0].value() else {
        panic!("field target");
    };
    assert_eq!(name.utf16_units(), &[0x66, 0x0a, 0x69, 0x65, 0x6c, 0x64]);
    assert_eq!(field_type.as_str().as_deref(), Some("I"));
}

// ---------------------------------------------------------------------------
// Limits and cancellation (REF-01 budget half)
// ---------------------------------------------------------------------------

#[test]
fn scan_limits_are_enforced_with_current_counts() {
    let bytes = input_bytes("ref04-shared-code-and-overloads.dex");
    let tok = || query::string_query("tok", MatchMode::Literal, &pattern_limits()).unwrap();

    // Table sizes: ref04 declares 5 types and 13 strings.
    let tight_tables = ScanLimits { max_table_items: 4, ..ScanLimits::DEFAULT };
    let error = scan_with(&bytes, &tok(), tight_tables, true).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::ResourceLimit), "{error}");

    // Per-string decode budget: "Lexample/Ident;" declares 16 units.
    let tight_strings = ScanLimits { max_string_units: 8, ..ScanLimits::DEFAULT };
    let error = scan_with(&bytes, &tok(), tight_strings, true).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::ResourceLimit), "{error}");

    // Result items: "tok" produces 5 rows.
    let tight_items = ScanLimits { max_result_items: 4, ..ScanLimits::DEFAULT };
    let error = scan_with(&bytes, &tok(), tight_items, true).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::ResourceLimit), "{error}");

    // Accumulated locations: "tok" carries 7 offsets total.
    let tight_locations = ScanLimits {
        max_reference_locations: 6,
        ..ScanLimits::DEFAULT
    };
    let error = scan_with(&bytes, &tok(), tight_locations, true).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::ResourceLimit), "{error}");

    // Result byte estimate.
    let tight_bytes = ScanLimits { max_result_bytes: 1, ..ScanLimits::DEFAULT };
    let error = scan_with(&bytes, &tok(), tight_bytes, true).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::ResourceLimit), "{error}");

    // The defaults leave the fixture well inside every budget.
    assert_eq!(scan(&bytes, &tok()).unwrap().len(), 5);
}

#[test]
fn scan_honors_user_cancellation_and_deadlines() {
    let bytes = input_bytes("ref03-opcode-families.dex");
    let query = query::string_query("str", MatchMode::Literal, &pattern_limits()).unwrap();
    let view = memory_view(&bytes);

    let cancelled = AtomicBool::new(true);
    let probe = bytes::ControlProbe { cancelled: &cancelled, deadline: None };
    let options = ScanOptions { limits: ScanLimits::DEFAULT, control: Some(&probe), prefilter: true };
    let error = dex::scan_references(&view, &query, &options).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::Cancelled { cause: CancelCause::User }), "{error}");

    let live = AtomicBool::new(false);
    let probe = bytes::ControlProbe {
        cancelled: &live,
        deadline: Some(Instant::now() - Duration::from_millis(1)),
    };
    let options = ScanOptions { limits: ScanLimits::DEFAULT, control: Some(&probe), prefilter: true };
    let error = dex::scan_references(&view, &query, &options).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::Cancelled { cause: CancelCause::Deadline }), "{error}");

    // No control: the same scan succeeds (and covers >4096-unit loops via the
    // ref03 payload method).
    let references = scan(&bytes, &query).unwrap();
    assert!(!references.is_empty());
}

// ---------------------------------------------------------------------------
// Fixture integrity and regeneration
// ---------------------------------------------------------------------------

/// The committed inputs must be exactly what the builders produce.
#[test]
fn committed_reference_inputs_match_their_builders() {
    let inputs = [
        ("ref02-mutf8-strings.dex", reference_fixtures::pool_a()),
        ("ref02-unpaired-surrogate-regex.dex", reference_fixtures::pool_b()),
        ("ref02-bad-mutf8-rejected.dex", reference_fixtures::bad_mutf8()),
        ("ref03-opcode-families.dex", reference_fixtures::opcode_families(MapStyle::Full)),
        ("ref03-unknown-instruction.dex", reference_fixtures::unknown_opcode()),
        ("ref04-shared-code-and-overloads.dex", reference_fixtures::identity()),
    ];
    for (name, bytes) in &inputs {
        assert_eq!(&input_bytes(name), bytes, "{name} drifted from its builder");
    }
}

/// Regenerates the A03 fixture inputs after a builder change. Opt in with
/// ASC_REGEN_FIXTURES=1, then update manifest.json's sha256/size fields (the
/// other tests in this file fail until they agree).
#[test]
fn regenerate_reference_fixture_inputs_when_explicitly_requested() {
    if std::env::var("ASC_REGEN_FIXTURES").ok().as_deref() != Some("1") {
        return;
    }
    let inputs = [
        ("ref02-mutf8-strings.dex", reference_fixtures::pool_a()),
        ("ref02-unpaired-surrogate-regex.dex", reference_fixtures::pool_b()),
        ("ref02-bad-mutf8-rejected.dex", reference_fixtures::bad_mutf8()),
        ("ref03-opcode-families.dex", reference_fixtures::opcode_families(MapStyle::Full)),
        ("ref03-unknown-instruction.dex", reference_fixtures::unknown_opcode()),
        ("ref04-shared-code-and-overloads.dex", reference_fixtures::identity()),
    ];
    let directory = contracts_dir().join("inputs");
    fs::create_dir_all(&directory).expect("create inputs directory");
    for (name, bytes) in &inputs {
        fs::write(directory.join(name), bytes).expect("write fixture input");
        println!(
            "{name}: size {} sha256 {}",
            bytes.len(),
            sha::hex_lower(&sha::sha256(bytes))
        );
    }
}
