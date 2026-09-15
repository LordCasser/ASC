//! Contract tests for the A01 domain model and query construction: pattern
//! semantics, descriptor normalization, query-shape invariants, error kinds
//! and the frozen DTO/golden bytes.
//!
//! The model sources are compiled into this test via `#[path]` includes -
//! the same approach tests/contract_harness.rs uses - so the binary crate
//! keeps its current shape while the contract layer is still being wired.

#![allow(dead_code)]

#[path = "../src/error.rs"]
mod error;
#[path = "../src/model.rs"]
mod model;
#[path = "../src/query.rs"]
mod query;

use error::{CancelCause, ErrorKind};
use model::dto;
use model::{
    ArtifactId, ClassConstraint, ClassDescriptor, DexEntry, DexId, DexText, Diagnostic,
    DiagnosticCode, MatchOutcome, MethodIdentity, Pattern, PatternLimits, Prototype, Reference,
    ReferenceQuery, Severity, Stage, TargetId, TargetKind, TargetMatch, TargetValue,
};
use query::{ClassSpec, MatchMode, MemberSpec};

fn limits() -> PatternLimits {
    PatternLimits::default()
}

// ---------------------------------------------------------------------------
// Pattern semantics (REF-01 constructor half)
// ---------------------------------------------------------------------------

#[test]
fn regex_matches_where_literal_does_not() {
    // The spec scenario: `tok.n` as a regex hits `token`, as a literal it
    // does not (no literal dot in the candidate).
    let regex = Pattern::regex("tok.n", &limits()).unwrap();
    let literal = Pattern::literal("tok.n", &limits()).unwrap();
    assert_eq!(regex.matches_str("token").unwrap(), MatchOutcome::Match);
    assert_eq!(literal.matches_str("token").unwrap(), MatchOutcome::NoMatch);
    assert_eq!(literal.matches_str("a tok.n b").unwrap(), MatchOutcome::Match);
}

#[test]
fn regex_grammar_covers_the_required_constructs() {
    // lookaround and backreference are the fancy-regex-only features the
    // reference relies on; each must compile and decide.
    for (pattern, candidate, expected) in [
        ("tok(en|x)", "token", MatchOutcome::Match),
        ("tok(en|x)", "tokx", MatchOutcome::Match),
        ("^token$", "token", MatchOutcome::Match),
        ("^token$", "atoken", MatchOutcome::NoMatch),
        (r"\btok\b", "a tok b", MatchOutcome::Match),
        (r"[a-z]+\d{2}", "ab12", MatchOutcome::Match),
        (r"(a)|\1", "aa", MatchOutcome::Match),
        (r"token(?=s)", "tokens", MatchOutcome::Match),
        (r"(?<!a)token", "btoken", MatchOutcome::Match),
    ] {
        let regex = Pattern::regex(pattern, &limits())
            .unwrap_or_else(|error| panic!("pattern {pattern:?} must compile: {error}"));
        assert_eq!(
            regex.matches_str(candidate).unwrap(),
            expected,
            "pattern {pattern:?} vs {candidate:?}"
        );
    }
}

#[test]
fn invalid_regex_is_invalid_query_not_a_literal_fallback() {
    let error = Pattern::regex("tok(en", &limits()).unwrap_err();
    assert_eq!(*error.kind(), ErrorKind::InvalidQuery);
}

#[test]
fn blank_patterns_are_rejected_but_meaningful_spaces_are_kept() {
    for blank in ["", " ", "\t", " \n\u{a0} "] {
        assert!(
            Pattern::literal(blank, &limits()).is_err(),
            "literal {blank:?} must be rejected"
        );
        assert!(Pattern::regex(blank, &limits()).is_err(), "regex {blank:?} must be rejected");
    }
    // A space inside a non-blank pattern is part of the needle.
    let spaces = Pattern::literal("Authorization Bearer", &limits()).unwrap();
    assert_eq!(spaces.matches_str("x Authorization Bearer y").unwrap(), MatchOutcome::Match);
    assert_eq!(spaces.matches_str("AuthorizationBearer").unwrap(), MatchOutcome::NoMatch);
    assert_eq!(spaces.source(), "Authorization Bearer");
}

#[test]
fn pattern_size_limit_is_a_resource_limit() {
    let tight = PatternLimits { max_pattern_bytes: 8, ..PatternLimits::default() };
    assert_eq!(*Pattern::literal("012345678", &tight).unwrap_err().kind(), ErrorKind::ResourceLimit);
    assert_eq!(*Pattern::regex("012345678", &tight).unwrap_err().kind(), ErrorKind::ResourceLimit);
}

#[test]
fn literals_compare_utf16_units_not_utf8_bytes() {
    // U+1F600 is 2 UTF-16 units / 4 UTF-8 bytes; NUL is one unit. Matching
    // must agree with UTF-16 semantics on both sides of the needle.
    let emoji = Pattern::literal("\u{1F600}z", &limits()).unwrap();
    let candidate: Vec<u16> = "a\u{1F600}z".encode_utf16().collect();
    assert_eq!(emoji.matches_utf16(&candidate).unwrap(), MatchOutcome::Match);
    let nul = Pattern::literal("a\0b", &limits()).unwrap();
    let with_nul: Vec<u16> = "xa\0b".encode_utf16().collect();
    assert_eq!(nul.matches_utf16(&with_nul).unwrap(), MatchOutcome::Match);
}

#[test]
fn regex_over_unpaired_surrogate_is_unsupported_not_nomatch() {
    let regex = Pattern::regex("t.ok", &limits()).unwrap();
    let units: Vec<u16> = vec![b't' as u16, 0xD800, b'o' as u16, b'k' as u16];
    assert_eq!(regex.matches_utf16(&units).unwrap(), MatchOutcome::Unsupported);
    // A literal needle still decides such candidates (unit-wise compare).
    let literal = Pattern::literal("t", &limits()).unwrap();
    assert_eq!(literal.matches_utf16(&units).unwrap(), MatchOutcome::Match);
}

// ---------------------------------------------------------------------------
// Descriptors and query construction
// ---------------------------------------------------------------------------

#[test]
fn exact_descriptor_normalizes_java_and_descriptor_inputs() {
    for (input, expected) in [
        ("com.example.Main", "Lcom/example/Main;"),
        ("Lcom/example/Main;", "Lcom/example/Main;"),
        ("Lcom.example.Main;", "Lcom/example/Main;"),
        ("com/example/Main", "Lcom/example/Main;"),
        ("Lcom/foo/Main", "Lcom/foo/Main;"),
        ("Main", "LMain;"),
        ("com.example.Main$Inner", "Lcom/example/Main$Inner;"),
    ] {
        let descriptor = query::exact_descriptor(input)
            .unwrap_or_else(|error| panic!("{input:?}: {error}"));
        assert_eq!(descriptor.as_str(), expected, "input {input:?}");
    }
}

#[test]
fn exact_descriptor_rejects_malformed_forms() {
    for bad in ["", "[Lcom/foo/Main;", "L[com;", "com/foo/Main;extra;", ";", "L"] {
        assert!(
            query::exact_descriptor(bad).is_err(),
            "{bad:?} must be rejected"
        );
    }
}

#[test]
fn type_literal_gets_dotted_conversion_but_regex_and_string_do_not() {
    let literal = query::type_query("java.lang.String", MatchMode::Literal, &limits()).unwrap();
    let ReferenceQuery::Type(pattern) = &literal else {
        panic!("type query");
    };
    assert_eq!(
        pattern.matches_str("Ljava/lang/String;").unwrap(),
        MatchOutcome::Match,
        "literal type patterns match descriptor text after dot conversion"
    );

    let regex = query::type_query("java\\.lang\\.String", MatchMode::Regex, &limits()).unwrap();
    let ReferenceQuery::Type(pattern) = &regex else {
        panic!("type query");
    };
    assert_eq!(
        pattern.matches_str("Ljava/lang/String;").unwrap(),
        MatchOutcome::NoMatch,
        "regex patterns are applied as written, never rewritten"
    );
    assert_eq!(pattern.matches_str("Ljava.lang.String;").unwrap(), MatchOutcome::Match);

    let string = query::string_query("java.lang.String", MatchMode::Literal, &limits()).unwrap();
    let ReferenceQuery::String(pattern) = &string else {
        panic!("string query");
    };
    assert_eq!(
        pattern.matches_str("see java.lang.String here").unwrap(),
        MatchOutcome::Match,
        "string literals are never converted"
    );
}

#[test]
fn member_query_constraints_are_independent() {
    // The audit G01 scenario: a regex member name with an exact class keeps
    // regex semantics on the name and exact semantics on the class.
    let spec = MemberSpec {
        name: Some("SEC.ND"),
        mode: MatchMode::Regex,
        class: Some(ClassSpec::Exact("example.Statics")),
    };
    let built = query::member_query(true, spec, &limits()).unwrap();
    let ReferenceQuery::Field(member) = &built else {
        panic!("field query");
    };
    let ClassConstraint::Exact(class) = member.declaring_class().unwrap() else {
        panic!("exact class constraint");
    };
    assert_eq!(class.as_str(), "Lexample/Statics;");
    let name = member.name().unwrap();
    assert_eq!(name.matches_str("SECOND").unwrap(), MatchOutcome::Match);
    assert_eq!(name.matches_str("SECONDARY").unwrap(), MatchOutcome::Match);
    assert_eq!(name.matches_str("SECRET").unwrap(), MatchOutcome::NoMatch);

    // Fuzzy + regex applies to descriptor text as written (slashes, no dot
    // rewriting); literal fuzzy input gets the dotted-name conversion.
    let spec = MemberSpec {
        name: None,
        mode: MatchMode::Regex,
        class: Some(ClassSpec::Fuzzy("example/(Statics|Other)")),
    };
    let built = query::member_query(false, spec, &limits()).unwrap();
    let ReferenceQuery::Method(member) = &built else {
        panic!("method query");
    };
    let ClassConstraint::Fuzzy(pattern) = member.declaring_class().unwrap() else {
        panic!("fuzzy constraint");
    };
    assert_eq!(pattern.matches_str("Lexample/Statics;").unwrap(), MatchOutcome::Match);
    assert_eq!(pattern.matches_str("Lexample/Main;").unwrap(), MatchOutcome::NoMatch);

    let spec = MemberSpec {
        name: None,
        mode: MatchMode::Literal,
        class: Some(ClassSpec::Fuzzy("example.Statics")),
    };
    let built = query::member_query(false, spec, &limits()).unwrap();
    let ReferenceQuery::Method(member) = &built else {
        panic!("method query");
    };
    let ClassConstraint::Fuzzy(pattern) = member.declaring_class().unwrap() else {
        panic!("fuzzy constraint");
    };
    assert_eq!(
        pattern.matches_str("Lexample/Statics;").unwrap(),
        MatchOutcome::Match,
        "literal fuzzy patterns are converted from dotted to descriptor form"
    );
}

#[test]
fn member_query_without_any_constraint_is_invalid() {
    let spec = MemberSpec { name: None, mode: MatchMode::Literal, class: None };
    let error = query::member_query(false, spec, &limits()).unwrap_err();
    assert_eq!(*error.kind(), ErrorKind::InvalidQuery);
}

#[test]
fn dex_selector_parsing_distinguishes_syntax_from_existence() {
    assert_eq!(query::parse_dex_selector("0:1").unwrap(), (0, 1));
    assert_eq!(query::parse_dex_selector("12:345").unwrap(), (12, 345));
    for bad in ["0", "0:", ":1", "a:1", "1:b", "-1:0", "0x1:2", "1:2:3", "", "4294967296:0"] {
        assert!(
            query::parse_dex_selector(bad).is_err(),
            "{bad:?} must be a syntax error"
        );
    }
}

// ---------------------------------------------------------------------------
// ClassFilter, DexText, diagnostics
// ---------------------------------------------------------------------------

#[test]
fn class_filter_is_case_insensitive_and_blank_means_no_filter() {
    let filter = model::ClassFilter::new("example.MA");
    let hit = DexText::from_str_lossless("com.Example.main");
    let miss = DexText::from_str_lossless("com.Other.main");
    assert!(filter.matches(&hit));
    assert!(!filter.matches(&miss));
    assert!(model::ClassFilter::none().matches(&miss));
    assert!(model::ClassFilter::new("").matches(&miss));
}

#[test]
fn dex_text_keeps_unpaired_surrogates_distinct() {
    // Two different broken values must not collapse through U+FFFD.
    let first = DexText::from_utf16_units(vec![0xD800]);
    let second = DexText::from_utf16_units(vec![0xDC00]);
    assert_ne!(first, second);
    assert!(first.as_str().is_none());
    assert_eq!(DexText::from_str_lossless("ab").utf16_units(), &[b'a' as u16, b'b' as u16]);
    let emoji = DexText::from_str_lossless("\u{1F600}");
    assert_eq!(emoji.utf16_units(), &[0xD83D, 0xDE00]);
    assert_eq!(emoji.as_str().as_deref(), Some("\u{1F600}"));
}

#[test]
fn error_codes_are_stable_and_cancellation_carries_its_cause() {
    assert_eq!(ErrorKind::InvalidQuery.code(), "InvalidQuery");
    assert_eq!(ErrorKind::IncompleteDecompilation.code(), "IncompleteDecompilation");
    let cancelled = ErrorKind::Cancelled { cause: CancelCause::Deadline };
    assert_eq!(cancelled.code(), "Cancelled");
    let diagnostics = [Diagnostic::new(
        DiagnosticCode::DexChecksumMismatch,
        Severity::Warning,
        Stage::Dex,
        "checksum field is zero",
    )];
    assert_eq!(diagnostics[0].code().as_str(), "dex-checksum-mismatch");
    assert_eq!(diagnostics[0].severity().as_str(), "warning");
    assert_eq!(diagnostics[0].stage().as_str(), "dex");
}

// ---------------------------------------------------------------------------
// DTO goldens (frozen bytes, schema_version 1)
// ---------------------------------------------------------------------------

fn artifact() -> ArtifactId {
    ArtifactId::from_digest([7u8; 32])
}

fn sample_dex_entry(artifact: ArtifactId) -> DexEntry {
    DexEntry::new(
        DexId::new(artifact, 0, 1),
        b"classes.dex".to_vec(),
        DexText::from_str_lossless("classes.dex"),
        DexText::from_str_lossless("classes2.dex"),
        model::DexVersion::V041,
        112,
    )
}

fn sample_reference(artifact: ArtifactId) -> Reference {
    let dex = sample_dex_entry(artifact);
    let caller = MethodIdentity::new(
        model::MethodId::new(dex.id(), 9),
        dex.clone(),
        DexText::from_str_lossless("Lexample/Regex;"),
        DexText::from_str_lossless("mark"),
        Prototype::new(vec![], DexText::from_str_lossless("V")),
    );
    let target = TargetMatch::new(
        TargetId::new(dex.id(), TargetKind::String, 5),
        TargetValue::String(DexText::from_str_lossless("token")),
        vec![0, 0, 2],
    );
    assert_eq!(target.code_unit_offsets(), &[0, 2], "offsets dedup ascending");
    Reference::new(caller, vec![target])
}

#[test]
fn golden_reference_dto_bytes_are_frozen() {
    let artifact = artifact();
    let reference = sample_reference(artifact);
    let mut writer = dto::Writer::new();
    dto::write_reference(&mut writer, &reference);
    let json = writer.finish();
    let expected = std::fs::read_to_string("schemas/goldens/reference.json").expect("golden file");
    assert_eq!(json, expected.trim_end());
}

#[test]
fn golden_envelope_and_error_dto_bytes_are_frozen() {
    let artifact = artifact();
    let diagnostics = vec![
        Diagnostic::new(
            DiagnosticCode::DexSignatureMismatch,
            Severity::Warning,
            Stage::Dex,
            "signature field is zero",
        )
        .with_dex(DexId::new(artifact, 0, 1))
        .with_offset(12),
    ];
    let json = dto::write_envelope("findrefs", &artifact, &diagnostics, |writer| {
        writer.begin_array();
        dto::write_reference(writer, &sample_reference(artifact));
        writer.end_array();
    });
    // stats never appear in the payload; key order is fixed.
    assert!(!json.contains("stats"));
    let expected = std::fs::read_to_string("schemas/goldens/envelope-findrefs.json").expect("golden file");
    assert_eq!(json, expected.trim_end());

    let error = error::Error::new(ErrorKind::IncompleteDecompilation)
        .with_context("method Lbroken;->hard failed to convert");
    let error_json = dto::write_error(&error);
    let error_expected = std::fs::read_to_string("schemas/goldens/error.json").expect("golden file");
    assert_eq!(error_json, error_expected.trim_end());
}

#[test]
fn golden_dex_text_and_class_dto_bytes_are_frozen() {
    let broken = DexText::from_utf16_units(vec![b't' as u16, 0xD800, b'o' as u16]);
    let mut writer = dto::Writer::new();
    dto::write_dex_text(&mut writer, &broken);
    assert_eq!(
        writer.finish(),
        r#"{"text":null,"utf16":[116,55296,111]}"#
    );
    let valid = DexText::from_str_lossless("to\"k\n");
    let mut writer = dto::Writer::new();
    dto::write_dex_text(&mut writer, &valid);
    assert_eq!(
        writer.finish(),
        r#"{"text":"to\"k\n","utf16":[116,111,34,107,10]}"#
    );

    let artifact = artifact();
    let class = model::Class::new(
        model::ClassId::new(DexId::new(artifact, 0, 0), 3),
        sample_dex_entry(artifact),
        ClassDescriptor::from_normalized("Lcom/example/Main$Inner;".to_owned()).unwrap(),
    );
    assert_eq!(class.java_name().as_str().as_deref(), Some("com.example.Main$Inner"));
    assert_eq!(class.package().as_str().as_deref(), Some("com.example"));
    assert_eq!(class.simple_name().as_str().as_deref(), Some("Main$Inner"));
    let mut writer = dto::Writer::new();
    dto::write_class(&mut writer, &class);
    let expected = std::fs::read_to_string("schemas/goldens/class.json").expect("golden file");
    assert_eq!(writer.finish(), expected.trim_end());
}

#[test]
fn writer_json_is_valid_and_escapes_control_characters() {
    let writer_text = dto::Writer::raw("a\"b\\c\nd\te\u{1}f\u{7f}g\u{4e2d}");
    assert_eq!(writer_text, "\"a\\\"b\\\\c\\nd\\te\\u0001f\u{7f}g\u{4e2d}\"");
    // Everything the writer produces parses back as JSON.
    let documents = [
        writer_text,
        {
            let mut writer = dto::Writer::new();
            dto::write_reference(&mut writer, &sample_reference(artifact()));
            writer.finish()
        },
    ];
    for document in documents {
        assert!(supports_json_check(&document), "not valid JSON: {document}");
    }
}

/// Independent structural JSON validation (no serde dependency): checks the
/// bracket balance and string escaping of a complete document.
fn supports_json_check(document: &str) -> bool {
    let mut bytes = document.as_bytes();
    let mut stack = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(&byte) = bytes.first() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => stack.push(if byte == b'{' { b'}' } else { b']' }),
                b'}' | b']' => {
                    if stack.pop() != Some(byte) {
                        return false;
                    }
                }
                _ => {}
            }
        }
        bytes = &bytes[1..];
    }
    stack.is_empty() && !in_string && !escaped
}


// ---------------------------------------------------------------------------
// A08 DTO goldens: getclass `metadata` projection and writer budget
// ---------------------------------------------------------------------------

fn sample_source_metadata() -> model::SourceMetadata {
    use model::{
        AnnotationEntry, AnnotationRecord, AnnotationTarget, AnnotationVisibility, ClassMetadata,
        DebugInfo, EnclosingRecord, EncodedValue, FieldMetadata, InnerClassRecord,
        LineNumberEntry, LocalVariable, MethodMetadata,
    };
    let text = DexText::from_str_lossless;
    model::SourceMetadata {
        class: ClassMetadata {
            access_flags: 0x11,
            super_class: Some(text("Ljava/lang/Object;")),
            interfaces: vec![text("Lcom/example/A;"), text("Lcom/example/B;")],
            source_file: Some(text("Statics.java")),
            generic_signature: Some(text("<T:Ljava/lang/Object;>Ljava/lang/Object;")),
            enclosing: Some(EnclosingRecord {
                outer_class: Some(text("Lcom/example/Outer;")),
                enclosing_method: Some((
                    text("handle(Ljava/lang/String;)V"),
                    text(""),
                    Prototype::default(),
                )),
            }),
            inner_classes: vec![InnerClassRecord {
                inner_class: text("Lcom/example/Outer$Inner;"),
                outer_class: Some(text("Lcom/example/Outer;")),
                inner_name: Some(text("Inner")),
                access_flags: 0x1c,
            }],
        },
        annotations: vec![AnnotationEntry {
            target: AnnotationTarget::Class,
            annotation: AnnotationRecord::new(
                AnnotationVisibility::Runtime,
                text("Lcom/example/Anno;"),
                vec![(
                    text("value"),
                    EncodedValue::Array(vec![
                        EncodedValue::String(text("hello")),
                        EncodedValue::Long(-2),
                    ]),
                )],
                "value = {\"hello\", -2L}".to_owned(),
            ),
        }],
        fields: vec![
            FieldMetadata {
                name: text("FIRST"),
                field_type: text("I"),
                access_flags: 0x19,
                generic_signature: None,
                initial_value: Some(EncodedValue::Int(11)),
            },
            FieldMetadata {
                name: text("RATE"),
                field_type: text("D"),
                access_flags: 0x1a,
                generic_signature: None,
                initial_value: Some(EncodedValue::Double(0x4008_0000_0000_0000)),
            },
        ],
        methods: vec![MethodMetadata {
            name: text("getSecond"),
            prototype: Prototype::new(vec![text("I"), text("J")], text("V")),
            access_flags: 0x9,
            generic_signature: Some(text("(TT;)V")),
            throws: vec![text("Ljava/io/IOException;")],
            annotations: vec![AnnotationEntry {
                target: AnnotationTarget::Parameter { method_index: 1, parameter_index: 0 },
                annotation: AnnotationRecord::new(
                    AnnotationVisibility::Build,
                    text("Lcom/example/Id;"),
                    vec![
                        (text("f"), EncodedValue::Float(0x3fc0_0000)),
                        (text("e"), EncodedValue::Enum {
                            owner: text("Lcom/example/Kind;"),
                            name: text("ONE"),
                        }),
                        (text("n"), EncodedValue::Annotation(AnnotationRecord::new(
                            AnnotationVisibility::System,
                            text("Lcom/example/Inner;"),
                            Vec::new(),
                            String::new(),
                        ))),
                    ],
                    "f = 1.5f, e = Kind.ONE, n = @Inner".to_owned(),
                ),
            }],
            parameter_signatures: vec![Some(text("TT;")), None],
            debug: Some(DebugInfo {
                parameter_names: vec![Some(text("value")), None],
                locals: vec![LocalVariable {
                    name: text("i"),
                    start_code_unit: 0,
                    end_code_unit: 5,
                    slot: 1,
                }],
                lines: vec![LineNumberEntry { code_unit: 0, line: 12 }],
            }),
        }],
    }
}

#[test]
fn golden_source_metadata_dto_bytes_are_frozen() {
    let mut writer = dto::Writer::new();
    dto::write_source_metadata(&mut writer, &sample_source_metadata());
    let json = writer.finish();
    let expected =
        std::fs::read_to_string("schemas/goldens/source-metadata.json").expect("golden file");
    assert_eq!(json, expected.trim_end());
}

#[test]
fn writer_budget_freezes_output_and_reports_resource_limit() {
    let mut writer = dto::Writer::new();
    writer.set_budget(16);
    dto::write_reference(&mut writer, &sample_reference(artifact()));
    assert!(writer.over_budget(), "a full reference exceeds 16 bytes");
    let error = writer.try_finish().unwrap_err();
    assert_eq!(*error.kind(), ErrorKind::ResourceLimit);
    // A budget that fits leaves the bytes byte-identical to the unbudgeted
    // writer.
    let mut writer = dto::Writer::new();
    dto::write_dex_text(&mut writer, &DexText::from_str_lossless("token"));
    let unbudgeted = writer.finish();
    let mut writer = dto::Writer::new();
    writer.set_budget(unbudgeted.len());
    dto::write_dex_text(&mut writer, &DexText::from_str_lossless("token"));
    assert!(!writer.over_budget());
    assert_eq!(writer.try_finish().unwrap(), unbudgeted);
}
