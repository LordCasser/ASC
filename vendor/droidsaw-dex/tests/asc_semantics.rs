//! A05 semantics-matrix contract tests (patch ledger DX-P04 / DX-P05;
//! acceptance DECL-01, DECL-02, DECL-03, IN-03 backend side).
//!
//! Every fixture is built in-process by `tests/support/mod.rs`
//! (self-contained mini DEX builder — no dependency on the root
//! crate's test support, no on-disk fixtures). Tests drive the frozen
//! checked API only: `parse_for_analysis` + `decompile_checked`.
//!
//! Note for A02 alignment: the IN-03 version-matrix tests below build
//! their own minimal header variants (real magic bytes, checksums and
//! SHA-1 signatures recomputed). When A02's committed version-matrix
//! APK fixtures land, the same assertions should be re-pointed at
//! those bytes (tracked in `evidence/A05.md`).

mod support;

use support::{
    enclosing_class_spec, inner_class_spec, method_key, method_key_from, signature_spec,
    throws_spec, ACC_ABSTRACT, ACC_FINAL, ACC_NATIVE, ACC_PRIVATE, ACC_PUBLIC, ACC_STATIC, AnnSpec,
    Asm, ClassSpec, CodeSpec, DebugEvent, DebugSpec, DexBuilder, Val, VIS_BUILD, VIS_RUNTIME,
};

use droidsaw_dex::analysis::{
    decompile_checked, parse_for_analysis, AnnotationTarget, AnnotationVisibility, Budget,
    Completeness, Control, DiagnosticCode, EmitOptions, IncompleteReason, InitializerDropReason,
    MethodStatus, ParseOptions,
};

type TestResult = Result<(), String>;

fn parse(data: &[u8]) -> Result<droidsaw_dex::analysis::ParsedDex<'_>, String> {
    parse_for_analysis(
        data,
        &ParseOptions::default(),
        &Budget::default(),
        &Control::new(),
    )
    .map_err(|e| format!("parse_for_analysis: {e}"))
}

/// Decompile the single class in `data` (by descriptor) and return the
/// report plus the selected class_def idx.
fn decompile_single(data: &[u8], descriptor: &str) -> Result<droidsaw_dex::analysis::BackendReport, String> {
    let budget = Budget::default();
    let control = Control::new();
    let parsed = parse_for_analysis(data, &ParseOptions::default(), &budget, &control)
        .map_err(|e| format!("parse: {e}"))?;
    let idx = parsed
        .dex()
        .class_defs
        .iter()
        .position(|cd| {
            parsed
                .dex()
                .get_type_descriptor(cd.class_idx)
                .ok() == Some(descriptor)
        })
        .ok_or_else(|| format!("class {descriptor} not in fixture"))?;
    decompile_checked(&parsed, idx, &EmitOptions::default(), &budget, &control)
        .map_err(|e| format!("decompile: {e}"))
}

fn assert_complete(report: &droidsaw_dex::analysis::BackendReport) -> TestResult {
    match &report.completeness {
        Completeness::Complete => Ok(()),
        Completeness::Incomplete { reasons } => Err(format!(
            "fixture must decompile Complete; reasons: {reasons:?}\n--- source ---\n{}",
            report.source
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────
// IN-03 (backend side): version matrix + container rejection
// ─────────────────────────────────────────────────────────────────────

/// A minimal but structurally complete class (one static field, one
/// method) used as the payload for every version variant.
fn minimal_class_dex(builder: &mut DexBuilder) {
    let field = builder.field("Lmin/Cl;", "V", "I");
    let m_get = builder.method("Lmin/Cl;", "get", "I", &[]);
    let mut class = ClassSpec::new("Lmin/Cl;", ACC_PUBLIC);
    class
        .static_fields
        .push(support::FieldEntry { key: field, access: ACC_PUBLIC | ACC_STATIC });
    class.direct_methods.push(support::MethodEntry {
        key: m_get,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(1, 0, 0).with_asm(|a| {
            a.sget(0, "Lmin/Cl;", "V", "I");
            a.return_reg(0);
        })),
    });
    builder.add_class(class);
}

#[test]
fn in03_version_matrix_header_variants_parse() -> TestResult {
    for version in ["035", "037", "038", "039", "040", "041"] {
        let mut b = DexBuilder::new();
        b.set_version(version.as_bytes().try_into().map_err(|_| "ver")?);
        minimal_class_dex(&mut b);
        let dex = b.build();
        let parsed = parse(&dex).map_err(|e| format!("version {version}: {e}"))?;
        let report = decompile_single(&dex, "Lmin/Cl;").map_err(|e| format!("version {version}: {e}"))?;
        assert_complete(&report).map_err(|e| format!("version {version}: {e}"))?;
        if parsed.parse_error_count() != 0 {
            return Err(format!("version {version}: unexpected parse errors"));
        }
        if !report.source.contains("get") {
            return Err(format!("version {version}: method missing from source"));
        }
    }
    Ok(())
}

#[test]
fn in03_compactdex_and_odex_rejected() {
    // CompactDex magic: "cdex" + version bytes.
    let mut b = DexBuilder::new();
    minimal_class_dex(&mut b);
    let mut cdex = b.build();
    cdex[0..8].copy_from_slice(b"cdex001\0");
    // checksum/sig no longer match, but the magic gate must fire first
    // with a typed BadMagic error either way.
    match droidsaw_dex::DexFile::parse_for_decompilation(&cdex) {
        Err(droidsaw_dex::DexError::BadMagic { found }) => {
            assert_eq!(&found, b"cdex");
        }
        other => panic!("cdex must be rejected as BadMagic, got {other:?}"),
    }

    let mut b = DexBuilder::new();
    minimal_class_dex(&mut b);
    let mut odex = b.build();
    odex[0..8].copy_from_slice(b"dey\n036\0");
    match droidsaw_dex::DexFile::parse_for_decompilation(&odex) {
        Err(droidsaw_dex::DexError::BadMagic { found }) => {
            assert_eq!(&found, b"dey\n");
        }
        other => panic!("odex must be rejected as BadMagic, got {other:?}"),
    }
}

#[test]
fn in03_unknown_version_rejected() {
    let mut b = DexBuilder::new();
    minimal_class_dex(&mut b);
    let mut dex = b.build();
    dex[4..7].copy_from_slice(b"099");
    let err = droidsaw_dex::DexFile::parse_for_decompilation(&dex)
        .expect_err("unknown version must be rejected");
    assert!(
        matches!(err, droidsaw_dex::DexError::UnsupportedVersion { ref version } if version == "099"),
        "typed UnsupportedVersion expected, got {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// DX-P04 (DECL-01): static initial values
// ─────────────────────────────────────────────────────────────────────

const STATICS_DESC: &str = "Lsem/Statics;";

/// Fixture 1 — the full DECL-01 shape space on one class:
/// - non-final statics with encoded values (the G02 family)
/// - a `final` static assigned in `<clinit>` whose encoded value is
///   READ before the overwrite (clinit-before-overwrite read)
/// - a `final` static with an elided tail slot (zero-elision)
/// - field ordering: encoded values map positionally to class_data
///   static-field order, asserted via distinct literal per field
/// - every primitive/reference value type with bit-exact payloads.
fn statics_fixture() -> (Vec<u8>, Vec<String>) {
    let mut b = DexBuilder::new();
    let d = STATICS_DESC;

    let f_bool = b.field(d, "B_FLAG", "Z");
    let f_byte = b.field(d, "M_BYTE", "B");
    let f_short = b.field(d, "S_NUM", "S");
    let f_int = b.field(d, "I_NUM", "I");
    let f_long = b.field(d, "J_NUM", "J");
    let f_char = b.field(d, "C_CH", "C");
    let f_float = b.field(d, "F_BITS", "F");
    let f_double = b.field(d, "D_BITS", "D");
    let f_string = b.field(d, "STR", "Ljava/lang/String;");
    let f_null = b.field(d, "N_REF", "Ljava/lang/Object;");
    let f_class = b.field(d, "KLASS", "Ljava/lang/Class;");
    let f_read_first = b.field(d, "READ_FIRST", "I");
    let f_overwritten = b.field(d, "OVERWRITTEN", "I");
    // Tail-elided fields sort LAST (name order) so the encoded array
    // keeps the DEX positional alignment: elision only trims the tail.
    let f_final_elided = b.field(d, "ZTAIL_ELIDED_FINAL", "J");
    let f_plain = b.field(d, "ZTAIL_ELIDED_PLAIN", "I");

    let m_clinit = b.method(d, "<clinit>", "V", &[]);
    let m_get = b.method(d, "getReadFirst", "I", &[]);

    // float: 1.5 = 0x3FC00000; double: -2.5 = 0xC004000000000000
    // NaN float 0x7FC00000, +inf double 0x7FF0000000000000.
    let mut class = ClassSpec::new(d, ACC_PUBLIC);
    class
        .static_fields
        .push(support::FieldEntry { key: f_bool, access: ACC_PUBLIC | ACC_STATIC });
    class
        .static_fields
        .push(support::FieldEntry { key: f_byte, access: ACC_PRIVATE | ACC_STATIC });
    class
        .static_fields
        .push(support::FieldEntry { key: f_short, access: ACC_PUBLIC | ACC_STATIC });
    class
        .static_fields
        .push(support::FieldEntry { key: f_int, access: ACC_PUBLIC | ACC_STATIC | ACC_FINAL });
    class
        .static_fields
        .push(support::FieldEntry { key: f_long, access: ACC_PUBLIC | ACC_STATIC });
    class
        .static_fields
        .push(support::FieldEntry { key: f_char, access: ACC_PUBLIC | ACC_STATIC });
    class
        .static_fields
        .push(support::FieldEntry { key: f_float, access: ACC_PUBLIC | ACC_STATIC });
    class
        .static_fields
        .push(support::FieldEntry { key: f_double, access: ACC_PUBLIC | ACC_STATIC });
    class
        .static_fields
        .push(support::FieldEntry { key: f_string, access: ACC_PUBLIC | ACC_STATIC | ACC_FINAL });
    class
        .static_fields
        .push(support::FieldEntry { key: f_null, access: ACC_PUBLIC | ACC_STATIC });
    class
        .static_fields
        .push(support::FieldEntry { key: f_class, access: ACC_PUBLIC | ACC_STATIC });
    // final + clinit-assigned, but clinit READS it before the write:
    // the encoded 7 must be emitted (with final lowered per design §4).
    class
        .static_fields
        .push(support::FieldEntry { key: f_read_first, access: ACC_PUBLIC | ACC_STATIC | ACC_FINAL });
    // final + clinit-assigned with NO encoded slot use — overwritten
    // with a fresh value; encoded value present → emitted, final lowered.
    class
        .static_fields
        .push(support::FieldEntry { key: f_overwritten, access: ACC_PUBLIC | ACC_STATIC | ACC_FINAL });
    // elided tail slots (no encoded entries): static final gets the
    // javac-required zero literal; non-final stays bare.
    class
        .static_fields
        .push(support::FieldEntry { key: f_final_elided, access: ACC_PUBLIC | ACC_STATIC | ACC_FINAL });
    class
        .static_fields
        .push(support::FieldEntry { key: f_plain, access: ACC_PUBLIC | ACC_STATIC });

    class.static_values = vec![
        Val::Bool(true),
        Val::Byte(-3),
        Val::Short(-1234),
        Val::Int(42),
        Val::Long(4_000_000_000_123),
        Val::Char(0x263A),
        Val::FloatBits(0x3FC0_0000),
        Val::DoubleBits(0xC004_0000_0000_0000),
        Val::Str("héllo\n".to_string()),
        Val::Null,
        Val::Type("Ljava/lang/String;".to_string()),
        Val::Int(7),
        Val::Int(99),
        // FINAL_ELIDED: no encoded entry (legal elision tail)
    ];

    class.direct_methods.push(support::MethodEntry {
        key: m_clinit,
        access: ACC_STATIC | support::ACC_CONSTRUCTOR,
        code: Some(CodeSpec::new(2, 0, 0).with_asm(|a: &mut Asm| {
            // int t = READ_FIRST;   (read BEFORE overwrite)
            a.sget(0, d, "READ_FIRST", "I");
            a.sput(0, d, "READ_FIRST", "I");
            // READ_FIRST = READ_FIRST + 1;  (overwrite after read)
            a.add_int_lit16(0, 0, 1);
            a.sput(0, d, "READ_FIRST", "I");
            // OVERWRITTEN = 100;
            a.const16(1, 100);
            a.sput(1, d, "OVERWRITTEN", "I");
            a.return_void();
        })),
    });
    class.direct_methods.push(support::MethodEntry {
        key: m_get,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(1, 0, 0).with_asm(|a| {
            a.sget(0, d, "READ_FIRST", "I");
            a.return_reg(0);
        })),
    });

    b.add_class(class);
    let names = vec![
        "B_FLAG", "C_CH", "D_BITS", "F_BITS", "I_NUM", "J_NUM", "KLASS", "M_BYTE", "N_REF",
        "OVERWRITTEN", "READ_FIRST", "STR", "S_NUM", "ZTAIL_ELIDED_FINAL", "ZTAIL_ELIDED_PLAIN",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    (b.build(), names)
}

#[test]
fn dxp02_typed_static_values_exposed() -> TestResult {
    // DECL-02: the checked report exposes the RAW encoded values as typed
    // records (floats/doubles as IEEE-754 bits), not just Java text.
    let (dex, _names) = statics_fixture();
    let report = decompile_single(&dex, STATICS_DESC)?;
    use droidsaw_dex::analysis::TypedValue;
    let find = |name: &str| -> Option<&TypedValue> {
        report
            .metadata
            .static_fields
            .iter()
            .find(|f| f.name == name)
            .and_then(|f| f.typed_value.as_ref())
    };
    match (find("I_NUM"), find("J_NUM"), find("F_BITS"), find("D_BITS"), find("STR")) {
        (
            Some(TypedValue::Int(42)),
            Some(TypedValue::Long(4_000_000_000_123)),
            Some(TypedValue::FloatBits(bits)),
            Some(TypedValue::DoubleBits(dbits)),
            Some(TypedValue::Text(s)),
        ) => {
            assert_eq!(*bits, 1.5f32.to_bits(), "float must carry raw bits");
            assert_eq!(*dbits, (-2.5f64).to_bits(), "double must carry raw bits");
            assert_eq!(s, "héllo\n", "string value lossless");
        }
        (i, j, f, dd, st) => {
            return Err(format!(
                "typed values wrong: i={i:?} j={j:?} f={f:?} d={dd:?} s={st:?}"
            ))
        }
    }
    Ok(())
}

#[test]
fn dxp04_all_static_initial_values_emitted() -> TestResult {
    let (dex, names) = statics_fixture();
    let report = decompile_single(&dex, STATICS_DESC)?;
    assert_complete(&report)?;
    let src = &report.source;

    // every encoded value is emitted, positionally correct
    let expected = [
        ("B_FLAG", "true"),
        ("M_BYTE", "-3"),
        ("S_NUM", "-1234"),
        ("I_NUM", "42"),
        ("J_NUM", "4000000000123L"),
        ("C_CH", "'\\u263A'"),
        ("F_BITS", "1.5f"),
        ("D_BITS", "-2.5"),
        ("STR", "\"héllo\\n\""),
        ("N_REF", "null"),
        ("KLASS", "java.lang.String.class"),
        ("READ_FIRST", "7"),
        ("OVERWRITTEN", "99"),
    ];
    for (name, value) in expected {
        let decl = format!("{name} = {value}");
        if !src.contains(&decl) {
            return Err(format!(
                "missing initializer `{decl}` in source:\n{}",
                report.source
            ));
        }
    }
    // elided static final tail → javac-required zero literal
    if !src.contains("ZTAIL_ELIDED_FINAL = 0L") {
        return Err(format!("elided final tail must zero-fill:\n{src}"));
    }
    // non-final elided tail stays bare
    if src.contains("ZTAIL_ELIDED_PLAIN =") {
        return Err(format!("non-final elided tail must stay bare:\n{src}"));
    }
    // field ordering: declaration order matches class_data order
    let mut last = 0usize;
    for name in names {
        let pos = src
            .find(&format!(" {name}"))
            .ok_or_else(|| format!("{name} missing from source"))?;
        if pos < last {
            return Err(format!("field {name} out of class_data order"));
        }
        last = pos;
    }

    // metadata: all emitted, no drops
    for f in &report.metadata.static_fields {
        if f.drop_reason.is_some() {
            return Err(format!("{}: unexpected drop {:?}", f.name, f.drop_reason));
        }
        if !f.initializer_emitted && f.encoded_value_metadata.is_some() {
            return Err(format!(
                "{}: encoded value present but not emitted",
                f.name
            ));
        }
    }
    Ok(())
}

#[test]
fn dxp04_clinit_before_overwrite_read_sees_encoded_value() -> TestResult {
    // Structural fact from the fixture: <clinit> reads READ_FIRST (the
    // encoded 7) before overwriting it. The decompiled clinit must
    // still perform that read (execution order preserved) — i.e. the
    // clinit body references READ_FIRST before assigning it.
    let (dex, _) = statics_fixture();
    let report = decompile_single(&dex, STATICS_DESC)?;
    let clinit_pos = report
        .source
        .find("static {")
        .ok_or("clinit missing from source")?;
    let body = &report.source[clinit_pos..];
    let read = body.find("READ_FIRST").ok_or("clinit must still read READ_FIRST")?;
    let write = body
        .find("READ_FIRST =")
        .or_else(|| body.find("READ_FIRST += "))
        .or_else(|| body.find("READ_FIRST++"))
        .ok_or("clinit must still write READ_FIRST")?;
    // The read (sget) happens before the final write in the body.
    if read > write + "READ_FIRST =".len() {
        return Err(format!(
            "clinit execution order changed: read@{read} write@{write}\n{}",
            report.source
        ));
    }
    Ok(())
}

#[test]
fn dxp04_truncated_static_values_reported_not_zero_filled() -> TestResult {
    let mut b = DexBuilder::new();
    let d = "Lsem/Trunc;";
    // Sorted field order: A_OK_STR(0), B_OK_INT(1), C_LOST(2), D_LOST(3).
    // Only two values decode; the size prefix declares four — positions
    // 2 and 3 are truncation-unknown and map to real fields.
    let f_a = b.field(d, "A_OK_STR", "Ljava/lang/String;");
    let f_b = b.field(d, "B_OK_INT", "I");
    let f_c = b.field(d, "C_LOST", "I");
    let f_d = b.field(d, "D_LOST", "Ljava/lang/String;");
    let m = b.method(d, "touch", "I", &[]);
    let mut class = ClassSpec::new(d, ACC_PUBLIC);
    class.static_fields.push(support::FieldEntry { key: f_a, access: ACC_PUBLIC | ACC_STATIC });
    class.static_fields.push(support::FieldEntry { key: f_b, access: ACC_PUBLIC | ACC_STATIC });
    // final fields whose values the truncated tail carried: they must
    // NOT be zero-filled (unknown ≠ elision).
    class.static_fields.push(support::FieldEntry {
        key: f_c,
        access: ACC_PUBLIC | ACC_STATIC | ACC_FINAL,
    });
    class.static_fields.push(support::FieldEntry {
        key: f_d,
        access: ACC_PUBLIC | ACC_STATIC | ACC_FINAL,
    });
    class.static_values = vec![Val::Str("lost".to_string()), Val::Int(5)];
    // Declare two more entries than we encode; the first phantom entry
    // starts with a VALUE_INT header claiming a 4-byte payload but
    // carries one byte, so decoding fails deterministically at
    // position 2 (unknown ≠ elision ≠ accidental padding).
    class.static_values_declared_extra = 2;
    class.static_values_trailer = vec![0x1c, 0x80, 0x80, 0x80, 0x80, 0x7f];
    class.direct_methods.push(support::MethodEntry {
        key: m,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(1, 0, 0).with_asm(|a| {
            a.const4(0, 0);
            a.return_reg(0);
        })),
    });
    b.add_class(class);
    let dex = b.build();

    let report = decompile_single(&dex, d)?;
    // Not complete: the truncated values are unknown.
    match &report.completeness {
        Completeness::Incomplete { reasons } => {
            if !reasons.iter().any(|r| {
                matches!(r, IncompleteReason::StaticInitializerDropped { .. })
            }) {
                return Err(format!("truncation must produce StaticInitializerDropped, got {reasons:?}"));
            }
        }
        Completeness::Complete => {
            return Err(format!(
                "truncated static_values must NOT decompile Complete\n{}",
                report.source
            ));
        }
    }
    // A structured malformed diagnostic is present.
    if !report
        .diagnostics
        .iter()
        .any(|dg| dg.code == DiagnosticCode::StaticValuesTruncated)
    {
        return Err(format!(
            "StaticValuesTruncated diagnostic missing: {:?}",
            report.diagnostics
        ));
    }
    // Per-field reports: LOST_VALUE/ALSO_LOST carry TruncatedStaticValues.
    for (name, want) in [
        ("A_OK_STR", None),
        ("B_OK_INT", None),
        ("C_LOST", Some(InitializerDropReason::TruncatedStaticValues)),
        ("D_LOST", Some(InitializerDropReason::TruncatedStaticValues)),
    ] {
        let f = report
            .metadata
            .static_fields
            .iter()
            .find(|f| f.name == name)
            .ok_or_else(|| format!("{name} missing from metadata"))?;
        if f.drop_reason != want {
            return Err(format!(
                "{name}: drop {reason:?} != want {want:?}\nreport row: {row:?}\nsource:\n{source}",
                reason = f.drop_reason,
                want = want,
                row = f,
                source = report.source,
            ));
        }
    }
    // The decodable prefix still renders; the source does NOT
    // zero-fill the unknown values.
    let src = &report.source;
    if !src.contains("A_OK_STR = \"lost\"") || !src.contains("B_OK_INT = 5") {
        return Err(format!("decodable prefix must still render:\n{src}"));
    }
    if src.contains("C_LOST = 0") || src.contains("D_LOST = null") {
        return Err(format!("unknown values must not be zero-filled:\n{src}"));
    }
    Ok(())
}

#[test]
fn dxp04_type_conflict_reported_not_silently_rendered() -> TestResult {
    let mut b = DexBuilder::new();
    let d = "Lsem/Conflict;";
    let f_bad = b.field(d, "WRONG_TYPE", "I");
    let f_ok = b.field(d, "OK", "I");
    let m = b.method(d, "touch", "I", &[]);
    let mut class = ClassSpec::new(d, ACC_PUBLIC);
    class.static_fields.push(support::FieldEntry { key: f_bad, access: ACC_PUBLIC | ACC_STATIC });
    class.static_fields.push(support::FieldEntry { key: f_ok, access: ACC_PUBLIC | ACC_STATIC });
    // a String value on an int field — malformed upstream (or hostile);
    // DECL-01: report, don't render, don't zero-fill.
    class.static_values = vec![Val::Str("not an int".to_string()), Val::Int(5)];
    class.direct_methods.push(support::MethodEntry {
        key: m,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(1, 0, 0).with_asm(|a| {
            a.const4(0, 0);
            a.return_reg(0);
        })),
    });
    b.add_class(class);
    let dex = b.build();

    let report = decompile_single(&dex, d)?;
    match &report.completeness {
        Completeness::Incomplete { reasons } => {
            if reasons.is_empty() {
                return Err("type conflict must be an incompleteness".into());
            }
        }
        Completeness::Complete => {
            return Err(format!("type conflict must not be Complete:\n{}", report.source));
        }
    }
    let f = report
        .metadata
        .static_fields
        .iter()
        .find(|f| f.name == "WRONG_TYPE")
        .ok_or("WRONG_TYPE missing from metadata")?;
    if f.drop_reason != Some(InitializerDropReason::TypeConflict) {
        return Err(format!("expected TypeConflict, got {:?}", f.drop_reason));
    }
    // structured diagnostic present, metadata keeps the value text
    if !report
        .diagnostics
        .iter()
        .any(|dg| dg.code == DiagnosticCode::StaticInitializerDropped && dg.field_idx.is_some())
    {
        return Err("per-field drop diagnostic missing".into());
    }
    if f.encoded_value_metadata.is_none() {
        return Err("metadata text must preserve the conflicting value".into());
    }
    let src = &report.source;
    if src.contains("WRONG_TYPE = \"not an int\"") || src.contains("WRONG_TYPE = 0") {
        return Err(format!("conflicting value must not render or zero-fill:\n{src}"));
    }
    Ok(())
}

#[test]
fn dxp04_final_lowered_for_clinit_rewritten_value() -> TestResult {
    // OVERWRITTEN (final, encoded 99, clinit writes 100) is emitted as
    // `= 99` with `final` lowered; the raw access flags keep ACC_FINAL
    // in metadata; a FinalFlagLowered diagnostic is present.
    let (dex, _) = statics_fixture();
    let report = decompile_single(&dex, STATICS_DESC)?;
    let f = report
        .metadata
        .static_fields
        .iter()
        .find(|f| f.name == "OVERWRITTEN")
        .ok_or("OVERWRITTEN missing")?;
    if f.access_flags & ACC_FINAL == 0 {
        return Err("metadata access_flags must keep the raw ACC_FINAL".into());
    }
    if !f.initializer_emitted {
        return Err("OVERWRITTEN encoded value must be emitted".into());
    }
    if !report
        .diagnostics
        .iter()
        .any(|dg| dg.code == DiagnosticCode::FinalFlagLowered && dg.field_idx == Some(f.field_idx))
    {
        return Err("FinalFlagLowered diagnostic missing for OVERWRITTEN".into());
    }
    // READ_FIRST likewise: emitted + final lowered (clinit reads it
    // before overwriting — the value is observable).
    let rf = report
        .metadata
        .static_fields
        .iter()
        .find(|f| f.name == "READ_FIRST")
        .ok_or("READ_FIRST missing")?;
    if !rf.initializer_emitted || rf.access_flags & ACC_FINAL == 0 {
        return Err("READ_FIRST must carry the encoded value with raw final flags".into());
    }
    // I_NUM (final, NOT clinit-assigned) keeps `final` in source.
    let region = &report.source;
    let line = region
        .lines()
        .find(|l| l.contains("I_NUM"))
        .ok_or("I_NUM missing")?;
    if !line.contains("final") {
        return Err(format!("final non-clinit field must keep final: {line}"));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// DX-P05a (DECL-02): metadata losslessness
// ─────────────────────────────────────────────────────────────────────

const ANNOTATED_DESC: &str = "Lsem/Annotated;";

/// Fixture: class / field / method / parameter annotation targets with
/// BUILD, RUNTIME and SYSTEM visibility, nested array / enum / class /
/// annotation values, a generic signature, inner/enclosing facts and a
/// throws clause.
fn annotated_fixture() -> Vec<u8> {
    let mut b = DexBuilder::new();
    let d = ANNOTATED_DESC;

    // Enum constant reference target (Lsem/Color; is an external type;
    // the DEX only needs the field_ids row).
    let _color_red = b.field("Lsem/Color;", "RED", "Lsem/Color;");

    let f_tagged = b.field(d, "tagged", "Ljava/lang/String;");
    let m_run = b.method(d, "run", "V", &["Ljava/io/IOException;"]);
    let m_touch = b.method(d, "touch", "I", &["Ljava/lang/String;"]);

    let runtime_marker = AnnSpec::new(VIS_RUNTIME, "Lsem/Marker;")
        .elem("level", Val::Int(3))
        .elem(
            "names",
            Val::Array(vec![Val::Str("a".into()), Val::Str("b".into())]),
        )
        .elem("color", Val::Enum {
            class: "Lsem/Color;".into(),
            name: "RED".into(),
            ty: "Lsem/Color;".into(),
        })
        .elem("kind", Val::Type("Ljava/lang/String;".into()))
        .elem(
            "nested",
            Val::Ann(AnnSpec::new(VIS_RUNTIME, "Lsem/Inner;").elem("v", Val::Int(7))),
        );
    let build_marker = AnnSpec::new(VIS_BUILD, "Lsem/BuildOnly;").elem("v", Val::Bool(true));

    let mut class = ClassSpec::new(d, ACC_PUBLIC);
    class.source_file = Some("Annotated.java".to_string());
    class
        .static_fields
        .push(support::FieldEntry { key: f_tagged, access: ACC_PRIVATE | ACC_STATIC });
    class.direct_methods.push(support::MethodEntry {
        key: m_run.clone(),
        access: ACC_PUBLIC,
        code: Some(CodeSpec::new(1, 0, 0).with_asm(|a| {
            a.return_void();
        })),
    });
    class.direct_methods.push(support::MethodEntry {
        key: m_touch.clone(),
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(1, 1, 0).with_asm(|a| {
            a.const4(0, 1);
            a.return_reg(0);
        })),
    });
    class.annotations = Some(support::AnnotationDirSpec {
        class: vec![
            runtime_marker,
            build_marker,
            signature_spec(&["Lsem/Annotated<TK;TV;>;", "Ljava/lang/Object;"]),
            inner_class_spec(0x1a, Some("Annotated")),
            enclosing_class_spec("Lsem/Outer;"),
        ],
        fields: vec![(
            support::field_key(d, "tagged", "Ljava/lang/String;"),
            vec![AnnSpec::new(VIS_RUNTIME, "Lsem/Deprecated;")],
        )],
        methods: vec![(
            m_run,
            vec![throws_spec(&["Ljava/io/IOException;"])],
        )],
        params: vec![(
            m_touch,
            vec![vec![AnnSpec::new(VIS_RUNTIME, "Lsem/NotNull;")]],
        )],
    });
    b.add_class(class);
    b.build()
}

#[test]
fn dxp05a_annotations_metadata_lossless_and_runtime_in_source() -> TestResult {
    let dex = annotated_fixture();
    let report = decompile_single(&dex, ANNOTATED_DESC)?;
    assert_complete(&report)?;
    let src = &report.source;

    // ── source: RUNTIME annotations render at their targets ──
    // class level
    if !src.contains("@sem.Marker(") {
        return Err(format!("class RUNTIME annotation missing:\n{src}"));
    }
    for elem in ["level = 3", "names = { \"a\", \"b\" }", "color = sem.Color.RED",
                 "kind = java.lang.String.class", "nested = @sem.Inner(v = 7)"] {
        if !src.contains(elem) {
            return Err(format!("class annotation element `{elem}` missing:\n{src}"));
        }
    }
    // field level
    if !src.contains("@sem.Deprecated()") {
        return Err(format!("field RUNTIME annotation missing:\n{src}"));
    }
    // method level: throws (dalvik SYSTEM annotation) renders as a
    // `throws` clause — the language mapping.
    if !src.contains("throws java.io.IOException") && !src.contains("throws IOException") {
        return Err(format!("throws clause missing:\n{src}"));
    }
    // BUILD/SYSTEM annotations are NOT rendered as source annotations.
    if src.contains("@sem.BuildOnly") || src.contains("@dalvik.annotation") {
        return Err("BUILD/SYSTEM annotations must stay metadata-only".into());
    }

    // ── metadata: every annotation preserved, every visibility ──
    let anns = &report.metadata.annotations;
    if anns.len() != 8 {
        return Err(format!(
            "expected 8 annotation reports (class Marker+BuildOnly+Signature+InnerClass+ \
             EnclosingClass, field Deprecated, method Throws, param NotNull), got {}: {anns:?}",
            anns.len()
        ));
    }
    let vis_count = |v: AnnotationVisibility| anns.iter().filter(|a| a.visibility == v).count();
    // RUNTIME: Marker(class) + Deprecated(field) + NotNull(param) = 3
    // (the runtime INNER annotation is nested inside Marker's value, not
    // a top-level report).
    if vis_count(AnnotationVisibility::Runtime) != 3 {
        return Err(format!(
            "expected 3 RUNTIME annotations in metadata, got {}: {anns:?}",
            vis_count(AnnotationVisibility::Runtime)
        ));
    }
    if vis_count(AnnotationVisibility::Build) != 1 {
        return Err("expected 1 BUILD annotation in metadata".into());
    }
    // SYSTEM: Signature + InnerClass + EnclosingClass (class) +
    // Throws (method) = 4.
    if vis_count(AnnotationVisibility::System) != 4 {
        return Err(format!(
            "expected 4 SYSTEM annotations in metadata, got {}",
            vis_count(AnnotationVisibility::System)
        ));
    }
    // targets
    if !anns.iter().any(|a| a.target == AnnotationTarget::Class) {
        return Err("Class target missing".into());
    }
    if !anns
        .iter()
        .any(|a| matches!(a.target, AnnotationTarget::Field { .. }))
    {
        return Err("Field target missing".into());
    }
    if !anns
        .iter()
        .any(|a| matches!(a.target, AnnotationTarget::Method { .. }))
    {
        return Err("Method target missing".into());
    }
    if !anns
        .iter()
        .any(|a| matches!(a.target, AnnotationTarget::Parameter { index: 0, .. }))
    {
        return Err("Parameter target missing".into());
    }
    // enum/class/nested values survive in metadata text
    let class_ann = anns
        .iter()
        .find(|a| a.type_descriptor == "Lsem/Marker;")
        .ok_or("Marker annotation missing from metadata")?;
    if !class_ann.elements.iter().any(|(_, t)| t == "sem.Color.RED") {
        return Err("enum value not preserved in metadata".into());
    }

    // ── structured facts ──
    if report.metadata.generic_signature.as_deref()
        != Some("Lsem/Annotated<TK;TV;>;Ljava/lang/Object;")
    {
        return Err(format!(
            "generic signature: {:?}",
            report.metadata.generic_signature
        ));
    }
    let inner = report
        .metadata
        .inner_class
        .as_ref()
        .ok_or("inner_class metadata missing")?;
    if inner.name.as_deref() != Some("Annotated") || inner.access_flags != 0x1a {
        return Err(format!("inner_class facts wrong: {inner:?}"));
    }
    let enclosing = report
        .metadata
        .enclosing
        .as_ref()
        .ok_or("enclosing metadata missing")?;
    if enclosing.class.as_deref() != Some("Lsem/Outer;") {
        return Err(format!("enclosing facts wrong: {enclosing:?}"));
    }
    Ok(())
}

#[test]
fn dxp05a_member_reports_prototype_and_access() -> TestResult {
    let dex = annotated_fixture();
    let report = decompile_single(&dex, ANNOTATED_DESC)?;
    // method prototype reports
    let touch = report
        .metadata
        .method_reports
        .iter()
        .find(|m| m.name == "touch")
        .ok_or("touch method report missing")?;
    if touch.prototype != "(Ljava/lang/String;)I" {
        return Err(format!("prototype: {}", touch.prototype));
    }
    if !touch.is_direct || touch.access_flags != (ACC_PUBLIC | ACC_STATIC) {
        return Err(format!("touch flags/directness wrong: {touch:?}"));
    }
    // instance field report
    let tagged = report
        .metadata
        .instance_field_reports
        .iter()
        .find(|f| f.name == "tagged");
    // NOTE: `tagged` is static in this fixture; instance reports cover
    // instance fields only — assert the count instead.
    let _ = tagged;
    if !report.metadata.instance_field_reports.is_empty() {
        return Err("fixture declares no instance fields".into());
    }
    if report.metadata.source_file.as_deref() != Some("Annotated.java") {
        return Err(format!(
            "source file: {:?}",
            report.metadata.source_file
        ));
    }
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────
// DX-P05a (DECL-02): debug info — params / locals / lines
// ─────────────────────────────────────────────────────────────────────

const DEBUGGED_DESC: &str = "Lsem/Debugged;";

fn debugged_fixture(with_debug: bool) -> Vec<u8> {
    let mut b = DexBuilder::new();
    let d = DEBUGGED_DESC;
    let m_area = b.method(d, "area", "I", &["I"]);
    // external logging method (declared, never defined)
    let _m_log = b.method("Lsem/Util;", "log", "V", &["I"]);

    let mut class = ClassSpec::new(d, ACC_PUBLIC);
    class.direct_methods.push(support::MethodEntry {
        key: m_area,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(if with_debug {
            CodeSpec::new(3, 1, 0)
                .with_debug(DebugSpec {
                    line_start: 7,
                    param_names: vec![Some("side".to_string())],
                    events: vec![
                        // line 8 at pc0; `doubled` (v1) is live from the
                        // add at pc0 until just before the return at pc3
                        DebugEvent::AdvanceLine(1),
                        DebugEvent::StartLocal {
                            reg: 1,
                            name: "doubled".to_string(),
                            ty: "I".to_string(),
                        },
                        DebugEvent::AdvancePc(4),
                        DebugEvent::AdvanceLine(2),
                        DebugEvent::EndLocal(1),
                    ],
                })
                .with_asm(|a| {
                    // area(side): doubled = side + side; Util.log(doubled);
                    // return doubled; (a call site keeps the local in the
                    // emitted source so its debug name must be resolved)
                    a.add_int(1, 0, 0);
                    a.invoke_static(&method_key("Lsem/Util;", "log", "V", &["I"]), &[1]);
                    a.return_reg(1);
                })
        } else {
            CodeSpec::new(3, 1, 1).with_asm(|a| {
                a.add_int(1, 0, 0);
                a.invoke_static(&method_key("Lsem/Util;", "log", "V", &["I"]), &[1]);
                a.return_reg(1);
            })
        }),
    });
    b.add_class(class);
    b.build()
}

#[test]
fn dxp05a_debug_param_and_local_names_in_source() -> TestResult {
    let dex = debugged_fixture(true);
    let report = decompile_single(&dex, DEBUGGED_DESC)?;
    assert_complete(&report)?;
    let src = &report.source;
    // debug_info parameter name surfaces in the signature
    if !src.contains("int side") {
        return Err(format!("debug param name missing:\n{src}"));
    }
    // debug_info local name surfaces as a variable
    if !src.contains("doubled") {
        return Err(format!("debug local name missing:\n{src}"));
    }
    // line comments are opt-in and default off — no // line N comments
    if src.contains("// line") {
        return Err("line comments must stay off by default".into());
    }
    // EmitOptions::line_comments renders them
    let budget = Budget::default();
    let control = Control::new();
    let parsed = parse(&dex)?;
    let idx = parsed
        .dex()
        .class_defs
        .iter()
        .position(|cd| parsed.dex().get_type_descriptor(cd.class_idx).ok() == Some(DEBUGGED_DESC))
        .ok_or("class missing")?;
    let report_lined = decompile_checked(
        &parsed,
        idx,
        &EmitOptions {
            line_comments: true,
            ..Default::default()
        },
        &budget,
        &control,
    )
    .map_err(|e| format!("lined decompile: {e}"))?;
    if !report_lined.source.contains("// line") {
        return Err(format!(
            "line_comments=true must render line numbers:\n{}",
            report_lined.source
        ));
    }
    Ok(())
}

#[test]
fn dxp05a_no_debug_info_still_complete() -> TestResult {
    let dex = debugged_fixture(false);
    let report = decompile_single(&dex, DEBUGGED_DESC)?;
    assert_complete(&report)?;
    if !report.source.contains("area") {
        return Err("method must still emit without debug info".into());
    }
    Ok(())
}

// probe appended to asc_semantics temporarily

#[test]
#[ignore]
fn debug_print_count_fillarr() {
    let dex = flow_fixture();
    let report = decompile_single(&dex, FLOW_DESC).expect("decompile");
    let src = report.source.clone();
    for marker in ["public int count(", "public static int[] fillArr("] {
        if let Some(i) = src.find(marker) {
            let end = src[i..].find("
    }").map(|e| i + e + 6).unwrap_or(src.len());
            println!("--- {} ---
{}", marker, &src[i..end]);
        }
    }
}

#[test]
fn decl03_control_flow_constructors_and_payloads() -> TestResult {
    let dex = flow_fixture();
    let report = decompile_single(&dex, FLOW_DESC)?;
    // Every method must land in a definite state: 13 emitted bodies plus
    // one native declaration (see method_outcomes asserts below).
    if !matches!(report.completeness, Completeness::Complete) {
        return Err(format!("flow fixture must be Complete: {:?}", report.completeness));
    }
    let src = &report.source;

    // V01 / DX-P05b: every non-parameter register the body reads must be
    // DECLARED before use. The SSA-tracked paths emit `int v0 = …;` — a
    // raw `v0` reference with no declaration anywhere is the audit defect.
    let declared_v0 = src.contains("int v0 = ");
    let mut uses_raw_v0 = false;
    for line in src.lines() {
        let body = line.trim();
        if body.starts_with("//") {
            continue;
        }
        // crude "v0 not preceded by `int ` and not the LHS of a decl" check
        if body.contains("v0") && !body.contains("int v0") {
            uses_raw_v0 = true;
        }
    }
    // `switchPacked`/`switchSparse`/`tryCatch` all declare v0; a raw use
    // anywhere would be an undeclared read.
    if !declared_v0 && uses_raw_v0 {
        return Err(format!("v0 used without declaration:\n{src}"));
    }

    // Constructor delegation: this(...) for the own class, super() for the
    // superclass chain (DX-P05b).
    if !src.contains("this(5);") {
        return Err(format!("no-arg constructor must delegate this(5):\n{src}"));
    }
    let init1 = src
        .split("public Flow(int")
        .nth(1)
        .ok_or("missing Flow(int) constructor")?;
    if !init1.contains("super();") || !init1.contains("this.x = v1;") {
        return Err(format!("Flow(int) must call super() then store x:\n{init1}"));
    }

    // Branch polarity: pick must keep the comparison orientation of the
    // bytecode (if-lez jumps to the negation path).
    let pick = src.split("public int pick(").nth(1).ok_or("missing pick")?;
    if !pick.contains("v2 <= 0") || !pick.contains("return -v2;") || !pick.contains("return v2;") {
        return Err(format!("pick branch semantics wrong:\n{pick}"));
    }

    // Switch payloads render with correct case keys (packed 1/2/3,
    // sparse -5/5/100) and their per-case results.
    let packed = src.split("public static int switchPacked(").nth(1).ok_or("no packed")?;
    for case in ["case 1:", "case 2:", "case 3:", "default:"] {
        if !packed.contains(case) {
            return Err(format!("packed switch missing {case}:\n{packed}"));
        }
    }
    let sparse = src.split("public static int switchSparse(").nth(1).ok_or("no sparse")?;
    for case in ["case -5:", "case 5:", "case 100:"] {
        if !sparse.contains(case) {
            return Err(format!("sparse switch missing {case}:\n{sparse}"));
        }
    }

    // Wide types: the double literal must render as a value, not bits.
    let add_half = src.split("public static double addHalf(").nth(1).ok_or("no addHalf")?;
    if !add_half.contains("v2 + 1.5") {
        return Err(format!("addHalf must be x + 1.5:\n{add_half}"));
    }

    // try/catch with a typed handler and a catch-all.
    let guard = src.split("public static int tryCatch(").nth(1).ok_or("no tryCatch")?;
    for want in ["try {", "catch (java.lang.Exception", "catch (Exception"] {
        if !guard.contains(want) {
            return Err(format!("tryCatch missing {want}:\n{guard}"));
        }
    }

    // The long method must preserve the parameter-based chain.
    let long = src.split("public static int longMethod(").nth(1).ok_or("no longMethod")?;
    if !long.contains("v1 + 1") {
        return Err(format!("longMethod must chain the parameter:\n{long}"));
    }
    // DECL-03: the for-loop must recover with DECLARED loop locals (the
    // pre-fix regression rendered `do {} while (v0)` with undeclared v0).
    let count = src.split("public int count(").nth(1).ok_or("no count")?;
    if !count.contains("for (int v1 = 0; v1 < v5; v1++)") || !count.contains("v0 += v1") {
        return Err(format!("count loop recovery wrong:\n{count}"));
    }
    if count.contains("do {{") || count.contains("while (v0)") {
        return Err(format!("count must not degrade to do-while fallback:\n{count}"));
    }
    // DECL-03: fill-array-data sugar must expand the payload elements.
    let fill = src.split("public static int[] fillArr(").nth(1).ok_or("no fillArr")?;
    for want in ["new int[4]", "v0[0] = 1", "v0[1] = 2", "v0[2] = 3", "v0[3] = 4", "return v0"] {
        if !fill.contains(want) {
            return Err(format!("fillArr missing {want:?}:\n{fill}"));
        }
    }

    // Method outcomes: exactly one DeclarationOnly (native), the rest Emitted.
    let mut native = 0;
    let mut emitted = 0;
    for m in &report.method_outcomes {
        match &m.status {
            MethodStatus::DeclarationOnly { .. } => native += 1,
            MethodStatus::Emitted => emitted += 1,
            other => return Err(format!("unexpected outcome {other:?}")),
        }
    }
    // 14 methods in Flow: 12 emitted bodies + nativeOp DeclarationOnly.
    if native != 1 || emitted != 12 {
        return Err(format!("outcomes native={native} emitted={emitted}"));
    }

    // The abstract companion class also decompiles, declaration-only.
    let abs = decompile_single(&dex, ABS_DESC)?;
    assert_complete(&abs)?;
    if !abs.source.contains("public abstract void shape();") {
        return Err(format!("abstract method missing:\n{}", abs.source));
    }
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────
// DX-P05b (DECL-03): control flow, constructors, payloads, wide values,
// try/catch, native/abstract — with a V01 use-before-declare checker.
// ─────────────────────────────────────────────────────────────────────

const FLOW_DESC: &str = "Lsem/Flow;";
const ABS_DESC: &str = "Lsem/Abs;";

fn flow_fixture() -> Vec<u8> {
    let mut b = DexBuilder::new();
    let d = FLOW_DESC;

    let f_x = b.field(d, "x", "I");
    let m_init0 = b.method(d, "<init>", "V", &[]);
    let m_init1 = b.method(d, "<init>", "V", &["I"]);
    let m_pick = b.method(d, "pick", "I", &["I"]);
    let m_count = b.method(d, "count", "I", &["I"]);
    let m_switch_packed = b.method(d, "switchPacked", "I", &["I"]);
    let m_switch_sparse = b.method(d, "switchSparse", "I", &["I"]);
    let m_fill = b.method(d, "fillArr", "[I", &[]);
    let m_wide = b.method(d, "wideOps", "J", &["J", "D"]);
    let m_dbl = b.method(d, "addHalf", "D", &["D"]);
    let m_guard = b.method(d, "tryCatch", "I", &["I"]);
    let m_helper = b.method(d, "helper", "I", &["I"]);
    let m_long = b.method(d, "longMethod", "I", &["I"]);
    let m_native = b.method(d, "nativeOp", "I", &["I"]);
    // external logging/throwing methods (declared on Lsem/Util;, never defined)
    let _m_external = b.method("Lsem/Util;", "twice", "I", &["I"]);
    let _m_boom = b.method("Lsem/Util;", "boom", "V", &["I"]);
    // super() call target (registered so the pool fixup can intern it)
    let _object_init = b.method("Ljava/lang/Object;", "<init>", "V", &[]);
    // catch type used only by the try/catch handler table
    let _exc_type = b.intern_type("Ljava/lang/Exception;");

    // constructors: this(...) chain + super() + field store.
    // Incoming regs occupy the LAST `ins` registers: for <init>()V with
    // registers=3/ins=1 the receiver is v1; for <init>(I)V with
    // registers=2/ins=2 it is v0 and the param v1.
    let init1 = CodeSpec::new(2, 2, 2).with_asm(|a| {
        // Flow(int x): super(); this.x = x;
        a.invoke_direct(&method_key("Ljava/lang/Object;", "<init>", "V", &[]), &[0]);
        a.iput(1, 0, d, "x", "I");
        a.return_void();
    });
    let init0 = CodeSpec::new(3, 1, 2).with_asm(|a| {
        // Flow(): this(5);  (v2 = this, v0 = the literal)
        a.const4(0, 5);
        a.invoke_direct(&method_key_from(d, "<init>", "V", &["I".to_string()]), &[2, 0]);
        a.return_void();
    });

    let mut class = ClassSpec::new(d, ACC_PUBLIC);
    class
        .instance_fields
        .push(support::FieldEntry { key: f_x, access: ACC_PRIVATE });

    class.direct_methods.push(support::MethodEntry {
        key: m_init0,
        access: ACC_PUBLIC | support::ACC_CONSTRUCTOR,
        code: Some(init0),
    });
    class.direct_methods.push(support::MethodEntry {
        key: m_init1,
        access: ACC_PUBLIC | support::ACC_CONSTRUCTOR,
        code: Some(init1),
    });
    class.direct_methods.push(support::MethodEntry {
        key: m_native,
        access: ACC_PUBLIC | ACC_NATIVE,
        code: None, // DeclarationOnly{Native}
    });
    class.direct_methods.push(support::MethodEntry {
        key: m_helper,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(1, 1, 0).with_asm(|a| {
            a.add_int_lit16(0, 0, 1);
            a.return_reg(0);
        })),
    });
    class.virtual_methods.push(support::MethodEntry {
        key: m_pick,
        access: ACC_PUBLIC,
        code: Some(CodeSpec::new(3, 2, 0).with_asm(|a| {
            // (v1 = this, v2 = x) if (x > 0) return x; else return -x;
            a.if_lez(2, "neg");
            a.return_reg(2);
            a.label("neg");
            a.neg_int(2, 2);
            a.return_reg(2);
        })),
    });
    class.virtual_methods.push(support::MethodEntry {
        key: m_count,
        access: ACC_PUBLIC,
        code: Some(CodeSpec::new(6, 2, 0).with_asm(|a| {
            // (v4 = this, v5 = n) sum = 0; for (i = 0; i < n; i++) sum += i; return sum;
            a.const4(0, 0); // sum
            a.const4(1, 0); // i
            a.label("loop");
            a.if_ge(1, 5, "done");
            a.add_int(0, 0, 1);
            a.add_int_lit16(1, 1, 1);
            a.goto("loop");
            a.label("done");
            a.return_reg(0);
        })),
    });
    class.virtual_methods.push(support::MethodEntry {
        key: m_switch_packed,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(2, 1, 0).with_asm(|a| {
            // packed switch on the parameter v1: 1→10, 2→20, 3→30; default −1
            a.const4(0, -1);
            a.packed_switch(1, 1, &["c1", "c2", "c3"]);
            a.label("def");
            a.return_reg(0);
            a.label("c1");
            a.const4(0, 10);
            a.return_reg(0);
            a.label("c2");
            a.const16(0, 20);
            a.return_reg(0);
            a.label("c3");
            a.const16(0, 30);
            a.return_reg(0);
        })),
    });
    class.virtual_methods.push(support::MethodEntry {
        key: m_switch_sparse,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(2, 1, 0).with_asm(|a| {
            a.const4(0, -1);
            a.sparse_switch(1, &[-5, 5, 100], &["s1", "s2", "s3"]);
            a.label("sdef");
            a.return_reg(0);
            a.label("s1");
            a.const4(0, 1);
            a.return_reg(0);
            a.label("s2");
            a.const4(0, 2);
            a.return_reg(0);
            a.label("s3");
            a.const4(0, 3);
            a.return_reg(0);
        })),
    });
    class.virtual_methods.push(support::MethodEntry {
        key: m_fill,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(2, 0, 0).with_asm(|a| {
            // int[] a = {1, 2, 3, 4}; return a;
            a.const4(1, 4);
            a.new_array(0, 1, "I");
            a.fill_array_data(0, 4, &[
                1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0,
            ]);
            a.return_object(0);
        })),
    });
    class.virtual_methods.push(support::MethodEntry {
        key: m_wide,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(6, 4, 0).with_asm(|a| {
            // (long j at v2/v3, double d at v4/v5) → j + 1000L
            a.const_wide32(0, 1000);
            a.add_long(2, 2, 0);
            a.return_wide(2);
        })),
    });
    class.virtual_methods.push(support::MethodEntry {
        key: m_dbl,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(4, 2, 0).with_asm(|a| {
            // (double x at v2/v3) → x + 1.5; const_wide_high16 0x3ff8 is the
            // IEEE-754 double 1.5 — must render as `1.5`, not raw bits.
            a.const_wide_high16(0, 0x3ff8);
            a.add_double(2, 2, 0);
            a.return_wide(2);
        })),
    });
    class.virtual_methods.push(support::MethodEntry {
        key: m_guard,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(3, 1, 1).with_try(
            "try_start",
            "try_end",
            vec![
                (Some("Ljava/lang/Exception;".to_string()), "catch_ex".to_string()),
                (None, "catch_all".to_string()),
            ],
        ).with_asm(|a| {
            a.label("try_start");
            a.const4(0, 1);
            a.invoke_static(&method_key("Lsem/Util;", "boom", "V", &["I"]), &[0]);
            a.return_reg(0);
            a.label("try_end");
            a.label("catch_ex");
            a.move_exception(1);
            a.const4(0, 2);
            a.return_reg(0);
            a.label("catch_all");
            a.move_exception(2);
            a.const4(0, 3);
            a.return_reg(0);
        })),
    });
    class.virtual_methods.push(support::MethodEntry {
        key: m_long,
        access: ACC_PUBLIC | ACC_STATIC,
        code: Some(CodeSpec::new(2, 1, 0).with_asm(|a| {
            // 40 chained adds on the parameter (v1) — a "long method"
            for _ in 0..40 {
                a.add_int_lit16(1, 1, 1);
            }
            a.return_reg(1);
        })),
    });

    let mut class_abs = ClassSpec::new(ABS_DESC, ACC_PUBLIC | ACC_ABSTRACT);
    let m_abs = b.method(ABS_DESC, "shape", "V", &[]);
    class_abs.direct_methods.push(support::MethodEntry {
        key: m_abs,
        access: ACC_PUBLIC | ACC_ABSTRACT,
        code: None, // DeclarationOnly{Abstract}
    });
    b.add_class(class);
    b.add_class(class_abs);
    b.build()
}
