//! ASC controlled-interface contract tests (work package A04, patch
//! ledger DX-P03; acceptance BACK-01/02/03, DECL-04 rails).
//!
//! `harness = false` on purpose: the env matrix test spawns this very
//! binary as a child process (`<exe> child-probe <out-file>`) with
//! every known `DROIDSAW*` switch set, and asserts the child produces
//! byte-empty stdout/stderr — impossible under the libtest harness,
//! which always prints its own summary. The root crate's
//! `tests/self_contained.rs` scans `src/` only (never `vendor/`), so
//! `std::process::Command` here does not violate the "production code
//! spawns no processes" rule.
//!
//! Fixtures are read via compile-time `include_bytes!` relative paths
//! into the repository's shared contract fixtures — no runtime path
//! dependence, no sibling-checkout requirement:
//! `tests/fixtures/contracts/inputs/g02-static-initializers.dex`
//! (sha256 5686e4a48559d4a641cb56c6b40c6e22a432bedde96651e7786a57782cef20fe,
//!  pinned byte-exact to the Python baseline by the root harness).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::process::Command;

use droidsaw_dex::analysis::{
    parse_for_analysis, BackendError, Completeness, Control, DiagnosticCode, EmitOptions,
    IncompleteReason, MethodStatus, ParseOptions, ParseScope,
};
use droidsaw_dex::analysis::decompile_checked;
use droidsaw_dex::DexFile;

const G02: &[u8] =
    include_bytes!("fixtures/g02-static-initializers.dex");
const G02_DESCRIPTOR: &str = "Lexample/Statics;";

const CHILD_ENV_SWITCHES: [(&str, &str); 7] = [
    ("DROIDSAW_DECOMPILE_TRACE", "1"),
    ("DROIDSAW_PANIC_ON_DECOMPILE_ERR", "1"),
    ("DROIDSAW_DEX_EMIT_LINE_COMMENTS", "1"),
    ("DROIDSAW_DUMP", "all"),
    ("DROIDSAW_DUMP_MAX_STAGES", "1"),
    ("DROIDSAW_CRASH_DIR", "crash-dir-should-not-be-created"),
    ("DROIDSAW_DEBUG_PRESERVE", "1"),
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("child-probe") {
        let out_path = args.get(2).cloned().unwrap_or_default();
        child_probe(&out_path);
        return;
    }

    let mut failures: Vec<&'static str> = Vec::new();
    for (name, result) in [
        ("env_switches_are_inert", env_switches_are_inert()),
        ("g02_static_initializers_emitted", g02_report()),
        ("declaration_only_outcome", declaration_only_outcome()),
        ("failed_method_outcome", failed_method_outcome()),
        ("cancel_and_deadline", cancel_and_deadline()),
        ("scoped_parse_equivalence", scoped_parse_equivalence()),
        ("legacy_bridge_matches_checked", legacy_bridge()),
        ("input_budget_cap", input_budget_cap()),
    ] {
        match result {
            Ok(()) => println!("ok   {name}"),
            Err(e) => {
                eprintln!("FAIL {name}: {e}");
                failures.push(name);
            }
        }
    }
    if failures.is_empty() {
        println!("asc_contracts: all tests passed");
    } else {
        eprintln!("asc_contracts: {} failing: {}", failures.len(), failures.join(", "));
        std::process::exit(1);
    }
}

type TestResult = Result<(), String>;

// ─────────────────────────────────────────────────────────────────────
// BACK-02: env switch matrix in a subprocess
// ─────────────────────────────────────────────────────────────────────

/// Child mode: run the normal fixture, the failing-method variant and
/// the declaration-only variant through the checked entry points and
/// write a digest of all three reports to `out_path`. Writes nothing
/// to stdout/stderr on success.
fn child_probe(out_path: &str) {
    let normal = decompile_g02(G02.to_vec());
    let corrupted = decompile_g02(corrupt_first_insn_opcode(G02));
    let abstracted = decompile_g02(make_method_declaration_only(G02));
    let digest = digest_of(&[
        format!("{normal:?}"),
        format!("{corrupted:?}"),
        format!("{abstracted:?}"),
    ]);
    std::fs::write(out_path, digest).expect("child writes digest file");
}

fn env_switches_are_inert() -> TestResult {
    let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let digest_clean_path = tmp.path().join("digest-clean");
    let digest_dirty_path = tmp.path().join("digest-dirty");

    let run_child = |out_path: &std::path::Path, dirty: bool| -> TestResult {
        let mut cmd = Command::new(&exe);
        cmd.arg("child-probe").arg(out_path);
        // Strip any ambient DROIDSAW switches for the clean run.
        for (key, _) in CHILD_ENV_SWITCHES {
            cmd.env_remove(key);
        }
        if dirty {
            for (key, value) in CHILD_ENV_SWITCHES {
                cmd.env(key, value);
            }
            cmd.env("RAYON_NUM_THREADS", "1");
        }
        let output = cmd
            .output()
            .map_err(|e| format!("spawn child: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "child exited {:?}; stderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        if !output.stdout.is_empty() {
            return Err(format!(
                "child wrote {} bytes to stdout: {:?}",
                output.stdout.len(),
                String::from_utf8_lossy(&output.stdout)
            ));
        }
        if !output.stderr.is_empty() {
            return Err(format!(
                "child wrote {} bytes to stderr: {:?}",
                output.stderr.len(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    };

    run_child(&digest_clean_path, false)?;
    run_child(&digest_dirty_path, true)?;
    // Also assert the crash-dir side effect never materialized.
    let crash_dir = tmp.path().join("crash-dir-should-not-be-created");
    if crash_dir.exists() {
        return Err("child created DROIDSAW_CRASH_DIR directory".to_string());
    }
    let clean = std::fs::read_to_string(&digest_clean_path).map_err(|e| format!("{e}"))?;
    let dirty = std::fs::read_to_string(&digest_dirty_path).map_err(|e| format!("{e}"))?;
    if clean != dirty {
        return Err(format!(
            "results differ between clean and DROIDSAW-switched env: {clean} vs {dirty}"
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Shared checked-path driver + fixture mutation helpers
// ─────────────────────────────────────────────────────────────────────

fn decompile_g02(data: Vec<u8>) -> droidsaw_dex::analysis::BackendReport {
    let options = ParseOptions::default();
    let budget = droidsaw_dex::analysis::Budget::default();
    let control = Control::new();
    let parsed = parse_for_analysis(&data, &options, &budget, &control)
        .expect("parse_for_analysis on G02 fixture");
    let idx = find_statics_class_def_idx(parsed.dex())
        .expect("G02 fixture declares Lexample/Statics;");
    decompile_checked(&parsed, idx, &EmitOptions::default(), &budget, &control)
        .expect("decompile_checked on G02 fixture")
}

fn find_statics_class_def_idx(dex: &DexFile) -> Option<usize> {
    dex.class_defs
        .iter()
        .position(|cd| dex.get_type_descriptor(cd.class_idx).ok() == Some(G02_DESCRIPTOR))
}

fn digest_of(parts: &[String]) -> String {
    let mut hasher = DefaultHasher::new();
    for p in parts {
        p.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

/// DEX header `file_size` (u32 LE at offset 32).
fn dex_file_size(data: &[u8]) -> usize {
    u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as usize
}

/// Recompute the Adler-32 checksum over `[12..file_size]` and store it
/// (u32 LE at offset 8) so the mutated bytes still parse.
fn fix_adler32(data: &mut [u8]) {
    let end = dex_file_size(data);
    let checksum = adler2::adler32_slice(&data[12..end]);
    data[8..12].copy_from_slice(&checksum.to_le_bytes());
}

fn read_uleb(data: &[u8], off: usize) -> (u32, usize) {
    let mut result: u32 = 0;
    let mut shift = 0;
    let mut i = off;
    loop {
        let byte = data[i];
        result |= u32::from(byte & 0x7f) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (result, i - off)
}

/// Redundantly padded ULEB128 encoding of exactly `len` bytes (trailing
/// zero groups keep the total byte length of the rewritten entry
/// constant so no following offsets shift).
fn write_uleb_padded(buf: &mut [u8], off: usize, value: u32, len: usize) {
    for i in 0..len {
        let mut byte = ((value >> (7 * i)) & 0x7f) as u8;
        if i + 1 < len {
            byte |= 0x80;
        }
        buf[off + i] = byte;
    }
}

/// Walk the G02 class_data and return, for the method entry named
/// `name`: (access_flags, code_off, flags_off, flags_len, code_off_off,
/// code_off_len).
struct MethodEntryPatch {
    access_flags: u32,
    code_off: u32,
    flags_off: usize,
    flags_len: usize,
    /// Reserved for the static_values_off relocation the truncated-array
    /// fixtures may need; currently the patcher edits values in place.
    #[allow(dead_code)]
    code_off_off: usize,
    code_off_len: usize,
}

fn locate_class_data_method(data: &[u8], name: &str) -> Option<MethodEntryPatch> {
    // Checked path only — this helper also runs inside the env-matrix
    // child process, which must never touch the legacy env-reading
    // entries.
    let parsed = parse_for_analysis(
        data,
        &ParseOptions::default(),
        &droidsaw_dex::analysis::Budget::default(),
        &Control::new(),
    )
    .ok()?;
    let dex = parsed.dex();
    let idx = find_statics_class_def_idx(dex)?;
    let class_def = dex.class_defs.get(idx)?;
    let target_method_idx = dex
        .methods
        .iter()
        .position(|m| {
            m.class_idx == class_def.class_idx
                && dex.get_string(m.name_idx).ok() == Some(name)
        })? as u32;
    let cd_off = class_def.class_data_off as usize;
    let mut pos = cd_off;
    let (static_n, l) = read_uleb(data, pos);
    pos += l;
    let (instance_n, l) = read_uleb(data, pos);
    pos += l;
    let (direct_n, l) = read_uleb(data, pos);
    pos += l;
    let (virtual_n, l) = read_uleb(data, pos);
    pos += l;
    // field entries: 2 ulebs each
    for _ in 0..(static_n + instance_n) {
        let (_, l) = read_uleb(data, pos);
        pos += l;
        let (_, l) = read_uleb(data, pos);
        pos += l;
    }
    // method entries: 3 ulebs each; method_idx_diff restarts at 0 per list
    for list_len in [direct_n, virtual_n] {
        let mut method_idx: u32 = 0;
        for _ in 0..list_len {
            let (diff, l) = read_uleb(data, pos);
            pos += l;
            method_idx += diff;
            let flags_off = pos;
            let (flags, fl) = read_uleb(data, pos);
            pos += fl;
            let code_off_off = pos;
            let (code_off, cl) = read_uleb(data, pos);
            pos += cl;
            if method_idx == target_method_idx {
                return Some(MethodEntryPatch {
                    access_flags: flags,
                    code_off,
                    flags_off,
                    flags_len: fl,
                    code_off_off,
                    code_off_len: cl,
                });
            }
        }
    }
    None
}

/// Rewrite `getSecond` to `abstract` with `code_off = 0`, preserving
/// the class_data byte length via padded ULEB128, then fix the
/// checksum. Produces a DeclarationOnly outcome fixture.
fn make_method_declaration_only(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let entry = locate_class_data_method(&out, "getSecond").expect("locate getSecond");
    let new_flags = entry.access_flags | 0x0400; // ACC_ABSTRACT
    let mut flags_len = 1usize;
    while (new_flags >> (7 * flags_len)) != 0 {
        flags_len += 1;
    }
    // code_off = 0, written directly after the (possibly longer) new
    // flags encoding and padded so the total entry length is unchanged.
    let total_old = entry.flags_len + entry.code_off_len;
    let code_len = total_old.checked_sub(flags_len).filter(|l| *l >= 1).unwrap_or(1);
    write_uleb_padded(&mut out, entry.flags_off, new_flags, flags_len);
    write_uleb_padded(&mut out, entry.flags_off + flags_len, 0, code_len);
    fix_adler32(&mut out);
    out
}

/// Make `getSecond`'s code item undecodable: set `insns_size` to a
/// value far past EOF so `parse_code_item` fails while decoding the
/// instruction stream, then fix the checksum. Produces a Failed
/// method outcome. (Corrupting a single opcode byte is NOT enough:
/// the tolerant parser records unmapped opcode bytes as invariant
/// violations and skips them — the method would still emit.)
fn corrupt_first_insn_opcode(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let entry = locate_class_data_method(&out, "getSecond").expect("locate getSecond");
    let insns_size_off = entry.code_off as usize + 12; // u32 LE in the code_item header
    out[insns_size_off..insns_size_off + 4].copy_from_slice(&0x00ff_00ffu32.to_le_bytes());
    fix_adler32(&mut out);
    out
}

// ─────────────────────────────────────────────────────────────────────
// G02 fixed behaviour (DX-P04, A05): encoded initial values emitted
// ─────────────────────────────────────────────────────────────────────

fn g02_report() -> TestResult {
    let report = decompile_g02(G02.to_vec());

    // PATCHED (asc, DX-P04, A05): the G02 defect is fixed. FIRST/SECOND
    // are non-final static fields with encoded_array values 11/22; the
    // declaration now carries the initializers and the report is
    // Complete. (A04's intermediate "defect-as-data" state —
    // Incomplete + NonFinalStatic drops + bare declarations — is pinned
    // by git history; this test is the A05 acceptance target.)
    if !matches!(&report.completeness, Completeness::Complete) {
        return Err(format!(
            "G02 must be Complete after the DX-P04 fix, got {:?}",
            report.completeness
        ));
    }

    for (name, value) in [("FIRST", "11"), ("SECOND", "22")] {
        let field = report
            .metadata
            .static_fields
            .iter()
            .find(|f| f.name == name)
            .ok_or_else(|| format!("static field {name} missing from metadata"))?;
        if field.encoded_value_java.as_deref() != Some(value) {
            return Err(format!(
                "{name}: encoded value must be visible as {value}, got {:?}",
                field.encoded_value_java
            ));
        }
        if !field.initializer_emitted {
            return Err(format!(
                "{name}: the encoded initializer must be emitted in the declaration"
            ));
        }
        if field.drop_reason.is_some() {
            return Err(format!(
                "{name}: no drop reason may remain after the fix, got {:?}",
                field.drop_reason
            ));
        }
        let expected_decl = format!("{name} = {value}");
        if !report.source.contains(&expected_decl) {
            return Err(format!(
                "source must contain the emitted initializer `{expected_decl}`"
            ));
        }
    }

    // Methods: getSecond has a body and emits.
    let emitted: Vec<&str> = report
        .method_outcomes
        .iter()
        .filter(|m| matches!(m.status, MethodStatus::Emitted))
        .map(|m| m.name.as_str())
        .collect();
    for expected in ["getSecond"] {
        if !emitted.contains(&expected) {
            return Err(format!("{expected} must be Emitted, outcomes: {emitted:?}"));
        }
    }
    if !report.source.contains("getSecond") {
        return Err("source must contain getSecond".into());
    }
    if report.metadata.descriptor != G02_DESCRIPTOR {
        return Err(format!("descriptor: {}", report.metadata.descriptor));
    }
    if report.metadata.static_fields.len() != 2 {
        return Err("expected exactly two static fields in metadata".into());
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// DECL-04 rails: declaration-only and failed outcomes
// ─────────────────────────────────────────────────────────────────────

fn declaration_only_outcome() -> TestResult {
    let data = make_method_declaration_only(G02);
    let report = decompile_g02(data);
    let outcome = report
        .method_outcomes
        .iter()
        .find(|m| m.name == "getSecond")
        .ok_or("getSecond outcome missing")?;
    match &outcome.status {
        MethodStatus::DeclarationOnly { kind } => {
            if !matches!(kind, droidsaw_dex::analysis::DeclarationKind::Abstract) {
                return Err(format!("expected Abstract, got {kind:?}"));
            }
        }
        other => return Err(format!("expected DeclarationOnly, got {other:?}")),
    }
    // A declaration-only method is a legal no-body shape and must NOT
    // by itself make the report incomplete (the G02 drop still does).
    if let Completeness::Incomplete { reasons } = &report.completeness {
        for reason in reasons {
            if !matches!(
                reason,
                IncompleteReason::StaticInitializerDropped { .. }
            ) {
                return Err(format!(
                    "declaration-only must not add incompleteness, got {reason:?}"
                ));
            }
        }
    }
    if !report.source.contains("getSecond") {
        return Err("declaration must still be rendered".into());
    }
    Ok(())
}

fn failed_method_outcome() -> TestResult {
    let data = corrupt_first_insn_opcode(G02);
    let report = decompile_g02(data);
    let outcome = report
        .method_outcomes
        .iter()
        .find(|m| m.name == "getSecond")
        .ok_or("getSecond outcome missing")?;
    match &outcome.status {
        MethodStatus::Failed { detail } => {
            if detail.is_empty() {
                return Err("failed outcome must carry a reason".into());
            }
        }
        other => return Err(format!("expected Failed, got {other:?}")),
    }
    let has_failed_reason = matches!(
        &report.completeness,
        Completeness::Incomplete { reasons } if reasons
            .iter()
            .any(|r| matches!(r, IncompleteReason::MethodFailed { method_idx: _ }))
    );
    if !has_failed_reason {
        return Err("Completeness must carry MethodFailed for the corrupted method".into());
    }
    if !report
        .diagnostics
        .iter()
        .any(|d| d.code == DiagnosticCode::MethodFailed && d.method_idx.is_some())
    {
        return Err("MethodFailed diagnostic with method_idx missing".into());
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Control / budget
// ─────────────────────────────────────────────────────────────────────

fn cancel_and_deadline() -> TestResult {
    let options = ParseOptions::default();
    let budget = droidsaw_dex::analysis::Budget::default();

    let cancelled = Control::new();
    cancelled.cancel();
    match parse_for_analysis(G02, &options, &budget, &cancelled) {
        Err(BackendError::Cancelled) => {}
        other => return Err(format!("cancelled parse: {other:?}")),
    }

    let control = Control::new();
    let past = droidsaw_dex::analysis::Budget {
        deadline: Some(std::time::Instant::now() - std::time::Duration::from_secs(1)),
        max_input_bytes: None,
        ..Default::default()
    };
    match parse_for_analysis(G02, &options, &past, &control) {
        Err(BackendError::DeadlineExceeded) => {}
        other => return Err(format!("expired deadline parse: {other:?}")),
    }

    let parsed = parse_for_analysis(G02, &options, &budget, &control)
        .map_err(|e| format!("parse: {e}"))?;
    let idx = find_statics_class_def_idx(parsed.dex()).ok_or("class missing")?;
    let cancelled = Control::new();
    cancelled.cancel();
    match decompile_checked(&parsed, idx, &EmitOptions::default(), &budget, &cancelled) {
        Err(BackendError::Cancelled) => {}
        other => return Err(format!("cancelled decompile: {other:?}")),
    }
    // cancelled parse of the already-cancelled control also holds for scoped
    match parse_for_analysis(
        G02,
        &ParseOptions {
            scope: ParseScope::ScopedToDescriptor {
                descriptor: G02_DESCRIPTOR.to_string(),
            },
        },
        &budget,
        &cancelled,
    ) {
        Err(BackendError::Cancelled) => {}
        other => return Err(format!("cancelled scoped parse: {other:?}")),
    }
    Ok(())
}

fn input_budget_cap() -> TestResult {
    let budget = droidsaw_dex::analysis::Budget {
        deadline: None,
        max_input_bytes: Some(100),
        ..Default::default()
    };
    match parse_for_analysis(G02, &ParseOptions::default(), &budget, &Control::new()) {
        Err(BackendError::InputBudget { bytes, cap }) => {
            if cap != 100 || bytes != G02.len() {
                return Err(format!("budget error payload: bytes={bytes} cap={cap}"));
            }
        }
        other => return Err(format!("expected InputBudget, got {other:?}")),
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// BACK-03: full vs scoped equivalence on the selected class
// ─────────────────────────────────────────────────────────────────────

fn scoped_parse_equivalence() -> TestResult {
    let budget = droidsaw_dex::analysis::Budget::default();
    let control = Control::new();
    let full = parse_for_analysis(G02, &ParseOptions::default(), &budget, &control)
        .map_err(|e| format!("full parse: {e}"))?;
    let idx = find_statics_class_def_idx(full.dex()).ok_or("class missing")?;
    let full_report = decompile_checked(&full, idx, &EmitOptions::default(), &budget, &control)
        .map_err(|e| format!("full decompile: {e}"))?;

    let scoped = parse_for_analysis(
        G02,
        &ParseOptions {
            scope: ParseScope::ScopedToDescriptor {
                descriptor: G02_DESCRIPTOR.to_string(),
            },
        },
        &budget,
        &control,
    )
    .map_err(|e| format!("scoped parse: {e}"))?;
    if scoped.scoped_fell_back_to_full() {
        return Err("matched descriptor must not fall back".into());
    }
    let scoped_report =
        decompile_checked(&scoped, idx, &EmitOptions::default(), &budget, &control)
            .map_err(|e| format!("scoped decompile: {e}"))?;

    if full_report.source != scoped_report.source {
        return Err("selected-class source differs between full and scoped parse".into());
    }
    if full_report.metadata != scoped_report.metadata {
        return Err("metadata differs between full and scoped parse".into());
    }
    if full_report.method_outcomes != scoped_report.method_outcomes {
        return Err("method outcomes differ between full and scoped parse".into());
    }
    if full_report.completeness != scoped_report.completeness {
        return Err("completeness differs between full and scoped parse".into());
    }
    if !scoped_report
        .diagnostics
        .iter()
        .any(|d| d.code == DiagnosticCode::R8OriginCommentsDropped)
    {
        return Err("scoped report must carry the R8OriginCommentsDropped diagnostic".into());
    }
    if full_report
        .diagnostics
        .iter()
        .any(|d| d.code == DiagnosticCode::R8OriginCommentsDropped)
    {
        return Err("full report must not carry the scoped-only diagnostic".into());
    }

    // Unmatched descriptor: falls back to the full parse and reports it.
    let fallback = parse_for_analysis(
        G02,
        &ParseOptions {
            scope: ParseScope::ScopedToDescriptor {
                descriptor: "Lno/such/Class;".to_string(),
            },
        },
        &budget,
        &control,
    )
    .map_err(|e| format!("fallback parse: {e}"))?;
    if !fallback.scoped_fell_back_to_full() {
        return Err("unmatched descriptor must fall back to full parse".into());
    }
    let fallback_report =
        decompile_checked(&fallback, idx, &EmitOptions::default(), &budget, &control)
            .map_err(|e| format!("fallback decompile: {e}"))?;
    if fallback_report.source != full_report.source {
        return Err("fallback source must equal full-parse source".into());
    }
    if !fallback_report
        .diagnostics
        .iter()
        .any(|d| d.code == DiagnosticCode::ScopedFallbackToFull)
    {
        return Err("fallback must carry the ScopedFallbackToFull diagnostic".into());
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Legacy bridge (kept until A07 rewires src/apk.rs)
// ─────────────────────────────────────────────────────────────────────

fn legacy_bridge() -> TestResult {
    let legacy_dex = DexFile::parse_for_class(G02, G02_DESCRIPTOR)
        .map_err(|e| format!("parse_for_class: {e}"))?;
    let class_def = legacy_dex
        .class_defs
        .iter()
        .find(|cd| legacy_dex.get_type_descriptor(cd.class_idx).ok() == Some(G02_DESCRIPTOR))
        .ok_or("class missing")?;
    let legacy_source = droidsaw_dex::classes::decompile_class(&legacy_dex, G02, class_def);

    let budget = droidsaw_dex::analysis::Budget::default();
    let control = Control::new();
    let parsed = parse_for_analysis(G02, &ParseOptions::default(), &budget, &control)
        .map_err(|e| format!("checked parse: {e}"))?;
    let idx = find_statics_class_def_idx(parsed.dex()).ok_or("class missing")?;
    let report = decompile_checked(&parsed, idx, &EmitOptions::default(), &budget, &control)
        .map_err(|e| format!("checked decompile: {e}"))?;

    if legacy_source != report.source {
        return Err(
            "legacy decompile_class and decompile_checked must produce identical source \
             under clean env and default options"
                .into(),
        );
    }
    Ok(())
}
