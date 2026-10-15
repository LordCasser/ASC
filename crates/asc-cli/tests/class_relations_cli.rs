//! A20: direct class relations use their own payload, with the existing CLI
//! validation, deterministic rendering, limits and atomic output contract.

mod support;

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use support::json::Json;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/contracts/inputs")
        .join(name)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rasc"))
        .args(args)
        .output()
        .expect("run rasc")
}

fn assert_status(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn json(output: &Output) -> Json {
    assert_status(output, 0);
    assert!(output.stdout.ends_with(b"}\n"));
    assert!(!output.stdout.ends_with(b"\n\n"));
    support::json::parse(std::str::from_utf8(&output.stdout).unwrap()).expect("JSON envelope")
}

struct TempFile(PathBuf);

impl TempFile {
    fn new(name: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rasc-class-relations-{}-{name}",
            std::process::id()
        ));
        fs::write(&path, bytes).expect("write temporary file");
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().expect("temporary path")
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn extends_text_and_json_keep_class_and_type_identity() {
    let apk = fixture("g01-regex-string.apk");
    let path = apk.to_str().unwrap();
    let expected = b"0:0 | classes.dex | 0 | Lexample/Regex; | extends | 1 | Ljava/lang/Object;\n";
    for target in ["java.lang.Object", "Ljava/lang/Object;"] {
        let output = run(&["findrefs", path, "extends", target]);
        assert_status(&output, 0);
        assert_eq!(output.stdout, expected);
    }
    let output = run(&[
        "findrefs",
        path,
        "extends",
        "java.lang.Object",
        "--format",
        "json",
    ]);
    let document = json(&output);
    assert_eq!(
        document.get("schema_version").and_then(Json::as_i64),
        Some(1)
    );
    assert_eq!(
        document.get("operation").and_then(Json::as_str),
        Some("class_relations")
    );
    let rows = document.get("data").and_then(Json::as_array).unwrap();
    assert_eq!(rows.len(), 1);
    let Json::Object(fields) = &rows[0] else {
        panic!("relation object")
    };
    assert_eq!(
        fields
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>(),
        ["class", "kind", "target_id", "target"]
    );
    let classes = json(&run(&["classes", path, "--format", "json"]));
    assert_eq!(
        rows[0].get("class"),
        Some(&classes.get("data").unwrap().as_array().unwrap()[0])
    );
    assert_eq!(rows[0].get("kind").and_then(Json::as_str), Some("extends"));
    let target_id = rows[0].get("target_id").unwrap();
    assert_eq!(target_id.get("artifact_id"), document.get("artifact_id"));
    assert_eq!(
        target_id.get("entry_ordinal").and_then(Json::as_i64),
        Some(0)
    );
    assert_eq!(
        target_id.get("logical_ordinal").and_then(Json::as_i64),
        Some(0)
    );
    assert_eq!(target_id.get("index").and_then(Json::as_i64), Some(1));
    let target = rows[0].get("target").unwrap();
    assert_eq!(
        target.get("text").and_then(Json::as_str),
        Some("Ljava/lang/Object;")
    );
    let units: Vec<Json> = "Ljava/lang/Object;"
        .encode_utf16()
        .map(|unit| Json::Int(i64::from(unit)))
        .collect();
    assert_eq!(target.get("utf16"), Some(&Json::Array(units)));
    assert!(
        document
            .get("diagnostics")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn exact_no_hits_and_both_interface_spellings_have_empty_success_payloads() {
    let apk = fixture("g01-regex-string.apk");
    for (kind, target) in [
        ("extends", "Object"), // A short name is exact, never a substring.
        ("extends", "example.Missing"),
        ("impl", "java.lang.Runnable"),
        ("implements", "Ljava/lang/Runnable;"),
    ] {
        let output = run(&["findrefs", apk.to_str().unwrap(), kind, target]);
        assert_status(&output, 0);
        assert!(output.stdout.is_empty());
        let output = run(&[
            "findrefs",
            apk.to_str().unwrap(),
            kind,
            target,
            "--format",
            "json",
        ]);
        let document = json(&output);
        assert_eq!(
            document.get("operation").and_then(Json::as_str),
            Some("class_relations")
        );
        assert_eq!(document.get("data"), Some(&Json::Array(vec![])));
    }
}

#[test]
fn relation_common_options_merge_and_output_matches_stdout() {
    let apk = fixture("g01-regex-string.apk");
    for format in ["text", "json"] {
        let out = TempFile::new(&format!("result-{format}"), b"stale output");
        let output = run(&[
            "findrefs",
            "--threads",
            "1",
            "--format",
            "text",
            "-o",
            out.path(),
            apk.to_str().unwrap(),
            "extends",
            "java.lang.Object",
            "--thread",
            "2",
            "--format",
            format,
            "--debug",
            "--timeout-ms",
            "60000",
            "--limit",
            "result-items=1",
        ]);
        assert_status(&output, 0);
        assert_eq!(fs::read(&out.0).unwrap(), output.stdout);
        assert!(String::from_utf8_lossy(&output.stderr).contains("result_items=1"));
        let baseline = run(&[
            "findrefs",
            apk.to_str().unwrap(),
            "extends",
            "java.lang.Object",
            "--format",
            format,
        ]);
        assert_status(&baseline, 0);
        assert_eq!(output.stdout, baseline.stdout);
    }
    let out = TempFile::new("empty-result", b"stale output");
    let output = run(&[
        "findrefs",
        apk.to_str().unwrap(),
        "impl",
        "java.lang.Runnable",
        "-o",
        out.path(),
    ]);
    assert_status(&output, 0);
    assert!(output.stdout.is_empty());
    assert!(fs::read(&out.0).unwrap().is_empty());
}

#[test]
fn bad_relation_queries_and_options_fail_before_opening_input() {
    for kind in ["extends", "impl", "implements"] {
        for target in ["", " ", "[Ljava/lang/Object;", "L;"] {
            let output = run(&["findrefs", "/nonexistent/rasc.apk", kind, target]);
            assert_status(&output, 2);
            let err = String::from_utf8_lossy(&output.stderr);
            assert!(err.contains("InvalidQuery"), "{kind} {target:?}: {err}");
            assert!(!err.contains("NotFound"));
            assert!(output.stdout.is_empty());
        }
        for option in ["--substring", "--regex", "--fuzzy-class"] {
            let output = run(&[
                "findrefs",
                "/nonexistent/rasc.apk",
                kind,
                "java.lang.Object",
                option,
            ]);
            assert_status(&output, 2);
            assert!(output.stdout.is_empty());
        }
        let output = run(&["findrefs", "/nonexistent/rasc.apk", kind]);
        assert_status(&output, 2);
    }
    for extra in [
        ["--threads", "0"],
        ["--timeout-ms", "0"],
        ["--limit", "unknown=5"],
    ] {
        let output = run(&[
            "findrefs",
            "/nonexistent/rasc.apk",
            "extends",
            "java.lang.Object",
            extra[0],
            extra[1],
        ]);
        assert_status(&output, 2);
        assert!(output.stdout.is_empty());
    }
    let output = run(&[
        "findrefs",
        "--limit",
        "pattern-bytes=4",
        "/nonexistent/rasc.apk",
        "extends",
        "java.lang.Object",
    ]);
    assert_status(&output, 1);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("ResourceLimit"), "{err}");
    assert!(
        !err.contains("nonexistent"),
        "query limits must precede input access: {err}"
    );
}

#[test]
fn relation_output_budget_failure_keeps_existing_file_and_stdout_empty() {
    let apk = fixture("g01-regex-string.apk");
    for format in ["text", "json"] {
        let out = TempFile::new(&format!("limited-{format}"), b"keep this output");
        let output = run(&[
            "findrefs",
            apk.to_str().unwrap(),
            "extends",
            "java.lang.Object",
            "--format",
            format,
            "--limit",
            "result-bytes=32",
            "-o",
            out.path(),
        ]);
        assert_status(&output, 1);
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("ResourceLimit"));
        assert_eq!(fs::read(&out.0).unwrap(), b"keep this output");
    }
}

#[test]
fn duplicate_class_relations_are_stable_across_worker_counts() {
    let apk = fixture("in01-root-dex-priority-and-dupes.apk");
    let baseline = run(&[
        "findrefs",
        apk.to_str().unwrap(),
        "extends",
        "java.lang.Object",
        "--threads",
        "1",
        "--format",
        "json",
    ]);
    let document = json(&baseline);
    let rows = document.get("data").and_then(Json::as_array).unwrap();
    let entries: Vec<_> = rows
        .iter()
        .map(|row| {
            row.get("class")
                .unwrap()
                .get("id")
                .unwrap()
                .get("entry_ordinal")
                .and_then(Json::as_i64)
                .unwrap()
        })
        .collect();
    assert_eq!(entries, [2, 4]);
    assert_eq!(
        rows[0].get("class").unwrap().get("descriptor"),
        rows[1].get("class").unwrap().get("descriptor")
    );
    for threads in ["2", "8"] {
        let output = run(&[
            "findrefs",
            "--threads",
            threads,
            apk.to_str().unwrap(),
            "extends",
            "java.lang.Object",
            "--format",
            "json",
        ]);
        assert_status(&output, 0);
        assert_eq!(output.stdout, baseline.stdout);
    }
    let output = run(&[
        "findrefs",
        apk.to_str().unwrap(),
        "extends",
        "java.lang.Object",
        "--limit",
        "result-items=1",
    ]);
    assert_status(&output, 1);
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ResourceLimit"));
}

#[test]
fn relation_text_escapes_source_and_target_columns() {
    let mut dex = support::dex::make_dex();
    for (before, after) in [
        (b"Lexample/Test;".as_slice(), b"Lexample/T|st;".as_slice()),
        (
            b"Ljava/lang/Object;".as_slice(),
            b"Ljava/lang/Ob|ect;".as_slice(),
        ),
    ] {
        let offset = dex
            .windows(before.len())
            .position(|bytes| bytes == before)
            .unwrap();
        dex[offset..offset + before.len()].copy_from_slice(after);
    }
    let signature = support::sha::sha1(&dex[32..]);
    dex[12..32].copy_from_slice(&signature);
    let checksum = support::sha::adler32(&dex[12..]);
    dex[8..12].copy_from_slice(&checksum.to_le_bytes());
    let apk = TempFile::new(
        "escaped.apk",
        &support::apk::apk_with_single_dex("classes.dex", &dex),
    );
    let output = run(&["findrefs", apk.path(), "extends", "Ljava/lang/Ob|ect;"]);
    assert_status(&output, 0);
    assert_eq!(
        output.stdout,
        b"0:0 | classes.dex | 0 | Lexample/T\\|st; | extends | 1 | Ljava/lang/Ob\\|ect;\n"
    );
    let output = run(&[
        "findrefs",
        apk.path(),
        "extends",
        "Ljava/lang/Ob|ect;",
        "--format",
        "json",
    ]);
    let document = json(&output);
    let row = &document.get("data").unwrap().as_array().unwrap()[0];
    assert_eq!(
        row.get("target")
            .unwrap()
            .get("text")
            .and_then(Json::as_str),
        Some("Ljava/lang/Ob|ect;")
    );
}

#[test]
fn relation_help_documents_direct_exact_queries_and_alias() {
    let output = run(&["findrefs", "--help"]);
    assert_status(&output, 0);
    let text = String::from_utf8(output.stdout).unwrap();
    for name in ["extends", "impl", "implements"] {
        assert!(text.contains(name), "{text}");
    }
    for kind in ["extends", "impl", "implements"] {
        let output = run(&["findrefs", "example.apk", kind, "--help"]);
        assert_status(&output, 0);
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Exact Java dotted"), "{text}");
        assert!(text.contains("Direct relations"), "{text}");
        assert!(!text.contains("--regex"), "{text}");
        assert!(!text.contains("--substring"), "{text}");
    }
}
