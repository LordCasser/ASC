//! Black-box CLI contract tests (A08, CLI-01/02/03): the seven command paths
//! in both formats, exit codes, output commitment and cancellation surfaces,
//! all through the real `rasc` binary (interfaces.md §6).
//!
//! Fixtures: the committed contract inputs plus synthetic APKs built with the
//! shared support builders. Bytes are asserted, never string-compared lossily.

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rasc")
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/contracts/inputs")
        .join(name)
}

/// Writes a synthetic APK under a per-process temp name.
fn temp_apk(name: &str, bytes: &[u8]) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("rasc-contract-cli-{}-{name}", std::process::id()));
    fs::write(&path, bytes).expect("write temp apk");
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("spawn rasc")
}

fn status(output: &Output) -> i32 {
    output.status.code().expect("rasc exits with a code, not a signal")
}

fn stdout(output: &Output) -> &[u8] {
    &output.stdout
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Lowercase hex sha-256 of a file's bytes: the artifact id of the fixture.
fn artifact_id(path: &Path) -> String {
    let bytes = fs::read(path).expect("read fixture");
    support::sha::hex_lower(&support::sha::sha256(&bytes))
}

const G01: &str = "g01-regex-string.apk";
const G02: &str = "g02-static-initializers.apk";
const MANIFEST_APK: &str = "man03-plain-xml-tree.apk";
const BAD_APK: &str = "in03-bad-container-rejected.apk";

// ---------------------------------------------------------------------------
// CLI-01: the seven call paths, both formats
// ---------------------------------------------------------------------------

#[test]
fn findrefs_string_regex_text_bytes_are_frozen() {
    let apk = fixture(G01);
    let id = artifact_id(&apk);
    let output = run(&["findrefs", apk.to_str().unwrap(), "string", "tok.n", "--regex"]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
    // The exact line: dex-key, display name, method_idx, caller, targets-json.
    let expected = format!(
        "0:0 | classes.dex | 0 | Lexample/Regex;->mark()V | \
         [{{\"id\":{{\"artifact_id\":\"{id}\",\"entry_ordinal\":0,\"logical_ordinal\":0,\
         \"index\":4}},\"kind\":\"string\",\"value\":{{\"text\":\"token\",\"utf16\":[116,111,107,101,110]}},\
         \"code_unit_offsets\":[0]}},{{\"id\":{{\"artifact_id\":\"{id}\",\"entry_ordinal\":0,\
         \"logical_ordinal\":0,\"index\":5}},\"kind\":\"string\",\"value\":{{\"text\":\"tokens\",\
         \"utf16\":[116,111,107,101,110,115]}},\"code_unit_offsets\":[2]}}]\n"
    );
    assert_eq!(stdout(&output), expected.as_bytes());
}

#[test]
fn findrefs_json_envelope_matches_the_frozen_shape() {
    let apk = fixture(G01);
    let id = artifact_id(&apk);
    let output =
        run(&["findrefs", apk.to_str().unwrap(), "string", "tok.n", "--regex", "--format", "json"]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
    let payload = stdout(&output);
    // Exactly one envelope object plus one trailing LF; the data carries the
    // caller with full identity and the target with kind/value/offsets.
    assert!(payload.ends_with(b"}\n"), "payload must end with a single LF");
    let text = std::str::from_utf8(&payload[..payload.len() - 1]).expect("utf-8 payload");
    assert_eq!(
        support::json::parse(text).ok().and_then(|document| {
            document.get("operation").and_then(|value| value.as_str()).map(str::to_owned)
        }),
        Some("findrefs".to_owned()),
        "envelope: {text}"
    );
    assert!(text.contains(&format!("\"artifact_id\":\"{id}\"")));
    assert!(text.contains("\"caller\":{\"id\":{\"artifact_id\":"));
    assert!(text.contains("\"kind\":\"string\",\"value\":{\"text\":\"token\""));
    assert!(text.contains("\"code_unit_offsets\":[0]"));
    assert!(!text.contains("\"stats\""), "stats never enter the payload");
}

#[test]
fn findrefs_type_method_field_paths_succeed_in_both_formats() {
    let apk = fixture(G01);
    // A type literal converts dotted names; a member query with a class
    // constraint constructs; on this fixture they simply have no hits.
    for args in [
        vec!["type", "Lexample/Regex;"],
        vec!["method", "mark"],
        vec!["field", "nothing", "--class", "example.Regex"],
        vec!["field", "mark", "--class", "Regex", "--fuzzy-class", "--regex"],
    ] {
        let mut text_args = vec!["findrefs", apk.to_str().unwrap()];
        text_args.extend(args.iter().copied());
        let output = run(&text_args);
        assert_eq!(status(&output), 0, "args {args:?}: {}", stderr_text(&output));
        assert!(stdout(&output).is_empty(), "no-hit text is empty bytes");
        let mut json_args = text_args.clone();
        json_args.extend(["--format", "json"]);
        let output = run(&json_args);
        assert_eq!(status(&output), 0, "args {args:?}: {}", stderr_text(&output));
        let payload = stdout(&output);
        assert!(payload.starts_with(b"{\"schema_version\":1,\"operation\":\"findrefs\""));
        assert!(payload.ends_with(b"\"data\":[],\"diagnostics\":[]}\n"));
    }
}

#[test]
fn classes_text_and_json_bytes_are_frozen() {
    let apk = fixture(G01);
    let id = artifact_id(&apk);
    let output = run(&["classes", apk.to_str().unwrap()]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
    let expected =
        "0:0 | classes.dex | 0 | Lexample/Regex; | example.Regex | example | Regex\n";
    assert_eq!(stdout(&output), expected.as_bytes());

    let output = run(&["classes", apk.to_str().unwrap(), "--format", "json"]);
    assert_eq!(status(&output), 0);
    let payload = stdout(&output);
    let prefix = format!(
        "{{\"schema_version\":1,\"operation\":\"classes\",\"artifact_id\":\"{id}\",\"data\":[{{\
         \"id\":{{\"artifact_id\":\"{id}\",\"entry_ordinal\":0,\"logical_ordinal\":0,\
         \"class_def_idx\":0}},\"dex\":{{\"id\":{{\"artifact_id\":\"{id}\",\"entry_ordinal\":0,\
         \"logical_ordinal\":0}},\"raw_entry_name\":\"classes.dex\""
    );
    assert!(
        payload.starts_with(prefix.as_bytes()),
        "unexpected classes envelope: {}",
        String::from_utf8_lossy(payload)
    );
    assert!(payload.ends_with(b"\"diagnostics\":[]}\n"));
    // The class object carries the lossless dex_text projection.
    let needle = b"\"descriptor\":\"Lexample/Regex;\",\"java_name\":{\"text\":\"example.Regex\"";
    assert!(payload.windows(needle.len()).any(|window| window == needle));
}

#[test]
fn getclass_text_and_json_match_the_source_contract() {
    let apk = fixture(G02);
    let output = run(&["getclass", apk.to_str().unwrap(), "example.Statics"]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
    let payload = stdout(&output);
    // Java source: UTF-8/LF with exactly one trailing LF.
    assert!(payload.ends_with(b"\n") && !payload.ends_with(b"\n\n"));
    assert!(!payload.windows(2).any(|window| window == b"\r\n"));
    let text = std::str::from_utf8(payload).unwrap();
    assert!(text.contains("public static int FIRST = 11;"), "source: {text}");
    assert!(text.contains("SECOND = 22"));

    let output = run(&["getclass", apk.to_str().unwrap(), "example.Statics", "--format", "json"]);
    assert_eq!(status(&output), 0);
    let payload = stdout(&output);
    assert!(payload.starts_with(b"{\"schema_version\":1,\"operation\":\"getclass\""));
    let text = std::str::from_utf8(&payload[..payload.len() - 1]).unwrap();
    assert!(text.contains("\"data\":{\"class\":{\"id\":"));
    assert!(text.contains("\"source\":\"package example;\\n\\npublic class Statics {"));
    assert!(text.contains("\"metadata\":{\"class\":{\"access_flags\":"));
    assert!(text.contains("\"methods\":[{\"name\":{\"text\":\"getSecond\""));
}

#[test]
fn manifest_text_and_json_match_the_document_contract() {
    let apk = fixture(MANIFEST_APK);
    let output = run(&["manifest", apk.to_str().unwrap()]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
    let payload = stdout(&output);
    assert!(payload.starts_with(b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"));
    assert!(payload.windows(b"    <uses-sdk".len()).any(|w| w == b"    <uses-sdk"));
    // The JSON xml field is the same complete rendering, and the document
    // carries the ordered model.
    let output = run(&["manifest", apk.to_str().unwrap(), "--format", "json"]);
    assert_eq!(status(&output), 0);
    let payload = stdout(&output);
    assert!(payload.starts_with(b"{\"schema_version\":1,\"operation\":\"manifest\""));
    let text = std::str::from_utf8(&payload[..payload.len() - 1]).unwrap();
    assert!(text.contains("\"xml\":\"<?xml version=\\\"1.0\\\""));
    assert!(text.contains("\"document\":{\"declaration\":{\"version\":\"1.0\""));
    assert!(text.contains("\"root\":{\"namespace\":"));
    assert!(text.contains("\"metadata\":{\"source\":"));
}

#[test]
fn getclass_accepts_descriptor_and_pinned_dex() {
    let apk = fixture(G02);
    let output = run(&["getclass", apk.to_str().unwrap(), "Lexample/Statics;"]);
    assert_eq!(status(&output), 0, "descriptor form: {}", stderr_text(&output));
    let output = run(&["getclass", apk.to_str().unwrap(), "example.Statics", "--dex", "0:0"]);
    assert_eq!(status(&output), 0, "pinned form: {}", stderr_text(&output));
    assert!(stdout(&output).windows(7).any(|window| window == b"Statics"));
}

#[test]
fn exact_class_is_never_affected_by_regex_and_member_class_stays_exact() {
    let apk = fixture(G02);
    // Spec scenario: the exact class normalizes, the member name stays a
    // regex — `SE.` matches the field SECOND and the result is non-empty.
    let output = run(&[
        "findrefs",
        apk.to_str().unwrap(),
        "field",
        "SE.",
        "--class",
        "example.Statics",
        "--regex",
    ]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
    let line = String::from_utf8_lossy(stdout(&output));
    assert!(line.contains("\"kind\":\"field\""), "field target: {line}");
    assert!(line.contains("\"text\":\"SECOND\""), "regex SE. hit SECOND: {line}");
    // The same query as a literal has no hit: no field is literally "SE.".
    let output = run(&[
        "findrefs",
        apk.to_str().unwrap(),
        "field",
        "SE.",
        "--class",
        "example.Statics",
    ]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
    assert!(stdout(&output).is_empty());
}

// ---------------------------------------------------------------------------
// CLI-02: output protocol properties
// ---------------------------------------------------------------------------

#[test]
fn empty_sets_are_empty_text_and_a_full_json_envelope() {
    let apk = fixture(G01);
    let output = run(&["findrefs", apk.to_str().unwrap(), "string", "zzz-not-there"]);
    assert_eq!(status(&output), 0);
    assert!(stdout(&output).is_empty(), "text empty set is zero bytes");
    let id = artifact_id(&apk);
    let output = run(&[
        "findrefs",
        apk.to_str().unwrap(),
        "string",
        "zzz-not-there",
        "--format",
        "json",
    ]);
    assert_eq!(status(&output), 0);
    let expected = format!(
        "{{\"schema_version\":1,\"operation\":\"findrefs\",\"artifact_id\":\"{id}\",\
         \"data\":[],\"diagnostics\":[]}}\n"
    );
    assert_eq!(stdout(&output), expected.as_bytes());
}

#[test]
fn debug_never_changes_the_payload_bytes() {
    let apk = fixture(G01);
    for args in [
        vec!["classes", apk.to_str().unwrap()],
        vec!["findrefs", apk.to_str().unwrap(), "string", "tok.n", "--regex", "--format", "json"],
    ] {
        let plain = run(&args);
        let mut debug_args = args.clone();
        debug_args.push("--debug");
        let debugged = run(&debug_args);
        assert_eq!(status(&plain), 0);
        assert_eq!(status(&debugged), 0);
        assert_eq!(stdout(&plain), stdout(&debugged), "--debug changed the payload");
        let err = stderr_text(&debugged);
        assert!(err.contains("[DEBUG]"), "debug output missing: {err}");
    }
}

#[test]
fn regex_flag_switches_between_literal_and_pattern() {
    let apk = fixture(G01);
    let literal = run(&["findrefs", apk.to_str().unwrap(), "string", "tok.n"]);
    assert_eq!(status(&literal), 0);
    assert!(stdout(&literal).is_empty(), "literal tok.n has no hits");
    let regex = run(&["findrefs", apk.to_str().unwrap(), "string", "tok.n", "--regex"]);
    assert_eq!(status(&regex), 0);
    assert_eq!(stdout(&regex).iter().filter(|&&b| b == b'\n').count(), 1, "one caller line");
}

// ---------------------------------------------------------------------------
// CLI-03: output commitment
// ---------------------------------------------------------------------------

#[test]
fn output_file_receives_exactly_the_stdout_bytes() {
    let apk = fixture(G01);
    let out = temp_apk("out-classes.txt", b"stale content that must be replaced");
    let output = run(&["classes", apk.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
    let file = fs::read(&out).expect("read output file");
    assert_eq!(file, stdout(&output), "-o bytes must equal stdout bytes");

    let json_out = temp_apk("out-refs.json", b"");
    let output = run(&[
        "findrefs",
        apk.to_str().unwrap(),
        "string",
        "tok.n",
        "--regex",
        "--format",
        "json",
        "-o",
        json_out.to_str().unwrap(),
    ]);
    assert_eq!(status(&output), 0);
    assert_eq!(fs::read(&json_out).unwrap(), stdout(&output));
    let _ = fs::remove_file(&out);
    let _ = fs::remove_file(&json_out);
}

#[test]
fn output_refuses_directory_symlink_input_alias_and_hardlink() {
    let apk = fixture(G01);
    let apk_bytes = fs::read(&apk).unwrap();

    // Directory.
    let dir = std::env::temp_dir();
    let output = run(&["classes", apk.to_str().unwrap(), "-o", dir.to_str().unwrap()]);
    assert_eq!(status(&output), 1, "directory output must be refused");
    assert!(stderr_text(&output).contains("OutputRefused"));

    // Symlink (dangling or not).
    let link = std::env::temp_dir().join(format!("rasc-cli-link-{}", std::process::id()));
    let _ = fs::remove_file(&link);
    #[cfg(unix)]
    std::os::unix::fs::symlink("/nonexistent/rasc-target", &link).expect("symlink");
    #[cfg(not(unix))]
    fs::write(&link, b"x").expect("fallback: plain file");
    let output = run(&["classes", apk.to_str().unwrap(), "-o", link.to_str().unwrap()]);
    #[cfg(unix)]
    {
        assert_eq!(status(&output), 1);
        assert!(stderr_text(&output).contains("OutputRefused"));
    }
    let _ = fs::remove_file(&link);

    // Same file as the input.
    let input = temp_apk("input-alias.apk", &apk_bytes);
    let output = run(&["classes", input.to_str().unwrap(), "-o", input.to_str().unwrap()]);
    assert_eq!(status(&output), 1);
    assert!(stderr_text(&output).contains("OutputRefused"));
    assert_eq!(fs::read(&input).unwrap(), apk_bytes, "input must be untouched");

    // A hardlink of the input (same device + inode).
    #[cfg(unix)]
    {
        let hard = std::env::temp_dir().join(format!("rasc-cli-hard-{}", std::process::id()));
        let _ = fs::remove_file(&hard);
        fs::hard_link(&input, &hard).expect("hard link");
        let output = run(&["classes", input.to_str().unwrap(), "-o", hard.to_str().unwrap()]);
        assert_eq!(status(&output), 1, "hardlink output must be refused");
        assert!(stderr_text(&output).contains("OutputRefused"));
        let _ = fs::remove_file(&hard);
    }
    let _ = fs::remove_file(&input);
}

#[test]
fn failed_file_write_sends_no_stdout_payload() {
    let apk = fixture(G01);
    let missing = std::env::temp_dir().join("rasc-cli-missing-dir/out.txt");
    let output = run(&["classes", apk.to_str().unwrap(), "-o", missing.to_str().unwrap()]);
    assert_eq!(status(&output), 1);
    assert!(stdout(&output).is_empty(), "no stdout payload after a failed file write");
    assert!(stderr_text(&output).contains("Error:"));
}

#[test]
fn atomic_replacement_leaves_no_temporary_files_behind() {
    let apk = fixture(G01);
    let out = temp_apk("replace-me.txt", b"old");
    // Snapshot-based leak check: sibling tests run in parallel and use the
    // same temp directory, so only files that appear AND survive this
    // command are leaks (concurrent in-flight temps belong to them).
    let snap = |parent: &Path| -> std::collections::BTreeSet<String> {
        fs::read_dir(parent)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect()
    };
    let parent = std::env::temp_dir();
    let before = snap(&parent);
    let output = run(&["classes", apk.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    assert_eq!(status(&output), 0);
    // Only the final file exists: the hidden temp file was renamed over it.
    // Sibling tests run concurrently in the same temp dir, so a diff hit
    // must settle: a concurrent test's in-flight temp disappears within a
    // moment, a real leak persists. Three settling rounds, then report.
    let mut leftovers: Vec<String> = Vec::new();
    for _ in 0..3 {
        std::thread::sleep(std::time::Duration::from_millis(150));
        let now = snap(&parent);
        leftovers = now
            .difference(&before)
            .filter(|name| name.contains(".rasc-") && name.ends_with(".tmp"))
            .cloned()
            .collect();
        if leftovers.is_empty() {
            break;
        }
    }
    assert!(leftovers.is_empty(), "temporary files leaked: {leftovers:?}");
    let _ = fs::remove_file(&out);
}

#[cfg(unix)]
#[test]
fn closed_pipe_terminates_quietly_without_panic_output() {
    // `| head -c 1` closes the pipe early; the CLI must die by SIGPIPE or
    // exit quietly — never print a panic message.
    let script = format!("{} classes {} 2>'{}' | head -c 1 >/dev/null", bin(), apk_path_display(G01), {
        let err = std::env::temp_dir().join(format!("rasc-cli-pipe-{}.err", std::process::id()));
        err.to_str().unwrap().to_owned()
    });
    let status = Command::new("sh").arg("-c").arg(&script).status().expect("run sh");
    // 141 = 128 + SIGPIPE; both are acceptable, a panic is not.
    let code = status.code().unwrap_or(141);
    assert!(code == 0 || code == 141, "unexpected exit code {code}");
}

fn apk_path_display(name: &str) -> String {
    fixture(name).to_str().expect("utf-8 fixture path").to_owned()
}

// ---------------------------------------------------------------------------
// CLI-01: exit codes and rejection before analysis
// ---------------------------------------------------------------------------

#[test]
fn no_args_prints_help_to_stderr_and_exits_two() {
    let output = Command::new(bin()).output().expect("spawn rasc");
    assert_eq!(status(&output), 2);
    let err = stderr_text(&output);
    assert!(err.contains("Usage:") && err.contains("rasc"), "help on stderr: {err}");
}

#[test]
fn help_and_version_go_to_stdout_with_exit_zero() {
    let output = run(&["--help"]);
    assert_eq!(status(&output), 0);
    assert!(stdout(&output).starts_with(b"Native Rust APK and DEX analysis CLI"));
    let output = run(&["--version"]);
    assert_eq!(status(&output), 0);
    assert!(!stdout(&output).is_empty());
    // Command-level help documents the shared options...
    let output = run(&["findrefs", "--help"]);
    assert_eq!(status(&output), 0);
    let help = stdout(&output);
    for option in ["--format", "--timeout-ms", "--limit", "--threads", "--debug"] {
        assert!(
            help.windows(option.len()).any(|window| window == option.as_bytes()),
            "findrefs help must document {option}"
        );
    }
    // ...and the query kind help documents --regex.
    let output = run(&["findrefs", "string", "--help"]);
    assert_eq!(status(&output), 0);
    let help = stdout(&output);
    for option in ["--regex", "--format", "--limit"] {
        assert!(
            help.windows(option.len()).any(|window| window == option.as_bytes()),
            "findrefs string help must document {option}"
        );
    }
}

#[test]
fn thread_and_timeout_rejections_happen_before_the_input_is_opened() {
    for args in [
        vec!["classes", "/nonexistent/rasc.apk", "--threads", "0"],
        vec!["classes", "/nonexistent/rasc.apk", "--timeout-ms", "0"],
    ] {
        let output = run(&args);
        assert_eq!(status(&output), 2, "args {args:?}: {}", stderr_text(&output));
        assert!(stderr_text(&output).starts_with("Error: "));
    }
    // Negative values never parse as numbers: clap rejects them (exit 2)
    // with its own usage error.
    for args in [
        vec!["classes", "/nonexistent/rasc.apk", "--threads", "-1"],
        vec!["classes", "/nonexistent/rasc.apk", "--timeout-ms", "-5"],
    ] {
        let output = run(&args);
        assert_eq!(status(&output), 2, "args {args:?}: {}", stderr_text(&output));
    }
    // The alias spelling is accepted.
    let output = run(&["classes", fixture(G01).to_str().unwrap(), "--thread", "2"]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
}

#[test]
fn dex_selector_syntax_and_resolution_errors_exit_two() {
    let apk = fixture(G01);
    for selector in ["abc", "0", "0:", ":1", "1:2:3", "99999999999999:0"] {
        let output = run(&[
            "getclass",
            apk.to_str().unwrap(),
            "example.Regex",
            "--dex",
            selector,
        ]);
        assert_eq!(status(&output), 2, "selector {selector:?}: {}", stderr_text(&output));
        assert!(
            stderr_text(&output).contains("InvalidQuery"),
            "selector {selector:?} must carry the stable code"
        );
    }
    // Well-formed but not in the catalog: InvalidQuery after resolution.
    let output = run(&["getclass", apk.to_str().unwrap(), "example.Regex", "--dex", "0:9"]);
    assert_eq!(status(&output), 2);
    assert!(stderr_text(&output).contains("InvalidQuery"));
}

#[test]
fn limit_syntax_errors_exit_two() {
    let apk = fixture(G01);
    for limits in [
        vec!["bogus=5"],
        vec!["result-items"],
        vec!["result-items=abc"],
        vec!["result-items=0"],
        vec!["result-items=-1"],
        vec!["result-items=5", "result-items=9"],
        vec!["result-items=99999999999999999999999"],
        vec!["input-bytes=1_000"],
    ] {
        let mut args = vec!["classes", apk.to_str().unwrap()];
        for limit in &limits {
            args.push("--limit");
            args.push(limit);
        }
        let output = run(&args);
        assert_eq!(status(&output), 2, "limits {limits:?}: {}", stderr_text(&output));
        assert!(stderr_text(&output).contains("InvalidQuery"));
    }
}

#[test]
fn enforced_and_accepted_limit_keys_behave_as_declared() {
    let apk = fixture(G01);
    // input-bytes below the file size: ResourceLimit, exit 1, stable code.
    let output = run(&["classes", apk.to_str().unwrap(), "--limit", "input-bytes=100"]);
    assert_eq!(status(&output), 1);
    assert!(stderr_text(&output).contains("ResourceLimit"));
    // string-units below the smallest string: ResourceLimit during analysis.
    let output = run(&["classes", apk.to_str().unwrap(), "--limit", "string-units=3"]);
    assert_eq!(status(&output), 1);
    assert!(stderr_text(&output).contains("ResourceLimit"));
    // result-bytes bounds the serialization, both formats.
    let output = run(&[
        "classes",
        apk.to_str().unwrap(),
        "--format",
        "json",
        "--limit",
        "result-bytes=64",
    ]);
    assert_eq!(status(&output), 1);
    assert!(stderr_text(&output).contains("ResourceLimit"));
    // A key this build accepts but does not enforce: success with a stderr
    // note, never a silent drop. (engine-bytes became enforced in A11; the
    // xml-nodes key still waits on the A06 limits setter.)
    let output = run(&["classes", apk.to_str().unwrap(), "--limit", "xml-nodes=99"]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
    assert!(stderr_text(&output).contains("not enforced"));
    // engine-bytes is now enforced: a tiny engine budget refuses the open.
    let output = run(&["classes", apk.to_str().unwrap(), "--limit", "engine-bytes=99"]);
    assert_eq!(status(&output), 1);
    assert!(stderr_text(&output).contains("ResourceLimit"));
}

#[test]
fn broken_inputs_fail_with_stable_codes_and_exit_one() {
    // Structurally broken DEX inside a valid archive.
    let output = run(&["classes", fixture(BAD_APK).to_str().unwrap()]);
    assert_eq!(status(&output), 1);
    let err = stderr_text(&output);
    assert!(err.starts_with("Error: MalformedInput"), "stderr: {err}");
    assert!(stdout(&output).is_empty(), "no success payload on failure");
    // Missing file: NotFound, exit 1.
    let output = run(&["classes", "/nonexistent/rasc.apk"]);
    assert_eq!(status(&output), 1);
    assert!(stderr_text(&output).starts_with("Error: NotFound"));
    // A missing class is NotFound (1), never an empty success.
    let output = run(&["getclass", fixture(G01).to_str().unwrap(), "com.example.Missing"]);
    assert_eq!(status(&output), 1);
    assert!(stderr_text(&output).contains("NotFound"));
}

#[test]
fn member_query_without_any_constraint_is_rejected_before_input() {
    // No name and no class: InvalidQuery (exit 2) without opening the file.
    let output = run(&["findrefs", "/nonexistent/rasc.apk", "method"]);
    assert_eq!(status(&output), 2);
    assert!(stderr_text(&output).contains("InvalidQuery"));
    // --fuzzy-class without --class is the same rejection.
    let output = run(&["findrefs", "/nonexistent/rasc.apk", "method", "x", "--fuzzy-class"]);
    assert_eq!(status(&output), 2);
    assert!(stderr_text(&output).contains("--fuzzy-class requires --class"));
}

#[test]
fn a_generous_deadline_still_completes_the_command() {
    let output = run(&[
        "classes",
        fixture(G01).to_str().unwrap(),
        "--threads",
        "2",
        "--timeout-ms",
        "60000",
    ]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
}

/// Deadline cancellation is real but timing-dependent: on a fast machine a
/// tiny fixture can finish before the first checkpoint fires, so this test
/// only asserts against a real (if unlikely) 130, and is ignored by default.
/// A09/A14 run it against a large corpus where it is deterministic.
#[test]
#[ignore = "timing-dependent; reliable only on a slow machine or a large corpus (A09/A14)"]
fn deadline_cancellation_exits_130_and_names_the_cause() {
    let output = run(&["classes", fixture(G01).to_str().unwrap(), "--timeout-ms", "1"]);
    assert_eq!(status(&output), 130);
    let err = stderr_text(&output);
    assert!(err.contains("Cancelled"), "stderr must name the cause: {err}");
    assert!(err.contains("deadline"), "stderr must distinguish deadline: {err}");
}

// ---------------------------------------------------------------------------
// Synthetic fixtures through the support builders
// ---------------------------------------------------------------------------

#[test]
fn synthetic_apk_runs_through_the_full_cli() {
    let dex = support::dex::make_regex_string_dex();
    let apk_bytes = support::apk::apk_with_single_dex("classes.dex", &dex);
    let apk = temp_apk("synthetic.apk", &apk_bytes);
    let id = artifact_id(&apk);

    let output = run(&["findrefs", apk.to_str().unwrap(), "string", "token"]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
    assert_eq!(stdout(&output).iter().filter(|&&b| b == b'\n').count(), 1);
    assert!(stdout(&output)
        .starts_with(b"0:0 | classes.dex | 0 | Lexample/Regex;->mark()V"));

    let output = run(&["classes", apk.to_str().unwrap(), "--format", "json"]);
    assert_eq!(status(&output), 0);
    assert!(stdout(&output).starts_with(
        format!("{{\"schema_version\":1,\"operation\":\"classes\",\"artifact_id\":\"{id}\"").as_bytes()
    ));

    // A manifest-only archive: the manifest command needs no DEX at all.
    let manifest_only = support::apk::apk_with_single_dex(
        "AndroidManifest.xml",
        b"<manifest package=\"cli.test\" />",
    );
    let apk = temp_apk("manifest-only.apk", &manifest_only);
    let output = run(&["manifest", apk.to_str().unwrap()]);
    assert_eq!(status(&output), 0, "stderr: {}", stderr_text(&output));
    assert!(stdout(&output).starts_with(b"<?xml version=\"1.0\""));
    let output = run(&["manifest", apk.to_str().unwrap(), "--format", "json"]);
    assert_eq!(status(&output), 0);
    let text = String::from_utf8_lossy(stdout(&output));
    assert!(text.contains("\"source\":{\"kind\":\"plain-xml\"}"));

    // And a manifest-only archive still splits correctly: queries fail with
    // NotFound (exit 1), never an empty success.
    let output = run(&["classes", apk.to_str().unwrap()]);
    assert_eq!(status(&output), 1);
    assert!(stderr_text(&output).contains("NotFound"));

    let _ = fs::remove_file(temp_apk_path("synthetic.apk"));
    let _ = fs::remove_file(temp_apk_path("manifest-only.apk"));
}

fn temp_apk_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rasc-contract-cli-{}-{name}", std::process::id()))
}
