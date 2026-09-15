//! Contract fixture harness: validates the fixture registry that every later
//! work package (A01-A14) consumes, and self-tests the support library.
//!
//! The registry lives in tests/fixtures/contracts/ (manifest.json plus inputs/
//! and expected/); generators.md there documents how the bytes are produced.
//! This harness keeps the registry honest on its own terms: schema shape,
//! acceptance-matrix coverage, input hash/size agreement, generator
//! provenance, non-empty facts, and comparator/sha negative controls.

mod support;

use support::apk;
use support::compare::compare_facts;
use support::dex;
use support::json::{self, Json};
use support::sha;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Every acceptance matrix ID from openspec/implementation/acceptance.md.
/// A case must exist for each of them, and the manifest may not invent IDs
/// outside this set, so the two stay in sync in both directions.
const ACCEPTANCE_IDS: [&str; 37] = [
    "CLI-01", "CLI-02", "CLI-03",
    "REF-01", "REF-02", "REF-03", "REF-04",
    "IN-01", "IN-02", "IN-03", "IN-04", "IN-05",
    "DECL-01", "DECL-02", "DECL-03", "DECL-04",
    "MAN-01", "MAN-02", "MAN-03", "MAN-04",
    "BACK-01", "BACK-02", "BACK-03",
    "CORE-01", "CORE-02", "CORE-03", "CORE-04", "CORE-05", "CORE-06",
    "DIST-01", "DIST-02", "DIST-03", "DIST-04",
    "QUAL-01", "QUAL-02", "QUAL-03", "QUAL-04",
];

/// Error codes named by openspec/implementation/interfaces.md; `error:<Code>`
/// outcomes must use one of them.
const KNOWN_ERROR_CODES: [&str; 8] = [
    "UnsupportedFormat",
    "MalformedInput",
    "InvalidQuery",
    "NotFound",
    "ResourceLimit",
    "Cancelled",
    "UnsupportedEncoding",
    "IncompleteDecompilation",
];

/// Facts kinds whose top-level arrays keep document order; every other kind
/// compares top-level arrays as multisets (see support::compare).
const ORDERED_FACTS_KINDS: [&str; 1] = ["manifest"];

/// SHA-256 of the Python baseline outputs, precomputed once with:
///
/// ```text
/// cd /Users/lordcasser/workspace/asc-ref/python-main/tests && python3 -c \
///   "import hashlib; from dex_fixture import make_dex, make_static_field_dex; \
///    print(hashlib.sha256(make_dex()).hexdigest()); \
///    print(hashlib.sha256(make_static_field_dex()).hexdigest())"
/// ```
///
/// The Python checkout is a generation-time reference recorded for
/// traceability; it is never read while tests run.
const PYTHON_MAKE_DEX_SHA256: &str =
    "d4f4848f5c16a58df276cee9750f225c9053d201473e3bd7c62c0873f9e093f0";
const PYTHON_MAKE_STATIC_FIELD_DEX_SHA256: &str =
    "5686e4a48559d4a641cb56c6b40c6e22a432bedde96651e7786a57782cef20fe";

fn contracts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/contracts")
}

fn load_manifest() -> Json {
    let text =
        fs::read_to_string(contracts_dir().join("manifest.json")).expect("read manifest.json");
    json::parse(&text).expect("manifest.json is valid JSON")
}

fn cases(manifest: &Json) -> Vec<Json> {
    manifest
        .get("cases")
        .and_then(Json::as_array)
        .expect("manifest has a cases array")
        .to_vec()
}

fn case_str<'a>(case: &'a Json, key: &str) -> &'a str {
    case.get(key).and_then(Json::as_str).unwrap_or_default()
}

fn expected_field<'a>(case: &'a Json, key: &str) -> Option<&'a Json> {
    case.get("expected").and_then(|expected| expected.get(key))
}

fn is_kebab_case(id: &str) -> bool {
    !id.is_empty()
        && id.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && id.split('-').all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

fn is_valid_owner(owner: &str) -> bool {
    let Some(number) = owner.strip_prefix('A') else {
        return false;
    };
    matches!(number.parse::<u32>(), Ok(0..=14)) && number.len() == 2
}

/// Registered input locations: generated fixtures under `inputs/`, corpus
/// samples under `corpus/apks/` (see tests/fixtures/contracts/corpus). Both
/// must stay flat files so a case can never smuggle in a path escape.
const INPUT_LOCATIONS: [(&str, &str); 4] = [
    ("inputs", ".apk"),
    ("inputs", ".dex"),
    ("corpus/apks", ".apk"),
    ("corpus/apks", ".dex"),
];

/// Registered facts locations: hand-encoded facts under `expected/`, pinned
/// reference archives under `corpus/expected/<case>/`.
const FACTS_LOCATIONS: [(&str, &str); 2] = [("expected", ".json"), ("corpus/expected", ".json")];

fn is_safe_relative(path: &str, directory: &str, suffix: &str) -> bool {
    let rest = path.strip_prefix(directory).and_then(|rest| rest.strip_prefix('/'));
    match rest {
        Some(name) => {
            !name.is_empty()
                && !name.contains('/')
                && !name.contains("..")
                && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                && name.ends_with(suffix)
        }
        None => false,
    }
}

/// Facts may sit one directory deeper for `corpus/expected/<case>/file.json`.
fn is_safe_facts_path(path: &str) -> bool {
    for (directory, suffix) in FACTS_LOCATIONS {
        if is_safe_relative(path, directory, suffix) {
            return true;
        }
        let rest = match path.strip_prefix(directory).and_then(|rest| rest.strip_prefix('/')) {
            Some(rest) => rest,
            None => continue,
        };
        let mut parts = rest.split('/');
        let subdir_is_safe = parts
            .next()
            .is_some_and(|case| {
                !case.is_empty()
                    && case
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            })
            && parts.next().is_some_and(|name| {
                !name.is_empty()
                    && name.ends_with(suffix)
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            })
            && parts.next().is_none();
        if subdir_is_safe {
            return true;
        }
    }
    false
}

fn is_registered_input_path(path: &str) -> bool {
    INPUT_LOCATIONS
        .iter()
        .any(|(directory, suffix)| is_safe_relative(path, directory, suffix))
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Facts count for the non-empty rule: top-level arrays count entries, objects
/// count keys. Process facts get a stricter dedicated check.
fn fact_entry_count(facts: &Json) -> usize {
    match facts {
        Json::Array(items) => items.len(),
        Json::Object(pairs) => pairs.len(),
        _ => 0,
    }
}

fn facts_kind_is_ordered(kind: &str) -> bool {
    ORDERED_FACTS_KINDS.contains(&kind)
}

#[test]
fn manifest_has_unique_well_formed_cases() {
    let manifest = load_manifest();
    assert_eq!(
        manifest.get("schema_version").and_then(Json::as_i64),
        Some(1),
        "manifest schema_version must be 1"
    );
    let all_cases = cases(&manifest);
    assert!(!all_cases.is_empty(), "manifest registers no cases");

    let mut seen_ids = BTreeSet::new();
    for case in &all_cases {
        let case_id = case_str(case, "case_id");
        assert!(!case_id.is_empty(), "case without case_id: {case:?}");
        assert!(is_kebab_case(case_id), "case_id {case_id:?} is not kebab-case");
        assert!(seen_ids.insert(case_id.to_owned()), "duplicate case_id {case_id:?}");

        let owner = case_str(case, "owner_package");
        assert!(is_valid_owner(owner), "case {case_id}: bad owner_package {owner:?}");

        let status = case_str(case, "status");
        assert!(
            matches!(status, "active" | "planned"),
            "case {case_id}: bad status {status:?}"
        );

        let notes = case_str(case, "notes");
        assert!(!notes.is_empty(), "case {case_id}: notes must explain the case");

        let outcome = expected_field(case, "outcome").and_then(Json::as_str).unwrap_or_default();
        if outcome != "pass" {
            let code = outcome.strip_prefix("error:").unwrap_or("");
            assert!(
                KNOWN_ERROR_CODES.contains(&code),
                "case {case_id}: outcome {outcome:?} is neither pass nor a known error:<Code>"
            );
        }

        let facts_kind = expected_field(case, "facts_kind").and_then(Json::as_str);
        assert!(
            matches!(
                facts_kind,
                Some(
                    "references"
                        | "classes"
                        | "source"
                        | "manifest"
                        | "dex-catalog"
                        | "process"
                        | "reference-archive"
                )
            ),
            "case {case_id}: bad facts_kind {facts_kind:?}"
        );

        let facts_path = expected_field(case, "facts_path").and_then(Json::as_str);
        if let Some(path) = facts_path {
            assert!(
                is_safe_facts_path(path),
                "case {case_id}: facts_path {path:?} must be expected/<name>.json or corpus/expected/<case>/<name>.json"
            );
        }
        if status == "planned" {
            assert!(
                facts_path.is_none(),
                "case {case_id}: planned cases register their target facts_kind but no facts file yet"
            );
        }

        let matrix_ids = case
            .get("matrix_ids")
            .and_then(Json::as_array)
            .unwrap_or_default();
        assert!(
            !matrix_ids.is_empty(),
            "case {case_id}: matrix_ids must not be empty"
        );
        for id in matrix_ids {
            let id = id.as_str().unwrap_or_default();
            assert!(
                ACCEPTANCE_IDS.contains(&id),
                "case {case_id}: unknown matrix id {id:?}"
            );
        }
        let audit_refs = case.get("audit_refs").and_then(Json::as_array);
        assert!(
            audit_refs.is_some_and(|refs| refs.iter().all(|value| matches!(value, Json::Str(_)))),
            "case {case_id}: audit_refs must be an array of strings"
        );

        let origin = case
            .get("source")
            .and_then(|source| source.get("origin"))
            .and_then(Json::as_str)
            .unwrap_or_default();
        assert!(
            matches!(origin, "generated" | "python-main" | "fdroid" | "external" | "process"),
            "case {case_id}: bad source.origin {origin:?}"
        );

        let input = case.get("input");
        let input_is_null = input.is_none_or(Json::is_null);
        match status {
            "planned" => assert!(
                input_is_null,
                "case {case_id}: planned cases must not carry input bytes yet"
            ),
            _ if facts_kind == Some("process") => assert!(
                input_is_null,
                "case {case_id}: process cases verify procedures, not input bytes"
            ),
            _ => assert!(
                !input_is_null,
                "case {case_id}: active cases with facts need a registered input"
            ),
        }
        if let Some(input) = input.filter(|value| !value.is_null()) {
            let path = input.get("path").and_then(Json::as_str).unwrap_or_default();
            assert!(
                is_registered_input_path(path),
                "case {case_id}: input.path {path:?} must be a flat file under inputs/ or corpus/apks/"
            );
            let sha = input.get("sha256").and_then(Json::as_str).unwrap_or_default();
            assert!(
                is_lower_hex_64(sha),
                "case {case_id}: input.sha256 must be 64 lowercase hex chars"
            );
            assert!(
                input.get("size").is_some_and(|size| matches!(size, Json::Int(_))),
                "case {case_id}: input.size must be an integer"
            );
        }
    }
}

#[test]
fn every_acceptance_id_is_covered_by_at_least_one_case() {
    let manifest = load_manifest();
    let mut covered = BTreeSet::new();
    for case in cases(&manifest) {
        for id in case.get("matrix_ids").and_then(Json::as_array).unwrap_or_default() {
            covered.insert(id.as_str().unwrap_or_default().to_owned());
        }
    }
    for id in ACCEPTANCE_IDS {
        assert!(
            covered.contains(id),
            "acceptance id {id} has no case in the manifest"
        );
    }
    assert_eq!(
        covered.len(),
        ACCEPTANCE_IDS.len(),
        "manifest and acceptance matrix ID sets disagree"
    );
}

#[test]
fn active_inputs_exist_with_matching_sha256_and_size() {
    for case in cases(&load_manifest()) {
        let case_id = case_str(&case, "case_id");
        if case_str(&case, "status") != "active" {
            continue;
        }
        let facts_kind = expected_field(&case, "facts_kind").and_then(Json::as_str);
        let Some(input) = case.get("input").filter(|value| !value.is_null()) else {
            assert_eq!(
                facts_kind,
                Some("process"),
                "active case {case_id} without input must be a process case"
            );
            continue;
        };
        let path = input.get("path").and_then(Json::as_str).unwrap();
        let bytes = fs::read(contracts_dir().join(path))
            .unwrap_or_else(|error| panic!("case {case_id}: read {path}: {error}"));
        let expected_size = input.get("size").and_then(Json::as_i64).unwrap();
        assert_eq!(
            bytes.len() as i64,
            expected_size,
            "case {case_id}: {path} size disagrees with the manifest"
        );
        let expected_sha = input.get("sha256").and_then(Json::as_str).unwrap();
        let actual_sha = sha::hex_lower(&sha::sha256(&bytes));
        assert_eq!(
            actual_sha, expected_sha,
            "case {case_id}: {path} sha256 disagrees with the manifest"
        );
    }
}

#[test]
fn generated_inputs_match_the_registered_generators() {
    // The shared builder must first reproduce the Python baseline exactly.
    let base_dex = dex::make_dex();
    let statics_dex = dex::make_static_field_dex();
    assert_eq!(
        sha::hex_lower(&sha::sha256(&base_dex)),
        PYTHON_MAKE_DEX_SHA256,
        "Rust make_dex() no longer matches the Python baseline output"
    );
    assert_eq!(
        sha::hex_lower(&sha::sha256(&statics_dex)),
        PYTHON_MAKE_STATIC_FIELD_DEX_SHA256,
        "Rust make_static_field_dex() no longer matches the Python baseline output"
    );

    let read_input = |name: &str| {
        fs::read(contracts_dir().join("inputs").join(name))
            .unwrap_or_else(|error| panic!("read input {name}: {error}"))
    };

    let regex_dex = dex::make_regex_string_dex();
    assert_eq!(read_input("g01-regex-string.dex"), regex_dex);
    assert_eq!(
        read_input("g01-regex-string.apk"),
        apk::apk_with_single_dex("classes.dex", &regex_dex)
    );
    assert_eq!(read_input("g02-static-initializers.dex"), statics_dex);
    assert_eq!(
        read_input("g02-static-initializers.apk"),
        apk::apk_with_single_dex("classes.dex", &statics_dex)
    );

    let zeroed = dex::zero_checksum_header(&base_dex);
    assert_eq!(
        read_input("g03-zero-checksum.apk"),
        apk::apk_with_single_dex("classes.dex", &zeroed)
    );
    // The zeroing must touch exactly the checksum/signature window.
    assert!(zeroed[8..32].iter().all(|byte| *byte == 0));
    assert_eq!(&base_dex[..8], &zeroed[..8]);
    assert_eq!(&base_dex[32..], &zeroed[32..]);
}

#[test]
fn pass_case_facts_parse_and_carry_at_least_one_fact() {
    for case in cases(&load_manifest()) {
        let case_id = case_str(&case, "case_id");
        if case_str(&case, "status") != "active" {
            continue;
        }
        let Some(outcome) = expected_field(&case, "outcome").and_then(Json::as_str) else {
            panic!("case {case_id}: expected.outcome missing");
        };
        if outcome != "pass" {
            continue;
        }
        let Some(facts_path) = expected_field(&case, "facts_path").and_then(Json::as_str) else {
            panic!("case {case_id}: pass case without facts_path");
        };
        let text = fs::read_to_string(contracts_dir().join(facts_path))
            .unwrap_or_else(|error| panic!("case {case_id}: read {facts_path}: {error}"));
        let facts = json::parse(&text)
            .unwrap_or_else(|error| panic!("case {case_id}: parse {facts_path}: {error}"));

        if expected_field(&case, "facts_kind").and_then(Json::as_str) == Some("process") {
            for key in ["procedure", "pass_criteria"] {
                let value = facts
                    .get(key)
                    .and_then(Json::as_str)
                    .unwrap_or_default()
                    .trim();
                assert!(
                    !value.is_empty(),
                    "case {case_id}: process facts need a non-empty {key}"
                );
            }
        } else if expected_field(&case, "facts_kind").and_then(Json::as_str) == Some("reference-archive")
        {
            // Pinned baseline archives must say exactly which reference
            // produced them and how (QUAL-02 provenance).
            for key in ["python_commit", "androguard"] {
                assert!(
                    facts.get(key).and_then(Json::as_str).is_some_and(|v| !v.trim().is_empty()),
                    "case {case_id}: reference-archive facts need a non-empty {key}"
                );
            }
            assert!(
                facts
                    .get("commands")
                    .and_then(Json::as_array)
                    .is_some_and(|commands| !commands.is_empty()),
                "case {case_id}: reference-archive facts need the command list"
            );
        } else {
            assert!(
                fact_entry_count(&facts) >= 1,
                "case {case_id}: facts in {facts_path} carry no fact entries"
            );
        }
    }
}

#[test]
fn comparator_flags_removed_references_and_edited_source_text() {
    // Control: identical facts compare clean.
    let g02_text =
        fs::read_to_string(contracts_dir().join("expected/g02-static-initializers.json")).unwrap();
    let g02_facts = json::parse(&g02_text).expect("g02 facts parse");
    assert!(compare_facts(&g02_facts, &g02_facts.clone(), false).is_empty());

    // Removing one real reference target must be flagged.
    let g01_text =
        fs::read_to_string(contracts_dir().join("expected/g01-regex-string.json")).unwrap();
    let g01_facts = json::parse(&g01_text).expect("g01 facts parse");
    let mut mutated = g01_facts.clone();
    let queries = mutated
        .get_mut("queries")
        .and_then(Json::as_array_mut)
        .expect("g01 facts have queries");
    let regex_query = queries
        .iter_mut()
        .find(|query| {
            query.get("query").and_then(|q| q.get("mode")).and_then(Json::as_str) == Some("regex")
                && query.get("query").and_then(|q| q.get("pattern")).and_then(Json::as_str)
                    == Some("tok.n")
        })
        .expect("tok.n regex query present");
    let targets = regex_query
        .get_mut("references")
        .and_then(Json::as_array_mut)
        .and_then(|references| references.first_mut())
        .and_then(|reference| reference.get_mut("targets"))
        .and_then(Json::as_array_mut)
        .expect("tok.n query has reference targets");
    assert!(targets.len() >= 2, "tok.n query must expect both strings");
    targets.remove(1); // drop the "tokens" hit
    let diffs = compare_facts(&g01_facts, &mutated, false);
    assert!(
        !diffs.is_empty(),
        "comparator must flag a removed reference; got none"
    );

    // Editing a source text expectation must be flagged.
    let mut edited = g02_facts.clone();
    let must_match = edited
        .get_mut("source_must_match")
        .and_then(Json::as_array_mut)
        .expect("g02 facts have source_must_match");
    let mut changed = false;
    for assertion in must_match.iter_mut() {
        if let Some(Json::Str(regex)) = assertion.get_mut("regex")
            && regex.contains("22")
        {
            *regex = regex.replace("22", "23");
            changed = true;
        }
    }
    assert!(changed, "g02 facts must contain the SECOND = 22 assertion");
    let diffs = compare_facts(&g02_facts, &edited, false);
    assert!(
        !diffs.is_empty(),
        "comparator must flag an edited source text expectation; got none"
    );

    // Top-level arrays compare as multisets: shuffling is equal, dropping is not.
    let first = Json::Array(vec![Json::Int(1), Json::Int(2)]);
    let shuffled = Json::Array(vec![Json::Int(2), Json::Int(1)]);
    assert!(compare_facts(&first, &shuffled, false).is_empty());
    let dropped = Json::Array(vec![Json::Int(1)]);
    assert!(!compare_facts(&first, &dropped, false).is_empty());

    // Ordered kinds (manifest facts) keep document order; the registered
    // behavior kinds do not.
    assert!(facts_kind_is_ordered("manifest"));
    assert!(!facts_kind_is_ordered("references"));
    assert!(!compare_facts(&first, &shuffled, facts_kind_is_ordered("manifest")).is_empty());

    // Integer and float values never match.
    let ints = Json::Array(vec![Json::Int(11)]);
    let floats = Json::Array(vec![Json::Float(11.0)]);
    assert!(!compare_facts(&ints, &floats, false).is_empty());
}

#[test]
fn sha256_verification_fails_on_a_flipped_input_byte() {
    let path = contracts_dir().join("inputs/g02-static-initializers.dex");
    let bytes = fs::read(&path).expect("read g02 dex input");
    assert_eq!(sha::hex_lower(&sha::sha256(&bytes)), PYTHON_MAKE_STATIC_FIELD_DEX_SHA256);

    let mut flipped = bytes.clone();
    let index = flipped.len() / 2;
    flipped[index] ^= 0x01;
    assert_eq!(flipped.len(), bytes.len());
    assert_ne!(
        sha::hex_lower(&sha::sha256(&flipped)),
        PYTHON_MAKE_STATIC_FIELD_DEX_SHA256,
        "a flipped input byte must fail the recorded sha256 check"
    );
}

/// Regenerates the committed fixture inputs from the support builders.
///
/// Not part of a normal run: opt in with `ASC_REGEN_FIXTURES=1` after changing
/// a generator, then update manifest.json's sha256/size fields (the other
/// tests in this file fail until they agree). See generators.md.
#[test]
fn regenerate_fixture_inputs_when_explicitly_requested() {
    if std::env::var("ASC_REGEN_FIXTURES").ok().as_deref() != Some("1") {
        return;
    }
    let inputs = contracts_dir().join("inputs");
    fs::create_dir_all(&inputs).expect("create inputs directory");

    let g01_dex = dex::make_regex_string_dex();
    let g02_dex = dex::make_static_field_dex();
    let g03_dex = dex::zero_checksum_header(&dex::make_dex());
    let outputs = [
        ("g01-regex-string.dex", g01_dex.clone()),
        ("g01-regex-string.apk", apk::apk_with_single_dex("classes.dex", &g01_dex)),
        ("g02-static-initializers.dex", g02_dex.clone()),
        ("g02-static-initializers.apk", apk::apk_with_single_dex("classes.dex", &g02_dex)),
        ("g03-zero-checksum.apk", apk::apk_with_single_dex("classes.dex", &g03_dex)),
    ];
    for (name, bytes) in &outputs {
        fs::write(inputs.join(name), bytes).expect("write fixture input");
        println!(
            "{name}: size {} sha256 {}",
            bytes.len(),
            sha::hex_lower(&sha::sha256(bytes))
        );
    }
}

