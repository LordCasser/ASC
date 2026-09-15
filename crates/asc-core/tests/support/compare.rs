//! Structured comparison of expected facts against actual (candidate) facts.
//!
//! Semantics, fixed by A00-a for all later contract tests:
//! - objects compare key-exactly: every key must exist on both sides;
//! - top-level arrays compare as multisets unless the caller passes
//!   `ordered = true` (the manifest facts kind is the one ordered kind);
//!   nested arrays always compare element-by-element in order;
//! - numbers distinguish integers from floats: `1` and `1.0` never match;
//! - a non-empty difference list means the candidate output is wrong.

use super::json::Json;

/// Compare expected against actual facts. Returns human-readable differences;
/// an empty result means the facts agree.
pub fn compare_facts(expected: &Json, actual: &Json, ordered: bool) -> Vec<String> {
    let mut diffs = Vec::new();
    if let (Json::Array(expected_items), Json::Array(actual_items)) = (expected, actual)
        && !ordered
    {
        compare_multiset(expected_items, actual_items, &mut diffs);
        return diffs;
    }
    compare_value(expected, actual, "$", &mut diffs);
    diffs
}

fn compare_multiset(expected: &[Json], actual: &[Json], diffs: &mut Vec<String>) {
    let mut consumed = vec![false; actual.len()];
    for expected_item in expected {
        let mut found = None;
        for (index, actual_item) in actual.iter().enumerate() {
            if !consumed[index] && deep_equal(expected_item, actual_item) {
                found = Some(index);
                break;
            }
        }
        match found {
            Some(index) => consumed[index] = true,
            None => diffs.push(format!("missing fact entry: {}", brief(expected_item))),
        }
    }
    for (index, taken) in consumed.iter().enumerate() {
        if !taken {
            diffs.push(format!("unexpected fact entry: {}", brief(&actual[index])));
        }
    }
}

fn compare_value(expected: &Json, actual: &Json, path: &str, diffs: &mut Vec<String>) {
    match (expected, actual) {
        (Json::Null, Json::Null) => {}
        (Json::Bool(expected), Json::Bool(actual)) => {
            if expected != actual {
                diffs.push(format!("{path}: expected {expected}, actual {actual}"));
            }
        }
        (Json::Int(expected), Json::Int(actual)) => {
            if expected != actual {
                diffs.push(format!("{path}: expected {expected}, actual {actual}"));
            }
        }
        (Json::Float(expected), Json::Float(actual)) => {
            if expected != actual {
                diffs.push(format!("{path}: expected {expected}, actual {actual}"));
            }
        }
        (Json::Str(expected), Json::Str(actual)) => {
            if expected != actual {
                diffs.push(format!("{path}: expected {expected:?}, actual {actual:?}"));
            }
        }
        (Json::Array(expected), Json::Array(actual)) => {
            if expected.len() != actual.len() {
                diffs.push(format!(
                    "{path}: expected {} entries, actual {}",
                    expected.len(),
                    actual.len()
                ));
            }
            for (index, (expected_item, actual_item)) in
                expected.iter().zip(actual.iter()).enumerate()
            {
                compare_value(expected_item, actual_item, &format!("{path}[{index}]"), diffs);
            }
        }
        (Json::Object(expected), Json::Object(actual)) => {
            for (key, expected_value) in expected {
                match object_get(actual, key) {
                    Some(actual_value) => {
                        compare_value(expected_value, actual_value, &format!("{path}.{key}"), diffs);
                    }
                    None => diffs.push(format!("{path}.{key}: key missing in actual facts")),
                }
            }
            for (key, _) in actual {
                if object_get(expected, key).is_none() {
                    diffs.push(format!("{path}.{key}: unexpected key in actual facts"));
                }
            }
        }
        _ => diffs.push(format!(
            "{path}: expected {}, actual {}",
            expected.type_name(),
            actual.type_name()
        )),
    }
}

/// Order-insensitive structural equality used for multiset matching.
fn deep_equal(expected: &Json, actual: &Json) -> bool {
    match (expected, actual) {
        (Json::Null, Json::Null) => true,
        (Json::Bool(expected), Json::Bool(actual)) => expected == actual,
        (Json::Int(expected), Json::Int(actual)) => expected == actual,
        (Json::Float(expected), Json::Float(actual)) => expected == actual,
        (Json::Str(expected), Json::Str(actual)) => expected == actual,
        (Json::Array(expected), Json::Array(actual)) => {
            expected.len() == actual.len()
                && expected.iter().zip(actual.iter()).all(|(l, r)| deep_equal(l, r))
        }
        (Json::Object(expected), Json::Object(actual)) => {
            expected.len() == actual.len()
                && expected.iter().all(|(key, value)| {
                    object_get(actual, key).is_some_and(|other| deep_equal(value, other))
                })
        }
        _ => false,
    }
}

/// Key lookup on destructured object pairs.
fn object_get<'a>(pairs: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    pairs.iter().find(|(name, _)| name == key).map(|(_, value)| value)
}

/// Short one-line preview for difference messages.
fn brief(value: &Json) -> String {
    let text = match value {
        Json::Null => "null".to_owned(),
        Json::Bool(value) => value.to_string(),
        Json::Int(value) => value.to_string(),
        Json::Float(value) => value.to_string(),
        Json::Str(value) => format!("{value:?}"),
        Json::Array(items) => format!("[{} items]", items.len()),
        Json::Object(pairs) => {
            let keys: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
            format!("{{{}}}", keys.join(","))
        }
    };
    if text.chars().count() > 80 {
        let truncated: String = text.chars().take(77).collect();
        format!("{truncated}...")
    } else {
        text
    }
}
