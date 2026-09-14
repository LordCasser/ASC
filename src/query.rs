//! The search query model shared by the CLI and the scanners.
//!
//! Two layers live here:
//! - the *contract* layer (`ReferenceQuery`, `Pattern`, descriptor helpers)
//!   builds validated domain queries per interfaces.md §1; A03's scanner and
//!   A07's integration consume it;
//! - the *legacy* layer (`Query`, `MemberQuery`, `ClassQuery`) is the current
//!   CLI/scanner glue. It is a short-lived bridge: A07 deletes it once the
//!   structured path is integrated. Do not extend it.

use crate::error::Error;
use crate::model::{
    ClassConstraint, ClassDescriptor, MemberQuery as ContractMemberQuery, Pattern, PatternLimits,
    ReferenceQuery,
};
use anyhow::{Result, bail};

// ---------------------------------------------------------------------------
// Contract layer (frozen by A01)
// ---------------------------------------------------------------------------

/// Whether a pattern argument is a literal substring or a regex.
// Contract layer, wired into the CLI by A07/A08 (tests use it now).
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchMode {
    Literal,
    Regex,
}

/// Builds a `findrefs` string query. String literals are never transformed:
/// dots and slashes belong to the searched text.
// Contract layer, wired into the CLI by A07/A08 (tests use it now).
#[allow(dead_code)]
pub fn string_query(pattern: &str, mode: MatchMode, limits: &PatternLimits) -> Result<ReferenceQuery, Error> {
    Ok(ReferenceQuery::String(build_pattern(pattern, mode, limits)?))
}

/// Builds a `findrefs` type query. A *literal* pattern gets the Java
/// dotted-name conversion (dots become package separators) so `java.lang.String`
/// behaves like the descriptor it names; regex patterns match descriptor text
/// as written and are never rewritten.
// Contract layer, wired into the CLI by A07/A08 (tests use it now).
#[allow(dead_code)]
pub fn type_query(pattern: &str, mode: MatchMode, limits: &PatternLimits) -> Result<ReferenceQuery, Error> {
    let effective = match mode {
        MatchMode::Literal => java_dotted_to_descriptor_form(pattern),
        MatchMode::Regex => pattern.to_owned(),
    };
    Ok(ReferenceQuery::Type(build_pattern(&effective, mode, limits)?))
}

/// A member (field/method) query's inputs before construction.
// Contract layer, wired into the CLI by A07/A08 (tests use it now).
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct MemberSpec<'a> {
    /// The member name pattern, if any.
    pub name: Option<&'a str>,
    /// How the name pattern (and a fuzzy class pattern) is interpreted.
    pub mode: MatchMode,
    /// Exact (`Lpkg/Name;`, Java dotted accepted) or fuzzy class constraint.
    pub class: Option<ClassSpec<'a>>,
}

/// The declaring-class half of a member query.
// Contract layer, wired into the CLI by A07/A08 (tests use it now).
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum ClassSpec<'a> {
    /// `--class` without `--fuzzy-class`: exact descriptor, never regex, never
    /// rewritten by `--regex`.
    Exact(&'a str),
    /// `--fuzzy-class`: a substring (literal) or regex pattern over the
    /// descriptor text; literal input gets the dotted-name conversion.
    Fuzzy(&'a str),
}

/// Builds a field or method query; both constraints are optional but at least
/// one must be present.
// Contract layer, wired into the CLI by A07/A08 (tests use it now).
#[allow(dead_code)]
pub fn member_query(
    field: bool,
    spec: MemberSpec<'_>,
    limits: &PatternLimits,
) -> Result<ReferenceQuery, Error> {
    let name = match spec.name {
        Some(text) => Some(build_pattern(text, spec.mode, limits)?),
        None => None,
    };
    let class = match spec.class {
        Some(ClassSpec::Exact(input)) => Some(ClassConstraint::Exact(exact_descriptor(input)?)),
        Some(ClassSpec::Fuzzy(input)) => {
            let effective = match spec.mode {
                MatchMode::Literal => java_dotted_to_descriptor_form(input),
                MatchMode::Regex => input.to_owned(),
            };
            Some(ClassConstraint::Fuzzy(build_pattern(&effective, spec.mode, limits)?))
        }
        None => None,
    };
    let query = ContractMemberQuery::new(name, class)?;
    Ok(if field { ReferenceQuery::Field(query) } else { ReferenceQuery::Method(query) })
}

/// Normalizes a class argument to a validated `Lpkg/Name;` descriptor.
///
/// Accepts Java dotted names, descriptors with or without the `L`/`;`
/// delimiters and mixed separators, then validates the result: no empty
/// names, no `[` (arrays) or stray `;` inside the body. Primitive spellings
/// become the class of that name in the default package (`I` -> `LI;`), which
/// is a legal class descriptor, not the primitive type.
// Contract layer, wired into the CLI by A07/A08 (tests use it now).
#[allow(dead_code)]
pub fn exact_descriptor(input: &str) -> Result<ClassDescriptor, Error> {
    if input.is_empty() {
        return Err(Error::invalid_query("class name cannot be empty"));
    }
    let body = if let Some(stripped) = input
        .strip_prefix('L')
        .and_then(|rest| rest.strip_suffix(';'))
        .filter(|_| input.contains('/'))
    {
        stripped.to_owned()
    } else {
        let no_prefix = input.strip_prefix('L').unwrap_or(input);
        let no_suffix = no_prefix.strip_suffix(';').unwrap_or(no_prefix);
        no_suffix.replace('.', "/")
    };
    if body.is_empty() {
        return Err(Error::invalid_query(format!("class name {input:?} is empty")));
    }
    ClassDescriptor::from_normalized(format!("L{body};"))
}

/// Dots become slashes for literal type/fuzzy patterns: a Java package name
/// should match the descriptor it names. Regex input is never passed here.
// Contract layer, wired into the CLI by A07/A08 (tests use it now).
#[allow(dead_code)]
pub fn java_dotted_to_descriptor_form(pattern: &str) -> String {
    pattern.replace('.', "/")
}

fn build_pattern(pattern: &str, mode: MatchMode, limits: &PatternLimits) -> Result<Pattern, Error> {
    match mode {
        MatchMode::Literal => Pattern::literal(pattern, limits),
        MatchMode::Regex => Pattern::regex(pattern, limits),
    }
}

/// Parses the `--dex <entry_ordinal>:<logical_ordinal>` selector. Syntax
/// errors (missing colon, non-digits, u32 overflow, negative) are distinct
/// from a well-formed selector that names no DEX.
// Contract layer, wired into the CLI by A07/A08 (tests use it now).
#[allow(dead_code)]
pub fn parse_dex_selector(input: &str) -> Result<(u32, u32), Error> {
    let syntax = || Error::invalid_query(format!("--dex expects <entry>:<logical>, got {input:?}"));
    let (entry, logical) = input.split_once(':').ok_or_else(syntax)?;
    let parse = |text: &str| -> Result<u32, Error> {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(syntax());
        }
        text.parse::<u32>().map_err(|_| syntax())
    };
    Ok((parse(entry)?, parse(logical)?))
}

// ---------------------------------------------------------------------------
// Legacy layer — removed by A07 when the structured path lands
// ---------------------------------------------------------------------------

/// What a `findrefs` invocation looks for.
#[derive(Clone, Debug)]
pub enum Query {
    String(String),
    Type(String),
    Method(MemberQuery),
    Field(MemberQuery),
}

/// A member query: at least one of a member name or a class constraint.
#[derive(Clone, Debug)]
pub struct MemberQuery {
    pub name: Option<String>,
    pub class: Option<ClassQuery>,
}

/// How a member query constrains the defining class.
#[derive(Clone, Debug)]
pub enum ClassQuery {
    /// A full `Lpkg/Name;` descriptor.
    Exact(String),
    /// A literal substring of the descriptor, in `pkg/Name` form.
    Fuzzy(String),
}

/// Normalizes a class name to the `Lpkg/Name;` descriptor form that `findrefs`
/// and `getclass` compare against the DEX tables.
///
/// Accepts dotted Java names, descriptors with or without their `L`/`;`
/// delimiters, and rejects the empty name.
pub fn format_class_name(name: &str) -> Result<String> {
    if name.is_empty() {
        bail!("Class name cannot be empty");
    }
    // A name that already looks like a descriptor is used as written, but only when
    // its slashes are there too: `Lcom.foo.Main;` still needs its dots normalised.
    // This mirrors the reference implementation exactly.
    if name.starts_with('L') && name.ends_with(';') && name.contains('/') {
        return Ok(name.to_owned());
    }
    let mut name = name.replace('.', "/");
    if !name.starts_with('L') {
        name.insert(0, 'L');
    }
    if !name.ends_with(';') {
        name.push(';');
    }
    Ok(name)
}

/// Normalizes a fuzzy class pattern by treating dots as package separators.
///
/// The reference implementation only replaces dots when the pattern has no slashes,
/// but that rule exists for its regex matcher, where a dot is a wildcard and
/// `com.example/Main` therefore matches `com/example/Main` by accident. rasc matches
/// literally, so leaving such a pattern alone would match nothing; replacing the dots
/// gives the same rows the reference reports for those inputs.
pub fn fuzzy_class_pattern(pattern: &str) -> String {
    pattern.replace('.', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every case here was read off the reference implementation's
    /// `_format_class_name` / `_normalize_class_query`.
    #[test]
    fn normalizes_class_names_like_the_reference() {
        for (input, expected) in [
            ("com.foo.Main", "Lcom/foo/Main;"),
            ("Lcom/foo/Main;", "Lcom/foo/Main;"),
            ("Lcom.foo.Main;", "Lcom/foo/Main;"),
            ("LMain;", "LMain;"),
            ("com/foo/Main", "Lcom/foo/Main;"),
            ("Main", "LMain;"),
            ("Lcom/foo/Main", "Lcom/foo/Main;"),
            ("com.foo.Main$Inner", "Lcom/foo/Main$Inner;"),
            ("Lcom/foo/Main$Inner;", "Lcom/foo/Main$Inner;"),
            ("I", "LI;"),
            ("[Lcom/foo/Main;", "L[Lcom/foo/Main;"),
            ("java.lang.String", "Ljava/lang/String;"),
            ("Lfoo.bar", "Lfoo/bar;"),
            ("foo.bar;", "Lfoo/bar;"),
        ] {
            assert_eq!(format_class_name(input).unwrap(), expected, "{input:?}");
        }
        assert!(format_class_name("").is_err());
    }

    #[test]
    fn normalizes_fuzzy_class_patterns_like_the_reference() {
        for (input, expected) in [
            ("com.foo", "com/foo"),
            ("com/foo", "com/foo"),
            ("com.foo/bar", "com/foo/bar"),
            ("com/foo.bar", "com/foo/bar"),
            ("Main", "Main"),
            ("", ""),
            ("Lcom/foo/Main;", "Lcom/foo/Main;"),
        ] {
            assert_eq!(fuzzy_class_pattern(input), expected, "{input:?}");
        }
    }
}
