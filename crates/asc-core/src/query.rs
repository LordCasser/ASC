//! Query construction: validated domain queries per interfaces.md §1.
//!
//! The CLI builds these before any input is read; the scanner consumes
//! them against decoded candidates. The legacy `Query`/`MemberQuery`/
//! `ClassQuery` layer (and the anyhow dependency) left with A07.

use crate::error::Error;
use crate::model::{
    ClassConstraint, ClassDescriptor, MemberQuery as ContractMemberQuery, Pattern, PatternLimits,
    ReferenceQuery,
};

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
