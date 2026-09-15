//! Argument parsing (CLI-01): clap definitions, the shared option model and
//! the option/limit validation that must fail before any input is read.
//!
//! The shared options live once in [`CommonArgs`]; every command flattens it,
//! and `findrefs` flattens it a second time after the query kind so all
//! common options are accepted in both positions (interfaces.md §6). The
//! later occurrence wins for scalars; `--limit` occurrences accumulate.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "rasc", version, about = "Native Rust APK and DEX analysis CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable text (default).
    Text,
    /// One JSON envelope object with a single trailing newline.
    Json,
}

/// Options shared by every command.
#[derive(Debug, Args, Clone, Default)]
pub struct CommonArgs {
    /// Worker threads for the parallel entry fold (default: all cores; must
    /// be positive).
    #[arg(long, alias = "thread")]
    pub threads: Option<usize>,
    /// Print stats and timings on stderr; never changes the payload bytes.
    #[arg(long)]
    pub debug: bool,
    /// Also write the payload to this file (atomically replaced) in addition
    /// to stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Payload format: text or json (default: text).
    #[arg(long)]
    pub format: Option<Format>,
    /// Cancel the operation after N milliseconds (positive integer).
    #[arg(long)]
    pub timeout_ms: Option<u64>,
    /// Override a resource limit: KEY=VALUE with KEY from the table below and
    /// VALUE a decimal positive integer (bytes or count, no unit suffix).
    /// Repeatable; unknown or repeated keys exit 2. Keys marked (accepted)
    /// are validated but not yet enforced; their internal defaults stay in
    /// effect and a stderr note says so:
    ///   input-bytes, entry-bytes, decoded-bytes, engine-bytes, entries,
    ///   string-units, table-items, result-items, locations, result-bytes,
    ///   depth, xml-nodes, xml-attributes, pattern-bytes, regex-bytes,
    ///   regex-steps;
    ///   dexes (accepted), code-units (accepted).
    #[arg(long = "limit")]
    pub limits: Vec<String>,
}

impl CommonArgs {
    /// Merges the before-kind and after-kind occurrences for `findrefs`.
    pub fn merge(outer: &Self, inner: &Self) -> Self {
        Self {
            threads: inner.threads.or(outer.threads),
            debug: outer.debug || inner.debug,
            output: inner.output.clone().or(outer.output.clone()),
            format: inner.format.or(outer.format),
            timeout_ms: inner.timeout_ms.or(outer.timeout_ms),
            limits: outer.limits.iter().chain(inner.limits.iter()).cloned().collect(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Locate a class in an APK and decompile it.
    Getclass(GetClassArgs),
    /// Find code references across every DEX in an APK.
    Findrefs(FindRefsArgs),
    /// Decode and print AndroidManifest.xml from an APK.
    Manifest(ManifestArgs),
    /// List classes defined across every DEX in an APK.
    Classes(ClassesArgs),
}

#[derive(Debug, Args)]
pub struct ClassesArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Case-insensitive substring filter over Java-style class names.
    #[arg(short, long)]
    pub filter: Option<String>,
    pub apk_path: PathBuf,
}

#[derive(Debug, Args)]
pub struct ManifestArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    pub apk_path: PathBuf,
}

#[derive(Debug, Args)]
pub struct GetClassArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Pin the class to one logical DEX: `<entry_ordinal>:<logical_ordinal>`
    /// (both zero-based, as shown by `classes` or `--format json`).
    #[arg(long)]
    pub dex: Option<String>,
    pub apk_path: PathBuf,
    pub dalvik_class: String,
}

#[derive(Debug, Args)]
pub struct FindRefsArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    pub apk_path: PathBuf,
    #[command(subcommand)]
    pub kind: FindKind,
}

impl FindKind {
    /// Whether this kind's value/member pattern was flagged .
    pub fn regex_mode(&self) -> bool {
        match self {
            FindKind::String(q) | FindKind::Type(q) => q.regex,
            FindKind::Method(q) | FindKind::Field(q) => q.regex,
        }
    }

}

impl FindRefsArgs {
    /// The common options given after the query kind.
    pub fn kind_common(&self) -> &CommonArgs {
        match &self.kind {
            FindKind::String(query) | FindKind::Type(query) => &query.common,
            FindKind::Method(query) | FindKind::Field(query) => &query.common,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum FindKind {
    /// String-constant references.
    String(ValueQuery),
    /// Type references.
    Type(ValueQuery),
    /// Method references.
    Method(MemberArgs),
    /// Field references.
    Field(MemberArgs),
}

#[derive(Debug, Args)]
pub struct ValueQuery {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Interpret the value as a regular expression instead of a literal
    /// substring.
    #[arg(long)]
    pub regex: bool,
    pub value: String,
}

#[derive(Debug, Args)]
pub struct MemberArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Interpret the member name (and a fuzzy class) as a regular expression;
    /// an exact `--class` descriptor is never affected.
    #[arg(long)]
    pub regex: bool,
    pub name: Option<String>,
    /// Constrain the target member's declaring class (Java dotted name or
    /// `Lpkg/Name;` descriptor).
    #[arg(long = "class")]
    pub class_name: Option<String>,
    /// Treat `--class` as a fuzzy pattern over the descriptor instead of an
    /// exact descriptor; requires `--class`.
    #[arg(long)]
    pub fuzzy_class: bool,
}

// ---------------------------------------------------------------------------
// Option and limit validation (all of it happens before the input is opened)
// ---------------------------------------------------------------------------

/// The worker count must be positive; zero is a syntax-level rejection.
pub fn validate_threads(threads: usize) -> Result<(), String> {
    if threads == 0 {
        return Err("worker count must be greater than zero".to_owned());
    }
    Ok(())
}

/// The deadline must be a positive number of milliseconds.
pub fn validate_timeout_ms(timeout_ms: u64) -> Result<(), String> {
    if timeout_ms == 0 {
        return Err("--timeout-ms must be greater than zero".to_owned());
    }
    Ok(())
}

/// One §5 limits-table key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LimitKey {
    InputBytes,
    EntryBytes,
    DecodedBytes,
    EngineBytes,
    Entries,
    Dexes,
    TableItems,
    StringUnits,
    Depth,
    XmlNodes,
    XmlAttributes,
    CodeUnits,
    ResultItems,
    Locations,
    ResultBytes,
    PatternBytes,
    RegexBytes,
    RegexSteps,
}

impl LimitKey {
    fn from_key(text: &str) -> Option<Self> {
        let key = match text {
            "input-bytes" => LimitKey::InputBytes,
            "entry-bytes" => LimitKey::EntryBytes,
            "decoded-bytes" => LimitKey::DecodedBytes,
            "engine-bytes" => LimitKey::EngineBytes,
            "entries" => LimitKey::Entries,
            "dexes" => LimitKey::Dexes,
            "table-items" => LimitKey::TableItems,
            "string-units" => LimitKey::StringUnits,
            "depth" => LimitKey::Depth,
            "xml-nodes" => LimitKey::XmlNodes,
            "xml-attributes" => LimitKey::XmlAttributes,
            "code-units" => LimitKey::CodeUnits,
            "result-items" => LimitKey::ResultItems,
            "locations" => LimitKey::Locations,
            "result-bytes" => LimitKey::ResultBytes,
            "pattern-bytes" => LimitKey::PatternBytes,
            "regex-bytes" => LimitKey::RegexBytes,
            "regex-steps" => LimitKey::RegexSteps,
            _ => return None,
        };
        Some(key)
    }

    /// The CLI spelling, for diagnostics.
    pub fn as_key(self) -> &'static str {
        match self {
            LimitKey::InputBytes => "input-bytes",
            LimitKey::EntryBytes => "entry-bytes",
            LimitKey::DecodedBytes => "decoded-bytes",
            LimitKey::EngineBytes => "engine-bytes",
            LimitKey::Entries => "entries",
            LimitKey::Dexes => "dexes",
            LimitKey::TableItems => "table-items",
            LimitKey::StringUnits => "string-units",
            LimitKey::Depth => "depth",
            LimitKey::XmlNodes => "xml-nodes",
            LimitKey::XmlAttributes => "xml-attributes",
            LimitKey::CodeUnits => "code-units",
            LimitKey::ResultItems => "result-items",
            LimitKey::Locations => "locations",
            LimitKey::ResultBytes => "result-bytes",
            LimitKey::PatternBytes => "pattern-bytes",
            LimitKey::RegexBytes => "regex-bytes",
            LimitKey::RegexSteps => "regex-steps",
        }
    }

    /// Whether this build actually routes the key into an operation. The
    /// remaining keys (`dexes`, `code-units`) belong to engine internals
    /// whose defaults are still in effect.
    pub fn enforced(self) -> bool {
        matches!(
            self,
            LimitKey::InputBytes
                | LimitKey::EngineBytes
                | LimitKey::Entries
                | LimitKey::EntryBytes
                | LimitKey::DecodedBytes
                | LimitKey::TableItems
                | LimitKey::StringUnits
                | LimitKey::Depth
                | LimitKey::XmlNodes
                | LimitKey::XmlAttributes
                | LimitKey::ResultItems
                | LimitKey::Locations
                | LimitKey::ResultBytes
                | LimitKey::PatternBytes
                | LimitKey::RegexBytes
                | LimitKey::RegexSteps
        )
    }
}

/// One validated `--limit KEY=VALUE` occurrence.
#[derive(Clone, Copy, Debug)]
pub struct ParsedLimit {
    pub key: LimitKey,
    pub value: u64,
}

/// Parses and validates the accumulated `--limit` occurrences: KEY must be
/// on the §5 whitelist, VALUE a decimal positive integer, and no key twice.
pub fn parse_limits(raw: &[String]) -> Result<Vec<ParsedLimit>, String> {
    let mut parsed = Vec::with_capacity(raw.len());
    let mut seen: Vec<LimitKey> = Vec::new();
    for item in raw {
        let (key_text, value_text) = item
            .split_once('=')
            .ok_or_else(|| format!("--limit expects KEY=VALUE, got {item:?}"))?;
        let key = LimitKey::from_key(key_text)
            .ok_or_else(|| format!("unknown --limit key {key_text:?}; see --help for the table"))?;
        if seen.contains(&key) {
            return Err(format!("--limit key {key_text:?} was given more than once"));
        }
        seen.push(key);
        if value_text.is_empty() || !value_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!(
                "--limit {} expects a decimal positive integer, got {value_text:?}",
                key.as_key()
            ));
        }
        let value = value_text
            .parse::<u64>()
            .map_err(|_| format!("--limit {} value {value_text:?} is too large", key.as_key()))?;
        if value == 0 {
            return Err(format!(
                "--limit {} must be greater than zero",
                key.as_key()
            ));
        }
        parsed.push(ParsedLimit { key, value });
    }
    Ok(parsed)
}

/// The resolved resource limits this CLI build enforces; defaults are the
/// initial values from interfaces.md §5.
#[derive(Clone, Copy, Debug)]
pub struct EffectiveLimits {
    pub max_input_bytes: u64,
    pub max_engine_owned_bytes: u64,
    pub max_entry_bytes: u64,
    pub max_total_decoded_bytes: u64,
    pub max_archive_entries: usize,
    pub max_xml_depth: usize,
    pub max_xml_nodes: usize,
    pub max_xml_attributes: usize,
    pub max_result_items: usize,
    pub max_reference_locations: u64,
    pub max_string_units: usize,
    pub max_table_items: usize,
    pub max_result_bytes: usize,
    pub pattern: asc_core::model::PatternLimits,
}

impl EffectiveLimits {
    /// Applies the enforced keys; non-enforced keys were accepted with a
    /// stderr note and are ignored here.
    pub fn new(limits: &[ParsedLimit]) -> Self {
        let mut resolved = Self {
            max_input_bytes: 512 * 1024 * 1024,
            max_engine_owned_bytes: 2 * 1024 * 1024 * 1024,
            max_entry_bytes: 256 * 1024 * 1024,
            max_total_decoded_bytes: 1024 * 1024 * 1024,
            max_archive_entries: 100_000,
            max_xml_depth: 256,
            max_xml_nodes: 1_000_000,
            max_xml_attributes: 1_000_000,
            max_result_items: 250_000,
            max_reference_locations: 1_000_000,
            max_string_units: 1_048_576,
            max_table_items: 4_000_000,
            max_result_bytes: 128 * 1024 * 1024,
            pattern: asc_core::model::PatternLimits::DEFAULT,
        };
        for limit in limits {
            let value = usize::try_from(limit.value).unwrap_or(usize::MAX);
            match limit.key {
                LimitKey::InputBytes => resolved.max_input_bytes = limit.value,
                LimitKey::EntryBytes => resolved.max_entry_bytes = limit.value,
                LimitKey::DecodedBytes => resolved.max_total_decoded_bytes = limit.value,
                LimitKey::ResultItems => resolved.max_result_items = value,
                LimitKey::Locations => resolved.max_reference_locations = limit.value,
                LimitKey::StringUnits => resolved.max_string_units = value,
                LimitKey::TableItems => resolved.max_table_items = value,
                LimitKey::ResultBytes => resolved.max_result_bytes = value,
                LimitKey::PatternBytes => resolved.pattern.max_pattern_bytes = value,
                LimitKey::RegexBytes => resolved.pattern.regex_compile_bytes = value,
                LimitKey::RegexSteps => resolved.pattern.regex_backtrack_limit = value,
                LimitKey::EngineBytes => resolved.max_engine_owned_bytes = value as u64,
                LimitKey::Entries => resolved.max_archive_entries = value,
                LimitKey::Depth => resolved.max_xml_depth = value,
                LimitKey::XmlNodes => resolved.max_xml_nodes = value,
                LimitKey::XmlAttributes => resolved.max_xml_attributes = value,
                LimitKey::Dexes | LimitKey::CodeUnits => {}
            }
        }
        resolved
    }
}
