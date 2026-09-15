//! CLI entry point: argument parsing, dispatch, output commitment.
//!
//! stdout carries a command's payload and nothing else: every diagnostic,
//! including `--debug` stats, goes to stderr, so redirecting a result can
//! never capture debug lines. An `-o` file receives exactly the bytes stdout
//! received (one serialization, committed to the file atomically first).
//!
//! Exit codes (interfaces.md §6): 0 complete success (incl. empty sets),
//! 1 input/analysis/output errors and incomplete decompilations, 2 argument
//! and query-construction errors, 130 cancellation (user or deadline).

use asc_core::bytes::OperationControl;
use asc_core::engine::{Engine, EngineOptions, InputKind, Limits};
use asc_core::error::{Error as CoreError, ErrorKind};
use asc_core::model::{ClassFilter, ClassSelector};
use asc_core::{dex, query};
use clap::Parser;
mod cli;
mod output;
mod render;
use cli::{Cli, Command, Format};
use render::CommandData;
use std::time::{Duration, Instant};

fn main() {
    restore_default_sigpipe();
    std::process::exit(run());
}

/// Restore the default `SIGPIPE` disposition so that piping into `head`,
/// `grep`, or a closed consumer terminates quietly, the way standard Unix
/// filters do.
///
/// Rust ignores `SIGPIPE` at startup, which turns an early-closed pipe into
/// a `BrokenPipe` write error and then a panic; with `panic = "abort"` that
/// aborts the process and prints a panic message for a completely normal
/// shell idiom.
#[cfg(unix)]
fn restore_default_sigpipe() {
    // SAFETY: setting the disposition of SIGPIPE to SIG_DFL is
    // async-signal-safe and only affects this process.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_default_sigpipe() {}

/// How the process exits: the code plus everything stderr needs.
enum Outcome {
    /// Complete success (including empty result sets).
    Success,
    /// `InvalidQuery` and argument-level rejections: exit 2.
    Usage(String),
    /// Analysis/input failures with a stable code: exit 1.
    Analysis(String),
    /// Output-layer failures: exit 1.
    Output(String),
    /// Cancellation (user or deadline): exit 130, stderr distinguishes.
    Cancelled(&'static str),
}

fn run() -> i32 {
    let args = Cli::parse();
    let outcome = match dispatch(args) {
        Ok(()) => Outcome::Success,
        Err(outcome) => outcome,
    };
    match &outcome {
        Outcome::Success => 0,
        Outcome::Usage(text) => {
            eprintln!("Error: InvalidQuery: {text}");
            2
        }
        Outcome::Analysis(text) => {
            eprintln!("Error: {text}");
            1
        }
        Outcome::Output(text) => {
            eprintln!("Error: {text}");
            1
        }
        Outcome::Cancelled(cause) => {
            eprintln!("Error: Cancelled: {cause}");
            130
        }
    }
}

fn dispatch(args: Cli) -> Result<(), Outcome> {
    match &args.command {
        Command::Getclass(args) => run_getclass(args),
        Command::Findrefs(args) => run_findrefs(args),
        Command::Manifest(args) => run_manifest(args),
        Command::Classes(args) => run_classes(args),
    }
}

fn core_outcome(error: CoreError) -> Outcome {
    match error.kind() {
        ErrorKind::InvalidQuery => Outcome::Usage(format!("{error}")),
        ErrorKind::Cancelled { cause } => Outcome::Cancelled(match cause {
            asc_core::error::CancelCause::User => "cancelled by user",
            asc_core::error::CancelCause::Deadline => "deadline exceeded",
        }),
        _ => Outcome::Analysis(format!("{error}")),
    }
}

fn validate_common(common: &cli::CommonArgs) -> Result<(), Outcome> {
    if let Some(threads) = common.threads {
        cli::validate_threads(threads).map_err(Outcome::Usage)?;
    }
    if let Some(timeout_ms) = common.timeout_ms {
        cli::validate_timeout_ms(timeout_ms).map_err(Outcome::Usage)?;
    }
    let parsed = cli::parse_limits(&common.limits).map_err(Outcome::Usage)?;
    for limit in &parsed {
        if !limit.key.enforced() {
            eprintln!(
                "[debug] limit {}={} is accepted but not enforced in this build",
                limit.key.as_key(),
                limit.value
            );
        }
    }
    Ok(())
}

fn make_context(
    common: &cli::CommonArgs,
    limits: &cli::EffectiveLimits,
) -> Result<(Engine, OperationControl), Outcome> {
    let control = match common.timeout_ms {
        Some(timeout_ms) => OperationControl::new()
            .with_deadline(Instant::now() + Duration::from_millis(timeout_ms)),
        None => OperationControl::new(),
    };
    let core_limits = Limits {
        max_input_bytes: limits.max_input_bytes,
        max_engine_owned_bytes: limits.max_engine_owned_bytes,
        max_entry_bytes: limits.max_entry_bytes,
        max_total_decoded_bytes: limits.max_total_decoded_bytes,
        max_archive_entries: limits.max_archive_entries,
        manifest: asc_core::manifest::XmlDecodeLimits {
            max_depth: limits.max_xml_depth,
            max_nodes: limits.max_xml_nodes,
            max_attributes: limits.max_xml_attributes,
            max_string_units: limits.max_string_units,
        },
        scan: dex::ScanLimits {
            max_result_items: limits.max_result_items,
            max_reference_locations: limits.max_reference_locations,
            max_string_units: limits.max_string_units,
            max_table_items: limits.max_table_items,
            max_result_bytes: limits.max_result_bytes,
        },
    };
    let engine = Engine::new(EngineOptions { limits: core_limits, threads: common.threads })
        .map_err(core_outcome)?;
    Ok((engine, control))
}

fn effective_limits(common: &cli::CommonArgs) -> Result<cli::EffectiveLimits, Outcome> {
    Ok(cli::EffectiveLimits::new(&cli::parse_limits(&common.limits).map_err(Outcome::Usage)?))
}

fn open_engine_and_control(
    common: &cli::CommonArgs,
) -> Result<(Engine, OperationControl, cli::EffectiveLimits), Outcome> {
    let limits = effective_limits(common)?;
    let (engine, control) = make_context(common, &limits)?;
    Ok((engine, control, limits))
}

fn member_spec<'a>(
    name: Option<&'a str>,
    args: &'a cli::MemberArgs,
    mode: query::MatchMode,
) -> Result<query::MemberSpec<'a>, Outcome> {
    if args.fuzzy_class && args.class_name.is_none() {
        return Err(Outcome::Usage("--fuzzy-class requires --class".to_owned()));
    }
    let class = match args.class_name.as_deref() {
        Some(text) if args.fuzzy_class => Some(query::ClassSpec::Fuzzy(text)),
        Some(text) => Some(query::ClassSpec::Exact(text)),
        None => None,
    };
    Ok(query::MemberSpec { name, mode, class })
}

#[allow(clippy::too_many_arguments)]
fn render_and_commit(
    common: &cli::CommonArgs,
    operation: &'static str,
    artifact_id: &asc_core::model::ArtifactId,
    diagnostics: &[asc_core::model::Diagnostic],
    data: &CommandData<'_>,
    output: Option<&std::path::Path>,
    input: &std::path::Path,
    control: &OperationControl,
) -> Result<(), Outcome> {
    let format = common.format.unwrap_or(Format::Text);
    let payload = match format {
        Format::Text => render::text(data, common_budget(common), control).map_err(core_outcome)?,
        Format::Json => {
            render::json(operation, artifact_id, diagnostics, data, common_budget(common), control)
                .map_err(core_outcome)?
        }
    };
    match output::commit(&payload, output, input) {
        Ok(output::WriteOutcome::Committed) => Ok(()),
        Ok(output::WriteOutcome::BrokenPipe) => Ok(()),
        Err(output_error) => Err(Outcome::Output(format!("{output_error}"))),
    }
}

fn common_budget(common: &cli::CommonArgs) -> usize {
    let Ok(parsed) = cli::parse_limits(&common.limits) else {
        return cli::EffectiveLimits::new(&[]).max_result_bytes;
    };
    cli::EffectiveLimits::new(&parsed).max_result_bytes
}

fn note_diagnostics(diagnostics: &[asc_core::model::Diagnostic]) {
    for diagnostic in diagnostics {
        eprintln!("[{}] {}", diagnostic.severity().as_str(), diagnostic.message());
    }
}

fn run_findrefs(args: &cli::FindRefsArgs) -> Result<(), Outcome> {
    let common = cli::CommonArgs::merge(&args.common, args.kind_common());
    validate_common(&common)?;
    let mode = if args.kind.regex_mode() {
        query::MatchMode::Regex
    } else {
        query::MatchMode::Literal
    };
    // The resolved `--limit pattern-bytes/regex-bytes/regex-steps` values
    // ride into the query construction; parsing happens before the input is
    // opened, so a bad limit or a bad query still exits 2 with no I/O.
    let limits = effective_limits(&common)?;
    let pattern_limits = limits.pattern;
    let reference_query = match &args.kind {
        cli::FindKind::String(q) => query::string_query(&q.value, mode, &pattern_limits),
        cli::FindKind::Type(q) => query::type_query(&q.value, mode, &pattern_limits),
        cli::FindKind::Method(q) => {
            let spec = member_spec(q.name.as_deref(), q, mode)?;
            query::member_query(false, spec, &pattern_limits)
        }
        cli::FindKind::Field(q) => {
            let spec = member_spec(q.name.as_deref(), q, mode)?;
            query::member_query(true, spec, &pattern_limits)
        }
    }
    .map_err(core_outcome)?;
    let (engine, control, _limits) = open_engine_and_control(&common)?;
    let artifact = engine
        .open_path(&args.apk_path, InputKind::Apk, &control)
        .map_err(core_outcome)?;
    let report = engine
        .references(&artifact, &reference_query, &control)
        .map_err(core_outcome)?;
    note_diagnostics(report.diagnostics());
    if common.debug {
        eprintln!("[DEBUG] result_items={}", report.stats().result_items);
    }
    render_and_commit(
        &common,
        "findrefs",
        &artifact.id(),
        report.diagnostics(),
        &CommandData::Findrefs(report.value()),
        common.output.as_deref(),
        &args.apk_path,
        &control,
    )
}

fn run_classes(args: &cli::ClassesArgs) -> Result<(), Outcome> {
    validate_common(&args.common)?;
    let filter = ClassFilter::new(args.filter.as_deref().unwrap_or(""));
    let (engine, control, _limits) = open_engine_and_control(&args.common)?;
    let artifact = engine
        .open_path(&args.apk_path, InputKind::Apk, &control)
        .map_err(core_outcome)?;
    let report = engine.classes(&artifact, &filter, &control).map_err(core_outcome)?;
    note_diagnostics(report.diagnostics());
    if args.common.debug {
        eprintln!("[DEBUG] result_items={}", report.stats().result_items);
    }
    render_and_commit(
        &args.common,
        "classes",
        &artifact.id(),
        report.diagnostics(),
        &CommandData::Classes(report.value()),
        args.common.output.as_deref(),
        &args.apk_path,
        &control,
    )
}

fn run_manifest(args: &cli::ManifestArgs) -> Result<(), Outcome> {
    validate_common(&args.common)?;
    let (engine, control, _limits) = open_engine_and_control(&args.common)?;
    let artifact = engine
        .open_path(&args.apk_path, InputKind::Apk, &control)
        .map_err(core_outcome)?;
    let report = engine.manifest(&artifact, &control).map_err(core_outcome)?;
    note_diagnostics(report.diagnostics());
    render_and_commit(
        &args.common,
        "manifest",
        &artifact.id(),
        report.diagnostics(),
        &CommandData::Manifest(report.value()),
        args.common.output.as_deref(),
        &args.apk_path,
        &control,
    )
}

fn run_getclass(args: &cli::GetClassArgs) -> Result<(), Outcome> {
    validate_common(&args.common)?;
    let descriptor = query::exact_descriptor(&args.dalvik_class).map_err(core_outcome)?;
    let (engine, control, _limits) = open_engine_and_control(&args.common)?;
    let artifact = engine
        .open_path(&args.apk_path, InputKind::Apk, &control)
        .map_err(core_outcome)?;
    // `--dex` resolves through the artifact's catalog: the ordinals must name
    // a DEX the catalog actually selected, or the query is invalid.
    let selector = match &args.dex {
        Some(text) => {
            let (entry_ordinal, logical_ordinal) =
                query::parse_dex_selector(text).map_err(core_outcome)?;
            let pinned = engine
                .dexes(&artifact, &control)
                .map_err(core_outcome)?
                .value()
                .iter()
                .map(|entry| entry.id())
                .find(|id| {
                    id.entry_ordinal() == entry_ordinal && id.logical_ordinal() == logical_ordinal
                })
                .ok_or_else(|| {
                    Outcome::Usage(format!(
                        "--dex {entry_ordinal}:{logical_ordinal} does not name a selected DEX \
                         in this archive"
                    ))
                })?;
            ClassSelector::Descriptor(descriptor, Some(pinned))
        }
        None => ClassSelector::Descriptor(descriptor, None),
    };
    let report = engine.decompile(&artifact, &selector, &control).map_err(core_outcome)?;
    note_diagnostics(report.diagnostics());
    if args.common.debug {
        eprintln!("[DEBUG] completeness=complete");
    }
    render_and_commit(
        &args.common,
        "getclass",
        &artifact.id(),
        report.diagnostics(),
        &CommandData::Getclass(report.value()),
        args.common.output.as_deref(),
        &args.apk_path,
        &control,
    )
}
