//! CLI entry point: argument parsing, dispatch, rendering, output commitment.
//!
//! stdout carries a command's payload and nothing else: every diagnostic,
//! warning and `--debug` line goes to stderr, so `--debug` can never change
//! the payload bytes. One serialization of the result is committed first to
//! the `-o` file (atomic replacement) and then to stdout.
//!
//! Exit codes (interfaces.md §6): 0 complete success (including empty
//! results), 2 argument/query construction errors, 1 input/analysis/output
//! errors and incomplete decompilations, 130 cancellation (user flag or
//! deadline). Error lines on stderr carry the stable code first:
//! `Error: <code>: <context chain>`.

mod apk;
mod bytes;
mod cli;
mod dex;
mod error;
mod manifest;
mod model;
mod output;
mod query;
mod render;
mod zip;

use clap::Parser;
use cli::{Cli, Command, CommonArgs, Format};
use error::{Error, ErrorKind};
use model::OperationStats;
use std::time::{Duration, Instant};

fn main() {
    restore_default_sigpipe();
    std::process::exit(run());
}

/// Restore the default `SIGPIPE` disposition so that piping into `head`,
/// `grep`, or a closed consumer terminates quietly, the way standard Unix
/// filters do.
///
/// Rust ignores `SIGPIPE` at startup, which turns an early-closed pipe into a
/// `BrokenPipe` write error and then a panic; with `panic = "abort"` that
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

/// A command failure with its exit code.
enum Failure {
    /// Analysis/query errors with their stable kind strings.
    Analysis(Error),
    /// Output commitment errors (exit 1).
    Output(output::OutputError),
}

impl Failure {
    fn exit_code(&self) -> i32 {
        match self {
            Failure::Analysis(error) => match error.kind() {
                ErrorKind::InvalidQuery => 2,
                ErrorKind::Cancelled { .. } => 130,
                _ => 1,
            },
            Failure::Output(_) => 1,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Analysis(error) => write!(f, "{error}"),
            Failure::Output(error) => write!(f, "{error}"),
        }
    }
}

fn usage_error(message: impl Into<String>) -> Failure {
    Failure::Analysis(Error::invalid_query(message))
}

fn run() -> i32 {
    // No arguments at all: help goes to stderr and the exit code is 2.
    // (`--help`/`--version` print to stdout and exit 0 via clap below.)
    if std::env::args_os().count() <= 1 {
        use clap::CommandFactory;
        let _ = Cli::command().write_help(&mut std::io::stderr());
        return 2;
    }
    let args = Cli::parse();
    match dispatch(args.command) {
        Ok(()) => 0,
        Err(failure) => {
            eprintln!("Error: {failure}");
            failure.exit_code()
        }
    }
}

fn dispatch(command: Command) -> Result<(), Failure> {
    match command {
        Command::Findrefs(args) => findrefs(args),
        Command::Classes(args) => classes(args),
        Command::Manifest(args) => manifest(args),
        Command::Getclass(args) => getclass(args),
    }
}

/// Everything the handlers resolved once, before any input is read.
struct Run {
    debug: bool,
    output: Option<std::path::PathBuf>,
    format: Format,
    control: manifest::OperationControl,
    limits: cli::EffectiveLimits,
    started: Instant,
}

fn prepare(common: &CommonArgs) -> Result<Run, Failure> {
    let threads = common.threads.unwrap_or(8);
    cli::validate_threads(threads).map_err(usage_error)?;
    if let Some(timeout_ms) = common.timeout_ms {
        cli::validate_timeout_ms(timeout_ms).map_err(usage_error)?;
    }
    let parsed_limits = cli::parse_limits(&common.limits).map_err(usage_error)?;
    for limit in &parsed_limits {
        if !limit.key.enforced() {
            eprintln!(
                "[debug] --limit {} is accepted but not enforced by this build; the internal \
                 default stays in effect",
                limit.key.as_key()
            );
        }
    }
    let limits = cli::EffectiveLimits::new(&parsed_limits);
    let control = match common.timeout_ms {
        Some(timeout_ms) => {
            let deadline = Instant::now() + Duration::from_millis(timeout_ms);
            manifest::OperationControl::new().with_deadline(deadline)
        }
        None => manifest::OperationControl::new(),
    };
    Ok(Run {
        debug: common.debug,
        output: common.output.clone(),
        format: common.format.unwrap_or(Format::Text),
        control,
        limits,
        started: Instant::now(),
    })
}

/// Prints the report's warnings on stderr (success warnings are visible both
/// in the JSON diagnostics and here), commits the payload and reports debug
/// stats.
fn finish(
    run: &Run,
    operation: &str,
    input: &std::path::Path,
    artifact: &apk::Artifact,
    diagnostics: &[model::Diagnostic],
    stats: OperationStats,
    data: render::CommandData<'_>,
) -> Result<(), Failure> {
    for diagnostic in diagnostics {
        eprintln!("[{}] {}", diagnostic.severity().as_str(), diagnostic.message());
    }
    let payload = match run.format {
        Format::Text => {
            render::text(&data, run.limits.max_result_bytes, &run.control)
        }
        Format::Json => render::json(
            operation,
            &artifact.id(),
            diagnostics,
            &data,
            run.limits.max_result_bytes,
            &run.control,
        ),
    }
    .map_err(Failure::Analysis)?;
    match output::commit(&payload, run.output.as_deref(), input).map_err(Failure::Output)? {
        output::WriteOutcome::Committed => {}
        // A closed stdout consumer is a quiet success; on Unix the default
        // SIGPIPE disposition usually terminates us before this.
        output::WriteOutcome::BrokenPipe => return Ok(()),
    }
    if run.debug {
        eprintln!(
            "[DEBUG] stats: selected_dexes={} scanned_methods={} matched_targets={} \
             result_items={}",
            stats.selected_dexes, stats.scanned_methods, stats.matched_targets, stats.result_items
        );
        eprintln!(
            "[DEBUG] Total Execution Time: {:.2} us",
            run.started.elapsed().as_secs_f64() * 1_000_000.0
        );
    }
    Ok(())
}

fn findrefs(args: cli::FindRefsArgs) -> Result<(), Failure> {
    let common = CommonArgs::merge(&args.common, args.kind_common());
    let run = prepare(&common)?;
    let mode = match (&args.kind, common_has_regex(&args.kind)) {
        (_, true) => query::MatchMode::Regex,
        (_, false) => query::MatchMode::Literal,
    };
    let pattern_limits = run.limits.pattern;
    // `--fuzzy-class` without `--class` has nothing to fuzz: reject it here
    // instead of letting the query silently drop the flag (interfaces.md §6).
    if let cli::FindKind::Method(member) | cli::FindKind::Field(member) = &args.kind
        && member.fuzzy_class
        && member.class_name.is_none()
    {
        return Err(usage_error("--fuzzy-class requires --class"));
    }
    let reference_query = match &args.kind {
        cli::FindKind::String(query) => {
            query::string_query(&query.value, mode, &pattern_limits)
        }
        cli::FindKind::Type(query) => query::type_query(&query.value, mode, &pattern_limits),
        cli::FindKind::Method(member) => {
            query::member_query(false, member_spec(member, mode), &pattern_limits)
        }
        cli::FindKind::Field(member) => {
            query::member_query(true, member_spec(member, mode), &pattern_limits)
        }
    }
    .map_err(Failure::Analysis)?;
    let artifact =
        apk::open_path(&args.apk_path, &apk_limits(&run), &run.control).map_err(Failure::Analysis)?;
    let report = apk::references(&artifact, &reference_query, &run.control)
        .map_err(Failure::Analysis)?;
    let stats = report.stats();
    let diagnostics = report.diagnostics().to_vec();
    let data = render::CommandData::Findrefs(report.value());
    finish(&run, "findrefs", &args.apk_path, &artifact, &diagnostics, stats, data)
}

fn common_has_regex(kind: &cli::FindKind) -> bool {
    match kind {
        cli::FindKind::String(query) | cli::FindKind::Type(query) => query.regex,
        cli::FindKind::Method(member) | cli::FindKind::Field(member) => member.regex,
    }
}

fn member_spec<'a>(q: &'a cli::MemberArgs, mode: query::MatchMode) -> query::MemberSpec<'a> {
    let class = match q.class_name.as_deref() {
        Some(text) if q.fuzzy_class => Some(query::ClassSpec::Fuzzy(text)),
        Some(text) => Some(query::ClassSpec::Exact(text)),
        None => None,
    };
    query::MemberSpec { name: q.name.as_deref(), mode, class }
}

fn classes(args: cli::ClassesArgs) -> Result<(), Failure> {
    let run = prepare(&args.common)?;
    let filter = model::ClassFilter::new(args.filter.as_deref().unwrap_or(""));
    let artifact =
        apk::open_path(&args.apk_path, &apk_limits(&run), &run.control).map_err(Failure::Analysis)?;
    let report = apk::classes(&artifact, &filter, &run.control).map_err(Failure::Analysis)?;
    let stats = report.stats();
    let diagnostics = report.diagnostics().to_vec();
    let data = render::CommandData::Classes(report.value());
    finish(&run, "classes", &args.apk_path, &artifact, &diagnostics, stats, data)
}

fn manifest(args: cli::ManifestArgs) -> Result<(), Failure> {
    let run = prepare(&args.common)?;
    let artifact =
        apk::open_path(&args.apk_path, &apk_limits(&run), &run.control).map_err(Failure::Analysis)?;
    let report = apk::manifest(&artifact, &run.control).map_err(Failure::Analysis)?;
    let stats = report.stats();
    let diagnostics = report.diagnostics().to_vec();
    let data = render::CommandData::Manifest(report.value());
    finish(&run, "manifest", &args.apk_path, &artifact, &diagnostics, stats, data)
}

fn getclass(args: cli::GetClassArgs) -> Result<(), Failure> {
    let run = prepare(&args.common)?;
    // Query construction happens before the input is read; a syntax error in
    // `--dex` or the class name exits 2 without opening the file.
    let descriptor = query::exact_descriptor(&args.dalvik_class).map_err(Failure::Analysis)?;
    let pinned_dex = match &args.dex {
        Some(text) => Some(query::parse_dex_selector(text).map_err(Failure::Analysis)?),
        None => None,
    };
    let artifact =
        apk::open_path(&args.apk_path, &apk_limits(&run), &run.control).map_err(Failure::Analysis)?;
    // `--dex` resolves through the artifact's catalog: the ordinals must name
    // a DEX the catalog actually selected, or the query is invalid
    // (interfaces.md §1).
    let selector = match pinned_dex {
        Some((entry_ordinal, logical_ordinal)) => {
            let pinned = apk::dexes(&artifact, &run.control)
                .map_err(Failure::Analysis)?
                .value()
                .iter()
                .map(|entry| entry.id())
                .find(|id| {
                    id.entry_ordinal() == entry_ordinal && id.logical_ordinal() == logical_ordinal
                })
                .ok_or_else(|| {
                    usage_error(format!(
                        "--dex {entry_ordinal}:{logical_ordinal} does not name a selected DEX \
                         in this archive"
                    ))
                })?;
            model::ClassSelector::Descriptor(descriptor, Some(pinned))
        }
        None => model::ClassSelector::Descriptor(descriptor, None),
    };
    let report = apk::decompile(&artifact, &selector, &run.control).map_err(Failure::Analysis)?;
    let stats = report.stats();
    let diagnostics = report.diagnostics().to_vec();
    let data = render::CommandData::Getclass(report.value());
    finish(&run, "getclass", &args.apk_path, &artifact, &diagnostics, stats, data)
}

/// The apk-layer projection of the resolved limits.
fn apk_limits(run: &Run) -> apk::Limits {
    apk::Limits {
        max_input_bytes: run.limits.max_input_bytes,
        max_entry_bytes: run.limits.max_entry_bytes,
        max_total_decoded_bytes: run.limits.max_total_decoded_bytes,
        scan: crate::dex::ScanLimits {
            max_result_items: run.limits.max_result_items,
            max_reference_locations: run.limits.max_reference_locations,
            max_string_units: run.limits.max_string_units,
            max_table_items: run.limits.max_table_items,
            max_result_bytes: run.limits.max_result_bytes,
        },
    }
}
