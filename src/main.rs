//! CLI entry point: argument parsing, dispatch, output.
//!
//! stdout carries a command's payload and nothing else: every diagnostic,
//! including `--debug` timing, goes to stderr, so redirecting a result can
//! never capture debug lines. An `-o` file receives exactly the bytes
//! stdout received.
//!
//! The rendering here is the A07 integration's minimal projection of the
//! structured reports; the frozen text/JSON output protocol with bounded
//! writers and atomic file replacement is A08's.

mod apk;
mod bytes;
mod cli;
mod dex;
mod error;
mod manifest;
mod model;
mod query;
mod zip;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command};
use query::{ClassSpec, MatchMode, MemberSpec};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

fn main() {
    restore_default_sigpipe();
    if let Err(error) = run() {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
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

/// Writes a command's payload to stdout and, when `output` is set, to that
/// file as well.
fn emit(payload: &str, output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        fs::write(path, payload).with_context(|| format!("write {}", path.display()))?;
    }
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    stdout.write_all(payload.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

/// This is the only place the CLI reports timing, so `--debug` reads the same
/// for every subcommand.
fn debug_timing(started: Instant) {
    eprintln!(
        "[DEBUG] Total Execution Time: {:.2} us",
        started.elapsed().as_secs_f64() * 1_000_000.0
    );
}

fn run() -> Result<()> {
    let started = Instant::now();
    let args = Cli::parse();
    let control = manifest::OperationControl::new();
    match &args.command {
        Command::Findrefs(args) => {
            cli::validate_threads(args.threads).map_err(|message| anyhow::anyhow!(message))?;
            let limits = model::PatternLimits::default();
            let reference_query = match &args.kind {
                cli::FindKind::String(q) => {
                    query::string_query(&q.value, MatchMode::Literal, &limits)?
                }
                cli::FindKind::Type(q) => {
                    query::type_query(&q.value, MatchMode::Literal, &limits)?
                }
                cli::FindKind::Method(q) => {
                    query::member_query(false, member_spec(q, MatchMode::Literal), &limits)?
                }
                cli::FindKind::Field(q) => {
                    query::member_query(true, member_spec(q, MatchMode::Literal), &limits)?
                }
            };
            let artifact = apk::open_path(&args.apk_path, &control)?;
            let report = apk::references(&artifact, &reference_query, &control)?;
            print_diagnostics(report.diagnostics());
            let mut payload = String::new();
            for reference in report.value() {
                payload.push_str(&render_reference(reference));
            }
            emit(&payload, args.output_path().map(|path| path.as_path()))?;
            if args.debug {
                debug_timing(started);
            }
        }
        Command::Classes(args) => {
            cli::validate_threads(args.threads).map_err(|message| anyhow::anyhow!(message))?;
            let filter = model::ClassFilter::new(args.filter.as_deref().unwrap_or(""));
            let artifact = apk::open_path(&args.apk_path, &control)?;
            let report = apk::classes(&artifact, &filter, &control)?;
            print_diagnostics(report.diagnostics());
            let mut payload = String::new();
            for class in report.value() {
                let id = class.id();
                payload.push_str(&format!(
                    "{}:{} | {} | {} | {}\n",
                    id.dex().entry_ordinal(),
                    id.dex().logical_ordinal(),
                    class.descriptor().as_str(),
                    class.java_name().as_str().unwrap_or_default(),
                    class.package().as_str().unwrap_or_default(),
                ));
            }
            emit(&payload, args.output.as_deref())?;
            if args.debug {
                debug_timing(started);
            }
        }
        Command::Manifest(args) => {
            let artifact = apk::open_path(&args.apk_path, &control)?;
            let report = apk::manifest(&artifact, &control)?;
            let options = manifest::XmlRenderOptions::default();
            let xml = report.value().to_xml(&options, &control)?;
            emit(&xml, args.output.as_deref())?;
        }
        Command::Getclass(args) => {
            cli::validate_threads(args.threads).map_err(|message| anyhow::anyhow!(message))?;
            let descriptor = query::exact_descriptor(&args.dalvik_class)?;
            let artifact = apk::open_path(&args.apk_path, &control)?;
            // `--dex` resolves through the artifact's catalog: the ordinals
            // must name a DEX the catalog actually selected, or the query is
            // invalid (interfaces.md §1).
            let selector = match &args.dex {
                Some(text) => {
                    let (entry_ordinal, logical_ordinal) = query::parse_dex_selector(text)?;
                    let pinned = apk::dexes(&artifact, &control)?
                        .value()
                        .iter()
                        .map(|entry| entry.id())
                        .find(|id| {
                            id.entry_ordinal() == entry_ordinal
                                && id.logical_ordinal() == logical_ordinal
                        })
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "InvalidQuery: --dex {entry_ordinal}:{logical_ordinal} does not \
                                 name a selected DEX in this archive"
                            )
                        })?;
                    model::ClassSelector::Descriptor(descriptor, Some(pinned))
                }
                None => model::ClassSelector::Descriptor(descriptor, None),
            };
            let report = apk::decompile(&artifact, &selector, &control)?;
            print_diagnostics(report.diagnostics());
            emit(report.value().text(), args.output.as_deref())?;
            if args.debug {
                debug_timing(started);
            }
        }
    }
    Ok(())
}

fn member_spec<'a>(q: &'a cli::MemberArgs, mode: MatchMode) -> MemberSpec<'a> {
    let class = match q.class_name.as_deref() {
        Some(text) if q.fuzzy_class => Some(ClassSpec::Fuzzy(text)),
        Some(text) => Some(ClassSpec::Exact(text)),
        None => None,
    };
    MemberSpec { name: q.name.as_deref(), mode, class }
}

/// Interim A07 projection of a structured reference: dex key, display name,
/// method index, full caller identity and per-target offsets. The frozen
/// escaping/ordering protocol is A08's.
fn render_reference(reference: &model::Reference) -> String {
    let caller = reference.caller();
    let dex = caller.id().dex();
    let mut line = format!(
        "{}:{} | {} | {} | ",
        dex.entry_ordinal(),
        dex.logical_ordinal(),
        caller.dex().display_name().as_str().unwrap_or_default(),
        caller.id().method_idx(),
    );
    line.push_str(&render_text(caller.owner()));
    line.push_str("->");
    line.push_str(&render_text(caller.name()));
    line.push_str(&render_prototype(caller.prototype()));
    for target in reference.targets() {
        line.push_str(" | ");
        line.push_str(target.id().kind().as_str());
        line.push(':');
        match target.value() {
            model::TargetValue::String(text) | model::TargetValue::Type(text) => {
                line.push_str(&render_text(text));
            }
            model::TargetValue::Field { owner, name, .. }
            | model::TargetValue::Method { owner, name, .. } => {
                line.push_str(&render_text(owner));
                line.push_str("->");
                line.push_str(&render_text(name));
            }
        }
        let offsets: Vec<String> =
            target.code_unit_offsets().iter().map(|offset| offset.to_string()).collect();
        line.push_str(&format!(" @{}", offsets.join(",")));
    }
    line.push('\n');
    line
}

fn render_text(text: &model::DexText) -> String {
    text.as_str().unwrap_or_else(|| {
        // Unpaired surrogates escape as \uXXXX in display order.
        text.utf16_units()
            .iter()
            .map(|unit| {
                if (0xD800..=0xDFFF).contains(unit) {
                    format!("\\u{unit:04x}")
                } else {
                    char::from_u32(*unit as u32).map(String::from).unwrap_or_default()
                }
            })
            .collect()
    })
}

fn render_prototype(prototype: &model::Prototype) -> String {
    let params: Vec<String> = prototype.parameters().iter().map(render_text).collect();
    format!("({}){}", params.join(""), render_text(prototype.return_type()))
}

fn print_diagnostics(diagnostics: &[model::Diagnostic]) {
    for diagnostic in diagnostics {
        eprintln!("[{}] {}", diagnostic.severity().as_str(), diagnostic.message());
    }
}
