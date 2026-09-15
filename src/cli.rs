//! Argument parsing: clap definitions plus the query-construction calls.
//!
//! The structured rendering, exit-code mapping and output protocol are
//! A08's; this module only turns arguments into typed operations.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "rasc", version, about = "Native Rust APK and DEX analysis CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
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
    #[arg(long, alias = "thread", default_value_t = 8)]
    pub threads: usize,
    /// Case-insensitive substring filter over Java-style class names.
    #[arg(short, long)]
    pub filter: Option<String>,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Print phase timings on stderr.
    #[arg(long)]
    pub debug: bool,
    pub apk_path: PathBuf,
}

#[derive(Debug, Args)]
pub struct ManifestArgs {
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    pub apk_path: PathBuf,
}

#[derive(Debug, Args)]
pub struct GetClassArgs {
    #[arg(long)]
    pub debug: bool,
    #[arg(long, alias = "thread", default_value_t = 8)]
    pub threads: usize,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Pin the class to one logical DEX: `<entry_ordinal>:<logical_ordinal>`
    /// (both zero-based, as shown by `classes` / `--format json`).
    #[arg(long)]
    pub dex: Option<String>,
    pub apk_path: PathBuf,
    pub dalvik_class: String,
}

#[derive(Debug, Args)]
pub struct FindRefsArgs {
    #[arg(long)]
    pub debug: bool,
    #[arg(long, alias = "thread", default_value_t = 8)]
    pub threads: usize,
    pub apk_path: PathBuf,
    #[command(subcommand)]
    pub kind: FindKind,
}

impl FindRefsArgs {
    pub fn output_path(&self) -> Option<&PathBuf> {
        match &self.kind {
            FindKind::String(q) | FindKind::Type(q) => q.output.as_ref(),
            FindKind::Method(q) | FindKind::Field(q) => q.output.as_ref(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum FindKind {
    String(ValueQuery),
    Type(ValueQuery),
    Method(MemberArgs),
    Field(MemberArgs),
}

#[derive(Debug, Args)]
pub struct ValueQuery {
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    pub value: String,
}

#[derive(Debug, Args)]
pub struct MemberArgs {
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    pub name: Option<String>,
    #[arg(long = "class")]
    pub class_name: Option<String>,
    #[arg(long)]
    pub fuzzy_class: bool,
}

/// The worker count must be positive; zero is a syntax-level rejection that
/// fires before any input is opened.
pub fn validate_threads(threads: usize) -> Result<(), String> {
    if threads == 0 {
        return Err("worker count must be greater than zero".to_owned());
    }
    Ok(())
}
