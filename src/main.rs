mod core;
mod gui;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ASC")]
#[command(about = "R8 Compiler Optimization as a DeCompiler Primitive (Rust Edition)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Locate the target class in APK, extract one DEX in memory, then decompile
    Getclass {
        #[arg(long)]
        debug: bool,
        #[arg(long, default_value_t = 8)]
        threads: usize,
        #[arg(short, long)]
        output: Option<String>,
        apk_path: PathBuf,
        dalvik_class: String,
    },
    /// Find code references for string/type/method/field across all DEX entries in APK
    Findrefs {
        apk_path: PathBuf,
    },
    /// Launch GUI
    Gui {
        apk_path: PathBuf,
    },
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Getclass { debug, threads, output, apk_path, dalvik_class } => {
            println!("Getclass {} from {:?}", dalvik_class, apk_path);
            if let Ok(handler) = crate::core::apk_handler::ApkHandler::new(&apk_path) {
                if let Ok(entries) = handler.get_dex_entries() {
                    println!("Found {} DEX entries", entries.len());
                }
            }
        },
        Commands::Findrefs { apk_path } => {
            println!("Findrefs in {:?}", apk_path);
        },
        Commands::Gui { apk_path } => {
            if let Err(e) = gui::launch_gui(apk_path) {
                eprintln!("GUI Error: {}", e);
            }
        }
    }
}
