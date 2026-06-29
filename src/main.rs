//! `checkmd5`: verify the integrity of files listed in `md5sum`-style lists.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use checkmd5::{Checker, Config};

/// Tool for checking the integrity of multiple files as one unit.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Continue checking even if errors occur.
    #[arg(long)]
    force: bool,

    /// Show verbose output.
    #[arg(long)]
    verbose: bool,

    /// Machine-readable output format.
    #[arg(long)]
    machine: bool,

    /// Log output to file.
    #[arg(long, value_name = "file")]
    log: Option<PathBuf>,

    /// Number of files to hash in parallel (0 = auto).
    #[arg(long, value_name = "count", default_value_t = 1)]
    jobs: usize,

    /// MD5 checksum files to verify.
    #[arg(value_name = "file", required = true)]
    files: Vec<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let config = Config {
        force: cli.force,
        verbose: cli.verbose,
        machine: cli.machine,
        jobs: cli.jobs,
        log_file: cli.log,
    };

    let mut checker = match Checker::new(config) {
        Ok(checker) => checker,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return ExitCode::from(checkmd5::ExitCode::System.code() as u8);
        }
    };

    ExitCode::from(checker.run(&cli.files).code() as u8)
}
