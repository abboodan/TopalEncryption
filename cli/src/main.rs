use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use topal_core::batch::{self, Mode, Options, Progress};
use topal_core::KdfParams;
use zeroize::Zeroizing;

const PASSWORD_ENV: &str = "TOPAL_PASSWORD";
const MAX_FAILURES_SHOWN: usize = 20;

/// Encrypt files and whole folders with a password.
#[derive(Parser)]
#[command(name = "topal-cli", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt files, or every file inside folders, into `<name>.topal`
    Encrypt(Job),
    /// Decrypt `.topal` files, or every `.topal` file inside folders
    Decrypt(Job),
}

#[derive(Args)]
struct Job {
    /// Files and folders to process; folders are walked recursively
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Delete each source file once its output is safely written (and, when
    /// encrypting, verified by decrypting it back). This is an ordinary delete,
    /// not a secure wipe: deleted data may remain recoverable from the disk.
    #[arg(long)]
    delete_source: bool,

    /// Overwrite outputs that already exist instead of skipping them
    #[arg(long)]
    force: bool,

    /// Files processed in parallel (default: number of CPU cores)
    #[arg(short, long)]
    jobs: Option<usize>,
}

/// Takes the password from `TOPAL_PASSWORD` (for scripts) or prompts for it without echo.
fn read_password(mode: Mode) -> Result<Zeroizing<String>> {
    if let Ok(password) = std::env::var(PASSWORD_ENV) {
        if password.is_empty() {
            bail!("{PASSWORD_ENV} is set but empty");
        }
        return Ok(Zeroizing::new(password));
    }
    let password = Zeroizing::new(rpassword::prompt_password("Password: ")?);
    if password.is_empty() {
        bail!("the password cannot be empty");
    }
    if mode == Mode::Encrypt {
        let again = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
        if *password != *again {
            bail!("the passwords do not match");
        }
    }
    Ok(password)
}

fn run(mode: Mode, job: Job) -> Result<bool> {
    let scan = batch::scan(mode, &job.paths);
    for warning in &scan.warnings {
        eprintln!("warning: cannot read {warning}");
    }
    if scan.files.is_empty() {
        println!("Nothing to do: no matching files.");
        return Ok(scan.warnings.is_empty());
    }

    let password = read_password(mode)?;
    let options = Options { delete_source: job.delete_source, force: job.force, jobs: job.jobs };

    let bar = ProgressBar::new(scan.total_bytes());
    bar.set_style(
        ProgressStyle::with_template("{bar:40} {bytes}/{total_bytes}  {bytes_per_sec}  eta {eta}")
            .expect("valid template"),
    );
    let progress = Progress::default();
    let finished = AtomicBool::new(false);
    let summary = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !finished.load(Ordering::Relaxed) {
                bar.set_position(progress.bytes.load(Ordering::Relaxed));
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let summary =
            batch::run(mode, &scan.files, &password, KdfParams::default(), options, &progress);
        finished.store(true, Ordering::Relaxed);
        summary
    })?;
    bar.finish_and_clear();

    let verb = if mode == Mode::Encrypt { "encrypted" } else { "decrypted" };
    println!(
        "{} {verb}, {} skipped (output already exists), {} failed",
        summary.done,
        summary.skipped,
        summary.failures.len()
    );
    for (path, reason) in summary.failures.iter().take(MAX_FAILURES_SHOWN) {
        eprintln!("  FAILED {}: {reason}", path.display());
    }
    if summary.failures.len() > MAX_FAILURES_SHOWN {
        eprintln!("  ... and {} more", summary.failures.len() - MAX_FAILURES_SHOWN);
    }
    Ok(summary.failures.is_empty() && scan.warnings.is_empty())
}

fn main() -> ExitCode {
    let outcome = match Cli::parse().command {
        Command::Encrypt(job) => run(Mode::Encrypt, job),
        Command::Decrypt(job) => run(Mode::Decrypt, job),
    };
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
