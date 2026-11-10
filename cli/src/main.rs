use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use topal_core::batch::{self, Job, Mode, Options, Progress, Unlock};
use topal_core::recovery::{self, RecoveryKey};
use topal_core::{passphrase, KdfParams};
use zeroize::Zeroizing;

const PASSWORD_ENV: &str = "TOPAL_PASSWORD";
const NEW_PASSWORD_ENV: &str = "TOPAL_NEW_PASSWORD";
const RECOVERY_KEY_ENV: &str = "TOPAL_RECOVERY_KEY";
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
    Encrypt(EncryptArgs),
    /// Decrypt `.topal` files, or every `.topal` file inside folders
    Decrypt(DecryptArgs),
    /// Check that `.topal` files open with the password and are undamaged; writes nothing
    Verify(UnlockArgs),
    /// Change the password of `.topal` files without re-encrypting their content
    ChangePassword(UnlockArgs),
    /// Manage the recovery key, a second way to open files if the password is forgotten
    #[command(subcommand)]
    Recovery(RecoveryCommand),
    /// Print a random passphrase made of common words
    Passphrase {
        /// Number of words; each adds 11 bits
        #[arg(long, default_value_t = passphrase::DEFAULT_WORDS)]
        words: usize,
    },
}

#[derive(Subcommand)]
enum RecoveryCommand {
    /// Create a recovery key, print it once, and use it for files encrypted from now on
    Create,
    /// Show whether a recovery key is in use
    Status,
    /// Stop adding the recovery key to new files (existing files keep it)
    Disable,
}

#[derive(Args)]
struct Common {
    /// Files and folders to process; folders are walked recursively
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Files processed in parallel (default: number of CPU cores)
    #[arg(short, long)]
    jobs: Option<usize>,
}

#[derive(Args)]
struct Output {
    /// Delete each source file once its output is safely written (and, when
    /// encrypting, verified by decrypting it back). This is an ordinary delete,
    /// not a secure wipe: deleted data may remain recoverable from the disk.
    #[arg(long)]
    delete_source: bool,

    /// Overwrite output files that already exist instead of skipping them
    #[arg(long)]
    force: bool,

    /// Write outputs to this folder, keeping the folder structure, instead of
    /// beside each source
    #[arg(short, long, value_name = "DIR")]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct EncryptArgs {
    #[command(flatten)]
    common: Common,
    #[command(flatten)]
    output: Output,

    /// Give every output a random name and pack each folder into a single file, so
    /// that file names, folder structure and file count are hidden
    #[arg(long)]
    hide_names: bool,

    /// Do not add the recovery key to these files, even if one is in use
    #[arg(long)]
    no_recovery: bool,
}

#[derive(Args)]
struct DecryptArgs {
    #[command(flatten)]
    common: Common,
    #[command(flatten)]
    output: Output,
    #[command(flatten)]
    unlock: UnlockWith,
}

#[derive(Args)]
struct UnlockArgs {
    #[command(flatten)]
    common: Common,
    #[command(flatten)]
    unlock: UnlockWith,
}

#[derive(Args)]
struct UnlockWith {
    /// Open the files with the recovery key instead of the password
    #[arg(long)]
    recovery_key: bool,
}

/// Takes a secret from an environment variable (for scripts) or prompts without echo.
fn read_secret(env: &str, prompt: &str, confirm: bool) -> Result<Zeroizing<String>> {
    if let Ok(secret) = std::env::var(env) {
        if secret.is_empty() {
            bail!("{env} is set but empty");
        }
        return Ok(Zeroizing::new(secret));
    }
    let secret = Zeroizing::new(rpassword::prompt_password(format!("{prompt}: "))?);
    if secret.is_empty() {
        bail!("the {} cannot be empty", prompt.to_lowercase());
    }
    if confirm {
        let again = Zeroizing::new(rpassword::prompt_password(format!("Repeat {}: ", prompt.to_lowercase()))?);
        if *secret != *again {
            bail!("the two entries do not match");
        }
    }
    Ok(secret)
}

/// The password or recovery key that opens existing files.
enum Opener {
    Password(Zeroizing<String>),
    Key(RecoveryKey),
}

impl Opener {
    fn read(unlock: &UnlockWith, password_prompt: &str) -> Result<Self> {
        if unlock.recovery_key {
            let text = read_secret(RECOVERY_KEY_ENV, "Recovery key", false)?;
            Ok(Self::Key(RecoveryKey::parse(&text)?))
        } else {
            Ok(Self::Password(read_secret(PASSWORD_ENV, password_prompt, false)?))
        }
    }

    fn unlock(&self) -> Unlock<'_> {
        match self {
            Self::Password(password) => Unlock::Password(password),
            Self::Key(key) => Unlock::RecoveryKey(key),
        }
    }
}

fn options(common: &Common, output: Option<&Output>, hide_names: bool) -> Options {
    Options {
        delete_source: output.is_some_and(|o| o.delete_source),
        force: output.is_some_and(|o| o.force),
        jobs: common.jobs,
        hide_names,
        output_dir: output.and_then(|o| o.output.clone()),
    }
}

/// Scans, asks for the secrets through `job`, runs, and reports. `true` means no problems.
fn run<'a>(
    mode: Mode,
    common: &Common,
    options: &Options,
    secrets: impl FnOnce() -> Result<Box<dyn AsJob + 'a>>,
) -> Result<bool> {
    let scan = batch::scan(mode, &common.paths, options);
    for warning in &scan.warnings {
        eprintln!("warning: cannot read {warning}");
    }
    if scan.items.is_empty() {
        println!("Nothing to do: no matching files.");
        return Ok(scan.warnings.is_empty());
    }
    let secrets = secrets()?;
    let job = secrets.job();

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
        let summary = batch::run(&job, &scan.items, KdfParams::default(), options, &progress);
        finished.store(true, Ordering::Relaxed);
        summary
    })?;
    bar.finish_and_clear();

    let failed = summary.failures.len();
    match mode {
        Mode::Encrypt => println!(
            "{} encrypted, {} skipped (output already exists), {failed} failed",
            summary.done, summary.skipped
        ),
        Mode::Decrypt => println!(
            "{} decrypted, {} skipped (output already exists), {failed} failed",
            summary.done, summary.skipped
        ),
        Mode::Verify => println!("{} intact, {failed} failed", summary.done),
        Mode::ChangePassword => println!("{} changed, {failed} failed", summary.done),
    }
    for (path, reason) in summary.failures.iter().take(MAX_FAILURES_SHOWN) {
        eprintln!("  FAILED {}: {reason}", path.display());
    }
    if failed > MAX_FAILURES_SHOWN {
        eprintln!("  ... and {} more", failed - MAX_FAILURES_SHOWN);
    }
    Ok(failed == 0 && scan.warnings.is_empty())
}

/// Owns the secrets a job borrows.
trait AsJob {
    fn job(&self) -> Job<'_>;
}

struct EncryptSecrets {
    password: Zeroizing<String>,
    recovery: Option<recovery::RecoveryPublic>,
}

impl AsJob for EncryptSecrets {
    fn job(&self) -> Job<'_> {
        Job::Encrypt { password: &self.password, recovery: self.recovery }
    }
}

struct OpenSecrets {
    opener: Opener,
    verify: bool,
}

impl AsJob for OpenSecrets {
    fn job(&self) -> Job<'_> {
        if self.verify {
            Job::Verify(self.opener.unlock())
        } else {
            Job::Decrypt(self.opener.unlock())
        }
    }
}

struct ChangeSecrets {
    opener: Opener,
    new_password: Zeroizing<String>,
}

impl AsJob for ChangeSecrets {
    fn job(&self) -> Job<'_> {
        Job::ChangePassword { unlock: self.opener.unlock(), new_password: &self.new_password }
    }
}

fn encrypt(args: EncryptArgs) -> Result<bool> {
    let options = options(&args.common, Some(&args.output), args.hide_names);
    run(Mode::Encrypt, &args.common, &options, || {
        let recovery = if args.no_recovery {
            None
        } else {
            recovery::load_public().context("cannot read the stored recovery key")?
        };
        if recovery.is_some() {
            eprintln!("The recovery key is in use: these files can also be opened with it.");
        }
        let password = read_secret(PASSWORD_ENV, "Password", true)?;
        Ok(Box::new(EncryptSecrets { password, recovery }))
    })
}

fn open(mode: Mode, common: &Common, output: Option<&Output>, unlock: &UnlockWith) -> Result<bool> {
    let options = options(common, output, false);
    run(mode, common, &options, || {
        let opener = Opener::read(unlock, "Password")?;
        Ok(Box::new(OpenSecrets { opener, verify: mode == Mode::Verify }))
    })
}

fn change_password(args: UnlockArgs) -> Result<bool> {
    let options = options(&args.common, None, false);
    run(Mode::ChangePassword, &args.common, &options, || {
        let opener = Opener::read(&args.unlock, "Current password")?;
        let new_password = read_secret(NEW_PASSWORD_ENV, "New password", true)?;
        Ok(Box::new(ChangeSecrets { opener, new_password }))
    })
}

fn recovery_command(command: RecoveryCommand) -> Result<bool> {
    match command {
        RecoveryCommand::Create => {
            if recovery::load_public().unwrap_or(None).is_some() {
                eprintln!(
                    "Replacing the recovery key in use. Files encrypted with the previous key \
                     still need that key: keep it."
                );
            }
            let key = RecoveryKey::generate();
            recovery::save_public(&key.public())?;
            println!("{}", *key.to_text());
            eprintln!();
            eprintln!("This is your recovery key. It is shown only once and is not stored anywhere.");
            eprintln!("Print it or write it down and keep it somewhere safe, away from this PC.");
            eprintln!("Anyone who has it can open files encrypted from now on without the password.");
        }
        RecoveryCommand::Status => match recovery::load_public()? {
            Some(_) => println!("A recovery key is in use: new files can also be opened with it."),
            None => println!("No recovery key is in use."),
        },
        RecoveryCommand::Disable => {
            recovery::clear_public()?;
            println!("New files will no longer include the recovery key. Existing files keep it.");
        }
    }
    Ok(true)
}

fn main() -> ExitCode {
    let outcome = match Cli::parse().command {
        Command::Encrypt(args) => encrypt(args),
        Command::Decrypt(args) => open(Mode::Decrypt, &args.common, Some(&args.output), &args.unlock),
        Command::Verify(args) => open(Mode::Verify, &args.common, None, &args.unlock),
        Command::ChangePassword(args) => change_password(args),
        Command::Recovery(command) => recovery_command(command),
        Command::Passphrase { words } => {
            println!("{}", *passphrase::generate(words));
            Ok(true)
        }
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
