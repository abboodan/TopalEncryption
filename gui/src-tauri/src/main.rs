// No console window behind the app in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use topal_core::batch::{self, Job, Mode, Options, Progress, Unlock};
use topal_core::recovery::{self, RecoveryKey};
use topal_core::{passphrase, Error, KdfParams};
use zeroize::Zeroizing;

const PROGRESS_EVENT: &str = "progress";
/// Sent when Explorer's right-click menu starts a second copy of the app with paths.
const OPEN_EVENT: &str = "open-paths";
const PROGRESS_INTERVAL: Duration = Duration::from_millis(80);
const MAX_FAILURES_REPORTED: usize = 200;
const RECOVERY_KEY_FILE: &str = "Topal Encryption recovery key.txt";

/// The batch in flight, if any, so that `cancel` can reach it.
#[derive(Default)]
struct AppState {
    current: Mutex<Option<Arc<Progress>>>,
}

#[derive(Deserialize, Serialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ModeArg {
    Encrypt,
    Decrypt,
    Verify,
    Change,
}

impl From<ModeArg> for Mode {
    fn from(mode: ModeArg) -> Self {
        match mode {
            ModeArg::Encrypt => Mode::Encrypt,
            ModeArg::Decrypt => Mode::Decrypt,
            ModeArg::Verify => Mode::Verify,
            ModeArg::Change => Mode::ChangePassword,
        }
    }
}

#[derive(Serialize)]
struct ScanInfo {
    /// Units of work: a folder packed whole counts once.
    items: usize,
    files: usize,
    bytes: u64,
    warnings: Vec<String>,
}

#[derive(Serialize, Clone)]
struct ProgressInfo {
    bytes: u64,
    total_bytes: u64,
    files: usize,
    total_files: usize,
}

#[derive(Serialize)]
struct Failure {
    path: String,
    /// Stable identifier the interface translates; `reason` is the English fallback.
    code: &'static str,
    reason: String,
}

#[derive(Serialize)]
struct SummaryInfo {
    done: usize,
    skipped: usize,
    failed: usize,
    cancelled: bool,
    /// At most `MAX_FAILURES_REPORTED`; `failed` is the true count.
    failures: Vec<Failure>,
    warnings: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartRequest {
    mode: ModeArg,
    paths: Vec<PathBuf>,
    /// The password, or the recovery key when `use_recovery_key` is set.
    secret: String,
    use_recovery_key: bool,
    /// Only when changing the password.
    new_password: Option<String>,
    delete_source: bool,
    hide_names: bool,
    output_dir: Option<PathBuf>,
}

/// Paths handed over on the command line, by the right-click menu or a double click.
#[derive(Serialize, Clone)]
struct OpenRequest {
    mode: ModeArg,
    paths: Vec<PathBuf>,
}

fn error_code(err: &Error) -> &'static str {
    match err {
        Error::Io(_) => "io",
        Error::NotTopal => "not_topal",
        Error::UnsupportedVersion(_) => "unsupported_version",
        Error::InvalidKdfParams => "invalid_kdf",
        Error::WrongPassword => "wrong_password",
        Error::WrongRecoveryKey => "wrong_recovery_key",
        Error::NoRecoverySlot => "no_recovery_slot",
        Error::InvalidRecoveryKey => "invalid_recovery_key",
        Error::Corrupted => "corrupted",
        Error::VerificationFailed => "verification_failed",
        Error::UnsafePath => "unsafe_path",
        Error::OutputExists => "output_exists",
    }
}

/// `--encrypt` / `--decrypt` followed by paths. Without a flag, `.topal` files are
/// decrypted (that is what a double click sends) and anything else is encrypted.
fn parse_args(args: impl IntoIterator<Item = String>) -> Option<OpenRequest> {
    let mut mode = None;
    let mut paths = Vec::new();
    for arg in args.into_iter().skip(1) {
        match arg.as_str() {
            "--encrypt" => mode = Some(ModeArg::Encrypt),
            "--decrypt" => mode = Some(ModeArg::Decrypt),
            other if other.starts_with("--") => {}
            _ => paths.push(PathBuf::from(arg)),
        }
    }
    if paths.is_empty() {
        return None;
    }
    let is_topal = |path: &PathBuf| {
        Path::new(path).extension().is_some_and(|ext| ext.eq_ignore_ascii_case(topal_core::EXTENSION))
    };
    let mode = mode.unwrap_or(if paths.iter().all(is_topal) { ModeArg::Decrypt } else { ModeArg::Encrypt });
    Some(OpenRequest { mode, paths })
}

#[tauri::command]
fn launch_request() -> Option<OpenRequest> {
    parse_args(std::env::args())
}

#[tauri::command]
async fn pick_files(app: AppHandle) -> Vec<PathBuf> {
    app.dialog()
        .file()
        .blocking_pick_files()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|file| file.into_path().ok())
        .collect()
}

#[tauri::command]
async fn pick_folders(app: AppHandle) -> Vec<PathBuf> {
    app.dialog()
        .file()
        .blocking_pick_folders()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|folder| folder.into_path().ok())
        .collect()
}

#[tauri::command]
async fn pick_output_folder(app: AppHandle) -> Option<PathBuf> {
    app.dialog().file().blocking_pick_folder().and_then(|folder| folder.into_path().ok())
}

/// Counts what a batch would process, without touching anything.
#[tauri::command]
async fn scan(mode: ModeArg, paths: Vec<PathBuf>, hide_names: bool) -> Result<ScanInfo, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let options = Options { hide_names, ..Options::default() };
        let scan = batch::scan(mode.into(), &paths, &options);
        ScanInfo {
            items: scan.items.len(),
            files: scan.total_files(),
            bytes: scan.total_bytes(),
            warnings: scan.warnings,
        }
    })
    .await
    .map_err(|err| err.to_string())
}

#[tauri::command]
fn generate_passphrase() -> String {
    passphrase::generate(passphrase::DEFAULT_WORDS).to_string()
}

/// Whether new files also get a recovery slot.
#[tauri::command]
fn recovery_status() -> bool {
    matches!(recovery::load_public(), Ok(Some(_)))
}

/// Creates a recovery key, remembers its public half, and returns the secret half once.
/// The secret is never stored by the app.
#[tauri::command]
fn recovery_create() -> Result<String, String> {
    let key = RecoveryKey::generate();
    recovery::save_public(&key.public()).map_err(|err| err.to_string())?;
    Ok(key.to_text().to_string())
}

#[tauri::command]
fn recovery_disable() -> Result<(), String> {
    recovery::clear_public().map_err(|err| err.to_string())
}

/// Lets the user choose where to save the recovery key as a text file.
#[tauri::command]
async fn save_recovery_key(app: AppHandle, key: String) -> Result<bool, String> {
    let key = Zeroizing::new(key);
    let Some(path) = app
        .dialog()
        .file()
        .set_file_name(RECOVERY_KEY_FILE)
        .add_filter("Text", &["txt"])
        .blocking_save_file()
        .and_then(|file| file.into_path().ok())
    else {
        return Ok(false);
    };
    let text = Zeroizing::new(format!(
        "Topal Encryption recovery key\r\n\r\n{}\r\n\r\n\
         Anyone who has this key can open the files it protects without the password.\r\n\
         Keep it somewhere safe, away from the PC that holds the encrypted files.\r\n",
        *key
    ));
    std::fs::write(path, text.as_bytes()).map_err(|err| err.to_string())?;
    Ok(true)
}

#[tauri::command]
async fn start(
    app: AppHandle,
    state: State<'_, AppState>,
    request: StartRequest,
) -> Result<SummaryInfo, String> {
    let StartRequest {
        mode,
        paths,
        secret,
        use_recovery_key,
        new_password,
        delete_source,
        hide_names,
        output_dir,
    } = request;
    let secret = Zeroizing::new(secret);
    let new_password = Zeroizing::new(new_password.unwrap_or_default());
    // Errors here are identifiers the interface translates.
    if secret.is_empty() || (mode == ModeArg::Change && new_password.is_empty()) {
        return Err("empty_password".into());
    }
    let recovery_key = match use_recovery_key && mode != ModeArg::Encrypt {
        true => Some(RecoveryKey::parse(&secret).map_err(|_| "invalid_recovery_key")?),
        false => None,
    };
    let progress = Arc::new(Progress::default());
    {
        let mut current = state.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if current.is_some() {
            return Err("busy".into());
        }
        *current = Some(progress.clone());
    }

    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let unlock = || match &recovery_key {
            Some(key) => Unlock::RecoveryKey(key),
            None => Unlock::Password(&secret),
        };
        let job = match mode {
            ModeArg::Encrypt => Job::Encrypt {
                password: &secret,
                recovery: recovery::load_public().map_err(|err| err.to_string())?,
            },
            ModeArg::Decrypt => Job::Decrypt(unlock()),
            ModeArg::Verify => Job::Verify(unlock()),
            ModeArg::Change => Job::ChangePassword { unlock: unlock(), new_password: &new_password },
        };
        let options = Options {
            delete_source: delete_source && matches!(mode, ModeArg::Encrypt | ModeArg::Decrypt),
            hide_names: hide_names && mode == ModeArg::Encrypt,
            output_dir: output_dir.filter(|_| matches!(mode, ModeArg::Encrypt | ModeArg::Decrypt)),
            ..Options::default()
        };
        let scan = batch::scan(job.mode(), &paths, &options);
        let snapshot = |progress: &Progress| ProgressInfo {
            bytes: progress.bytes.load(Ordering::Relaxed),
            total_bytes: scan.total_bytes(),
            files: progress.files.load(Ordering::Relaxed),
            total_files: scan.items.len(),
        };

        let finished = AtomicBool::new(false);
        let summary = std::thread::scope(|scope| {
            scope.spawn(|| {
                while !finished.load(Ordering::Relaxed) {
                    let _ = app.emit(PROGRESS_EVENT, snapshot(&progress));
                    std::thread::sleep(PROGRESS_INTERVAL);
                }
            });
            let summary = batch::run(&job, &scan.items, KdfParams::default(), &options, &progress);
            finished.store(true, Ordering::Relaxed);
            summary
        })
        .map_err(|err| err.to_string())?;
        let _ = app.emit(PROGRESS_EVENT, snapshot(&progress));

        Ok(SummaryInfo {
            done: summary.done,
            skipped: summary.skipped,
            failed: summary.failures.len(),
            cancelled: summary.cancelled,
            failures: summary
                .failures
                .into_iter()
                .take(MAX_FAILURES_REPORTED)
                .map(|(path, err)| Failure {
                    path: path.display().to_string(),
                    code: error_code(&err),
                    reason: err.to_string(),
                })
                .collect(),
            warnings: scan.warnings,
        })
    })
    .await
    .map_err(|err| err.to_string());

    *state.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    outcome?
}

#[tauri::command]
fn cancel(state: State<'_, AppState>) {
    if let Some(progress) =
        state.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).as_ref()
    {
        progress.cancel.store(true, Ordering::Relaxed);
    }
}

fn main() {
    tauri::Builder::default()
        // Must be registered first. Selecting several files in Explorer starts the app
        // once per file: the extra copies hand their path to the first one and exit.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if let Some(request) = parse_args(args) {
                let _ = app.emit(OPEN_EVENT, request);
            }
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            launch_request,
            pick_files,
            pick_folders,
            pick_output_folder,
            scan,
            generate_passphrase,
            recovery_status,
            recovery_create,
            recovery_disable,
            save_recovery_key,
            start,
            cancel
        ])
        .run(tauri::generate_context!())
        .expect("failed to start Topal Encryption");
}
