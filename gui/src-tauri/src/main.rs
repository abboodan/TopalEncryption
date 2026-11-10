// No console window behind the app in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_dialog::DialogExt;
use topal_core::batch::{self, Mode, Options, Progress};
use topal_core::KdfParams;
use zeroize::Zeroizing;

const PROGRESS_EVENT: &str = "progress";
const PROGRESS_INTERVAL: Duration = Duration::from_millis(80);
const MAX_FAILURES_REPORTED: usize = 200;

/// The batch in flight, if any, so that `cancel` can reach it.
#[derive(Default)]
struct AppState {
    current: Mutex<Option<Arc<Progress>>>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum ModeArg {
    Encrypt,
    Decrypt,
}

impl From<ModeArg> for Mode {
    fn from(mode: ModeArg) -> Self {
        match mode {
            ModeArg::Encrypt => Mode::Encrypt,
            ModeArg::Decrypt => Mode::Decrypt,
        }
    }
}

#[derive(Serialize)]
struct ScanInfo {
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

/// Counts what a batch would process, without touching anything.
#[tauri::command]
async fn scan(mode: ModeArg, paths: Vec<PathBuf>) -> Result<ScanInfo, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let scan = batch::scan(mode.into(), &paths);
        ScanInfo { files: scan.files.len(), bytes: scan.total_bytes(), warnings: scan.warnings }
    })
    .await
    .map_err(|err| err.to_string())
}

#[tauri::command]
async fn start(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: ModeArg,
    paths: Vec<PathBuf>,
    password: String,
    delete_source: bool,
) -> Result<SummaryInfo, String> {
    let password = Zeroizing::new(password);
    if password.is_empty() {
        return Err("The password cannot be empty.".into());
    }
    let progress = Arc::new(Progress::default());
    {
        let mut current = state.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if current.is_some() {
            return Err("A job is already running.".into());
        }
        *current = Some(progress.clone());
    }

    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let mode: Mode = mode.into();
        let scan = batch::scan(mode, &paths);
        let snapshot = |progress: &Progress| ProgressInfo {
            bytes: progress.bytes.load(Ordering::Relaxed),
            total_bytes: scan.total_bytes(),
            files: progress.files.load(Ordering::Relaxed),
            total_files: scan.files.len(),
        };

        let finished = AtomicBool::new(false);
        let summary = std::thread::scope(|scope| {
            scope.spawn(|| {
                while !finished.load(Ordering::Relaxed) {
                    let _ = app.emit(PROGRESS_EVENT, snapshot(&progress));
                    std::thread::sleep(PROGRESS_INTERVAL);
                }
            });
            let options = Options { delete_source, ..Options::default() };
            let summary =
                batch::run(mode, &scan.files, &password, KdfParams::default(), options, &progress);
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
                .map(|(path, reason)| Failure { path: path.display().to_string(), reason })
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
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![pick_files, pick_folders, scan, start, cancel])
        .run(tauri::generate_context!())
        .expect("failed to start Topal Encryption");
}
