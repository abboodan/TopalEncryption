//! Updates, through the official Tauri updater plugin.
//!
//! This is the only part of the app that uses the network, and it does so in two cases
//! only: the user presses "Check for updates", or the "check once a day" setting (off
//! by default) is on. The single endpoint is the one in `tauri.conf.json`; the installer
//! is downloaded from the same site and is run only after the plugin has verified its
//! signature against the public key built into the app.
//!
//! An installed copy updates itself. A portable copy (the bare `.exe`) never does: it
//! only reports that a new version exists.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_updater::{Error as UpdaterError, Update, UpdaterExt};

use crate::AppState;

const DOWNLOAD_EVENT: &str = "update-progress";
const DOWNLOAD_EVENT_INTERVAL: Duration = Duration::from_millis(80);
const CHECK_TIMEOUT: Duration = Duration::from_secs(20);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);
/// The automatic check runs at most this often.
const AUTOMATIC_INTERVAL_SECS: u64 = 24 * 60 * 60;
const SETTINGS_FILE: &str = "settings.json";
/// Written next to the app by the installer, and by nothing else.
const UNINSTALLER: &str = "uninstall.exe";

#[derive(Default)]
pub struct UpdateState {
    /// A download or an installation is in progress: no job may start meanwhile.
    busy: AtomicBool,
    /// What the last check found.
    found: Mutex<Option<Update>>,
    /// The installer for `found`, downloaded and verified.
    package: Mutex<Option<Vec<u8>>>,
}

impl UpdateState {
    pub fn is_busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }
}

/// Clears the busy flag when a download or an installation ends, however it ends.
struct Busy<'a>(&'a AtomicBool);

impl<'a> Busy<'a> {
    fn claim(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).ok().map(|_| Self(flag))
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Kept in `%APPDATA%\TopalEncryption\settings.json`, beside the recovery key's public half.
#[derive(Serialize, Deserialize, Default, Clone, Copy, PartialEq, Debug)]
#[serde(default)]
struct Settings {
    /// Look for a new version once a day without being asked. Off unless switched on.
    daily_update_check: bool,
    /// When the last automatic check was made, in seconds since 1970.
    last_update_check: u64,
}

fn settings_path() -> Option<PathBuf> {
    Some(topal_core::recovery::store_path()?.parent()?.join(SETTINGS_FILE))
}

/// A missing or unreadable file means the defaults: nothing automatic.
fn load_settings() -> Settings {
    settings_path()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_settings(settings: &Settings) -> std::io::Result<()> {
    let path = settings_path().ok_or_else(|| std::io::Error::other("no settings folder"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(settings).map_err(std::io::Error::other)?)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_secs()).unwrap_or(0)
}

/// Whether an automatic check may run now. A clock that went backwards counts as due.
fn automatic_check_due(settings: &Settings, now: u64) -> bool {
    settings.daily_update_check
        && (now < settings.last_update_check
            || now - settings.last_update_check >= AUTOMATIC_INTERVAL_SECS)
}

/// An installed copy has the uninstaller the installer wrote beside it; the portable
/// `.exe` has nothing beside it.
pub fn is_installed() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join(UNINSTALLER).is_file()))
        .unwrap_or(false)
}

/// The first configured endpoint: updates are only ever downloaded from its site.
fn endpoint(app: &AppHandle) -> Option<tauri::Url> {
    app.config().plugins.0.get("updater")?.get("endpoints")?.get(0)?.as_str()?.parse().ok()
}

fn same_site(a: &tauri::Url, b: &tauri::Url) -> bool {
    a.scheme() == b.scheme() && a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
}

/// Identifiers the interface translates.
fn error_code(err: &UpdaterError) -> &'static str {
    match err {
        UpdaterError::Minisign(_)
        | UpdaterError::Base64(_)
        | UpdaterError::SignatureUtf8(_)
        | UpdaterError::SignedVersionMismatch { .. }
        | UpdaterError::MissingSignedVersion => "update_bad_signature",
        UpdaterError::Reqwest(_) | UpdaterError::Network(_) | UpdaterError::ReleaseNotFound => {
            "update_offline"
        }
        _ => "update_failed",
    }
}

#[derive(Serialize)]
pub struct AppInfo {
    version: String,
    installed: bool,
    daily_check: bool,
}

#[tauri::command]
pub fn app_info(app: AppHandle) -> AppInfo {
    AppInfo {
        version: app.package_info().version.to_string(),
        installed: is_installed(),
        daily_check: load_settings().daily_update_check,
    }
}

#[tauri::command]
pub fn set_daily_check(enabled: bool) -> Result<(), String> {
    let mut settings = load_settings();
    settings.daily_update_check = enabled;
    save_settings(&settings).map_err(|err| err.to_string())
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CheckResult {
    /// An automatic check that is switched off, or was already made today.
    NotDue,
    /// Nothing newer than this version is published.
    Current,
    Available { version: String },
}

/// Asks the endpoint for the latest version. `automatic` is the daily check: it does
/// nothing unless the setting is on and a day has passed since the last one.
#[tauri::command]
pub async fn update_check(
    app: AppHandle,
    state: State<'_, AppState>,
    automatic: bool,
) -> Result<CheckResult, String> {
    let update_state = &state.update;
    if automatic {
        let mut settings = load_settings();
        // Never in the middle of a job or of an update already under way.
        if !automatic_check_due(&settings, now()) || update_state.is_busy() || state.job_running() {
            return Ok(CheckResult::NotDue);
        }
        // Recorded first, so that a check that fails is not repeated until tomorrow.
        settings.last_update_check = now();
        save_settings(&settings).map_err(|err| err.to_string())?;
    } else if update_state.is_busy() {
        return Err("updating".into());
    }
    // Whatever an earlier check found is forgotten: only this answer counts.
    *lock(&update_state.found) = None;
    *lock(&update_state.package) = None;

    let updater = app
        .updater_builder()
        .timeout(CHECK_TIMEOUT)
        .build()
        .map_err(|err| error_code(&err))?;
    let found = updater.check().await.map_err(|err| error_code(&err))?;
    let Some(mut update) = found else {
        return Ok(CheckResult::Current);
    };
    // The answer names where the installer is. It must be the site that was asked.
    if !endpoint(&app).is_some_and(|endpoint| same_site(&endpoint, &update.download_url)) {
        return Err("update_failed".into());
    }
    update.timeout = Some(DOWNLOAD_TIMEOUT);
    let version = update.version.clone();
    if update_state.is_busy() {
        return Err("updating".into());
    }
    *lock(&update_state.found) = Some(update);
    Ok(CheckResult::Available { version })
}

#[derive(Serialize, Clone)]
struct DownloadProgress {
    downloaded: u64,
    /// Unknown when the server does not say.
    total: Option<u64>,
}

/// Downloads the installer of the version the last check found and verifies its
/// signature. Nothing is installed yet.
#[tauri::command]
pub async fn update_download(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if !is_installed() {
        return Err("update_portable".into());
    }
    let update_state = &state.update;
    let Some(_busy) = Busy::claim(&update_state.busy) else {
        return Err("updating".into());
    };
    if state.job_running() {
        return Err("busy".into());
    }
    let Some(update) = lock(&update_state.found).clone() else {
        return Err("update_failed".into());
    };

    let mut downloaded = 0u64;
    let mut last_event: Option<Instant> = None;
    let bytes = update
        .download(
            |chunk, total| {
                downloaded += chunk as u64;
                let finished = total.is_some_and(|total| downloaded >= total);
                if finished || last_event.is_none_or(|at| at.elapsed() >= DOWNLOAD_EVENT_INTERVAL) {
                    last_event = Some(Instant::now());
                    let _ = app.emit(DOWNLOAD_EVENT, DownloadProgress { downloaded, total });
                }
            },
            || {},
        )
        .await
        .map_err(|err| error_code(&err))?;
    *lock(&update_state.package) = Some(bytes);
    Ok(())
}

/// Runs the downloaded installer, which closes the app and starts the new version.
/// The plugin verifies the signature once more before it runs anything.
#[tauri::command]
pub async fn update_install(state: State<'_, AppState>) -> Result<(), String> {
    if !is_installed() {
        return Err("update_portable".into());
    }
    let update_state = &state.update;
    let Some(_busy) = Busy::claim(&update_state.busy) else {
        return Err("updating".into());
    };
    if state.job_running() {
        return Err("busy".into());
    }
    let update = lock(&update_state.found).clone();
    let package = lock(&update_state.package).take();
    let (Some(update), Some(package)) = (update, package) else {
        return Err("update_failed".into());
    };
    // Does not return when it succeeds: the app exits as the installer starts.
    update.install(package).map_err(|err| error_code(&err).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_automatic_by_default() {
        let settings = Settings::default();
        assert!(!settings.daily_update_check);
        assert!(!automatic_check_due(&settings, now()));
        // An empty, older or damaged settings file means the defaults.
        assert_eq!(serde_json::from_str::<Settings>("{}").unwrap(), Settings::default());
        assert_eq!(
            serde_json::from_str::<Settings>(r#"{"something_else": 1}"#).unwrap(),
            Settings::default()
        );
    }

    #[test]
    fn the_daily_check_runs_once_a_day() {
        let day = AUTOMATIC_INTERVAL_SECS;
        let on = |last| Settings { daily_update_check: true, last_update_check: last };
        assert!(automatic_check_due(&on(0), 10 * day));
        assert!(!automatic_check_due(&on(10 * day), 10 * day + 1));
        assert!(!automatic_check_due(&on(10 * day), 11 * day - 1));
        assert!(automatic_check_due(&on(10 * day), 11 * day));
        // The clock was set back: do not wait for it to catch up.
        assert!(automatic_check_due(&on(10 * day), 9 * day));
        let off = Settings { daily_update_check: false, last_update_check: 0 };
        assert!(!automatic_check_due(&off, 10 * day));
    }

    #[test]
    fn the_installer_must_come_from_the_site_that_was_asked() {
        let url = |text: &str| text.parse::<tauri::Url>().unwrap();
        let endpoint = url("https://github.com/abboodan/TopalEncryption/releases/latest/download/latest.json");
        let same = "https://github.com/abboodan/TopalEncryption/releases/download/v0.4.0/TopalEncryption_0.4.0_x64-setup.exe";
        assert!(same_site(&endpoint, &url(same)));
        assert!(!same_site(&endpoint, &url("http://github.com/x.exe")));
        assert!(!same_site(&endpoint, &url("https://github.com.example.org/x.exe")));
        assert!(!same_site(&endpoint, &url("https://example.org/x.exe")));
        assert!(!same_site(&endpoint, &url("https://github.com:8443/x.exe")));
    }

    #[test]
    fn the_committed_configuration_names_only_the_real_endpoint_and_key() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let updater = &config["plugins"]["updater"];
        assert_eq!(
            updater["endpoints"],
            serde_json::json!([
                "https://github.com/abboodan/TopalEncryption/releases/latest/download/latest.json"
            ])
        );
        assert_eq!(
            updater["pubkey"],
            "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDlFQkNGRkVFRjlGODNDRjQKUldUMFBQajU3dis4bmxjTXBQYWZzZFczQVpseGxOQ28zVVQ5UCsyNk02bFBLNGdaeEZwU2JlT3MK"
        );
        for key in updater.as_object().unwrap().keys() {
            assert!(!key.to_lowercase().contains("dangerous"), "{key}");
        }
        assert_eq!(config["bundle"]["createUpdaterArtifacts"], true);
    }
}
