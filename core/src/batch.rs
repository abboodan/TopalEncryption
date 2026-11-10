//! Encrypting and decrypting many files at once: the engine behind the CLI and the GUI.
//!
//! * One key derivation per batch, however many files there are.
//! * Files are processed in parallel; each uses two chunks of memory whatever its size.
//! * Output goes to a temporary file beside the destination and is renamed into place
//!   only on success, so an interrupted run never leaves a half-written output and never
//!   touches the source. Re-running skips what is already done.
//! * One file failing (locked, unreadable, damaged) does not stop the others.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use rayon::prelude::*;
use walkdir::WalkDir;

use crate::{Decryptor, Encryptor, Error, KdfParams, Result, EXTENSION};

const TEMP_PREFIX: &str = ".topal-tmp-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Delete each source once its output is written and synced to disk. When
    /// encrypting, the output is first decrypted back to prove it is readable.
    /// This is an ordinary delete, not a secure wipe.
    pub delete_source: bool,
    /// Overwrite existing outputs instead of skipping them.
    pub force: bool,
    /// Files processed in parallel; `None` uses every CPU core.
    pub jobs: Option<usize>,
}

/// Live counters a caller can poll from another thread, plus a cancel switch.
#[derive(Debug, Default)]
pub struct Progress {
    /// Source bytes consumed so far (skipped files count in full).
    pub bytes: AtomicU64,
    /// Files finished so far, whatever their outcome.
    pub files: AtomicUsize,
    /// Set to `true` to stop: files in flight are abandoned and cleaned up.
    pub cancel: AtomicBool,
}

/// The files a batch will process, with their sizes.
#[derive(Debug, Default)]
pub struct Scan {
    pub files: Vec<(PathBuf, u64)>,
    /// Paths that could not be read while scanning.
    pub warnings: Vec<String>,
}

impl Scan {
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|(_, size)| size).sum()
    }
}

#[derive(Debug, Default)]
pub struct Summary {
    pub done: usize,
    /// Outputs that already existed and were left alone.
    pub skipped: usize,
    pub cancelled: bool,
    pub failures: Vec<(PathBuf, String)>,
}

enum Outcome {
    Done,
    Skipped,
}

fn is_topal(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case(EXTENSION))
}

fn is_temp(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name.to_string_lossy().starts_with(TEMP_PREFIX))
}

fn append(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Where the result of processing `source` is written.
pub fn output_path(mode: Mode, source: &Path) -> PathBuf {
    match mode {
        Mode::Encrypt => append(source, &format!(".{EXTENSION}")),
        Mode::Decrypt if is_topal(source) => source.with_extension(""),
        Mode::Decrypt => append(source, ".decrypted"),
    }
}

/// Expands files and folders into the list of files to process. A file named explicitly
/// is always taken; inside folders, encryption skips `.topal` files and decryption takes
/// only them.
pub fn scan(mode: Mode, paths: &[PathBuf]) -> Scan {
    let mut scan = Scan::default();
    for path in paths {
        let meta = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(err) => {
                scan.warnings.push(format!("{}: {err}", path.display()));
                continue;
            }
        };
        if meta.is_file() {
            scan.files.push((path.clone(), meta.len()));
            continue;
        }
        for entry in WalkDir::new(path) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    scan.warnings.push(err.to_string());
                    continue;
                }
            };
            let wanted = match mode {
                Mode::Encrypt => !is_topal(entry.path()),
                Mode::Decrypt => is_topal(entry.path()),
            };
            if entry.file_type().is_file() && wanted && !is_temp(entry.path()) {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                scan.files.push((entry.into_path(), size));
            }
        }
    }
    scan
}

struct CountingReader<'a> {
    inner: File,
    progress: &'a Progress,
    /// Bytes of this file already added to `progress.bytes`.
    counted: &'a AtomicU64,
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.progress.cancel.load(Ordering::Relaxed) {
            return Err(io::Error::other("cancelled"));
        }
        let n = self.inner.read(buf)?;
        self.counted.fetch_add(n as u64, Ordering::Relaxed);
        self.progress.bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

struct Runner<'a> {
    mode: Mode,
    options: Options,
    encryptor: Option<Encryptor>,
    decryptor: Option<Decryptor>,
    progress: &'a Progress,
}

impl Runner<'_> {
    /// Processes one file, keeping the byte counter honest when it fails part-way so
    /// that a progress bar still reaches the end.
    fn process(&self, source: &Path, size: u64) -> Result<Outcome> {
        let counted = AtomicU64::new(0);
        let result = self.transform(source, size, &counted);
        if result.is_err() {
            let rest = size.saturating_sub(counted.load(Ordering::Relaxed));
            self.progress.bytes.fetch_add(rest, Ordering::Relaxed);
        }
        result
    }

    fn transform(&self, source: &Path, size: u64, counted: &AtomicU64) -> Result<Outcome> {
        let dest = output_path(self.mode, source);
        if !self.options.force && dest.exists() {
            self.progress.bytes.fetch_add(size, Ordering::Relaxed);
            return Ok(Outcome::Skipped);
        }
        let dir = match dest.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        // Dropped (and so deleted) on every early return below.
        let mut temp = tempfile::Builder::new().prefix(TEMP_PREFIX).tempfile_in(dir)?;
        let reader =
            CountingReader { inner: File::open(source)?, progress: self.progress, counted };

        let written = match self.mode {
            Mode::Encrypt => {
                self.encryptor.as_ref().expect("encryptor").encrypt(reader, temp.as_file_mut())?
            }
            Mode::Decrypt => {
                self.decryptor.as_ref().expect("decryptor").decrypt(reader, temp.as_file_mut())?
            }
        };

        if self.options.delete_source {
            temp.as_file().sync_all()?;
            if self.mode == Mode::Encrypt {
                let sealed = temp.reopen()?;
                let verified =
                    self.decryptor.as_ref().expect("decryptor").decrypt(sealed, io::sink())?;
                if verified != written || written != size {
                    return Err(Error::VerificationFailed);
                }
            }
        }

        if self.options.force {
            temp.persist(&dest).map_err(|e| e.error)?;
        } else {
            temp.persist_noclobber(&dest).map_err(|e| e.error)?;
        }
        if self.options.delete_source {
            fs::remove_file(source)?;
        }
        Ok(Outcome::Done)
    }
}

/// Processes `files` (as returned by [`scan`]) under one password.
///
/// Fails outright only if the key cannot be derived; per-file problems are collected in
/// the returned [`Summary`].
pub fn run(
    mode: Mode,
    files: &[(PathBuf, u64)],
    password: &str,
    params: KdfParams,
    options: Options,
    progress: &Progress,
) -> Result<Summary> {
    let runner = Runner {
        mode,
        options,
        encryptor: match mode {
            Mode::Encrypt => Some(Encryptor::new(password, params)?),
            Mode::Decrypt => None,
        },
        decryptor: (mode == Mode::Decrypt || options.delete_source)
            .then(|| Decryptor::new(password)),
        progress,
    };

    let mut pool = rayon::ThreadPoolBuilder::new();
    if let Some(jobs) = options.jobs {
        pool = pool.num_threads(jobs.max(1));
    }
    let pool = pool.build().map_err(io::Error::other)?;
    let results: Vec<Option<Result<Outcome>>> = pool.install(|| {
        files
            .par_iter()
            .map(|(path, size)| {
                if progress.cancel.load(Ordering::Relaxed) {
                    return None;
                }
                let result = runner.process(path, *size);
                progress.files.fetch_add(1, Ordering::Relaxed);
                Some(result)
            })
            .collect()
    });

    let cancelled = progress.cancel.load(Ordering::Relaxed);
    let mut summary = Summary { cancelled, ..Summary::default() };
    for ((path, _), result) in files.iter().zip(results) {
        match result {
            Some(Ok(Outcome::Done)) => summary.done += 1,
            Some(Ok(Outcome::Skipped)) => summary.skipped += 1,
            // Once cancelled, errors are files abandoned mid-way, not real failures.
            Some(Err(_)) if cancelled => {}
            Some(Err(err)) => summary.failures.push((path.clone(), err.to_string())),
            None => {}
        }
    }
    Ok(summary)
}
