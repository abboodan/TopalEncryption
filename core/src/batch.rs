//! Working on many files at once: the engine behind the CLI and the GUI.
//!
//! * One key derivation per batch, however many files there are.
//! * Files are processed in parallel; each uses two chunks of memory whatever its size.
//! * Output goes to a temporary file beside the destination and is renamed into place
//!   only on success, so an interrupted run never leaves a half-written output and never
//!   touches the source. Re-running skips what is already done.
//! * One file failing (locked, unreadable, damaged) does not stop the others.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use rand::rngs::OsRng;
use rand::RngCore;
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::archive::{self, Packer};
use crate::recovery::{RecoveryKey, RecoveryPublic};
use crate::{DecryptReader, Decryptor, Encryptor, Error, KdfParams, Kind, Result, EXTENSION};

const TEMP_PREFIX: &str = ".topal-tmp-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
    /// Check that encrypted files open and are undamaged, writing nothing.
    Verify,
    /// Replace the password of encrypted files in place.
    ChangePassword,
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Delete each source once its output is written and synced to disk. When
    /// encrypting, the output is first decrypted back to prove it is readable.
    /// This is an ordinary delete, not a secure wipe.
    pub delete_source: bool,
    /// Overwrite existing output files instead of skipping them. Existing folders are
    /// never overwritten.
    pub force: bool,
    /// Files processed in parallel; `None` uses every CPU core.
    pub jobs: Option<usize>,
    /// When encrypting: give every output a random name, and pack each selected folder
    /// into a single file, so that names, structure and file count are hidden.
    pub hide_names: bool,
    /// Write outputs here, keeping the folder structure of the selection, instead of
    /// beside each source.
    pub output_dir: Option<PathBuf>,
}

/// How encrypted files are opened.
pub enum Unlock<'a> {
    Password(&'a str),
    RecoveryKey(&'a RecoveryKey),
}

impl Unlock<'_> {
    fn decryptor(&self) -> Decryptor {
        match self {
            Unlock::Password(password) => Decryptor::new(password),
            Unlock::RecoveryKey(key) => Decryptor::with_recovery_key((*key).clone()),
        }
    }
}

/// What to do, with the secrets it needs.
pub enum Job<'a> {
    Encrypt { password: &'a str, recovery: Option<RecoveryPublic> },
    Decrypt(Unlock<'a>),
    Verify(Unlock<'a>),
    ChangePassword { unlock: Unlock<'a>, new_password: &'a str },
}

impl Job<'_> {
    pub fn mode(&self) -> Mode {
        match self {
            Job::Encrypt { .. } => Mode::Encrypt,
            Job::Decrypt(_) => Mode::Decrypt,
            Job::Verify(_) => Mode::Verify,
            Job::ChangePassword { .. } => Mode::ChangePassword,
        }
    }
}

/// Live counters a caller can poll from another thread, plus a cancel switch.
#[derive(Debug, Default)]
pub struct Progress {
    /// Source bytes consumed so far (skipped files count in full).
    pub bytes: AtomicU64,
    /// Items finished so far, whatever their outcome.
    pub files: AtomicUsize,
    /// Set to `true` to stop: files in flight are abandoned and cleaned up.
    pub cancel: AtomicBool,
}

/// One unit of work: a file, or a whole folder packed into a single output.
#[derive(Debug, Clone)]
pub struct Item {
    pub source: PathBuf,
    /// Bytes of content: the file's size, or the total of a folder's files.
    pub size: u64,
    /// Where the source sits inside the selection, used to rebuild the structure under
    /// an output folder. Empty for something that was selected directly.
    pub rel_dir: PathBuf,
    /// The source is a folder to be packed whole.
    pub folder: bool,
    /// Files this item stands for.
    pub file_count: usize,
}

/// What a batch will process.
#[derive(Debug, Default)]
pub struct Scan {
    pub items: Vec<Item>,
    /// Paths that could not be read while scanning.
    pub warnings: Vec<String>,
}

impl Scan {
    pub fn total_bytes(&self) -> u64 {
        self.items.iter().map(|item| item.size).sum()
    }

    pub fn total_files(&self) -> usize {
        self.items.iter().map(|item| item.file_count).sum()
    }
}

#[derive(Debug, Default)]
pub struct Summary {
    pub done: usize,
    /// Outputs that already existed and were left alone.
    pub skipped: usize,
    pub cancelled: bool,
    pub failures: Vec<(PathBuf, Error)>,
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

fn file_name(path: &Path) -> String {
    path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn random_name() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{hex}.{EXTENSION}")
}

/// Name for a decrypted file when the encrypted file does not carry a usable one.
fn fallback_name(source: &Path) -> String {
    if is_topal(source) {
        source.file_stem().map(|stem| stem.to_string_lossy().into_owned()).unwrap_or_default()
    } else {
        format!("{}.decrypted", file_name(source))
    }
}

/// Expands files and folders into the work list. A file named explicitly is always taken;
/// inside folders, encryption skips `.topal` files and the other modes take only them.
/// With `hide_names`, a folder being encrypted is a single item.
pub fn scan(mode: Mode, paths: &[PathBuf], options: &Options) -> Scan {
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
            scan.items.push(Item {
                source: path.clone(),
                size: meta.len(),
                rel_dir: PathBuf::new(),
                folder: false,
                file_count: 1,
            });
            continue;
        }
        if mode == Mode::Encrypt && options.hide_names {
            match archive::list(path) {
                Ok(entries) => scan.items.push(Item {
                    source: path.clone(),
                    size: archive::content_bytes(&entries),
                    rel_dir: PathBuf::new(),
                    folder: true,
                    file_count: entries.iter().filter(|entry| !entry.is_dir).count(),
                }),
                Err(err) => scan.warnings.push(format!("{}: {err}", path.display())),
            }
            continue;
        }
        let top = PathBuf::from(path.file_name().unwrap_or_default());
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
                _ => is_topal(entry.path()),
            };
            if entry.file_type().is_file() && wanted && !is_temp(entry.path()) {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let inside = entry.path().strip_prefix(path).ok().and_then(Path::parent);
                scan.items.push(Item {
                    rel_dir: top.join(inside.unwrap_or(Path::new(""))),
                    source: entry.into_path(),
                    size,
                    folder: false,
                    file_count: 1,
                });
            }
        }
    }
    scan
}

struct CountingReader<'a> {
    inner: File,
    progress: &'a Progress,
    /// Bytes of this item already added to `progress.bytes`.
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

/// Whether the rest of `content` is byte-for-byte the file at `plain`.
fn same_content<R: Read>(content: &mut DecryptReader<R>, plain: &Path) -> Result<bool> {
    let mut file = File::open(plain)?;
    let mut buf = Vec::new();
    while let Some(chunk) = content.next_chunk()? {
        buf.resize(chunk.len(), 0);
        if crate::read_full(&mut file, &mut buf)? != chunk.len() || buf != chunk {
            return Ok(false);
        }
    }
    Ok(file.read(&mut [0u8; 1])? == 0)
}

fn persist(temp: tempfile::NamedTempFile, dest: &Path, force: bool) -> Result<()> {
    let result = if force {
        temp.persist(dest).map(drop).map_err(|err| err.error)
    } else {
        temp.persist_noclobber(dest).map(drop).map_err(|err| err.error)
    };
    result.map_err(|err| match err.kind() {
        io::ErrorKind::AlreadyExists => Error::OutputExists,
        _ => err.into(),
    })
}

struct Runner<'a> {
    mode: Mode,
    options: &'a Options,
    encryptor: Option<Encryptor>,
    decryptor: Option<Decryptor>,
    progress: &'a Progress,
}

impl Runner<'_> {
    fn encryptor(&self) -> &Encryptor {
        self.encryptor.as_ref().expect("this mode has an encryptor")
    }

    fn decryptor(&self) -> &Decryptor {
        self.decryptor.as_ref().expect("this mode has a decryptor")
    }

    fn open_counted<'s>(&'s self, path: &Path, counted: &'s AtomicU64) -> io::Result<CountingReader<'s>> {
        Ok(CountingReader { inner: File::open(path)?, progress: self.progress, counted })
    }

    /// The folder an item's output goes into.
    fn dest_dir(&self, item: &Item) -> PathBuf {
        match &self.options.output_dir {
            // Random names need no structure, and structure would give names away.
            Some(out) if self.mode == Mode::Encrypt && self.options.hide_names => out.clone(),
            Some(out) => out.join(&item.rel_dir),
            None => parent_dir(&item.source).to_owned(),
        }
    }

    /// Where encrypting `item` writes to, when that is known in advance.
    fn encrypt_dest(&self, item: &Item) -> Option<PathBuf> {
        (!self.options.hide_names)
            .then(|| self.dest_dir(item).join(format!("{}.{EXTENSION}", file_name(&item.source))))
    }

    /// Processes one item, keeping the byte counter honest when it stops part-way or
    /// does not need to read everything, so that a progress bar still reaches the end.
    fn process(&self, item: &Item) -> Result<Outcome> {
        let counted = AtomicU64::new(0);
        let result = match self.mode {
            Mode::Encrypt if item.folder => self.encrypt_folder(item, &counted),
            Mode::Encrypt => self.encrypt_file(item, &counted),
            Mode::Decrypt => self.decrypt(item, &counted),
            Mode::Verify => self.verify(item, &counted),
            Mode::ChangePassword => self.change_password(item),
        };
        let rest = item.size.saturating_sub(counted.load(Ordering::Relaxed));
        self.progress.bytes.fetch_add(rest, Ordering::Relaxed);
        result
    }

    /// Syncs a finished encrypted file and proves it decrypts back to `written` bytes.
    fn verify_sealed(&self, temp: &tempfile::NamedTempFile, written: u64, expected: u64) -> Result<()> {
        temp.as_file().sync_all()?;
        let verified = self.decryptor().decrypt(temp.reopen()?, io::sink())?;
        if verified != written || written != expected {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }

    fn encrypt_file(&self, item: &Item, counted: &AtomicU64) -> Result<Outcome> {
        let dir = self.dest_dir(item);
        let dest = self.encrypt_dest(item).unwrap_or_else(|| dir.join(random_name()));
        if !self.options.force && dest.exists() {
            // An earlier run that was interrupted may have encrypted this file without
            // getting to delete it. Finish that, but only if the existing output really
            // holds this exact content under this password.
            if self.options.delete_source {
                let matches = match self.decryptor().open(File::open(&dest)?) {
                    Ok(mut opened) if opened.kind == Kind::File => {
                        same_content(&mut opened.content, &item.source)?
                    }
                    Ok(_) => false,
                    Err(Error::Io(err)) => return Err(err.into()),
                    Err(_) => false,
                };
                if matches {
                    fs::remove_file(&item.source)?;
                    return Ok(Outcome::Done);
                }
            }
            return Ok(Outcome::Skipped);
        }
        fs::create_dir_all(&dir)?;
        // Dropped (and so deleted) on every early return below.
        let mut temp = tempfile::Builder::new().prefix(TEMP_PREFIX).tempfile_in(&dir)?;
        let reader = self.open_counted(&item.source, counted)?;
        let written = self.encryptor().encrypt(
            Kind::File,
            &file_name(&item.source),
            reader,
            temp.as_file_mut(),
        )?;
        if self.options.delete_source {
            self.verify_sealed(&temp, written, item.size)?;
        }
        persist(temp, &dest, self.options.force)?;
        if self.options.delete_source {
            fs::remove_file(&item.source)?;
        }
        Ok(Outcome::Done)
    }

    fn encrypt_folder(&self, item: &Item, counted: &AtomicU64) -> Result<Outcome> {
        let entries = archive::list(&item.source)?;
        let dir = self.dest_dir(item);
        let dest = dir.join(random_name());
        fs::create_dir_all(&dir)?;
        let mut temp = tempfile::Builder::new().prefix(TEMP_PREFIX).tempfile_in(&dir)?;
        let packer = Packer::new(&entries, |path: &Path| self.open_counted(path, counted));
        let written = self.encryptor().encrypt(
            Kind::Folder,
            &file_name(&item.source),
            packer,
            temp.as_file_mut(),
        )?;
        if self.options.delete_source {
            self.verify_sealed(&temp, written, written)?;
        }
        persist(temp, &dest, false)?;
        if self.options.delete_source {
            // Only what was packed is removed: anything that appeared in the folder in
            // the meantime stays, and so do the folders that still hold something.
            for entry in entries.iter().filter(|entry| !entry.is_dir) {
                fs::remove_file(&entry.path)?;
            }
            for entry in entries.iter().rev().filter(|entry| entry.is_dir) {
                let _ = fs::remove_dir(&entry.path);
            }
            let _ = fs::remove_dir(&item.source);
        }
        Ok(Outcome::Done)
    }

    fn decrypt(&self, item: &Item, counted: &AtomicU64) -> Result<Outcome> {
        let mut opened = self.decryptor().open(self.open_counted(&item.source, counted)?)?;
        let dir = self.dest_dir(item);
        // The recorded name comes from the file itself: use it only as a plain name.
        let name = opened
            .name
            .take()
            .filter(|name| archive::is_safe_name(name))
            .unwrap_or_else(|| fallback_name(&item.source));
        let dest = dir.join(name);

        if opened.kind == Kind::Folder {
            if dest.exists() {
                return Ok(Outcome::Skipped);
            }
            fs::create_dir_all(&dir)?;
            // Removed with everything in it on every early return below.
            let temp = tempfile::Builder::new().prefix(TEMP_PREFIX).tempdir_in(&dir)?;
            archive::unpack(&mut opened.content, temp.path())?;
            let temp = temp.keep();
            if let Err(err) = fs::rename(&temp, &dest) {
                let _ = fs::remove_dir_all(&temp);
                return Err(if dest.exists() { Error::OutputExists } else { err.into() });
            }
        } else {
            if !self.options.force && dest.exists() {
                // As when encrypting: finish the deletion an interrupted run left undone.
                if self.options.delete_source && same_content(&mut opened.content, &dest)? {
                    drop(opened);
                    fs::remove_file(&item.source)?;
                    return Ok(Outcome::Done);
                }
                return Ok(Outcome::Skipped);
            }
            fs::create_dir_all(&dir)?;
            let mut temp = tempfile::Builder::new().prefix(TEMP_PREFIX).tempfile_in(&dir)?;
            while let Some(chunk) = opened.content.next_chunk()? {
                temp.as_file_mut().write_all(chunk)?;
            }
            if self.options.delete_source {
                temp.as_file().sync_all()?;
            }
            persist(temp, &dest, self.options.force)?;
        }
        // The source is still open for reading, which would block deleting it on Windows.
        drop(opened);
        if self.options.delete_source {
            fs::remove_file(&item.source)?;
        }
        Ok(Outcome::Done)
    }

    fn verify(&self, item: &Item, counted: &AtomicU64) -> Result<Outcome> {
        let mut opened = self.decryptor().open(self.open_counted(&item.source, counted)?)?;
        while opened.content.next_chunk()?.is_some() {}
        Ok(Outcome::Done)
    }

    /// Only the header is rewritten. It is at most 210 bytes, written with a single call
    /// at the start of the file, so it sits inside one disk sector and is replaced as a
    /// unit: a power cut leaves either the old header or the new one.
    fn change_password(&self, item: &Item) -> Result<Outcome> {
        if self.progress.cancel.load(Ordering::Relaxed) {
            return Err(io::Error::other("cancelled").into());
        }
        let mut file = OpenOptions::new().read(true).write(true).open(&item.source)?;
        let header = self.encryptor().rewrap(self.decryptor(), &mut file)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header)?;
        file.sync_all()?;
        Ok(Outcome::Done)
    }
}

/// Runs `job` on `items` (as returned by [`scan`] for the same mode and options).
///
/// Fails outright only if the key cannot be derived; per-file problems are collected in
/// the returned [`Summary`].
pub fn run(
    job: &Job,
    items: &[Item],
    params: KdfParams,
    options: &Options,
    progress: &Progress,
) -> Result<Summary> {
    let mode = job.mode();
    let (encryptor, decryptor) = match job {
        Job::Encrypt { password, recovery } => (
            Some(Encryptor::new(password, params)?.with_recovery(*recovery)),
            // Needed to read outputs back before any source is deleted.
            options.delete_source.then(|| Decryptor::new(password)),
        ),
        Job::Decrypt(unlock) | Job::Verify(unlock) => (None, Some(unlock.decryptor())),
        Job::ChangePassword { unlock, new_password } => {
            (Some(Encryptor::new(new_password, params)?), Some(unlock.decryptor()))
        }
    };
    let runner = Runner { mode, options, encryptor, decryptor, progress };

    // Two sources that would produce the same output (same name from different places,
    // sent to one output folder): the first wins, the rest are reported, not skipped.
    let mut taken = HashSet::new();
    let clashes: Vec<bool> = items
        .iter()
        .map(|item| {
            mode == Mode::Encrypt
                && !item.folder
                && runner.encrypt_dest(item).is_some_and(|dest| {
                    !taken.insert(dest.to_string_lossy().to_lowercase())
                })
        })
        .collect();

    let mut pool = rayon::ThreadPoolBuilder::new();
    if let Some(jobs) = options.jobs {
        pool = pool.num_threads(jobs.max(1));
    }
    let pool = pool.build().map_err(io::Error::other)?;
    let results: Vec<Option<Result<Outcome>>> = pool.install(|| {
        items
            .par_iter()
            .zip(&clashes)
            .map(|(item, clash)| {
                if progress.cancel.load(Ordering::Relaxed) {
                    return None;
                }
                let result = if *clash {
                    progress.bytes.fetch_add(item.size, Ordering::Relaxed);
                    Err(Error::OutputExists)
                } else {
                    runner.process(item)
                };
                progress.files.fetch_add(1, Ordering::Relaxed);
                Some(result)
            })
            .collect()
    });

    let cancelled = progress.cancel.load(Ordering::Relaxed);
    let mut summary = Summary { cancelled, ..Summary::default() };
    for (item, result) in items.iter().zip(results) {
        match result {
            Some(Ok(Outcome::Done)) => summary.done += 1,
            Some(Ok(Outcome::Skipped)) => summary.skipped += 1,
            // Once cancelled, errors are files abandoned mid-way, not real failures.
            Some(Err(_)) if cancelled => {}
            Some(Err(err)) => summary.failures.push((item.source.clone(), err)),
            None => {}
        }
    }
    Ok(summary)
}
