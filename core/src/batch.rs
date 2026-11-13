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
use std::sync::Mutex;

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
    /// Files decrypted to a program-type name (`.exe`, `.dll`, `.lnk`...) that the name
    /// of the encrypted file did not show. The real name is stored inside an encrypted
    /// file, so `photo.jpg.topal` from someone else can produce `setup.exe`; callers
    /// should point these out.
    pub program_outputs: Vec<PathBuf>,
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
                // Kept as an item so that the run reports it as a failure with its
                // reason, rather than the folder silently dropping out of the batch.
                Err(Error::UnsupportedName(_)) => scan.items.push(Item {
                    source: path.clone(),
                    size: 0,
                    rel_dir: PathBuf::new(),
                    folder: true,
                    file_count: 0,
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

/// The error every read returns once the batch is cancelled.
#[derive(Debug)]
struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelled")
    }
}

impl std::error::Error for Cancelled {}

fn cancelled() -> io::Error {
    io::Error::other(Cancelled)
}

/// Whether `err` is a file abandoned because of cancelling, not something that went wrong.
fn is_cancelled(err: &Error) -> bool {
    matches!(err, Error::Io(err) if err.get_ref().is_some_and(|inner| inner.is::<Cancelled>()))
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
            return Err(cancelled());
        }
        let n = self.inner.read(buf)?;
        self.counted.fetch_add(n as u64, Ordering::Relaxed);
        self.progress.bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Fails every read once the batch is cancelled. Unpacking a folder asks for its next
/// entry through this, so a folder of very many entries stops between two of them.
struct StopOnCancel<'a, R> {
    inner: R,
    progress: &'a Progress,
}

impl<R: Read> Read for StopOnCancel<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.progress.cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        self.inner.read(buf)
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

/// Flushes a finished output to the disk. Always done before the output gets its final
/// name: a later run treats a file with that name as complete and skips it, and with
/// `delete_source` the source is removed next. Without this, a power cut shortly after
/// could leave the name on a file whose content never reached the disk.
fn sync_output(file: &File) -> io::Result<()> {
    file.sync_all()
}

/// Extensions Windows runs, loads or follows when the file is opened.
const PROGRAM_EXTENSIONS: [&str; 25] = [
    "exe", "dll", "com", "scr", "pif", "cpl", "msi", "msp", "bat", "cmd", "ps1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "url", "reg", "inf", "sys", "ocx",
];

fn is_program(name: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|ext| PROGRAM_EXTENSIONS.iter().any(|known| ext.eq_ignore_ascii_case(known)))
}

/// The alternate data stream in which Windows records that a file came from elsewhere
/// (the internet, an email attachment), which is what makes SmartScreen and Office's
/// Protected View check it before opening.
#[cfg(windows)]
fn zone_stream(path: &Path) -> PathBuf {
    let mut stream = path.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    stream.into()
}

/// The download mark of `source`, if it has one.
fn read_zone(source: &Path) -> Option<Vec<u8>> {
    #[cfg(windows)]
    return fs::read(zone_stream(source)).ok().filter(|zone| zone.len() <= 4096);
    #[cfg(not(windows))]
    {
        let _ = source;
        None
    }
}

/// Gives `dest`, and every file inside it if it is a folder, the download mark of the
/// encrypted file it came out of. Best effort: not every file system has streams.
fn write_zone(dest: &Path, zone: &[u8]) {
    #[cfg(windows)]
    for entry in WalkDir::new(dest).into_iter().flatten() {
        if entry.file_type().is_file() {
            let _ = fs::write(zone_stream(entry.path()), zone);
        }
    }
    #[cfg(not(windows))]
    let _ = (dest, zone);
}

/// Held open inside a temporary folder for as long as it is being filled.
const LOCK_NAME: &str = "lock";
/// The folder inside a temporary folder that becomes the output.
const STAGING_NAME: &str = "content";
/// Without a way to ask whether a file is open elsewhere, leftovers are judged by age.
#[cfg(not(windows))]
const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Whether `name` is exactly what we name temporary files: the prefix and six characters.
fn is_temp_name(name: &str) -> bool {
    name.strip_prefix(TEMP_PREFIX)
        .is_some_and(|rest| rest.len() == 6 && rest.bytes().all(|byte| byte.is_ascii_alphanumeric()))
}

/// Whether some program, possibly another copy of this one, is still writing `file`.
/// Anything unclear counts as in use: a leftover is only removed when it is certain.
fn in_use(file: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Asking for the file with no sharing fails while anyone else has it open.
        OpenOptions::new().read(true).share_mode(0).open(file).is_err()
    }
    #[cfg(not(windows))]
    {
        let age = fs::metadata(file).and_then(|meta| meta.modified()).ok().and_then(|at| at.elapsed().ok());
        !age.is_some_and(|age| age > STALE_AFTER)
    }
}

/// Removes what an earlier run left in `dir` when it was killed or the power went out:
/// half-written outputs under temporary names. When decrypting those hold plaintext,
/// so they should not stay behind. Temporary files of a run that is still going are
/// recognised by being open, and left alone. Best effort: errors are ignored.
fn remove_stale_temps(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if !is_temp_name(&entry.file_name().to_string_lossy()) {
            continue;
        }
        let path = entry.path();
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_file() {
            if !in_use(&path) {
                let _ = fs::remove_file(&path);
            }
        } else if kind.is_dir() {
            // A folder being filled keeps its lock file open. One without a lock file
            // is either a leftover or was created this very moment, so give it a minute.
            let lock = path.join(LOCK_NAME);
            let stale = if lock.exists() {
                !in_use(&lock)
            } else {
                fs::metadata(&path)
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|at| at.elapsed().ok())
                    .is_some_and(|age| age > std::time::Duration::from_secs(60))
            };
            if stale {
                let _ = fs::remove_dir_all(&path);
            }
        }
    }
}

/// Where the header of `source` is kept while its password is being changed.
fn header_backup(source: &Path) -> PathBuf {
    let mut name = source.as_os_str().to_owned();
    name.push(".header-backup");
    name.into()
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
    /// Files this run has decrypted to, so that `force` never lets one source overwrite
    /// what another source of the same run has just produced.
    outputs: Mutex<HashSet<String>>,
    /// See [`Summary::program_outputs`].
    program_outputs: Mutex<Vec<PathBuf>>,
}

impl Runner<'_> {
    /// Reserves `dest` for the calling item. `false` if another item of this run took it.
    fn claim(&self, dest: &Path) -> bool {
        // Compared without case, as Windows compares file names.
        let key = dest.to_string_lossy().to_lowercase();
        self.outputs.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(key)
    }

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

    /// Reads decrypted content to its authenticated end. A folder is also walked entry
    /// by entry, so that passing means it can really be unpacked. Returns the byte count.
    fn read_through<R: Read>(kind: Kind, content: &mut DecryptReader<R>) -> Result<u64> {
        let mut total = 0u64;
        if kind == Kind::Folder {
            struct Counted<'a, R>(&'a mut R, &'a mut u64);
            impl<R: Read> Read for Counted<'_, R> {
                fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                    let n = self.0.read(buf)?;
                    *self.1 += n as u64;
                    Ok(n)
                }
            }
            archive::check(Counted(content, &mut total))?;
        } else {
            while let Some(chunk) = content.next_chunk()? {
                total += chunk.len() as u64;
            }
        }
        Ok(total)
    }

    /// Proves that a finished, synced encrypted file decrypts back to `written` bytes
    /// of `expected`, and for a folder that every entry in it can be unpacked.
    fn verify_sealed(&self, temp: &tempfile::NamedTempFile, written: u64, expected: u64) -> Result<()> {
        let mut opened = self.decryptor().open(temp.reopen()?)?;
        let verified = Self::read_through(opened.kind, &mut opened.content)?;
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
        sync_output(temp.as_file())?;
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
        sync_output(temp.as_file())?;
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
        let stored = opened.name.take().filter(|name| archive::is_safe_name(name));
        // What the encrypted file's own name leads the user to expect.
        let shown = fallback_name(&item.source);
        let expected = stored.as_ref().is_none_or(|name| name.to_lowercase() == shown.to_lowercase());
        let name = stored.unwrap_or(shown);
        let dest = dir.join(&name);
        let zone = read_zone(&item.source);
        // `force` is consent to replace the output the user can see coming. A name
        // that only the inside of the file knows could be aimed at any other file in
        // the folder, so such an output is never written over an existing file.
        let force = self.options.force && expected;

        if opened.kind == Kind::Folder {
            if dest.exists() {
                return Ok(Outcome::Skipped);
            }
            fs::create_dir_all(&dir)?;
            // Removed with everything in it on every return below. The lock file stays
            // open until then, which tells another run that this folder is not a leftover.
            let temp = tempfile::Builder::new().prefix(TEMP_PREFIX).tempdir_in(&dir)?;
            let _lock = File::create(temp.path().join(LOCK_NAME))?;
            let staging = temp.path().join(STAGING_NAME);
            fs::create_dir(&staging)?;
            // Synced for the same reason as `sync_output`, file by file.
            // The whole archive may already be in memory, so cancelling is checked here
            // and not only where the encrypted file is read.
            let content = StopOnCancel { inner: &mut opened.content, progress: self.progress };
            archive::unpack_synced(content, &staging)?;
            // Take the name first, in the one way that cannot replace anything: creating
            // a folder fails if a file or folder of that name appeared in the meantime.
            // Renaming alone would silently replace a file.
            match fs::create_dir(&dest) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => return Err(Error::OutputExists),
                Err(err) => return Err(err.into()),
            }
            if fs::rename(&staging, &dest).is_err() {
                // Systems that cannot rename onto an empty folder: give the name back
                // and rename the ordinary way.
                fs::remove_dir(&dest)?;
                fs::rename(&staging, &dest)?;
            }
        } else {
            if !force && dest.exists() {
                // As when encrypting: finish the deletion an interrupted run left undone.
                if self.options.delete_source && same_content(&mut opened.content, &dest)? {
                    drop(opened);
                    fs::remove_file(&item.source)?;
                    return Ok(Outcome::Done);
                }
                return Ok(Outcome::Skipped);
            }
            // Two encrypted files can hold the same original name. `force` is consent
            // to replace what was there before this run, not what this run wrote: the
            // second one is reported and its source is kept.
            if !self.claim(&dest) {
                return Err(Error::OutputExists);
            }
            fs::create_dir_all(&dir)?;
            let mut temp = tempfile::Builder::new().prefix(TEMP_PREFIX).tempfile_in(&dir)?;
            while let Some(chunk) = opened.content.next_chunk()? {
                temp.as_file_mut().write_all(chunk)?;
            }
            sync_output(temp.as_file())?;
            persist(temp, &dest, force)?;
            if !expected && is_program(&name) {
                self.program_outputs
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(dest.clone());
            }
        }
        if let Some(zone) = &zone {
            write_zone(&dest, zone);
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
        Self::read_through(opened.kind, &mut opened.content)?;
        Ok(Outcome::Done)
    }

    /// Only the header is rewritten, in place. The old header is first saved beside the
    /// file and synced, and removed once the new one is on the disk, so if the write is
    /// ever cut short (power, a network drive going away) the next password change finds
    /// the saved header and repairs the file from it. The saved bytes hold nothing that
    /// the file itself does not show.
    fn change_password(&self, item: &Item) -> Result<Outcome> {
        if self.progress.cancel.load(Ordering::Relaxed) {
            return Err(cancelled().into());
        }
        let backup = header_backup(&item.source);
        let mut file = OpenOptions::new().read(true).write(true).open(&item.source)?;
        let mut current = vec![0u8; crate::MAX_HEADER_LEN];
        let len = crate::read_full(&mut file, &mut current)?;
        current.truncate(len);

        let header = match self.encryptor().rewrap(self.decryptor(), &current[..]) {
            Ok(header) => {
                let mut saved = File::create(&backup)?;
                saved.write_all(&current)?;
                saved.sync_all()?;
                header
            }
            // The header does not open. If an earlier change was interrupted, the one
            // saved then may; it is kept as it is until this change has succeeded.
            Err(err) => match fs::read(&backup) {
                Ok(saved) => self.header_from_backup(&saved, &mut file).map_err(|_| err)?,
                Err(_) => return Err(err),
            },
        };
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header)?;
        file.sync_all()?;
        let _ = fs::remove_file(&backup);
        Ok(Outcome::Done)
    }

    /// The new header for `file` made from a saved one, but only if the saved header
    /// really belongs to this file: its key must decrypt the file's first chunk. A
    /// header from any other file would otherwise replace the only copy of the key.
    fn header_from_backup(&self, saved: &[u8], file: &mut File) -> Result<Vec<u8>> {
        let header = self.encryptor().rewrap(self.decryptor(), saved)?;
        if saved.len() < header.len() {
            return Err(Error::Corrupted);
        }
        file.seek(SeekFrom::Start(header.len() as u64))?;
        let whole = io::Cursor::new(&saved[..header.len()]).chain(&mut *file);
        self.decryptor().open(whole)?.content.next_chunk()?;
        Ok(header)
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
    let runner =
        Runner {
            mode,
            options,
            encryptor,
            decryptor,
            progress,
            outputs: Mutex::new(HashSet::new()),
            program_outputs: Mutex::new(Vec::new()),
        };

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

    if matches!(mode, Mode::Encrypt | Mode::Decrypt) {
        let dirs: HashSet<PathBuf> = items.iter().map(|item| runner.dest_dir(item)).collect();
        for dir in &dirs {
            remove_stale_temps(dir);
        }
    }

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
    let program_outputs =
        runner.program_outputs.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut summary = Summary { cancelled, program_outputs, ..Summary::default() };
    for (item, result) in items.iter().zip(results) {
        match result {
            Some(Ok(Outcome::Done)) => summary.done += 1,
            Some(Ok(Outcome::Skipped)) => summary.skipped += 1,
            // A file abandoned mid-way by cancelling is not a failure. Anything else
            // that went wrong is still reported, cancelled or not.
            Some(Err(err)) if is_cancelled(&err) => {}
            Some(Err(err)) => summary.failures.push((item.source.clone(), err)),
            None => {}
        }
    }
    Ok(summary)
}
