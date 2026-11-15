//! What the Topal Encryption Android app calls: `topal-core` driven through streams.
//!
//! Android hands an app `content://` documents, not paths, so the path-based batch engine
//! of the core does not fit. Here every operation takes one input and writes to whatever
//! the caller opens for it, counts the bytes it consumed, and can be cancelled. All
//! cryptography, the archive format and the name checks stay in `topal-core`.
//!
//! The functions in this file are plain Rust and are tested on any host. The `jni` module
//! is the thin layer that exposes them to Kotlin.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use topal_core::archive::{self, Sink};
use topal_core::recovery::RecoveryKey;
use topal_core::{passphrase, Decryptor, Encryptor, Error, KdfParams, Kind, Result};
use zeroize::Zeroizing;

#[cfg(target_os = "android")]
mod jni;

/// Shared by every item of one batch: a byte counter to poll, and a cancel switch.
#[derive(Debug, Default)]
pub struct Control {
    /// Source bytes consumed so far. An item that ends early counts in full.
    pub bytes: AtomicU64,
    /// Set to `true` to stop: the item in flight fails with the code `cancelled`.
    pub cancel: AtomicBool,
}

/// Accounts for one item. When it is dropped, whatever the item did not read (skipped,
/// failed, or simply not needed) is added to the batch counter, so that a progress bar
/// still reaches the end.
pub struct Meter<'a> {
    control: &'a Control,
    size: u64,
    counted: AtomicU64,
}

impl<'a> Meter<'a> {
    /// `size` is the input's size in bytes, or 0 when it is not known.
    pub fn new(control: &'a Control, size: u64) -> Self {
        Self { control, size, counted: AtomicU64::new(0) }
    }
}

impl Drop for Meter<'_> {
    fn drop(&mut self) {
        let rest = self.size.saturating_sub(self.counted.load(Ordering::Relaxed));
        self.control.bytes.fetch_add(rest, Ordering::Relaxed);
    }
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

/// A short, stable name for `err`, which the app maps to a translated message. They are
/// the names the desktop app uses.
pub fn code(err: &Error) -> &'static str {
    match err {
        Error::Io(err) if err.get_ref().is_some_and(|inner| inner.is::<Cancelled>()) => "cancelled",
        Error::Io(_) => "io",
        Error::NotTopal => "not_topal",
        Error::UnsupportedVersion(_) => "unsupported_version",
        Error::InvalidKdfParams => "invalid_kdf_params",
        Error::WrongPassword => "wrong_password",
        Error::WrongRecoveryKey => "wrong_recovery_key",
        Error::NoRecoverySlot => "no_recovery_slot",
        Error::InvalidRecoveryKey => "invalid_recovery_key",
        Error::Corrupted => "corrupted",
        Error::VerificationFailed => "verification_failed",
        Error::UnsafePath => "unsafe_path",
        Error::OutputExists => "output_exists",
        Error::UnsupportedName(_) => "unsupported_name",
    }
}

/// Counts what is read from the source, and fails once the batch is cancelled.
struct Tracked<'a, R> {
    inner: R,
    meter: &'a Meter<'a>,
}

impl<R: Read> Read for Tracked<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.meter.control.cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        let n = self.inner.read(buf)?;
        self.meter.counted.fetch_add(n as u64, Ordering::Relaxed);
        self.meter.control.bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Fails every read once the batch is cancelled. A folder is unpacked through this: up to
/// a whole chunk of it is already decrypted in memory, so cancelling has to be noticed
/// here and not only where the encrypted file is read.
struct StopOnCancel<'a, R> {
    inner: R,
    control: &'a Control,
}

impl<R: Read> Read for StopOnCancel<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.control.cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        self.inner.read(buf)
    }
}

/// Derives the key for a batch of files to encrypt. This is the slow step (256 MiB of
/// memory, about a second): do it once and reuse the result for every file.
pub fn encryptor(password: &str) -> Result<Encryptor> {
    Encryptor::new(password, KdfParams::default())
}

/// What opens a batch of encrypted files: the password or, when `recovery_key` is given,
/// the recovery key in its text form. Keys are derived on first use and cached.
pub fn decryptor(password: &str, recovery_key: Option<&str>) -> Result<Decryptor> {
    match recovery_key {
        Some(text) => Ok(Decryptor::with_recovery_key(RecoveryKey::parse(text)?)),
        None => Ok(Decryptor::new(password)),
    }
}

/// Whether `text` is a well-formed recovery key (prefix, length and checksum).
pub fn is_recovery_key(text: &str) -> bool {
    RecoveryKey::parse(text).is_ok()
}

/// A fresh six-word passphrase.
pub fn generate_passphrase() -> Zeroizing<String> {
    passphrase::generate(passphrase::DEFAULT_WORDS)
}

/// Encrypts `input` into `output` as one file, recording `name` inside it. Returns the
/// number of plaintext bytes. On error the caller discards what was written.
pub fn encrypt(
    encryptor: &Encryptor,
    name: &str,
    input: impl Read,
    output: impl Write,
    meter: &Meter,
) -> Result<u64> {
    encryptor.encrypt(Kind::File, name, Tracked { inner: input, meter }, output)
}

/// Where decrypted content goes. The caller learns what the encrypted file holds before
/// anything is written, and decides where to put it, or to leave it out.
///
/// The names passed to `begin_file` and `begin_folder` come out of the encrypted file and
/// are passed on only if `archive::is_safe_name` accepts them; otherwise, and for files
/// that record no name, they are `None` and the caller falls back to the name of the
/// encrypted file. The [`Sink`] half receives the entries of a folder.
pub trait Output: Sink {
    /// The encrypted file holds one file. Returns what to write it to, or `None` to
    /// skip it (its output already exists).
    fn begin_file(&mut self, name: Option<&str>) -> io::Result<Option<Self::File>>;

    /// The encrypted file holds a whole folder. Returns `false` to skip it.
    fn begin_folder(&mut self, name: Option<&str>) -> io::Result<bool>;
}

/// Decrypts `input` into `output`. Returns `false` if the output chose to skip it.
///
/// Every byte handed to the output has been authenticated, but damage further on is only
/// found when it is reached: on error, the caller discards everything the output created.
pub fn decrypt(
    decryptor: &Decryptor,
    input: impl Read,
    output: &mut impl Output,
    meter: &Meter,
) -> Result<bool> {
    let mut opened = decryptor.open(Tracked { inner: input, meter })?;
    let name = opened.name.take().filter(|name| archive::is_safe_name(name));
    match opened.kind {
        Kind::File => {
            let Some(mut file) = output.begin_file(name.as_deref())? else { return Ok(false) };
            while let Some(chunk) = opened.content.next_chunk()? {
                file.write_all(chunk)?;
            }
            output.finish(file)?;
        }
        Kind::Folder => {
            if !output.begin_folder(name.as_deref())? {
                return Ok(false);
            }
            let content = StopOnCancel { inner: &mut opened.content, control: meter.control };
            archive::unpack_to(content, output)?;
        }
    }
    Ok(true)
}

/// Checks that `input` opens and is intact to its authenticated end, writing nothing. A
/// folder is also walked entry by entry, so passing means it can really be unpacked.
pub fn verify(decryptor: &Decryptor, input: impl Read, meter: &Meter) -> Result<()> {
    let mut opened = decryptor.open(Tracked { inner: input, meter })?;
    match opened.kind {
        Kind::File => while opened.content.next_chunk()?.is_some() {},
        Kind::Folder => {
            archive::check(StopOnCancel { inner: &mut opened.content, control: meter.control })?
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Cursor;
    use std::path::Path;

    use topal_core::archive::Packer;
    use topal_core::CHUNK_SIZE;

    use super::*;

    const FAST: KdfParams = KdfParams { memory_kib: 1024, passes: 1, lanes: 1 };
    const CHUNK: usize = CHUNK_SIZE as usize;

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8).collect()
    }

    fn seal(password: &str, name: &str, data: &[u8]) -> Vec<u8> {
        let control = Control::default();
        let mut out = Vec::new();
        let encryptor = Encryptor::new(password, FAST).unwrap();
        encrypt(&encryptor, name, data, &mut out, &Meter::new(&control, data.len() as u64)).unwrap();
        assert_eq!(control.bytes.load(Ordering::Relaxed), data.len() as u64);
        out
    }

    /// Remembers everything it is asked to create, like the app's output does.
    #[derive(Default)]
    struct Recorded {
        /// What `begin_file` or `begin_folder` was told, with `true` for a folder.
        begun: Option<(bool, Option<String>)>,
        skip: bool,
        dirs: Vec<String>,
        /// Only files that were reported as finished.
        files: Vec<(String, Vec<u8>)>,
        created: usize,
    }

    struct Buffer(String, Vec<u8>);

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.1.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Sink for Recorded {
        type File = Buffer;

        fn dir(&mut self, rel: &str) -> io::Result<()> {
            self.dirs.push(rel.to_owned());
            Ok(())
        }

        fn file(&mut self, rel: &str) -> io::Result<Buffer> {
            self.created += 1;
            Ok(Buffer(rel.to_owned(), Vec::new()))
        }

        fn finish(&mut self, file: Buffer) -> io::Result<()> {
            self.files.push((file.0, file.1));
            Ok(())
        }
    }

    impl Output for Recorded {
        fn begin_file(&mut self, name: Option<&str>) -> io::Result<Option<Buffer>> {
            self.begun = Some((false, name.map(str::to_owned)));
            if self.skip {
                return Ok(None);
            }
            self.created += 1;
            Ok(Some(Buffer(String::new(), Vec::new())))
        }

        fn begin_folder(&mut self, name: Option<&str>) -> io::Result<bool> {
            self.begun = Some((true, name.map(str::to_owned)));
            Ok(!self.skip)
        }
    }

    fn open(password: &str, sealed: &[u8]) -> (Result<bool>, Recorded, u64) {
        let control = Control::default();
        let mut output = Recorded::default();
        let result = {
            let meter = Meter::new(&control, sealed.len() as u64);
            decrypt(&Decryptor::new(password), sealed, &mut output, &meter)
        };
        (result, output, control.bytes.load(Ordering::Relaxed))
    }

    #[test]
    fn a_file_round_trips_with_its_name_and_is_counted() {
        for len in [0, 1, CHUNK - 3, CHUNK, 2 * CHUNK + 77] {
            let data = sample(len);
            let sealed = seal("pw", "تقرير 2025.pdf", &data);
            let (result, output, bytes) = open("pw", &sealed);
            assert!(result.unwrap(), "len {len}");
            assert_eq!(output.begun, Some((false, Some("تقرير 2025.pdf".to_owned()))));
            assert_eq!(output.files, [(String::new(), data)], "len {len}");
            assert_eq!(bytes, sealed.len() as u64, "len {len}");

            let control = Control::default();
            verify(&Decryptor::new("pw"), &sealed[..], &Meter::new(&control, sealed.len() as u64)).unwrap();
            assert_eq!(control.bytes.load(Ordering::Relaxed), sealed.len() as u64);
        }
    }

    #[test]
    fn a_name_that_is_not_safe_is_not_passed_on() {
        // Harmless stand-ins for names a crafted file could carry.
        for name in ["", "../up.txt", "a/b.txt", "nul", "trailing."] {
            let (result, output, _) = open("pw", &seal("pw", name, b"x"));
            assert!(result.unwrap());
            assert_eq!(output.begun, Some((false, None)), "{name:?}");
        }
    }

    #[test]
    fn a_skipped_file_writes_nothing_and_still_counts_in_full() {
        let sealed = seal("pw", "a.txt", &sample(CHUNK + 5));
        let control = Control::default();
        let mut output = Recorded { skip: true, ..Recorded::default() };
        let result = {
            let meter = Meter::new(&control, sealed.len() as u64);
            decrypt(&Decryptor::new("pw"), &sealed[..], &mut output, &meter)
        };
        assert!(!result.unwrap());
        assert_eq!((output.created, output.files.len()), (0, 0));
        assert_eq!(control.bytes.load(Ordering::Relaxed), sealed.len() as u64);
    }

    #[test]
    fn failures_have_their_codes_and_finish_nothing() {
        let sealed = seal("pw", "a.bin", &sample(2 * CHUNK + 100));

        let (result, output, bytes) = open("wrong", &sealed);
        assert_eq!(code(&result.unwrap_err()), "wrong_password");
        assert_eq!((output.begun, output.created), (None, 0), "nothing is asked for before the key fits");
        assert_eq!(bytes, sealed.len() as u64);

        let (result, output, _) = open("pw", &sealed[..sealed.len() - 1]);
        assert_eq!(code(&result.unwrap_err()), "corrupted");
        assert!(output.files.is_empty(), "a cut file is never reported as finished");

        let mut flipped = sealed.clone();
        flipped[sealed.len() / 2] ^= 1;
        let (result, output, _) = open("pw", &flipped);
        assert_eq!(code(&result.unwrap_err()), "corrupted");
        assert!(output.files.is_empty());

        assert_eq!(code(&open("pw", b"just some text").0.unwrap_err()), "not_topal");

        let control = Control::default();
        let err = verify(&Decryptor::new("pw"), &flipped[..], &Meter::new(&control, 0)).unwrap_err();
        assert_eq!(code(&err), "corrupted");
        let err = verify(&Decryptor::new("no"), &sealed[..], &Meter::new(&control, 0)).unwrap_err();
        assert_eq!(code(&err), "wrong_password");
    }

    /// Reads normally, and flips the cancel switch after a number of bytes.
    struct CancelAfter<'a> {
        inner: Cursor<&'a [u8]>,
        control: &'a Control,
        after: u64,
    }

    impl Read for CancelAfter<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.inner.position() >= self.after {
                self.control.cancel.store(true, Ordering::Relaxed);
            }
            self.inner.read(buf)
        }
    }

    #[test]
    fn cancelling_stops_every_operation_part_way() {
        let data = sample(3 * CHUNK);
        let sealed = seal("pw", "a.bin", &data);
        let half = |control| CancelAfter { inner: Cursor::new(&sealed[..]), control, after: CHUNK as u64 };

        let control = Control::default();
        let mut output = Recorded::default();
        let err = decrypt(&Decryptor::new("pw"), half(&control), &mut output, &Meter::new(&control, 0))
            .unwrap_err();
        assert_eq!(code(&err), "cancelled");
        assert!(output.files.is_empty());

        let control = Control::default();
        let err = verify(&Decryptor::new("pw"), half(&control), &Meter::new(&control, 0)).unwrap_err();
        assert_eq!(code(&err), "cancelled");

        let control = Control::default();
        let input = CancelAfter { inner: Cursor::new(&data[..]), control: &control, after: CHUNK as u64 };
        let encryptor = Encryptor::new("pw", FAST).unwrap();
        let err = encrypt(&encryptor, "a.bin", input, io::sink(), &Meter::new(&control, 0)).unwrap_err();
        assert_eq!(code(&err), "cancelled");

        // Cancelled before it began: nothing is read at all.
        let control = Control::default();
        control.cancel.store(true, Ordering::Relaxed);
        let err = verify(&Decryptor::new("pw"), &sealed[..], &Meter::new(&control, 9)).unwrap_err();
        assert_eq!(code(&err), "cancelled");
    }

    /// A folder container as the desktop app writes it with "Hide file names".
    fn seal_folder(password: &str, name: &str, folder: &Path) -> Vec<u8> {
        let entries = archive::list(folder).unwrap();
        let packer = Packer::new(&entries, |path: &Path| File::open(path));
        let mut out = Vec::new();
        Encryptor::new(password, FAST).unwrap().encrypt(Kind::Folder, name, packer, &mut out).unwrap();
        out
    }

    #[test]
    fn a_folder_container_is_handed_over_entry_by_entry() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir_all(source.path().join("a/فارغ")).unwrap();
        fs::write(source.path().join("a/one.txt"), b"one").unwrap();
        fs::write(source.path().join("صورة.jpg"), sample(CHUNK + 9)).unwrap();
        let sealed = seal_folder("pw", "صور العطلة", source.path());

        let (result, output, bytes) = open("pw", &sealed);
        assert!(result.unwrap());
        assert_eq!(output.begun, Some((true, Some("صور العطلة".to_owned()))));
        assert_eq!(output.dirs, ["a", "a/فارغ"]);
        assert_eq!(
            output.files,
            [("a/one.txt".to_owned(), b"one".to_vec()), ("صورة.jpg".to_owned(), sample(CHUNK + 9))]
        );
        assert_eq!(bytes, sealed.len() as u64);

        let control = Control::default();
        verify(&Decryptor::new("pw"), &sealed[..], &Meter::new(&control, 0)).unwrap();

        // Skipped as a whole, and cut short.
        let control = Control::default();
        let mut skipping = Recorded { skip: true, ..Recorded::default() };
        assert!(!decrypt(&Decryptor::new("pw"), &sealed[..], &mut skipping, &Meter::new(&control, 0)).unwrap());
        assert_eq!((skipping.created, skipping.dirs.len()), (0, 0));
        let (result, _, _) = open("pw", &sealed[..sealed.len() - 20]);
        assert_eq!(code(&result.unwrap_err()), "corrupted");
    }

    #[test]
    fn a_folder_already_in_memory_still_stops_when_cancelled() {
        // Small enough to be decrypted in one chunk before the first entry is unpacked.
        let source = tempfile::tempdir().unwrap();
        for index in 0..50 {
            fs::write(source.path().join(format!("{index}.txt")), b"x").unwrap();
        }
        let sealed = seal_folder("pw", "many", source.path());

        struct CancelOnFirstFile<'a>(Recorded, &'a Control);
        impl Sink for CancelOnFirstFile<'_> {
            type File = Buffer;
            fn dir(&mut self, rel: &str) -> io::Result<()> {
                self.0.dir(rel)
            }
            fn file(&mut self, rel: &str) -> io::Result<Buffer> {
                self.1.cancel.store(true, Ordering::Relaxed);
                self.0.file(rel)
            }
        }
        impl Output for CancelOnFirstFile<'_> {
            fn begin_file(&mut self, name: Option<&str>) -> io::Result<Option<Buffer>> {
                self.0.begin_file(name)
            }
            fn begin_folder(&mut self, name: Option<&str>) -> io::Result<bool> {
                self.0.begin_folder(name)
            }
        }

        let control = Control::default();
        let mut output = CancelOnFirstFile(Recorded::default(), &control);
        let err = decrypt(&Decryptor::new("pw"), &sealed[..], &mut output, &Meter::new(&control, 0))
            .unwrap_err();
        assert_eq!(code(&err), "cancelled");
        assert_eq!(output.0.created, 1, "stopped at the first entry");
    }

    #[test]
    fn the_recovery_key_opens_files_and_typos_are_refused() {
        let key = RecoveryKey::generate();
        let text = key.to_text();
        let mut sealed = Vec::new();
        Encryptor::new("pw", FAST)
            .unwrap()
            .with_recovery(Some(key.public()))
            .encrypt(Kind::File, "a.txt", &b"secret"[..], &mut sealed)
            .unwrap();

        assert!(is_recovery_key(&text));
        assert!(is_recovery_key(&text.to_lowercase().replace('-', " ")));
        assert!(!is_recovery_key("TOPAL-KEY-AAAAA"));
        assert_eq!(code(&decryptor("", Some("not a key")).err().unwrap()), "invalid_recovery_key");

        let control = Control::default();
        let mut output = Recorded::default();
        let by_key = decryptor("ignored", Some(&text)).unwrap();
        assert!(decrypt(&by_key, &sealed[..], &mut output, &Meter::new(&control, 0)).unwrap());
        assert_eq!(output.files[0].1, b"secret");

        let other = decryptor("", Some(&RecoveryKey::generate().to_text())).unwrap();
        let err = verify(&other, &sealed[..], &Meter::new(&control, 0)).unwrap_err();
        assert_eq!(code(&err), "wrong_recovery_key");
        let err = verify(&other, &seal("pw", "a", b"x")[..], &Meter::new(&control, 0)).unwrap_err();
        assert_eq!(code(&err), "no_recovery_slot");
    }

    #[test]
    fn version_1_files_open_and_carry_no_name() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/tests/fixtures");
        let sealed = fs::read(fixtures.join("v1-sample.txt.topal")).unwrap();
        let (result, output, _) = open("topal-test", &sealed);
        assert!(result.unwrap());
        assert_eq!(output.begun, Some((false, None)));
        assert_eq!(output.files[0].1, fs::read(fixtures.join("v1-sample.txt")).unwrap());
    }

    #[test]
    fn passphrases_have_six_words() {
        let phrase = generate_passphrase();
        assert_eq!(phrase.split('-').count(), 6);
        assert_ne!(*phrase, *generate_passphrase());
    }
}
