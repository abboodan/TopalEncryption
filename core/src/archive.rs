//! Packing a folder into one stream, so that names and structure are encrypted too.
//!
//! The stream is a sequence of entries followed by an end marker (integers little-endian):
//!
//! | size | field                                                      |
//! |------|------------------------------------------------------------|
//! | 1    | kind: `1` file, `2` folder, `0` end of archive             |
//! | 2    | path length in bytes                                       |
//! | ...  | path relative to the packed folder, UTF-8, `/` separated   |
//! | 8    | file size (files only)                                     |
//! | ...  | file content (files only)                                  |
//!
//! Nothing is compressed and nothing is written to disk unencrypted: [`Packer`] is a
//! reader that the cipher pulls from, and [`unpack`] writes straight from the decrypted
//! stream.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::{Error, Result};

const KIND_END: u8 = 0;
const KIND_FILE: u8 = 1;
const KIND_DIR: u8 = 2;

const COPY_BUFFER: usize = 256 * 1024;

/// Folders nested deeper than this are not packed and not unpacked. Real folders stay
/// far below it; a crafted archive with thousands of levels in one path costs minutes
/// of work to create and to remove again.
pub const MAX_DEPTH: usize = 128;

/// One file or folder inside a folder that is being packed.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Path relative to the packed folder, `/` separated.
    pub rel: String,
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
}

/// Lists everything inside `folder`, parents before their children. Fails on the first
/// unreadable item: a folder is packed whole or not at all. Links are not followed and
/// not packed.
///
/// A name that [`unpack`] would refuse, or could not tell apart from another one, is an
/// error here: what gets packed must be certain to come back out.
pub fn list(folder: &Path) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    for entry in WalkDir::new(folder).min_depth(1).sort_by_file_name() {
        let entry = entry.map_err(io::Error::from)?;
        let kind = entry.file_type();
        if !kind.is_file() && !kind.is_dir() {
            continue;
        }
        let unsupported = || Error::UnsupportedName(entry.path().display().to_string());
        let rel = entry
            .path()
            .strip_prefix(folder)
            .expect("walked paths start with the folder")
            .components()
            // A name that is not valid Unicode cannot be written down faithfully.
            .map(|part| part.as_os_str().to_str().filter(|name| is_safe_name(name)))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(unsupported)?
            .join("/");
        // Two names differing only in case would collide when unpacked on Windows.
        if !seen.insert(rel.to_lowercase()) || entry.depth() > MAX_DEPTH {
            return Err(unsupported());
        }
        if u16::try_from(rel.len()).is_err() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a path is too long").into());
        }
        let size = if kind.is_file() { entry.metadata().map_err(io::Error::from)?.len() } else { 0 };
        entries.push(Entry { rel, path: entry.into_path(), size, is_dir: kind.is_dir() });
    }
    Ok(entries)
}

/// Total bytes [`Packer`] will take from the files of `entries`.
pub fn content_bytes(entries: &[Entry]) -> u64 {
    entries.iter().map(|entry| entry.size).sum()
}

/// Reads as the archive of `entries`, opening each file through `open` when its turn
/// comes. A file whose size changed since it was listed is an error.
pub struct Packer<'a, R, F> {
    entries: std::slice::Iter<'a, Entry>,
    open: F,
    /// Entry header (or end marker) bytes not handed out yet.
    pending: Vec<u8>,
    pending_pos: usize,
    file: Option<(R, u64)>,
    ended: bool,
}

impl<'a, R: Read, F: FnMut(&Path) -> io::Result<R>> Packer<'a, R, F> {
    pub fn new(entries: &'a [Entry], open: F) -> Self {
        Self {
            entries: entries.iter(),
            open,
            pending: Vec::new(),
            pending_pos: 0,
            file: None,
            ended: false,
        }
    }
}

fn changed() -> io::Error {
    Error::VerificationFailed.into()
}

impl<R: Read, F: FnMut(&Path) -> io::Result<R>> Read for Packer<'_, R, F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pending_pos < self.pending.len() {
                let n = buf.len().min(self.pending.len() - self.pending_pos);
                buf[..n].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
                self.pending_pos += n;
                return Ok(n);
            }
            if let Some((file, remaining)) = &mut self.file {
                if *remaining == 0 {
                    // The listed size is used up: the file must end here too.
                    if file.read(&mut buf[..1])? != 0 {
                        return Err(changed());
                    }
                    self.file = None;
                    continue;
                }
                let want = buf.len().min(usize::try_from(*remaining).unwrap_or(usize::MAX));
                let n = file.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(changed());
                }
                *remaining -= n as u64;
                return Ok(n);
            }
            self.pending.clear();
            self.pending_pos = 0;
            match self.entries.next() {
                Some(entry) => {
                    self.pending.push(if entry.is_dir { KIND_DIR } else { KIND_FILE });
                    self.pending.extend_from_slice(&(entry.rel.len() as u16).to_le_bytes());
                    self.pending.extend_from_slice(entry.rel.as_bytes());
                    if !entry.is_dir {
                        self.pending.extend_from_slice(&entry.size.to_le_bytes());
                        self.file = Some(((self.open)(&entry.path)?, entry.size));
                    }
                }
                None if !self.ended => {
                    self.pending.push(KIND_END);
                    self.ended = true;
                }
                None => return Ok(0),
            }
        }
    }
}

/// Whether `name` is safe to create as a single file or folder: one plain path component
/// that cannot escape its folder or reach a device on Windows.
///
/// Names come out of encrypted files, and a file can be crafted by anyone who knows a
/// password for it, so they are checked before anything is written.
pub fn is_safe_name(name: &str) -> bool {
    const RESERVED: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    // Windows limits a name to 255 UTF-16 units, not bytes: a name in Arabic or Chinese
    // takes two or three bytes per character and is still legal.
    if name.is_empty() || name == "." || name == ".." || name.encode_utf16().count() > 255 {
        return false;
    }
    if name.chars().any(|c| c.is_control() || r#"/\:*?"<>|"#.contains(c)) {
        return false;
    }
    // Characters that override the direction text is drawn in. They make a name read
    // differently from what it is: `invoice<U+202E>fdp.exe` is shown as `invoiceexe.pdf`.
    // Arabic and Hebrew names do not need them; the marks they do use are left alone.
    if name.chars().any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')) {
        return false;
    }
    if name.ends_with(' ') || name.ends_with('.') {
        return false;
    }
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    let numbered = |prefix: &str| {
        // Windows also reserves the superscript digits: COM¹, LPT².
        stem.strip_prefix(prefix).is_some_and(|rest| {
            let mut chars = rest.chars();
            matches!((chars.next(), chars.next()), (Some(c), None) if c.is_ascii_digit() || "¹²³".contains(c))
        })
    };
    !(RESERVED.contains(&stem.as_str()) || numbered("COM") || numbered("LPT"))
}

fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    let mut path = root.to_owned();
    for (depth, part) in rel.split('/').enumerate() {
        if depth >= MAX_DEPTH || !is_safe_name(part) {
            return Err(Error::UnsafePath);
        }
        path.push(part);
    }
    Ok(path)
}

/// A short read inside an entry means the archive is cut off.
fn exact(reader: &mut impl Read, buf: &mut [u8]) -> Result<()> {
    reader.read_exact(buf).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            Error::Corrupted
        } else {
            err.into()
        }
    })
}

/// Reads the start of the next entry: whether it is a folder, and its path. For a file,
/// the size and content follow in `reader`. `None` is the end of the archive, reported
/// only once the stream is known to end there too.
fn next_entry(reader: &mut impl Read) -> Result<Option<(bool, String)>> {
    let mut kind = [0u8; 1];
    exact(reader, &mut kind)?;
    if kind[0] == KIND_END {
        // Anything after the end marker was not written by us.
        return match reader.read(&mut kind)? {
            0 => Ok(None),
            _ => Err(Error::Corrupted),
        };
    }
    if kind[0] != KIND_FILE && kind[0] != KIND_DIR {
        return Err(Error::Corrupted);
    }
    let mut len = [0u8; 2];
    exact(reader, &mut len)?;
    let mut rel = vec![0u8; usize::from(u16::from_le_bytes(len))];
    exact(reader, &mut rel)?;
    let rel = String::from_utf8(rel).map_err(|_| Error::Corrupted)?;
    Ok(Some((kind[0] == KIND_DIR, rel)))
}

/// Passes the content of the file entry that `reader` is positioned at to `sink`.
fn file_content(
    reader: &mut impl Read,
    buf: &mut [u8],
    mut sink: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<()> {
    let mut size = [0u8; 8];
    exact(reader, &mut size)?;
    let mut remaining = u64::from_le_bytes(size);
    while remaining > 0 {
        let want = buf.len().min(usize::try_from(remaining).unwrap_or(usize::MAX));
        exact(reader, &mut buf[..want])?;
        sink(&buf[..want])?;
        remaining -= want as u64;
    }
    Ok(())
}

/// Creates the file at `path`, or at `name (2).ext`, `name (3).ext`... if that is taken.
///
/// Archives written before names were checked when packing can hold the same path twice
/// (names that differed only in case, or in characters that could not be stored). Both
/// files are kept rather than refusing the whole folder.
fn create_unique(path: &Path) -> io::Result<File> {
    match File::create_new(path) {
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        other => return other,
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let (stem, extension) = match name.rfind('.') {
        Some(dot) if dot > 0 => name.split_at(dot),
        _ => (&*name, ""),
    };
    for number in 2..1000 {
        match File::create_new(path.with_file_name(format!("{stem} ({number}){extension}"))) {
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            other => return other,
        }
    }
    Err(io::ErrorKind::AlreadyExists.into())
}

/// Recreates the packed folder's content inside `root`, which must already exist and
/// should be empty. Never overwrites: a file whose path is taken gets a numbered name.
/// On error, what was written so far is left for the caller to remove.
pub fn unpack(reader: impl Read, root: &Path) -> Result<()> {
    unpack_into(reader, root, false)
}

/// Like [`unpack`], and also flushes every file to the disk before returning, so that
/// the result survives a power cut. Use it when the archive may be deleted afterwards.
pub fn unpack_synced(reader: impl Read, root: &Path) -> Result<()> {
    unpack_into(reader, root, true)
}

fn unpack_into(mut reader: impl Read, root: &Path, sync: bool) -> Result<()> {
    let mut buf = vec![0u8; COPY_BUFFER];
    while let Some((is_dir, rel)) = next_entry(&mut reader)? {
        let path = safe_join(root, &rel)?;
        if is_dir {
            fs::create_dir_all(&path)?;
            continue;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = create_unique(&path)?;
        file_content(&mut reader, &mut buf, |bytes| file.write_all(bytes))?;
        if sync {
            file.sync_all()?;
        }
    }
    Ok(())
}

/// Reads a whole archive exactly as [`unpack`] would, writing nothing: succeeds only if
/// the archive is complete and every path in it would be accepted.
pub fn check(mut reader: impl Read) -> Result<()> {
    let mut buf = vec![0u8; COPY_BUFFER];
    while let Some((is_dir, rel)) = next_entry(&mut reader)? {
        safe_join(Path::new(""), &rel)?;
        if !is_dir {
            file_content(&mut reader, &mut buf, |_| Ok(()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(entries: &[Entry]) -> Vec<u8> {
        let mut out = Vec::new();
        Packer::new(entries, |path: &Path| File::open(path)).read_to_end(&mut out).unwrap();
        out
    }

    fn entry(kind: u8, rel: &str, content: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&(rel.len() as u16).to_le_bytes());
        out.extend_from_slice(rel.as_bytes());
        if kind == KIND_FILE {
            out.extend_from_slice(&(content.len() as u64).to_le_bytes());
            out.extend_from_slice(content);
        }
        out
    }

    #[test]
    fn folder_roundtrip_keeps_structure_and_empty_folders() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir_all(source.path().join("a/فارغ")).unwrap();
        fs::create_dir_all(source.path().join("b")).unwrap();
        fs::write(source.path().join("a/one.txt"), b"one").unwrap();
        fs::write(source.path().join("b/صورة.jpg"), vec![5u8; 700_000]).unwrap();
        fs::write(source.path().join("empty"), b"").unwrap();

        let entries = list(source.path()).unwrap();
        assert_eq!(content_bytes(&entries), 700_003);
        let packed = pack(&entries);

        let dest = tempfile::tempdir().unwrap();
        unpack(&packed[..], dest.path()).unwrap();
        assert!(dest.path().join("a/فارغ").is_dir());
        assert_eq!(fs::read(dest.path().join("a/one.txt")).unwrap(), b"one");
        assert_eq!(fs::read(dest.path().join("b/صورة.jpg")).unwrap(), vec![5u8; 700_000]);
        assert_eq!(fs::read(dest.path().join("empty")).unwrap(), b"");
    }

    #[test]
    fn paths_that_escape_the_folder_are_refused() {
        for rel in [
            "../evil", "a/../../evil", "/evil", "C:/evil", "a\\b", "nul", "COM1.txt", "ok/",
            "LPT².log", "conin$", "x/trailing.", "x/ends with space ", "stream.txt:hidden",
        ] {
            let mut archive = entry(KIND_FILE, rel, b"x");
            archive.push(KIND_END);
            let dest = tempfile::tempdir().unwrap();
            let inner = dest.path().join("inner");
            fs::create_dir(&inner).unwrap();
            assert!(matches!(unpack(&archive[..], &inner), Err(Error::UnsafePath)), "{rel}");
            assert_eq!(fs::read_dir(dest.path()).unwrap().count(), 1, "{rel} wrote outside");
            assert_eq!(fs::read_dir(&inner).unwrap().count(), 0, "{rel} wrote something");
        }
    }

    #[test]
    fn damaged_archives_are_refused() {
        let dest = tempfile::tempdir().unwrap();
        let good = [entry(KIND_FILE, "f", b"data"), vec![KIND_END]].concat();
        for cut in [0, 1, 3, 8, good.len() - 1] {
            let target = dest.path().join(format!("cut{cut}"));
            fs::create_dir(&target).unwrap();
            assert!(matches!(unpack(&good[..cut], &target), Err(Error::Corrupted)), "cut {cut}");
        }
        let trailing = [good.clone(), vec![1]].concat();
        let target = dest.path().join("trailing");
        fs::create_dir(&target).unwrap();
        assert!(matches!(unpack(&trailing[..], &target), Err(Error::Corrupted)));
        let unknown = [vec![9u8], good].concat();
        assert!(matches!(unpack(&unknown[..], dest.path()), Err(Error::Corrupted)));
    }

    #[test]
    fn names_that_display_as_something_else_are_refused() {
        assert!(!is_safe_name("invoice\u{202E}fdp.exe"));
        assert!(!is_safe_name("photo\u{202B}jpg.exe"));
        assert!(!is_safe_name("a\u{2067}b"));
        // Ordinary right-to-left names, with the marks real names contain, are fine.
        assert!(is_safe_name("تقرير 2025.pdf"));
        assert!(is_safe_name("ملف\u{200F} (1).txt"));
        assert!(is_safe_name("می\u{200C}خواهم.txt"));
    }

    #[test]
    fn paths_nested_too_deeply_are_refused_in_both_directions() {
        let at_limit = vec!["a"; MAX_DEPTH].join("/");
        let beyond = vec!["a"; MAX_DEPTH + 1].join("/");
        check(&[entry(KIND_DIR, &at_limit, b""), vec![KIND_END]].concat()[..]).unwrap();
        let deep = [entry(KIND_DIR, &beyond, b""), vec![KIND_END]].concat();
        assert!(matches!(check(&deep[..]), Err(Error::UnsafePath)));
        let dest = tempfile::tempdir().unwrap();
        assert!(matches!(unpack(&deep[..], dest.path()), Err(Error::UnsafePath)));
        assert_eq!(fs::read_dir(dest.path()).unwrap().count(), 0, "nothing was created");

        // And such a folder is not packed in the first place.
        let source = tempfile::tempdir().unwrap();
        let mut path = source.path().to_owned();
        for _ in 0..MAX_DEPTH {
            path.push("a");
        }
        fs::create_dir_all(&path).unwrap();
        assert_eq!(list(source.path()).unwrap().len(), MAX_DEPTH);
        fs::create_dir(path.join("a")).unwrap();
        assert!(matches!(list(source.path()), Err(Error::UnsupportedName(_))));
    }

    #[test]
    fn name_length_is_counted_as_windows_counts_it() {
        // 130 Arabic letters are 260 bytes of UTF-8 but only 130 UTF-16 units.
        assert!(is_safe_name(&format!("{}.txt", "ص".repeat(130))));
        assert!(is_safe_name(&"a".repeat(255)));
        assert!(!is_safe_name(&"a".repeat(256)));
        assert!(!is_safe_name(&"ص".repeat(256)));
    }

    #[test]
    fn check_accepts_exactly_what_unpack_accepts_and_writes_nothing() {
        let good = [entry(KIND_DIR, "d", b""), entry(KIND_FILE, "d/f", b"data"), vec![KIND_END]].concat();
        check(&good[..]).unwrap();
        for cut in [0, 1, 3, 8, good.len() - 1] {
            assert!(matches!(check(&good[..cut]), Err(Error::Corrupted)), "cut {cut}");
        }
        assert!(matches!(check(&[good.clone(), vec![1]].concat()[..]), Err(Error::Corrupted)));
        for rel in ["../evil", "a/nul", "x/trailing."] {
            let bad = [entry(KIND_FILE, rel, b"x"), vec![KIND_END]].concat();
            assert!(matches!(check(&bad[..]), Err(Error::UnsafePath)), "{rel}");
        }
    }

    #[test]
    fn synced_unpacking_writes_the_same_tree() {
        let archive = [
            entry(KIND_DIR, "empty", b""),
            entry(KIND_FILE, "d/one.txt", b"one"),
            entry(KIND_FILE, "d/zero", b""),
            vec![KIND_END],
        ]
        .concat();
        let dest = tempfile::tempdir().unwrap();
        unpack_synced(&archive[..], dest.path()).unwrap();
        assert!(dest.path().join("empty").is_dir());
        assert_eq!(fs::read(dest.path().join("d/one.txt")).unwrap(), b"one");
        assert_eq!(fs::read(dest.path().join("d/zero")).unwrap(), b"");
    }

    #[test]
    fn a_path_stored_twice_keeps_both_files() {
        // Archives written before names were checked when packing can contain this.
        let archive = [
            entry(KIND_FILE, "d/report.txt", b"first"),
            entry(KIND_FILE, "d/report.txt", b"second"),
            entry(KIND_FILE, "d/README", b"one"),
            entry(KIND_FILE, "d/README", b"two"),
            vec![KIND_END],
        ]
        .concat();
        check(&archive[..]).unwrap();
        let dest = tempfile::tempdir().unwrap();
        unpack(&archive[..], dest.path()).unwrap();
        assert_eq!(fs::read(dest.path().join("d/report.txt")).unwrap(), b"first");
        assert_eq!(fs::read(dest.path().join("d/report (2).txt")).unwrap(), b"second");
        assert_eq!(fs::read(dest.path().join("d/README")).unwrap(), b"one");
        assert_eq!(fs::read(dest.path().join("d/README (2)")).unwrap(), b"two");
    }

    #[test]
    fn a_file_that_changes_size_while_packing_is_an_error() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("f"), b"12345").unwrap();
        for wrong in [3, 9] {
            let mut entries = list(source.path()).unwrap();
            entries[0].size = wrong;
            let mut out = Vec::new();
            let err = Packer::new(&entries, |path: &Path| File::open(path))
                .read_to_end(&mut out)
                .unwrap_err();
            assert!(matches!(Error::from(err), Error::VerificationFailed), "size {wrong}");
        }
    }
}
