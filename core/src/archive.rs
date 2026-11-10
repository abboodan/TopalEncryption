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

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::{Error, Result};

const KIND_END: u8 = 0;
const KIND_FILE: u8 = 1;
const KIND_DIR: u8 = 2;

const COPY_BUFFER: usize = 256 * 1024;

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
pub fn list(folder: &Path) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for entry in WalkDir::new(folder).min_depth(1).sort_by_file_name() {
        let entry = entry.map_err(io::Error::from)?;
        let kind = entry.file_type();
        if !kind.is_file() && !kind.is_dir() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(folder)
            .expect("walked paths start with the folder")
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
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
    const RESERVED: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    if name.is_empty() || name == "." || name == ".." || name.len() > 255 {
        return false;
    }
    if name.chars().any(|c| c.is_control() || r#"/\:*?"<>|"#.contains(c)) {
        return false;
    }
    if name.ends_with(' ') || name.ends_with('.') {
        return false;
    }
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    let numbered = |prefix: &str| {
        stem.strip_prefix(prefix)
            .is_some_and(|rest| rest.len() == 1 && rest.chars().all(|c| c.is_ascii_digit()))
    };
    !(RESERVED.contains(&stem.as_str()) || numbered("COM") || numbered("LPT"))
}

fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    let mut path = root.to_owned();
    for part in rel.split('/') {
        if !is_safe_name(part) {
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

/// Recreates the packed folder's content inside `root`, which must already exist. Never
/// overwrites: an existing file is an error. On error, what was written so far is left
/// for the caller to remove.
pub fn unpack(mut reader: impl Read, root: &Path) -> Result<()> {
    let mut buf = vec![0u8; COPY_BUFFER];
    loop {
        let mut kind = [0u8; 1];
        exact(&mut reader, &mut kind)?;
        if kind[0] == KIND_END {
            // Anything after the end marker was not written by us.
            return match reader.read(&mut buf[..1])? {
                0 => Ok(()),
                _ => Err(Error::Corrupted),
            };
        }
        if kind[0] != KIND_FILE && kind[0] != KIND_DIR {
            return Err(Error::Corrupted);
        }
        let mut len = [0u8; 2];
        exact(&mut reader, &mut len)?;
        let mut rel = vec![0u8; usize::from(u16::from_le_bytes(len))];
        exact(&mut reader, &mut rel)?;
        let rel = String::from_utf8(rel).map_err(|_| Error::Corrupted)?;
        let path = safe_join(root, &rel)?;

        if kind[0] == KIND_DIR {
            fs::create_dir_all(&path)?;
            continue;
        }
        let mut size = [0u8; 8];
        exact(&mut reader, &mut size)?;
        let mut remaining = u64::from_le_bytes(size);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = File::create_new(&path)?;
        while remaining > 0 {
            let want = buf.len().min(usize::try_from(remaining).unwrap_or(usize::MAX));
            exact(&mut reader, &mut buf[..want])?;
            file.write_all(&buf[..want])?;
            remaining -= want as u64;
        }
    }
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
        for rel in ["../evil", "a/../../evil", "/evil", "C:/evil", "a\\b", "nul", "COM1.txt", "ok/"] {
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
